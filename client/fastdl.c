/*
 * FastDL-WON - verified HTTP downloads for Half-Life WON clients, 1.0.0.5 - 1.1.1.0 (protocols 35 - 46).
 *
 * Built twice from this file: fastdl.asi (the standard loader: Mss32.dll loads every *.asi in the game
 * folder in its first AIL_startup, which can happen while the engine already runs; HL 1.1.0.8+) and
 * wsock32.dll (legacy loader for hl.exe builds without Miles, loaded at process start). Hooks the engine's
 * resource check (hw.dll or sw.dll: CL_CheckFile in 1.1.x, CL_CheckOrDownloadFile in 1.0.x; rows in
 * engines.h). For every resource the server lists:
 *
 *   - FDL_BLOCK (code, configs, unknown types, path tricks, names the engine build mishandles): reported
 *     as present, so the engine never requests it
 *   - FDL_FETCH (game file in its usual place) and missing: fetched over HTTP, but only if cl_allowdownload
 *     is on, the server publishes sv_won_downloadurl and sv_won_dlkey, the signed manifest at
 *     <url>/fastdl.manifest verifies with that key and belongs to that URL, the file is listed, and
 *     size + BLAKE2b-256 match
 *   - everything else, and every failure: the engine's normal in-band download
 *
 * All network I/O runs on a worker thread; the engine thread waits with a hard deadline, so a slow or
 * hostile web server can delay a connection by at most the time budget, never hang the game.
 * Security-relevant parsing lives in core.c (unit tested and fuzzed on Linux, see test/).
 */
#define _WIN32_WINNT 0x0501		/* XP: GetModuleHandleExA, OpenThread */
#include <windows.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "third_party/monocypher/monocypher.h"

#define FASTDL_VERSION		"1.0"

/* time budget: the engine thread is blocked while we work, and the game server drops a client that is
 * silent for sv_timeout (65 s by default) */
#define BURST_MS			40000		/* HTTP time per connection attempt (burst of CheckFile calls) */
#define BURST_GAP_MS		20000		/* idle time that starts a new burst */
#define MANIFEST_MS			10000
#define FILE_BASE_MS		8000		/* + size / MIN_SPEED */
#define MIN_SPEED			65536		/* bytes/s; slower transfers are cut off (in-band is ~30 KB/s) */
#define ABORT_GRACE_MS		1500

#define SESSION_MAX_BYTES	(512u * 1024u * 1024u)
#define SESSION_MAX_FILES	4096
#define SESSION_MAX_ERRORS	3			/* errors before HTTP is switched off for the rest of this signon */
#define MANIFEST_RETRY_PAUSE_MS	1000	/* one retry of the manifest after a transport failure, within MANIFEST_MS */
#define MANIFEST_REFRESH_MS	60000
#define DISK_RESERVE		(64u * 1024u * 1024u)
#define LOG_MAX				(512 * 1024)

typedef int (__cdecl *CheckFile_t)(void *msg, const char *filename);
typedef int (__cdecl *CheckOrDl_t)(const char *filename);
typedef int (__cdecl *CopyFile_t)(BYTE *chan, void *arg2);		/* 1.1.0.0: 2 args, later 1 (cdecl: the extra is harmless) */
typedef int (__cdecl *FileSize_t)(const char *filename);
typedef int (__cdecl *FOpen_t)(const char *filename, void **file);
typedef int (__cdecl *FClose_t)(void *file);
typedef void (__cdecl *ConPrintf_t)(const char *fmt, ...);
typedef const char *(__cdecl *CmdArgv_t)(int i);

#include "engine.h"

/* every known engine build; addresses, signatures and how they were found: engines.h */
static const engine_t g_engines[] =
{
#include "engines.h"
};
#define N_ENGINES	((int)(sizeof(g_engines) / sizeof(g_engines[0])))

typedef enum { SESS_NONE, SESS_READY, SESS_FAILED } sess_state_t;

typedef struct
{
	char id[FDL_INFO_MAX];			/* url + key + gamedir: a different server starts a new session */
	sess_state_t state;				/* SESS_FAILED lasts until the next signon (connect, reconnect, map change) */
	fdl_url_t url;
	uint8_t key[32];
	char root[MAX_PATH];			/* com_gamedir + '\' */
	fdl_manifest_t man;
	DWORD man_time;
	unsigned bytes, files, errors;
	DWORD burst_start, burst_last;	/* time budget of the current connection attempt; burst_last = end of the last HTTP work */
	int burst_in_call;				/* inside one CheckFile call: the budget may not restart in the middle */
	unsigned tmpseq;
	HINTERNET conn;					/* kept for the session: WinINet reuses the keep-alive connection */
} session_t;

static engine_t g_rt;				/* the matched row, addresses resolved to VAs */
static const engine_t *g_eng;		/* &g_rt once hooked */
static DWORD g_cmd_add;				/* Cmd_AddCommand (ENG_EXPORTS rows): no list insert while a thread is in it */
static BYTE *g_tramp;				/* CL_CheckFile / CL_CheckOrDownloadFile */
static BYTE *g_tramp_cf;			/* Netchan_CopyFileFragments */
static FileSize_t FS_FileSize;
static FOpen_t FS_FOpen;
static FClose_t FS_FClose;
static ConPrintf_t Con_Printf;
static CmdArgv_t Cmd_Argv;
static FILE *g_log;
static CRITICAL_SECTION g_log_lock;
static char g_dir[MAX_PATH];		/* folder of this DLL = Half-Life folder, independent of the cwd */
static HINTERNET g_inet;
static session_t g_sess;
static int g_debug;
static DWORD g_loaded;			/* GetTickCount() at DllMain */

/* ---- logging --------------------------------------------------------------------------------- */

static void ModPath(char *out, size_t outlen, const char *name)
{
	_snprintf(out, outlen - 1, "%s%s", g_dir, name);
	out[outlen - 1] = 0;
}

/* The log is capped at LOG_MAX per file (plus one rotated file): a hostile server can trigger a line
 * per pushed file. Called from the engine thread and the watchdog. */
static void Log(const char *fmt, ...)
{
	va_list va;
	EnterCriticalSection(&g_log_lock);
	if (g_log && ftell(g_log) > LOG_MAX)
	{
		fclose(g_log);
		g_log = NULL;
	}
	if (!g_log)
	{
		char path[MAX_PATH], old[MAX_PATH];
		WIN32_FILE_ATTRIBUTE_DATA fa;
		ModPath(path, sizeof(path), "fastdl.log");
		if (GetFileAttributesExA(path, GetFileExInfoStandard, &fa) && (fa.nFileSizeHigh || fa.nFileSizeLow > LOG_MAX))
		{
			ModPath(old, sizeof(old), "fastdl.log.1");
			DeleteFileA(old);
			MoveFileA(path, old);
		}
		g_log = fopen(path, "a");
	}
	if (!g_log)
	{
		LeaveCriticalSection(&g_log_lock);
		return;
	}
	if (fmt[0] != ' ')		/* continuation lines (LogEngineBytes) carry no timestamp */
	{
		SYSTEMTIME t;
		GetLocalTime(&t);
		fprintf(g_log, "%04u-%02u-%02u %02u:%02u:%02u.%03u v" FASTDL_VERSION " ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
			t.wMilliseconds);
	}
	va_start(va, fmt);
	vfprintf(g_log, fmt, va);
	va_end(va);
	fflush(g_log);
	LeaveCriticalSection(&g_log_lock);
}

/* names from the server are untrusted: printable ASCII only, bounded */
static const char *Safe(const char *s, char *buf, size_t len)
{
	size_t i;
	if (!s)
		return "(null)";
	for (i = 0; s[i] && i < len - 1; i++)
		buf[i] = (s[i] >= 0x20 && s[i] < 0x7F && s[i] != '%') ? s[i] : '?';
	buf[i] = 0;
	return buf;
}

/* reads engine memory without faulting on unmapped or protected pages */
static int ReadMem(DWORD addr, void *out, SIZE_T n)
{
	SIZE_T got = 0;
	return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, out, n, &got) && got == n;
}

/* ---- filesystem ------------------------------------------------------------------------------ */

/* Creates the directories of rel (forward slashes) below root. Every existing component must be a
 * real directory, not a junction/reparse point, so writes can never be redirected out of the game dir. */
static int MakeDirs(const char *root, const char *rel)
{
	char path[MAX_PATH];
	size_t rl = strlen(root), i;
	if (rl + strlen(rel) >= sizeof(path))
		return 0;
	memcpy(path, root, rl + 1);
	for (i = 0; rel[i]; i++)
	{
		if (rel[i] == '/')
		{
			DWORD a;
			path[rl + i] = 0;
			a = GetFileAttributesA(path);
			if (a == INVALID_FILE_ATTRIBUTES)
			{
				if (!CreateDirectoryA(path, NULL))
					return 0;
				a = GetFileAttributesA(path);
			}
			if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY) || (a & FILE_ATTRIBUTE_REPARSE_POINT))
				return 0;
			path[rl + i] = '\\';
		}
		else
			path[rl + i] = rel[i];
	}
	return 1;
}

/* strlen(com_gamedir), MAX_PATH if unreadable */
static size_t GameDirLen(void)
{
	char g[MAX_PATH];
	if (!ReadMem(g_eng->gamedir, g, sizeof(g)) || !memchr(g, 0, sizeof(g)))
		return MAX_PATH;
	return strlen(g);
}

/* <com_gamedir>\ from the engine; its last component must be the server's *gamedir */
static int GameRoot(const char *gamedir, char *root, size_t len)
{
	char g[MAX_PATH], p[MAX_PATH];
	const char *last;
	size_t n, i;
	DWORD a;

	if (!ReadMem(g_eng->gamedir, g, sizeof(g)) || !memchr(g, 0, sizeof(g)))
		return 0;
	n = strlen(g);
	if (n < 4 || n + 2 > len || strstr(g, "..") || !(g[1] == ':' && (g[2] == '\\' || g[2] == '/')))
		return 0;
	for (i = 0; i < n; i++)
		if (g[i] == '/')
			g[i] = '\\';
	last = strrchr(g, '\\') + 1;
	if (_stricmp(last, gamedir))
		return 0;
	_snprintf(root, len - 1, "%s\\", g);
	root[len - 1] = 0;
	a = GetFileAttributesA(g);
	if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY) || (a & FILE_ATTRIBUTE_REPARSE_POINT))
		return 0;
	_snprintf(p, sizeof(p) - 1, "%sliblist.gam", root);
	p[sizeof(p) - 1] = 0;
	return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES;
}

/* ---- HTTP on a worker thread ----------------------------------------------------------------- */

typedef struct
{
	/* input */
	char host[254];
	unsigned short port;
	int secure;						/* https: INTERNET_FLAG_SECURE, certificate errors are failures */
	char object[FDL_URL_MAX + 3 * FDL_PATH_MAX + 32];
	DWORD expect;					/* exact size, 0 = any up to max */
	DWORD max;
	int text;						/* reject NUL bytes */
	char tmp[MAX_PATH];				/* "" = keep in memory */
	/* output */
	int ok;
	char fail[96];
	int transport;					/* failed before an HTTP status arrived, or while receiving: worth one retry */
	uint8_t *mem;
	DWORD got;
	uint8_t hash[FDL_HASH_LEN];
	uint8_t head[16];
	size_t hl;
	/* shared */
	volatile LONG refs;				/* engine thread + worker */
	volatile LONG abort;
	HINTERNET conn;					/* session connection, owned by the engine thread */
	HINTERNET volatile req;			/* published for the engine thread to close on timeout */
} job_t;

static void JobRelease(job_t *j)
{
	if (InterlockedDecrement(&j->refs) == 0)
	{
		if (j->tmp[0])
			DeleteFileA(j->tmp);	/* no-op after a successful rename; removes it in every other case */
		free(j->mem);
		free(j);
	}
}

/* publish a handle; if the engine thread already gave up, close it right away */
static int Publish(job_t *j, HINTERNET volatile *slot, HINTERNET h)
{
	InterlockedExchangePointer((PVOID volatile *)slot, h);
	if (j->abort)
	{
		h = (HINTERNET)InterlockedExchangePointer((PVOID volatile *)slot, NULL);
		if (h)
			InternetCloseHandle(h);
		return 0;
	}
	return 1;
}

static void Unpublish(HINTERNET volatile *slot)
{
	HINTERNET h = (HINTERNET)InterlockedExchangePointer((PVOID volatile *)slot, NULL);
	if (h)
		InternetCloseHandle(h);
}

/* WinINet / WinSock error codes seen in practice */
static const char *NetErrName(DWORD e)
{
	switch (e)
	{
	case 12002: return "timeout";
	case 12007: return "name not resolved";
	case 12017: return "operation cancelled";
	case 12029: return "cannot connect";
	case 12030: return "connection aborted";
	case 12031: return "connection reset";
	case 12152: return "invalid server response";
	case 12037: return "certificate expired or not yet valid";
	case 12038: return "certificate host name does not match";
	case 12044: return "server requests a client certificate";
	case 12045: return "certificate issuer not trusted";
	case 12057: return "certificate revocation check failed";
	case 12169: return "invalid certificate";
	case 12157: return "TLS handshake failed (Windows XP: no TLS 1.2 / SNI)";
	case 12175: return "TLS decoding failed (Windows XP: no TLS 1.2 / SNI)";
	case 10060: return "WSAETIMEDOUT";
	case 10061: return "WSAECONNREFUSED";
	case 10054: return "WSAECONNRESET";
	default: return "";
	}
}

/* records the phase and the exact error of a transport failure (worker thread) */
static void NetFail(job_t *j, const char *phase)
{
	DWORD e = GetLastError(), ext = 0, len;
	char info[48];
	const char *name = NetErrName(e);
	info[0] = 0;
	if (e == ERROR_INTERNET_EXTENDED_ERROR)
	{
		len = sizeof(info);
		if (!InternetGetLastResponseInfoA(&ext, info, &len))
			info[0] = 0;
		info[sizeof(info) - 1] = 0;
		for (len = 0; info[len]; len++)		/* text from the server: printable ASCII only in the log */
			if ((unsigned char)info[len] < 0x20 || (unsigned char)info[len] > 0x7e)
				info[len] = '?';
	}
	_snprintf(j->fail, sizeof(j->fail) - 1, "%s failed: error %lu%s%s%s%s", phase, e, name[0] ? " " : "", name,
		info[0] ? " - " : "", info);
	j->fail[sizeof(j->fail) - 1] = 0;
	/* a certificate the client rejects stays rejected: no retry for 12037/12038/12044/12045/12057/12169 */
	j->transport = !(e == 12037 || e == 12038 || e == 12044 || e == 12045 || e == 12057 || e == 12169);
}

static volatile LONG g_workers;		/* running worker threads; > 0 between jobs = an abandoned one */

static DWORD WINAPI JobThread(LPVOID arg)
{
	static const char *accept[] = { "*/*", NULL };
	const DWORD flags = INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD
		| INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_AUTH
		| INTERNET_FLAG_KEEP_CONNECTION;
	job_t *j = (job_t *)arg;
	HANDLE out = INVALID_HANDLE_VALUE;
	DWORD status = 0, clen = 0, len, n, w, cap = 0;
	crypto_blake2b_ctx ctx;
	uint8_t *buf = (uint8_t *)malloc(65536);
	HINTERNET h;

	InterlockedIncrement(&g_workers);
	strcpy(j->fail, buf ? "aborted" : "out of memory");
	if (!buf || j->abort)
		goto done;
	/* https: WinINet checks the certificate chain, dates and host name; no INTERNET_FLAG_IGNORE_CERT_* flags,
	 * so every certificate problem fails the request (and the engine's normal download takes over) */
	h = HttpOpenRequestA(j->conn, "GET", j->object, "HTTP/1.1", NULL, accept, flags | (j->secure ? INTERNET_FLAG_SECURE : 0), 0);
	if (!h)
	{
		NetFail(j, "open request");
		goto done;
	}
	if (!Publish(j, &j->req, h))
		goto done;
	/* WinINet resolves, connects and sends here: the error code tells which (12007 / 12029 / 12002 ...) */
	if (!HttpSendRequestA(j->req, "Accept-Encoding: identity\r\n", (DWORD)-1, NULL, 0))
	{
		NetFail(j, "resolve/connect/send");
		goto done;
	}
	len = sizeof(status);
	if (!HttpQueryInfoA(j->req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &len, NULL))
	{
		NetFail(j, "status");
		goto done;
	}
	if (status != 200)
	{
		_snprintf(j->fail, sizeof(j->fail) - 1, "HTTP %lu", status);
		goto done;
	}
	len = sizeof(clen);
	if (HttpQueryInfoA(j->req, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &clen, &len, NULL)
		&& ((j->expect && clen != j->expect) || clen > j->max))
	{
		strcpy(j->fail, "wrong Content-Length");
		goto done;
	}

	if (j->tmp[0])
	{
		DeleteFileA(j->tmp);
		out = CreateFileA(j->tmp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (out == INVALID_HANDLE_VALUE)
		{
			strcpy(j->fail, "cannot write temp file");
			goto done;
		}
	}
	crypto_blake2b_init(&ctx, FDL_HASH_LEN);
	strcpy(j->fail, "aborted");
	for (;;)
	{
		if (j->abort)
			goto done;
		if (!InternetReadFile(j->req, buf, 65536, &n))
		{
			NetFail(j, "receive");
			goto done;
		}
		if (!n)
			break;
		if (n > j->max - j->got)
		{
			strcpy(j->fail, "longer than allowed");
			goto done;
		}
		if (j->text && memchr(buf, 0, n))
		{
			strcpy(j->fail, "binary data in text file");
			goto done;
		}
		if (j->hl < sizeof(j->head))
		{
			size_t c = sizeof(j->head) - j->hl < n ? sizeof(j->head) - j->hl : n;
			memcpy(j->head + j->hl, buf, c);
			j->hl += c;
		}
		crypto_blake2b_update(&ctx, buf, n);
		if (out != INVALID_HANDLE_VALUE)
		{
			if (!WriteFile(out, buf, n, &w, NULL) || w != n)
			{
				strcpy(j->fail, "write error");
				goto done;
			}
		}
		else
		{
			if (j->got + n > cap)
			{
				DWORD nc = cap ? cap : 65536;
				uint8_t *nm;
				while (nc < j->got + n)
					nc *= 2;
				nm = (uint8_t *)realloc(j->mem, nc);
				if (!nm)
				{
					strcpy(j->fail, "out of memory");
					goto done;
				}
				j->mem = nm;
				cap = nc;
			}
			memcpy(j->mem + j->got, buf, n);
		}
		j->got += n;
	}
	crypto_blake2b_final(&ctx, j->hash);
	/* deliberately no FlushFileBuffers / MOVEFILE_WRITE_THROUGH: they cost ~20 ms per file (measured),
	 * and the engine does not flush its own downloads either - after a power loss the risk is the same
	 * as with an in-band download */
	j->ok = 1;
	j->fail[0] = 0;
	goto done;

done:
	if (out != INVALID_HANDLE_VALUE)
		CloseHandle(out);
	Unpublish(&j->req);
	free(buf);
	JobRelease(j);
	InterlockedDecrement(&g_workers);
	return 0;
}

/* Runs the job with a deadline. On timeout the handles are closed to unblock the worker; if it still
 * does not finish, it is abandoned (it frees itself) and the job counts as failed. */
static int RunJob(job_t *j, DWORD ms)
{
	HANDLE t;
	DWORD r;

	j->refs = 2;
	t = CreateThread(NULL, 0, JobThread, j, 0, NULL);
	if (!t)
	{
		j->refs = 1;
		strcpy(j->fail, "no thread");
		return 0;
	}
	r = WaitForSingleObject(t, ms);
	if (r != WAIT_OBJECT_0)
	{
		InterlockedExchange(&j->abort, 1);
		Unpublish(&j->req);
		r = WaitForSingleObject(t, 300);
		if (r != WAIT_OBJECT_0 && g_sess.conn == j->conn)
		{
			/* still stuck (connect/DNS): closing the connection handle aborts it; a new one is
			 * created for the next job */
			InternetCloseHandle(g_sess.conn);
			g_sess.conn = NULL;
			r = WaitForSingleObject(t, ABORT_GRACE_MS);
		}
		if (r != WAIT_OBJECT_0)
		{
			/* closing the root handle ends everything below it, also WinINet draining the rest of an
			 * endless response; NewJob opens a new one, but only once this worker has ended */
			strcpy(j->fail, "timeout (abandoned)");
			if (g_inet)
				InternetCloseHandle(g_inet);
			g_inet = NULL;
			g_sess.conn = NULL;
		}
		else
			strcpy(j->fail, "timeout");
		j->ok = 0;
	}
	CloseHandle(t);
	return j->ok;
}

static job_t *NewJob(const char *object)
{
	static int told;
	job_t *j;
	/* no new transfer while an abandoned worker still runs: at most one stray thread per process */
	if (g_workers > 0)
	{
		if (!told)
			Log("fastdl: previous transfer still running, no new HTTP request until it ends\n");
		told = 1;
		return NULL;
	}
	told = 0;
	if (!g_inet)
	{
		DWORD v;
		g_inet = InternetOpenA("FastDL-WON/" FASTDL_VERSION, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (!g_inet)
			return NULL;
		v = 4000; InternetSetOptionA(g_inet, INTERNET_OPTION_CONNECT_TIMEOUT, &v, sizeof(v));
		v = 1;    InternetSetOptionA(g_inet, INTERNET_OPTION_CONNECT_RETRIES, &v, sizeof(v));
		v = 4000; InternetSetOptionA(g_inet, INTERNET_OPTION_SEND_TIMEOUT, &v, sizeof(v));
		v = 8000; InternetSetOptionA(g_inet, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof(v));
	}
	/* InternetConnect does no network I/O; the socket is opened by the first request */
	if (!g_sess.conn)
		g_sess.conn = InternetConnectA(g_inet, g_sess.url.host, g_sess.url.port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!g_sess.conn)
		return NULL;
	j = (job_t *)calloc(1, sizeof(job_t));
	if (!j)
		return NULL;
	j->conn = g_sess.conn;
	memcpy(j->host, g_sess.url.host, sizeof(j->host));
	j->port = g_sess.url.port;
	j->secure = g_sess.url.https;
	_snprintf(j->object, sizeof(j->object) - 1, "%s/%s", g_sess.url.path, object);
	return j;
}

/* milliseconds left in the current burst */
static DWORD BurstLeft(void)
{
	uint32_t start = g_sess.burst_start;
	DWORD left = fdl_burst_left(&start, g_sess.burst_in_call ? 0 : g_sess.burst_last, GetTickCount(), BURST_MS, BURST_GAP_MS);
	g_sess.burst_start = start;
	return left;
}

/* ---- session / manifest ---------------------------------------------------------------------- */

static void SessionReset(void)
{
	if (g_sess.conn)
		InternetCloseHandle(g_sess.conn);
	fdl_manifest_free(&g_sess.man);
	memset(&g_sess, 0, sizeof(g_sess));
}

static void SessionFail(const char *why)
{
	g_sess.state = SESS_FAILED;
	Log("fastdl: HTTP downloads off until the next connect or map change: %s\n", why);
	if (Con_Printf)
		Con_Printf("fastdl: HTTP downloads off for this loading (%s), using normal downloads\n", why);
}

static void CountError(const char *why)
{
	if (++g_sess.errors >= SESSION_MAX_ERRORS)
		SessionFail(why);
}

/* Replay of an older, validly signed manifest (stale mirror or proxy, someone on the plain HTTP path): the
 * highest serial seen per key, host, port and tree is kept for the life of the process, and a lower one is
 * refused. Not kept across restarts. */
static int SerialFresh(uint64_t serial)
{
	static struct { uint8_t key[32]; char host[254]; unsigned short port; char tree[40]; uint64_t serial; } seen[32];
	static int nseen, next;
	const char *tree = fdl_url_tree(&g_sess.url);
	int i;
	for (i = 0; i < nseen; i++)
		if (!memcmp(seen[i].key, g_sess.key, 32) && !strcmp(seen[i].host, g_sess.url.host)
			&& seen[i].port == g_sess.url.port && !strcmp(seen[i].tree, tree))
		{
			if (serial < seen[i].serial)
			{
				Log("fastdl: manifest rejected: older than one already seen (serial %I64u < %I64u)\n", serial, seen[i].serial);
				return 0;
			}
			seen[i].serial = serial;
			return 1;
		}
	i = nseen < 32 ? nseen++ : next++ % 32;
	memcpy(seen[i].key, g_sess.key, 32);
	strcpy(seen[i].host, g_sess.url.host);
	seen[i].port = g_sess.url.port;
	_snprintf(seen[i].tree, sizeof(seen[i].tree) - 1, "%s", tree);
	seen[i].serial = serial;
	return 1;
}

/* 1 = loaded, 0 = not available, -1 = invalid. A transport failure (no HTTP status, or broken while
 * receiving) is retried once after MANIFEST_RETRY_PAUSE_MS; both attempts together stay within MANIFEST_MS
 * (and the burst budget). */
static int LoadManifest(void)
{
	char err[64];
	fdl_manifest_t m;
	DWORD left = BurstLeft(), t0 = GetTickCount(), total, used;
	job_t *j;
	int ok, attempt;

	g_sess.man_time = t0;		/* also after a failure: no retry storm */
	if (left < 1000)
		return 0;
	total = left < MANIFEST_MS ? left : MANIFEST_MS;
	for (attempt = 1;; attempt++)
	{
		used = GetTickCount() - t0;
		if (used + 1000 > total)		/* also catches a Sleep that overran (suspend, loaded host) */
			return 0;
		j = NewJob("fastdl.manifest");
		if (!j)
			return 0;
		j->max = FDL_MANIFEST_MAX;
		if (RunJob(j, total - used))
			break;
		Log("fastdl: manifest (attempt %d): %s\n", attempt, j->fail);
		used = GetTickCount() - t0;
		if (attempt == 2 || !j->transport || used + MANIFEST_RETRY_PAUSE_MS + 1000 > total)
		{
			JobRelease(j);
			return 0;
		}
		JobRelease(j);
		Sleep(MANIFEST_RETRY_PAUSE_MS);
	}
	ok = fdl_manifest_load(&m, j->mem, j->got, g_sess.key, fdl_url_tree(&g_sess.url), err, sizeof(err));
	JobRelease(j);
	if (!ok)
	{
		Log("fastdl: manifest rejected: %s\n", err);
		return -1;
	}
	if (!SerialFresh(m.serial))
	{
		fdl_manifest_free(&m);
		return -1;
	}
	fdl_manifest_free(&g_sess.man);
	g_sess.man = m;
	Log("fastdl: manifest verified, %d files\n", m.count);
	return 1;
}

/* ---- serverinfo ------------------------------------------------------------------------------ */

/* SI_PLUGIN_CMD (1.0.0.5 - 1.0.0.8): these engines have no "fullserverinfo" command and no cl.serverinfo.
 * The plugin links its own command node into cmd_functions (Cmd_AddCommand refuses calls after host init)
 * and keeps the string together with net_from at that moment, i.e. the address of the server whose
 * stufftext carried it. It is used only while net_from is still that address: another server, or one
 * that never sends the command, never gets the previous server's URL. */
typedef struct { DWORD next; const char *name; void (__cdecl *function)(void); int flags; } cmd_node_t;

static void __cdecl Cmd_FullServerinfo(void);
static cmd_node_t g_cmd = { 0, "fullserverinfo", Cmd_FullServerinfo, 0 };
static struct { int set; unsigned gen; BYTE from[20]; char info[FDL_INFO_MAX]; } g_psi;

/* runs on the engine thread (command buffer) */
static void __cdecl Cmd_FullServerinfo(void)
{
	const char *a = Cmd_Argv ? Cmd_Argv(1) : NULL;
	size_t n;
	g_psi.set = 0;
	if (!a || !ReadMem(g_eng->net_from, g_psi.from, sizeof(g_psi.from)))
		return;
	n = strlen(a);
	if (n >= sizeof(g_psi.info))
		n = sizeof(g_psi.info) - 1;
	memcpy(g_psi.info, a, n);
	memset(g_psi.info + n, 0, sizeof(g_psi.info) - n);
	g_psi.set = 1;
	g_psi.gen++;
	if (g_debug)
		Log("fullserverinfo received (%u bytes)\n", (unsigned)n);
}

/* 1 = list readable and it holds the engine's "connect"; *ours / *other: our node / an engine "fullserverinfo" */
static int CmdList(DWORD head, int *ours, int *other)
{
	DWORD p;
	int i, connect = 0;
	*ours = *other = 0;
	if (!ReadMem(head, &p, 4))
		return 0;
	for (i = 0; p && i < 4096; i++)
	{
		DWORD node[2];
		char nm[16];
		if (!ReadMem(p, node, sizeof(node)))
			return 0;
		if (p == (DWORD)&g_cmd)
			*ours = 1;
		else if (ReadMem(node[1], nm, 8) && !memcmp(nm, "connect", 8))
			connect = 1;
		else if (ReadMem(node[1], nm, 15) && !memcmp(nm, "fullserverinfo", 15))
			*other = 1;
		p = node[0];
	}
	return !p && connect;
}

/* 1 once per signon (connect, reconnect, map change). SI_ENGINE: the engine clears cl (and cl.serverinfo
 * with it) for every svc_serverinfo; the plugin marks the unused last byte of the 512-byte buffer and
 * sees the mark gone after the next clear. The mark is set only behind a terminator, so the string is
 * never touched. SI_PLUGIN_CMD: the server sends "fullserverinfo" in every "new" reply. */
#define SIGNON_MARK		0xFD
static int NewSignon(void)
{
	static unsigned seen_gen;
	char info[FDL_INFO_MAX];
	BYTE mark = SIGNON_MARK;
	DWORD at;
	SIZE_T w;

	if (g_eng->si_src == SI_PLUGIN_CMD)
	{
		if (g_psi.gen == seen_gen)
			return 0;
		seen_gen = g_psi.gen;
		return 1;
	}
	if (!ReadMem(g_eng->serverinfo, info, sizeof(info)) || (BYTE)info[FDL_INFO_MAX - 1] == SIGNON_MARK)
		return 0;
	if (!memchr(info, 0, FDL_INFO_MAX - 1))
		return 0;		/* no room for the mark: treated as the same signon */
	at = g_eng->serverinfo + FDL_INFO_MAX - 1;
	return WriteProcessMemory(GetCurrentProcess(), (LPVOID)at, &mark, 1, &w) && w == 1;
}

/* reads the serverinfo of the current server into info (FDL_INFO_MAX bytes, need not be terminated) */
static int GetServerinfo(char *info)
{
	BYTE now[20];
	if (g_eng->si_src == SI_ENGINE)
		return ReadMem(g_eng->serverinfo, info, FDL_INFO_MAX);
	if (!g_psi.set || !ReadMem(g_eng->net_from, now, sizeof(now)) || memcmp(now, g_psi.from, sizeof(now)))
		return 0;
	memcpy(info, g_psi.info, FDL_INFO_MAX);
	return 1;
}

/* 3.1.0.4-3.1.0.8 servers send the resource list in the same message as the 'fullserverinfo' command: when
 * CL_CheckFile runs, that command still waits in cmd_text and cl.serverinfo is empty. Reads the pending text
 * (read only, bounded) and takes the serverinfo from that one command. 1 = info filled. */
static int PendingServerinfo(char *info)
{
	static char text[FDL_CBUF_MAX];		/* CL_CheckFile runs on the engine's main thread only */
	static int logged;
	DWORD sb[3];						/* cmd_text: data, maxsize, cursize */

	if (!g_eng->cmd_text || !ReadMem(g_eng->cmd_text, sb, sizeof(sb)))
		return 0;
	if (!sb[2] || sb[2] > sb[1] || sb[2] > FDL_CBUF_MAX || !ReadMem(sb[0], text, sb[2]))
		return 0;
	if (!fdl_cbuf_serverinfo(text, sb[2], info))
		return 0;
	if (!logged++)
		Log("fastdl: serverinfo taken from the pending fullserverinfo command\n");
	return 1;
}

/* Temp files of crashed or killed earlier runs (fastdl-<pid>-<n>.tmp in the game folder): removed when their
 * process no longer runs, or when they are older than 30 minutes. Only our own name pattern, only regular
 * files; the current process's own files are left to it. */
static void CleanTemp(void)
{
	char pat[MAX_PATH], path[MAX_PATH];
	WIN32_FIND_DATAA fd;
	HANDLE h;
	FILETIME now;
	ULONGLONG age;

	_snprintf(pat, sizeof(pat) - 1, "%sfastdl-*.tmp", g_sess.root);
	pat[sizeof(pat) - 1] = 0;
	h = FindFirstFileA(pat, &fd);
	if (h == INVALID_HANDLE_VALUE)
		return;
	GetSystemTimeAsFileTime(&now);
	do
	{
		unsigned long pid = strtoul(fd.cFileName + 7, NULL, 10);
		if (fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
			continue;
		age = ((((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime)
			- (((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime)) / 10000000;
		if (pid == GetCurrentProcessId())
			continue;
		if (age < 1800)
		{
			/* another hl.exe in the same folder may still be writing it: keep it while that process lives
			 * (a transfer never takes longer than 30 minutes: 8 s + 64 MB at 64 KB/s) */
			HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
			/* no such process: ERROR_INVALID_PARAMETER; any other failure (access denied) counts as alive */
			DWORD r = p ? WaitForSingleObject(p, 0) : (GetLastError() == ERROR_INVALID_PARAMETER ? WAIT_OBJECT_0 : WAIT_TIMEOUT);
			if (p)
				CloseHandle(p);
			if (r == WAIT_TIMEOUT)
				continue;
		}
		_snprintf(path, sizeof(path) - 1, "%s%s", g_sess.root, fd.cFileName);
		path[sizeof(path) - 1] = 0;
		if (DeleteFileA(path))
			Log("fastdl: removed old temp file %s\n", fd.cFileName);
	} while (FindNextFileA(h, &fd));
	FindClose(h);
}

/* numeric hosts (dotted, decimal or hex forms, which also cover loopback and LAN addresses) and localhost:
 * allowed for LAN servers, but worth a line in the log */
static int HostIsLocal(const char *h)
{
	return !strcmp(h, "localhost") || !strncmp(h, "0x", 2) || h[strspn(h, "0123456789.")] == 0;
}

/* Sets up g_sess from the current serverinfo. Returns 0 if this server offers no verified HTTP. */
static int SessionFor(void)
{
	char info[FDL_INFO_MAX], url[FDL_URL_MAX + 2], key[80], gamedir[40], id[FDL_INFO_MAX];
	fdl_url_t u;
	int r;

	url[0] = key[0] = gamedir[0] = 0;
	if (NewSignon())
	{
		/* every connect, reconnect and map change starts clean: no lockout carried over */
		g_sess.errors = 0;
		g_sess.burst_start = 0;
		if (g_sess.state == SESS_FAILED)
			g_sess.id[0] = 0;
	}
	if (!GetServerinfo(info))
		return 0;
	if (!fdl_info_value(info, "sv_won_downloadurl", url, sizeof(url)) || !url[0])
	{
		if (!PendingServerinfo(info) || !fdl_info_value(info, "sv_won_downloadurl", url, sizeof(url)) || !url[0])
			return 0;
	}
	fdl_info_value(info, "sv_won_dlkey", key, sizeof(key));
	fdl_info_value(info, "*gamedir", gamedir, sizeof(gamedir));
	_snprintf(id, sizeof(id) - 1, "%s|%s|%s", url, key, gamedir);
	id[sizeof(id) - 1] = 0;
	if (!strcmp(id, g_sess.id))
		return g_sess.state == SESS_READY;

	SessionReset();
	memcpy(g_sess.id, id, sizeof(id));
	if (!fdl_url_parse(url, &u))
		return SessionFail("invalid sv_won_downloadurl"), 0;
	if (!key[0] || !fdl_hex_decode(key, g_sess.key, 32))
		return SessionFail("server does not publish a valid sv_won_dlkey"), 0;
	if (!fdl_gamedir_valid(gamedir) || !GameRoot(gamedir, g_sess.root, sizeof(g_sess.root)))
		return SessionFail("game folder does not match the server"), 0;
	g_sess.url = u;
	CleanTemp();
	if (HostIsLocal(u.host))
		Log("fastdl: note: the server's download URL points to a numeric, LAN or loopback address (%s)\n", u.host);
	if (u.https)
		Log("fastdl: HTTPS to %s:%u, certificate checked by Windows\n", u.host, (unsigned)u.port);

	r = LoadManifest();
	if (r <= 0)
		return SessionFail(r < 0 ? "manifest signature/format invalid" : "manifest not available"), 0;
	g_sess.state = SESS_READY;
	return 1;
}

/* ---- download -------------------------------------------------------------------------------- */

static int Fetch(const fdl_entry_t *e)
{
	char esc[3 * FDL_PATH_MAX + 1], final[MAX_PATH];
	ULARGE_INTEGER freeb;
	DWORD t0 = GetTickCount(), left = BurstLeft(), budget;
	job_t *j;
	size_t i;
	const char *fail = NULL;

	if (g_sess.files >= SESSION_MAX_FILES || g_sess.bytes + e->size > SESSION_MAX_BYTES)
		return Log("fastdl: session limit reached, %s left to the engine\n", e->path), 0;
	budget = FILE_BASE_MS + (DWORD)((unsigned long long)e->size * 1000 / MIN_SPEED);
	if (left < 1000)
		return Log("fastdl: time budget used up, %s left to the engine\n", e->path), 0;
	if (budget > left)
		budget = left;
	if (strlen(g_sess.root) + strlen(e->path) + 32 >= MAX_PATH || !fdl_url_escape(e->path, esc, sizeof(esc)))
		return 0;
	_snprintf(final, sizeof(final) - 1, "%s%s", g_sess.root, e->path);
	final[sizeof(final) - 1] = 0;
	for (i = 0; final[i]; i++)
		if (final[i] == '/')
			final[i] = '\\';
	if (GetFileAttributesA(final) != INVALID_FILE_ATTRIBUTES)
		return 0;		/* exists on disk but the engine does not see it: do not touch it */
	if (GetDiskFreeSpaceExA(g_sess.root, &freeb, NULL, NULL) && freeb.QuadPart < (ULONGLONG)e->size + DISK_RESERVE)
		return Log("fastdl: not enough disk space for %s\n", e->path), 0;

	j = NewJob(esc);
	if (!j)
		return 0;
	j->expect = j->max = e->size;
	j->text = fdl_is_text(e->path);
	/* temp file in the game folder root (same volume, no directories created before verification) */
	_snprintf(j->tmp, sizeof(j->tmp) - 1, "%sfastdl-%lu-%u.tmp", g_sess.root, GetCurrentProcessId(), ++g_sess.tmpseq);

	if (!RunJob(j, budget))
		fail = j->fail;
	else if (j->got != e->size)
		fail = "incomplete";
	else if (crypto_verify32(j->hash, e->hash) != 0)
		fail = "hash mismatch";
	else if (!fdl_magic_ok(e->path, j->head, j->hl, e->size))
		fail = "unexpected file content";
	else if (!MakeDirs(g_sess.root, e->path))
		fail = "cannot create folders";
	else if (!MoveFileExA(j->tmp, final, 0))	/* never replaces an existing file */
		fail = "cannot rename temp file";
	if (fail)
	{
		Log("fastdl: %s: %s\n", e->path, fail);
		JobRelease(j);		/* deletes the temp file (now, or when an abandoned worker ends) */
		CountError(fail);
		return 0;
	}
	JobRelease(j);
	{
		DWORD ms = GetTickCount() - t0;
		g_sess.files++;
		g_sess.bytes += e->size;
		Log("fastdl: %s verified, %lu bytes in %lu ms\n", e->path, (unsigned long)e->size, ms);
		if (Con_Printf)
			Con_Printf("fastdl: %s (%lu KB, %lu KB/s, verified)\n", e->path, (unsigned long)e->size / 1024,
				ms ? (DWORD)((unsigned long long)e->size * 1000 / 1024 / ms) : (DWORD)e->size / 1024);
	}
	return 1;
}

/* ---- the hooks ------------------------------------------------------------------------------- */

/* engine-specific name limits (engines.h): names the engine itself would mishandle */
static int EngineNameUnsafe(const char *s, size_t n)
{
	size_t i;
	if (g_eng->name_max && n > g_eng->name_max)
		return 1;
	for (i = 0; i < n; i++)
	{
		unsigned char c = (unsigned char)s[i];
		if ((g_eng->flags & ENG_NAME_ASCII) && (c < 0x20 || c > 0x7e))
			return 1;
		if ((g_eng->flags & ENG_NAME_IS_FORMAT) && c == '%')
			return 1;
	}
	return 0;
}

/* the player's cl_allowdownload: 0 = no HTTP downloads either (the engine checks it only after us) */
static int AllowDownload(void)
{
	static int last = -1;
	float v = 0;
	int on = ReadMem(g_eng->allowdl_cvar + g_eng->allowdl_off, &v, sizeof(v)) && v != 0.0f;
	if (on != last)
	{
		if (!on)
			Log("fastdl: cl_allowdownload is 0, no HTTP downloads\n");
		last = on;
	}
	return on;
}

static int FileMissing(const char *name)
{
	void *f = NULL;
	int r;
	if (g_eng->fs_api == FS_SIZE)
		return FS_FileSize(name) == -1;
	r = FS_FOpen(name, &f);
	if (f)
		FS_FClose(f);
	return r == -1;
}

/* The engine passes filename in its shared va() buffer. Engine functions we call (Con_Printf with
 * -condebug, the file system) can reuse that buffer, which would hand the original function - and the
 * caller after us - a corrupted name (seen on XP: "dlfile sound/fastdl_e2eC:\Half-Life/valve/qconsole.log").
 * So all work is done on a private copy, and the engine's bytes are put back before returning.
 * Returns 1 if the resource is blocked: the caller reports it as present without calling the engine, which
 * then neither downloads it nor asks the server for it. */
static int CheckResource(const char *filename)
{
	char name[FDL_PATH_MAX + 64], safe[128];
	uint32_t limit;
	size_t n = strlen(filename);
	fdl_class_t cls;

	if (n >= sizeof(name))
		/* longer than any allowed resource: never fetched; still refuse it if it is unsafe */
		return EngineNameUnsafe(filename, n) || fdl_classify(filename, &limit) == FDL_BLOCK;
	memcpy(name, filename, n + 1);
	cls = EngineNameUnsafe(name, n) ? FDL_BLOCK : fdl_classify(name, &limit);
	if (g_debug)
		Log("CheckFile(%s): class %d\n", Safe(name, safe, sizeof(safe)), cls);

	if (cls == FDL_BLOCK)
	{
		Log("fastdl: blocked unsafe download %s\n", Safe(name, safe, sizeof(safe)));
		if (Con_Printf)
			Con_Printf("fastdl: blocked unsafe download %s\n", Safe(name, safe, sizeof(safe)));
	}
	else if (cls == FDL_FETCH && AllowDownload() && FileMissing(name))
	{
		/* the gap since the end of the previous call decides here whether a new budget starts */
		g_sess.burst_in_call = 0;
		BurstLeft();
		g_sess.burst_in_call = 1;
		if (SessionFor())
		{
			const fdl_entry_t *e = fdl_manifest_find(&g_sess.man, name);
			if (!e && GetTickCount() - g_sess.man_time > MANIFEST_REFRESH_MS)
			{
				int lr = LoadManifest();
				if (lr > 0)
					e = fdl_manifest_find(&g_sess.man, name);
				else
					CountError(lr < 0 ? "manifest signature/format invalid" : "manifest not available");
			}
			if (e && e->size <= limit)
				Fetch(e);
			else if (g_debug)
				Log("fastdl: %s not in manifest\n", Safe(name, safe, sizeof(safe)));
		}
		/* end of this call's HTTP work: the idle gap that starts a new budget counts from here, so even slow
		 * or stalled transfers cannot stretch one loading beyond BURST_MS */
		g_sess.burst_in_call = 0;
		g_sess.burst_last = GetTickCount();
	}
	if (memcmp(filename, name, n + 1))
		memcpy((char *)filename, name, n + 1);	/* changed means writable engine memory */
	return cls == FDL_BLOCK;
}

/* 1.1.x: int CL_CheckFile(sizebuf_t *msg, const char *name) */
static int __cdecl Hook_CheckFile(void *msg, const char *filename)
{
	if (filename && CheckResource(filename))
		return 1;
	return ((CheckFile_t)g_tramp)(msg, filename);
}

/* 1.0.x: int CL_CheckOrDownloadFile(const char *name) */
static int __cdecl Hook_CheckOrDownload(const char *filename)
{
	if (filename && CheckResource(filename))
		return 1;
	return ((CheckOrDl_t)g_tramp)(filename);
}

/* The server names a file transfer in its first fragment, independent of what the client asked for, and
 * the engine writes it to disk if the name has no ".." and the file does not exist yet - a hostile
 * server can push autoexec.cfg or similar without any request. Unsafe names are turned into "..":
 * the engine then rejects the transfer itself ("relative path, ignoring") and flushes the stream.
 * ENG_UNBOUNDED_NAMES engines strcpy the whole name before that check, so the refusal also ends the name
 * after "..", and a name without terminator in the first 0x103 bytes is refused ("!" names too).
 * 1.0.x has no such stream (svc_download writes only names the client requested): no hook there. */
static int __cdecl Hook_CopyFileFragments(BYTE *chan, void *arg2)
{
	const push_t *p = &g_eng->push;
	DWORD ready = 0, frag = 0, data = 0, isfile = 1;
	int size = 0, n = 0, lim;
	BYTE raw[0x104];
	char name[0x104], safe[128];

	if (chan && ReadMem((DWORD)chan + p->ready, &ready, 4) && ready
		&& ReadMem((DWORD)chan + p->frags, &frag, 4) && frag
		&& (!p->fb_isfile || (ReadMem(frag + p->fb_isfile, &isfile, 4) && isfile))
		&& ReadMem(frag + p->fb_data, &data, 4) && data && ReadMem(frag + p->fb_size, &size, 4) && size >= 2)
	{
		lim = size < 0x103 ? size : 0x103;
		if (ReadMem(data, raw, (SIZE_T)lim))
		{
			int unbounded = (g_eng->flags & ENG_UNBOUNDED_NAMES) != 0;
			/* same end rule as MSG_ReadString: NUL or 0xFF (-1 as signed char) */
			while (n < lim && raw[n] && raw[n] != 0xFF)
			{
				name[n] = (char)raw[n];
				n++;
			}
			name[n] = 0;
			/* COM_WriteFile builds "<com_gamedir>/<name>" in 260 bytes (_snprintf, or sprintf on
			 * ENG_UNBOUNDED_NAMES engines): such names never reach it */
			if ((unbounded && n == 0x103)
				|| (n > 0 && (fdl_classify(name, NULL) == FDL_BLOCK || (name[0] != '!' && GameDirLen() + 1 + n >= MAX_PATH))))
			{
				((BYTE *)data)[0] = '.';
				((BYTE *)data)[1] = '.';
				if (unbounded && size > 2)
					((BYTE *)data)[2] = 0;
				Log("fastdl: refused file pushed by the server: %s\n", Safe(name, safe, sizeof(safe)));
				if (Con_Printf)
					Con_Printf("fastdl: refused file pushed by the server: %s\n", Safe(name, safe, sizeof(safe)));
			}
			else if (g_debug)
				Log("CopyFileFragments(%s)\n", Safe(name, safe, sizeof(safe)));
		}
	}
	return ((CopyFile_t)g_tramp_cf)(chan, arg2);
}

static void *CheckHook(const engine_t *e)
{
	return e->api == API_CHECKORDOWNLOAD_NAME ? (void *)Hook_CheckOrDownload : (void *)Hook_CheckFile;
}

/* ---- engine detection ------------------------------------------------------------------------ */

/* Copies row into rt with every address as a VA. Module rows: only if that module is loaded and its PE
 * header has the row's TimeDateStamp and SizeOfImage. */
static int Resolve(const engine_t *row, engine_t *rt, HMODULE *mod)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS32 nt;
	DWORD base;

	*rt = *row;
	*mod = NULL;
	if (!row->module)
		return 1;
	*mod = GetModuleHandleA(row->module);
	if (!*mod)
		return 0;
	base = (DWORD)*mod;
	if (!ReadMem(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE
		|| !ReadMem(base + (DWORD)dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE
		|| nt.FileHeader.TimeDateStamp != row->stamp || nt.OptionalHeader.SizeOfImage != row->imagesize)
		return 0;
#define REBASE(f) if (rt->f) rt->f += base
	REBASE(check.addr); REBASE(filesize.addr); REBASE(fclose.addr); REBASE(conprintf.addr); REBASE(copyfile.addr);
	REBASE(serverinfo); REBASE(cmd_functions); REBASE(net_from); REBASE(gamedir); REBASE(allowdl_cvar);
	REBASE(cbuf.addr); REBASE(cmd_text);
#undef REBASE
	return 1;
}

static int SiteMatches(const site_t *s)
{
	BYTE b[16];
	return !s->addr || (ReadMem(s->addr, b, s->siglen) && !memcmp(b, s->sig, s->siglen));
}

/* 1 = this engine build is mapped with exactly the expected bytes at every address we use, and its data
 * looks as expected (the cvar points at its name, the command list is set up) */
static int EngineMatches(const engine_t *e, HMODULE mod)
{
	DWORD p;
	char nm[17];
	int ours, other;

	if (!SiteMatches(&e->check) || !SiteMatches(&e->filesize) || !SiteMatches(&e->fclose)
		|| !SiteMatches(&e->conprintf) || !SiteMatches(&e->copyfile) || !SiteMatches(&e->cbuf))
		return 0;
	if (e->cmd_text)
	{
		/* Cbuf_AddText: mov ecx,[&cursize] / add esp,4 / add ecx,eax / mov eax,[&maxsize] */
		DWORD cur, max;
		if (!e->cbuf.addr || !ReadMem(e->cbuf.addr - 4, &cur, 4) || !ReadMem(e->cbuf.addr + 6, &max, 4)
			|| cur != e->cmd_text + 8 || max != e->cmd_text + 4)
			return 0;
	}
	if (!ReadMem(e->allowdl_cvar, &p, 4) || !ReadMem(p, nm, sizeof(nm)) || memcmp(nm, "cl_allowdownload", 17))
		return 0;
	if (e->flags & ENG_EXPORTS)
	{
		if (!mod || (DWORD)GetProcAddress(mod, "Con_Printf") != e->conprintf.addr || !GetProcAddress(mod, "Cmd_Argv"))
			return 0;
	}
	if (e->si_src == SI_PLUGIN_CMD && (!(e->flags & ENG_EXPORTS) || !CmdList(e->cmd_functions, &ours, &other) || other))
		return 0;
	return 1;
}

static int JumpsTo(DWORD at, void *fn)
{
	BYTE b[5];
	DWORD rel = (DWORD)fn - (at + 5);
	return ReadMem(at, b, 5) && b[0] == 0xE9 && !memcmp(b + 1, &rel, 4);
}

static int HookIntact(void)
{
	return JumpsTo(g_eng->check.addr, CheckHook(g_eng))
		&& (!g_eng->copyfile.addr || JumpsTo(g_eng->copyfile.addr, Hook_CopyFileFragments));
}

/* trampoline: the moved prologue, then a jump back behind it; read+execute only (W^X) */
static BYTE *MakeTramp(DWORD target, const BYTE *prologue, int len)
{
	DWORD old;
	BYTE *t = (BYTE *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!t)
		return NULL;
	memcpy(t, prologue, len);
	t[len] = 0xE9;
	*(DWORD *)(t + len + 1) = (target + len) - (DWORD)(t + len + 5);
	if (!VirtualProtect(t, 32, PAGE_EXECUTE_READ, &old))
		return NULL;
	return t;
}

/* Called with all other threads suspended: no heap, no CRT, no logging in here. */
static int Patch(DWORD target, int len, void *fn)
{
	BYTE *p = (BYTE *)target, code[16];
	DWORD old, rel = (DWORD)fn - (target + 5);
	SIZE_T w = 0;
	int ok;
	code[0] = 0xE9;
	memcpy(code + 1, &rel, 4);
	memset(code + 5, 0x90, len - 5);
	if (!VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &old))
		return 0;
	/* not a plain store: the watchdog may race an engine unload (renderer change) */
	ok = WriteProcessMemory(GetCurrentProcess(), p, code, len, &w) && w == (SIZE_T)len;
	VirtualProtect(p, len, old, &old);
	FlushInstructionCache(GetCurrentProcess(), p, len);
	return ok;
}

#define MAX_SUSPEND 256

typedef struct { DWORD from, len; } range_t;

/* Suspends every other thread of the process. Returns the number suspended, -1 if one of them is inside
 * one of the ranges (all resumed again; the caller retries) or the thread list is unavailable. Ranges:
 * prologues about to be patched (past their first byte, a thread there would resume in the middle of the
 * jump), or Cmd_AddCommand while the command list head is replaced. The .asi can be loaded while the
 * engine runs (Miles loads it from the CD audio thread or during voice init on the engine thread), so a
 * patch must not race the engine thread. */
static int SuspendOthers(HANDLE *h, const range_t *r, int nr)
{
	THREADENTRY32 te;
	DWORD pid = GetCurrentProcessId(), self = GetCurrentThreadId();
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	int n = 0, bad = 0, i, k;

	if (snap == INVALID_HANDLE_VALUE)
		return -1;
	te.dwSize = sizeof(te);
	for (i = Thread32First(snap, &te); i && !bad; i = Thread32Next(snap, &te))
	{
		CONTEXT c;
		HANDLE t;
		if (te.th32OwnerProcessID != pid || te.th32ThreadID == self)
			continue;
		if (n == MAX_SUSPEND)
		{
			bad = 1;
			break;
		}
		t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
		if (!t)
			continue;		/* exited since the snapshot */
		if (SuspendThread(t) == (DWORD)-1)
		{
			CloseHandle(t);
			continue;
		}
		h[n++] = t;
		c.ContextFlags = CONTEXT_CONTROL;
		if (!GetThreadContext(t, &c))
			bad = 1;
		for (k = 0; k < nr && !bad; k++)
			if (r[k].from && c.Eip > r[k].from && c.Eip < r[k].from + r[k].len)
				bad = 1;
	}
	CloseHandle(snap);
	if (bad)
	{
		for (i = 0; i < n; i++)
		{
			ResumeThread(h[i]);
			CloseHandle(h[i]);
		}
		return -1;
	}
	return n;
}

static void ResumeOthers(HANDLE *h, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		ResumeThread(h[i]);
		CloseHandle(h[i]);
	}
}

/* SI_PLUGIN_CMD: links our "fullserverinfo" node at the head of cmd_functions if it is not there (also
 * again if an engine Cmd_AddCommand raced us and dropped it). The node is complete before the one pointer
 * store; the engine thread only reads the list after init. */
static void EnsureCommand(void)
{
	HANDLE th[MAX_SUSPEND];
	range_t r = { g_cmd_add, 0x100 };
	int ours, other, n;
	DWORD head;

	if (!g_eng || g_eng->si_src != SI_PLUGIN_CMD || (ReadMem(g_eng->cmd_functions, &head, 4) && head == (DWORD)&g_cmd)
		|| !CmdList(g_eng->cmd_functions, &ours, &other) || ours || other)
		return;
	n = SuspendOthers(th, &r, 1);
	if (n < 0)
		return;		/* retried by the watchdog */
	if (ReadMem(g_eng->cmd_functions, &head, 4))
	{
		g_cmd.next = head;
		InterlockedExchange((LONG volatile *)g_eng->cmd_functions, (LONG)(DWORD)&g_cmd);
	}
	ResumeOthers(th, n);
	Log("fastdl: command fullserverinfo added (engine without one)\n");
}

static int InstallHook(void)
{
	int i;
	for (i = 0; i < N_ENGINES; i++)
	{
		engine_t e;
		HMODULE mod;
		BYTE *t1, *t2 = NULL;
		HANDLE th[MAX_SUSPEND];
		range_t r[2];
		int n, ok;

		if (!Resolve(&g_engines[i], &e, &mod) || !EngineMatches(&e, mod))
			continue;
		/* fresh trampolines per (re)hook; old ones stay valid for calls still in flight */
		t1 = MakeTramp(e.check.addr, e.check.sig, e.check.prologue);
		if (e.copyfile.addr)
			t2 = MakeTramp(e.copyfile.addr, e.copyfile.sig, e.copyfile.prologue);
		r[0].from = e.check.addr; r[0].len = e.check.prologue;
		r[1].from = e.copyfile.addr; r[1].len = e.copyfile.prologue;
		n = t1 && (t2 || !e.copyfile.addr) ? SuspendOthers(th, r, 2) : -1;
		if (n < 0)
		{
			if (t1) VirtualFree(t1, 0, MEM_RELEASE);
			if (t2) VirtualFree(t2, 0, MEM_RELEASE);
			return 0;		/* retried by the watchdog */
		}
		g_rt = e;
		g_eng = &g_rt;
		g_tramp = t1;
		g_tramp_cf = t2;
		FS_FileSize = (FileSize_t)e.filesize.addr;
		FS_FOpen = (FOpen_t)e.filesize.addr;
		FS_FClose = (FClose_t)e.fclose.addr;
		Con_Printf = (ConPrintf_t)e.conprintf.addr;
		Cmd_Argv = (e.flags & ENG_EXPORTS) ? (CmdArgv_t)(DWORD)GetProcAddress(mod, "Cmd_Argv") : NULL;
		g_cmd_add = (e.flags & ENG_EXPORTS) ? (DWORD)GetProcAddress(mod, "Cmd_AddCommand") : 0;
		/* the file write guard first: from then on nothing unsafe is written, even if the second patch fails */
		ok = (!e.copyfile.addr || Patch(e.copyfile.addr, e.copyfile.prologue, Hook_CopyFileFragments))
			&& Patch(e.check.addr, e.check.prologue, CheckHook(&e));
		ResumeOthers(th, n);
		if (!ok)
			return 0;
		Log("fastdl: hooked %s (base %08lx): %s at %08lx, push guard %s%08lx, %lu ms after load (thread %lu)\n",
			e.name, (DWORD)mod, e.api == API_CHECKORDOWNLOAD_NAME ? "CL_CheckOrDownloadFile" : "CL_CheckFile",
			e.check.addr, e.copyfile.addr ? "at " : "not needed ", e.copyfile.addr, GetTickCount() - g_loaded,
			GetCurrentThreadId());
		EnsureCommand();
		return 1;
	}
	return 0;
}

static int EngineMapped(void)
{
	BYTE b;
	int i;
	if (GetModuleHandleA("hw.dll") || GetModuleHandleA("sw.dll"))
		return 1;
	for (i = 0; i < N_ENGINES; i++)
		if (!g_engines[i].module && ReadMem(g_engines[i].check.addr, &b, 1))
			return 1;
	return 0;
}

/* what is mapped: tells an unknown engine build from a missing engine */
static void LogEngineBytes(void)
{
	static const char *const mods[] = { "hw.dll", "sw.dll" };
	int i, j;
	for (i = 0; i < 2; i++)
	{
		HMODULE h = GetModuleHandleA(mods[i]);
		IMAGE_DOS_HEADER dos;
		IMAGE_NT_HEADERS32 nt;
		if (h && ReadMem((DWORD)h, &dos, sizeof(dos)) && ReadMem((DWORD)h + (DWORD)dos.e_lfanew, &nt, sizeof(nt)))
			Log("fastdl: %s at %08lx: TimeDateStamp %08lx, SizeOfImage %08lx\n", mods[i], (DWORD)h,
				nt.FileHeader.TimeDateStamp, nt.OptionalHeader.SizeOfImage);
	}
	for (i = 0; i < N_ENGINES; i++)
	{
		BYTE t[16];
		if (g_engines[i].module)
			continue;
		if (!ReadMem(g_engines[i].check.addr, t, sizeof(t)))
		{
			Log("fastdl: %s: %08lx not mapped\n", g_engines[i].name, g_engines[i].check.addr);
			continue;
		}
		Log("fastdl: %s: bytes at %08lx:", g_engines[i].name, g_engines[i].check.addr);
		for (j = 0; j < 16; j++) Log(" %02x", t[j]);
		Log(" \n");
	}
}

/* Watchdog for the life of the process: installs the hook once the engine is mapped, and again if
 * hl.exe maps a fresh engine (renderer change, restart) - protection must not silently disappear. */
static DWORD WINAPI HookThread(LPVOID arg)
{
	int warned = 0;
	DWORD start = GetTickCount();
	(void)arg;
	for (;;)
	{
		if (!g_eng || !HookIntact())
		{
			if (InstallHook())
				warned = 0;
			else if (!warned && GetTickCount() - start > 120000)
			{
				/* after a successful hook this is the engine leaving (game exit, renderer change), not an unknown build */
				if (g_eng)
					Log("fastdl: engine module unmapped or hook lost (%s) - waiting for a new engine\n", g_eng->name);
				else
					Log("fastdl: no known engine build mapped after 120 s - not active\n");
				LogEngineBytes();
				warned = 1;
			}
		}
		else
			EnsureCommand();
		Sleep(GetTickCount() - start < 120000 ? 100 : 1000);
	}
	return 0;
}

#ifdef FASTDL_PROXY
int WsProxyInit(void);
#endif

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH)
	{
		char exe[MAX_PATH], self[MAX_PATH], dbg[MAX_PATH], *slash;
		HANDLE t;
		HMODULE pin;
		FILETIME ct, xt, kt, ut, now;
		ULONGLONG up = 0;
		g_loaded = GetTickCount();
		DisableThreadLibraryCalls(inst);
		InitializeCriticalSection(&g_log_lock);
#ifdef FASTDL_PROXY
		if (!WsProxyInit())
			return FALSE;		/* without the real winsock the game cannot run: fail loudly */
#endif
		/* GetModuleFileNameA does not terminate on truncation (XP) */
		if (!GetModuleFileNameA(inst, g_dir, sizeof(g_dir) - 1))
			return TRUE;
		g_dir[sizeof(g_dir) - 1] = 0;
		memcpy(self, g_dir, sizeof(self));
		slash = strrchr(g_dir, '\\');
		if (slash) slash[1] = 0; else g_dir[0] = 0;
		exe[0] = 0;
		GetModuleFileNameA(NULL, exe, sizeof(exe) - 1);
		exe[sizeof(exe) - 1] = 0;
		ModPath(dbg, sizeof(dbg), "fastdl.debug");
		g_debug = GetFileAttributesA(dbg) != INVALID_FILE_ATTRIBUTES;
		GetSystemTimeAsFileTime(&now);
		if (GetProcessTimes(GetCurrentProcess(), &ct, &xt, &kt, &ut))
			up = ((((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime) - (((ULONGLONG)ct.dwHighDateTime << 32) | ct.dwLowDateTime)) / 10000;
		Log("=== FastDL-WON %s session start ===\n", FASTDL_VERSION);
		Log("FastDL-WON %s loaded: %s, process %s, %lu ms after process start, thread %lu, engine %s%s\n", FASTDL_VERSION, self, exe,
			(unsigned long)up, GetCurrentThreadId(), EngineMapped() ? "mapped" : "not mapped yet",
			g_debug ? ", debug" : "");

		/* wsock32.dll (process start) and fastdl.asi (Miles) may both be installed: one hook per
		 * process. The marker lives in this process's environment, out of reach of other processes. */
		if (GetEnvironmentVariableA("FASTDL_ACTIVE", dbg, sizeof(dbg)))
		{
			Log("fastdl: another fastdl instance is active in this process, this one stays idle\n");
			return TRUE;
		}
		SetEnvironmentVariableA("FASTDL_ACTIVE", "1");
		/* Miles frees its *.asi providers in AIL_shutdown (voice_miles.dll calls it when the last voice
		 * codec goes away, seen around a reconnect): pinned, the hooks and the watchdog never point into an
		 * unmapped image, and the next AIL_startup gets this instance back without a new DllMain. */
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCSTR)DllMain, &pin)
			&& !LoadLibraryA(self))		/* a reference that is never released */
			Log("fastdl: could not pin the module (%lu)\n", GetLastError());
		/* hook right away if the engine is already running (load during voice setup on the engine thread);
		 * otherwise the watchdog hooks once the engine is mapped */
		InstallHook();
		t = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
		if (t)
			CloseHandle(t);
	}
	return TRUE;
}
