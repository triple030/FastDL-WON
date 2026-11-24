/*
 * fastdl core - see core.h. No Windows, no engine, no global state.
 */
#include "core.h"
#include "third_party/monocypher/monocypher.h"
#include "third_party/monocypher/monocypher-ed25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lower(int c)
{
	return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static int is_alnum(int c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int is_sep(int c)
{
	return c == '/' || c == '\\';
}

/* case-insensitive equality of s[0..n) with a NUL-terminated lowercase literal */
static int eq_n(const char *s, size_t n, const char *lit)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (!lit[i] || lower((unsigned char)s[i]) != lit[i])
			return 0;
	return lit[n] == 0;
}

/* ---- classification ----------------------------------------------------------------------- */

/* extensions that must never be written by a download, in-band or HTTP */
static const char *const g_blocked_ext[] =
{
	"dll", "exe", "com", "bat", "cmd", "scr", "pif", "cpl", "msi", "msp", "asi", "flt", "m3d", "mix",
	"vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "reg", "inf", "ini", "cfg", "rc",
	"gam", "lst", "sys", "drv", "ocx", "so", "dylib", "ps1", "psm1", "jar", "cab", "chm", "hlp", "hpk",
	"scf", "sct", "vxd", "tlb", "ax", "acm", "manifest", NULL
};

/* top-level directories that hold code or engine data */
static const char *const g_blocked_dir[] = { "cl_dlls", "dlls", "addons", "bin", "platform", NULL };

typedef struct
{
	const char *dir;		/* first path component, NULL = file in the game dir root */
	int subdirs;			/* deeper paths allowed */
	const char *ext;
	uint32_t limit;
} rule_t;

#define MB (1024u * 1024u)
static const rule_t g_rules[] =
{
	{ NULL,        0, "wad", 64 * MB },
	{ "maps",      0, "bsp", 64 * MB },
	{ "maps",      0, "res", 256 * 1024 },
	{ "maps",      0, "txt", 256 * 1024 },
	{ "models",    1, "mdl", 32 * MB },
	{ "models",    1, "bmp", 4 * MB },		/* player model remap textures */
	{ "sound",     1, "wav", 16 * MB },
	{ "sound",     1, "mp3", 32 * MB },
	{ "media",     1, "mp3", 32 * MB },
	{ "sprites",   1, "spr", 8 * MB },
	{ "sprites",   1, "txt", 256 * 1024 },
	{ "gfx",       1, "tga", 16 * MB },
	{ "gfx",       1, "bmp", 16 * MB },
	{ "overviews", 0, "bmp", 4 * MB },
	{ "overviews", 0, "tga", 4 * MB },
	{ "overviews", 0, "txt", 256 * 1024 },
};

static int reserved_device(const char *comp, size_t n)
{
	static const char *const names[] = { "con", "prn", "aux", "nul", "conin$", "conout$", "clock$", NULL };
	size_t base = 0;
	int i;
	while (base < n && comp[base] != '.')
		base++;
	while (base && comp[base - 1] == ' ')		/* "con .bsp" is CON as well */
		base--;
	for (i = 0; names[i]; i++)
		if (eq_n(comp, base, names[i]))
			return 1;
	/* COM1..9, LPT1..9; Windows also counts the superscript digits (code page dependent bytes) */
	if (base == 4 && (eq_n(comp, 3, "com") || eq_n(comp, 3, "lpt"))
		&& ((comp[3] >= '0' && comp[3] <= '9') || (unsigned char)comp[3] >= 0x80))
		return 1;
	return 0;
}

/* BLOCK check: works on any string, even ones the strict rules would not accept */
static int blocked(const char *path)
{
	const char *p, *last = path, *dot = NULL;
	size_t n, first;
	int i;

	/* characters Windows refuses in names, absolute paths, streams/drives, ".." */
	if (path[0] == '/' || path[0] == '\\' || strpbrk(path, ":<>\"|*?") || strstr(path, ".."))
		return 1;
	{
		/* in any component: "." ("./dlls/x"), trailing dots or spaces (Windows drops them, so "cl_dlls. " is
		 * cl_dlls and ". " is the current folder), and device names (CON, COM1.bsp) */
		const char *c = path;
		for (p = path;; p++)
			if (!*p || is_sep((unsigned char)*p))
			{
				size_t n = (size_t)(p - c);
				if ((n == 1 && c[0] == '.') || (n && (c[n - 1] == '.' || c[n - 1] == ' ')) || (n && reserved_device(c, n)))
					return 1;
				if (!*p)
					break;
				c = p + 1;
			}
	}
	for (p = path; *p; p++)
		if (is_sep((unsigned char)*p))
			last = p + 1;

	/* Windows drops trailing dots and spaces: "autoexec.cfg. " opens autoexec.cfg */
	n = strlen(last);
	while (n && (last[n - 1] == '.' || last[n - 1] == ' '))
		n--;
	for (p = last; p < last + n; p++)
		if (*p == '.')
			dot = p;
	if (dot)
	{
		/* strip ADS-like and stream suffixes are impossible (':' rejected above) */
		size_t elen = (size_t)(last + n - dot - 1);
		for (i = 0; g_blocked_ext[i]; i++)
			if (eq_n(dot + 1, elen, g_blocked_ext[i]))
				return 1;
	}

	first = 0;
	while (path[first] && !is_sep((unsigned char)path[first]))
		first++;
	if (path[first])
	{
		size_t f = first;
		while (f && (path[f - 1] == '.' || path[f - 1] == ' '))
			f--;
		for (i = 0; g_blocked_dir[i]; i++)
			if (eq_n(path, f, g_blocked_dir[i]))
				return 1;
	}
	return 0;
}

/* "!MD5" + 32 hex digits: the engine's name for player logos/sprays (customization) */
static int custom_resource(const char *path, size_t len)
{
	size_t i;
	if (len != 36 || memcmp(path, "!MD5", 4))
		return 0;
	for (i = 4; i < 36; i++)
		if (!((path[i] >= '0' && path[i] <= '9') || (lower((unsigned char)path[i]) >= 'a' && lower((unsigned char)path[i]) <= 'f')))
			return 0;
	return 1;
}

/* What the engine may still download in-band (not over HTTP): game content types only, so an
 * unknown type (.htm, .theme, .library-ms, commandmenu.txt, ...) can never be written. Text files
 * only where the HTTP rules allow them. Called after blocked(). */
static int inband_ok(const char *path)
{
	static const char *const content[] = { "bsp", "wad", "wav", "mp3", "mdl", "spr", "tga", "bmp", "sc", NULL };
	const char *last = path, *p, *dot = NULL;
	size_t n;
	int i;
	for (p = path; *p; p++)
		if (is_sep((unsigned char)*p))
			last = p + 1;
	n = strlen(last);
	while (n && (last[n - 1] == '.' || last[n - 1] == ' '))
		n--;
	for (p = last; p < last + n; p++)
		if (*p == '.')
			dot = p;
	if (!dot)
		return 0;
	for (i = 0; content[i]; i++)
		if (eq_n(dot + 1, (size_t)(last + n - dot - 1), content[i]))
			return 1;
	return 0;
}

static int path_char_ok(int c)
{
	return is_alnum(c) || c == '_' || c == '-' || c == '.' || c == '+' || c == '!' || c == '(' || c == ')'
		|| c == '[' || c == ']';
}

fdl_class_t fdl_classify(const char *path, uint32_t *limit)
{
	const char *p, *comp, *first_end = NULL, *ext = NULL;
	size_t len, ncomp = 0;
	unsigned i;

	if (limit)
		*limit = 0;
	if (!path || !path[0])
		return FDL_PASS;
	len = strlen(path);
	if (blocked(path))
		return FDL_BLOCK;
	if (path[0] == '!')			/* custom resources (logos/sprays): exactly "!MD5" + 32 hex digits */
		return custom_resource(path, len) ? FDL_PASS : FDL_BLOCK;
	if (len > FDL_PATH_MAX)
		return inband_ok(path) ? FDL_PASS : FDL_BLOCK;

	/* strict shape: components of allowed characters, no empty/dot-edged/device/8.3 names */
	comp = path;
	for (p = path;; p++)
	{
		int c = (unsigned char)*p;
		if (c == 0 || is_sep(c))
		{
			size_t n = (size_t)(p - comp);
			if (n == 0 || comp[0] == '.' || comp[n - 1] == '.' || reserved_device(comp, n))
				return inband_ok(path) ? FDL_PASS : FDL_BLOCK;
			if (++ncomp > 8)
				return inband_ok(path) ? FDL_PASS : FDL_BLOCK;
			if (!first_end)
				first_end = p;
			if (c == 0)
				break;
			comp = p + 1;
			continue;
		}
		if (!path_char_ok(c))		/* '~' (8.3 aliases), spaces, high bytes: never fetched by us */
			return inband_ok(path) ? FDL_PASS : FDL_BLOCK;
	}
	for (p = comp; *p; p++)
		if (*p == '.')
			ext = p + 1;
	if (!ext)
		return FDL_BLOCK;

	for (i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); i++)
	{
		const rule_t *r = &g_rules[i];
		if (!eq_n(ext, strlen(ext), r->ext))
			continue;
		if (r->dir == NULL)
		{
			if (ncomp != 1)
				continue;
		}
		else
		{
			if (ncomp < 2 || !eq_n(path, (size_t)(first_end - path), r->dir))
				continue;
			if (!r->subdirs && ncomp != 2)
				continue;
		}
		if (limit)
			*limit = r->limit;
		return FDL_FETCH;
	}
	return inband_ok(path) ? FDL_PASS : FDL_BLOCK;
}

int fdl_is_text(const char *path)
{
	size_t n = strlen(path);
	return n > 4 && (eq_n(path + n - 4, 4, ".txt") || eq_n(path + n - 4, 4, ".res"));
}

/* ---- URL / info strings ---------------------------------------------------------------------- */

int fdl_url_parse(const char *url, fdl_url_t *out)
{
	size_t len, i, h = 0, n = 0;
	int prev = '.', label = 0;
	unsigned long port = 80;
	int secure = 0;

	if (!url)
		return 0;
	len = strlen(url);
	if (len > FDL_URL_MAX)
		return 0;
	if (len >= 9 && eq_n(url, 8, "https://"))
		secure = 1, port = 443, i = 8;
	else if (len >= 8 && eq_n(url, 7, "http://"))
		i = 7;
	else
		return 0;
	memset(out, 0, sizeof(*out));
	out->https = secure;
	while (i < len && url[i] != ':' && url[i] != '/')
	{
		int c = lower((unsigned char)url[i]);
		if (c == '.')
		{
			if (prev == '.' || prev == '-')
				return 0;
			label = 0;
		}
		else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
		{
			if ((c == '-' && prev == '.') || ++label > 63)
				return 0;
		}
		else
			return 0;
		if (h >= sizeof(out->host) - 1)
			return 0;
		out->host[h++] = (char)c;
		prev = c;
		i++;
	}
	if (h == 0 || prev == '.' || prev == '-')
		return 0;
	if (i < len && url[i] == ':')
	{
		int digits = 0;
		port = 0;
		for (i++; i < len && url[i] >= '0' && url[i] <= '9'; i++)
		{
			port = port * 10 + (unsigned long)(url[i] - '0');
			if (++digits > 5)
				return 0;
		}
		if (!digits || port < 1 || port > 65535 || (i < len && url[i] != '/'))
			return 0;
	}
	out->port = (unsigned short)port;
	prev = 0;
	for (; i < len; i++)
	{
		int c = (unsigned char)url[i];
		if (c == '/')
		{
			if (prev == '/')
				return 0;
		}
		else if (c == '.')
		{
			if (prev == '.' || prev == '/')		/* "..", "." and hidden segments */
				return 0;
		}
		else if (!(is_alnum(c) || c == '_' || c == '-' || c == '~'))
			return 0;
		out->path[n++] = (char)c;
		prev = c;
	}
	while (n && out->path[n - 1] == '/')
		n--;
	out->path[n] = 0;
	return 1;
}

const char *fdl_url_tree(const fdl_url_t *u)
{
	const char *s = strrchr(u->path, '/');
	return (s && s[1]) ? s + 1 : "-";
}

/* one command [c, e): 'fullserverinfo', blanks, '"', at most FDL_INFO_MAX - 1 bytes without '"' or control
 * characters, '"', optional blanks. -1 = it is a fullserverinfo command but not of that form. */
static int cbuf_one(const char *c, const char *e, char *info)
{
	static const char cmd[] = "fullserverinfo";
	const char *v;
	size_t n;

	while (c < e && (*c == ' ' || *c == '\t'))
		c++;
	if ((size_t)(e - c) < sizeof(cmd) - 1 || memcmp(c, cmd, sizeof(cmd) - 1))
		return 0;
	c += sizeof(cmd) - 1;
	if (c < e && *c != ' ' && *c != '\t' && *c != '"')
		return 0;		/* another command whose name starts with fullserverinfo */
	while (c < e && (*c == ' ' || *c == '\t'))
		c++;
	if (c >= e || *c != '"')
		return -1;
	v = ++c;
	while (c < e && *c != '"')
	{
		if ((unsigned char)*c < 0x20 || *c == 0x7f)
			return -1;
		c++;
	}
	if (c >= e)
		return -1;		/* no closing quote */
	n = (size_t)(c - v);
	if (n >= FDL_INFO_MAX)
		return -1;
	for (c++; c < e; c++)
		if (*c != ' ' && *c != '\t' && *c != '\r')
			return -1;
	memcpy(info, v, n);
	info[n] = 0;
	return 1;
}

int fdl_cbuf_serverinfo(const char *buf, size_t len, char *info)
{
	char tmp[FDL_INFO_MAX];
	size_t i = 0;
	int found = 0;

	memset(info, 0, FDL_INFO_MAX);
	memset(tmp, 0, sizeof(tmp));
	if (len > FDL_CBUF_MAX)
		return 0;
	while (i < len)
	{
		/* Cbuf_Execute: a command ends at a newline, or at a ';' outside quotes */
		size_t s = i;
		int quotes = 0, r;
		while (i < len && buf[i] != '\n' && (buf[i] != ';' || (quotes & 1)))
		{
			if (!buf[i])
			{
				memset(info, 0, FDL_INFO_MAX);
				return 0;
			}
			if (buf[i] == '"')
				quotes++;
			i++;
		}
		r = cbuf_one(buf + s, buf + i, tmp);
		if (r < 0 || (r > 0 && found++))
		{
			memset(info, 0, FDL_INFO_MAX);
			return 0;
		}
		if (r > 0)
			memcpy(info, tmp, FDL_INFO_MAX);
		i++;
	}
	return found;
}

int fdl_info_value(const char *info, const char *key, char *out, size_t outlen)
{
	size_t i = 0, klen = strlen(key);

	if (!outlen)
		return 0;
	out[0] = 0;
	while (i < FDL_INFO_MAX && info[i] == '\\')
	{
		size_t ks = ++i, vs, vn;
		while (i < FDL_INFO_MAX && info[i] && info[i] != '\\')
			i++;
		if (i >= FDL_INFO_MAX || info[i] != '\\')
			return 0;
		vs = ++i;
		while (i < FDL_INFO_MAX && info[i] && info[i] != '\\')
			i++;
		if (i >= FDL_INFO_MAX)
			return 0;			/* unterminated within the buffer */
		vn = i - vs;
		if (vs - 1 - ks == klen && !memcmp(info + ks, key, klen))
		{
			if (vn >= outlen)
				return 0;		/* never act on a truncated value */
			memcpy(out, info + vs, vn);
			out[vn] = 0;
			return 1;
		}
	}
	return 0;
}

int fdl_gamedir_valid(const char *g)
{
	size_t i;
	for (i = 0; g[i]; i++)
		if (i >= 32 || !((g[i] >= 'a' && g[i] <= 'z') || (g[i] >= '0' && g[i] <= '9') || g[i] == '_' || g[i] == '-'))
			return 0;
	return i > 0 && !reserved_device(g, i);
}

/* lowercase only: one canonical encoding, so any changed character changes the value */
static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

int fdl_hex_decode(const char *hex, uint8_t *out, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
	{
		int hi = hexval((unsigned char)hex[2 * i]), lo;
		if (hi < 0)
			return 0;
		lo = hexval((unsigned char)hex[2 * i + 1]);
		if (lo < 0)
			return 0;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return hex[2 * n] == 0;
}

int fdl_url_escape(const char *in, char *out, size_t outlen)
{
	static const char hx[] = "0123456789ABCDEF";
	size_t n = 0;
	for (; *in; in++)
	{
		int c = (unsigned char)*in;
		if (c == '\\')
			c = '/';
		if (is_alnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '/')
		{
			if (n + 1 >= outlen)
				return 0;
			out[n++] = (char)c;
		}
		else
		{
			if (n + 3 >= outlen)
				return 0;
			out[n++] = '%';
			out[n++] = hx[c >> 4];
			out[n++] = hx[c & 15];
		}
	}
	if (n >= outlen)
		return 0;
	out[n] = 0;
	return 1;
}

/* ---- manifest -------------------------------------------------------------------------------- */

int fdl_path_cmp(const char *a, const char *b)
{
	for (;; a++, b++)
	{
		int x = lower((unsigned char)*a), y = lower((unsigned char)*b);
		if (x == '\\') x = '/';
		if (y == '\\') y = '/';
		if (x != y || !x)
			return x - y;
	}
}

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (errlen)
	{
		size_t n = strlen(msg);
		if (n >= errlen)
			n = errlen - 1;
		memcpy(err, msg, n);
		err[n] = 0;
	}
}

#define HDR		"FASTDL-WON1\n"
#define HDR_LEN	(sizeof(HDR) - 1)
#define SIG_LEN	133			/* "sig " + 128 hex + "\n" */

/* Ed25519 public keys of small order (and their non-canonical encodings, sign bit ignored): with such a key
 * a trivial signature verifies for any message (same list as libsodium's has_small_order) */
static int small_order_key(const uint8_t k[32])
{
	static const uint8_t bad[7][32] = {
		{ 0 },
		{ 1 },
		{ 0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
		  0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05 },
		{ 0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
		  0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a },
		{ 0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f },
		{ 0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f },
		{ 0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f },
	};
	int i;
	for (i = 0; i < 7; i++)
		if (!memcmp(k, bad[i], 31) && (k[31] & 0x7f) == bad[i][31])
			return 1;
	return 0;
}

int fdl_manifest_load(fdl_manifest_t *m, const uint8_t *data, size_t len, const uint8_t pubkey[32],
	const char *tree, char *err, size_t errlen)
{
	char treeline[48];
	size_t tl, start;
	uint8_t sig[64];
	char sighex[129];
	size_t body, i, lines = 0;
	char *t;
	int n = 0;

	memset(m, 0, sizeof(*m));
	set_err(err, errlen, "");
	if (len > FDL_MANIFEST_MAX)
		return set_err(err, errlen, "manifest too big"), 0;
	if (len < HDR_LEN + SIG_LEN || memcmp(data, HDR, HDR_LEN))
		return set_err(err, errlen, "not a manifest"), 0;

	body = len - SIG_LEN;
	if (data[body - 1] != '\n' || memcmp(data + body, "sig ", 4) || data[len - 1] != '\n')
		return set_err(err, errlen, "no signature line"), 0;
	memcpy(sighex, data + body + 4, 128);
	sighex[128] = 0;
	if (!fdl_hex_decode(sighex, sig, 64))
		return set_err(err, errlen, "bad signature encoding"), 0;

	if (small_order_key(pubkey))
		return set_err(err, errlen, "weak signing key"), 0;

	/* nothing of the content is looked at before the signature holds */
#ifndef FDL_FUZZ_SKIP_SIGNATURE	/* only test/fuzz.sh defines this, to reach the parser */
	if (crypto_ed25519_check(sig, pubkey, data, body) != 0)
#else
	if (0)
#endif
		return set_err(err, errlen, "signature check failed"), 0;

	/* "tree <name>": binds the manifest to the URL it was fetched from (no substitution of another
	 * mod's validly signed manifest) */
	if (strlen(tree) > 32)
		return set_err(err, errlen, "bad tree name"), 0;
	tl = (size_t)sprintf(treeline, "tree %s", tree);
	if (body - HDR_LEN < tl + 1 || memcmp(data + HDR_LEN, treeline, tl) || (data[HDR_LEN + tl] != '\n' && data[HDR_LEN + tl] != ' '))
		return set_err(err, errlen, "manifest is for another tree"), 0;
	start = HDR_LEN + tl;
	/* optional " <serial>": decimal, 1-19 digits, no leading zero; a client refuses a lower serial than one it
	 * has already seen for the same key and tree (replay of an older signed manifest) */
	if (data[start] == ' ')
	{
		size_t d = 0;
		for (start++; start < body && data[start] >= '0' && data[start] <= '9' && d < 20; start++, d++)
			m->serial = m->serial * 10 + (uint64_t)(data[start] - '0');
		if (d == 0 || d > 19 || (d > 1 && data[start - d] == '0') || start >= body || data[start] != '\n')
			return set_err(err, errlen, "bad serial"), 0;
	}
	start++;

	for (i = start; i < body; i++)
	{
		if (data[i] == '\n')
			lines++;
		else if (data[i] == 0 || data[i] == '\r')
			return set_err(err, errlen, "control character"), 0;
	}
	if (lines > FDL_ENTRIES_MAX)
		return set_err(err, errlen, "too many entries"), 0;

	m->text = (char *)malloc(body - start + 1);
	m->entries = (fdl_entry_t *)calloc(lines ? lines : 1, sizeof(fdl_entry_t));
	if (!m->text || !m->entries)
	{
		fdl_manifest_free(m);
		return set_err(err, errlen, "out of memory"), 0;
	}
	memcpy(m->text, data + start, body - start);
	m->text[body - start] = 0;

	for (t = m->text; *t; )
	{
		fdl_entry_t *e = &m->entries[n];
		char *nl = strchr(t, '\n'), *path;
		unsigned long long size = 0;
		uint32_t limit;
		int digits = 0;

		if (!nl)
			break;			/* cannot happen: body ends with '\n' */
		*nl = 0;
		if (strlen(t) < 64 + 1 + 1 + 1 + 1 || t[64] != ' ')
			goto bad;
		t[64] = 0;
		if (!fdl_hex_decode(t, e->hash, FDL_HASH_LEN))
			goto bad;
		for (path = t + 65; *path >= '0' && *path <= '9'; path++)
		{
			size = size * 10 + (unsigned)(*path - '0');
			if (++digits > 10 || size > 0xFFFFFFFFull)
				goto bad;
		}
		if (!digits || (digits > 1 && t[65] == '0') || *path != ' ')
			goto bad;
		path++;
		if (fdl_classify(path, &limit) != FDL_FETCH || strchr(path, '\\') || size == 0 || size > limit)
			goto bad;
		if (n > 0 && fdl_path_cmp(m->entries[n - 1].path, path) >= 0)
			goto bad;		/* sorted and unique (case-insensitive) */
		e->path = path;
		e->size = (uint32_t)size;
		n++;
		t = nl + 1;
	}
	m->count = n;
	return 1;

bad:
	fdl_manifest_free(m);
	set_err(err, errlen, "malformed entry");
	return 0;
}

const fdl_entry_t *fdl_manifest_find(const fdl_manifest_t *m, const char *path)
{
	int lo = 0, hi = m->count - 1;
	while (lo <= hi)
	{
		int mid = lo + (hi - lo) / 2;
		int c = fdl_path_cmp(m->entries[mid].path, path);
		if (!c)
			return &m->entries[mid];
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return NULL;
}

void fdl_manifest_free(fdl_manifest_t *m)
{
	free(m->text);
	free(m->entries);
	memset(m, 0, sizeof(*m));
}

/* ---- content plausibility -------------------------------------------------------------------- */

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int fdl_magic_ok(const char *path, const uint8_t *h, size_t n, uint32_t size)
{
	const char *ext = strrchr(path, '.');
	if (!ext)
		return 0;
	ext++;
#define EXT(x) eq_n(ext, strlen(ext), x)
	if (EXT("bsp"))
		return n >= 4 && le32(h) == 30;
	if (EXT("wad"))
		return n >= 12 && (!memcmp(h, "WAD3", 4) || !memcmp(h, "WAD2", 4)) && le32(h + 8) <= size;
	if (EXT("mdl"))
		return n >= 4 && (!memcmp(h, "IDST", 4) || !memcmp(h, "IDSQ", 4));
	if (EXT("spr"))
		return n >= 4 && !memcmp(h, "IDSP", 4);
	if (EXT("wav"))
		return n >= 12 && !memcmp(h, "RIFF", 4) && !memcmp(h + 8, "WAVE", 4);
	if (EXT("bmp"))
		return n >= 2 && h[0] == 'B' && h[1] == 'M';
	if (EXT("tga"))
		return n >= 3 && h[1] <= 1 && (h[2] == 1 || h[2] == 2 || h[2] == 3 || h[2] == 9 || h[2] == 10 || h[2] == 11);
	if (EXT("mp3"))
		return n >= 3 && (!memcmp(h, "ID3", 3) || (h[0] == 0xFF && (h[1] & 0xE0) == 0xE0));
	if (EXT("txt") || EXT("res"))
		return 1;				/* NUL bytes are rejected while streaming */
#undef EXT
	return 0;
}

uint32_t fdl_burst_left(uint32_t *start, uint32_t last_end, uint32_t now, uint32_t burst_ms, uint32_t gap_ms)
{
	uint32_t used;
	if (!now)
		now = 1;			/* 0 means "no burst" in *start */
	if (!*start || (last_end && now - last_end > gap_ms))
		*start = now;
	used = now - *start;
	return used >= burst_ms ? 0 : burst_ms - used;
}
