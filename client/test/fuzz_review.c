/* libFuzzer target with property checks (review 1): fuzz_core.c only looks for crashes, this one aborts
 * when an accepted input breaks a rule. Built by test/fuzz.sh with TARGET=fuzz_review. */
#include "../core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lc(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

static int in_list(const char *s, size_t n, const char *const *l)
{
	for (; *l; l++)
		if (strlen(*l) == n && !memcmp(s, *l, n)) return 1;
	return 0;
}

/* extension Windows sees in the last component (trailing dots/spaces dropped), lowercased into e */
static size_t win_ext(const char *p, char *e, size_t cap)
{
	const char *last = p, *q, *dot = NULL; size_t l, i;
	for (q = p; *q; q++) if (*q == '/' || *q == '\\') last = q + 1;
	l = strlen(last);
	while (l && (last[l - 1] == '.' || last[l - 1] == ' ')) l--;
	for (q = last; q < last + l; q++) if (*q == '.') dot = q;
	if (!dot) return 0;
	for (i = 0; i < cap && dot + 1 + i < last + l; i++) e[i] = (char)lc((unsigned char)dot[1 + i]);
	return i;
}

static void check_classify(const char *p)
{
	static const char *const content[] = { "bsp", "wad", "wav", "mp3", "mdl", "spr", "tga", "bmp", "sc", "txt", "res", NULL };
	static const char *const fetch[] = { "bsp", "wad", "wav", "mp3", "mdl", "spr", "tga", "bmp", "txt", "res", NULL };
	char e[8]; size_t n, i, first;
	uint32_t lim = 0;
	fdl_class_t c = fdl_classify(p, &lim);
	if (c == FDL_BLOCK || !p[0] || (p[0] == '!' && strlen(p) == 36 && !memcmp(p, "!MD5", 4)))
		return;
	n = win_ext(p, e, sizeof(e));
	if (!in_list(e, n, content) || strstr(p, "..") || strchr(p, ':') || p[0] == '/' || p[0] == '\\')
		abort();
	/* first component after Windows trims its trailing dots/spaces is never a code folder */
	for (first = 0; p[first] && p[first] != '/' && p[first] != '\\'; first++) ;
	if (p[first])
	{
		size_t f = first; char d[16];
		while (f && (p[f - 1] == '.' || p[f - 1] == ' ')) f--;
		if (f < sizeof(d))
		{
			for (i = 0; i < f; i++) d[i] = (char)lc((unsigned char)p[i]);
			if (in_list(d, f, (const char *const[]){ "cl_dlls", "dlls", "addons", "bin", "platform", NULL })) abort();
		}
	}
	if (c == FDL_FETCH)
	{
		if (!in_list(e, n, fetch) || !lim || strlen(p) > FDL_PATH_MAX) abort();
		for (i = 0; p[i]; i++)
			if ((unsigned char)p[i] <= 0x20 || (unsigned char)p[i] >= 0x7f || p[i] == '~' || p[i] == '%') abort();
	}
	if (lim && c != FDL_FETCH) abort();
}

static void check_url(const char *s)
{
	fdl_url_t u, v;
	char again[400];
	size_t i;
	if (!fdl_url_parse(s, &u))
		return;
	if (!u.host[0] || !u.port || u.https != (lc((unsigned char)s[4]) == 's')) abort();
	for (i = 0; u.host[i]; i++)
		if (!((u.host[i] >= 'a' && u.host[i] <= 'z') || (u.host[i] >= '0' && u.host[i] <= '9') || u.host[i] == '-' || u.host[i] == '.')) abort();
	if (u.path[0] && u.path[0] != '/') abort();
	for (i = 0; u.path[i]; i++)
	{
		int c = (unsigned char)u.path[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '~' || c == '.' || c == '/')) abort();
		if (c == '.' && (i == 0 || u.path[i - 1] == '/' || u.path[i - 1] == '.')) abort();
		if (c == '/' && u.path[i + 1] == '/') abort();
	}
	if (strcmp(fdl_url_tree(&u), "-") && strchr(fdl_url_tree(&u), '/')) abort();
	/* canonical form parses to the same thing */
	snprintf(again, sizeof(again), "%s://%s:%u%s", u.https ? "https" : "http", u.host, (unsigned)u.port, u.path);
	if (strlen(again) <= FDL_URL_MAX)
	{
		if (!fdl_url_parse(again, &v) || strcmp(u.host, v.host) || u.port != v.port || u.https != v.https || strcmp(u.path, v.path)) abort();
	}
}

static void check_manifest(const uint8_t *d, size_t n, const char *probe)
{
	static const uint8_t pub[32] = { 1 };
	fdl_manifest_t m;
	char err[64], up[FDL_PATH_MAX + 1];
	int i;
	if (!fdl_manifest_load(&m, d, n, pub, "web", err, sizeof(err)))
	{
		if (m.text || m.entries || m.count) abort();		/* nothing kept on failure */
		return;
	}
	for (i = 0; i < m.count; i++)
	{
		uint32_t lim; size_t k, l = strlen(m.entries[i].path);
		if (fdl_classify(m.entries[i].path, &lim) != FDL_FETCH || !m.entries[i].size || m.entries[i].size > lim) abort();
		if (strchr(m.entries[i].path, '\\')) abort();
		if (i && fdl_path_cmp(m.entries[i - 1].path, m.entries[i].path) >= 0) abort();
		if (fdl_manifest_find(&m, m.entries[i].path) != &m.entries[i]) abort();
		if (l <= FDL_PATH_MAX)
		{
			for (k = 0; k <= l; k++) up[k] = (char)((m.entries[i].path[k] >= 'a' && m.entries[i].path[k] <= 'z') ? m.entries[i].path[k] - 32 : (m.entries[i].path[k] == '/' ? '\\' : m.entries[i].path[k]));
			if (fdl_manifest_find(&m, up) != &m.entries[i]) abort();
		}
	}
	{
		const fdl_entry_t *e = fdl_manifest_find(&m, probe);
		if (e && fdl_path_cmp(e->path, probe)) abort();
	}
	fdl_manifest_free(&m);
}

static void check_escape(const char *s)
{
	char o[1024], dec[400];
	size_t i, n = 0;
	if (strlen(s) > 300 || !fdl_url_escape(s, o, sizeof(o)))
		return;
	for (i = 0; o[i]; i++)
	{
		int c = (unsigned char)o[i];
		if (c == '%')
		{
			int hi = o[i + 1], lo = hi ? o[i + 2] : 0, v = 0, k;
			for (k = 0; k < 2; k++)
			{
				int h = k ? lo : hi;
				v = v * 16 + ((h >= '0' && h <= '9') ? h - '0' : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : (abort(), 0));
			}
			dec[n++] = (char)v; i += 2;
		}
		else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' || c == '/')
			dec[n++] = (char)c;
		else
			abort();
	}
	dec[n] = 0;
	for (i = 0; s[i]; i++)
		if (dec[i] != (s[i] == '\\' ? '/' : s[i])) abort();
	if (dec[i]) abort();
}

static void check_cmp(const char *s, size_t n)
{
	/* three strings separated by NUL-free split points */
	char a[64], b[64], c[64];
	size_t la = n / 3, lb = n / 3, lc2 = n - 2 * (n / 3);
	int ab, ba, bc, ac;
	if (la >= sizeof(a) || lc2 >= sizeof(c)) return;
	memcpy(a, s, la); a[la] = 0; memcpy(b, s + la, lb); b[lb] = 0; memcpy(c, s + la + lb, lc2); c[lc2] = 0;
	ab = fdl_path_cmp(a, b); ba = fdl_path_cmp(b, a); bc = fdl_path_cmp(b, c); ac = fdl_path_cmp(a, c);
	if ((ab < 0) != (ba > 0) || (ab == 0) != (ba == 0)) abort();
	if (ab <= 0 && bc <= 0 && ac > 0) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s;
	size_t n;
	if (size < 1)
		return 0;
	s = (char *)malloc(size);
	memcpy(s, data + 1, size - 1);
	s[size - 1] = 0;
	n = strlen(s);
	switch (data[0] % 5)
	{
	case 0: check_classify(s); break;
	case 1: check_url(s); break;
	case 2: check_manifest(data + 1, size - 1, s); break;
	case 3: check_escape(s); break;
	case 4: check_cmp(s, n); break;
	}
	free(s);
	return 0;
}
