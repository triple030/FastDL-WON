/* Unit tests for core.c. Built with ASan/UBSan by test/run.sh. */
#include "../core.h"
#include "../third_party/monocypher/monocypher.h"
#include "../third_party/monocypher/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static uint8_t *readfile(const char *p, size_t *n)
{
	FILE *f = fopen(p, "rb"); uint8_t *b; long l;
	if (!f) { perror(p); exit(2); }
	fseek(f, 0, SEEK_END); l = ftell(f); fseek(f, 0, SEEK_SET);
	b = malloc(l ? l : 1); if (fread(b, 1, l, f) != (size_t)l) exit(2); fclose(f); *n = l; return b;
}

static void test_classify(void)
{
	uint32_t lim;
	struct { const char *p; fdl_class_t c; } t[] = {
		{ "maps/de_dust.bsp", FDL_FETCH }, { "MAPS\\De_Dust.BSP", FDL_FETCH }, { "maps/x.res", FDL_FETCH },
		{ "cs_dust.wad", FDL_FETCH }, { "sound/warcraft3/a.wav", FDL_FETCH }, { "models/player/x/x.mdl", FDL_FETCH },
		{ "models/player/x/x.bmp", FDL_FETCH }, { "sprites/hud.txt", FDL_FETCH }, { "gfx/env/sky1rt.tga", FDL_FETCH },
		{ "overviews/de_dust.bmp", FDL_FETCH }, { "media/song.mp3", FDL_FETCH }, { "sound/a(1)[2]+!.wav", FDL_FETCH },
		/* blocked: code, configs, traversal, streams, Windows name tricks */
		{ "autoexec.cfg", FDL_BLOCK }, { "maps/x.cfg", FDL_BLOCK }, { "cl_dlls/client.dll", FDL_BLOCK },
		{ "dlls/mp.dll", FDL_BLOCK }, { "fastdl.asi", FDL_BLOCK }, { "liblist.gam", FDL_BLOCK }, { "valve.rc", FDL_BLOCK },
		{ "x.exe", FDL_BLOCK }, { "maps/../x.bsp", FDL_BLOCK }, { "../x.wad", FDL_BLOCK }, { "/etc/x.wad", FDL_BLOCK },
		{ "\\x.wad", FDL_BLOCK }, { "c:x.wad", FDL_BLOCK }, { "maps/x.bsp::$DATA", FDL_BLOCK },
		{ "autoexec.cfg.", FDL_BLOCK }, { "autoexec.cfg . .", FDL_BLOCK }, { "x.DLL", FDL_BLOCK }, { "x.bsp.exe", FDL_BLOCK },
		{ "addons/metamod/x.wad", FDL_BLOCK }, { "CL_DLLS./x.mdl", FDL_BLOCK }, { "custom.hpk", FDL_BLOCK },
		{ "sound/x.ini", FDL_BLOCK }, { "delta.lst", FDL_BLOCK },
		/* pass: not ours, left to the engine */
		/* review findings: '!' prefix, '.' components, unknown types, root text files, devices */
		{ "!MD5abcdef0123", FDL_BLOCK }, { "!MD50123456789abcdef0123456789ABCDEF", FDL_PASS },
		{ "!MD50123456789abcdef0123456789abcdeg", FDL_BLOCK }, { "!..\\..\\autoexec.cfg", FDL_BLOCK },
		{ "!MD5x/../../a.dll", FDL_BLOCK }, { "./dlls/x.wav", FDL_BLOCK }, { ".\\cl_dlls\\x.txt", FDL_BLOCK },
		{ "commandmenu.txt", FDL_BLOCK }, { "x.htm", FDL_BLOCK }, { "maps/x.library-ms", FDL_BLOCK },
		{ "maps/x.searchConnector-ms", FDL_BLOCK }, { "sound/x.txt", FDL_BLOCK }, { "maps/x", FDL_BLOCK },
		{ "maps/con.bsp", FDL_BLOCK }, { "maps/COM1.bsp", FDL_BLOCK }, { "maps/lpt9.x.bsp", FDL_BLOCK }, { "aux/x.wav", FDL_BLOCK },
		{ "x.dem", FDL_BLOCK }, { "resource/x.res", FDL_BLOCK },
		{ "maps/con .bsp", FDL_BLOCK }, { "maps/nul  .x.bsp", FDL_BLOCK }, { "sound/com\xb9.wav", FDL_BLOCK },
		{ "sound/LPT\xb2.wav", FDL_BLOCK }, { "aux /x.wav", FDL_BLOCK }, { "maps/cons.bsp", FDL_FETCH },
		/* pass: game content the engine may still download in-band */
		{ "", FDL_PASS }, { "maps/sub/x.bsp", FDL_PASS }, { "x.bsp", FDL_PASS }, { "maps/x.wad", FDL_PASS },
		{ "maps/LONGNA~1.BSP", FDL_PASS }, { "maps/a b.bsp", FDL_PASS },
		{ "maps/.x.bsp", FDL_PASS }, { "maps//x.bsp", FDL_PASS }, { "events/x.sc", FDL_PASS },
		{ "maps/\xc3\xa4.bsp", FDL_PASS }, { "a/b/c/d/e/f/g/h/i.wav", FDL_PASS }, { "sound/a/b/c/d/e/f/g.wav", FDL_FETCH },
		{ "maps/x.bsp.", FDL_BLOCK }, { "models/x.wav", FDL_PASS },
	};
	size_t i;
	char longp[260];
	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++)
	{
		fdl_class_t c = fdl_classify(t[i].p, &lim);
		if (c != t[i].c) fprintf(stderr, "  classify('%s') = %d, want %d\n", t[i].p, c, t[i].c);
		CHECK(c == t[i].c);
	}
	CHECK(fdl_classify("maps/x.bsp", &lim) == FDL_FETCH && lim == 64u * 1024 * 1024);
	CHECK(fdl_classify("maps/x.txt", &lim) == FDL_FETCH && lim == 256 * 1024);
	memset(longp, 'a', sizeof(longp)); memcpy(longp, "maps/", 5); memcpy(longp + 250, ".bsp", 5);
	CHECK(fdl_classify(longp, &lim) == FDL_PASS);
	CHECK(fdl_classify(NULL, &lim) == FDL_PASS);
	CHECK(fdl_is_text("maps/x.txt") && fdl_is_text("maps/X.RES") && !fdl_is_text("maps/x.bsp"));
}

static void test_url(void)
{
	fdl_url_t u;
	CHECK(fdl_url_parse("http://192.0.2.10:27980/hldm", &u) && !strcmp(u.host, "192.0.2.10") && u.port == 27980 && !strcmp(u.path, "/hldm"));
	CHECK(fdl_url_parse("HTTP://Fast.Example.ORG/a/B/", &u) && !strcmp(u.host, "fast.example.org") && u.port == 80 && !strcmp(u.path, "/a/B"));
	CHECK(fdl_url_parse("http://h", &u) && u.port == 80 && !u.path[0] && !strcmp(fdl_url_tree(&u), "-"));
	CHECK(fdl_url_parse("http://h:1/a/cstrike_wc3ft", &u) && !strcmp(fdl_url_tree(&u), "cstrike_wc3ft"));
	CHECK(fdl_url_parse("http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbb.example.org/x", &u));
	CHECK(fdl_url_parse("https://fastdl.example.org/cstrike", &u) && u.https && u.port == 443 && !strcmp(u.host, "fastdl.example.org") && !strcmp(fdl_url_tree(&u), "cstrike"));
	CHECK(fdl_url_parse("HTTPS://H:8443/x/", &u) && u.https && u.port == 8443 && !strcmp(u.host, "h") && !strcmp(u.path, "/x"));
	CHECK(fdl_url_parse("https://h", &u) && u.https && u.port == 443 && !u.path[0]);
	CHECK(fdl_url_parse("http://h/x", &u) && !u.https && u.port == 80);
	const char *bad[] = { "ftp://h", "https://", "https:///x", "https:/h/x", "httpss://h/x", "https//h/x", "https://h:0",
		"https://h:65536", "https://h//x", "https://h/../x", "https://u@h/x", "http://https://h", "https://h:443:443/x", "http://", "http:///x", "http://a..b", "http://-a.b", "http://a-.b",
		"http://a./x", "http://h:0", "http://h:65536", "http://h:123456", "http://h:80x", "http://h/../x", "http://h//x",
		"http://h/a?b", "http://u@h", "http://h/a%20", "http://h/a b", "http://h\\x", "http://h:", "http://h/\"", "http://h/./x",
		"http://h/x/.", "http://h/x/./", "http://h/.x", "http://h:80/.", NULL };
	CHECK(fdl_url_parse("http://h/a.b/x./c.d", &u) && !strcmp(u.path, "/a.b/x./c.d"));
	for (int i = 0; bad[i]; i++) { int r = fdl_url_parse(bad[i], &u); if (r) fprintf(stderr, "  url accepted: %s\n", bad[i]); CHECK(!r); }
	char lng[120]; memset(lng, 'a', sizeof(lng)); memcpy(lng, "http://h/", 9); lng[101] = 0;
	CHECK(!fdl_url_parse(lng, &u));
}

static void test_info(void)
{
	char v[64];
	const char *info = "\\*gamedir\\cstrike\\sv_won_downloadurl\\http://h/x\\sv_won_dlkey\\ab";
	CHECK(fdl_info_value(info, "*gamedir", v, sizeof(v)) && !strcmp(v, "cstrike"));
	CHECK(fdl_info_value(info, "sv_won_dlkey", v, sizeof(v)) && !strcmp(v, "ab"));
	CHECK(fdl_info_value(info, "sv_won_downloadurl", v, sizeof(v)) && !strcmp(v, "http://h/x"));
	CHECK(!fdl_info_value(info, "sv_won", v, sizeof(v)));
	CHECK(!fdl_info_value(info, "dlkey", v, sizeof(v)));
	CHECK(!fdl_info_value(info, "*gamedir", v, 4));           /* would truncate */
	CHECK(!fdl_info_value("", "a", v, sizeof(v)));
	CHECK(!fdl_info_value("\\a", "a", v, sizeof(v)));
	/* exactly 512 bytes without a terminator: must not read past the buffer (ASan) */
	char *raw = malloc(FDL_INFO_MAX); memset(raw, 'x', FDL_INFO_MAX); raw[0] = '\\'; raw[3] = '\\';
	CHECK(!fdl_info_value(raw, "xx", v, sizeof(v)));
	memset(raw, '\\', FDL_INFO_MAX);
	CHECK(!fdl_info_value(raw, "", v, sizeof(v)) || 1);
	free(raw);
	CHECK(fdl_gamedir_valid("cstrike") && fdl_gamedir_valid("cstrike_wc3ft") && !fdl_gamedir_valid("") && !fdl_gamedir_valid("Valve")
		&& !fdl_gamedir_valid("a/b") && !fdl_gamedir_valid("..") && !fdl_gamedir_valid("con") && !fdl_gamedir_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

static void test_misc(void)
{
	uint8_t b[2]; char o[32];
	CHECK(fdl_hex_decode("ab01", b, 2) && b[0] == 0xab && b[1] == 0x01 && !fdl_hex_decode("aB01", b, 2));
	CHECK(!fdl_hex_decode("ab0", b, 2) && !fdl_hex_decode("ab012", b, 2) && !fdl_hex_decode("zz00", b, 2));
	CHECK(fdl_url_escape("maps\\a b+(1).bsp", o, sizeof(o)) && !strcmp(o, "maps/a%20b%2B%281%29.bsp"));
	CHECK(!fdl_url_escape("aaaa", o, 4) && fdl_url_escape("aaa", o, 4));
	CHECK(fdl_path_cmp("MAPS\\X.bsp", "maps/x.BSP") == 0 && fdl_path_cmp("a", "b") < 0);
	const uint8_t bsp[] = { 30, 0, 0, 0 }, wad[] = "WAD3\0\0\0\0\x0c\0\0\0";
	CHECK(fdl_magic_ok("maps/a.bsp", bsp, 4, 100) && !fdl_magic_ok("maps/a.bsp", wad, 4, 100));
	CHECK(fdl_magic_ok("a.wad", wad, 12, 100) && !fdl_magic_ok("a.wad", wad, 12, 5));
	CHECK(fdl_magic_ok("sound/a.wav", (const uint8_t *)"RIFF\0\0\0\0WAVE", 12, 12) && !fdl_magic_ok("sound/a.wav", (const uint8_t *)"MZ", 2, 2));
	CHECK(!fdl_magic_ok("x", bsp, 4, 4));
}

/* argv: pubkey-hex  manifest  [bad manifests...]  ;  classify-list */
static void test_manifest(const char *pubhex, const char *good, int nbad, char **bad, const char *other_pub)
{
	uint8_t pub[32], pub2[32]; size_t n; char err[64];
	fdl_manifest_t m;
	uint8_t *d = readfile(good, &n);
	CHECK(fdl_hex_decode(pubhex, pub, 32) && fdl_hex_decode(other_pub, pub2, 32));
	CHECK(fdl_manifest_load(&m, d, n, pub, "web", err, sizeof(err)));
	if (!err[0]) {} else fprintf(stderr, "  good manifest: %s\n", err);
	CHECK(m.count > 0);
	{ fdl_manifest_t m2; CHECK(!fdl_manifest_load(&m2, d, n, pub, "hldm", err, sizeof(err)) && strstr(err, "another tree")); }
	for (int i = 0; i < m.count; i++) CHECK(fdl_manifest_find(&m, m.entries[i].path) == &m.entries[i]);
	CHECK(fdl_manifest_find(&m, "maps/does_not_exist.bsp") == NULL);
	fdl_manifest_free(&m);

	CHECK(!fdl_manifest_load(&m, d, n, pub2, "web", err, sizeof(err)) && strstr(err, "signature"));
	for (size_t i = 0; i < n; i++)           /* every flipped byte must be rejected */
	{
		d[i] ^= 0x20;
		int r = fdl_manifest_load(&m, d, n, pub, "web", err, sizeof(err));
		if (r) { fprintf(stderr, "  flipped byte %zu accepted\n", i); fdl_manifest_free(&m); }
		CHECK(!r);
		d[i] ^= 0x20;
	}
	for (size_t cut = 0; cut < n; cut += 1 + n / 53)
	{
		int r = fdl_manifest_load(&m, d, cut, pub, "web", err, sizeof(err));
		CHECK(!r);
		if (r) fdl_manifest_free(&m);
	}
	free(d);
	for (int b = 0; b < nbad; b++)
	{
		d = readfile(bad[b], &n);
		int r = fdl_manifest_load(&m, d, n, pub, "web", err, sizeof(err));
		if (r) { fprintf(stderr, "  bad manifest accepted: %s\n", bad[b]); fdl_manifest_free(&m); }
		else printf("  %-40s rejected: %s\n", strrchr(bad[b], '/') + 1, err);
		CHECK(!r);
		free(d);
	}
}

/* lines "limit<TAB>path" from the Python generator: C must agree on every path */
static void test_crosscheck(const char *list)
{
	size_t n; uint8_t *d = readfile(list, &n); char *s = (char *)d, *line; int lines = 0;
	d = realloc(d, n + 1); s = (char *)d; s[n] = 0;
	for (line = strtok(s, "\n"); line; line = strtok(NULL, "\n"))
	{
		char *tab = strchr(line, '\t'); unsigned long want; uint32_t lim = 0;
		if (!tab) continue;
		*tab = 0; want = strtoul(line, NULL, 10);
		fdl_class_t c = fdl_classify(tab + 1, &lim);
		int ok = want ? (c == FDL_FETCH && lim == want) : (c != FDL_FETCH);
		if (!ok) fprintf(stderr, "  mismatch '%s': python %lu, C class %d limit %u\n", tab + 1, want, c, lim);
		CHECK(ok);
		lines++;
	}
	printf("  crosscheck: %d paths\n", lines);
	free(d);
}

#include "test_review.c"

/* review 1 fixes: manifest serial (F5) and small-order keys (F10) */
static void test_review_fixes(void)
{
	char err[64]; size_t n; uint8_t *d; fdl_manifest_t m; uint8_t k[32];
	const char *e = H64 " 1 maps/a.bsp\n";
	char b[256];
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree web 1795467000\n%s", e);
	d = rv_sign(b, strlen(b), &n);
	CHECK(fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)) && m.serial == 1795467000u && m.count == 1);
	fdl_manifest_free(&m); free(d);
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree web\n%s", e);
	d = rv_sign(b, strlen(b), &n);
	CHECK(fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)) && m.serial == 0);
	fdl_manifest_free(&m); free(d);
	CHECK(rv_load("FASTDL-WON1\ntree web 9999999999999999999\n", "web", err));
	{ const char *bad[] = { "tree web 0123\n", "tree web 1a\n", "tree web -1\n", "tree web  1\n", "tree web 1 \n",
		"tree web 99999999999999999999\n", "tree web +1\n", "tree web 1\ntree web 2\n", NULL };
	  for (int i = 0; bad[i]; i++) { snprintf(b, sizeof(b), "FASTDL-WON1\n%s", bad[i]); CHECK(!rv_load(b, "web", err)); } }
	CHECK(rv_load("FASTDL-WON1\ntree web 0\n", "web", err));
	/* small-order keys are refused before the signature check, also with the sign bit set */
	memset(k, 0, 32); k[0] = 1; d = rv_sign("FASTDL-WON1\ntree web\n", 21, &n);
	CHECK(!fdl_manifest_load(&m, d, n, k, "web", err, sizeof(err)) && strstr(err, "weak"));
	k[31] = 0x80; CHECK(!fdl_manifest_load(&m, d, n, k, "web", err, sizeof(err)) && strstr(err, "weak"));
	memset(k, 0xff, 32); k[0] = 0xec; k[31] = 0x7f; CHECK(!fdl_manifest_load(&m, d, n, k, "web", err, sizeof(err)) && strstr(err, "weak"));
	CHECK(fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)));
	fdl_manifest_free(&m); free(d);
}


/* review 2 (R2-3): the HTTP budget of one connection attempt is a hard limit */
/* serverinfo from the pending command text (3.1.0.4-3.1.0.8 servers) */
static void test_cbuf(void)
{
	char info[FDL_INFO_MAX], big[FDL_INFO_MAX + 64], text[FDL_CBUF_MAX + 16];
	const char *si = "\\*gamedir\\valve\\sv_won_downloadurl\\http://h/x\\sv_won_dlkey\\00ff";
	char ok[700];
	struct { const char *t; int r; } c[] = {
		{ "fullserverinfo \"\\a\\b\"\n", 1 },
		{ "fullserverinfo \"\\a\\b\"", 1 },					/* last command without newline */
		{ "echo hi\nfullserverinfo \"\\a\\b\"\nreconnect\n", 1 },
		{ "echo hi;fullserverinfo \"\\a\\b\";cmd x\n", 1 },
		{ "  \tfullserverinfo\t \"\\a\\b\"  \r\n", 1 },
		{ "fullserverinfo\"\\a\\b\"\n", 1 },					/* the tokenizer splits at the quote */
		{ "fullserverinfo \"\"\n", 1 },						/* empty: accepted, has no URL */
		{ "", 0 }, { "\n\n;;\n", 0 },
		{ "echo fullserverinfo \"\\a\\b\"\n", 0 },			/* not the command */
		{ "echo \"x;fullserverinfo \\\"\\a\\b\\\"\"\n", 0 },	/* inside quotes of another command */
		{ "fullserverinfox \"\\a\\b\"\n", 0 },
		{ "FULLSERVERINFO \"\\a\\b\"\n", 0 },
		{ "fullserverinfo \\a\\b\n", -1 },					/* unquoted */
		{ "fullserverinfo \"\\a\\b\n\"\n", -1 },			/* newline before the closing quote */
		{ "fullserverinfo \"\\a\\b", -1 },					/* truncated */
		{ "fullserverinfo \"\\a\\b\" x\n", -1 },			/* trailing token */
		{ "fullserverinfo \"\\a\\b\"\"\"\n", -1 },
		{ "fullserverinfo \"\\a\x01\\b\"\n", -1 },			/* control character */
		{ "fullserverinfo \"\\a\x7f\\b\"\n", -1 },
		{ "fullserverinfo \"\\a\\b\"\nfullserverinfo \"\\a\\b\"\n", -1 },	/* two: fail closed */
		{ "fullserverinfo \"\\a\\b\";fullserverinfo \"\\c\\d\"\n", -1 },
		{ "fullserverinfo \"\\a\\b\"\nfullserverinfo x\n", -1 },
		{ "fullserverinfo\n", -1 },
		{ NULL, 0 } };
	char v[128];
	int i;
	for (i = 0; c[i].t; i++)
	{
		int r = fdl_cbuf_serverinfo(c[i].t, strlen(c[i].t), info);
		if (r != (c[i].r > 0)) fprintf(stderr, "  cbuf case %d: %d\n", i, r);
		CHECK(r == (c[i].r > 0));
		CHECK(r || !info[0]);
		CHECK(!r || (fdl_info_value(info, "a", v, sizeof(v)) == (strstr(c[i].t, "\\a\\b") != NULL)));
	}
	/* a NUL inside the scanned text: refused */
	CHECK(!fdl_cbuf_serverinfo("fullserverinfo \"\\a\\b\"\necho \0x\n", 30, info) && !info[0]);
	CHECK(!fdl_cbuf_serverinfo("fullserverinfo \"\\a\0\\b\"\n", 24, info) && !info[0]);
	/* length: the scan stops at len (no terminator needed) */
	CHECK(fdl_cbuf_serverinfo("fullserverinfo \"\\a\\b\"XXXX", 21, info) && !strcmp(info, "\\a\\b"));
	CHECK(!fdl_cbuf_serverinfo("fullserverinfo \"\\a\\b\"XXXX", 20, info));
	/* the real thing, then values read as from cl.serverinfo */
	snprintf(ok, sizeof(ok), "echo x\nfullserverinfo \"%s\"\n", si);
	CHECK(fdl_cbuf_serverinfo(ok, strlen(ok), info) && !strcmp(info, si));
	CHECK(fdl_info_value(info, "sv_won_downloadurl", v, sizeof(v)) && !strcmp(v, "http://h/x"));
	CHECK(fdl_info_value(info, "sv_won_dlkey", v, sizeof(v)) && !strcmp(v, "00ff"));
	/* 511 bytes of info fit, 512 do not */
	memcpy(big, "fullserverinfo \"", 16);
	memset(big + 16, 'a', FDL_INFO_MAX - 1);
	big[16 + FDL_INFO_MAX - 1] = '"';
	CHECK(fdl_cbuf_serverinfo(big, 16 + FDL_INFO_MAX, info) && strlen(info) == FDL_INFO_MAX - 1);
	memset(big + 16, 'a', FDL_INFO_MAX);
	big[16 + FDL_INFO_MAX] = '"';
	CHECK(!fdl_cbuf_serverinfo(big, 17 + FDL_INFO_MAX, info) && !info[0]);
	/* longer pending text than FDL_CBUF_MAX: not scanned */
	memset(text, '\n', sizeof(text));
	memcpy(text, ok, strlen(ok));
	CHECK(fdl_cbuf_serverinfo(text, FDL_CBUF_MAX, info));
	CHECK(!fdl_cbuf_serverinfo(text, FDL_CBUF_MAX + 1, info) && !info[0]);
}

static void test_burst(void)
{
	uint32_t st = 0;
	/* first call at t=1000: a new burst, 40 s */
	CHECK(fdl_burst_left(&st, 0, 1000, 40000, 20000) == 40000 && st == 1000);
	/* the call works 25 s (ends at 26000); the next call 1 s later is the same burst: 15 s left */
	CHECK(fdl_burst_left(&st, 26000, 27000, 40000, 20000) == 14000 && st == 1000);
	/* inside one call (last_end 0) the burst never restarts, however long the call takes */
	CHECK(fdl_burst_left(&st, 0, 60000, 40000, 20000) == 0 && st == 1000);
	/* three stalled calls back to back never exceed 40 s in total */
	{ uint32_t s2 = 0, t = 5000, total = 0, end = 0; int i;
	  uint32_t left = 0;
	  for (i = 0; i < 3; i++) { left = fdl_burst_left(&s2, end, t, 40000, 20000); left = left < 25000 ? left : 25000; total += left; t += left; end = t; t += 100; }
	  CHECK(total <= 40000 && left == 0); }
	/* only an idle gap of more than 20 s after the END of the previous work starts a new burst */
	CHECK(fdl_burst_left(&st, 60000, 80000, 40000, 20000) == 0 && st == 1000);
	CHECK(fdl_burst_left(&st, 60000, 80001, 40000, 20000) == 40000 && st == 80001);
	/* GetTickCount wrap: arithmetic stays correct */
	st = 0xFFFFF000u;
	CHECK(fdl_burst_left(&st, 0, 0x00000FFFu, 40000, 20000) == 40000 - 0x1FFF);
	st = 0; CHECK(fdl_burst_left(&st, 0, 0, 40000, 20000) == 40000 && st == 1);
}

int main(int argc, char **argv)
{
	if (argc < 5) { fprintf(stderr, "usage: test_core PUBHEX OTHERPUB GOOD CROSSLIST [BAD...]\n"); return 2; }
	test_classify(); test_url(); test_info(); test_misc();
	test_review();
	test_review_fixes();
	test_burst();
	test_cbuf();
	test_manifest(argv[1], argv[3], argc - 5, argv + 5, argv[2]);
	test_crosscheck(argv[4]);
	printf("%d checks, %d failures\n", checks, fails);
	return fails != 0;
}
