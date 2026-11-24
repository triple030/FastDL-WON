/* Review 2 (pre-release, independent pass): extra negative tests for the client core. Standalone program,
 * built and run by test/run.sh with ASan/UBSan. Manifests are signed in memory with a fixed test key. */
#include "../core.h"
#include "../third_party/monocypher/monocypher.h"
#include "../third_party/monocypher/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static uint8_t sk[64], pk[32];
static const char H[] = "0000000000000000000000000000000000000000000000000000000000000000";

static uint8_t *sign(const char *body, size_t blen, size_t *outlen)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t sig[64], *o = malloc(blen + 133);
	size_t i;
	crypto_ed25519_sign(sig, sk, (const uint8_t *)body, blen);
	memcpy(o, body, blen);
	memcpy(o + blen, "sig ", 4);
	for (i = 0; i < 64; i++) { o[blen + 4 + 2 * i] = hx[sig[i] >> 4]; o[blen + 5 + 2 * i] = hx[sig[i] & 15]; }
	o[blen + 132] = '\n';
	*outlen = blen + 133;
	return o;
}

/* 1 = accepted; *serial / *count out */
static int load(const char *body, const char *tree, uint64_t *serial, int *count)
{
	size_t n; uint8_t *d = sign(body, strlen(body), &n); fdl_manifest_t m; char err[64];
	int r = fdl_manifest_load(&m, d, n, pk, tree, err, sizeof(err));
	if (r) { if (serial) *serial = m.serial; if (count) *count = m.count; fdl_manifest_free(&m); }
	else CHECK(!m.text && !m.entries && !m.count);
	free(d);
	return r;
}

static void test_windows_names(void)
{
	/* nothing here may be fetched over HTTP; every name is one Windows resolves to code/config, a device,
	 * a stream, another folder or an 8.3 alias */
	static const char *const never_fetch[] = {
		"maps/x.bsp:", "maps/x.bsp::$DATA", "maps/x.bsp:$I30:$INDEX_ALLOCATION", "maps/x.bsp.", "maps/x.bsp ",
		"maps/x.bsp. .", "maps/x.bsp\t", "maps/x\r.bsp", "maps/x\n.bsp", "sound/a\n/x.wav", "sound/a\r/x.wav",
		"maps/con.bsp", "maps/CON .bsp", "maps/nul.txt.bsp", "maps/clock$.bsp", "maps/conin$.bsp",
		"maps/com1.bsp", "maps/COM\xb9.bsp", "maps/lpt\xb3.bsp", "maps/com0.bsp", "aux/x.wav", "sound/prn/x.wav",
		"\\\\?\\C:\\x.bsp", "\\\\.\\pipe\\x.bsp", "//server/share/x.bsp", "C:\\x.bsp", "c:maps/x.bsp",
		"maps/LONGNA~1.BSP", "MAPS~1/x.bsp", "sound/SOUNDS~1/x.wav", "maps/x~1.bsp", "maps/./x.bsp",
		"maps/../maps/x.bsp", "maps//x.bsp", "maps/x.bsp/", "maps/ x.bsp", "maps/x .bsp", "maps/x%2e.bsp",
		"maps/x\xc0\xae.bsp", "maps/\xe4.bsp", "maps/x\\..\\..\\hl.bsp", "sound/x.wav\\..\\..\\cl_dlls\\x.wav",
		"maps/x.bsp\"", "maps/x<.bsp", "maps/x>.bsp", "maps/x|.bsp", "maps/x*.bsp", "maps/x?.bsp",
		"cl_dlls/x.wav", "CL_DLLS/x.wav", "cl_dlls./x.wav", "cl_dlls /x.wav", "cl_dlls. ./x.wav", "dlls\\x.wav",
		"addons/x.wav", "bin/x.wav", "platform/x.tga", "sound/x.dll", "sound/x.asi", "sound/x.ASI ", "sound/x.m3d",
		"sound/x.flt", "sound/x.mix", "x.cfg", "userconfig.cfg", "liblist.gam", "LIBLIST.GAM.", "hl.exe.manifest",
		"opengl32.dll", "mss32.dll", "fastdl.asi", "wsock32.dll", "titles.txt", "commandmenu.txt", "motd.txt",
		"gfx/palette.lmp", "resource/GameMenu.res", "events/x.sc", "sound/sentences.txt", "x.bsp", "models/x.wav",
		"maps/sub/x.bsp", "overviews/a/b.bmp", "a/b/c/d/e/f/g/h/i.wav", "maps/x", "maps/.x.bsp", "maps/x.",
		"!MD5", "!MD50123456789abcdef0123456789abcdef", "fastdl.manifest", "fastdl.log", "fastdl.debug",
		"fastdl-1-1.tmp", "", NULL };
	/* never written at all, not even by the engine's in-band download */
	static const char *const never_write[] = {
		"maps/x.bsp:", "maps/x.bsp::$DATA", "maps/x.bsp.", "maps/x.bsp ", "maps/con.bsp", "maps/COM\xb9.bsp",
		"maps/nul.txt.bsp", "\\\\?\\C:\\x.bsp", "C:\\x.bsp", "maps/./x.bsp", "maps/x\\..\\..\\hl.bsp",
		"cl_dlls/x.wav", "cl_dlls. ./x.wav", "dlls\\x.wav", "addons/x.wav", "sound/x.dll", "sound/x.ASI ",
		"x.cfg", "LIBLIST.GAM.", "hl.exe.manifest", "opengl32.dll", "fastdl.asi", "titles.txt", "commandmenu.txt",
		"motd.txt", "gfx/palette.lmp", "resource/GameMenu.res", "sound/sentences.txt", "fastdl.log",
		"fastdl.debug", "fastdl-1-1.tmp", "maps/x.bsp\"", "maps/x*.bsp", "!MD5x/../../a.dll", "x.lnk", "x.url",
		"desktop.ini", "x.scf", "x.library-ms", "x.theme", "x.htm", "x.hta", "x.ps1", "x.bat .", NULL };
	int i;
	uint32_t lim;
	for (i = 0; never_fetch[i]; i++)
	{
		int ok = fdl_classify(never_fetch[i], &lim) != FDL_FETCH;
		if (!ok) fprintf(stderr, "  fetchable: %s\n", never_fetch[i]);
		CHECK(ok);
	}
	for (i = 0; never_write[i]; i++)
	{
		int ok = fdl_classify(never_write[i], &lim) == FDL_BLOCK;
		if (!ok) fprintf(stderr, "  not blocked: %s\n", never_write[i]);
		CHECK(ok);
	}
	/* still fetched: ordinary content, any case */
	CHECK(fdl_classify("MAPS/De_Dust2.BSP", &lim) == FDL_FETCH && lim == 64u << 20);
	CHECK(fdl_classify("sound/a/b/c/d/e/f/g.wav", &lim) == FDL_FETCH);
	CHECK(fdl_classify("Halflife.WAD", &lim) == FDL_FETCH);
	/* a pushed name of exactly the engine's limit is classified as a whole (no truncation in classify) */
	{
		char p[300];
		memset(p, 'a', sizeof(p)); memcpy(p, "maps/", 5); memcpy(p + 290, ".cfg", 5);
		CHECK(fdl_classify(p, &lim) == FDL_BLOCK);
	}
}

static void test_manifest_edges(void)
{
	char b[1024];
	uint64_t s;
	int n;

	/* tree binding: prefixes, suffixes and case of the tree name are other trees */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree cstrike 5\n%s 4 maps/a.bsp\n", H);
	CHECK(load(b, "cstrike", &s, &n) && s == 5 && n == 1);
	CHECK(!load(b, "cs", NULL, NULL));
	CHECK(!load(b, "cstrike2", NULL, NULL));
	CHECK(!load(b, "CSTRIKE", NULL, NULL));
	CHECK(!load(b, "-", NULL, NULL));
	/* serial: decimal, 1-19 digits, no leading zero, single space, nothing after it */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 9999999999999999999\n%s 4 maps/a.bsp\n", H);
	CHECK(load(b, "t", &s, NULL) && s == 9999999999999999999ull);
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 18446744073709551616\n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 05\n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t  5\n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 5 \n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t -5\n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t +5\n%s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 0\n%s 4 maps/a.bsp\n", H);
	CHECK(load(b, "t", &s, NULL) && s == 0);
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t\n%s 4 maps/a.bsp\n", H);
	CHECK(load(b, "t", &s, NULL) && s == 0);		/* no serial = 0: never accepted after a serial was seen */
	/* empty manifest is valid (no entries) */
	CHECK(load("FASTDL-WON1\ntree t 1\n", "t", NULL, &n) && n == 0);
	/* entry shape */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s +4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 4 maps/a.bsp \n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 4 maps/a.bsp\t\n", H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 4294967295 a.wad\n", H);
	CHECK(!load(b, "t", NULL, NULL));			/* above the .wad limit */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 67108864 a.wad\n", H);
	CHECK(load(b, "t", NULL, NULL));			/* exactly the limit */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 4 sound/a\n/x.wav\n", H);
	CHECK(!load(b, "t", NULL, NULL));			/* what the builder writes for a directory "a\n" (finding R2-2) */
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%s 4 maps/a.bsp\n%s 4 maps/a.bsp\n", H, H);
	CHECK(!load(b, "t", NULL, NULL));
	snprintf(b, sizeof(b), "FASTDL-WON1\ntree t 1\n%.63s 4 maps/a.bsp\n", H);
	CHECK(!load(b, "t", NULL, NULL));
}

static void test_signature_edges(void)
{
	static const char body[] = "FASTDL-WON1\ntree t 1\n0000000000000000000000000000000000000000000000000000000000000000 4 maps/a.bsp\n";
	size_t n, bl = sizeof(body) - 1;
	uint8_t *d = sign(body, bl, &n), sig[64], key[32];
	fdl_manifest_t m;
	char err[64], hx[3];
	int i, carry;
	/* L = 2^252 + 27742317777372353535851937790883648493, little endian */
	static const uint8_t L[32] = { 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };

	CHECK(fdl_manifest_load(&m, d, n, pk, "t", err, sizeof(err)));
	fdl_manifest_free(&m);
	/* malleability: S + L is the same scalar but a different encoding, must be refused */
	{
		char sh[129];
		memcpy(sh, d + bl + 4, 128); sh[128] = 0;
		CHECK(fdl_hex_decode(sh, sig, 64));
	}
	for (i = 0, carry = 0; i < 32; i++)
	{
		int v = sig[32 + i] + L[i] + carry;
		sig[32 + i] = (uint8_t)v; carry = v >> 8;
	}
	for (i = 0; i < 64; i++) { snprintf(hx, 3, "%02x", sig[i]); memcpy(d + bl + 4 + 2 * i, hx, 2); }
	CHECK(!fdl_manifest_load(&m, d, n, pk, "t", err, sizeof(err)));
	free(d);
	/* every byte of the body is covered: flip each one */
	d = sign(body, bl, &n);
	for (i = 0; i < (int)bl; i++)
	{
		d[i] ^= 1;
		CHECK(!fdl_manifest_load(&m, d, n, pk, "t", err, sizeof(err)));
		d[i] ^= 1;
	}
	/* small-order and non-canonical identity keys never verify anything */
	memset(key, 0, 32); key[0] = 1;
	CHECK(!fdl_manifest_load(&m, d, n, key, "t", err, sizeof(err)) && !strcmp(err, "weak signing key"));
	key[31] = 0x80;
	CHECK(!fdl_manifest_load(&m, d, n, key, "t", err, sizeof(err)));
	/* truncation at every length is refused without reading out of bounds (ASan) */
	for (i = 0; i < (int)n; i++)
	{
		uint8_t *c = malloc(i ? i : 1);
		memcpy(c, d, i);
		CHECK(!fdl_manifest_load(&m, c, i, pk, "t", err, sizeof(err)));
		free(c);
	}
	free(d);
}

static void test_limits(void)
{
	/* 65536 entries are accepted, 65537 are not; 8 MiB + 1 byte is refused before the signature check */
	size_t cap = 66000u * 90u, len, n, i;
	char *b = malloc(cap), *p;
	uint8_t *d;
	fdl_manifest_t m;
	char err[64];
	int cnt;
	for (cnt = 65536; cnt <= 65537; cnt++)
	{
		p = b + sprintf(b, "FASTDL-WON1\ntree t 1\n");
		for (i = 0; i < (size_t)cnt; i++)
			p += sprintf(p, "%s 4 sound/%06zu.wav\n", H, i);
		len = (size_t)(p - b);
		d = sign(b, len, &n);
		i = fdl_manifest_load(&m, d, n, pk, "t", err, sizeof(err));
		CHECK(cnt == 65536 ? i == 1 && m.count == 65536 : i == 0);
		if (i)
		{
			CHECK(fdl_manifest_find(&m, "SOUND\\000123.WAV") != NULL);
			CHECK(fdl_manifest_find(&m, "sound/065536.wav") == NULL);
			fdl_manifest_free(&m);
		}
		free(d);
	}
	free(b);
	d = calloc(1, FDL_MANIFEST_MAX + 1);
	memcpy(d, "FASTDL-WON1\n", 12);
	CHECK(!fdl_manifest_load(&m, d, FDL_MANIFEST_MAX + 1, pk, "t", err, sizeof(err)) && !strcmp(err, "manifest too big"));
	free(d);
}

static void test_info_and_url(void)
{
	char out[128], info[FDL_INFO_MAX];
	fdl_url_t u;
	/* key prefix/suffix confusion, empty keys, value exactly filling the buffer */
	CHECK(!fdl_info_value("\\sv_won_downloadurlx\\a\\", "sv_won_downloadurl", out, sizeof(out)));
	CHECK(!fdl_info_value("\\xsv_won_downloadurl\\a\\", "sv_won_downloadurl", out, sizeof(out)));
	CHECK(fdl_info_value("\\\\x\\sv_won_downloadurl\\a", "sv_won_downloadurl", out, sizeof(out)) && !strcmp(out, "a"));
	CHECK(!fdl_info_value("\\k\\abcd", "k", out, 4));
	CHECK(fdl_info_value("\\k\\abc", "k", out, 4) && !strcmp(out, "abc"));
	memset(info, 'a', sizeof(info)); info[0] = '\\'; info[2] = '\\';
	CHECK(!fdl_info_value(info, "a", out, sizeof(out)));		/* unterminated value at the end of the buffer */
	/* URLs: userinfo, IPv6, query, fragment, percent, backslash, spaces, CR/LF injection, bad ports */
	CHECK(!fdl_url_parse("http://user@host/x", &u));
	CHECK(!fdl_url_parse("http://[::1]/x", &u));
	CHECK(!fdl_url_parse("http://host/x?y", &u));
	CHECK(!fdl_url_parse("http://host/x#y", &u));
	CHECK(!fdl_url_parse("http://host/%2e%2e", &u));
	CHECK(!fdl_url_parse("http://host\\x", &u));
	CHECK(!fdl_url_parse("http://host/x y", &u));
	CHECK(!fdl_url_parse("http://host/x\r\nHost: evil", &u));
	CHECK(!fdl_url_parse("http://host:0/x", &u));
	CHECK(!fdl_url_parse("http://host:65536/x", &u));
	CHECK(!fdl_url_parse("http://host:080808/x", &u));
	CHECK(!fdl_url_parse("http://host:/x", &u));
	CHECK(!fdl_url_parse("ftp://host/x", &u));
	CHECK(!fdl_url_parse("https:/host/x", &u));
	CHECK(!fdl_url_parse("http://host/x/../y", &u));
	CHECK(fdl_url_parse("HTTPS://Host.Example:8443/Tree", &u) && u.https && u.port == 8443 && !strcmp(u.host, "host.example")
		&& !strcmp(fdl_url_tree(&u), "Tree"));
	CHECK(fdl_url_parse("http://h/", &u) && !strcmp(fdl_url_tree(&u), "-"));
	/* gamedir: no devices, no separators, no dots */
	CHECK(!fdl_gamedir_valid("con") && !fdl_gamedir_valid("com1") && !fdl_gamedir_valid("..") && !fdl_gamedir_valid("a/b")
		&& !fdl_gamedir_valid("A") && !fdl_gamedir_valid("") && fdl_gamedir_valid("cstrike"));
}

static void test_magic(void)
{
	static const uint8_t cfg[] = "rcon_password x\n", pem[] = "-----BEGIN PRIVATE KEY-----\n";
	static const uint8_t elf[] = { 0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	static const uint8_t mz[] = { 'M', 'Z', 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xff, 0xff, 0, 0 };
	const char *const bin[] = { "maps/a.bsp", "a.wad", "models/a.mdl", "sprites/a.spr", "sound/a.wav", "gfx/a.tga", "media/a.mp3", NULL };
	int i;
	for (i = 0; bin[i]; i++)
	{
		CHECK(!fdl_magic_ok(bin[i], cfg, sizeof(cfg) - 1, 100));
		CHECK(!fdl_magic_ok(bin[i], pem, sizeof(pem) - 1, 100));
		CHECK(!fdl_magic_ok(bin[i], elf, sizeof(elf), 100));
		CHECK(!fdl_magic_ok(bin[i], mz, sizeof(mz), 100));
		CHECK(!fdl_magic_ok(bin[i], cfg, 0, 100));
	}
	/* MZ starts with 'M', BMP with 'B': a PE renamed .bmp is refused */
	CHECK(!fdl_magic_ok("gfx/a.bmp", mz, sizeof(mz), 100));
	/* NOTE: .txt/.res accept any content here (NUL bytes are refused while streaming) - see finding R2-1 */
	CHECK(fdl_magic_ok("maps/a.txt", cfg, sizeof(cfg) - 1, 100));
}

int main(void)
{
	uint8_t seed[32];
	memset(seed, 0x2b, sizeof(seed));
	crypto_ed25519_key_pair(sk, pk, seed);
	test_windows_names();
	test_manifest_edges();
	test_signature_edges();
	test_limits();
	test_info_and_url();
	test_magic();
	printf("review2: %d checks, %d failures\n", checks, fails);
	return fails != 0;
}
