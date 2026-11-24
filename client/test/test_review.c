/* Review 1 (pre-release): negative tests for every client rule, included by test_core.c.
 * Signed manifests are built in memory with a fixed test key (monocypher), so every parser branch is
 * reached with a valid signature. HARDEN marks a stricter rule suggested by the review (REVIEW.md): it is
 * reported, not counted as a failure, because the current behaviour is safe for another reason. */

static int hardening;
#define HARDEN(c, what) do { if (!(c)) { hardening++; printf("  harden %s:%d: %s\n", __FILE__, __LINE__, what); } } while (0)

static uint8_t rv_sk[64], rv_pk[32];

static void rv_keys(void)
{
	uint8_t seed[32];
	memset(seed, 0x5a, sizeof(seed));
	crypto_ed25519_key_pair(rv_sk, rv_pk, seed);	/* wipes seed */
}

/* body + "sig <hex>\n"; caller frees */
static uint8_t *rv_sign(const char *body, size_t blen, size_t *outlen)
{
	static const char hx[] = "0123456789abcdef";
	uint8_t sig[64], *o = malloc(blen + 133);
	size_t i;
	crypto_ed25519_sign(sig, rv_sk, (const uint8_t *)body, blen);
	memcpy(o, body, blen);
	memcpy(o + blen, "sig ", 4);
	for (i = 0; i < 64; i++) { o[blen + 4 + 2 * i] = hx[sig[i] >> 4]; o[blen + 5 + 2 * i] = hx[sig[i] & 15]; }
	o[blen + 132] = '\n';
	*outlen = blen + 133;
	return o;
}

static int rv_load(const char *body, const char *tree, char *err)
{
	size_t n; uint8_t *d = rv_sign(body, strlen(body), &n); fdl_manifest_t m;
	int r = fdl_manifest_load(&m, d, n, rv_pk, tree, err, 64);
	if (r) fdl_manifest_free(&m);
	free(d);
	return r;
}

#define H64 "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"	/* BLAKE2b-256("x") */

/* manifest with one entry line */
static int rv_one(const char *line)
{
	char body[1024], err[64];
	snprintf(body, sizeof(body), "FASTDL-WON1\ntree web\n%s\n", line);
	return rv_load(body, "web", err);
}

/* ---- names: what Windows would make of the last component ------------------------------------ */

/* extension Windows sees: last component, trailing dots and spaces dropped, lowercased */
static void rv_win_ext(const char *p, char *ext, size_t n)
{
	const char *last = p, *q, *dot = NULL; size_t l, i;
	for (q = p; *q; q++) if (*q == '/' || *q == '\\') last = q + 1;
	l = strlen(last);
	while (l && (last[l - 1] == '.' || last[l - 1] == ' ')) l--;
	for (q = last; q < last + l; q++) if (*q == '.') dot = q;
	ext[0] = 0;
	if (!dot) return;
	for (i = 0; i + 1 < n && dot + 1 + i < last + l; i++) ext[i] = (char)((dot[1 + i] >= 'A' && dot[1 + i] <= 'Z') ? dot[1 + i] + 32 : dot[1 + i]);
	ext[i] = 0;
}

static int rv_in(const char *s, const char *const *list)
{
	for (; *list; list++) if (!strcmp(s, *list)) return 1;
	return 0;
}

/* oracle for every name the tests below and the fuzzer throw at fdl_classify */
static void rv_oracle(const char *p)
{
	static const char *const content[] = { "bsp", "wad", "wav", "mp3", "mdl", "spr", "tga", "bmp", "sc", "txt", "res", NULL };
	static const char *const fetch[] = { "bsp", "wad", "wav", "mp3", "mdl", "spr", "tga", "bmp", "txt", "res", NULL };
	char ext[16]; uint32_t lim = 0; size_t i;
	fdl_class_t c = fdl_classify(p, &lim);
	if (c == FDL_BLOCK || !p[0] || (p[0] == '!' && strlen(p) == 36))
		return;
	rv_win_ext(p, ext, sizeof(ext));
	if (!rv_in(ext, content)) { fprintf(stderr, "  oracle: '%s' class %d, Windows extension '%s'\n", p, c, ext); CHECK(0); }
	CHECK(!strstr(p, "..") && !strchr(p, ':') && p[0] != '/' && p[0] != '\\');
	if (c == FDL_FETCH)
	{
		CHECK(rv_in(ext, fetch) && lim > 0 && strlen(p) <= FDL_PATH_MAX);
		for (i = 0; p[i]; i++) CHECK((unsigned char)p[i] > 0x20 && (unsigned char)p[i] < 0x7f && p[i] != '~' && p[i] != '%');
	}
}

static void rv_classify(void)
{
	static const char *const block[] = {
		/* code and configs, also with Windows name tricks */
		"autoexec.cfg", "AUTOEXEC.CFG", "config.cfg", "userconfig.cfg", "listenserver.cfg", "maps/de_dust.cfg",
		"autoexec.cfg.", "autoexec.cfg ", "autoexec.cfg. . .", "autoexec.cfg::$DATA", "autoexec.cfg:x.wav",
		"liblist.gam", "LibList.GAM.", "liblist.gam ", "valve.rc", "delta.lst", "server.ini", "desktop.ini",
		"fastdl.asi", "mss32.dll", "x.flt", "x.m3d", "x.mix", "x.exe", "x.com", "x.bat", "x.cmd", "x.scr", "x.pif",
		"x.lnk", "x.url", "x.reg", "x.inf", "x.hta", "x.js", "x.vbs", "x.ps1", "x.jar", "x.cpl", "x.msi", "x.sys",
		"x.ocx", "x.so", "x.manifest", "x.chm", "x.scf", "x.theme", "x.library-ms", "x.searchconnector-ms", "x.htm",
		"x.html", "x.xml", "x.dem", "x.hpk", "custom.hpk", "x.wav.dll", "sound/x.wav.exe", "maps/x.bsp.cfg",
		"maps/x.bsp:evil.cfg", "maps/x.BsP:$DATA",
		/* folders the engine loads code or engine data from, also disguised */
		"cl_dlls/client.wav", "CL_DLLS/x.bmp", "cl_dlls./x.wav", "cl_dlls ./x.wav", "cl_dlls. . /x.wav",
		"dlls/mp.wav", "Dlls/x.mdl", "addons/x.wav", "bin/x.wav", "platform/x.tga",
		/* escaping the game folder */
		"../x.wad", "..\\x.wad", "maps/../../x.bsp", "maps\\..\\..\\x.bsp", "sound/.../x.wav", "a..b.wav",
		"/x.wad", "\\x.wad", "//server/share/x.wad", "\\\\server\\share\\x.wad", "\\\\?\\C:\\x.wad",
		"\\\\.\\COM1", "\\??\\C:\\x.wad", "C:x.wad", "c:/x.wad", "C:\\Windows\\x.wad", "x.wad:", "./x.wad",
		"maps/./x.bsp", ".\\x.wad",
		/* devices, in any component, with spaces and extensions; superscript digits (cp1252 0xb9 0xb2 0xb3) */
		"con.wav", "CON", "maps/con.bsp", "maps/Con.x.bsp", "maps/con .bsp", "prn.wad", "aux.wav", "nul.bmp",
		"maps/com1.bsp", "maps/COM9.bsp", "maps/com0.bsp", "maps/lpt1.bsp", "maps/LPT0.bsp", "sound/com\xb9.wav",
		"sound/lpt\xb3.wav", "conin$.wav", "CONOUT$.wav", "clock$.wav", "aux/x.wav", "nul/x.wav", "sound/con/x.wav",
		"sound/con.d/x.wav",
		/* unknown or empty extensions */
		"maps/x", "x", "maps/x.", "maps/x.bs", "commandmenu.txt", "motd.txt", "sound/x.txt", "x.txt",
		/* custom resources: only "!MD5" + 32 hex digits */
		"!", "!MD5", "!MD5abc", "!MD50123456789abcdef0123456789abcdef0", "!MD50123456789abcdef0123456789abcdeg",
		"!x.wav", "!MD5/../x.wav",
		/* control characters */
		"sound/x.wav\r", "sound/x\n.wav.cfg", "maps/x\x01.cfg",
		NULL };
	static const char *const nofetch[] = {
		/* not FETCH (in-band at most): 8.3 aliases, spaces, high bytes, odd places, odd shapes */
		"maps/DE_DUS~1.BSP", "maps/a b.bsp", "maps/x.bsp.", "maps/x.bsp ", "maps/\xe4.bsp", "maps/sub/x.bsp",
		"x.bsp", "sound.wav", "models/x.wav", "maps/x.wad", "sounds/x.wav", "maps//x.bsp", "maps/.x.bsp",
		"maps/x..bsp", "sound/a/b/c/d/e/f/g/h.wav", "overviews/a/b.bmp", "maps/x.bsp\t", "maps/x%41.bsp",
		"maps/x;.bsp", "maps/x'.bsp", "maps/x`.bsp", "maps/x&.bsp", "maps/x$.bsp", "maps/x=.bsp", "maps/x,.bsp",
		"maps/x@.bsp", "maps/x#.bsp", "maps/x{.bsp", "maps/x^.bsp", "maps/x*.bsp", "maps/x?.bsp", "maps/x<.bsp",
		"maps/x>.bsp", "maps/x|.bsp", "maps/x\".bsp", "events/x.sc", "maps/.bsp.", NULL };
	static const char *const fetchok[] = {
		"maps/de_dust.bsp", "MAPS/DE_DUST.BSP", "maps\\de_dust.bsp", "Maps/x.Res", "maps/x.txt", "x.wad",
		"sound/a/b/c/d/e/f/g.wav", "models/player/a/a.mdl", "models/player/a/a.bmp", "gfx/env/a.tga", "gfx/a.bmp",
		"sprites/a/b.spr", "sprites/a.txt", "overviews/a.bmp", "overviews/a.tga", "overviews/a.txt", "media/a.mp3",
		"sound/a.mp3", "maps/cons.bsp", "maps/com10.bsp", "maps/lpt.bsp", "maps/conx.bsp", "maps/a-b_c+d!(e)[f].bsp",
		NULL };
	uint32_t lim;
	int i;
	char longp[400];

	for (i = 0; block[i]; i++)
	{
		fdl_class_t c = fdl_classify(block[i], &lim);
		if (c != FDL_BLOCK) fprintf(stderr, "  review: classify('%s') = %d, want BLOCK\n", block[i], c);
		CHECK(c == FDL_BLOCK);
		rv_oracle(block[i]);
	}
	for (i = 0; nofetch[i]; i++)
	{
		fdl_class_t c = fdl_classify(nofetch[i], &lim);
		if (c == FDL_FETCH) fprintf(stderr, "  review: classify('%s') = FETCH\n", nofetch[i]);
		CHECK(c != FDL_FETCH);
		rv_oracle(nofetch[i]);
	}
	for (i = 0; fetchok[i]; i++)
	{
		fdl_class_t c = fdl_classify(fetchok[i], &lim);
		if (c != FDL_FETCH) fprintf(stderr, "  review: classify('%s') = %d, want FETCH\n", fetchok[i], c);
		CHECK(c == FDL_FETCH);
		rv_oracle(fetchok[i]);
	}
	/* limits */
	CHECK(fdl_classify("x.wad", &lim) == FDL_FETCH && lim == 64u << 20);
	CHECK(fdl_classify("models/a.mdl", &lim) == FDL_FETCH && lim == 32u << 20);
	CHECK(fdl_classify("models/a.bmp", &lim) == FDL_FETCH && lim == 4u << 20);
	CHECK(fdl_classify("gfx/a.bmp", &lim) == FDL_FETCH && lim == 16u << 20);
	CHECK(fdl_classify("sprites/a.txt", &lim) == FDL_FETCH && lim == 256u << 10);
	CHECK(fdl_classify("autoexec.cfg", &lim) == FDL_BLOCK && lim == 0);
	/* overlong: 200 characters may be fetched, 201 not; longer content names only in-band, longer code never */
	memset(longp, 'a', sizeof(longp)); memcpy(longp, "maps/", 5); memcpy(longp + 196, ".bsp", 5);
	CHECK(strlen(longp) == 200 && fdl_classify(longp, &lim) == FDL_FETCH);
	memcpy(longp + 196, "a.bsp", 6);
	CHECK(strlen(longp) == 201 && fdl_classify(longp, &lim) == FDL_PASS);
	memset(longp, 'a', sizeof(longp)); memcpy(longp + 390, ".cfg", 5);
	CHECK(fdl_classify(longp, &lim) == FDL_BLOCK);
	memcpy(longp + 390, ".dll", 5);
	CHECK(fdl_classify(longp, &lim) == FDL_BLOCK);
	memcpy(longp, "cl_dlls/", 8); memcpy(longp + 390, ".wav", 5);
	CHECK(fdl_classify(longp, &lim) == FDL_BLOCK);
	/* components made only of dots and spaces are passed in-band. Win32 keeps ". " as a name (only "." and
	 * ".." are relative), so the engine's write fails; and only content types get here anyway. */
	HARDEN(fdl_classify(". /cl_dlls/x.wav", &lim) == FDL_BLOCK, "'. /cl_dlls/x.wav' is passed in-band (dot/space-only component)");
	HARDEN(fdl_classify(". ./dlls/x.wav", &lim) == FDL_BLOCK, "'. ./dlls/x.wav' is passed in-band (dot/space-only component)");
	HARDEN(fdl_classify(" /addons/x.wav", &lim) == FDL_BLOCK, "' /addons/x.wav' is passed in-band (space-only component)");
	/* every single byte as a one-character file name and as the byte before ".wav": no crash, oracle holds */
	for (i = 1; i < 256; i++)
	{
		char a[16];
		snprintf(a, sizeof(a), "%c", i); rv_oracle(a);
		snprintf(a, sizeof(a), "sound/x%c.wav", i); rv_oracle(a);
		snprintf(a, sizeof(a), "sound/x.wav%c", i); rv_oracle(a);
		snprintf(a, sizeof(a), "%ccl_dlls/x.wav", i); rv_oracle(a);
	}
}

/* ---- URLs ------------------------------------------------------------------------------------- */

static void rv_url(void)
{
	static const char *const bad[] = {
		"", "h", "//h/x", "http:", "http:/h", "http:h", "file:///c:/x", "ftp://h/x", "gopher://h", " http://h",
		"http ://h", "http://h /x", "http://h\t/x", "http://h\r\n/x", "http://h/x\n",
		/* userinfo, IPv6, IDN bytes, odd host characters */
		"http://u@h/x", "http://u:p@h/x", "https://u@h", "http://h@/x", "http://@h", "http://[::1]/x",
		"http://[::1]:80/x", "https://[2001:db8::1]/x", "http://::1/x", "http://h_x/x", "http://h%2e/x",
		"http://\xc3\xa4.de/x", "http://h!/x", "http://h$/x", "http://h*/x", "http://h,x/x", "http://h;x/x",
		"http://.h/x", "http://h../x", "http://h-/x", "http://-h/x", "http://h.-x/x",
		/* ports */
		"http://h:/x", "http://h:+80/x", "http://h:-1/x", "http://h: 80/x", "http://h:80 /x", "http://h:0/x",
		"http://h:65536/x", "http://h:999999/x", "http://h:0x50/x", "http://h:80:80/x", "https://h:44a3/x",
		/* path: encodings, queries, fragments, dot segments, backslashes */
		"http://h/a%2e%2e/x", "http://h/%2e%2e", "http://h/a%00", "http://h/a?x=1", "http://h/a#f", "http://h/a;b",
		"http://h/a\\b", "http://h\\a", "http://h/..", "http://h/../x", "http://h/a/..", "http://h/a/../b",
		"http://h/.", "http://h/./a", "http://h/a/./b", "http://h/.hidden", "http://h//a", "http://h/a//b",
		"http://h/a b", "http://h/a+b", "http://h/a'b", "http://h/a\"b", "http://h/a<b", "http://h/a@b",
		"http://h/a:b", "http://h/\xff",
		/* scheme confusion */
		"http://https://h/x", "https:/h/x", "httpss://h", "hxxp://h", "http//h",
		NULL };
	fdl_url_t u;
	char lng[160];
	int i;

	for (i = 0; bad[i]; i++)
	{
		int r = fdl_url_parse(bad[i], &u);
		if (r) fprintf(stderr, "  review: url accepted: '%s'\n", bad[i]);
		CHECK(!r);
	}
	/* scheme decides TLS and default port; mixed case is fine, nothing downgrades */
	CHECK(fdl_url_parse("hTTpS://H/x", &u) && u.https == 1 && u.port == 443);
	CHECK(fdl_url_parse("https://h:80/x", &u) && u.https == 1 && u.port == 80);
	CHECK(fdl_url_parse("http://h:443/x", &u) && u.https == 0 && u.port == 443);
	CHECK(fdl_url_parse("https://h:65535", &u) && u.https && u.port == 65535);
	CHECK(fdl_url_parse("http://h:1", &u) && u.port == 1);
	CHECK(fdl_url_parse("http://h:00080/x", &u) && u.port == 80);	/* leading zeros: harmless, same port */
	CHECK(!fdl_url_parse("http://h:000080/x", &u));					/* more than 5 digits */
	/* path and tree */
	CHECK(fdl_url_parse("http://h/a/b//", &u) == 0);
	CHECK(fdl_url_parse("http://h/a/B~x/", &u) && !strcmp(u.path, "/a/B~x") && !strcmp(fdl_url_tree(&u), "B~x"));
	CHECK(fdl_url_parse("http://h/", &u) && !u.path[0] && !strcmp(fdl_url_tree(&u), "-"));
	/* host: 63-character label ok, 64 not */
	memset(lng, 0, sizeof(lng)); memcpy(lng, "http://", 7); memset(lng + 7, 'a', 63); memcpy(lng + 70, ".b/x", 5);
	CHECK(fdl_url_parse(lng, &u) && strlen(u.host) == 65);
	memset(lng + 7, 'a', 64); memcpy(lng + 71, ".b/x", 5);
	CHECK(!fdl_url_parse(lng, &u));
	/* length: exactly FDL_URL_MAX accepted, one more refused */
	memset(lng, 'a', sizeof(lng)); memcpy(lng, "http://h/", 9); lng[FDL_URL_MAX] = 0;
	CHECK(fdl_url_parse(lng, &u) && strlen(u.path) == FDL_URL_MAX - 8);
	lng[FDL_URL_MAX] = 'a'; lng[FDL_URL_MAX + 1] = 0;
	CHECK(!fdl_url_parse(lng, &u));
	/* a tree name longer than 32 never matches a manifest */
	memset(lng, 'a', sizeof(lng)); memcpy(lng, "http://h/", 9); lng[9 + 33] = 0;
	{ char err[64]; CHECK(fdl_url_parse(lng, &u) && !rv_load("FASTDL-WON1\ntree -\n", fdl_url_tree(&u), err) && strstr(err, "tree")); }
	/* Numeric host forms WinINet resolves to loopback/LAN (no IPv6). Accepted today: the server picks the URL
	 * anyway, the client only sends GETs with fixed suffixes (see REVIEW.md, informational). */
	CHECK(fdl_url_parse("http://127.0.0.1/x", &u) && fdl_url_parse("http://2130706433/x", &u) && fdl_url_parse("http://0x7f000001/x", &u));
}

/* ---- info strings, hex, escaping ---------------------------------------------------------------- */

static void rv_info(void)
{
	char v[32], *buf;
	uint8_t b[32];
	char o[700], in[256];
	int i, k;

	CHECK(fdl_info_value("\\a\\1\\a\\2", "a", v, sizeof(v)) && !strcmp(v, "1"));	/* first wins, like the engine */
	CHECK(fdl_info_value("\\ab\\1\\a\\2", "a", v, sizeof(v)) && !strcmp(v, "2"));	/* no prefix match */
	CHECK(fdl_info_value("\\a\\1\\ba\\2", "ba", v, sizeof(v)) && !strcmp(v, "2"));
	CHECK(fdl_info_value("\\a\\\\b\\2", "a", v, sizeof(v)) && !v[0]);				/* empty value */
	CHECK(fdl_info_value("\\a\\\\b\\2", "b", v, sizeof(v)) && !strcmp(v, "2"));
	CHECK(!fdl_info_value("a\\1", "a", v, sizeof(v)));								/* must start with '\' */
	CHECK(!fdl_info_value("\\a", "a", v, sizeof(v)) && !fdl_info_value("\\a\\", "b", v, sizeof(v)));
	CHECK(fdl_info_value("\\a\\0123456789", "a", v, 11) && !fdl_info_value("\\a\\0123456789", "a", v, 10));
	CHECK(!fdl_info_value("\\a\\1", "a", v, 0));
	/* value running exactly to the end of the 512-byte buffer without terminator: refused (ASan) */
	buf = malloc(FDL_INFO_MAX);
	memset(buf, 'v', FDL_INFO_MAX); memcpy(buf, "\\k\\", 3);
	CHECK(!fdl_info_value(buf, "k", o, sizeof(o)));
	buf[FDL_INFO_MAX - 1] = 0;
	CHECK(fdl_info_value(buf, "k", o, sizeof(o)) && strlen(o) == FDL_INFO_MAX - 4);
	free(buf);
	/* gamedir */
	CHECK(!fdl_gamedir_valid("CStrike") && !fdl_gamedir_valid("cs.1") && !fdl_gamedir_valid("nul") && !fdl_gamedir_valid("com1")
		&& !fdl_gamedir_valid("lpt9") && !fdl_gamedir_valid("a b") && !fdl_gamedir_valid("a\\b") && !fdl_gamedir_valid("."));
	CHECK(fdl_gamedir_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") && fdl_gamedir_valid("cs-15_x") && fdl_gamedir_valid("conx"));
	/* hex: exact length, lowercase only, NUL inside */
	memset(o, 'a', 64); o[64] = 0;
	CHECK(fdl_hex_decode(o, b, 32));
	o[63] = 'A'; CHECK(!fdl_hex_decode(o, b, 32));
	o[63] = 0; CHECK(!fdl_hex_decode(o, b, 32));
	o[63] = 'a'; o[10] = 0; CHECK(!fdl_hex_decode(o, b, 32));
	o[10] = 'a'; o[64] = 'a'; o[65] = 0; CHECK(!fdl_hex_decode(o, b, 32));
	CHECK(!fdl_hex_decode("0x", b, 1) && !fdl_hex_decode(" a", b, 1) && !fdl_hex_decode("", b, 1) && fdl_hex_decode("", b, 0));
	/* escaping: every byte; output uses only unreserved characters and decodes back to the input */
	for (i = 1; i < 256; i++)
	{
		char dec[16]; size_t n = 0, j;
		in[0] = 'a'; in[1] = (char)i; in[2] = 0;
		CHECK(fdl_url_escape(in, o, sizeof(o)));
		for (j = 0; o[j]; j++)
		{
			int c = (unsigned char)o[j];
			CHECK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' || c == '/' || c == '%');
			if (c == '%') { unsigned x; sscanf(o + j + 1, "%2X", &x); dec[n++] = (char)x; j += 2; } else dec[n++] = (char)c;
		}
		dec[n] = 0;
		CHECK(!strcmp(dec, i == '\\' ? "a/" : in));
	}
	/* the longest fetchable path fully escaped fits the buffer of Fetch() (3 * FDL_PATH_MAX + 1) */
	memset(in, '+', FDL_PATH_MAX); in[FDL_PATH_MAX] = 0;
	CHECK(fdl_url_escape(in, o, 3 * FDL_PATH_MAX + 1) && strlen(o) == 3 * FDL_PATH_MAX);
	CHECK(!fdl_url_escape(in, o, 3 * FDL_PATH_MAX));
	for (k = 0; k < 4; k++) CHECK(!fdl_url_escape("abc", o, (size_t)k));
}

/* ---- signed manifests -------------------------------------------------------------------------- */

static void rv_manifest(void)
{
	char err[64], body[4096], line[512];
	size_t n;
	uint8_t *d, zero[32];
	fdl_manifest_t m;
	int i;

	/* a header-only manifest is valid and lists nothing */
	{ d = rv_sign("FASTDL-WON1\ntree web\n", 21, &n);
	  CHECK(fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)) && m.count == 0 && !fdl_manifest_find(&m, "maps/a.bsp"));
	  fdl_manifest_free(&m); free(d); }
	/* entries: well-formed ones pass, every malformation fails */
	CHECK(rv_one(H64 " 1 maps/a.bsp"));
	CHECK(rv_one(H64 " 67108864 maps/a.bsp"));			/* exactly the limit */
	CHECK(!rv_one(H64 " 67108865 maps/a.bsp"));
	CHECK(rv_one(H64 " 262144 maps/a.txt") && !rv_one(H64 " 262145 maps/a.txt"));
	CHECK(rv_one(H64 " 4294967295 maps/a.bsp") == 0);		/* fits uint32, but over the limit */
	CHECK(!rv_one(H64 " 4294967296 maps/a.bsp") && !rv_one(H64 " 18446744073709551617 maps/a.bsp"));
	CHECK(!rv_one(H64 " -1 maps/a.bsp") && !rv_one(H64 " +1 maps/a.bsp") && !rv_one(H64 " 0x1 maps/a.bsp") && !rv_one(H64 " 1e3 maps/a.bsp"));
	CHECK(!rv_one(H64 " 00 maps/a.bsp") && !rv_one(H64 " 0 maps/a.bsp") && !rv_one(H64 "  maps/a.bsp"));
	CHECK(!rv_one(H64 "\t1 maps/a.bsp") && !rv_one(H64 " 1\tmaps/a.bsp") && !rv_one(H64 " 1  maps/a.bsp") && !rv_one(" " H64 " 1 maps/a.bsp"));
	CHECK(!rv_one(H64 " 1 maps/a.bsp ") && !rv_one(H64 " 1 maps/a.bsp\t") && !rv_one(H64 " 1 maps/a.bsp."));
	CHECK(!rv_one("0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A8 1 maps/a.bsp"));
	CHECK(!rv_one(H64 "a 1 maps/a.bsp") && !rv_one("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a 1 maps/a.bsp"));
	CHECK(!rv_one(H64 " 1 maps\\a.bsp") && !rv_one(H64 " 1 MAPS\\A.BSP") && !rv_one(H64 " 1 /maps/a.bsp"));
	CHECK(!rv_one(H64 " 1 maps/../a.bsp") && !rv_one(H64 " 1 maps/a.bsp::$DATA") && !rv_one(H64 " 1 C:/a.wad"));
	CHECK(!rv_one(H64 " 1 autoexec.cfg") && !rv_one(H64 " 1 cl_dlls/client.dll") && !rv_one(H64 " 1 fastdl.asi"));
	CHECK(!rv_one(H64 " 1 maps/sub/a.bsp") && !rv_one(H64 " 1 a.bsp") && !rv_one(H64 " 1 maps/A~1.BSP") && !rv_one(H64 " 1 maps/a b.bsp"));
	CHECK(!rv_one(H64 " 1 maps/con.bsp") && !rv_one(H64 " 1 !MD50123456789abcdef0123456789abcdef") && !rv_one(H64 " 1 events/a.sc"));
	CHECK(!rv_one(H64 " 1 maps/\xe4.bsp") && !rv_one(H64 " 1 maps/a\x7f.bsp") && !rv_one(H64 " 1 maps/a\x01.bsp"));
	CHECK(!rv_one(H64 " 1 maps/a.bsp\r") && !rv_one(""));
	/* ordering: strictly increasing by fdl_path_cmp; exact and case duplicates refused */
	{ const char *ok = "FASTDL-WON1\ntree web\n" H64 " 1 maps/A-b.bsp\n" H64 " 1 maps/a.bsp\n" H64 " 1 maps/a_b.bsp\n" H64 " 1 maps/ab.bsp\n" H64 " 1 sound/a-b.wav\n" H64 " 1 sound/a.wav\n" H64 " 1 sound/a/b.wav\n" H64 " 1 sound/a_b.wav\n";
	  CHECK(rv_load(ok, "web", err)); }
	CHECK(!rv_load("FASTDL-WON1\ntree web\n" H64 " 1 maps/a.bsp\n" H64 " 1 maps/a.bsp\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree web\n" H64 " 1 maps/a.bsp\n" H64 " 1 maps/A.BSP\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree web\n" H64 " 1 sound/a/b.wav\n" H64 " 1 sound/a.wav\n", "web", err));
	/* header and tree line */
	CHECK(!rv_load("FASTDL-WON1 \ntree web\n", "web", err) && !rv_load("fastdl-won1\ntree web\n", "web", err));
	CHECK(!rv_load("FASTDL-WON2\ntree web\n", "web", err) && !rv_load("\nFASTDL-WON1\ntree web\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree web \n", "web", err) && !rv_load("FASTDL-WON1\ntree  web\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree web\n", "we", err) && !rv_load("FASTDL-WON1\ntree we\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree Web\n", "web", err) && !rv_load("FASTDL-WON1\ntree web\ntree web\n", "web", err));
	CHECK(!rv_load("FASTDL-WON1\ntree -\n", "web", err) && rv_load("FASTDL-WON1\ntree -\n", "-", err));
	CHECK(!rv_load("FASTDL-WON1\ntree web", "web", err) && !rv_load("FASTDL-WON1\n", "web", err));
	/* signature line: framing, encoding, every bit, malleable S, other key */
	{ const char *b = "FASTDL-WON1\ntree web\n" H64 " 1 maps/a.bsp\n"; size_t bl = strlen(b), j;
	  d = rv_sign(b, bl, &n);
	  CHECK(fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)) && m.count == 1); fdl_manifest_free(&m);
	  for (j = bl; j < n; j++)
	  { uint8_t o = d[j]; int bit;
	    for (bit = 0; bit < 8; bit++) { d[j] = (uint8_t)(o ^ (1 << bit)); i = fdl_manifest_load(&m, d, n, rv_pk, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i); }
	    d[j] = o; }
	  /* S + L (the group order): same point, non-canonical S; Monocypher must refuse it */
	  { static const uint8_t L[32] = { 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
	                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };
	    uint8_t sig[64]; unsigned carry = 0; int q; static const char hx[] = "0123456789abcdef";
	    memcpy(line, d + bl + 4, 128); line[128] = 0; CHECK(fdl_hex_decode(line, sig, 64));
	    for (q = 0; q < 32; q++) { unsigned s = sig[32 + q] + L[q] + carry; sig[32 + q] = (uint8_t)s; carry = s >> 8; }
	    if (!carry && sig[63] < 0x20)
	    { uint8_t *d2 = malloc(n); memcpy(d2, d, n);
	      for (q = 0; q < 64; q++) { d2[bl + 4 + 2 * q] = (uint8_t)hx[sig[q] >> 4]; d2[bl + 5 + 2 * q] = (uint8_t)hx[sig[q] & 15]; }
	      i = fdl_manifest_load(&m, d2, n, rv_pk, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i);
	      free(d2); } }
	  /* framing around a valid signature */
	  { uint8_t *d2 = malloc(n + 2);
	    memcpy(d2, d, n); d2[n] = '\n'; i = fdl_manifest_load(&m, d2, n + 1, rv_pk, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i);
	    i = fdl_manifest_load(&m, d2, n - 1, rv_pk, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i);
	    memcpy(d2 + 1, d, n); d2[0] = ' '; i = fdl_manifest_load(&m, d2, n + 1, rv_pk, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i);
	    free(d2); }
	  /* zero key and wrong key */
	  memset(zero, 0, sizeof(zero));
	  i = fdl_manifest_load(&m, d, n, zero, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m); CHECK(!i);
	  free(d); }
	/* A small-order public key (the neutral point) with the trivial signature R = neutral, S = 0 verifies for
	 * any message unless the verifier rejects such keys. The key comes from the game server itself, so this
	 * only matters for a misconfigured sv_won_dlkey (informational, REVIEW.md). Reported, not asserted. */
	{ uint8_t ident[32] = { 1 }; const char *b = "FASTDL-WON1\ntree web\n" H64 " 1 maps/a.bsp\n"; size_t bl = strlen(b);
	  uint8_t *d2 = malloc(bl + 133); memcpy(d2, b, bl); memcpy(d2 + bl, "sig ", 4);
	  memset(d2 + bl + 4, '0', 128); d2[bl + 4 + 1] = '1'; d2[bl + 132] = '\n';
	  i = fdl_manifest_load(&m, d2, bl + 133, ident, "web", err, sizeof(err)); if (i) fdl_manifest_free(&m);
	  printf("  info: small-order key with trivial signature %s\n", i ? "ACCEPTED" : "rejected");
	  free(d2); }
	/* size limits: FDL_MANIFEST_MAX + 1 bytes refused before anything else; 65536 entries ok, 65537 not */
	{ uint8_t *big = calloc(1, FDL_MANIFEST_MAX + 1);
	  memcpy(big, "FASTDL-WON1\n", 12);
	  CHECK(!fdl_manifest_load(&m, big, FDL_MANIFEST_MAX + 1, rv_pk, "web", err, sizeof(err)) && strstr(err, "too big"));
	  free(big); }
	{ size_t cap = 65537u * 90 + 64, len = 0; char *b = malloc(cap); int e; fdl_manifest_t mm;
	  len += (size_t)sprintf(b, "FASTDL-WON1\ntree web\n");
	  for (e = 0; e < 65536; e++) len += (size_t)sprintf(b + len, H64 " 1 sound/%05d.wav\n", e);
	  d = rv_sign(b, len, &n);
	  CHECK(fdl_manifest_load(&mm, d, n, rv_pk, "web", err, sizeof(err)) && mm.count == 65536);
	  if (mm.count == 65536)
	  { CHECK(fdl_manifest_find(&mm, "sound/00000.wav") == &mm.entries[0] && fdl_manifest_find(&mm, "SOUND\\65535.WAV") == &mm.entries[65535]);
	    CHECK(!fdl_manifest_find(&mm, "sound/65536.wav") && !fdl_manifest_find(&mm, "sound/0000.wav") && !fdl_manifest_find(&mm, ""));
	    fdl_manifest_free(&mm); }
	  free(d);
	  len += (size_t)sprintf(b + len, H64 " 1 sound/x.wav\n");
	  d = rv_sign(b, len, &n);
	  CHECK(!fdl_manifest_load(&mm, d, n, rv_pk, "web", err, sizeof(err)) && strstr(err, "too many"));
	  free(d); free(b); }
	/* every byte value (but NUL, see bad_nul) at every position of a short valid manifest */
	{ const char *b = "FASTDL-WON1\ntree web\n" H64 " 7 maps/a.bsp\n"; size_t bl = strlen(b), j; int c;
	  for (j = 0; j < bl; j++)
	    for (c = 1; c < 256; c += 3)
	    { if ((unsigned char)b[j] == c) continue;
	      memcpy(body, b, bl + 1); body[j] = (char)c;
	      i = rv_load(body, "web", err);
	      /* a changed byte may still form a valid manifest only if the entry stays a FETCH path */
	      if (i) { char *sp = strrchr(body, ' '); body[bl - 1] = 0; if (!(sp && fdl_classify(sp + 1, NULL) == FDL_FETCH)) fprintf(stderr, "  mutation %zu=%d accepted: [%s]\n", j, c, sp ? sp + 1 : "?"); CHECK(sp && fdl_classify(sp + 1, NULL) == FDL_FETCH); } } }
}

/* ---- lookup and ordering ------------------------------------------------------------------------- */

static void rv_cmp(void)
{
	static const char *const s[] = { "", "a", "A", "a/b", "a\\b", "a-b", "a.b", "a_b", "a0", "aa", "Ab", "b", "~", "[", "]", NULL };
	int i, j, k;
	for (i = 0; s[i]; i++)
		for (j = 0; s[j]; j++)
		{
			int x = fdl_path_cmp(s[i], s[j]), y = fdl_path_cmp(s[j], s[i]);
			CHECK((x < 0 && y > 0) || (x > 0 && y < 0) || (x == 0 && y == 0));
			for (k = 0; s[k]; k++)
				if (x <= 0 && fdl_path_cmp(s[j], s[k]) <= 0) CHECK(fdl_path_cmp(s[i], s[k]) <= 0);
		}
}

/* ---- content plausibility ------------------------------------------------------------------------- */

static void rv_magic(void)
{
	const uint8_t wad[12] = { 'W','A','D','3', 0,0,0,0, 100,0,0,0 }, z[16] = { 0 };
	CHECK(!fdl_magic_ok("maps/a.bsp", (const uint8_t *)"\x1e\0\0", 3, 3));
	CHECK(!fdl_magic_ok("maps/a.bsp", (const uint8_t *)"\x1d\0\0\0", 4, 4));
	CHECK(fdl_magic_ok("a.wad", wad, 12, 100) && !fdl_magic_ok("a.wad", wad, 12, 99) && !fdl_magic_ok("a.wad", wad, 11, 100));
	CHECK(!fdl_magic_ok("a.mdl", (const uint8_t *)"IDS", 3, 3) && fdl_magic_ok("a.MDL", (const uint8_t *)"IDSQ", 4, 4));
	CHECK(!fdl_magic_ok("a.wav", (const uint8_t *)"RIFF\0\0\0\0WAV", 11, 11));
	CHECK(!fdl_magic_ok("a.bmp", (const uint8_t *)"B", 1, 1) && !fdl_magic_ok("a.tga", z, 3, 3));
	CHECK(!fdl_magic_ok("a.mp3", (const uint8_t *)"\xff\x1f\0", 3, 3) && fdl_magic_ok("a.mp3", (const uint8_t *)"\xff\xfb\0", 3, 3));
	CHECK(!fdl_magic_ok("a.dll", (const uint8_t *)"MZ", 2, 2) && !fdl_magic_ok("a.", z, 16, 16) && !fdl_magic_ok("", z, 16, 16));
	CHECK(!fdl_magic_ok("a.wad", wad, 0, 0));
}

static void test_review(void)
{
	rv_keys();
	rv_classify(); rv_url(); rv_info(); rv_manifest(); rv_cmp(); rv_magic();
	printf("  review: %d hardening notes\n", hardening);
}
