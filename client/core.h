/*
 * fastdl core: everything security relevant that does not touch Windows or the engine.
 * Portable C so it can be unit tested and fuzzed on Linux (see test/).
 */
#ifndef FASTDL_CORE_H
#define FASTDL_CORE_H

#include <stddef.h>
#include <stdint.h>

#define FDL_PATH_MAX		200		/* relative resource path */
#define FDL_URL_MAX			100		/* same limit as the server side */
#define FDL_INFO_MAX		512		/* cl.serverinfo buffer size */
#define FDL_MANIFEST_MAX	(8u * 1024u * 1024u)
#define FDL_ENTRIES_MAX		65536
#define FDL_HASH_LEN		32		/* BLAKE2b-256 */

/* what to do with a resource the engine asks for */
typedef enum
{
	FDL_PASS = 0,	/* leave it to the engine's in-band download: "!MD5<32 hex>" customizations and
					   game content types (bsp wad wav mp3 mdl spr tga bmp sc) outside the HTTP rules */
	FDL_FETCH,		/* client game file type in its usual place: may be fetched over HTTP */
	FDL_BLOCK		/* everything else: never downloaded, not even in-band */
} fdl_class_t;

/* Classify a resource path from the server. On FDL_FETCH, *limit is the maximum file size. */
fdl_class_t fdl_classify(const char *path, uint32_t *limit);

/* Text file types are checked for NUL bytes while streaming. */
int fdl_is_text(const char *path);

/* http://host[:port][/path] or https://host[:port][/path] with the server's rules (no "//", no segment
 * starting with '.'); splits it on success. Default port 80 / 443. */
typedef struct
{
	char host[254];			/* at most 253 characters */
	unsigned short port;
	int https;				/* 1: TLS (certificate checked by WinINet, no fallback to http) */
	char path[FDL_URL_MAX + 1];		/* "" or "/a/b", no trailing slash */
} fdl_url_t;
int fdl_url_parse(const char *url, fdl_url_t *out);

#define FDL_CBUF_MAX		16384	/* longest pending command text that is scanned */
/* Serverinfo from pending console text (the engine's cmd_text, len bytes, need not be terminated): the
 * argument of the one command 'fullserverinfo "<info>"' in it, split into commands like Cbuf_Execute does.
 * info gets FDL_INFO_MAX bytes, NUL-terminated. 0 (info empty) if there is no such command, more than one,
 * or it is malformed or too long. */
int fdl_cbuf_serverinfo(const char *buf, size_t len, char *info);

/* Reads key from a "\k\v\k\v" info string of at most FDL_INFO_MAX bytes (need not be terminated). */
int fdl_info_value(const char *info, const char *key, char *out, size_t outlen);

/* *gamedir: [a-z0-9_-], 1..32 chars */
int fdl_gamedir_valid(const char *gamedir);

/* exactly 2*n lowercase hex digits */
int fdl_hex_decode(const char *hex, uint8_t *out, size_t n);

/* percent-encodes everything but [A-Za-z0-9-._~/]; returns 0 if it does not fit */
int fdl_url_escape(const char *in, char *out, size_t outlen);

/* ---- signed manifest -------------------------------------------------------------------------
 *  FASTDL-WON1\n
 *  tree <name>[ <serial>]\n                  (last path segment of the URL, "-" for none; serial: decimal,
 *                                            increases with every build, refused when lower than seen)
 *  <64 hex BLAKE2b-256> <size> <path>\n      (sorted by lowercased path, unique, all FDL_FETCH)
 *  ...
 *  sig <128 hex Ed25519 signature over every byte before "sig ">\n
 */
typedef struct
{
	const char *path;		/* points into the manifest copy */
	uint32_t size;
	uint8_t hash[FDL_HASH_LEN];
} fdl_entry_t;

typedef struct
{
	char *text;				/* private copy, NUL separated paths */
	fdl_entry_t *entries;
	int count;
	uint64_t serial;		/* "tree <name> <serial>", 0 without */
} fdl_manifest_t;

/* Verifies the signature first, then parses. Returns 1 on success; err gets a short reason. */
int fdl_manifest_load(fdl_manifest_t *m, const uint8_t *data, size_t len, const uint8_t pubkey[32],
	const char *tree, char *err, size_t errlen);
/* tree name for a parsed URL: last path segment, "-" for none */
const char *fdl_url_tree(const fdl_url_t *u);
const fdl_entry_t *fdl_manifest_find(const fdl_manifest_t *m, const char *path);
void fdl_manifest_free(fdl_manifest_t *m);

/* case-insensitive (ASCII), '\\' == '/' */
int fdl_path_cmp(const char *a, const char *b);

/* HTTP time budget of one connection attempt (GetTickCount milliseconds, wrap-safe): returns the time left.
 * *start = start of the current burst (0 = none); last_end = when the previous HTTP work ENDED (0 = never).
 * A new burst starts only after gap_ms without HTTP work, so the budget is a hard limit for one loading. */
uint32_t fdl_burst_left(uint32_t *start, uint32_t last_end, uint32_t now, uint32_t burst_ms, uint32_t gap_ms);

/* Plausibility of the first bytes of a finished download (catches operator mistakes). */
int fdl_magic_ok(const char *path, const uint8_t *head, size_t headlen, uint32_t size);

#endif
