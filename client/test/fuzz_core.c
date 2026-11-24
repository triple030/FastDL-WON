/* libFuzzer target for every parser in core.c (built by test/fuzz.sh). */
#include "../core.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t pub[32] = { 1 };
	char *s, out[256], *info;
	uint32_t lim;
	fdl_url_t u;
	fdl_manifest_t m;
	char err[64];

	if (size < 1)
		return 0;
	/* NUL-terminated copy for the string APIs */
	s = (char *)malloc(size);
	memcpy(s, data + 1, size - 1);
	s[size - 1] = 0;
	switch (data[0] % 6)
	{
	case 0:
		fdl_classify(s, &lim);
		fdl_is_text(s);
		break;
	case 1:
		if (fdl_url_parse(s, &u))
		{
			/* invariants of an accepted URL: scheme decides TLS, host and port set, path without "//" */
			int sec = (s[4] == 's' || s[4] == 'S');
			if (u.https != sec || !u.host[0] || !u.port || strstr(u.path, "//") || strlen(u.host) > 253)
				abort();
		}
		break;
	case 2:		/* exactly the engine's 512-byte buffer, possibly without a terminator */
		info = (char *)malloc(FDL_INFO_MAX);
		memset(info, 0, FDL_INFO_MAX);
		memcpy(info, data + 1, size - 1 > FDL_INFO_MAX ? FDL_INFO_MAX : size - 1);
		fdl_info_value(info, "sv_won_downloadurl", out, sizeof(out));
		fdl_info_value(info, "*gamedir", out, 8);
		free(info);
		break;
	case 3:
		fdl_url_escape(s, out, sizeof(out));
		fdl_gamedir_valid(s);
		{ uint8_t b[32]; fdl_hex_decode(s, b, 32); }
		break;
	case 4:
		if (fdl_manifest_load(&m, data + 1, size - 1, pub, "web", err, sizeof(err)))
		{
			fdl_manifest_find(&m, s);
			if (m.count)
				fdl_manifest_find(&m, m.entries[m.count - 1].path);
			fdl_manifest_free(&m);
		}
		break;
	case 5:
		fdl_magic_ok(s, data + 1, size - 1, (uint32_t)size);
		break;
	}
	free(s);
	return 0;
}
