#define _GNU_SOURCE		/* strnlen */
/* libFuzzer target with property checks for fdl_cbuf_serverinfo (built by test/fuzz.sh, TARGET=fuzz_cbuf).
 * The input is the pending command text as read from the engine: any bytes, no terminator. */
#include "../core.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char info[FDL_INFO_MAX + 1];
	size_t n, i;
	char *buf = (char *)malloc(size ? size : 1);	/* exact size: ASan catches reads past len */

	memcpy(buf, data, size);
	memset(info, 'Z', sizeof(info));
	if (!fdl_cbuf_serverinfo(buf, size, info))
	{
		for (i = 0; i < FDL_INFO_MAX; i++)
			if (info[i])
				abort();	/* refused: nothing left in info */
		free(buf);
		return 0;
	}
	if (info[FDL_INFO_MAX] != 'Z')
		abort();		/* wrote past the buffer */
	n = strnlen(info, FDL_INFO_MAX);
	if (n >= FDL_INFO_MAX)
		abort();
	for (i = 0; i < n; i++)
		if ((unsigned char)info[i] < 0x20 || info[i] == 0x7f || info[i] == '"')
			abort();
	/* the value is the quoted argument of a "fullserverinfo" in the input */
	for (i = 0; i + 14 <= size; i++)
	{
		size_t j = i + 14;
		if (memcmp(buf + i, "fullserverinfo", 14))
			continue;
		while (j < size && (buf[j] == ' ' || buf[j] == '\t'))
			j++;
		if (j + n + 2 <= size && buf[j] == '"' && !memcmp(buf + j + 1, info, n) && buf[j + n + 1] == '"')
			break;
	}
	if (i + 14 > size)
		abort();
	/* exactly one command named fullserverinfo at a command start: a second one would have been refused */
	free(buf);
	return 0;
}
