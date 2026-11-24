/* Review 2: helper for server/tools/fuzz_diff_classify.py. Reads NUL-terminated paths on stdin and writes
 * "<class> <limit>\n" for each (fdl_classify), so the Python rules of the builder can be compared with the
 * client's. Built by the fuzz script (gcc -static). */
#include "../core.h"
#include <stdio.h>

int main(void)
{
	static char p[65536];
	size_t n = 0;
	int c;
	while ((c = getchar()) != EOF)
	{
		if (c)
		{
			if (n < sizeof(p) - 1) p[n++] = (char)c;
			continue;
		}
		p[n] = 0; n = 0;
		{
			uint32_t lim = 0;
			fdl_class_t k = fdl_classify(p, &lim);
			printf("%d %u\n", (int)k, (unsigned)lim);
		}
	}
	return 0;
}
