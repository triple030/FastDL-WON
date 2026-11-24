/*
 * wsock32.dll proxy (generated from the export table of Windows XP SP3 wsock32.dll: same names and
 * ordinals). hl.exe imports WSOCK32.dll, so a copy in the Half-Life folder is loaded at process start,
 * before the engine runs: this gives fastdl a load point that does not depend on Miles loading *.asi.
 * Every export jumps to the same export of the system wsock32.dll, loaded by full path.
 */
#include <windows.h>

#define WS_ORDINALS 1143
void *g_ws_real[WS_ORDINALS];

int WsProxyInit(void)
{
	char path[MAX_PATH];
	HMODULE m;
	int i;
	UINT n = GetSystemDirectoryA(path, MAX_PATH - 16);
	if (!n || n >= MAX_PATH - 16)
		return 0;
	lstrcatA(path, "\\wsock32.dll");
	m = LoadLibraryA(path);
	if (!m)
		return 0;
	for (i = 1; i < WS_ORDINALS; i++)
		g_ws_real[i] = (void *)GetProcAddress(m, (LPCSTR)(ULONG_PTR)i);
	return 1;
}

/* jmp [g_ws_real + 4*ordinal] - registers and stack untouched, so any calling convention passes through */
__asm__(".globl _ws_stub_1\n_ws_stub_1:\n\tjmp *_g_ws_real+4\n");
__asm__(".globl _ws_stub_2\n_ws_stub_2:\n\tjmp *_g_ws_real+8\n");
__asm__(".globl _ws_stub_3\n_ws_stub_3:\n\tjmp *_g_ws_real+12\n");
__asm__(".globl _ws_stub_4\n_ws_stub_4:\n\tjmp *_g_ws_real+16\n");
__asm__(".globl _ws_stub_5\n_ws_stub_5:\n\tjmp *_g_ws_real+20\n");
__asm__(".globl _ws_stub_6\n_ws_stub_6:\n\tjmp *_g_ws_real+24\n");
__asm__(".globl _ws_stub_7\n_ws_stub_7:\n\tjmp *_g_ws_real+28\n");
__asm__(".globl _ws_stub_8\n_ws_stub_8:\n\tjmp *_g_ws_real+32\n");
__asm__(".globl _ws_stub_9\n_ws_stub_9:\n\tjmp *_g_ws_real+36\n");
__asm__(".globl _ws_stub_10\n_ws_stub_10:\n\tjmp *_g_ws_real+40\n");
__asm__(".globl _ws_stub_11\n_ws_stub_11:\n\tjmp *_g_ws_real+44\n");
__asm__(".globl _ws_stub_12\n_ws_stub_12:\n\tjmp *_g_ws_real+48\n");
__asm__(".globl _ws_stub_13\n_ws_stub_13:\n\tjmp *_g_ws_real+52\n");
__asm__(".globl _ws_stub_14\n_ws_stub_14:\n\tjmp *_g_ws_real+56\n");
__asm__(".globl _ws_stub_15\n_ws_stub_15:\n\tjmp *_g_ws_real+60\n");
__asm__(".globl _ws_stub_16\n_ws_stub_16:\n\tjmp *_g_ws_real+64\n");
__asm__(".globl _ws_stub_17\n_ws_stub_17:\n\tjmp *_g_ws_real+68\n");
__asm__(".globl _ws_stub_18\n_ws_stub_18:\n\tjmp *_g_ws_real+72\n");
__asm__(".globl _ws_stub_19\n_ws_stub_19:\n\tjmp *_g_ws_real+76\n");
__asm__(".globl _ws_stub_20\n_ws_stub_20:\n\tjmp *_g_ws_real+80\n");
__asm__(".globl _ws_stub_21\n_ws_stub_21:\n\tjmp *_g_ws_real+84\n");
__asm__(".globl _ws_stub_22\n_ws_stub_22:\n\tjmp *_g_ws_real+88\n");
__asm__(".globl _ws_stub_23\n_ws_stub_23:\n\tjmp *_g_ws_real+92\n");
__asm__(".globl _ws_stub_24\n_ws_stub_24:\n\tjmp *_g_ws_real+96\n");
__asm__(".globl _ws_stub_51\n_ws_stub_51:\n\tjmp *_g_ws_real+204\n");
__asm__(".globl _ws_stub_52\n_ws_stub_52:\n\tjmp *_g_ws_real+208\n");
__asm__(".globl _ws_stub_53\n_ws_stub_53:\n\tjmp *_g_ws_real+212\n");
__asm__(".globl _ws_stub_54\n_ws_stub_54:\n\tjmp *_g_ws_real+216\n");
__asm__(".globl _ws_stub_55\n_ws_stub_55:\n\tjmp *_g_ws_real+220\n");
__asm__(".globl _ws_stub_56\n_ws_stub_56:\n\tjmp *_g_ws_real+224\n");
__asm__(".globl _ws_stub_57\n_ws_stub_57:\n\tjmp *_g_ws_real+228\n");
__asm__(".globl _ws_stub_101\n_ws_stub_101:\n\tjmp *_g_ws_real+404\n");
__asm__(".globl _ws_stub_102\n_ws_stub_102:\n\tjmp *_g_ws_real+408\n");
__asm__(".globl _ws_stub_103\n_ws_stub_103:\n\tjmp *_g_ws_real+412\n");
__asm__(".globl _ws_stub_104\n_ws_stub_104:\n\tjmp *_g_ws_real+416\n");
__asm__(".globl _ws_stub_105\n_ws_stub_105:\n\tjmp *_g_ws_real+420\n");
__asm__(".globl _ws_stub_106\n_ws_stub_106:\n\tjmp *_g_ws_real+424\n");
__asm__(".globl _ws_stub_107\n_ws_stub_107:\n\tjmp *_g_ws_real+428\n");
__asm__(".globl _ws_stub_108\n_ws_stub_108:\n\tjmp *_g_ws_real+432\n");
__asm__(".globl _ws_stub_109\n_ws_stub_109:\n\tjmp *_g_ws_real+436\n");
__asm__(".globl _ws_stub_110\n_ws_stub_110:\n\tjmp *_g_ws_real+440\n");
__asm__(".globl _ws_stub_111\n_ws_stub_111:\n\tjmp *_g_ws_real+444\n");
__asm__(".globl _ws_stub_112\n_ws_stub_112:\n\tjmp *_g_ws_real+448\n");
__asm__(".globl _ws_stub_113\n_ws_stub_113:\n\tjmp *_g_ws_real+452\n");
__asm__(".globl _ws_stub_114\n_ws_stub_114:\n\tjmp *_g_ws_real+456\n");
__asm__(".globl _ws_stub_115\n_ws_stub_115:\n\tjmp *_g_ws_real+460\n");
__asm__(".globl _ws_stub_116\n_ws_stub_116:\n\tjmp *_g_ws_real+464\n");
__asm__(".globl _ws_stub_151\n_ws_stub_151:\n\tjmp *_g_ws_real+604\n");
__asm__(".globl _ws_stub_500\n_ws_stub_500:\n\tjmp *_g_ws_real+2000\n");
__asm__(".globl _ws_stub_1000\n_ws_stub_1000:\n\tjmp *_g_ws_real+4000\n");
__asm__(".globl _ws_stub_1100\n_ws_stub_1100:\n\tjmp *_g_ws_real+4400\n");
__asm__(".globl _ws_stub_1101\n_ws_stub_1101:\n\tjmp *_g_ws_real+4404\n");
__asm__(".globl _ws_stub_1102\n_ws_stub_1102:\n\tjmp *_g_ws_real+4408\n");
__asm__(".globl _ws_stub_1103\n_ws_stub_1103:\n\tjmp *_g_ws_real+4412\n");
__asm__(".globl _ws_stub_1104\n_ws_stub_1104:\n\tjmp *_g_ws_real+4416\n");
__asm__(".globl _ws_stub_1105\n_ws_stub_1105:\n\tjmp *_g_ws_real+4420\n");
__asm__(".globl _ws_stub_1106\n_ws_stub_1106:\n\tjmp *_g_ws_real+4424\n");
__asm__(".globl _ws_stub_1107\n_ws_stub_1107:\n\tjmp *_g_ws_real+4428\n");
__asm__(".globl _ws_stub_1108\n_ws_stub_1108:\n\tjmp *_g_ws_real+4432\n");
__asm__(".globl _ws_stub_1109\n_ws_stub_1109:\n\tjmp *_g_ws_real+4436\n");
__asm__(".globl _ws_stub_1110\n_ws_stub_1110:\n\tjmp *_g_ws_real+4440\n");
__asm__(".globl _ws_stub_1111\n_ws_stub_1111:\n\tjmp *_g_ws_real+4444\n");
__asm__(".globl _ws_stub_1112\n_ws_stub_1112:\n\tjmp *_g_ws_real+4448\n");
__asm__(".globl _ws_stub_1113\n_ws_stub_1113:\n\tjmp *_g_ws_real+4452\n");
__asm__(".globl _ws_stub_1114\n_ws_stub_1114:\n\tjmp *_g_ws_real+4456\n");
__asm__(".globl _ws_stub_1115\n_ws_stub_1115:\n\tjmp *_g_ws_real+4460\n");
__asm__(".globl _ws_stub_1116\n_ws_stub_1116:\n\tjmp *_g_ws_real+4464\n");
__asm__(".globl _ws_stub_1117\n_ws_stub_1117:\n\tjmp *_g_ws_real+4468\n");
__asm__(".globl _ws_stub_1118\n_ws_stub_1118:\n\tjmp *_g_ws_real+4472\n");
__asm__(".globl _ws_stub_1119\n_ws_stub_1119:\n\tjmp *_g_ws_real+4476\n");
__asm__(".globl _ws_stub_1120\n_ws_stub_1120:\n\tjmp *_g_ws_real+4480\n");
__asm__(".globl _ws_stub_1130\n_ws_stub_1130:\n\tjmp *_g_ws_real+4520\n");
__asm__(".globl _ws_stub_1140\n_ws_stub_1140:\n\tjmp *_g_ws_real+4560\n");
__asm__(".globl _ws_stub_1141\n_ws_stub_1141:\n\tjmp *_g_ws_real+4564\n");
__asm__(".globl _ws_stub_1142\n_ws_stub_1142:\n\tjmp *_g_ws_real+4568\n");
