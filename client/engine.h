/*
 * fastdl engine rows: what the plugin needs to know about one engine DLL build. The rows themselves are in
 * engines.h (generated, see the comment tables there). A row matches only if every check passes: PE header
 * (module rows), every signature, the export cross-checks (ENG_EXPORTS) and the data checks (cl_allowdownload
 * cvar_t name, cmd_functions list). Needs DWORD/WORD/BYTE (windows.h, or the typedefs of test/test_engines.c).
 */
#ifndef FASTDL_ENGINE_H
#define FASTDL_ENGINE_H

typedef struct
{
	DWORD addr;			/* absolute VA (blob rows) or RVA (module rows); 0 = not used by this row */
	BYTE sig[16];		/* bytes at addr; no base relocation falls inside them */
	BYTE siglen;		/* bytes compared */
	BYTE prologue;		/* bytes moved to the trampoline when hooked (position independent); 0 = not hooked */
} site_t;

/* netchan_t / fragbuf_t offsets for the Netchan_CopyFileFragments guard */
typedef struct
{
	WORD ready;			/* netchan_t: incomingready[file stream] */
	WORD frags;			/* netchan_t: incomingbufs[file stream] */
	WORD fb_data;		/* fragbuf_t: frag_message.data */
	WORD fb_size;		/* fragbuf_t: frag_message.cursize */
	WORD fb_isfile;		/* fragbuf_t: "is a file" flag of a shared stream (1.1.0.0); 0 = file-only stream */
} push_t;

enum { API_CHECKFILE_MSG_NAME,		/* int CL_CheckFile(sizebuf_t *msg, const char *name)   1.1.x */
	   API_CHECKORDOWNLOAD_NAME };	/* int CL_CheckOrDownloadFile(const char *name)         1.0.x */
enum { FS_SIZE,						/* int f(const char *name): size, -1 = not found */
	   FS_FOPEN_FCLOSE };			/* int f(const char *name, FILE **f) + the engine's fclose */
enum { SI_ENGINE,					/* cl.serverinfo (512 bytes), filled by the engine's "fullserverinfo" */
	   SI_PLUGIN_CMD };				/* no such command: the plugin links its own into cmd_functions */

#define ENG_NAME_IS_FORMAT	0x01	/* the engine sprintf()s the resource name: names with '%' are blocked */
#define ENG_NAME_ASCII		0x02	/* names with bytes outside 0x20..0x7e are blocked */
#define ENG_EXPORTS			0x04	/* Con_Printf / Cmd_Argv are named exports: cross-checked, Cmd_Argv taken from there */
#define ENG_UNBOUNDED_NAMES	0x08	/* CopyFileFragments strcpy's the pushed name: refusal terminates it, unterminated
									   names are refused */

typedef struct
{
	const char *name;
	const char *module;			/* NULL: blob mapped at its fixed base, absolute VAs; else "hw.dll" / "sw.dll" */
	DWORD stamp, imagesize;		/* PE TimeDateStamp / SizeOfImage of the module (module rows) */
	BYTE api, fs_api, si_src;
	BYTE allowdl_off;			/* offset of the float value in the cl_allowdownload cvar_t */
	site_t check;				/* hooked: CL_CheckFile / CL_CheckOrDownloadFile */
	site_t filesize;			/* FS_FileSize / COM_FileSize / COM_FOpenFile */
	site_t fclose;				/* FS_FOPEN_FCLOSE: the engine's CRT fclose */
	site_t conprintf;
	site_t copyfile;			/* hooked: Netchan_CopyFileFragments; addr 0 = engine has no server-named file stream */
	push_t push;
	DWORD serverinfo;			/* SI_ENGINE: cl.serverinfo */
	DWORD cmd_functions;		/* SI_PLUGIN_CMD: head of the command list, node { next, name, function, flags } */
	DWORD net_from;				/* SI_PLUGIN_CMD: netadr_t (20 bytes) of the last received packet */
	DWORD gamedir;				/* com_gamedir */
	DWORD allowdl_cvar;			/* cvar_t of cl_allowdownload; its first dword points at the name */
	WORD name_max;				/* longest resource name the engine handles safely, 0 = no extra limit */
	WORD flags;
	site_t cbuf;				/* "83 c4 04 03 c8 a1" in Cbuf_AddText: the disp32 before it is &cmd_text.cursize,
								   the one after it &cmd_text.maxsize */
	DWORD cmd_text;				/* &cmd_text.data (then maxsize, cursize): pending console text, read for a
								   'fullserverinfo' that is not executed yet; 0 = not used */
} engine_t;

#endif
