/*
 * FastDL-WON
 *
 * Publishes sv_won_downloadurl and sv_won_dlkey in the serverinfo, where the FastDL client
 * plugin reads them. Both are published together or not at all.
 *
 * Requires AMX Mod X 1.8.1 with fakemeta. On reHLDSWON the engine publishes the keys itself
 * and this plugin only reports.
 */
#include <amxmodx>
#include <amxmisc>
#include <fakemeta>

#define PLUGIN		"FastDL-WON"
#define VERSION		"1.0.0"
#define AUTHOR		"FastDL-WON"

#define KEY			"sv_won_downloadurl"
#define KEY_DLKEY	"sv_won_dlkey"
#define URL_MAX		100		// serverinfo is 256 bytes on some engines
#define BUF_LEN		128
#define POLL_SECS	2.0		// no cvar change hook in AMXX 1.8.1

enum
{
	MODE_OFF = 0,
	MODE_PLUGIN,
	MODE_ENGINE
}

new g_pUrl;
new g_pKey;
new g_pEnable;
new g_mode = MODE_OFF;
new bool:g_engineOwned;
new g_infoBuf;					// 0 = serverinfo not verified
new g_lastSeen[BUF_LEN * 2 + 8];
new g_pubUrl[BUF_LEN];
new g_pubKey[BUF_LEN];
new g_status[128];

public plugin_init()
{
	register_plugin(PLUGIN, VERSION, AUTHOR);
	register_cvar("fastdl_won_version", VERSION, FCVAR_SERVER | FCVAR_SPONLY);

	// sv_won_dlrate exists only in the reHLDSWON engine
	g_engineOwned = bool:cvar_exists("sv_won_dlrate");

	g_pUrl = register_cvar(KEY, "", FCVAR_SERVER);
	g_pKey = register_cvar(KEY_DLKEY, "", FCVAR_SERVER);
	g_pEnable = register_cvar("fastdl_won_enable", "1");

	register_srvcmd("fastdl_status", "SrvStatus");
	register_concmd("amx_fastdl", "CmdStatus", ADMIN_RCON, "- shows the FastDL-WON state");

	copy(g_status, charsmax(g_status), "not checked yet");
}

public plugin_cfg()
{
	if (!g_engineOwned)
		g_infoBuf = FindServerinfo();

	Update(true);
	set_task(POLL_SECS, "TaskPoll", 0, "", 0, "b");
}

public TaskPoll()
{
	Update(false);
}

// the serverinfo is sent to the client right after this forward
public client_connect(id)
{
	Update(false);
}

/* ---------------------------------------------------------------------------------------------- */

// SetKeyValue on any buffer other than localinfo or serverinfo is a Sys_Error, so the buffer of
// entity 0 is only used if it is not the localinfo and carries the engine's *gamedir key.
FindServerinfo()
{
	new buf = engfunc(EngFunc_GetInfoKeyBuffer, 0);
	new local = engfunc(EngFunc_GetInfoKeyBuffer, FM_NULLENT);
	new gamedir[64], modname[64];

	if (!buf || buf == local)
	{
		log_amx("serverinfo buffer not available (got %d, localinfo %d) - not publishing", buf, local);
		return 0;
	}

	engfunc(EngFunc_InfoKeyValue, buf, "*gamedir", gamedir, charsmax(gamedir));
	get_modname(modname, charsmax(modname));
	if (!gamedir[0] || !equali(gamedir, modname))
	{
		log_amx("buffer from entity 0 is not the serverinfo (*gamedir '%s', mod '%s') - not publishing", gamedir, modname);
		return 0;
	}
	return buf;
}

Update(bool:force)
{
	new rawUrl[BUF_LEN], rawKey[BUF_LEN], seen[BUF_LEN * 2 + 8], url[BUF_LEN], key[BUF_LEN], err[96];
	new enable = get_pcvar_num(g_pEnable);

	get_pcvar_string(g_pUrl, rawUrl, charsmax(rawUrl));
	get_pcvar_string(g_pKey, rawKey, charsmax(rawKey));
	formatex(seen, charsmax(seen), "%d|%s|%s", enable, rawUrl, rawKey);

	if (!force && equal(seen, g_lastSeen))
	{
		if (g_mode == MODE_PLUGIN && !(InfoMatches(KEY, g_pubUrl) && InfoMatches(KEY_DLKEY, g_pubKey)))
			Publish(g_pubUrl, g_pubKey);
		return;
	}
	copy(g_lastSeen, charsmax(g_lastSeen), seen);

	// a URL without key would serve old clients that do not verify downloads
	new bool:valid = Validate(rawUrl, rawKey, url, key, err, charsmax(err));

	if (g_engineOwned)
	{
		g_mode = MODE_ENGINE;
		if (!valid && (rawUrl[0] || rawKey[0]))
			formatex(g_status, charsmax(g_status), "engine mode, NOT VALID (%s)", err);
		else
			formatex(g_status, charsmax(g_status), "engine mode (reHLDSWON publishes %s/%s)", KEY, KEY_DLKEY);
		log_amx("%s", g_status);
		return;
	}

	if (!g_infoBuf)
	{
		g_mode = MODE_OFF;
		copy(g_status, charsmax(g_status), "off: serverinfo buffer could not be verified");
		return;
	}

	if (!enable)
	{
		Withdraw();
		copy(g_status, charsmax(g_status), "off: fastdl_won_enable 0");
	}
	else if (!valid)
	{
		Withdraw();
		formatex(g_status, charsmax(g_status), "off: %s", err);
	}
	else if (Publish(url, key))
	{
		g_mode = MODE_PLUGIN;
		formatex(g_status, charsmax(g_status), "publishing %s (key %.8s...)", url, key);
	}
	log_amx("%s", g_status);
}

bool:Validate(const rawUrl[], const rawKey[], url[], key[], err[], errlen)
{
	new e[64];
	if (!rawUrl[0])
		return Fail(err, errlen, "sv_won_downloadurl is empty");
	if (!NormalizeUrl(rawUrl, url, BUF_LEN - 1, e, charsmax(e)))
	{
		formatex(err, errlen, "invalid sv_won_downloadurl (%s)", e);
		return false;
	}
	if (!rawKey[0])
		return Fail(err, errlen, "sv_won_dlkey is empty");
	if (!NormalizeKey(rawKey, key, BUF_LEN - 1))
		return Fail(err, errlen, "invalid sv_won_dlkey (64 hex digits expected)");
	return true;
}

// the client accepts lowercase hex only
bool:NormalizeKey(const in[], out[], outlen)
{
	new i, c;
	if (strlen(in) != 64 || outlen < 64)
		return false;
	for (i = 0; i < 64; i++)
	{
		c = in[i];
		if (c >= 'A' && c <= 'F')
			c += 32;
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return false;
		out[i] = c;
	}
	out[64] = 0;
	return true;
}

bool:Publish(const url[], const key[])
{
	engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY, url);
	engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY_DLKEY, key);
	if (!InfoMatches(KEY, url) || !InfoMatches(KEY_DLKEY, key))
	{
		engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY, "");
		engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY_DLKEY, "");
		g_pubUrl[0] = g_pubKey[0] = 0;
		g_mode = MODE_OFF;
		copy(g_status, charsmax(g_status), "off: engine refused the keys (serverinfo full?)");
		return false;
	}
	copy(g_pubUrl, charsmax(g_pubUrl), url);
	copy(g_pubKey, charsmax(g_pubKey), key);
	return true;
}

// the serverinfo survives map changes: always remove both keys, not only our own
Withdraw()
{
	if (g_infoBuf)
	{
		engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY, "");
		engfunc(EngFunc_SetKeyValue, g_infoBuf, KEY_DLKEY, "");
	}
	g_pubUrl[0] = g_pubKey[0] = 0;
	g_mode = MODE_OFF;
}

bool:InfoMatches(const name[], const value[])
{
	new cur[BUF_LEN];
	engfunc(EngFunc_InfoKeyValue, g_infoBuf, name, cur, charsmax(cur));
	return bool:equal(cur, value);
}

/* ---------------------------------------------------------------------------------------------- */

// http://host[:port][/path] or https://host[:port][/path], lowercase scheme and host, no trailing slash. Same rules as the reHLDSWON
// engine (WonServer_DownloadUrl) and the client (fdl_url_parse).
bool:NormalizeUrl(const in[], out[], outlen, err[], errlen)
{
	new len = strlen(in), i, n = 0, c;

	if (len > URL_MAX)
		return Fail(err, errlen, "longer than 100 characters");
	if (len >= 9 && equali(in, "https://", 8))
	{
		n = copy(out, outlen, "https://");
		i = 8;
	}
	else if (len >= 8 && equali(in, "http://", 7))
	{
		n = copy(out, outlen, "http://");
		i = 7;
	}
	else
		return Fail(err, errlen, "must start with http:// or https://");

	new hostStart = i, labelLen = 0, prev = '.';
	while (i < len && in[i] != ':' && in[i] != '/')
	{
		c = in[i];
		if (c >= 'A' && c <= 'Z')
			c += 32;
		if (c == '.')
		{
			if (prev == '.' || prev == '-')
				return Fail(err, errlen, "bad host name");
			labelLen = 0;
		}
		else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
		{
			if (c == '-' && prev == '.')
				return Fail(err, errlen, "bad host name");
			if (++labelLen > 63)
				return Fail(err, errlen, "host label too long");
		}
		else
			return Fail(err, errlen, "invalid character in host");
		if (n >= outlen)
			return Fail(err, errlen, "too long");
		out[n++] = c;
		prev = c;
		i++;
	}
	if (i == hostStart || prev == '.' || prev == '-')
		return Fail(err, errlen, "bad host name");

	if (i < len && in[i] == ':')
	{
		new port = 0, digits = 0;
		if (n >= outlen)
			return Fail(err, errlen, "too long");
		out[n++] = ':';
		i++;
		while (i < len && in[i] >= '0' && in[i] <= '9')
		{
			port = port * 10 + (in[i] - '0');
			if (++digits > 5 || n >= outlen)
				return Fail(err, errlen, "bad port");
			out[n++] = in[i++];
		}
		if (!digits || port < 1 || port > 65535)
			return Fail(err, errlen, "bad port");
		if (i < len && in[i] != '/')
			return Fail(err, errlen, "bad port");
	}

	prev = 0;
	while (i < len)
	{
		c = in[i];
		if (c == '/')
		{
			if (prev == '/')
				return Fail(err, errlen, "empty path segment (//)");
		}
		else if (c == '.')
		{
			if (prev == '.' || prev == '/')
				return Fail(err, errlen, "'.' at the start of a path segment");
		}
		else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '~'))
			return Fail(err, errlen, "invalid character in path");
		if (n >= outlen)
			return Fail(err, errlen, "too long");
		out[n++] = c;
		prev = c;
		i++;
	}
	while (n > 7 && out[n - 1] == '/')
		n--;
	out[n] = 0;
	return true;
}

bool:Fail(err[], errlen, const msg[])
{
	copy(err, errlen, msg);
	return false;
}

/* ---------------------------------------------------------------------------------------------- */

public SrvStatus()
{
	PrintStatus(0);
	return PLUGIN_HANDLED;
}

public CmdStatus(id, level, cid)
{
	if (!cmd_access(id, level, cid, 1))
		return PLUGIN_HANDLED;
	PrintStatus(id);
	return PLUGIN_HANDLED;
}

PrintStatus(id)
{
	new raw[BUF_LEN], rawKey[BUF_LEN], cur[BUF_LEN], curKey[BUF_LEN];
	static const modes[][] = { "off", "plugin", "engine" };

	get_pcvar_string(g_pUrl, raw, charsmax(raw));
	get_pcvar_string(g_pKey, rawKey, charsmax(rawKey));
	if (!raw[0])
		copy(raw, charsmax(raw), "(empty)");
	if (!rawKey[0])
		copy(rawKey, charsmax(rawKey), "(empty)");
	curKey[0] = 0;
	if (g_engineOwned)
		copy(cur, charsmax(cur), "(set by the engine on connect)");
	else if (!g_infoBuf)
		copy(cur, charsmax(cur), "(serverinfo not verified)");
	else
	{
		engfunc(EngFunc_InfoKeyValue, g_infoBuf, KEY, cur, charsmax(cur));
		engfunc(EngFunc_InfoKeyValue, g_infoBuf, KEY_DLKEY, curKey, charsmax(curKey));
		if (!cur[0])
			copy(cur, charsmax(cur), "(not set)");
	}

	Out(id, "[FastDL-WON %s] mode: %s", VERSION, modes[g_mode]);
	Out(id, "  %-20s %s", KEY, raw);
	Out(id, "  %-20s %s", KEY_DLKEY, rawKey);
	Out(id, "  %-20s %s %s", "serverinfo", cur, curKey);
	Out(id, "  %-20s %s", "status", g_status);
}

Out(id, const fmt[], any:...)
{
	new line[192];
	vformat(line, charsmax(line), fmt, 3);
	if (id)
		console_print(id, "%s", line);
	else
		server_print("%s", line);
}
