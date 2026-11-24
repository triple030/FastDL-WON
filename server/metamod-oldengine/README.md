# Metamod for old Linux servers (HLDS 3.1.0.4 - 3.1.0.8)

Only needed if your server runs the original Linux HLDS 3.1.0.4, 3.1.0.6, 3.1.0.7 or 3.1.0.8.
On 3.1.0.9 and 3.1.1.1e you don't need it (it would change nothing there).

**Why:** AMX Mod X 1.8.1 asks the server for a player's ID on every connect. Valve only added that function
to the Linux server in 3.1.0.9. On older servers it is missing, and the server crashes as soon as a player
connects, with or without FastDL-WON.

**What it does:** this is Metamod-P 1.21p38 with a small patch. At startup it checks which engine functions
the server really has and fills the missing ones with harmless stand-ins: the player's WON ID for the player
ID, and "off" for the two voice functions. Nothing else changes. AMX Mod X and your plugins stay as they are.

## Install

1) Replace the Metamod library of your mod with metamod.so from this folder:
```bash
cp metamod.so /path/to/hlds_l/cstrike/addons/metamod/dlls/metamod.so
```

2) Restart the server. The Metamod startup banner shows one extra line, for example:
```
Old engine (141 engine functions): stand-ins for pfnVoice_GetClientListening pfnVoice_SetClientListening pfnGetPlayerAuthId
```

> [!NOTE]
> Players on these servers need FastDL-WON 1.0 or later to download over HTTP.

## Build it yourself

`build.sh` clones Metamod-P v1.21p38, applies metamod-p-1.21p38-oldengine.patch and builds it in Docker
(i386 Debian jessie, so the library runs on the old servers).
