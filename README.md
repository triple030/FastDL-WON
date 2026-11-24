# FastDL-WON

FastDL for WON Half-Life and Counter-Strike Retail on WON servers. Maps, sounds, sprites, models and textures transferred via
HTTP in seconds instead of regular ingame sloooow downloading. Every file is checked against a list signed by the game server before it is saved. If anything is wrong, the game simply uses the normal download method.

FastDL-WON is NOT compatible with Steam, Non-Steam or Xash servers.

## Compatibility

- Client: WON based Half-Life 1.0.0.5 - 1.1.1.0 and Counter-Strike Retail 1.0 - 1.5
- Servers: HLDS Linux 3.1.0.4 to 3.1.1.1e. For 3.1.0.4 to 3.1.0.8 use the patched Metamod from
  server/metamod-oldengine, otherwise AMX Mod X crashes these servers.
- Windows XP to 11

**A note regarding HL 1.0.x.x servers:** these versions can't natively run AMX Mod X, therefore can't offer
FastDL for their clients. For them there is **reHLDSWON**, an upcoming ReHLDS fork for WON: one server for WON
clients of every version, from the 1999 betas to 1.1.1.0, with the FastDL-WON server part built in.

Again, Steam, NonSteam or Xash3d are NOT supported for obvious reasons.

## How is this working exactly?

We are using 2 methods for different versions of Half-Life.

**Method 1) Miles Sound System** Half-Life ships with the Miles Sound System, a DSP middleware which loads extensions via their .asi file format. It loads EVERY .asi file in the game folder as an audio plugin. We're using this method to enable FastDL. Copy 'fastdl.asi' in your HL/CS main folder and it's enabled for your client. Like in CS 1.6, fastdl only works when the server operator provides FastDL files (see 'Installation for Server ops' below). If you want to delete it, simply delete that file and it is gone. Nothing in the game is patched, no permanent changes. This method only works for version 1.1.0.8 - 1.1.1.0.
Miles starts with the game if a CD/DVD drive is present (an empty one is enough); otherwise only on the first connect, so the very first map may still come the slow way.

**Method 2) wsock32.dll** Half-Life versions before 1.1.0.8 don't use Miles Sound System. For those versions, FastDL-WON uses another method to load into Half-Life, wsock32.dll: Half-Life uses the Winsock API for networking, it first looks for it in the Half-Life main folder and if not, then checks the system32 Windows folder. Our wsock32.dll loads the real one from the system32 folder, passes everything through to it unchanged and starts FastDL-WON right when the game starts. This method works for almost every WON Half-Life version, from 1.0.0.5 to 1.1.1.0. You can have both files in your folder, doesn't matter really.

**Where does the client get the download address from?** Every Half-Life server sends a "serverinfo" string to
each player while connecting (server name, mod, playercount etc..). The server operator adds two entries to it in
his server.cfg:

    sv_won_downloadurl "http://your.server:27980/cstrike"
    sv_won_dlkey "<64 hex digits>"

sv_won_downloadurl is the public address to the download folder. sv_won_dlkey is the server's public key. The
plugin reads both while you connect. With the key, it checks that the file list on the web server really
comes from this game server: the list is signed with the matching private key, which only the server
operator has. If the server doesn't send these two strings, the plugin does nothing and just downloads the regular old way.

**"I set the server up and open the URL in my browser and get a 404 error. Is it broken?"** That's on purpose. The web server only answers to the FastDL-WON plugin identifier and gives everything else (browsers, search engines, scanners) a 404 error.
There is no file listing either. This is not a lock, the files are the same ones every player gets when joining;
it just keeps crawlers and curious weirdos out.

**HTTP or HTTPS?** Both work. Plain HTTP is safe because we use a signature: every file must match the size
and hash in the signed list, and if a file is changed on the way, it gets rejected and thrown away on the client's side.

HTTPS additionally hides which files a player downloads. For HTTPS the server operator needs a
domain name and a certificate (for example from Let's Encrypt) and writes https:// in sv_won_downloadurl.
Windows XP cannot do HTTPS (no TLS 1.2); XP players then simply get the normal in-game download.

## Installation for Players

1. Copy fastdl.asi into your Half-Life main folder, next to hl.exe/cstrike.exe
   (Half-Life 1.0.0.5 to 1.1.0.7 and Counter-Strike Retail 1.0 to 1.3: use wsock32.dll instead.)
2. Make sure downloading is enabled in console: `cl_allowdownload 1`

## Installation for Server ops

### What you need

- A Linux HLDS (WON) for your game server:

| HLDS | for clients | Notes |
|---|---|---|
| 3.1.1.1e | HL 1.1.1.0, CS Retail 1.5 | the usual WON server, works as it is |
| 3.1.0.9 | HL 1.1.0.9, CS Retail 1.4 | with Counter-Strike add `-insecure` to the command line (see below) |
| 3.1.0.4 to 3.1.0.8 | HL 1.1.0.4 to 1.1.0.8, CS Retail 1.0 to 1.3 | needs the Metamod from `server/metamod-oldengine` |

- Metamod (tested 1.19 to 1.21p38) and AMX Mod X 1.8.1 for Linux (tested 1.8.1.3746)
- Docker with Compose 2.20 or newer, for the web server (`docker compose version`)
- One free TCP port for the web server, 27980 by default

> [!NOTE]
> HLDS 3.1.0.4 to 3.1.0.8 don't have an engine function AMX Mod X 1.8.1 calls on every connect, so the server crashes as soon as a player joins. Replace the Metamod of your mod with the one from `server/metamod-oldengine`, see its README.

> [!NOTE]
> HLDS 3.1.0.9 with Counter-Strike: add -insecure to the command line, otherwise the server tries to download
> a security module from a server that no longer exists and keeps restarting.

HL 1.0.x.x servers (3.0.1.6 and older) can't run AMX Mod X, so FastDL-WON can't work on them.

### Step 1: Game server

Do this for every mod you want FastDL for:

1) Install Metamod and AMX Mod X as usual.

2) Copy `fastdl_won.amxx` to `addons/amxmodx/plugins/` of your mod and add this line to `addons/amxmodx/configs/plugins.ini`:
```
fastdl_won.amxx
```

3) Make sure the fakemeta module is enabled in `addons/amxmodx/configs/modules.ini`.

### Step 2: Web server

The web server creates the file manifest (the list of downloadable game files, signed with your key) and serves the files to the players.

1) Unpack the release zip and enter the `server` folder:
```bash
cd FastDL-WON/server
cp .env.example .env
```

2) Edit `.env`. For instance, for a CS 1.5 and a CS 1.3 server in `/home/hluser/hlds`:
```ini
DATA_DIR=/home/hluser/hlds
FASTDL_TREES="cstrike=cstrike cstrk13=cstrk13"
PUBLIC_HOST=your.server.address
PORT=27980
```

> [!NOTE]
> `DATA_DIR` is the folder that contains your mod folders. `cstrike=cstrike` means: the name in the URL = the mod folder in `DATA_DIR`. FastDL-WON creates its own `fastdl-won` folder in there. The download folder uses hardlinks instead of copies, so it takes no extra disk space, but it has to be on the same disk as your mod folders.

> [!CAUTION]
> `DATA_DIR` should belong to the user the game server runs as, not to root. FastDL-WON runs as the owner of `DATA_DIR`. If it belongs to root, FastDL-WON refuses to start: give it to your HLDS user, or set `FASTDL_UID` and `FASTDL_GID` in `.env` (check with `id hluser`).

3) Start it:
```bash
docker compose up -d
```

4) Get the two lines for your server.cfg:
```bash
cat keys/sv_won_dlkey.cfg
```

> [!IMPORTANT]
> The `keys` folder holds your signing key. Back it up. If you lose it, a new key is created and you have to put the new `sv_won_dlkey` into every server.cfg.

### Step 3: Connect game server and web server

1) Put the two lines of each mod into that mod's `server.cfg`:
```
sv_won_downloadurl "http://your.server.address:27980/cstrike"
sv_won_dlkey "<64 hex digits>"
```

> [!WARNING]
> Use the address players can reach (your public IP or domain), never `localhost`, `127.0.0.1` or a Docker address like `172.17.x.x`. The last part of the URL is the mod's name from `FASTDL_TREES`.

2) Change the map or restart the game server. `fastdl_status` in the server console shows what is published.

3) Check everything at once:
```bash
docker compose run --rm build check
```

That's it. Players with the plugin now download over HTTP.

### Using Ch0wW's docker-hlds-won2

If your game servers run with Ch0wW's [docker-hlds-won2](https://github.com/Ch0wW/docker-hlds-won2), FastDL-WON plugs right into it. Its image already includes Metamod, so Step 1 is only AMX Mod X and the plugin in `config/<mod>`.

1) Copy the `server` folder into your `docker-hlds-won2` folder as `fastdl-won`:
```bash
cp -r FastDL-WON/server ~/docker-hlds-won2/fastdl-won
cd ~/docker-hlds-won2/fastdl-won
cp .env.example .env
```

2) In `.env`, set only `FASTDL_TREES`, `PUBLIC_HOST` and `PORT`. Leave `DATA_DIR` out: it points at `docker-hlds-won2/config` by default.

3) Add these lines at the top of your `docker-compose.override.yml`:
```yml
include:
  - fastdl-won/docker-compose.yml
```

4) In the `docker-hlds-won2` folder, run `docker compose up -d`, then `cat fastdl-won/keys/sv_won_dlkey.cfg` and continue with Step 3. All `docker compose` commands below work from the `docker-hlds-won2` folder too.

### Several servers

Same steps. `FASTDL_TREES` lists all your mods, each gets its own URL:
```ini
FASTDL_TREES="cstrike=cstrike dm=cstrike_dm gungame=cstrike_gungame"
```

All mod folders must be inside `DATA_DIR`. One web server serves all of them. `keys/sv_won_dlkey.cfg` has two lines per mod; each server gets its own pair.

### Adding maps later

After adding or changing maps, sounds or models:
```bash
docker compose run --rm build build
```
Add a mod's name to rebuild only that one, e.g. `docker compose run --rm build build cstrike`. The new files are online right away; players who are downloading at that moment are not cut off.

### HTTPS (optional)

1) Copy `fullchain.pem` and `privkey.pem` of your certificate into a folder of their own.

> [!CAUTION]
> They must be real files readable by the web server (uid 101), not the links in `/etc/letsencrypt/live`. With Let's Encrypt, use a renewal hook that copies them after each renewal.

2) Add to `.env`:
```ini
TLS_DIR=/path/to/that/folder
TLS_PORT=443
COMPOSE_FILE=docker-compose.yml:docker-compose.tls.yml
```
With docker-hlds-won2, instead of `COMPOSE_FILE` change the include lines to:
```yml
include:
  - path: [fastdl-won/docker-compose.yml, fastdl-won/docker-compose.tls.yml]
```

3) Run `docker compose up -d` again, open the TLS port and use the `https://` address in `sv_won_downloadurl`.

### Players still download the slow way?

- The port (27980, TCP) must be open in your firewall. Test the curl line above from another machine, not from the server itself.
- Check the warning in Step 3.
- `docker compose run --rm build check` shows a wrong URL or key in server.cfg.
- The player's console shows a line starting with `fastdl:` that says why.
- `fastdl_won_enable 0` switches FastDL off without removing the plugin.

## License

GPLv3. Includes Monocypher (BSD-2-Clause or CC0).
