#!/bin/bash
# FastDL-WON build service of docker-compose.yml: validates the configuration, builds the trees, checks the
# game servers' server.cfg. Runs in the build container with ONE mount, /data = DATA_DIR: the mod folders and
# FastDL-WON's own folder /data/$FASTDL_DIR (dl/ = web root, keys/, logs/) are on it, so the trees can hardlink
# the game files (a hardlink cannot cross mounts). Only dl/, keys/ and logs/ are written.
#
#   fastdl-compose.sh build [TREE ...]   validate, then build all trees (or the named ones); default command
#   fastdl-compose.sh check              validate, then compare each server.cfg with the trees and the key
#   fastdl-compose.sh validate           only the configuration checks
#
# Environment (from .env):
#   FASTDL_TREES      "name=dir name2=dir2 ..."   tree name = last path segment of sv_won_downloadurl;
#                     dir = mod folder relative to DATA_DIR (or an absolute path under /data)
#   FASTDL_SERVERCFG  "name=dir/server.cfg ..."   optional; default <dir>/server.cfg when it exists
#   FASTDL_DIR        FastDL-WON's folder in DATA_DIR (default fastdl-won)
#   PORT              public port (for the printed sv_won_downloadurl lines)
#   PUBLIC_HOST       public host name or IP (for the printed lines; default <this host>)
# One signing key (keys/fastdl.key) signs every tree; keys/sv_won_dlkey.cfg gets the server.cfg lines.
set -uo pipefail
T=$(cd "$(dirname "$0")" && pwd)
DATA=${FASTDL_DATA:-/data}; W=$DATA/${FASTDL_DIR:-fastdl-won}
# Started as root (user 0:0 in docker-compose.yml, capabilities CHOWN, SETUID, SETGID only): hands the
# folders Docker created for the web service's mounts to the data owner, then continues as that user
# (FASTDL_UID:FASTDL_GID, default the owner of DATA_DIR, the user the game server runs as).
if [ "$(id -u)" = 0 ]; then
	ou=${FASTDL_UID:-$(stat -c %u "$DATA")}; og=${FASTDL_GID:-$(stat -c %g "$DATA")}
	if ! [[ "$ou" =~ ^[0-9]+$ && "$og" =~ ^[0-9]+$ ]] || [ "$ou" = 0 ] || [ "$og" = 0 ]; then
		echo "ERROR: the build would run as uid:gid $ou:$og. DATA_DIR must belong to the game server's user" \
			"(not root), or set FASTDL_UID and FASTDL_GID in .env to that user's numbers (id hluser)." >&2
		exit 1
	fi
	# a missing bind source is created by Docker as an empty root:root folder: only those, never a link
	for d in "$W" "$W/dl" "$W/logs"; do
		[ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %u:%g "$d")" = 0:0 ] || continue
		[ -z "$(ls -A "$d" | grep -vx -e dl -e logs)" ] || continue
		for x in "$d"/dl "$d"/logs; do [ "$d" != "$W" ] || [ ! -e "$x" ] || [ "$(stat -c %u:%g "$x")" = 0:0 ] || continue 2; done
		chown -h "$ou:$og" "$d" || exit 1
	done
	exec setpriv --reuid="$ou" --regid="$og" --clear-groups -- "$0" "$@"
fi
KEYDIR=${FASTDL_KEYDIR:-$W/keys}; KEY=$KEYDIR/fastdl.key; OUT=$W/dl; LOGS=$W/logs
err=0; warn=0
e() { if [ "${SOFT:-0}" = 1 ]; then w "$*"; else echo "ERROR: $*" >&2; err=$((err + 1)); fi; }
w() { echo "WARNING: $*" >&2; warn=$((warn + 1)); }

declare -A DIR=() CFG=()
ORDER=()

validate() {
	local item name dir real
	declare -A seen=()
	[ -n "${FASTDL_TREES:-}" ] || { e "FASTDL_TREES is empty (e.g. FASTDL_TREES=\"cstrike=cstrike\")"; return; }
	for item in $FASTDL_TREES; do
		name=${item%%=*}; dir=${item#*=}; [[ "$dir" == /* ]] || dir=$DATA/$dir
		if [ "$name" = "$item" ] || [ -z "$dir" ]; then e "FASTDL_TREES: '$item' is not name=dir"; continue; fi
		if ! [[ "$name" =~ ^[a-z0-9_-]{1,32}$ ]]; then e "tree '$name': name must be 1-32 of a-z 0-9 _ - (it is the last segment of sv_won_downloadurl)"; continue; fi
		if [ -n "${DIR[$name]+x}" ]; then e "tree '$name' is listed twice"; continue; fi
		if [ ! -d "$dir" ]; then e "tree '$name': $dir is not a directory (DATA_DIR must contain the mod folder)"; continue; fi
		if [ ! -r "$dir" ] || [ ! -x "$dir" ]; then e "tree '$name': $dir is not readable"; continue; fi
		real=$(realpath "$dir")
		case "$real/" in "$(realpath -m "$DATA")/"*) ;; *) e "tree '$name': $dir is not inside DATA_DIR"; continue ;; esac
		case "$real/" in "$(realpath -m "$KEYDIR")/"*) e "tree '$name': $dir is the key folder"; continue ;; esac
		case "$real/" in "$(realpath -m "$W")/"*) e "tree '$name': $dir is inside FastDL-WON's own folder $W"; continue ;; esac
		case "$(realpath -m "$W")/" in "$real/"*) e "tree '$name': FastDL-WON's folder $W is inside the mod folder $dir (set FASTDL_DIR)"; continue ;; esac
		[ -n "${seen[$real]+x}" ] && w "trees '${seen[$real]}' and '$name' use the same folder $real"
		seen[$real]=$name
		[ -f "$dir/liblist.gam" ] || w "tree '$name': $dir has no liblist.gam - is it a mod folder?"
		DIR[$name]=$dir; ORDER+=("$name")
	done
	for item in ${FASTDL_SERVERCFG:-}; do
		name=${item%%=*}
		[ -n "${DIR[$name]+x}" ] || { e "FASTDL_SERVERCFG: '$name' is not a tree in FASTDL_TREES"; continue; }
		CFG[$name]=${item#*=}; [[ "${CFG[$name]}" == /* ]] || CFG[$name]=$DATA/${CFG[$name]}
	done
	if [ -f "$KEY" ]; then
		[ $(( 0$(stat -c %a "$KEY") & 077 )) -eq 0 ] || e "$KEY is readable or writable by other users - chmod 600 it (and treat it as leaked if it was exposed)"
		python3 "$T/fastdl_manifest.py" pubkey "$KEY" >/dev/null 2>&1 || e "$KEY is not a valid signing key"
	else
		echo "no signing key yet: $KEY is created by the first build"
	fi
}

# value of a cvar in a server.cfg: last line that sets it; a quoted value up to the closing quote,
# otherwise the first word (so "//" inside a URL is not taken for a comment)
cfgval() {
	local line v
	line=$(tr -d '\r' < "$1" | grep -E "^[[:space:]]*$2([[:space:]]|$)" | tail -1)
	v=${line#*"$2"}; v=${v#"${v%%[![:space:]]*}"}
	if [[ $v == \"* ]]; then v=${v#\"}; v=${v%%\"*}; else v=${v%%[[:space:]]*}; fi
	printf '%s' "$v"
}

check() {
	local name cfg url key pub seg before
	[ -f "$KEY" ] || { e "no signing key $KEY - run the build first"; return; }
	pub=$(python3 "$T/fastdl_manifest.py" pubkey "$KEY")
	for name in "${ORDER[@]}"; do
		cfg=${CFG[$name]:-${DIR[$name]}/server.cfg}
		if [ ! -f "$cfg" ]; then
			if [ -n "${CFG[$name]+x}" ]; then e "tree '$name': $cfg not found"; else w "tree '$name': no $cfg - not checked"; fi
			continue
		fi
		url=$(cfgval "$cfg" sv_won_downloadurl); key=$(cfgval "$cfg" sv_won_dlkey); before=$((err + warn))
		if [ -z "$url" ]; then e "$cfg: sv_won_downloadurl is not set"; continue; fi
		seg=$(printf '%s' "$url" | sed 's#/*$##; s#.*/##' | tr 'A-Z' 'a-z')
		if ! [[ "$(printf '%s' "$url" | tr 'A-Z' 'a-z')" =~ ^https?://[^/]+/ ]]; then
			e "$cfg: sv_won_downloadurl \"$url\" must be http://host[:port]/$name"
		elif [ "$seg" != "$name" ]; then
			e "$cfg: sv_won_downloadurl \"$url\" ends in '$seg', but this server's tree is '$name'"
		fi
		if [ -z "$key" ]; then e "$cfg: sv_won_dlkey is not set"
		elif [ "$(printf '%s' "$key" | tr 'A-F' 'a-f')" != "$pub" ]; then e "$cfg: sv_won_dlkey does not match the signing key ($pub)"; fi
		[ $((err + warn)) -eq $before ] && echo "ok: $cfg -> tree '$name', key matches"
	done
}

cmd=${1:-build}; [ $# -gt 0 ] && shift
validate
[ $err -eq 0 ] || { echo "configuration invalid: $err error(s)" >&2; exit 1; }
case $cmd in
validate) echo "configuration ok: ${#ORDER[@]} tree(s)"; exit 0 ;;
check) check ;;
build)
	todo=("$@"); [ ${#todo[@]} -gt 0 ] || todo=("${ORDER[@]}")
	for name in "${todo[@]}"; do [ -n "${DIR[$name]+x}" ] || { e "'$name' is not a tree in FASTDL_TREES"; }; done
	[ $err -eq 0 ] || exit 1
	# keys/ private to the data owner; logs/ 2770 for the owner and the web service (ACL or group_add), so
	# logrotate accepts it with "su root <gid>"
	mkdir -p "$OUT" "$LOGS" || { echo "cannot create $W as uid $(id -u) (does that user own DATA_DIR?)" >&2; exit 1; }
	[ -d "$KEYDIR" ] && [ -w "$KEYDIR" ] || { echo "the key folder is not writable by uid $(id -u) - create it next to docker-compose.yml: mkdir -m 700 keys" >&2; exit 1; }
	chmod 700 "$KEYDIR"; chmod 2770 "$LOGS"
	# nginx (uid 101) appends to logs/access.log: an ACL entry for it, else only the group of group_add
	setfacl -m u:101:rwx "$LOGS" 2>/dev/null \
		|| w "no ACL on $LOGS (file system without ACLs): the web service writes it only with FASTDL_GID=$(id -g) in .env"
	for name in "${todo[@]}"; do
		FASTDL_KEY=$KEY FASTDL_OUT=$OUT "$T/mkfastdl.sh" "$name" "${DIR[$name]}" || e "tree '$name': build failed"
	done
	# served files must be hardlinks of the game files (link count > 1), unless FASTDL_ALLOW_COPY is set
	if [ -z "${FASTDL_ALLOW_COPY:-}" ]; then
		for name in "${todo[@]}"; do
			c=$(find "$OUT/$name/" -type f ! -name fastdl.manifest -links 1 2>/dev/null | head -3)
			[ -z "$c" ] || e "tree '$name': not hardlinked: $c"
		done
	fi
	if [ -f "$KEY" ]; then
		pub=$(python3 "$T/fastdl_manifest.py" pubkey "$KEY")
		for name in "${ORDER[@]}"; do
			printf '// %s (%s)\nsv_won_downloadurl "%s://%s:%s/%s"\nsv_won_dlkey "%s"\n' "$name" "${DIR[$name]}" \
				"${PUBLIC_SCHEME:-http}" "${PUBLIC_HOST:-<this host>}" "${PUBLIC_PORT:-${PORT:-27980}}" "$name" "$pub"
		done > "$(dirname "$KEY")/sv_won_dlkey.cfg"
		cat "$(dirname "$KEY")/sv_won_dlkey.cfg"
	fi
	[ $err -eq 0 ] && { echo "--- server.cfg check (warnings only here; 'check' gives a strict result)"; SOFT=1 check; } ;;
*) echo "usage: $0 build [TREE ...] | check | validate" >&2; exit 2 ;;
esac
[ $err -eq 0 ] || { echo "$err error(s)" >&2; exit 1; }
[ $warn -eq 0 ] || echo "$warn warning(s)"
exit 0
