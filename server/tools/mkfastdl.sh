#!/bin/bash
# Build the HTTP fast-download tree dl/<name>/ from a game dir: hardlinks of client file types only
# (web root and game dir on one file system; FASTDL_ALLOW_COPY=1 copies instead)
# (never cfg/ini/dll/so/logs -> no rcon passwords or plugins exposed) plus the signed fastdl.manifest.
# Files the manifest does not list (wrong place, too big, case collision, bad name) are removed from the
# tree again, so the web server can only serve what the manifest lists.
# dl/<name> is a symlink to a generation directory dl/.<name>.<timestamp>.<rnd>; a new generation is swapped
# in with one atomic rename, and the previous one is kept for clients that are still downloading from it.
# usage: tools/mkfastdl.sh NAME GAMEDIR      (key: $FASTDL_KEY, default fastdl/keys/fastdl.key;
#                                             web root: $FASTDL_OUT, default dl; defaults relative to the repo)
#        NAME must be the last path segment of sv_won_downloadurl (the manifest is bound to it)
set -eo pipefail; name=$1
[[ "$name" =~ ^[a-z0-9_-]{1,32}$ ]] || { echo "bad name" >&2; exit 1; }
[ -n "$2" ] && [ -d "$2" ] || { echo "game dir '$2' not found" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd); tools=$root/tools; src=$(realpath -e "$2")
key=$(realpath -m "${FASTDL_KEY:-$root/fastdl/keys/fastdl.key}"); out=$(realpath -m "${FASTDL_OUT:-$root/dl}")
mkdir -p "$out"; cd "$out"
exec 9> ".$name.lock"; flock -n 9 || { echo "another build of $name is running" >&2; exit 1; }
[ -f "$key" ] || { python3 "$tools/fastdl_manifest.py" keygen "$key" >/dev/null
  echo "created a NEW signing key $key - every server using this tree needs the sv_won_dlkey below" >&2; }
chmod 700 "$(dirname "$key")" 2>/dev/null || true
# inodes that must never be published: every file of the mod folder the type rules exclude (configs, plugins,
# logs, addons, ...) and the key. A hardlink of one of them under an allowed name ("maps/notes.txt" = server.cfg)
# is the same inode and is skipped.
SEL=( \( -iname '*.bsp' -o -iname '*.wad' -o -iname '*.wav' -o -iname '*.mdl' -o -iname '*.spr' \
    -o -iname '*.tga' -o -iname '*.bmp' -o -iname '*.res' -o -iname '*.txt' -path './maps/*' -o -iname '*.txt' -path './sprites/*' \
    -o -iname '*.txt' -path './overviews/*' -o -iname '*.mp3' \) -not -path './addons/*' -not -path './logs/*' -not -path './maps/_disabled/*' )
declare -A deny=()
while IFS= read -r id; do deny[$id]=1; done < <(
  stat -L -c '%d:%i' "$key"
  cd "$src" && find . -type f ! \( "${SEL[@]}" \) -printf '%D:%i\n' )
# the serial of the current tree, so the next one is higher even if the clock went back
prev=$(sed -n '2s/^tree [^ ]* \([0-9]\{1,19\}\)$/\1/p' "$out/$name/fastdl.manifest" 2>/dev/null || true); export FASTDL_PREV_SERIAL=${prev:-0}
# the tree hardlinks the game files: web root and mod folder must be on one file system (and, in a
# container, inside one mount); copies only with FASTDL_ALLOW_COPY=1
if [ "$(stat -c %d "$src")" != "$(stat -c %d "$out")" ] && [ -z "$FASTDL_ALLOW_COPY" ]; then
  echo "$out and $src are on different file systems (or different mounts): the tree cannot hardlink the game files." >&2
  echo "Put the web root next to the mod folders on the same file system (one mount in docker), or set FASTDL_ALLOW_COPY=1 to copy." >&2
  exit 1
fi
gen=$(mktemp -d ".$name.$(date -u +%Y%m%d%H%M%S).XXXX"); chmod 755 "$gen"; dst=$name
trap 'cat ".$name.skipped.new" >&2 2>/dev/null; rm -rf "$gen" ".$name.link" ".$name.skipped.new"' EXIT
# Every link of a published file must be known: in the mod folder or in the web root (tree generations). A file
# that is also linked from anywhere else (another mod's server.cfg, a .env, a file outside DATA_DIR) has more
# links than that and is skipped. Counted before the new generation adds its own links.
declare -A known=()
while IFS= read -r id; do known[$id]=$(( ${known[$id]:-0} + 1 )); done < <(
  find "$src" -type f -printf '%D:%i\n'
  find "$out" -path "$out/$gen" -prune -o -type f -printf '%D:%i\n' )
accept=$(mktemp ".$name.accept.XXXX"); trap 'cat ".$name.skipped.new" >&2 2>/dev/null; rm -rf "$gen" ".$name.link" ".$name.skipped.new" "$accept"' EXIT
( cd "$src" && find . -type f "${SEL[@]}" -print0 ) |
while IFS= read -r -d '' f; do
  [ -f "$src/$f" ] && [ ! -L "$src/$f" ] || continue
  read -r id nl < <(stat -c '%d:%i %h' "$src/$f")
  [ -z "${deny[$id]+x}" ] || { echo "skipped ${f#./}: same file as an excluded file or the key (hardlink)" >&2; continue; }
  [ "$nl" -eq "${known[$id]:-0}" ] || { echo "skipped ${f#./}: also linked from outside the mod folder ($nl links, ${known[$id]:-0} known)" >&2; continue; }
  printf '%s\0' "$f"
done > "$accept"
while IFS= read -r -d '' f; do
  mkdir -p "$gen/${f%/*}"
  if [ -n "$FASTDL_ALLOW_COPY" ]; then ln -P "$src/$f" "$gen/$f" 2>/dev/null || cp -P -- "$src/$f" "$gen/$f"
  else ln -P "$src/$f" "$gen/$f" || { echo "cannot hardlink $f: the web root and $src must be on one file system and, in docker, in one mount (FASTDL_ALLOW_COPY=1 copies instead)" >&2; exit 1; }; fi
done < "$accept"
python3 "$tools/fastdl_manifest.py" build --prune "$gen" "$key" "$name" 2> ".$name.skipped.new" | sed "s|$gen|$dst|"
n=$(find "$gen" -type f ! -name fastdl.manifest | wc -l)
[ "$n" -gt 0 ] || [ -n "$FASTDL_ALLOW_EMPTY" ] || { echo "no files for $name - not switching (FASTDL_ALLOW_EMPTY=1 to force)" >&2; exit 1; }
prev=$( [ -L "$dst" ] && readlink "$dst" || true )
if [ -d "$dst" ] && [ ! -L "$dst" ]; then mv "$dst" ".$name.legacy"; prev=.$name.legacy; fi   # first run: migrate
ln -sfn "$gen" ".$name.link" && mv -T ".$name.link" "$dst"; mv ".$name.skipped.new" ".$name.skipped"
rm -f "$accept"; trap - EXIT
for g in ".$name".[0-9]* ".$name.legacy"; do      # keep the current and the previous generation
  [ -e "$g" ] || continue; [ "$g" = "$gen" ] || [ "$g" = "$prev" ] || rm -rf "$g"
done
echo "$out/$dst -> $gen: $n files, $(du -sh "$gen" | cut -f1); skipped list: $out/.$name.skipped"
echo "server.cfg: sv_won_dlkey \"$(python3 "$tools/fastdl_manifest.py" pubkey "$key")\""
