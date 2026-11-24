#!/bin/bash
# Compile fastdl_won.sma with the AMX Mod X 1.8.1 compiler (32-bit) in a container.
# AMXX_SCRIPTING = an addons/amxmodx/scripting folder of AMX Mod X 1.8.1 (amxxpc + include/).
set -e; cd "$(dirname "$0")"
S=$(realpath "${AMXX_SCRIPTING:?set AMXX_SCRIPTING to addons/amxmodx/scripting of AMX Mod X 1.8.1}")
docker run --rm -v "$S":/amxx:ro -v "$PWD":/src -w /src -e SMA -e OUTX debian:bookworm bash -c '
dpkg --add-architecture i386 && apt-get update -qq >/dev/null && apt-get install -y -qq libc6:i386 libstdc++6:i386 >/dev/null
LD_LIBRARY_PATH=/amxx /amxx/amxxpc -i/amxx/include "${SMA:-fastdl_won.sma}" -o"${OUTX:-fastdl_won.amxx}"
chown '"$(id -u):$(id -g)"' "${OUTX:-fastdl_won.amxx}"'
ls -l "${OUTX:-fastdl_won.amxx}"
