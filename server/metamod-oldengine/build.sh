#!/bin/bash
# Builds Metamod-P 1.21p38 with the old-engine patch for Linux HLDS 3.1.0.4 - 3.1.0.8 (i386 Debian jessie, gcc 4.9:
# the library needs at most GLIBC_2.3). Output: metamod_i386.so in the current directory. Needs docker and network.
set -e; H=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d "$PWD/mmbuild.XXXX")
git clone -q --branch v1.21p38 --depth 1 https://github.com/jkivilin/metamod-p.git "$W/src"
git -C "$W/src" apply "$H/metamod-p-1.21p38-oldengine.patch"
printf 'FROM i386/debian:jessie-slim\nRUN printf "deb http://archive.debian.org/debian jessie main\\ndeb http://archive.debian.org/debian-security jessie/updates main\\n" > /etc/apt/sources.list && apt-get update && apt-get install -y --force-yes g++ make && apt-get clean\n' > "$W/Dockerfile"
docker build -q -t metamod-oldengine-cc "$W" >/dev/null
docker run --rm --user "$(id -u):$(id -g)" -v "$W/src":/s -w /s/metamod metamod-oldengine-cc make OPT=opt linux >/dev/null
cp "$W/src/dlls/metamod.so" ./metamod_i386.so && echo "built ./metamod_i386.so (source in $W)"
