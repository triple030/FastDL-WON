#!/bin/bash
# Cross-compile fastdl.asi (32-bit, Windows XP compatible) in a container.
set -e; cd "$(dirname "$0")"
docker run --rm -v "$PWD":/src -w /src debian:bookworm bash -c 'set -e

apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc-mingw-w64-i686 >/dev/null
i686-w64-mingw32-gcc -std=gnu99 -O2 -Wall -Wextra -Werror -shared -static-libgcc -fno-strict-aliasing -o fastdl.asi \
  fastdl.c core.c third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c -lwininet \
  -Wl,--major-subsystem-version,5,--minor-subsystem-version,1,--major-os-version,5,--minor-os-version,1
i686-w64-mingw32-gcc -std=gnu99 -O2 -Wall -Wextra -Werror -shared -static-libgcc -fno-strict-aliasing -DFASTDL_PROXY \
  -o wsock32.dll wsock32.def wsock32_proxy.c fastdl.c core.c third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c -lwininet \
  -Wl,--major-subsystem-version,5,--minor-subsystem-version,1,--major-os-version,5,--minor-os-version,1
i686-w64-mingw32-objdump -p fastdl.asi | grep -E "DLL Name|Subsystem|MajorOSystem|MajorSubsystem|MinorSubsystem"
chown '"$(id -u):$(id -g)"' fastdl.asi wsock32.dll'
ls -l fastdl.asi wsock32.dll
