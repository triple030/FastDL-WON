#!/bin/bash
# Unit tests of the fastdl core with AddressSanitizer + UndefinedBehaviorSanitizer (Linux, gcc in docker).
set -e; cd "$(dirname "$0")"
FX=${FX:-$PWD/build/fx}; mkdir -p "$FX"
python3 mkfixtures.py "$FX" >/dev/null
docker run --rm -v "$PWD/..":/src:ro -v "$FX":/fx -w /tmp gcc:13 bash -c '
gcc -std=c99 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all \
  -o t /src/test/test_core.c /src/core.c /src/third_party/monocypher/monocypher.c /src/third_party/monocypher/monocypher-ed25519.c
./t $(cat /fx/pub) $(cat /fx/otherpub) /fx/web/fastdl.manifest /fx/classify.list /fx/bad_*'
# review 2: extra negative tests (standalone program)
docker run --rm -v "$PWD/..":/src:ro -w /tmp gcc:13 bash -c '
gcc -std=c99 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=all \
  -o t2 /src/test/test_review2.c /src/core.c /src/third_party/monocypher/monocypher.c /src/third_party/monocypher/monocypher-ed25519.c
./t2'
