#!/bin/bash
# Fuzz the fastdl core with libFuzzer + ASan/UBSan. Signature check is skipped (FDL_FUZZ_SKIP_SIGNATURE)
# so the manifest parser itself is reached. usage: test/fuzz.sh [seconds]
#   TARGET=fuzz_core (default): every parser, crashes only; TARGET=fuzz_review: property checks (abort on a
#   rule violation by an accepted input); TARGET=fuzz_cbuf: pending-command serverinfo, property checks.
#   JOBS=n runs n workers on one corpus.
set -e; cd "$(dirname "$0")"
SECS=${1:-300}; TARGET=${TARGET:-fuzz_core}; WORK=${WORK:-$PWD/build/$TARGET}; mkdir -p "$WORK/corpus"
# seeds: a real manifest body and typical strings (first byte selects the parser: fuzz_core % 6, fuzz_review % 5)
FX=${FX:-$PWD/build/fx}
if [ "$TARGET" = fuzz_cbuf ]; then
  printf 'echo x\nfullserverinfo "\\*gamedir\\valve\\sv_won_downloadurl\\http://h/x\\sv_won_dlkey\\00ff"\nreconnect\n' > "$WORK/corpus/seed_cbuf"
  printf 'cmd a;fullserverinfo "\\a\\b";cmd "x;y"\n' > "$WORK/corpus/seed_cbuf2"
elif [ "$TARGET" = fuzz_review ]; then
  [ -f "$FX/web/fastdl.manifest" ] && { printf '\x02'; cat "$FX/web/fastdl.manifest"; } > "$WORK/corpus/seed_manifest"
  printf '\x00maps/de_dust.bsp' > "$WORK/corpus/seed_path"; printf '\x00cl_dlls. /x.wav' > "$WORK/corpus/seed_path2"
  printf '\x01https://fastdl.example.org:8443/cstrike' > "$WORK/corpus/seed_url"; printf '\x03maps/a b+(1).bsp' > "$WORK/corpus/seed_esc"
  printf '\x04maps/a.bspMAPS\\A.BSPmaps/b.bsp' > "$WORK/corpus/seed_cmp"
else
  [ -f "$FX/web/fastdl.manifest" ] && { printf '\x04'; cat "$FX/web/fastdl.manifest"; } > "$WORK/corpus/seed_manifest"
  printf '\x00maps/de_dust.bsp' > "$WORK/corpus/seed_path"; printf '\x01http://h:27980/hldm' > "$WORK/corpus/seed_url"; printf '\x01https://fastdl.example.org:8443/cstrike' > "$WORK/corpus/seed_url_https"
  printf '\x02\\*gamedir\\valve\\sv_won_downloadurl\\http://h/x' > "$WORK/corpus/seed_info"
fi
docker run --rm -v "$PWD/..":/src:ro -v "$WORK":/w -w /w silkeh/clang:17 bash -c "
clang -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -DFDL_FUZZ_SKIP_SIGNATURE \
  -o fuzz /src/test/$TARGET.c /src/core.c /src/third_party/monocypher/monocypher.c /src/third_party/monocypher/monocypher-ed25519.c &&
./fuzz -max_total_time=$SECS -max_len=65536 -print_final_stats=1 ${JOBS:+-fork=$JOBS} corpus 2>&1 | grep -E 'stat::number_of_executed_units|cov:|ERROR|SUMMARY|crash|abort|Test unit written' | tail -8"
