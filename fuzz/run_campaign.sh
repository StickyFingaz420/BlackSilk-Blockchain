#!/usr/bin/env sh
# Coverage-guided campaign over every target (AUDIT.md "Fuzzing").
# Usage: ./run_campaign.sh [seconds per target]   (Windows: needs MSVC's ASan
# runtime, clang_rt.asan_dynamic-x86_64.dll, on PATH.)
set -u
T="${1:-900}"
TC="${TOOLCHAIN:-nightly}"
cd "$(dirname "$0")"
cargo +"$TC" fuzz build --release --fuzz-dir . || exit 1
for target in tx_decode block_decode p2p_message zkvm_elf kernel_diff delivery_open wasm_module proof_decode; do
  case "$target" in
    proof_decode) extra="-max_len=2200000 -rss_limit_mb=4096" ;;
    zkvm_elf) extra="-max_len=32768" ;;
    kernel_diff) extra="-max_len=8192" ;;
    *) extra="-max_len=65536" ;;
  esac
  mkdir -p "corpus/$target"
  echo "=== $target"
  cargo +"$TC" fuzz run --release --fuzz-dir . "$target" "corpus/$target" -- \
    -max_total_time="$T" -timeout=60 -print_final_stats=1 $extra 2>&1 \
    | grep -E "^#[0-9]+ +(DONE|INITED)|stat::|ERROR|panicked|crash-|Done [0-9]+ runs"
  echo "exit $?"
done
echo "=== artifacts"
ls -R artifacts 2>/dev/null || echo "none"
