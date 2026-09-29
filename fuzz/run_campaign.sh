#!/usr/bin/env bash
# Coverage-guided campaign over every target (AUDIT.md "Fuzzing").
# Usage: ./run_campaign.sh [seconds per target]   (Windows: needs MSVC's ASan
# runtime, clang_rt.asan_dynamic-x86_64.dll, on PATH.)
#
# Fails (non-zero exit) when the build fails, when any target's fuzzer exits
# non-zero (a crash, leak, timeout or OOM, or a fuzzer that did not start),
# when a target reports no executed units, or when libFuzzer left an artifact.
# Targets are built and run optimized (-O) and with debug assertions (-a), so
# arithmetic overflow and debug_assert! failures are findings too. cargo-fuzz
# 0.13 adds debug assertions (and with them rustc's overflow checks) to a
# release build only with -a; campaigns before 2026-09-27 ran without them.
# Build and run must use the same flags, or `run` rebuilds without them.
set -uo pipefail
T="${1:-900}"
TC="${TOOLCHAIN:-nightly}"
cd "$(dirname "$0")"
FLAGS=(-O -a --fuzz-dir .)
cargo +"$TC" fuzz build "${FLAGS[@]}" || { echo "fuzz build failed"; exit 1; }
mkdir -p logs
failed=()
for target in tx_decode block_decode p2p_message zkvm_elf kernel_diff delivery_open proof_decode \
              store_records seed_words transport_recv transport_handshake addr_v2; do
  case "$target" in
    # The largest proof the decoder accepts (zk MAX_PROOF_BYTES, 4 MiB):
    # libFuzzer truncates longer seeds at load, and a real transfer proof
    # outgrew the old 2,200,000 limit (W4-FUZZ), so it never decoded.
    proof_decode) extra=(-max_len=4194304 -rss_limit_mb=4096) ;;
    zkvm_elf) extra=(-max_len=32768) ;;
    kernel_diff) extra=(-max_len=8192) ;;
    # Bounded allocation is part of these targets' contract: one allocation
    # of 32 MiB or more is a finding (the inputs are at most 256 KiB).
    store_records) extra=(-max_len=262144 -malloc_limit_mb=32) ;;
    transport_recv|transport_handshake) extra=(-max_len=65536 -malloc_limit_mb=32) ;;
    seed_words) extra=(-max_len=1024) ;;
    *) extra=(-max_len=65536) ;;
  esac
  mkdir -p "corpus/$target"
  log="logs/$target.log"
  echo "=== $target"
  cargo +"$TC" fuzz run "${FLAGS[@]}" "$target" "corpus/$target" -- \
    -max_total_time="$T" -timeout=60 -print_final_stats=1 "${extra[@]}" 2>&1 |
    tee "$log" |
    grep -E "^#[0-9]+ +(DONE|INITED)|stat::|ERROR|panicked|crash-|Done [0-9]+ runs"
  status="${PIPESTATUS[0]}"
  units="$(sed -n 's/^stat::number_of_executed_units: *\([0-9]*\).*/\1/p' "$log" | tail -n 1)"
  echo "exit $status, executed units ${units:-none}"
  if [ "$status" != 0 ]; then
    failed+=("$target (exit $status)")
  elif [ -z "$units" ] || [ "$units" -eq 0 ]; then
    failed+=("$target (no executed units)")
  fi
done
echo "=== artifacts"
# libFuzzer writes a crash-/leak-/timeout-/oom- file for every failure.
if [ -d artifacts ] && [ -n "$(find artifacts -type f)" ]; then
  find artifacts -type f
  failed+=("artifacts present")
else
  echo "none"
fi
if [ "${#failed[@]}" -gt 0 ]; then
  echo "=== fuzzing failed:"
  printf '  %s\n' "${failed[@]}"
  exit 1
fi
echo "=== all targets ran"
