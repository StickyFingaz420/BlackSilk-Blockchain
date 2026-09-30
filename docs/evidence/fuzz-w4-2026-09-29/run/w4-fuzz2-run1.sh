#!/usr/bin/env bash
# W4-FUZZ2: run ONE fuzz target for T seconds against the scratch corpus copy.
# Usage: run1.sh <target> <seconds>
set -uo pipefail
source C:/bszkeval/w4-fuzz2-scratch/env.sh
t="$1"; T="$2"
case "$t" in
  proof_decode) extra=(-max_len=4194304 -rss_limit_mb=4096) ;;
  zkvm_elf) extra=(-max_len=32768) ;;
  kernel_diff) extra=(-max_len=8192) ;;
  store_records) extra=(-max_len=262144 -malloc_limit_mb=32) ;;
  transport_recv|transport_keyless_peer) extra=(-max_len=65536 -malloc_limit_mb=32) ;;
  seed_words) extra=(-max_len=1024) ;;
  delivery_plain|px_tx_struct) extra=(-max_len=256) ;;
  proof_struct) extra=(-max_len=256 -len_control=0 -rss_limit_mb=4096) ;;
  *) extra=(-max_len=65536) ;;
esac
mkdir -p "$SC/corpus/$t" "$SC/artifacts/$t" "$SC/logs"
log="$SC/logs/$t.log"
before_n=$(ls "$SC/corpus/$t" | wc -l); before_b=$(du -sb "$SC/corpus/$t" | cut -f1)
start=$(date +%s)
echo "start $(date -u +%FT%TZ) target=$t T=$T corpus_before=$before_n files/$before_b bytes free_kb=$(powershell -NoProfile '(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory' | tr -d '\r')" > "$log.meta"
export BLACKSILK_FUZZ_SEEDS=$SC/seeds
cd "$FZ"
cargo +"$TC" fuzz run -O -a --fuzz-dir . "$t" "$SC/corpus/$t" -- \
  -max_total_time="$T" -timeout=60 -print_final_stats=1 -artifact_prefix="$SC/artifacts/$t/" "${extra[@]}" > "$log" 2>&1
status=$?
end=$(date +%s)
after_n=$(ls "$SC/corpus/$t" | wc -l); after_b=$(du -sb "$SC/corpus/$t" | cut -f1)
arts=$(find "$SC/artifacts/$t" -type f | wc -l)
echo "end $(date -u +%FT%TZ) exit=$status wall=$((end-start))s corpus_after=$after_n files/$after_b bytes artifacts=$arts" >> "$log.meta"
cat "$log.meta"
grep -E "^#[0-9]+ +(INITED|DONE)|stat::" "$log"
