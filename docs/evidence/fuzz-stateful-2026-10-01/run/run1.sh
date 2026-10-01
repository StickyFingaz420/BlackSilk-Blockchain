#!/usr/bin/env bash
# W4-STATEFUL: run ONE fuzz target for T seconds against the scratch corpus.
# Usage: run1.sh <target> <seconds> [tag]
set -uo pipefail
source C:/bszkeval/w4-stateful-scratch/env.sh
t="$1"; T="$2"; tag="${3:-run}"
case "$t" in
  peer_protocol) extra=(-max_len=256 -len_control=0) ;;
  scan_outputs) extra=(-max_len=65536) ;;
  px_admission) extra=(-max_len=256 -len_control=0 -rss_limit_mb=4096 -report_slow_units=60) ;;
  *) extra=(-max_len=65536) ;;
esac
mkdir -p "$SC/corpus/$t" "$SC/artifacts/$t" "$SC/logs"
log="$SC/logs/$t-$tag.log"
before_n=$(ls "$SC/corpus/$t" | wc -l); before_b=$(du -sb "$SC/corpus/$t" | cut -f1)
start=$(date +%s)
echo "start $(date -u +%FT%TZ) target=$t T=$T corpus_before=$before_n files/$before_b bytes free_kb=$(powershell -NoProfile '(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory' | tr -d '\r')" > "$log.meta"
cd "$SC"
export BLACKSILK_FUZZ_SEEDS="$SC"
# The prebuilt binary (`cargo fuzz build -O -a`), never `cargo fuzz run`:
# that rebuilds from the working tree, which a concurrent local edit (a
# demonstration) may have changed (it did once: see the evidence README).
bin="$CARGO_TARGET_DIR/x86_64-pc-windows-msvc/release/$t.exe"
echo "binary $(stat -c '%y %s' "$bin")" >> "$log.meta"
"$bin" "$SC/corpus/$t" \
  -max_total_time="$T" -timeout=60 -print_final_stats=1 -artifact_prefix="$SC/artifacts/$t/" "${extra[@]}" > "$log" 2>&1
status=$?
end=$(date +%s)
after_n=$(ls "$SC/corpus/$t" | wc -l); after_b=$(du -sb "$SC/corpus/$t" | cut -f1)
arts=$(find "$SC/artifacts/$t" -type f | wc -l)
echo "end $(date -u +%FT%TZ) exit=$status wall=$((end-start))s corpus_after=$after_n files/$after_b bytes artifacts=$arts" >> "$log.meta"
cat "$log.meta"
grep -E "^#[0-9]+ +(INITED|DONE)|stat::|panicked|ERROR" "$log" | head -20
