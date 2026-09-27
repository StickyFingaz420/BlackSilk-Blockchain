#!/usr/bin/env bash
# Runs zkvm/guests/reproduce.sh and, on failure, reports what differed as
# GitHub error annotations (job logs need admin access; annotations do not).
set -uo pipefail
log=$(mktemp)
bash zkvm/guests/reproduce.sh 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  msg=$(tail -40 "$log" | tr -d '\r' | sed 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}')
  echo "::error title=guests reproduce (tail)::$msg"
  for name in kernel vault; do
    rebuilt=$(find . -path "*riscv32i-unknown-none-elf/release/guest-$name" -type f 2>/dev/null | head -1)
    committed="px/$name.elf"
    if [ -n "$rebuilt" ] && command -v readelf >/dev/null; then
      a=$(readelf -S -W "$rebuilt" | grep -E '^\s+\[' | awk '{print $2, $5, $6}' | tr '\n' ';')
      b=$(readelf -S -W "$committed" | grep -E '^\s+\[' | awk '{print $2, $5, $6}' | tr '\n' ';')
      echo "::error title=$name sections rebuilt (name off size)::$(stat -c %s "$rebuilt") bytes; $a"
      echo "::error title=$name sections committed::$(stat -c %s "$committed") bytes; $b"
      first=$(cmp "$rebuilt" "$committed" 2>&1 | head -1)
      echo "::error title=$name first difference::$first; differing bytes: $(cmp -l "$rebuilt" "$committed" 2>/dev/null | wc -l)"
      c=$(readelf -p .comment "$rebuilt" 2>/dev/null | tr -d '\r' | tr '\n' '|')
      echo "::error title=$name .comment rebuilt::$c"
      c=$(readelf -p .comment "$committed" 2>/dev/null | tr -d '\r' | tr '\n' '|')
      echo "::error title=$name .comment committed::$c"
    fi
  done
fi
exit "$status"
