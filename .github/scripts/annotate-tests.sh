#!/usr/bin/env bash
# Runs a test command and, if it fails, reports each failed test, panic and build
# error as a GitHub error annotation. Annotations are readable without log access,
# so failures (including intermittent ones) can be diagnosed from the run page.
set -uo pipefail
log=$(mktemp)
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  grep -E '^test .* \.\.\. FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | sort -u |
    while read -r t; do echo "::error title=Failed test::$t"; done
  grep -A2 -E "^thread '.*' .*panicked at " "$log" | grep -v '^--$' | head -60 | paste -sd '|' - |
    tr '|' '\n' | awk 'NR%3==1{p=$0} NR%3==2{print "::error title=Panic::" substr(p,1,200) " :: " substr($0,1,300)}'
  grep -E '^error(\[E[0-9]+\])?:' "$log" | head -10 |
    while read -r l; do echo "::error title=Build error::${l:0:300}"; done
fi
exit "$status"
