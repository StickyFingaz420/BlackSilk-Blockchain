#!/usr/bin/env bash
# Runs a test command and, if it fails, reports each failed test, panic and build
# error as a GitHub error annotation. Annotations are readable without log access,
# so failures (including intermittent ones) can be diagnosed from the run page.
#
# ANNOTATE_TIMEOUT (e.g. 150m, GNU timeout syntax) stops the command before the
# job's own limit, so a hang is reported instead of the job being cancelled
# silently (CI run 113): the tests libtest reports as running for over 60 s and
# the last test binary started are annotated.
set -uo pipefail
log=$(mktemp)
if [ -n "${ANNOTATE_TIMEOUT:-}" ]; then
  timeout --signal=TERM --kill-after=60s "$ANNOTATE_TIMEOUT" "$@" 2>&1 | tee "$log"
else
  "$@" 2>&1 | tee "$log"
fi
status=${PIPESTATUS[0]}
if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
  echo "::error title=Timed out::the tests exceeded ${ANNOTATE_TIMEOUT:-?}: $*"
  grep -E '^ *Running ' "$log" | tail -1 | while read -r l; do echo "::error title=Last test binary::${l:0:300}"; done
  grep -E 'has been running for over [0-9]+ seconds' "$log" | sed -E 's/^test (.*) has been running.*/\1/' | sort -u | head -20 |
    while read -r t; do echo "::error title=Still running at timeout::$t"; done
fi
if [ "$status" -ne 0 ]; then
  grep -E '^test .* \.\.\. FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | sort -u |
    while read -r t; do echo "::error title=Failed test::$t"; done
  grep -A2 -E "^thread '.*' .*panicked at " "$log" | grep -v '^--$' | head -60 | paste -sd '|' - |
    tr '|' '\n' | awk 'NR%3==1{p=$0} NR%3==2{print "::error title=Panic::" substr(p,1,200) " :: " substr($0,1,300)}'
  grep -E '^error(\[E[0-9]+\])?:' "$log" | head -10 |
    while read -r l; do echo "::error title=Build error::${l:0:300}"; done
fi
exit "$status"
