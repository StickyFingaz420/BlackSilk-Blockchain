#!/usr/bin/env bash
# W4-FUZZ2: the new and changed targets, one at a time, 600 s each.
SC=C:/bszkeval/w4-fuzz2-scratch
for t in "$@"; do
  if [ "$t" = proof_struct ]; then
    while :; do
      free=$(powershell -NoProfile '(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory' | tr -d '\r')
      echo "$(date -u +%FT%TZ) free_kb=$free" >> $SC/logs/memcheck.log
      [ "$free" -ge 4000000 ] && break
      sleep 60
    done
  fi
  bash $SC/run1.sh "$t" 600 > $SC/logs/$t.summary 2>&1
  echo "$(date -u +%FT%TZ) done $t: $(tail -1 $SC/logs/$t.log.meta)"
done
