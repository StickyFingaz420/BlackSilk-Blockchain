#!/usr/bin/env bash
# W4-FUZZ: the campaign, one target at a time. proof_decode last, after a memory check.
SC=C:/bszkeval/w4-fuzz-scratch
for t in "$@"; do
  if [ "$t" = proof_decode ]; then
    while :; do
      free=$(powershell -NoProfile '(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory' | tr -d '\r')
      echo "$(date -u +%FT%TZ) free_kb=$free" >> $SC/logs/memcheck.log
      [ "$free" -ge 6000000 ] && break
      sleep 60
    done
  fi
  bash $SC/run1.sh "$t" 1800 > $SC/logs/$t.summary 2>&1
  echo "$(date -u +%FT%TZ) done $t: $(head -2 $SC/logs/$t.log.meta | tail -1)"
done
