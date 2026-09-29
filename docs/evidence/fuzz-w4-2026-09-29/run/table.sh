#!/usr/bin/env bash
# W4-FUZZ: per-target summary from the logs.
SC=C:/bszkeval/w4-fuzz-scratch
printf "target|wall_s|execs|exec_s|init cov/ft|final cov/ft|corp before->after (files)|new_units|last NEW at exec (share)|peak_rss_mb|slowest_s|artifacts|exit\n"
for t in "$@"; do
  L=$SC/logs/$t.log; M=$L.meta
  [ -f "$M" ] || continue
  wall=$(sed -n 's/.*wall=\([0-9]*\)s.*/\1/p' $M); ex=$(sed -n 's/.*exit=\([0-9]*\).*/\1/p' $M)
  cb=$(sed -n 's/.*corpus_before=\([0-9]*\) files.*/\1/p' $M); ca=$(sed -n 's/.*corpus_after=\([0-9]*\) files.*/\1/p' $M)
  arts=$(sed -n 's/.*artifacts=\([0-9]*\).*/\1/p' $M)
  st(){ sed -n "s/^stat::$1: *\([0-9]*\).*/\1/p" $L | tail -1; }
  n=$(st number_of_executed_units); r=$(st average_exec_per_sec); nu=$(st new_units_added); rss=$(st peak_rss_mb); slow=$(st slowest_unit_time_sec)
  init=$(grep -E "INITED" $L | sed -n 's/.*cov: \([0-9]*\) ft: \([0-9]*\).*/\1\/\2/p' | tail -1)
  fin=$(grep -E "DONE" $L | sed -n 's/.*cov: \([0-9]*\) ft: \([0-9]*\).*/\1\/\2/p' | tail -1)
  last=$(grep -E "^#[0-9]+.(NEW|REDUCE) " $L | grep -E "NEW " | tail -1 | sed -n 's/^#\([0-9]*\).*/\1/p')
  share=$(awk -v a="${last:-0}" -v b="${n:-1}" 'BEGIN{printf "%.0f%%", 100*a/b}')
  printf "%s|%s|%s|%s|%s|%s|%s->%s|%s|%s (%s)|%s|%s|%s|%s\n" $t "$wall" "$n" "$r" "$init" "$fin" "$cb" "$ca" "$nu" "${last:-none}" "$share" "$rss" "$slow" "$arts" "$ex"
done
