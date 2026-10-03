#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^end" $S/rerunH.time 2>/dev/null && grep -q "^end" $S/provingQ.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
cat $S/rerunH/mutants.out/timeout.txt | python $S/mkre.py > $S/ev/timeoutH.args
date -u +"start %H:%M" > $S/timeoutH.time
mapfile -t R < $S/ev/timeoutH.args
for r in "${R[@]}"; do
  case "$r" in
    *373*) T=(a_heavier_fork_deeper_than_one_batch_syncs) ;;
    *) T=(a_solicited_batch_that_is_not_a_chain_is_scored_on_arrival a_second_header_request_waits_for_the_outstanding_one invalid_header_gets_the_peer_disconnected a_departed_senders_batch_stops_at_the_next_chunk) ;;
  esac
  n=$(echo "$r" | md5sum | cut -c1-8)
  cargo mutants -p blacksilk-p2p -f p2p/src/net/headers.rs "$r" --baseline skip --profile mutants --jobs 1 \
    --timeout 1500 --build-timeout 2400 --cap-lints true -o $S/timeoutH-$n -C=--lib -C=--test=network \
    -- -- --test-threads=4 "${T[@]}" > $S/timeoutH-$n.log 2>&1
  echo "$n exit $? $r" >> $S/timeoutH.time
done
date -u +"end %H:%M" >> $S/timeoutH.time
