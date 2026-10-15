#!/usr/bin/env bash
# run.sh LABEL OUT [labnet args...]: one labnet run from C:/bszkeval/labnet-v3,
# console teed to console/LABEL.console.log (outside --out), load sampled to
# console/LABEL.load.csv, exit status to console/LABEL.exit.
set -u
cd C:/bszkeval/labnet-v3
label="$1"; out="$2"; shift 2
mkdir -p console runs
export RUST_LOG="info,blacksilk_p2p::net=debug" BLACKSILK_REQUIRE_CLEAN_BUILD=1
unset RUSTFLAGS BLACKSILK_ALLOW_DIRTY
cmd=(bin/blacksilk-labnet.exe --bin-dir C:/bszkeval/labnet-v3/bin --out "$out" "$@")
{ echo "cwd: $(pwd -W)"; echo "env: RUST_LOG=$RUST_LOG BLACKSILK_REQUIRE_CLEAN_BUILD=$BLACKSILK_REQUIRE_CLEAN_BUILD"; echo "cmd: ${cmd[*]}"; echo "start_utc: $(date -u +%FT%TZ)"; } > "console/$label.meta"
"${cmd[@]}" > "console/$label.console.log" 2>&1 &
pid=$!
winpid=$(cat /proc/$pid/winpid)
echo "labnet_winpid: $winpid" >> "console/$label.meta"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:/bszkeval/labnet-v3/scripts/load-sampler.ps1" -LabnetPid "$winpid" -Csv "C:/bszkeval/labnet-v3/console/$label.load.csv" > "console/$label.sampler.log" 2>&1 &
spid=$!
bash scripts/table-poller.sh "$out" "console/$label.node0-table.csv" "$pid" &
tpid=$!
echo "sampler_winpid: $(cat /proc/$spid/winpid 2>/dev/null)" >> "console/$label.meta"
wait $pid; st=$?
echo "end_utc: $(date -u +%FT%TZ)" >> "console/$label.meta"
echo "exit: $st" >> "console/$label.meta"
echo "$st" > "console/$label.exit"
wait $spid 2>/dev/null; wait $tpid 2>/dev/null
exit $st
