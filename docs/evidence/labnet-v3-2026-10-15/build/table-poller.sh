#!/usr/bin/env bash
# table-poller.sh OUT CSV MSYS_PID: every 5 s, node 0's address-table size
# (entry count of OUT/node0/peers.json; the file and its key are not copied),
# until MSYS_PID exits.
out="$1"; csv="$2"; pid="$3"
echo "unix,node0_table_entries,peers_json_mtime" > "$csv"
while kill -0 "$pid" 2>/dev/null; do
  f="$out/node0/peers.json"
  if [ -f "$f" ]; then
    c=$(python -c "import json,sys;print(len(json.load(open(sys.argv[1]))['entries']))" "$f" 2>/dev/null || echo err)
    echo "$(date -u +%s),$c,$(stat -c %Y "$f")" >> "$csv"
  fi
  sleep 5
done
