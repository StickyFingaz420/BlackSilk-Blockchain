#!/usr/bin/env bash
# Prints a node's health from its RPC and exits non-zero if something looks wrong.
#   deploy/scripts/check-node.sh [rpc address, default 127.0.0.1:29333]
set -euo pipefail
RPC="${1:-127.0.0.1:29333}"
INFO="$(curl -fsS "http://$RPC/info")" || { echo "CRITICAL: RPC $RPC unreachable"; exit 2; }
field() { echo "$INFO" | sed -n "s/.*\"$1\":\([^,}]*\).*/\1/p" | tr -d '"'; }
HEIGHT="$(field height)"; HEADERS="$(field header_height)"; PEERS="$(field peers)"
echo "network=$(field network) height=$HEIGHT headers=$HEADERS peers=$PEERS mempool=$(field mempool_txs) tip=$(field tip | cut -c1-16)"
STATUS=0
[ "${PEERS:-0}" -ge 1 ] || { echo "WARNING: no peers"; STATUS=1; }
if [ -n "$HEADERS" ] && [ "$HEADERS" -gt $((HEIGHT + 10)) ]; then
  echo "NOTE: still syncing ($((HEADERS - HEIGHT)) blocks behind the best header)"
fi
exit $STATUS
