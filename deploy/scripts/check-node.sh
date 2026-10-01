#!/usr/bin/env bash
# Prints a node's health from its RPC and exits non-zero if something looks wrong.
#   deploy/scripts/check-node.sh [rpc address, default 127.0.0.1:29333] [cookie file]
# The RPC requires the node's cookie (docs/blocks.md §9.1): <data dir>/rpc.cookie,
# default /var/lib/blacksilk/testnet/rpc.cookie or $BLACKSILK_RPC_COOKIE. It is
# readable only by the node's user: run as that user, e.g.
#   sudo -u blacksilk deploy/scripts/check-node.sh
set -euo pipefail
RPC="${1:-127.0.0.1:29333}"
COOKIE="${2:-${BLACKSILK_RPC_COOKIE:-/var/lib/blacksilk/testnet/rpc.cookie}}"
[ -r "$COOKIE" ] || { echo "CRITICAL: cannot read the RPC cookie $COOKIE (node not running, or run as the node's user)"; exit 2; }
# The credential goes to curl on stdin, never on its command line (which other
# local users can read).
INFO="$(printf 'Authorization: Bearer %s\n' "$(tr -d '[:space:]' < "$COOKIE")" \
  | curl -fsS -H @- "http://$RPC/info")" || { echo "CRITICAL: RPC $RPC unreachable or refused the cookie"; exit 2; }
field() { echo "$INFO" | sed -n "s/.*\"$1\":\([^,}]*\).*/\1/p" | tr -d '"'; }
HEIGHT="$(field height)"; HEADERS="$(field header_height)"; PEERS="$(field peers)"
echo "network=$(field network) height=$HEIGHT headers=$HEADERS peers=$PEERS mempool=$(field mempool_txs) tip=$(field tip | cut -c1-16)"
# Identity: compare these, in full, across every device (docs/testnet.md §2.1).
# A node older than these fields prints them empty.
echo "genesis=$(field genesis_id) fingerprint=$(field consensus_fingerprint) commit=$(field build_commit) version=$(field version)"
STATUS=0
FLAGS="$(field build_flags)"
echo "${FLAGS:-build flags: (not reported)}"
case "$FLAGS" in
  "build flags: none" | "") ;;
  *) echo "WARNING: the node has test-only code compiled in (docs/testnet.md §2)"; STATUS=1 ;;
esac
[ "${PEERS:-0}" -ge 1 ] || { echo "WARNING: no peers"; STATUS=1; }
if [ -n "$HEADERS" ] && [ "$HEADERS" -gt $((HEIGHT + 10)) ]; then
  echo "NOTE: still syncing ($((HEADERS - HEIGHT)) blocks behind the best header)"
fi
exit $STATUS
