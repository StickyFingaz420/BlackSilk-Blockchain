#!/usr/bin/env bash
# Prints a node's health from its RPC and exits non-zero if something looks wrong.
#   deploy/scripts/check-node.sh [rpc address, default 127.0.0.1:29333] [cookie file]
# The RPC requires the node's cookie (docs/blocks.md §9.1): <data dir>/rpc.cookie,
# default /var/lib/blacksilk/testnet/rpc.cookie or $BLACKSILK_RPC_COOKIE. It is
# readable only by the node's user: run as that user, e.g.
#   sudo -u blacksilk deploy/scripts/check-node.sh
# A trial device must run with the network pre-shared key (docs/testnet.md
# §12.3): set BLACKSILK_REQUIRE_PSK=1 (the trial procedure does) to get a
# warning when the node has none loaded.
set -euo pipefail
RPC="${1:-127.0.0.1:29333}"
COOKIE="${2:-${BLACKSILK_RPC_COOKIE:-/var/lib/blacksilk/testnet/rpc.cookie}}"
[ -r "$COOKIE" ] || { echo "CRITICAL: cannot read the RPC cookie $COOKIE (node not running, or run as the node's user)"; exit 2; }
# The credential goes to curl on stdin, never on its command line (which other
# local users can read).
INFO="$(printf 'Authorization: Bearer %s\n' "$(tr -d '[:space:]' < "$COOKIE")" \
  | curl -fsS -H @- "http://$RPC/info")" || { echo "CRITICAL: RPC $RPC unreachable or refused the cookie"; exit 2; }
# A top-level scalar field: its first occurrence (nested objects that come
# later, such as operator_verdicts, have their own "height").
field() { echo "$INFO" | { grep -o "\"$1\":[^,}]*" || true; } | head -n1 | sed "s/^\"$1\"://" | tr -d '"'; }
# The contents of a JSON array field (empty for [] or a missing field).
array() { echo "$INFO" | sed -n "s/.*\"$1\":\[\([^]]*\)\].*/\1/p"; }
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
# The network pre-shared key: whether one is loaded, never the key.
PSK="$(field network_psk_loaded)"
echo "psk_loaded=${PSK:-(not reported)}"
if [ "${BLACKSILK_REQUIRE_PSK:-0}" = 1 ] && [ "$PSK" != true ]; then
  echo "WARNING: no network pre-shared key loaded, and this device is on a trial (BLACKSILK_REQUIRE_PSK=1): set network_psk_file (docs/testnet.md §12.3)"
  STATUS=1
fi
# Operator overrides of this run and operator verdicts in force (F48-9):
# normally none; each one changes what this node follows or serves.
OVERRIDES="$(array overrides)"
if [ -n "$OVERRIDES" ]; then
  echo "WARNING: operator overrides in force: $OVERRIDES"
  STATUS=1
fi
VERDICTS="$(array operator_verdicts | { grep -o '"block":"[0-9a-f]*"' || true; } | cut -d'"' -f4 | tr '\n' ' ')"
if [ -n "$VERDICTS" ]; then
  echo "WARNING: blocks invalidated by the operator (--reconsider-block undoes it): $VERDICTS"
  STATUS=1
fi
if [ -n "$HEADERS" ] && [ "$HEADERS" -gt $((HEIGHT + 10)) ]; then
  echo "NOTE: still syncing ($((HEADERS - HEIGHT)) blocks behind the best header)"
fi
exit $STATUS
