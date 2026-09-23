#!/usr/bin/env bash
# Builds and installs a BlackSilk testnet node as a systemd service.
#   sudo deploy/scripts/install-linux.sh [--seed] [--miner <address>]
# Run from the repository root. Needs: Rust (rustup), systemd.
set -euo pipefail

SEED=0
MINER_ADDRESS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --seed) SEED=1 ;;
    --miner) MINER_ADDRESS="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -f Cargo.toml ] && [ -d node ] || { echo "run from the repository root" >&2; exit 1; }

BUILD_USER="${SUDO_USER:-root}"
echo "==> building release binaries as $BUILD_USER"
sudo -u "$BUILD_USER" cargo build --release --locked \
  -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet

echo "==> installing binaries"
install -m 0755 target/release/blacksilk-node target/release/blacksilk-miner \
  target/release/blacksilk-wallet /usr/local/bin/

echo "==> user, directories, configuration"
id blacksilk >/dev/null 2>&1 || useradd --system --home /var/lib/blacksilk --shell /usr/sbin/nologin blacksilk
install -d -m 0750 -o blacksilk -g blacksilk /var/lib/blacksilk
install -d -m 0755 /etc/blacksilk
if [ ! -f /etc/blacksilk/node.toml ]; then
  if [ "$SEED" -eq 1 ]; then
    install -m 0644 deploy/config/testnet-seed.toml /etc/blacksilk/node.toml
    echo "!! edit public_address in /etc/blacksilk/node.toml before starting a seed"
  else
    install -m 0644 deploy/config/testnet-node.toml /etc/blacksilk/node.toml
  fi
else
  echo "keeping existing /etc/blacksilk/node.toml"
fi

echo "==> systemd units"
install -m 0644 deploy/systemd/blacksilk-node.service /etc/systemd/system/
if [ -n "$MINER_ADDRESS" ]; then
  echo "BLACKSILK_MINER_ADDRESS=$MINER_ADDRESS" > /etc/blacksilk/miner.env
  chmod 0644 /etc/blacksilk/miner.env
  install -m 0644 deploy/systemd/blacksilk-miner.service /etc/systemd/system/
fi
systemctl daemon-reload
systemctl enable --now blacksilk-node.service
[ -n "$MINER_ADDRESS" ] && systemctl enable --now blacksilk-miner.service

echo "==> done. Open TCP 29334 inbound. Status: deploy/scripts/check-node.sh"
