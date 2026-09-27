#!/usr/bin/env bash
# Rebuilds the consensus-pinned guest programs from source and checks them
# against the pinned ones (zkvm/guests/README.md):
#   guest-kernel -> px/kernel.elf, id in px/kernel.id (consensus, px.md §4.3)
#   guest-vault  -> px/vault.elf,  id in px/vault.id  (the reference contract)
# Checks, for each: the rebuilt program id equals the pinned id, the committed
# ELF's id equals the pinned id, and the rebuilt ELF is byte-identical
# (sha256) to the committed one. Exits non-zero on any mismatch. CI runs it
# (.github/workflows/ci.yml, job `guests`).
#
# Requirements (README): bash and rustc 1.98.1 with the riscv32i-unknown-none-elf
# target (rust-toolchain.toml installs both), on any host and at any checkout
# path (the build is path-independent since testnet v3). The toolchain check, the
# environment check and the flags live in build.sh, sourced here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build.sh
source "$here/build.sh"
root="$guest_root"

guest_build guest-kernel guest-vault

# The id tool is a host build: it must not see the guest flags (guest_build
# sets them only for its own cargo call).
ids="$(cd "$root" && cargo run --locked --quiet --release -p blacksilk-zkvm --example program_id -- \
  "$GUEST_OUT/guest-kernel" "$GUEST_OUT/guest-vault" "$root/px/kernel.elf" "$root/px/vault.elf")"
echo "$ids"
id_of() { echo "$ids" | sed -n "${1}p" | cut -d' ' -f1; }
sha_of() { guest_sha256 "$1"; }

status=0
check() {
  local name="$1" rebuilt_id="$2" committed_id="$3" rebuilt="$4" committed="$5" pinned
  pinned="$(tr -d '[:space:]' < "$root/px/$name.id")"
  if [ "$rebuilt_id" = "$pinned" ]; then
    echo "$name: rebuilt id reproduced (matches px/$name.id)"
  else
    echo "$name: rebuilt id MISMATCH with px/$name.id"; status=1
  fi
  if [ "$committed_id" != "$pinned" ]; then
    echo "$name: committed px/$name.elf id MISMATCH with px/$name.id"; status=1
  fi
  local a b
  a="$(sha_of "$rebuilt")"
  b="$(sha_of "$committed")"
  echo "$name: sha256 rebuilt $a"
  echo "$name: sha256 px/$name.elf $b"
  if [ "$a" = "$b" ]; then
    echo "$name: rebuilt ELF byte-identical to px/$name.elf"
  else
    echo "$name: rebuilt ELF bytes DIFFER from px/$name.elf"; status=1
  fi
}
check kernel "$(id_of 1)" "$(id_of 3)" "$GUEST_OUT/guest-kernel" "$root/px/kernel.elf"
check vault "$(id_of 2)" "$(id_of 4)" "$GUEST_OUT/guest-vault" "$root/px/vault.elf"
exit $status
