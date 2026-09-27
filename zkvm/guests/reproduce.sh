#!/usr/bin/env bash
# Rebuilds the consensus-pinned guest programs from source and checks their
# program ids against the pinned ones (zkvm/guests/README.md):
#   guest-kernel -> px/kernel.elf, id in px/kernel.id (consensus, px.md §4.3)
#   guest-vault  -> px/vault.elf,  id in px/vault.id  (the reference contract)
# Exits non-zero if an id differs. CI runs it (.github/workflows/ci.yml).
#
# Requirements (README): a Windows host (the pinned binaries embed a Windows
# source path, see README), rustc 1.98.1 with the riscv32i-unknown-none-elf
# target (rust-toolchain.toml installs both), Git Bash.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# The absolute source path the pinned binaries were built at. Panic messages of
# px-core embed it, so it is part of the program's data and of its id.
canonical='C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain'
# This checkout's path as rustc sees it (Windows form, backslashes).
native="$(cd "$root" && pwd -W 2>/dev/null || pwd)"
native="${native//\//\\}"
sep=$'\x1f'
# The flags of .cargo/config.toml plus the path remapping (for the guest build
# only; the host build of the id tool below must not see them).
flags="-Crelocation-model=static${sep}-Ctarget-feature=+zmmul${sep}--remap-path-prefix=${native}=${canonical}"
target="${CARGO_TARGET_DIR:-$here/target}"
(cd "$here" && CARGO_ENCODED_RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target"   cargo build --release --locked -p guest-kernel -p guest-vault)
out="$target/riscv32i-unknown-none-elf/release"
ids="$(cd "$root" && cargo run --quiet --release -p blacksilk-zkvm --example program_id -- \
  "$out/guest-kernel" "$out/guest-vault")"
echo "$ids"
kernel="$(echo "$ids" | sed -n 1p | cut -d' ' -f1)"
vault="$(echo "$ids" | sed -n 2p | cut -d' ' -f1)"
status=0
if [ "$kernel" = "$(tr -d '[:space:]' < "$root/px/kernel.id")" ]; then
  echo "kernel: reproduced (matches px/kernel.id)"
else
  echo "kernel: MISMATCH with px/kernel.id"; status=1
fi
if [ "$vault" = "$(tr -d '[:space:]' < "$root/px/vault.id")" ]; then
  echo "vault: reproduced (matches px/vault.id)"
else
  echo "vault: MISMATCH with px/vault.id"; status=1
fi
exit $status
