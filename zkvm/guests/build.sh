#!/usr/bin/env bash
# Rebuilds every guest and copies them to their pinned places:
#   the test fixtures used by zkvm/tests/guest.rs (guest-sum, guest-arith);
#   px/kernel.elf (CONSENSUS: its program id is pinned in px/kernel.id);
#   px/vault.elf (the reference contract; id pinned in px/vault.id).
# The build is the reproducible one of README.md (rustc 1.98.1 from
# rust-toolchain.toml, source path remapped to the canonical path), so an
# unchanged source tree gives unchanged program ids wherever it is checked out.
# Run ./reproduce.sh afterwards: a changed kernel id is a consensus change and
# needs the owner's approval and a new testnet identity.
# Requires a Windows host and Git Bash (README.md).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
canonical='C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain'
native="$(cd "$root" && pwd -W 2>/dev/null || pwd)"
native="${native//\//\\}"
sep=$'\x1f'
flags="-Crelocation-model=static${sep}-Ctarget-feature=+zmmul${sep}--remap-path-prefix=${native}=${canonical}"
target="${CARGO_TARGET_DIR:-$here/target}"
(cd "$here" && CARGO_ENCODED_RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target" cargo build --release --locked)
out="$target/riscv32i-unknown-none-elf/release"
for g in sum arith; do cp "$out/guest-$g" "$here/../tests/fixtures/guest-$g.elf"; done
cp "$out/guest-kernel" "$root/px/kernel.elf"
cp "$out/guest-vault" "$root/px/vault.elf"
echo "guests rebuilt; now run ./reproduce.sh (a changed kernel id is a consensus change)"
