#!/usr/bin/env sh
# Rebuilds the guest test fixtures used by zkvm/tests/guest.rs.
# Requires: rustup target add riscv32i-unknown-none-elf
# Output depends on the exact rustc version; the fixtures are committed so the
# host tests never need the RISC-V target.
set -eu
cd "$(dirname "$0")"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}" cargo build --release
for g in sum arith; do cp "${CARGO_TARGET_DIR:-target}/riscv32i-unknown-none-elf/release/guest-$g" ../tests/fixtures/guest-$g.elf; done
# The PX kernel: its program id is pinned in px/src/prove.rs.
cp "${CARGO_TARGET_DIR:-target}/riscv32i-unknown-none-elf/release/guest-kernel" ../../px/kernel.elf
# The reference contract (px/src/vault.rs): its program id is pinned in px/vault.id.
cp "${CARGO_TARGET_DIR:-target}/riscv32i-unknown-none-elf/release/guest-vault" ../../px/vault.elf
echo "fixtures updated"
