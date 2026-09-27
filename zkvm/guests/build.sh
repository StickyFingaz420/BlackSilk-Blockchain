#!/usr/bin/env bash
# The reproducible guest build (README.md). This file is the single source of
# the build's toolchain check, environment check and rustflags; reproduce.sh
# sources it.
#
# Run directly, it rebuilds every guest and copies them to their pinned places:
#   the test fixtures used by zkvm/tests/guest.rs (guest-sum, guest-arith);
#   px/kernel.elf (CONSENSUS: its program id is pinned in px/kernel.id);
#   px/vault.elf (the reference contract; id pinned in px/vault.id).
# Run ./reproduce.sh afterwards: a changed kernel id is a consensus change and
# needs the owner's approval and a new testnet identity.
#
# Path independence (testnet v3, R15-6; README.md "Path independence"): the
# guests are linked with --strip-all, so the path-dependent crate hashes in the
# symbol table are not in the file, and px-core has no panic with a source
# location on the guest paths (Permutation::invalid_input). The build runs in
# place, from any checkout path, on any host with bash and the pinned rustc.
set -euo pipefail

guest_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guest_root="$(cd "$guest_here/../.." && pwd)"

# The pinned compiler (rust-toolchain.toml selects it in this directory).
GUEST_RUSTC_RELEASE='1.98.1'
GUEST_RUSTC_COMMIT='48a229cea'
# The target flags (docs/zkvm.md §4: static, non-PIE, RV32I + Zmmul), and
# --strip-all: no symbol table, so no path-derived crate hashes in the ELF.
# .cargo/config.toml carries the same list for ad-hoc `cargo build` runs in this
# directory; guest_check_config fails on drift.
GUEST_FLAGS=(-Crelocation-model=static -Ctarget-feature=+zmmul -Clink-arg=--strip-all)

guest_die() {
  echo "error: $*" >&2
  exit 1
}

# Refuses environment variables that would change what cargo/rustc build.
guest_check_env() {
  local v bad=0
  for v in RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS \
    CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_BUILD_TARGET \
    CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
    if [ -n "${!v+x}" ]; then
      echo "error: $v is set; unset it for the reproducible guest build" >&2
      bad=1
    fi
  done
  for v in $(compgen -e); do
    case "$v" in
      CARGO_PROFILE_* | CARGO_TARGET_RISCV32I_UNKNOWN_NONE_ELF_*)
        echo "error: $v is set; unset it for the reproducible guest build" >&2
        bad=1
        ;;
    esac
  done
  [ "$bad" = 0 ] || exit 1
}

# Prints `rustc -vV` as the directory $1 resolves it (rust-toolchain.toml) and
# fails unless it is the pinned release.
guest_check_rustc() {
  local info release commit
  info="$(cd "$1" && rustc -vV)" || guest_die "rustc not found"
  echo "$info"
  release="$(echo "$info" | sed -n 's/^release: //p' | tr -d '\r')"
  commit="$(echo "$info" | sed -n 's/^commit-hash: //p' | tr -d '\r')"
  [ "$release" = "$GUEST_RUSTC_RELEASE" ] && [ "${commit#"$GUEST_RUSTC_COMMIT"}" != "$commit" ] ||
    guest_die "rustc $release ($commit) is not the pinned $GUEST_RUSTC_RELEASE ($GUEST_RUSTC_COMMIT...); see rust-toolchain.toml"
}

# Fails if .cargo/config.toml's rustflags drifted from GUEST_FLAGS.
guest_check_config() {
  local f expected=""
  for f in "${GUEST_FLAGS[@]}"; do
    expected+="${expected:+, }\"-C\", \"${f#-C}\""
  done
  grep -Fqx "rustflags = [$expected]" "$guest_here/.cargo/config.toml" ||
    guest_die ".cargo/config.toml rustflags differ from GUEST_FLAGS in build.sh; expected: rustflags = [$expected]"
}

# Builds the given guest packages (all without arguments) into
# $GUEST_OUT/<package>, in place.
guest_build() {
  guest_check_env
  guest_check_config
  guest_check_rustc "$guest_here"
  local sep flags f pkgs=()
  sep=$'\x1f'
  flags=""
  for f in "${GUEST_FLAGS[@]}"; do flags+="${flags:+$sep}$f"; done
  for f in "$@"; do pkgs+=(-p "$f"); done
  local target="${CARGO_TARGET_DIR:-$guest_here/target}"
  (cd "$guest_here" && CARGO_ENCODED_RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target" \
    cargo build --release --locked "${pkgs[@]}")
  GUEST_OUT="$target/riscv32i-unknown-none-elf/release"
}

guest_main() {
  guest_build
  local g
  for g in sum arith; do cp "$GUEST_OUT/guest-$g" "$guest_here/../tests/fixtures/guest-$g.elf"; done
  cp "$GUEST_OUT/guest-kernel" "$guest_root/px/kernel.elf"
  cp "$GUEST_OUT/guest-vault" "$guest_root/px/vault.elf"
  echo "guests rebuilt; now run ./reproduce.sh (a changed kernel id is a consensus change)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  guest_main "$@"
fi
