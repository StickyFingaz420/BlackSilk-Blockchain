#!/usr/bin/env bash
# The reproducible guest build (README.md). This file is the single source of
# the build's toolchain check, environment check, build location and rustflags;
# reproduce.sh sources it.
#
# Run directly, it rebuilds every guest and copies them to their pinned places:
#   the test fixtures used by zkvm/tests/guest.rs (guest-sum, guest-arith);
#   px/kernel.elf (CONSENSUS: its program id is pinned in px/kernel.id);
#   px/vault.elf (the reference contract; id pinned in px/vault.id).
# Run ./reproduce.sh afterwards: a changed kernel id is a consensus change and
# needs the owner's approval and a new testnet identity.
#
# Why the build runs at one fixed absolute path (README.md, "Why a fixed build
# path"): the pinned ELFs embed that path (px-core panic messages), and their
# symbol tables carry crate hashes that cargo derives from the absolute path of
# px-core and zkvm/sdk (both outside this workspace). The symbol table's size
# moves the section header offset, which is in the ELF header, which is inside
# the first loaded segment, so it is part of the program id. A build anywhere
# else gives other bytes and, depending on the hash lengths, another id.
# Requires a Windows host and Git Bash (README.md).
set -euo pipefail

guest_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guest_root="$(cd "$guest_here/../.." && pwd)"

# The pinned compiler (rust-toolchain.toml selects it in this directory).
GUEST_RUSTC_RELEASE='1.98.1'
GUEST_RUSTC_COMMIT='48a229cea'
# The absolute path the pinned binaries were built at.
GUEST_CANONICAL='C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain'
# The target flags (docs/zkvm.md §4: static, non-PIE, RV32I + Zmmul).
# .cargo/config.toml carries the same list for ad-hoc `cargo build` runs in this
# directory; guest_check_config fails on drift.
GUEST_FLAGS=(-Crelocation-model=static -Ctarget-feature=+zmmul)

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

# The checkout's path in Windows form (backslashes). Only MSYS bash (Git Bash)
# has `pwd -W`; another bash (WSL, Cygwin, Linux) cannot reproduce the build.
guest_native_root() {
  local native
  native="$(cd "$guest_root" && pwd -W 2>/dev/null)" ||
    guest_die "this bash has no 'pwd -W': run the guest build from Git Bash (MSYS) on Windows (README.md)"
  echo "${native//\//\\}"
}

# GUEST_CANONICAL as an MSYS path (C:\a\b -> /c/a/b).
guest_canonical_posix() {
  local p="${GUEST_CANONICAL//\\//}"
  echo "/$(echo "${p:0:1}" | tr '[:upper:]' '[:lower:]')${p:2}"
}

# Chooses the tree to build and sets GUEST_SRC to its guests directory, always
# spelled from GUEST_CANONICAL (cargo hashes the path string it is given):
# - this checkout, when it is at GUEST_CANONICAL;
# - otherwise, when GUEST_CANONICAL does not exist (a CI runner), a copy of the
#   guest sources (px-core, zkvm/sdk, zkvm/guests) staged there.
# It never deletes or overwrites anything: an existing GUEST_CANONICAL that is
# not this checkout is an error.
guest_prepare_tree() {
  local native posix
  native="$(guest_native_root)"
  posix="$(guest_canonical_posix)"
  if [ "$(echo "$native" | tr '[:upper:]' '[:lower:]')" = \
    "$(echo "$GUEST_CANONICAL" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "building in place: this checkout is at the canonical path"
  elif [ -e "$posix" ]; then
    guest_die "this checkout is not at the canonical build path, and that path exists:
  $GUEST_CANONICAL
Run the build from the checkout at that path, or on a host where the path does
not exist (the script then stages a copy of the guest sources there). A stale
copy from an earlier run must be removed by hand. README.md, 'Why a fixed build path'."
  else
    echo "staging the guest sources at the canonical path $GUEST_CANONICAL"
    mkdir -p "$posix/zkvm/guests" || guest_die "cannot create $GUEST_CANONICAL"
    cp -R "$guest_root/px-core" "$posix/px-core"
    cp -R "$guest_root/zkvm/sdk" "$posix/zkvm/sdk"
    local item
    for item in "$guest_here"/* "$guest_here"/.cargo; do
      [ "$(basename "$item")" = target ] && continue
      cp -R "$item" "$posix/zkvm/guests/"
    done
  fi
  GUEST_SRC="$posix/zkvm/guests"
}

# Builds the given guest packages (all without arguments) into
# $GUEST_OUT/<package>.
guest_build() {
  guest_check_env
  guest_check_config
  guest_prepare_tree
  guest_check_rustc "$GUEST_SRC"
  local sep flags f pkgs=()
  sep=$'\x1f'
  flags=""
  for f in "${GUEST_FLAGS[@]}"; do flags+="${flags:+$sep}$f"; done
  for f in "$@"; do pkgs+=(-p "$f"); done
  # The target directory stays in the checkout (it does not affect the output).
  local target="${CARGO_TARGET_DIR:-$guest_here/target}"
  (cd "$GUEST_SRC" && CARGO_ENCODED_RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target" \
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
