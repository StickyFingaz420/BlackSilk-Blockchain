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
# The target flags (docs/zkvm.md §4: static, non-PIE, RV32I + Zmmul),
# --strip-all: no symbol table, so no path-derived crate hashes in the ELF, and
# the link layout guest.ld (CI-1: no ELF header in any PT_LOAD, no .comment; a
# path relative to this directory, where cargo runs rustc and rustc runs LLD).
# .cargo/config.toml carries the same list for ad-hoc `cargo build` runs in this
# directory; guest_check_config fails on drift.
GUEST_FLAGS=(-Crelocation-model=static -Ctarget-feature=+zmmul -Clink-arg=--strip-all -Clink-arg=-Tguest.ld)

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

# Refuses cargo configuration files that would change what the canonical build
# produces (CI-6). Cargo merges every .cargo/config[.toml] from the build
# directory up to the filesystem root, then $CARGO_HOME/config[.toml]; only
# this directory's own .cargo/config.toml is part of the canonical build.
# Refused, in any other of those files:
#   [profile.*] tables or profile.* keys (config profiles override Cargo.toml);
#   build.rustc, build.rustc-wrapper, build.rustc-workspace-wrapper;
#   [target.riscv32i-unknown-none-elf] and [target.'cfg(...)'] tables (linker,
#   runner or rustflags for the guest target);
#   [patch.*] tables and path overrides (paths = [...]).
# rustflags elsewhere are harmless: CARGO_ENCODED_RUSTFLAGS, which guest_build
# sets, takes precedence over every config rustflags. The check is line-based:
# it may refuse a file that only mentions such a key in a way cargo would
# ignore, never the reverse for the forms above.
guest_check_cargo_config() {
  local d parent f bad=0 hits
  local own="$guest_here/.cargo/config.toml"
  local files=()
  d="$guest_here"
  while :; do
    files+=("$d/.cargo/config" "$d/.cargo/config.toml")
    parent="$(dirname "$d")"
    [ "$parent" != "$d" ] || break
    d="$parent"
  done
  local cargo_home="${CARGO_HOME:-${HOME:-}/.cargo}"
  files+=("$cargo_home/config" "$cargo_home/config.toml")
  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    [ "$f" != "$own" ] || continue
    hits="$(tr -d '\r' < "$f" | grep -nE \
      -e '^[[:space:]]*\[+[[:space:]]*profile([[:space:]]*[].]|$)' \
      -e '^[[:space:]]*profile[[:space:]]*[.=]' \
      -e '^[[:space:]]*(build[[:space:]]*\.[[:space:]]*)?rustc(-workspace)?(-wrapper)?[[:space:]]*=' \
      -e '^[[:space:]]*\[+[[:space:]]*target[[:space:]]*(\]|\.[[:space:]]*("|'"'"')?(riscv32i-unknown-none-elf|cfg))' \
      -e '^[[:space:]]*target[[:space:]]*\.[[:space:]]*("|'"'"')?(riscv32i-unknown-none-elf|cfg)' \
      -e '^[[:space:]]*\[+[[:space:]]*patch([[:space:]]*[].]|$)' \
      -e '^[[:space:]]*(patch|paths)[[:space:]]*[.=]' || true)"
    if [ -n "$hits" ]; then
      echo "error: cargo config $f would change the reproducible guest build:" >&2
      printf '%s\n' "$hits" | sed 's/^/  line /' >&2
      bad=1
    fi
  done
  [ "$bad" = 0 ] || guest_die "move or rename the cargo config above for the guest build (README.md \"Build environment\")"
}

# sha256 of a file, with whatever the host has (CI-17: stock macOS has shasum,
# not sha256sum).
guest_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | cut -d' ' -f1
  else
    guest_die "no sha256 tool (sha256sum, shasum or openssl)"
  fi
}

# The value of key $3 in table [$2] of the TOML file $1 (one-line string
# values only; enough for rustup's channel manifests).
guest_toml_value() {
  # awk reads the file itself and to the end: an early `exit` behind a pipe
  # makes the writer die of SIGPIPE on large manifests, which `pipefail`
  # turns into a failure (the Linux CI legs, whose manifests exceed the pipe
  # buffer).
  awk -v t="[$2]" -v k="$3" '
    { sub(/\r$/, "") }
    $0 == t { on = 1; next }
    /^\[/ { on = 0 }
    on && !done && index($0, k " = \"") == 1 { v = substr($0, length(k) + 5); sub(/"$/, "", v); print v; done = 1 }' "$1"
}

# Checks the installed toolchain against toolchain.sha256 (CI-13). rustup
# verifies each download only against the channel manifest fetched from the
# same server; this file pins that manifest and the riscv32i standard library
# (the precompiled core and compiler_builtins linked into every guest) in the
# repository.
#   Always: rustup's copy of the manifest (<sysroot>/lib/rustlib/
#   multirust-channel-manifest.toml, which rustup re-serializes, so its own
#   hash is not the published one) must list the pinned rust-std hashes and
#   the pinned rustc release.
#   GUEST_VERIFY_MANIFEST_ONLINE=1 (CI): also downloads the published channel
#   manifest, checks its sha256 against the pin, and checks that rustup's copy
#   lists the same rustc package hash for this host.
# A rustc not installed by rustup has no manifest: a warning, or an error with
# GUEST_REQUIRE_MANIFEST=1 (CI).
guest_check_toolchain_manifest() {
  local pins="$guest_here/toolchain.sha256" sysroot manifest host pin got name hash
  [ -f "$pins" ] || guest_die "missing $pins"
  sysroot="$(cd "$guest_here" && rustc --print sysroot | tr -d '\r')"
  manifest="$sysroot/lib/rustlib/multirust-channel-manifest.toml"
  if [ ! -f "$manifest" ]; then
    [ "${GUEST_REQUIRE_MANIFEST:-0}" != 1 ] || guest_die "no rustup channel manifest at $manifest"
    echo "warning: rustc is not a rustup toolchain; the toolchain manifest pin (toolchain.sha256) was not checked" >&2
    return 0
  fi
  got="$(guest_toml_value "$manifest" pkg.rustc version)"
  [ "${got#"$GUEST_RUSTC_RELEASE ($GUEST_RUSTC_COMMIT"}" != "$got" ] ||
    guest_die "rustup manifest lists rustc '$got', not $GUEST_RUSTC_RELEASE ($GUEST_RUSTC_COMMIT...)"
  while read -r hash name; do
    hash="${hash%$'\r'}"
    name="${name%$'\r'}"
    case "$name" in
      rust-std-*-riscv32i-unknown-none-elf.tar.gz) got="$(guest_toml_value "$manifest" pkg.rust-std.target.riscv32i-unknown-none-elf hash)" ;;
      rust-std-*-riscv32i-unknown-none-elf.tar.xz) got="$(guest_toml_value "$manifest" pkg.rust-std.target.riscv32i-unknown-none-elf xz_hash)" ;;
      *) continue ;;
    esac
    [ "$got" = "$hash" ] || guest_die "rustup manifest: $name is '$got', pinned $hash (toolchain.sha256)"
  done < "$pins"
  echo "toolchain: rustup manifest matches the pinned rustc release and riscv32i rust-std (toolchain.sha256)"
  [ "${GUEST_VERIFY_MANIFEST_ONLINE:-0}" = 1 ] || return 0

  local url="https://static.rust-lang.org/dist/channel-rust-$GUEST_RUSTC_RELEASE.toml" tmp
  pin="$(tr -d '\r' < "$pins" | awk -v n="channel-rust-$GUEST_RUSTC_RELEASE.toml" '$2 == n { print $1 }')"
  [ -n "$pin" ] || guest_die "toolchain.sha256 has no channel-rust-$GUEST_RUSTC_RELEASE.toml line"
  tmp="$(mktemp)"
  curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$tmp" || { rm -f "$tmp"; guest_die "cannot download $url"; }
  got="$(guest_sha256 "$tmp")"
  [ "$got" = "$pin" ] || { rm -f "$tmp"; guest_die "published manifest $url has sha256 $got, pinned $pin"; }
  host="$(cd "$guest_here" && rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
  pin="$(guest_toml_value "$tmp" "pkg.rustc.target.$host" hash)"
  got="$(guest_toml_value "$manifest" "pkg.rustc.target.$host" hash)"
  rm -f "$tmp"
  [ -n "$pin" ] && [ "$got" = "$pin" ] || guest_die "rustc for $host: rustup recorded '$got', the pinned manifest lists '$pin'"
  echo "toolchain: published manifest sha256 matches the pin; rustc $host package hash $got"
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
  guest_check_cargo_config
  guest_check_rustc "$guest_here"
  guest_check_toolchain_manifest
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
