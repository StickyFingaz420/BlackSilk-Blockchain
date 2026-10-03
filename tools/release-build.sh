#!/usr/bin/env bash
# The release build of BlackSilk binaries (W4-GUARD, RT-GUARD): a plain
# `cargo build --release --locked` with flags that keep the build machine's
# paths out of the binaries and, on Windows, make the bytes reproducible.
#
#   tools/release-build.sh [cargo build arguments]
#   (default: -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet
#    -p blacksilk-genesis)
#
# - `--remap-path-prefix` for CARGO_HOME (`/cargo`), the toolchain sysroot
#   (`/rustc-sysroot`) and this checkout (`/blacksilk`): the panic locations
#   of registry crates otherwise embed the build user's home directory
#   (`C:\Users\<user>\.cargo\registry\...`, `/home/<user>/.cargo/...`) in
#   the node, miner and wallet, which tells anyone holding a binary who built
#   it, and makes the bytes depend on the user name.
# - On x86_64-pc-windows-msvc, `-Brepro` (as in .cargo/config.toml, which
#   these flags replace: cargo uses only one source of rustflags).
#
# The flags go through CARGO_ENCODED_RUSTFLAGS, which keeps paths with spaces
# intact. They change no source file, so the node's dirty check (build.rs)
# and --locked behave as for a plain build. Not for `cargo test`: it is a
# release-artifact command.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
host="$(rustc -vV | sed -n 's/^host: //p')"
sysroot="$(rustc --print sysroot)"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
native() { # the path as rustc sees it (Windows form under Git Bash)
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi
}
cargo_home="$(native "$cargo_home")"
sysroot="$(native "$sysroot")"
root_native="$(native "$root")"
[ -n "$cargo_home" ] && [ -n "$sysroot" ] && [ -n "$host" ] || {
  echo "release-build: cannot determine CARGO_HOME, the sysroot or the host" >&2
  exit 2
}

flags=(
  "--remap-path-prefix=$cargo_home=/cargo"
  "--remap-path-prefix=$sysroot=/rustc-sysroot"
  "--remap-path-prefix=$root_native=/blacksilk"
)
case "$host" in
  x86_64-pc-windows-msvc) flags+=("-Clink-arg=-Brepro") ;;
esac
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${flags[*]}")"
export CARGO_ENCODED_RUSTFLAGS

if [ $# -eq 0 ]; then
  set -- -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet -p blacksilk-genesis
fi
echo "release-build: host $host; remapping CARGO_HOME, the sysroot and the checkout" >&2
exec cargo build --release --locked "$@"
