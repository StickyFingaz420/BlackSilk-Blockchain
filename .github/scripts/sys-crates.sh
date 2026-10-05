#!/usr/bin/env bash
# Native-code checks cargo-deny cannot express (S1, dossier 44 P1; CI job
# `deny`). deny.toml bans the named C-toolchain crates and allow-lists every
# build script by exact version; this script adds:
#
#   1. *-sys names: a crate named *-sys or *_sys conventionally links a native
#      library, so every one in a lockfile must be on the reviewed list below,
#      with its reason. Both lockfiles.
#   2. C in build scripts, per release target: for each target a shipped
#      binary is built for, the resolved graph of the main workspace (normal
#      and build edges, no dev) must contain
#        a. no C/C++/assembler build helper crate (cc, cmake, ...);
#        b. no build script that runs a C compiler, assembler or C build tool
#           itself (Command::new("gcc"), reading $CC, ...);
#        c. no C/C++/assembly source or pre-built object or library in any
#           crate, except the reviewed import libraries below.
#      Target-aware: cargo tree --target resolves each target's cfgs, so a
#      crate compiled only for wasm (wit-bindgen-rt, with its C file) or only
#      for *-windows-gnu is not reported for the release targets (dossier 44
#      SC-14).
#
# The fuzz workspace links libFuzzer (C++) on purpose and is not shipped; its
# policy is fuzz/deny.toml (cc only as libfuzzer-sys's build dependency).
#
# Usage: sys-crates.sh   (from the repository root; needs the crate sources,
#        so it runs `cargo fetch --locked` first, offline if all are cached)
# Exit: 0 pass, 1 a finding.
set -euo pipefail

# ---- 1. *-sys names -------------------------------------------------------

# Reviewed: OS bindings that declare system APIs in Rust and compile no C.
main_allowed=(
  windows-sys   # Windows API declarations (raw-dylib / import libraries)
  linux-raw-sys # Linux syscall numbers and types, no libc
  dirs-sys      # home/config directory lookup over libc and windows-sys
  js-sys        # JavaScript bindings: reqwest's wasm32 backend only, never built for a release target
  web-sys       # as js-sys
)
# The fuzz workspace adds libFuzzer (C++), its reason for existing.
fuzz_allowed=("${main_allowed[@]}" libfuzzer-sys)

check_sys() {
  local lock="$1" name ok bad=0
  shift
  for name in $(sed -n 's/^name = "\(.*[-_]sys\)"\r\{0,1\}$/\1/p' "$lock" | sort -u); do
    ok=0
    for a in "$@"; do [ "$name" = "$a" ] && ok=1; done
    if [ "$ok" = 1 ]; then
      echo "$lock: $name (reviewed)"
    else
      echo "::error title=unreviewed native binding crate::$lock contains $name; review it and add it to .github/scripts/sys-crates.sh, or remove it"
      bad=1
    fi
  done
  return "$bad"
}

status=0
check_sys Cargo.lock "${main_allowed[@]}" || status=1
check_sys fuzz/Cargo.lock "${fuzz_allowed[@]}" || status=1

# ---- 2. C in build scripts, per release target ----------------------------

# The targets shipped binaries are built for: deny.toml [graph] targets.
targets=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-pc-windows-msvc
  aarch64-apple-darwin
)

# a. Crates whose purpose is to compile or locate C/C++/assembly.
builders='^(cc|cmake|bindgen|cxx|cxx-build|autotools|nasm-rs|pkg-config|vcpkg|system-deps|metadeps)$'

# b. A build script that starts a C compiler, assembler or C build tool, or
#    reads the C compiler variables, compiles C whatever crate it uses.
compiler_call='Command::new\((r#)?"(cc|c\+\+|gcc|g\+\+|clang|clang\+\+|clang-cl|cl|cl\.exe|nasm|yasm|as|ml|ml64|ar|lib\.exe|make|gmake|nmake|cmake|ninja|meson|configure|zig)"|env::var(_os)?\("(CC|CXX|CFLAGS|CXXFLAGS|AR|HOST_CC|TARGET_CC)"\)'

# c. Native sources and pre-built objects/libraries.
native_files='\.(c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx|S|s|asm|o|obj|a|lib|so|dll|dylib)$'
# Reviewed exceptions, "name@version path": pre-built Windows import
# libraries (OS API stubs, no code; dossier 44 SC-7). Only the msvc ones are
# in a release-target graph; the exact version fixes the content (Cargo.lock
# checksum).
native_allowed=(
  "windows_x86_64_msvc@0.48.5 lib/windows.0.48.5.lib"
)

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
if ! cargo fetch --locked --offline >/dev/null 2>&1; then
  cargo fetch --locked >/dev/null
fi

# The unpacked source directory of a crates.io package (every registry index
# unpacks under registry/src/<index>/<name>-<version>).
src_dir() {
  local d
  for d in "$cargo_home"/registry/src/*/"$1-$2"; do
    [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
  done
  return 1
}

# The build script of a package directory, or nothing: `build = "path"` in
# its (normalized) Cargo.toml, else build.rs if present; `build = false` means
# none.
build_script() {
  local dir="$1" b
  b="$(tr -d '\r' < "$dir/Cargo.toml" | sed -n 's/^build = \(.*\)$/\1/p' | head -n 1)"
  case "$b" in
    false) return 0 ;;
    \"*\") b="${b#\"}"; printf '%s\n' "$dir/${b%\"}"; return 0 ;;
  esac
  [ -f "$dir/build.rs" ] && printf '%s\n' "$dir/build.rs"
  return 0
}

native_ok() { # name@version relpath
  local e
  for e in "${native_allowed[@]}"; do [ "$e" = "$1 $2" ] && return 0; done
  return 1
}

build_bad=0
declare -A seen=()
for t in "${targets[@]}"; do
  pkgs="$(cargo tree --locked --offline --workspace -e normal,build --target "$t" \
    --prefix none --format '{p}' | awk '{ print $1, $2 }' | sort -u)"
  n=0
  nb=0
  while read -r name ver rest; do
    [ -n "$name" ] || continue
    n=$((n + 1))
    if [[ "$name" =~ $builders ]]; then
      echo "::error title=C build helper in a release graph::$t: $name $ver is a C/C++/assembly build helper (deny.toml bans it; .github/scripts/sys-crates.sh)"
      build_bad=1
    fi
    ver="${ver#v}"
    dir="$(src_dir "$name" "$ver")" || continue # a workspace (path) crate
    bs="$(build_script "$dir")"
    [ -n "$bs" ] && nb=$((nb + 1))
    [ -z "${seen[$name@$ver]:-}" ] || continue
    seen[$name@$ver]=1
    if [ -n "$bs" ]; then
      # The build script, and its own directory when it is not the crate root.
      scan=("$bs")
      [ "$(dirname "$bs")" = "$dir" ] || scan=("$(dirname "$bs")")
      if hit="$(grep -rnE --include='*.rs' "$compiler_call" "${scan[@]}" | head -n 1)" && [ -n "$hit" ]; then
        echo "::error title=build script runs a C toolchain::$name@$ver: ${hit#"$dir"/}"
        build_bad=1
      fi
    fi
    while IFS= read -r f; do
      rel="${f#"$dir"/}"
      if native_ok "$name@$ver" "$rel"; then
        echo "$name@$ver: $rel (reviewed import library)"
      else
        echo "::error title=native code in a release graph::$name@$ver contains $rel; review it and add it to .github/scripts/sys-crates.sh, or remove the dependency"
        build_bad=1
      fi
    done < <(find "$dir" -type f | grep -E "$native_files" | sort)
  done <<< "$pkgs"
  echo "$t: $n packages checked, $nb registry crates with a build script"
done

# The workspace's own crates (path dependencies, not in the registry): no
# tracked build script may run a C toolchain, and no tracked file may be
# C/C++/assembly or a native object.
ws_scripts=0
while IFS= read -r f; do
  ws_scripts=$((ws_scripts + 1))
  if hit="$(grep -nE "$compiler_call" "$f" | head -n 1)" && [ -n "$hit" ]; then
    echo "::error title=build script runs a C toolchain::$f:$hit"
    build_bad=1
  fi
done < <(git ls-files -- '*build.rs')
while IFS= read -r f; do
  echo "::error title=native code in the repository::$f; BlackSilk is pure Rust (no C, C++ or assembly)"
  build_bad=1
done < <(git ls-files | grep -E "$native_files")
echo "workspace: $ws_scripts tracked build scripts checked"

[ "$build_bad" = 0 ] || { echo "sys-crates: native code found (see above)"; status=1; }

exit "$status"
