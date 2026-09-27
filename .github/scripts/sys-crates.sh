#!/usr/bin/env bash
# The "*-sys" half of the native-code ban (S1; deny.toml [bans] lists the named
# crates, but cargo-deny has no name patterns). A crate named *-sys or *_sys
# conventionally links a native library, so every one in a lockfile must be on
# the reviewed list below, with its reason.
#
# Usage: sys-crates.sh   (from the repository root; checks both lockfiles)
# Exit: 0 pass, 1 an unreviewed *-sys crate.
set -euo pipefail

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

check() {
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
check Cargo.lock "${main_allowed[@]}" || status=1
check fuzz/Cargo.lock "${fuzz_allowed[@]}" || status=1
exit "$status"
