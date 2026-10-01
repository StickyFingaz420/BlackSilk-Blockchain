#!/usr/bin/env bash
# Fails when a BlackSilk binary has test-only code compiled in (W4-GUARD).
#
#   tools/check-build-flags.sh [--strings] <binary>...
#
# `cargo test` unifies dev-dependency features into every binary it writes,
# at the path a plain `cargo build --release` uses: after `cargo test
# --release`, target/release/blacksilk-node has the test hooks of chain, tx,
# px (and p2p in a workspace run). A cargo-fuzz build adds `cfg(fuzzing)`
# code. Such a binary is for this repository's regtest tests only, never for
# evidence, genesis or a shared network.
#
# Per binary:
# - `--version` must succeed and name no marker (`+test-hooks:<crate>`,
#   `+fuzzing:<crate>`; each is compiled in only with its code);
# - blacksilk-node and blacksilk-genesis must print the line
#   `build flags: none` (a build older than the guard cannot show its test
#   code, so it is refused);
# - with --strings, the file itself must contain neither a marker nor the
#   chain actor's injected-panic message (an independent check of the bytes,
#   in case `--version` lied or the binary was edited).
# Exit status: 0 when every binary is clean, 1 otherwise, 2 on usage errors.
set -uo pipefail

strings=0
if [ "${1:-}" = "--strings" ]; then
  strings=1
  shift
fi
[ $# -gt 0 ] || { echo "usage: $0 [--strings] <binary>..." >&2; exit 2; }

markers='\+(test-hooks|fuzzing):[a-z0-9-]+'
rc=0
for bin in "$@"; do
  bad=0
  if [ ! -x "$bin" ]; then
    echo "check-build-flags: $bin: not an executable file" >&2
    rc=1
    continue
  fi
  if ! version="$("$bin" --version </dev/null 2>&1 | tr -d '\r')"; then
    echo "check-build-flags: $bin --version failed: $version" >&2
    rc=1
    continue
  fi
  name="$(basename "$bin" .exe)"
  if found="$(grep -Eo "$markers" <<<"$version" | sort -u | tr '\n' ' ')" && [ -n "$found" ]; then
    echo "check-build-flags: $bin was built with test-only code: $found" >&2
    bad=1
  elif case "$name" in blacksilk-node | blacksilk-genesis) true ;; *) false ;; esac &&
    ! grep -qx 'build flags: none' <<<"$version"; then
    echo "check-build-flags: $bin --version has no 'build flags: none' line" >&2
    bad=1
  fi
  if [ "$strings" = 1 ]; then
    if LC_ALL=C grep -aEq "$markers|injected chain actor panic \(test-hooks\)" "$bin"; then
      hits="$(LC_ALL=C grep -aEo "$markers|injected chain actor panic \(test-hooks\)" "$bin" | sort -u | tr '\n' ' ')"
      echo "check-build-flags: $bin contains test-only code: $hits" >&2
      bad=1
    fi
  fi
  if [ "$bad" = 0 ]; then
    echo "check-build-flags: $bin: $(grep -m1 '' <<<"$version"), no test-only code"
  else
    rc=1
  fi
done
exit "$rc"
