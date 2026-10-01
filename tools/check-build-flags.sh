#!/usr/bin/env bash
# Fails when a BlackSilk binary has test-only code compiled in (W4-GUARD).
#
#   tools/check-build-flags.sh [--strings] <binary>...
#   tools/check-build-flags.sh --selftest
#
# `cargo test` unifies dev-dependency features into every binary it writes,
# at the path a plain `cargo build --release` uses: after `cargo test
# --release`, target/release/blacksilk-node has the test hooks of chain, tx
# and px (and p2p's, once its hooks exist). A cargo-fuzz build adds
# `cfg(fuzzing)` code. Such a binary is for this repository's regtest tests
# only, never for evidence, genesis or a shared network.
#
# Per binary, judged from what it prints, never from its file name (a
# renamed binary is judged the same):
# - `--version` must succeed and its first word must be a BlackSilk program
#   name (`blacksilk-*`);
# - it must print the line `build flags: none` (a build older than the guard
#   cannot show its test code, so it is refused);
# - it must name no marker (`+test-hooks:<crate>`, `+fuzzing:<crate>`; each
#   is compiled in only with its code);
# - with --strings, the file itself must contain neither a marker nor the
#   chain actor's injected-panic message (an independent check of the bytes,
#   in case `--version` lied or the binary was edited).
# --selftest checks these rules on fake executables (a renamed binary among
# them) and needs no build.
# Exit status: 0 when every binary is clean, 1 otherwise, 2 on usage errors.
set -uo pipefail

markers='\+(test-hooks|fuzzing):[a-z0-9-]+'
panic_msg='injected chain actor panic \(test-hooks\)'

# check_one STRINGS BINARY: 0 when clean; the reason on stderr otherwise.
check_one() {
  local strings="$1" bin="$2" version name found hits
  if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    echo "check-build-flags: $bin: not an executable file" >&2
    return 1
  fi
  if ! version="$("$bin" --version </dev/null 2>&1 | tr -d '\r')"; then
    echo "check-build-flags: $bin --version failed: $version" >&2
    return 1
  fi
  name="$(awk 'NR == 1 { print $1; exit }' <<<"$version")"
  local bad=0
  case "$name" in
    blacksilk-*) ;;
    *)
      echo "check-build-flags: $bin --version does not name a BlackSilk program (first word: '$name')" >&2
      bad=1
      ;;
  esac
  found="$(grep -Eo "$markers" <<<"$version" | sort -u | tr '\n' ' ')"
  if [ -n "$found" ]; then
    echo "check-build-flags: $bin ($name) was built with test-only code: $found" >&2
    bad=1
  fi
  if ! grep -qx 'build flags: none' <<<"$version"; then
    echo "check-build-flags: $bin ($name) --version has no 'build flags: none' line" >&2
    bad=1
  fi
  if [ "$strings" = 1 ]; then
    hits="$(LC_ALL=C grep -aEo "$markers|$panic_msg" "$bin" | sort -u | tr '\n' ' ')"
    if [ -n "$hits" ]; then
      echo "check-build-flags: $bin ($name) contains test-only code: $hits" >&2
      bad=1
    fi
  fi
  [ "$bad" = 0 ] || return 1
  echo "check-build-flags: $bin: $name, $(head -n 1 <<<"$version" | cut -d' ' -f2-), no test-only code"
}

selftest() {
  local dir rc=0
  dir="$(mktemp -d)"
  # fake NAME VERSION-TEXT [EXTRA-BYTES]: an executable printing the text.
  fake() {
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n# %s\n' "$2" "${3:-}" >"$dir/$1"
    chmod +x "$dir/$1"
  }
  expect() { # WANT(0|1) STRINGS NAME
    if check_one "$2" "$dir/$3" 2>/dev/null >/dev/null; then got=0; else got=1; fi
    if [ "$got" != "$1" ]; then
      echo "check-build-flags selftest: $3 (strings=$2): want $1, got $got" >&2
      rc=1
    fi
  }
  nl=$'\n'
  fake blacksilk-node "blacksilk-node 0.1.0${nl}commit abc${nl}build flags: none"
  fake blacksilk-miner "blacksilk-miner 0.1.0 (commit abc)${nl}build flags: none"
  # The hooked node renamed: the name does not hide it.
  fake renamed.exe "blacksilk-node 0.1.0${nl}commit abc${nl}build flags: +test-hooks:chain"
  fake hooked-miner "blacksilk-miner 0.1.0 (commit abc)${nl}build flags: +test-hooks:tx"
  # A miner older than the guard (no line) under the node's name.
  fake old-node "blacksilk-miner 0.1.0 (commit abc)"
  fake not-blacksilk "something 1.0${nl}build flags: none"
  # A clean --version, but the marker and the panic message in the bytes.
  fake liar "blacksilk-node 0.1.0${nl}build flags: none" "+test-hooks:chain injected chain actor panic (test-hooks)"
  expect 0 1 blacksilk-node
  expect 0 1 blacksilk-miner
  expect 1 0 renamed.exe
  expect 1 0 hooked-miner
  expect 1 0 old-node
  expect 1 0 not-blacksilk
  expect 0 0 liar
  expect 1 1 liar
  expect 1 0 missing
  rm -rf "$dir"
  [ "$rc" = 0 ] && echo "check-build-flags selftest: pass"
  return "$rc"
}

strings=0
case "${1:-}" in
  --selftest) selftest; exit $? ;;
  --strings) strings=1; shift ;;
esac
[ $# -gt 0 ] || { echo "usage: $0 [--strings] <binary>... | --selftest" >&2; exit 2; }

rc=0
for bin in "$@"; do
  check_one "$strings" "$bin" || rc=1
done
exit "$rc"
