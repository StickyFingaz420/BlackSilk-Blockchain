#!/usr/bin/env bash
# Fails when a BlackSilk binary has test-only code compiled in (W4-GUARD).
#
#   tools/check-build-flags.sh [--strings] <binary>...
#   tools/check-build-flags.sh --selftest
#
# `cargo test` unifies dev-dependency features into every binary it writes,
# at the path a plain `cargo build --release` uses: after `cargo test
# --release`, target/release/blacksilk-node has the test hooks of chain, tx
# px and p2p. A cargo-fuzz build adds
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
# The byte scan (--strings) looks for the exact markers the sources export,
# not the marker shape: Rust string literals are not NUL-terminated, so in a
# binary a literal ending in `+fuzzing:` can run into the next one and read
# as `+fuzzing:built` (CI run 119, on Linux). A real marker is still found
# when it runs into its neighbour. The names come from the `Some("+...")`
# exports (tools/check-test-features.sh keeps every marked crate exporting
# one); the fallback list is the set at this commit.
marker_names() {
  local names
  names="$(git -C "$(dirname "$0")/.." grep -hoE 'Some\("\+(test-hooks|fuzzing):[a-z0-9-]+"\)|&\["\+fuzzing:[a-z0-9-]+"\]' -- '*.rs' 2>/dev/null |
    sed -E 's/.*:([a-z0-9-]+)".*/\1/' | sort -u | paste -sd'|' -)"
  printf '%s' "${names:-chain|genesis|p2p|px|tx}"
}
exact_markers="\\+(test-hooks|fuzzing):($(marker_names))"

# fail MESSAGE: the reason on stderr, and as an annotation on GitHub Actions
# (CI run 119 failed this check with no reason in its annotations).
fail() {
  echo "check-build-flags: $1" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ] && [ "${CHECK_BUILD_FLAGS_QUIET:-}" != 1 ]; then
    echo "::error title=build flags::$1"
  fi
}

# check_one STRINGS BINARY: 0 when clean; the reason on stderr otherwise.
check_one() {
  local strings="$1" bin="$2" version name found hits
  if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    fail "$bin: not an executable file"
    return 1
  fi
  if ! version="$("$bin" --version </dev/null 2>&1 | tr -d '\r')"; then
    fail "$bin --version failed: $version"
    return 1
  fi
  name="$(awk 'NR == 1 { print $1; exit }' <<<"$version")"
  local bad=0
  case "$name" in
    blacksilk-*) ;;
    *)
      fail "$bin --version does not name a BlackSilk program (first word: '$name')"
      bad=1
      ;;
  esac
  found="$(grep -Eo "$markers" <<<"$version" | sort -u | tr '\n' ' ')"
  if [ -n "$found" ]; then
    fail "$bin ($name) was built with test-only code: $found"
    bad=1
  fi
  if ! grep -qx 'build flags: none' <<<"$version"; then
    fail "$bin ($name) --version has no 'build flags: none' line"
    bad=1
  fi
  if [ "$strings" = 1 ]; then
    hits="$(LC_ALL=C grep -aEo "$exact_markers|$panic_msg" "$bin" | sort -u | tr '\n' ' ')"
    if [ -n "$hits" ]; then
      fail "$bin ($name) contains test-only code: $hits"
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
    if CHECK_BUILD_FLAGS_QUIET=1 check_one "$2" "$dir/$3" 2>/dev/null >/dev/null; then got=0; else got=1; fi
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
  # A clean binary whose bare marker prefixes run into the next literal (a
  # checker's own `+fuzzing:` string; CI run 119), and a real marker that
  # runs into its neighbour (RT-GUARD saw `+test-hooks:chainbuild`).
  fake adjacent "blacksilk-labnet 0.1.0${nl}build flags: none" "+fuzzing:built with test-only code, +test-hooks:recorded"
  fake run-together "blacksilk-node 0.1.0${nl}build flags: none" "+test-hooks:chainbuild flags"
  expect 0 1 blacksilk-node
  expect 0 1 blacksilk-miner
  expect 1 0 renamed.exe
  expect 1 0 hooked-miner
  expect 1 0 old-node
  expect 1 0 not-blacksilk
  expect 0 0 liar
  expect 1 1 liar
  expect 0 1 adjacent
  expect 1 1 run-together
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
