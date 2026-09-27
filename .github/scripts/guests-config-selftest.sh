#!/usr/bin/env bash
# Self-test of zkvm/guests/build.sh's cargo-config refusal (CI-6, W5): copies
# build.sh and the canonical .cargo/config.toml into a temporary tree, plants
# one fake cargo config at a time (an ancestor directory or $CARGO_HOME), and
# checks that guest_check_cargo_config refuses exactly the overrides it must.
# Usage (repository root): bash .github/scripts/guests-config-selftest.sh
set -uo pipefail
root="$(pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
G="$T/a/b/zkvm/guests"
mkdir -p "$G/.cargo" "$T/home"
cp "$root/zkvm/guests/build.sh" "$G/"
cp "$root/zkvm/guests/.cargo/config.toml" "$G/.cargo/"

failures=0
# expect <pass|refuse> <label> [<config file> <contents>]
expect() {
  local want="$1" label="$2" file="${3:-}" status got
  rm -rf "$T/a/.cargo" "$T/a/b/.cargo" "$T/a/b/zkvm/.cargo" "$G/.cargo/config" "$T/home"
  mkdir -p "$T/home"
  if [ -n "$file" ]; then
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$4" > "$file"
  fi
  (CARGO_HOME="$T/home" && source "$G/build.sh" && guest_check_cargo_config) >"$T/out" 2>&1
  status=$?
  if [ "$status" = 0 ]; then got=pass; else got=refuse; fi
  if [ "$got" = "$want" ]; then
    echo "ok   $label: $got"
  else
    echo "FAIL $label: expected $want, got $got"
    sed 's/^/     /' "$T/out"
    failures=$((failures + 1))
  fi
}

expect pass "the canonical config only"
expect pass "CARGO_HOME: rustflags, jobs, net" "$T/home/config.toml" \
  $'[build]\nrustflags = ["-C", "target-cpu=native"]\njobs = 4\n[net]\ngit-fetch-with-cli = true'
expect pass "ancestor: a host target's linker" "$T/a/.cargo/config.toml" \
  $'[target.x86_64-unknown-linux-gnu]\nlinker = "clang"'
expect refuse "ancestor: [profile.release]" "$T/a/.cargo/config.toml" \
  $'[profile.release]\nopt-level = 3'
expect refuse "ancestor legacy file: dotted profile key" "$T/a/b/.cargo/config" \
  'profile.release.lto = false'
expect refuse "CARGO_HOME: build.rustc-wrapper" "$T/home/config.toml" \
  $'[build]\nrustc-wrapper = "sccache"'
expect refuse "CARGO_HOME legacy file: build.rustc" "$T/home/config" \
  'build.rustc = "/opt/rustc"'
expect refuse "parent: [target.riscv32i-unknown-none-elf] linker" "$T/a/b/zkvm/.cargo/config.toml" \
  $'[target.riscv32i-unknown-none-elf]\nlinker = "ld.lld"'
expect refuse "ancestor: [target.'cfg(...)'] table" "$T/a/.cargo/config.toml" \
  $'[target.\'cfg(target_os = "none")\']\nrunner = "x"'
expect refuse "ancestor: [patch.crates-io]" "$T/a/.cargo/config.toml" \
  $'[patch.crates-io]\nfoo = { path = "x" }'
expect refuse "ancestor: path override" "$T/a/.cargo/config.toml" \
  'paths = ["../px-core"]'
expect refuse "legacy config beside the canonical one" "$G/.cargo/config" \
  $'[profile.release]\nopt-level = 1'

[ "$failures" = 0 ] || { echo "::error title=guests config self-test::$failures case(s) failed"; exit 1; }
echo "guests config self-test: all cases behave as expected"
