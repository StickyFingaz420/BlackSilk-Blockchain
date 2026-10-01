#!/usr/bin/env bash
# CI (W4-GUARD, RT-STATEFUL): the binaries of a plain release build carry no
# test-only code, checked three independent ways; and the checks detect a
# binary that does.
#
# Run after `cargo test --release --workspace` in the same target directory
# (the `test` job). That run leaves a node with dev-dependency features
# unified (the test hooks of chain, tx, px and p2p) in target/release, which
# is the case to catch, so it is the control: tools/check-build-flags.sh
# must refuse it. (Only the node: the job's later `-p blacksilk-wallet` tests
# rewrite the wallet without hooks.) Then the plain build overwrites them, and:
# 1. the normal-edge dependency tree of every shipped package (each alone,
#    and all together as the build unifies them) enables no `test-hooks`
#    feature; the same tree with dev edges must show it (control);
# 2. `--version` of every binary names no marker, and the node's and the
#    genesis tool's print `build flags: none`;
# 3. the binary files contain no marker string and not the chain actor's
#    injected-panic message.
set -euo pipefail

pkgs=(blacksilk-node blacksilk-miner blacksilk-wallet blacksilk-genesis)
dir="${CARGO_TARGET_DIR:-target}/release"
bins=()
for p in "${pkgs[@]}"; do bins+=("$dir/$p"); done
check=tools/check-build-flags.sh

echo "== control: the node left by cargo test"
controls=0
for b in "$dir/blacksilk-node"; do
  [ -x "$b" ] || continue
  controls=$((controls + 1))
  if bash "$check" --strings "$b"; then
    echo "::error title=build guard control::$b, written by cargo test --workspace, was not flagged: the check is broken"
    exit 1
  fi
done
[ "$controls" -gt 0 ] ||
  echo "::warning title=build guard control::no binary left by cargo test in $dir; the control did not run"

echo "== control: the dev-edge tree shows the hooks"
cargo tree --locked -e normal,dev -p blacksilk-node -f '{p} {f}' | grep -q 'test-hooks' || {
  echo "::error title=build guard control::cargo tree with dev edges shows no test-hooks; the tree check is broken"
  exit 1
}

echo "== plain release build"
p_args=()
for p in "${pkgs[@]}"; do p_args+=(-p "$p"); done
cargo build --release --locked "${p_args[@]}"

echo "== 1. dependency trees (normal edges)"
rc=0
for set in "${pkgs[@]}" "${pkgs[*]}"; do
  args=()
  for p in $set; do args+=(-p "$p"); done
  if hits="$(cargo tree --locked -e normal "${args[@]}" -f '{p} {f}' | grep 'test-hooks')"; then
    echo "::error title=test-hooks in a release graph::$set: $hits"
    rc=1
  fi
done

echo "== 2 and 3. --version and binary contents"
bash "$check" --strings "${bins[@]}" || rc=1
exit "$rc"
