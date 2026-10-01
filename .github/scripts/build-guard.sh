#!/usr/bin/env bash
# CI (W4-GUARD, RT-STATEFUL, RT-GUARD): the binaries of a plain release build
# carry no test-only code, checked three independent ways; and the checks are
# shown to detect a binary that does.
#
# Controls (each must be flagged, or the check is broken):
# - self-contained: tools/check-build-flags.sh --selftest, on fake
#   executables (a marker in `--version`, a renamed binary, a binary older
#   than the guard, marker bytes behind a clean `--version`); independent of
#   step order;
# - the real case: run after `cargo test --release --workspace` in the same
#   target directory (the `test` job), target/release/blacksilk-node is a
#   node with dev-dependency features unified (the test hooks of chain, tx
#   and px). Fatal when it is missing on GitHub Actions (GITHUB_ACTIONS=true:
#   the step order is fixed there); a warning elsewhere;
# - the dependency tree with dev edges shows `test-hooks`.
# Then a plain release build of the shipped binaries, and:
# 1. the normal-edge dependency tree of each package, and of all of them
#    together as the build unifies them, enables no test-like feature
#    (`test-hooks`, or a third-party `test-util`, `test-utils` or `mock`).
#    Dev-only features (tokio's `test-util` in a crate's dev-dependencies)
#    are not in a plain build and do not appear with `-e normal`; one that
#    does appear is in the release binary, so any match fails;
# 2. `--version` of every binary identifies a BlackSilk program, prints
#    `build flags: none` and names no marker;
# 3. the binary files contain no marker string and not the chain actor's
#    injected-panic message.
set -euo pipefail

pkgs=(blacksilk-node blacksilk-miner blacksilk-wallet blacksilk-genesis
  blacksilk-supply-audit blacksilk-labnet)
dir="${CARGO_TARGET_DIR:-target}/release"
bins=(blacksilk-node blacksilk-miner blacksilk-wallet blacksilk-genesis
  blacksilk-supply-audit blacksilk-labnet blacksilk-labnet-report blacksilk-rx-verify)
check=tools/check-build-flags.sh
features='test-hooks|test-util|test-utils|mock'
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== control: the checks on fake executables"
bash "$check" --selftest

echo "== control: the node left by cargo test"
node="$dir/blacksilk-node"
if [ -x "$node" ]; then
  if bash "$check" --strings "$node"; then
    echo "::error title=build guard control::$node, written by cargo test --workspace, was not flagged: the check is broken"
    exit 1
  fi
elif [ "${GITHUB_ACTIONS:-}" = true ]; then
  echo "::error title=build guard control::no node left by cargo test in $dir; the control did not run"
  exit 1
else
  echo "::warning title=build guard control::no node left by cargo test in $dir; the control did not run"
fi

echo "== control: the dev-edge tree shows the hooks"
cargo tree --locked -e normal,dev -p blacksilk-node -f '{p} {f}' >"$tmp/dev-tree.txt"
grep -Eq "$features" "$tmp/dev-tree.txt" || {
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
  # Into a file first, under set -e: a cargo failure fails the step instead
  # of looking like a clean tree.
  cargo tree --locked -e normal "${args[@]}" -f '{p} {f}' >"$tmp/tree.txt"
  [ -s "$tmp/tree.txt" ] || { echo "::error title=build guard::empty cargo tree for $set"; exit 1; }
  if hits="$(grep -E "$features" "$tmp/tree.txt")"; then
    echo "::error title=test-only feature in a release graph::$set: $hits"
    rc=1
  fi
done

echo "== 2 and 3. --version and binary contents"
paths=()
for b in "${bins[@]}"; do paths+=("$dir/$b"); done
bash "$check" --strings "${paths[@]}" || rc=1
exit "$rc"
