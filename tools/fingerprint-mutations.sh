#!/usr/bin/env bash
# Fingerprint coverage check (RT-FP3 acceptance; docs/reviews/v3-consensus-
# changes.md#fingerprint-v3, Follow-up (RT-FP3)).
#
# Applies each consensus mutation of the RT-FP3 red-team demonstration, one at
# a time, to a scratch copy of HEAD, builds `blacksilk-node`, and compares its
# `--print-manifest regtest` with the unmutated build's. Every mutation must
# change the rules fingerprint; the changed manifest entries are printed.
#
# Each mutation is a deliberate consensus bug. They are applied only inside
# the scratch copy (never to this tree) and never committed.
#
# Usage: tools/fingerprint-mutations.sh SCRATCH_DIR
#   SCRATCH_DIR  an empty or absent directory for the copy, its target
#                directory and the manifests (several GB; one release build of
#                the node per mutation, minutes each).
# Exit: 0 every mutation changes the rules fingerprint; 1 one does not; 2 a
# usage or build error.
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: $0 SCRATCH_DIR" >&2; exit 2; }
repo="$(git rev-parse --show-toplevel)"
scratch="$1"
mkdir -p "$scratch"
scratch="$(cd "$scratch" && pwd)"
src="$scratch/src"
out="$scratch/out"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/target}"
# The copy has no .git: the build commit is `unknown`, never `-dirty`.
unset BLACKSILK_BUILD_COMMIT

# The mutations: the file, the exact text (one occurrence), its replacement,
# and what it breaks.
FILES=(
  consensus/src/difficulty.rs
  consensus/src/timestamp.rs
  crypto/src/hash.rs
  px/src/tree.rs
  randomx/src/config.rs
  tx/src/types.rs
  tx/src/validate.rs
)
FROMS=(
  'next.clamp(1, u64::MAX as u128) as u64'
  'timestamp <= now.saturating_add(future_time_limit)'
  'pub const TX_HASH: &str = "tx/hash";'
  'let mut e = [ZERO_DIGEST; TREE_DEPTH + 1];'
  'pub(crate) const PROGRAM_ITERATIONS: usize = 2048;'
  '(320 * m).saturating_sub(bp_size) * 4 / 5'
  'if !strictly_increasing(tx.inputs.iter().map(|i| i.key_image)) {'
)
TOS=(
  'next.clamp(2, u64::MAX as u128) as u64'
  'timestamp < now.saturating_add(future_time_limit)'
  'pub const TX_HASH: &str = "tx/hash/rt";'
  'let mut e = [[1, 0, 0, 0, 0, 0, 0, 0]; TREE_DEPTH + 1];'
  'pub(crate) const PROGRAM_ITERATIONS: usize = 1024;'
  '(320 * m).saturating_sub(bp_size) * 1 / 2'
  'if false && !strictly_increasing(tx.inputs.iter().map(|i| i.key_image)) {'
)
WHATS=(
  "the difficulty's lower clamp"
  'the future time limit at its boundary'
  "the transaction id's hash tag"
  'the empty leaf of the PX tree'
  'RandomX program iterations'
  'the Bulletproofs+ weight clawback'
  'the key-image order rule (T4)'
)
# A quoted replacement is literal (bash 5.2 `patsub_replacement` expands an
# unquoted `&`).

rm -rf "$src" "$out"
mkdir -p "$src" "$out"
git -C "$repo" archive --format=tar HEAD | (cd "$src" && tar -x)

build_manifest() {
  (cd "$src" && cargo build --locked --release -q -p blacksilk-node --bin blacksilk-node) ||
    { echo "build failed" >&2; exit 2; }
  "$CARGO_TARGET_DIR/release/blacksilk-node" --print-manifest regtest | tr -d '\r' >"$1"
}

field() { sed -n "s/^$1 = //p" "$2"; }

echo "base: $(git -C "$repo" rev-parse --short HEAD)"
build_manifest "$out/base.txt"
base_rules="$(field rules_fingerprint "$out/base.txt")"
echo "base rules_fingerprint $base_rules"

fail=0
n=0
for i in "${!FILES[@]}"; do
  n=$((i + 1))
  file="${FILES[$i]}" from="${FROMS[$i]}" to="${TOS[$i]}" what="${WHATS[$i]}"
  path="$src/$file"
  cp "$path" "$out/orig"
  content="$(cat "$path")"
  count="$(grep -cF -- "$from" "$path" || true)"
  if [ "$count" != 1 ]; then
    echo "mutation $n ($file): the text occurs $count times; the tree moved, update this script" >&2
    exit 2
  fi
  printf '%s\n' "${content/"$from"/"$to"}" >"$path"
  build_manifest "$out/m$n.txt"
  cp "$out/orig" "$path"
  rules="$(field rules_fingerprint "$out/m$n.txt")"
  changed="$(diff <(grep -v '_encoding = \|_fingerprint = \|^# ' "$out/base.txt") \
    <(grep -v '_encoding = \|_fingerprint = \|^# ' "$out/m$n.txt") | sed -n 's/^> //p' | cut -c1-110 || true)"
  if [ "$rules" = "$base_rules" ]; then
    echo "FAIL  $n $what ($file): rules fingerprint unchanged"
    fail=1
  else
    echo "ok    $n $what ($file): rules $rules"
  fi
  printf '%s\n' "$changed" | sed '/^$/d; s/^/        /'
done
echo "fingerprint-mutations: $n mutations, $([ "$fail" = 0 ] && echo "every one changes the rules fingerprint" || echo FAIL)"
exit "$fail"
