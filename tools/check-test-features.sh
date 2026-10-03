#!/usr/bin/env bash
# Proposal (RT-GUARD): fails when a workspace crate has test-only code that the
# build guard (W4-GUARD) does not mark.
#
# For every workspace member:
# - a feature whose name looks test-only (test, fuzz, hook, mock, debug, bench,
#   unsafe, insecure) must be `test-hooks`, and the crate root must export
#   `TEST_HOOKS_MARKER` defined under `#[cfg(feature = "test-hooks")]`;
# - a crate whose sources use `cfg(fuzzing)` must export `FUZZING_MARKER`, or
#   be a binary crate root that refuses the cfg with `compile_error!`;
# - every crate exporting a marker must be named in a `BuildFlags` composition
#   (chain/src/build_flags.rs or node/src/fingerprint.rs).
# Exit status 0 when all hold, 1 otherwise.
set -uo pipefail

members=$(sed -n '/^members *= *\[/,/^\]/p' Cargo.toml | grep -o '"[^"]*"' | tr -d '"')
compose="chain/src/build_flags.rs node/src/fingerprint.rs"
rc=0
for m in $members; do
  toml="$m/Cargo.toml"
  root="$m/src/lib.rs"
  [ -f "$root" ] || root="$m/src/main.rs"
  crate=$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$toml" | head -1 | tr - _)
  feats=$(awk '/^\[features\]/{p=1;next} /^\[/{p=0} p && /^[a-zA-Z0-9_-]+ *=/{sub(/ *=.*/,""); print}' "$toml")
  for f in $feats; do
    if echo "$f" | grep -Eqi 'test|fuzz|hook|mock|debug|bench|unsafe|insecure'; then
      if [ "$f" != "test-hooks" ]; then
        echo "check-test-features: $m: feature '$f' looks test-only; name it test-hooks or extend the guard" >&2
        rc=1
      elif ! grep -A1 -E '#\[cfg\(feature = "test-hooks"\)\]' "$root" | grep -q 'pub const TEST_HOOKS_MARKER'; then
        echo "check-test-features: $m: has test-hooks but $root exports no TEST_HOOKS_MARKER" >&2
        rc=1
      elif ! { [ "$m" = chain ] && grep -q "crate::TEST_HOOKS_MARKER" chain/src/build_flags.rs; } &&
        ! grep -q "${crate}::TEST_HOOKS_MARKER" $compose; then
        echo "check-test-features: $m: TEST_HOOKS_MARKER is in no BuildFlags composition ($compose)" >&2
        rc=1
      fi
    fi
  done
  if grep -rqE 'cfg\((all\(|any\()?[^)]*\bfuzzing\b' "$m/src" 2>/dev/null; then
    if [ -f "$m/src/main.rs" ] && grep -A1 -E '^#\[cfg\(fuzzing\)\]' "$m/src/main.rs" | grep -q '^compile_error!'; then
      :
    elif ! grep -rh -A1 -E '^#\[cfg\(fuzzing\)\]' "$m/src" | grep -q '^pub const FUZZING_MARKER: Option<&str> = Some('; then
      echo "check-test-features: $m: uses cfg(fuzzing) but exports no FUZZING_MARKER" >&2
      rc=1
    fi
  fi
done
[ "$rc" = 0 ] && echo "check-test-features: every test-only feature and cfg(fuzzing) crate is marked"
exit "$rc"
