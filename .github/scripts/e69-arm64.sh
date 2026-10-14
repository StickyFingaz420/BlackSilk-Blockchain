#!/usr/bin/env bash
# Mutation self-test for exemption E69 (docs/reviews/mutation-exemptions.md):
# the two `+` -> `-` mutants in `smallest_pow_witness` (zk/src/config.rs,
# cargo-mutants ids 250:64 and 253:35) are equivalent only where BabyBear's
# packing width is 1 (x86_64 without AVX2/AVX-512). On aarch64 NEON is a
# default target feature and p3-monty-31 0.7.0 packs 4 lanes, so the mutants
# are live there and the zk tests must kill them. This script applies each
# mutant with an exact substitution (it must hit exactly one occurrence, on the
# expected line and column), runs zk/tests/grinding.rs, and REQUIRES
# `the_prover_grinds_the_smallest_valid_nonce` to fail. A mutant that survives,
# does not apply exactly, or does not compile fails the script. The file is
# restored after each mutant and on exit.
#
# Usage (from anywhere in the repository):
#   bash .github/scripts/e69-arm64.sh                   # aarch64 with NEON only
#   bash .github/scripts/e69-arm64.sh --check-patterns  # any host: apply each
#       substitution, show the diff, restore; no build, no tests
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
file=zk/src/config.rs
expect=the_prover_grinds_the_smallest_valid_nonce
mode="${1:-run}"
case "$mode" in run | --check-patterns) ;; *) echo "usage: $0 [--check-patterns]" >&2; exit 2 ;; esac

die() { echo "::error title=E69 arm64 self-test::$*"; exit 1; }

# Mutants: id | line | exact text before | exact text after | column of the
# mutated operator (1-based, cargo-mutants' convention).
mutants=(
  "250:64|250|(start + l as u64).min(order - 1)|(start - l as u64).min(order - 1)|64"
  "253:35|253|let candidate = start + l as u64;|let candidate = start - l as u64;|35"
)

git diff --quiet -- "$file" || die "$file has local changes; refusing to mutate it"
restore() { git checkout -q -- "$file"; }
trap restore EXIT

# Escape a literal string for a sed BRE (pattern) or replacement.
bre() { printf '%s' "$1" | sed -e 's/[]\/$*.^[]/\\&/g'; }
rep() { printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'; }

# Apply one mutant exactly, or fail.
apply() {
  local id="$1" line="$2" from="$3" to="$4" col="$5" n got
  n=$(grep -cF -- "$from" "$file" || true)
  [ "$n" = 1 ] || die "mutant $id: '$from' occurs $n times in $file (expected exactly 1)"
  got=$(grep -nF -- "$from" "$file" | cut -d: -f1)
  [ "$got" = "$line" ] || die "mutant $id: '$from' is on line $got, expected $line"
  sed -i -e "${line}s/$(bre "$from")/$(rep "$to")/" "$file"
  # Exactly one line changed, it is the expected line, and it now holds the
  # mutant with the `-` at the recorded column.
  [ "$(git diff --numstat -- "$file" | cut -f1-2)" = "$(printf '1\t1')" ] ||
    die "mutant $id: the substitution did not change exactly one line"
  [ "$(grep -cF -- "$from" "$file" || true)" = 0 ] || die "mutant $id: the original text is still present"
  local text
  text=$(sed -n "${line}p" "$file")
  case "$text" in *"$to"*) ;; *) die "mutant $id: line $line does not hold '$to'" ;; esac
  [ "${text:$((col - 1)):1}" = "-" ] || die "mutant $id: column $col of line $line is '${text:$((col - 1)):1}', not '-'"
  echo "mutant $id applied: line $line, column $col"
  git --no-pager diff -U0 -- "$file" | sed -n '/^[-+][^-+]/p'
}

if [ "$mode" = --check-patterns ]; then
  for m in "${mutants[@]}"; do
    IFS='|' read -r id line from to col <<<"$m"
    apply "$id" "$line" "$from" "$to" "$col"
    restore
    git diff --quiet -- "$file" || die "mutant $id: $file not restored"
  done
  echo "E69 patterns: both substitutions hit exactly one occurrence at the recorded line and column"
  exit 0
fi

# The exemption is about width-4 packing: refuse to run anywhere else, so a
# pass here always means "on aarch64 with NEON".
cfg=$(rustc --print cfg)
grep -qx 'target_arch="aarch64"' <<<"$cfg" || die "not an aarch64 host (rustc --print cfg)"
grep -qx 'target_feature="neon"' <<<"$cfg" || die "NEON is not enabled (rustc --print cfg)"
echo "host: $(rustc -vV | sed -n 's/^host: //p'), target_feature=\"neon\" on"

tests() { # $1 = log file
  timeout --signal=TERM --kill-after=60s 30m \
    cargo test --locked --release -p blacksilk-zk --test grinding --no-fail-fast 2>&1 | tee "$1"
  return "${PIPESTATUS[0]}"
}
logdir="${RUNNER_TEMP:-$(mktemp -d)}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

# Control: the unmutated tests pass here, so a failure below is the mutant's.
echo "== control (unmutated $file)"
tests "$logdir/e69-control.log" || die "control: zk/tests/grinding.rs fails without a mutant"
grep -qE "^test $expect \.\.\. ok$" "$logdir/e69-control.log" || die "control: $expect did not run and pass"

echo "### E69 on $(uname -m) (packing width 4 expected)" >>"$summary"
fail=0
for m in "${mutants[@]}"; do
  IFS='|' read -r id line from to col <<<"$m"
  echo "== mutant $id: '$from' -> '$to'"
  apply "$id" "$line" "$from" "$to" "$col"
  log="$logdir/e69-$id.log"
  rc=0
  tests "$log" || rc=$?
  restore
  git diff --quiet -- "$file" || die "mutant $id: $file not restored"
  # A mutant that does not build, or whose test binary never ran, is not a kill.
  grep -qE 'Running.*tests/grinding\.rs' "$log" || die "mutant $id: the grinding tests did not run (build failure?)"
  [ "$rc" != 124 ] && [ "$rc" != 137 ] || die "mutant $id: the tests timed out (30 min)"
  failed=$(grep -E '^test .* \.\.\. FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | sort -u | paste -sd ' ' -)
  if [ "$rc" != 0 ] && grep -qE "^test $expect \.\.\. FAILED$" "$log"; then
    echo "E69 mutant $id: CAUGHT by $expect (failed tests: $failed)"
    echo "::notice title=E69 mutant $id caught::by $expect (failed tests: $failed)"
    grep -A3 -E "^---- $expect stdout ----" "$log" | head -4 || true
    echo "- mutant $id (\`$to\`): caught by \`$expect\`; failed: $failed" >>"$summary"
  else
    echo "::error title=E69 mutant $id survived::$expect did not fail (exit $rc; failed tests: ${failed:-none})"
    echo "- mutant $id (\`$to\`): NOT caught by \`$expect\` (exit $rc; failed: ${failed:-none})" >>"$summary"
    fail=1
  fi
done
exit "$fail"
