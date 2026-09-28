#!/usr/bin/env bash
# Self-test of doc-lint.sh: one seeded failing fixture per rule, plus the allowed
# uses, in a throw-away repository. Run by the CI job `doc-lint` before the lint.
# Exit: 0 if every rule fires where it must and nowhere else.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q
mkdir -p .github/scripts docs/reviews docs/evidence/x
cp "$here/doc-lint.sh" .github/scripts/

hex64=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
cat > docs/bad.md <<EOF
BlackSilk is production-ready.
The engine was audited by someone.
The proofs are perfectly zero-knowledge.
The protocol is secure.
Seeds have 24 words, the 24-word format.
The parameter set is BS-ZK-2.
Difficulty is LWMA-60.
Blocks hold 4 PX per block.
The kernel id starts 0577e667.
The fingerprint is \`$hex64\`.
See [the spec](missing.md) and [a section](missing-too.md#part).
EOF
cat > docs/good.md <<EOF
BlackSilk is not production-ready and has not been audited.
The report says "audited" about another version.
The former 24-word format was removed; BS-ZK-2 was the earlier set.
The id is pinned by a test, not copied here.
See [the other page](other.md), [a section](other.md#part), [the site](https://example.org) and [a dir](reviews/).
\`\`\`
BlackSilk is production-ready (inside a code fence: ignored).
[fenced](nowhere.md)
\`\`\`
An accepted exception: $hex64 <!-- doc-lint: allow -->
EOF
echo "Other page." > docs/other.md
echo "A review may say BS-ZK-2 and \`$hex64\` and audited." > docs/reviews/r.md
echo "Evidence: $hex64" > docs/evidence/x/README.md
git add -A

set +e
out="$(bash .github/scripts/doc-lint.sh 2>&1)"
status=$?
set -e
printf '%s\n' "$out"

fail=0
expect() { # line rule
  printf '%s\n' "$out" | grep -q "^docs/bad.md:$1: $2:" || { echo "MISSING: docs/bad.md:$1 $2"; fail=1; }
}
expect 1 claims
expect 2 claims
expect 3 claims
expect 4 claims
expect 5 stale
expect 6 stale
expect 7 stale
expect 8 stale
expect 9 stale
expect 10 hex
expect 11 link
[ "$(printf '%s\n' "$out" | grep -c '^docs/bad.md:11: link:')" = 2 ] || { echo "expected two link findings on line 11"; fail=1; }
if printf '%s\n' "$out" | grep -E '^docs/(good|other|reviews|evidence)'; then
  echo "UNEXPECTED findings in the allowed fixtures"
  fail=1
fi
[ "$status" = 1 ] || { echo "expected exit 1, got $status"; fail=1; }

# Without the bad file the tree is clean.
git rm -q --cached docs/bad.md
rm docs/bad.md
bash .github/scripts/doc-lint.sh >/dev/null || { echo "expected a clean run without docs/bad.md"; fail=1; }

[ "$fail" = 0 ] && echo "doc-lint self-test: pass" || { echo "doc-lint self-test: FAIL"; exit 1; }
