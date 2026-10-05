#!/usr/bin/env bash
# Hazardous-material APIs stay where they were reviewed (decisions "Agent 44":
# "ml-kem in p2p: approved, with hazmat blocked"; CI job `deny`).
#
# cargo-deny cannot express this. Its feature bans act on the unified feature
# set of the whole graph, and px needs ml-kem's `hazmat`. Worse, in ml-kem
# 0.3.2 `hazmat` gates nothing: it only un-hides the documentation of
# `EncapsulationKey::encapsulate_deterministic`, which is public either way. So
# the rule is checked where it matters, per crate:
#
#   manifests  the `hazmat` feature of ml-kem is requested only by
#              px/Cargo.toml, and aes's `hazmat` only by randomx/Cargo.toml;
#   sources    the deterministic ML-KEM encapsulation (caller-chosen coins,
#              FIPS 203 section 6.2's internal ML-KEM.Encaps_internal) is
#              called only in px/src/ (record delivery, docs/px.md section 6),
#              and the single-round AES functions only in randomx/src/.
#
# A new use needs its own review and an entry below, in the same commit.
#
# Usage: hazmat-policy.sh   (from anywhere in the repository)
# Exit: 0 pass, 1 a use outside the reviewed places.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

# third_party/ is upstream Plonky3.
SKIP='^third_party/'

bad=0
fail() { # title, message
  echo "::error title=$1::$2"
  bad=1
}

# "crate feature allowed-manifest": the only manifest that may request it.
manifest_rules=(
  "ml-kem hazmat px/Cargo.toml"
  "aes hazmat randomx/Cargo.toml"
)
mapfile -t MANIFESTS < <(git ls-files '*Cargo.toml' | grep -Ev "$SKIP")

# Prints "file:line" for every place a manifest enables feature $2 of crate $1:
# an inline dependency (`name = { ..., features = [..."f"...] }`, possibly
# renamed with `package = "name"`), a dependency table
# (`[dependencies.name]` ... `features = [...]`), or a feature forwarded from
# a [features] table ("name/f", "name?/f").
enables() {
  local crate="$1" feat="$2" f
  for f in "${MANIFESTS[@]}"; do
    tr -d '\r' < "$f" | awk -v crate="$crate" -v feat="$feat" -v file="$f" '
      function has_feat(s) { return s ~ ("features[[:space:]]*=[[:space:]]*\\[[^]]*\"" feat "\"") }
      /^[[:space:]]*\[/ {
        table = $0
        intable = (table ~ ("dependencies\\." crate "\\][[:space:]]*$"))
        next
      }
      intable && has_feat($0) { print file ":" NR; next }
      # Inline dependency, by its key or by `package = "crate"`.
      ($0 ~ ("^[[:space:]]*\"?" crate "\"?[[:space:]]*=[[:space:]]*\\{") ||
       $0 ~ ("package[[:space:]]*=[[:space:]]*\"" crate "\"")) && has_feat($0) { print file ":" NR; next }
      index($0, "\"" crate "/" feat "\"") || index($0, "\"" crate "?/" feat "\"") { print file ":" NR }
    '
  done
}

for rule in "${manifest_rules[@]}"; do
  read -r crate feat allowed <<< "$rule"
  n=0
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    n=$((n + 1))
    if [ "${hit%%:*}" = "$allowed" ]; then
      echo "ok   $hit enables $crate/$feat (reviewed)"
    else
      fail "hazmat feature outside its reviewed crate" "$hit enables $crate/$feat; only $allowed may (decisions Agent 44; .github/scripts/hazmat-policy.sh)"
    fi
  done < <(enables "$crate" "$feat")
  [ "$n" -gt 0 ] || echo "note $crate/$feat is requested nowhere"
done

# "pattern allowed-directory reason": the only sources that may call it.
source_rules=(
  "encapsulate_deterministic|px/src/|ML-KEM deterministic encapsulation (hazmat)"
  "aes::hazmat|randomx/src/|single-round AES (hazmat)"
  "cipher_round|randomx/src/|single-round AES (hazmat)"
)
for rule in "${source_rules[@]}"; do
  IFS='|' read -r pat allowed what <<< "$rule"
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    if [[ "$file" == "$allowed"* ]]; then
      echo "ok   $hit: $what (reviewed)"
    else
      fail "hazmat API outside its reviewed crate" "$hit calls $what ($pat); only $allowed may (decisions Agent 44; .github/scripts/hazmat-policy.sh)"
    fi
  done < <(git grep -n -I -F "$pat" -- '*.rs' ':!third_party' | cut -d: -f1,2)
done

if [ "$bad" = 0 ]; then
  echo "hazmat-policy: pass"
else
  echo "hazmat-policy: FAIL"
fi
exit "$bad"
