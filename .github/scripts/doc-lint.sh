#!/usr/bin/env bash
# Documentation lint (dossier 47 W47-8, decisions "Agent 47"; CI job `doc-lint`).
#
# Checks every tracked Markdown file except third_party/ (upstream code, not
# documentation of this tree) and the issue templates:
#
#   claims  forbidden claims: "production-ready", "audited", "perfectly
#           zero-knowledge", "mathematically proven", and "secure" as a blanket
#           claim ("BlackSilk is secure", "fully secure", ...). BlackSilk's own
#           rule: never claim it is secure, audited, production-ready or
#           perfectly ZK (docs/STATUS.md).
#   stale   retired identifiers: "24-word" (seed format v1 has 27 words),
#           "BS-ZK-2" (the parameter set is BS-ZK-4), "LWMA-60" (N = 75),
#           "4 PX per block", the pre-rebuild kernel and vault ids (prefixes
#           0577e667 and 666f7aab), "the v2 identity is approved".
#   link    relative Markdown links to files or directories that are not tracked
#           (or new and not ignored, for a local run before `git add`).
#   hex     64-hex-digit values (fingerprints, ids, hashes) copied into docs:
#           they go stale; reference the pinning test, file or evidence instead.
#           Allowed only under docs/evidence/ and docs/reviews/.
#
# Allowed uses:
# - claims: a line that negates the phrase ("not audited", "never
#   production-ready") or quotes it ("...", `...`: cited, not made);
# - stale: a line that negates it or reads as history ("was BS-ZK-2", "the
#   former 24-word format", "previous ids");
# - history files (HISTORY below) are exempt from claims, stale and hex; their
#   links are still checked;
# - any rule: `<!-- doc-lint: allow -->` on the line, for a reviewed exception.
# - TEMP_EXCLUDE below: files owned by other workstreams that still fail a
#   rule, listed for the coordinator to clear. Every entry is temporary.
#
# Usage: bash .github/scripts/doc-lint.sh   (from anywhere in the repository)
# Exit: 0 clean, 1 findings (printed as file:line: rule: text).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

# History: records of past reviews, evidence and superseded designs. They keep
# what was true when written; STATUS.md and the specs say what is true now.
HISTORY='^(AUDIT\.md|Claude\.md|docs/reviews/|docs/evidence/|docs/research/wasm-contracts\.md|docs/testnet-(v2-validation|reset-plan|launch-checklist|roadmap)\.md)'

# Temporary exclusions "rule path" (W2-29/47, 2026-09-28). Files edited by other
# workstreams at the time the lint landed; the coordinator clears each entry
# once its owner fixes the finding (the findings are listed in the W2-29/47
# report). Do not add entries without the coordinator. DOC_LINT_NO_EXCLUDE=1
# ignores the list, to show what is left.
TEMP_EXCLUDE=()

NEG="(^|[^a-z])(not|never|no|nor|none|nothing|neither|without|cannot|unaudited|non-audit|refused|refuses|rejected|rejects)([^a-z]|\$)|n't([^a-z]|\$)"
HIST='(^|[^a-z])(was|were|former|formerly|previous|previously|earlier|old|retired|superseded|replaced|removed|history|historical|pre-rebuild|no longer|until|before|instead of)([^a-z]|$)'

findings=0
report() { # file line rule text
  printf '%s:%s: %s: %s\n' "$1" "$2" "$3" "$(printf '%s' "$4" | cut -c1-200)"
  findings=$((findings + 1))
}

excluded() { # rule file
  local e
  [ -z "${DOC_LINT_NO_EXCLUDE:-}" ] || return 1
  for e in "${TEMP_EXCLUDE[@]}"; do
    [ "$e" = "$1 $2" ] && return 0
  done
  return 1
}

# Lines of a file outside ``` fences, as "lineno<TAB>text".
unfenced() {
  tr -d '\r' < "$1" | awk '/^[[:space:]]*(```|~~~)/ { f = !f; next } !f { printf "%d\t%s\n", NR, $0 }'
}

# Tracked and new (untracked, not ignored) files, so a local run sees new docs.
list_files() { git ls-files --cached --others --exclude-standard "$@"; }

# Issue templates hold placeholders such as [Link](url), not documentation.
mapfile -t FILES < <(list_files '*.md' | grep -Ev '^(third_party|\.github/ISSUE_TEMPLATE)/' | sort -u)

# Tracked files and their directories, for the link check.
declare -A TRACKED=()
while IFS= read -r f; do
  TRACKED["$f"]=1
  d="$f"
  while [ "${d%/*}" != "$d" ]; do
    d="${d%/*}"
    TRACKED["$d"]=1
  done
done < <(list_files)

# Normalizes a/b/../c/./d to a/c/d; prints nothing if it leaves the repository.
normalize() {
  local IFS=/ part out=()
  for part in $1; do
    case "$part" in
      "" | .) ;;
      ..)
        [ "${#out[@]}" -gt 0 ] || return 0
        unset 'out[${#out[@]}-1]'
        ;;
      *) out+=("$part") ;;
    esac
  done
  printf '%s' "${out[*]}"
}

claim_re='production[- ]ready|audited|perfectly zero[- ]knowledge|perfect zero[- ]knowledge|mathematically proven|(blacksilk|the (system|project|network|protocol|chain|node|wallet|software)) (is|are) (now |fully |completely |totally )?secure([^a-z]|$)|(fully|completely|totally|provably|perfectly|guaranteed) secure'
stale_re='24-word|BS-ZK-2|LWMA-60|4 PX per block|0577e667|666f7aab|the v2 identity is approved'

for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  hist=0
  [[ "$f" =~ $HISTORY ]] && hist=1
  body="$(unfenced "$f")"

  if [ "$hist" = 0 ]; then
    for rule in claims stale; do
      excluded "$rule" "$f" && continue
      if [ "$rule" = claims ]; then re="$claim_re"; else re="$stale_re"; fi
      while IFS=$'\t' read -r n text; do
        [ -n "$n" ] || continue
        low="$(printf '%s' "$text" | tr 'A-Z' 'a-z')"
        [[ "$low" == *"doc-lint: allow"* ]] && continue
        [[ "$low" =~ $NEG ]] && continue
        # History wording excuses a retired identifier, never a claim ("was
        # audited" is still a claim).
        [ "$rule" = stale ] && [[ "$low" =~ $HIST ]] && continue
        # A claim quoted ("...", `...`): cited, not made. Identifiers are
        # always in backticks, so this does not apply to the stale rule.
        if [ "$rule" = claims ] && printf '%s' "$low" | grep -qiE "[\"\`“][^\"\`”]*($re)[^\"\`”]*[\"\`”]"; then continue; fi
        report "$f" "$n" "$rule" "$text"
      done < <(printf '%s\n' "$body" | grep -iE "^[0-9]+	.*($re)")
    done

    if ! excluded hex "$f"; then
      while IFS=$'\t' read -r n text; do
        [ -n "$n" ] || continue
        [[ "$text" == *"doc-lint: allow"* ]] && continue
        report "$f" "$n" hex "$text"
      done < <(printf '%s\n' "$body" | grep -E "^[0-9]+	.*(^|[^0-9a-fA-F])[0-9a-f]{64}([^0-9a-fA-F]|$)")
    fi
  fi

  excluded link "$f" && continue
  dir="$(dirname "$f")"
  [ "$dir" = . ] && dir=""
  while IFS=$'\t' read -r n target; do
    [ -n "$n" ] || continue
    t="${target%%#*}"
    t="${t#<}"
    t="${t%>}"
    t="${t//%20/ }"
    [ -n "$t" ] || continue
    [[ "$t" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]] && continue # http:, mailto:, ...
    if [ "${t:0:1}" = / ]; then
      p="$(normalize "$t")"
    else
      p="$(normalize "${dir:+$dir/}$t")"
    fi
    if [ -z "$p" ] || [ -z "${TRACKED[$p]:-}" ]; then
      report "$f" "$n" link "($target) does not resolve to a tracked file"
    fi
  done < <(printf '%s\n' "$body" | awk -F'\t' '{
      s = $0; sub(/^[0-9]+\t/, "", s)
      while (match(s, /\]\([^)[:space:]]+([[:space:]]+"[^"]*")?\)/)) {
        l = substr(s, RSTART + 2, RLENGTH - 3)
        sub(/[[:space:]].*$/, "", l)
        print $1 "\t" l
        s = substr(s, RSTART + RLENGTH)
      }
    }')
done

if [ "$findings" -gt 0 ]; then
  echo "doc-lint: $findings finding(s) in ${#FILES[@]} files (rules and allowed uses: .github/scripts/doc-lint.sh)"
  exit 1
fi
echo "doc-lint: ${#FILES[@]} files clean"
