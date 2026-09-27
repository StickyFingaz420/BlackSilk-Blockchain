#!/usr/bin/env bash
# Consensus-path trailer gate (F48-3, decisions "Agent 48").
#
# Every commit that changes a consensus path must say so in a git trailer, so
# no consensus change can land looking like a routine edit:
#
#   Consensus-Change: docs/reviews/v3-consensus-changes.md §<section>
#   Consensus-Change: none: <why this edit does not change consensus>
#
# The value must name a consensus-changes record (…consensus-changes.md) or
# start with "none:" and a reason (tests, comments). The trailer goes in the
# last paragraph of the message, next to Co-Authored-By; git's trailer rules
# apply (`git interpret-trailers --parse` shows what counts).
#
# Merge commits are checked on what the merge itself changed (the dense
# combined diff: conflict resolutions and edits in the merge); the commits
# they bring in are checked one by one.
#
# Usage: consensus-gate.sh [BASE [HEAD]]   (range rules: gate-range.sh)
# Exit: 0 pass, 1 a commit lacks the trailer, 2 usage or clone error.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gate-range.sh
source "$here/gate-range.sh"

# The consensus paths. Changing this list is a reviewed change of the gate.
is_consensus_path() {
  case "$1" in
    consensus/* | px-core/* | zk/* | zkvm/src/air/*) return 0 ;;
    tx/src/validate.rs | tx/src/px.rs | tx/src/params.rs) return 0 ;;
    zkvm/src/prove.rs | node/src/fingerprint.rs | px/src/fingerprint.rs) return 0 ;;
    chain/src/block.rs | chain/src/emission.rs) return 0 ;;
    px/*.elf | px/*.id) return 0 ;;
  esac
  return 1
}

# The paths a commit changes: against its parent (both sides of a rename), or
# for a merge the paths its dense combined diff shows.
changed_paths() {
  local c="$1" parents
  parents="$(git rev-list --parents -n 1 "$c" | wc -w)"
  if [ "$parents" -gt 2 ]; then
    git -c core.quotepath=false diff-tree --cc -p --no-commit-id "$c" | sed -n 's/^diff --cc //p'
  else
    git -c core.quotepath=false diff-tree -r --root --no-renames --name-only --no-commit-id "$c"
  fi
}

valid_trailer() {
  local v
  while IFS= read -r v; do
    v="${v%$'\r'}"
    case "$v" in
      *consensus-changes.md*) return 0 ;;
      none:*[![:space:]]*) return 0 ;;
    esac
  done
  return 1
}

main() {
  [ "$#" -le 2 ] || gate_die "usage: consensus-gate.sh [BASE [HEAD]]"
  local commits c hits bad=0 n=0 flagged=0
  commits="$(gate_commits "${1:-}" "${2:-HEAD}")"
  for c in $commits; do
    n=$((n + 1))
    hits=""
    local p
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      if is_consensus_path "$p"; then hits+="${hits:+, }$p"; fi
    done < <(changed_paths "$c")
    [ -n "$hits" ] || continue
    flagged=$((flagged + 1))
    local trailers subject
    trailers="$(git log -1 --format='%(trailers:key=Consensus-Change,valueonly=true,unfold=true)' "$c")"
    subject="$(git log -1 --format='%h %s' "$c")"
    if printf '%s\n' "$trailers" | valid_trailer; then
      echo "ok   $subject"
      printf '%s\n' "$trailers" | sed '/^[[:space:]]*$/d; s/^/     Consensus-Change: /'
    else
      bad=1
      gate_annotate "consensus path without a Consensus-Change trailer: $subject" \
        "Touches: $hits
Add a trailer 'Consensus-Change: docs/reviews/v3-consensus-changes.md <section>' or 'Consensus-Change: none: <reason>' (.github/scripts/consensus-gate.sh)."
    fi
  done
  echo "consensus-gate: $n commits checked, $flagged touch consensus paths, $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

main "$@"
