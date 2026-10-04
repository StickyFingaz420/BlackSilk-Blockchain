#!/usr/bin/env bash
# Consensus-path trailer gate (F48-3, decisions "Agent 48").
#
# Every commit that changes a consensus path must say so in a git trailer, so
# no consensus change can land looking like a routine edit:
#
#   Consensus-Change: docs/reviews/v3-consensus-changes.md#<anchor>
#   Consensus-Change: docs/reviews/v3-consensus-changes.md §<N>
#   Consensus-Change: none: <why this edit does not change consensus>
#
# The value must name a section of the consensus-changes record that exists
# at that commit, exactly (and, once the record has them, a section with its
# `Revision:` line), or start with "none:" and a reason (tests, comments).
# The trailer goes in the
# last paragraph of the message, next to Co-Authored-By; git's trailer rules
# apply (`git interpret-trailers --parse` shows what counts).
#
# Merge commits are checked on what the merge itself changed (the dense
# combined diff: conflict resolutions and edits in the merge); the commits
# they bring in are checked one by one.
#
# Usage: consensus-gate.sh [BASE [HEAD]]   (range rules: gate-range.sh)
#        consensus-gate.sh --selftest       (the record-citation rules)
# Exit: 0 pass, 1 a commit lacks the trailer, 2 usage or clone error.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gate-range.sh
source "$here/gate-range.sh"

# The consensus paths. Changing this list is a reviewed change of the gate.
# RTFP3-10 added the v1 cryptography, the transaction types, codec and
# state, the chain manager, the PX prover, state and tree, RandomX, the
# patched Plonky3 crates and the fingerprint fixture; commits before it that
# touch them without a trailer are in the waiver file. RT-TPGATE added the
# commit gates themselves, their waiver file and every .cargo/ configuration
# (cargo honours [patch], [paths] and [source] there); the commits before it
# that touch them are in the waiver file too. RT-TPGATE2 added the CI
# workflows, the release and guest build scripts, the Dockerfile, the
# lockfile waiver file and tools/tpgate (waived likewise, and only within the
# waiver horizon, gate-range.sh). RT-TPGATE3 added every .gitattributes (it
# decides how git and GitHub show third_party/ changes) and the cargo
# configuration pins.
is_consensus_path() {
  case "$1" in
    consensus/* | px-core/* | zk/* | zkvm/src/air/*) return 0 ;;
    tx/src/validate.rs | tx/src/px.rs | tx/src/params.rs) return 0 ;;
    tx/src/types.rs | tx/src/codec.rs | tx/src/state.rs) return 0 ;;
    zkvm/src/prove.rs | node/src/fingerprint.rs | px/src/fingerprint.rs) return 0 ;;
    node/src/fingerprint_fixture.txt) return 0 ;;
    chain/src/block.rs | chain/src/emission.rs | chain/src/manager/*) return 0 ;;
    px/*.elf | px/*.id) return 0 ;;
    px/src/prove.rs | px/src/state.rs | px/src/tree.rs) return 0 ;;
    crypto/* | randomx/* | third_party/*) return 0 ;;
    .github/scripts/consensus-gate.sh | .github/scripts/gate-range.sh) return 0 ;;
    .github/scripts/lockfile-gate.sh | .github/scripts/third-party-gate.sh) return 0 ;;
    .github/consensus-gate-waivers.txt | .github/lockfile-gate-waivers.txt) return 0 ;;
    .cargo/* | */.cargo/* | tools/tpgate/*) return 0 ;;
    .gitattributes | */.gitattributes | .github/cargo-config.sha256) return 0 ;;
    .github/workflows/* | tools/release-build.sh | deploy/docker/Dockerfile) return 0 ;;
    zkvm/guests/build.sh | zkvm/guests/reproduce.sh | .github/scripts/guests-reproduce.sh) return 0 ;;
  esac
  return 1
}

# The consensus-changes record. A trailer that cites it must name a section
# that exists in it at that commit, exactly: `#<key>` (an `<a id>` anchor, a
# heading's GitHub anchor, or a heading's one-word key before its `:`, as
# `## daa-lwma75-warm: …`) or ` §N` (RTFP3-8). Once the record carries
# `Revision:` lines, the cited section must have one (the record template):
# that line says whether the change is a rule revision, which the node's
# `revision_lines_are_the_revision_list` test ties to `REVISIONS`.
RECORD=docs/reviews/v3-consensus-changes.md

# record_keys: the record on stdin; prints `<section> key <key>` for every
# key a section can be cited by, and `<section> revision` for each
# `Revision:` line (section 0 is the text before the first `## `).
record_keys() {
  LC_ALL=C awk '
    function slug(s) { s = tolower(s); gsub(/[^a-z0-9 _-]/, "", s); gsub(/ /, "-", s); return s }
    { sub(/\r$/, "") }
    /^<a id="/ { a = $0; sub(/^<a id="/, "", a); sub(/".*/, "", a); pending = a; next }
    /^## / {
      sec++; h = substr($0, 4)
      if (pending != "") print sec, "key", pending
      pending = ""
      print sec, "key", slug(h)
      k = h; sub(/:.*/, "", k)
      if (k != h && k !~ / /) print sec, "key", k
      split(h, w, " ")
      if (w[1] ~ /^\302\247[0-9]+$/) print sec, "key", w[1]
      next
    }
    /^###+ / { h = $0; sub(/^#+ /, "", h); print sec, "key", slug(h); next }
    /^Revision: / { print sec, "revision"; next }
    /[^[:space:]]/ { pending = "" }
    END { print 0, "sections", sec + 0 }
  '
}

# record_ref VALUE: the section key a trailer value cites (`#x` → x,
# ` §N` → §N), or nothing.
record_ref() {
  local v="${1#*consensus-changes.md}"
  if [[ "$v" =~ ^#([A-Za-z0-9_-]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  elif [[ "$v" =~ ^[[:space:]]*(§[0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}

# check_record_ref KEYS VALUE: 0 when VALUE cites a section of the record
# whose keys (record_keys output) are KEYS, with its `Revision:` line when the
# record has any; otherwise prints why and returns 1.
check_record_ref() {
  local keys="$1" value="$2" ref sec
  ref="$(record_ref "$value")"
  if [ -z "$ref" ]; then
    echo "cites no section (#<anchor> or §N): $value"
    return 1
  fi
  sec="$(printf '%s\n' "$keys" | awk -v r="$ref" '$2 == "key" && $3 == r { print $1; exit }')"
  if [ -z "$sec" ] || [ "$sec" = 0 ]; then
    echo "cites a section that does not exist in $RECORD: $ref"
    return 1
  fi
  if printf '%s\n' "$keys" | grep -q ' revision$' &&
    ! printf '%s\n' "$keys" | grep -qx "$sec revision"; then
    echo "section $ref has no \`Revision:\` line (the record template)"
    return 1
  fi
  return 0
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

# valid_trailer [COMMIT]: the trailer values on stdin; 0 when one is valid.
# `none: <reason>` is valid as it is; a record citation is valid when it
# names a section of the record as of COMMIT (check_record_ref). Without
# COMMIT (waiver values) only the form is checked.
valid_trailer() {
  local v commit="${1:-}" keys="" why ok=1
  while IFS= read -r v; do
    v="${v%$'\r'}"
    case "$v" in
      none:*[![:space:]]*) ok=0 ;;
      *consensus-changes.md*)
        if [ -z "$commit" ]; then
          ok=0
          continue
        fi
        if [ -z "$keys" ]; then
          keys="$(git show "$commit:$RECORD" 2>/dev/null | record_keys)"
        fi
        if why="$(check_record_ref "$keys" "$v")"; then
          ok=0
        else
          echo "     Consensus-Change: $why" >&2
        fi
        ;;
    esac
  done
  return "$ok"
}

# A published commit that lacks the trailer cannot be amended without
# rewriting shared history. `.github/consensus-gate-waivers.txt` records such
# commits, one per line: `<full sha> <trailer value>`, where the value must be
# a valid trailer value (`none: <reason>` or a record reference). Adding a
# line is a reviewed change, like changing the path list above; the gate
# prints every waived commit.
waiver_for() {
  gate_waiver "$here/../consensus-gate-waivers.txt" "$1"
}

# The record-citation rules on a fixture record.
selftest() {
  local strict loose bad=0 v
  strict="$(printf '%s\n' '# Record' 'Intro.' '' '<a id="alpha"></a>' '' '## alpha: first' '' \
    'Revision: A-1' '' '### Follow-up (X-1/2)' '' '## §2 Second: title' '' 'Revision: none (r)' '' \
    '## beta: keyed' '' 'Revision: B-1' '' '## gamma: no revision line' '' 'Text.' | record_keys)"
  loose="$(printf '%s\n' '# Record' '## gamma: no revision line' 'Text.' | record_keys)"
  for v in '#alpha' '#alpha-first' '#follow-up-x-12' ' §2' '#2-second-title' '#beta'; do
    check_record_ref "$strict" "docs/reviews/v3-consensus-changes.md$v" >/dev/null ||
      { echo "selftest: '$v' should pass"; bad=1; }
  done
  for v in '#alph' '#gamma' '#gamma-no-revision-line' ' §20' ' §' '' '#record'; do
    if check_record_ref "$strict" "docs/reviews/v3-consensus-changes.md$v" >/dev/null; then
      echo "selftest: '$v' should fail"
      bad=1
    fi
  done
  check_record_ref "$loose" "docs/reviews/v3-consensus-changes.md#gamma-no-revision-line" >/dev/null ||
    { echo "selftest: a record without Revision lines needs none"; bad=1; }
  printf '%s\n' 'none: tests only' | valid_trailer || { echo "selftest: none: failed"; bad=1; }
  if printf '%s\n' 'none:' 'something else' | valid_trailer; then
    echo "selftest: an empty reason passed"
    bad=1
  fi
  echo "consensus-gate selftest: $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

main() {
  if [ "${1:-}" = "--selftest" ]; then
    selftest
    return
  fi
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
    local full waiver
    full="$(git rev-parse "$c")"
    waiver="$(waiver_for "$full")"
    if printf '%s\n' "$trailers" | valid_trailer "$c"; then
      echo "ok   $subject"
      printf '%s\n' "$trailers" | sed '/^[[:space:]]*$/d; s/^/     Consensus-Change: /'
    elif [ -n "$waiver" ] && printf '%s\n' "$waiver" | valid_trailer; then
      echo "waived $subject"
      echo "     (.github/consensus-gate-waivers.txt) $waiver"
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
