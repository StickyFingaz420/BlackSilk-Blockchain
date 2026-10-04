#!/usr/bin/env bash
# Lockfile-diff gate (F48-3, decisions "Agent 48").
#
# A commit that changes Cargo.lock or fuzz/Cargo.lock must name, in its commit
# message, every crate it adds, moves to another version or moves to another
# source, so no dependency enters the graph unseen (a `cargo update` side
# effect, a new transitive crate, a registry crate swapped for a path copy or a
# git fork at the same version: RT-PXDET finding 1). A crate's source is its
# `source = ` line; a crate without one (a path crate, e.g. a [patch] copy in
# third_party/) counts as source "path". A crate counts as named when its name
# appears as a whole word (letters, digits, '_' and '-'); case is ignored.
# Removals need no mention.
#
# For a merge, "added" means: in the merged lockfile but in none of the
# parents' lockfiles (the merge resolved the lock differently from every side).
#
# Usage: lockfile-gate.sh [BASE [HEAD]]   (range rules: gate-range.sh)
#        lockfile-gate.sh --selftest      (fixture repository; needs git)
# Exit: 0 pass, 1 a commit does not name its lockfile changes, 2 usage error.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=gate-range.sh
source "$here/gate-range.sh"

LOCKFILES=(Cargo.lock fuzz/Cargo.lock)

# "name version source" lines of a lockfile at a commit (nothing if it has
# none); a package without a `source` line has source "path".
lock_pairs() {
  git show "$1:$2" 2>/dev/null | tr -d '\r' | awk '
    function emit() { if (n != "") print n, v, (s == "" ? "path" : s); n = ""; v = ""; s = "" }
    /^\[\[package\]\]/ { emit(); next }
    /^\[/ { emit(); next }
    /^name = "/ { n = $3; gsub(/"/, "", n) }
    /^version = "/ { v = $3; gsub(/"/, "", v) }
    /^source = "/ { s = $3; gsub(/"/, "", s) }
    END { emit() }' | sort -u
}

# The crate names whose "name version source" triple is new in commit $1's
# lockfile $2.
new_names() {
  local c="$1" f="$2" p tmp
  tmp="$(mktemp)"
  for p in $(git rev-list --parents -n 1 "$c" | awk '{ for (i = 2; i <= NF; i++) print $i }'); do
    lock_pairs "$p" "$f" >> "$tmp"
  done
  sort -u -o "$tmp" "$tmp"
  lock_pairs "$c" "$f" | comm -23 - "$tmp" | cut -d' ' -f1 | sort -u
  rm -f "$tmp"
}

# Whether commit $1 changes lockfile $2 relative to its first parent (or adds it).
touches() {
  local c="$1" f="$2"
  if git rev-parse -q --verify "$c^1" >/dev/null; then
    ! git diff --quiet "$c^1" "$c" -- "$f"
  else
    git cat-file -e "$c:$f" 2>/dev/null
  fi
}

main() {
  [ "$#" -le 2 ] || gate_die "usage: lockfile-gate.sh [BASE [HEAD]]"
  local commits c f name bad=0 n=0 flagged=0
  commits="$(gate_commits "${1:-}" "${2:-HEAD}")"
  for c in $commits; do
    n=$((n + 1))
    local words="" missing="" required=""
    for f in "${LOCKFILES[@]}"; do
      touches "$c" "$f" || continue
      if [ -z "$words" ]; then
        words="$(git log -1 --format=%B "$c" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9_-' '\n' | sort -u)"
      fi
      for name in $(new_names "$c" "$f"); do
        required+=" $name"
        printf '%s\n' "$words" | grep -Fqx -- "$(printf '%s' "$name" | tr 'A-Z' 'a-z')" ||
          missing+="${missing:+, }$name ($f)"
      done
    done
    [ -n "$required" ] || continue
    flagged=$((flagged + 1))
    local subject
    subject="$(git log -1 --format='%h %s' "$c")"
    if [ -z "$missing" ]; then
      echo "ok   $subject: names$required"
    else
      bad=1
      gate_annotate "lockfile change not named in the commit message: $subject" \
        "Added or changed crates missing from the message: $missing
List every added, re-versioned or re-sourced crate by name (.github/scripts/lockfile-gate.sh)."
    fi
  done
  echo "lockfile-gate: $n commits checked, $flagged add or change locked crates, $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

# A fixture repository: one commit per case on top of a cut-over commit; each
# case runs the gate on its own commit only (BASE = its parent).
selftest() {
  local t bad=0 self
  self="$here/lockfile-gate.sh"
  t="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$t'" RETURN
  (
    set -e
    cd "$t"
    git init -q -b main .
    git config user.email selftest@invalid
    git config user.name selftest
    git config commit.gpgsign false
    git config core.autocrlf false
    lock() { # name version [source]: a one-package lockfile
      printf 'version = 4\n\n[[package]]\nname = "%s"\nversion = "%s"\n' "$1" "$2" > Cargo.lock
      [ -z "${3:-}" ] || printf 'source = "%s"\nchecksum = "00"\n' "$3" >> Cargo.lock
      printf '\n[[package]]\nname = "other"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' >> Cargo.lock
    }
    reg="registry+https://github.com/rust-lang/crates.io-index"
    lock foo 1.0.0 "$reg"; git add Cargo.lock; git commit -q -m cutover
    git tag cutover
    c() { git add Cargo.lock; git commit -q -m "$1"; git tag "$2"; }
    lock foo 1.0.0;                      c "patch a crate"              src-unnamed
    lock foo 1.0.0 "$reg";               c "back to the registry: foo"  src-named
    lock foo 1.0.0 "git+https://example.invalid/foo#abc"; c "fork"      git-unnamed
    lock foo 1.0.0 "$reg";               c "registry foo again"         git-back-named
    lock foo 1.0.1 "$reg";               c "bump"                       ver-unnamed
    lock foo 1.0.2 "$reg";               c "bump FOO"                   ver-named
    printf 'version = 4\n' > Cargo.lock; c "drop everything"            removal
  ) > /dev/null || { echo "lockfile-gate selftest: fixture setup failed"; return 1; }
  local case want got
  for case in src-unnamed:1 src-named:0 git-unnamed:1 git-back-named:0 ver-unnamed:1 ver-named:0 removal:0; do
    want="${case#*:}"
    case="${case%%:*}"
    if (cd "$t" && GATE_CUTOVER="$(git rev-parse cutover)" bash "$self" "$case^" "$case") > /dev/null 2>&1; then got=0; else got=$?; fi
    if [ "$got" = "$want" ]; then
      echo "selftest ok   $case (exit $got)"
    else
      echo "selftest FAIL $case: expected exit $want, got $got"
      bad=1
    fi
  done
  echo "lockfile-gate selftest: $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

if [ "${1:-}" = "--selftest" ]; then
  [ "$#" = 1 ] || gate_die "usage: lockfile-gate.sh --selftest"
  selftest
else
  main "$@"
fi
