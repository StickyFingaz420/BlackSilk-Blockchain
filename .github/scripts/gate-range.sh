#!/usr/bin/env bash
# Shared by the commit gates (consensus-gate.sh, lockfile-gate.sh): which
# commits a CI run must check. Sourced, not run.
#
# The cut-over commit. The gates were introduced on top of it (F48-3,
# decisions "Agent 48"); it and every commit reachable from it predate the
# rules and are never checked. Every other commit is, wherever it was forked
# from, so a branch forked before the cut-over cannot bring unchecked commits
# in. GATE_CUTOVER overrides it (fixture tests only). Changing it is a
# reviewed change of the gate itself.
# 55f110e: rebuild/core when the gates were written (2026-09-27).
GATE_CUTOVER_DEFAULT=55f110ea6c9e1341fbb671bef0ad9bdaf4dd88a3

gate_die() {
  echo "gate: $*" >&2
  exit 2
}

# gate_commits BASE HEAD: prints the commits to check, oldest first.
#   BASE: the last commit already checked (a push's github.event.before, a
#   pull request's base SHA), or empty. The all-zero SHA (new branch or tag),
#   an empty value, or a commit this clone does not have (a force push
#   dropped it) means "unknown": then every commit after the cut-over that
#   HEAD contains is checked, which is always correct, only slower.
#   HEAD: the commit under test (github.sha), default HEAD.
# Needs the full history (actions/checkout fetch-depth: 0); a shallow clone
# without the cut-over commit is an error, never a silent pass.
gate_commits() {
  local base="${1:-}" head="${2:-HEAD}" cutover="${GATE_CUTOVER:-$GATE_CUTOVER_DEFAULT}"
  git cat-file -e "$cutover^{commit}" 2>/dev/null ||
    gate_die "cut-over commit $cutover is not in this clone (shallow checkout? use fetch-depth: 0)"
  git cat-file -e "$head^{commit}" 2>/dev/null || gate_die "head $head is not a commit"
  if [ -n "$base" ] && [ -n "${base//0/}" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
    git rev-list --reverse "$head" "^$base" "^$cutover"
  else
    [ -z "$base" ] || [ -z "${base//0/}" ] || echo "gate: base $base not in this clone; checking every commit after the cut-over" >&2
    git rev-list --reverse "$head" "^$cutover"
  fi
}

# gate_annotate TITLE MESSAGE: a GitHub error annotation in CI (job logs need
# admin access; annotations do not), plain text elsewhere.
gate_annotate() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    local m="${2//'%'/%25}"
    m="${m//$'\r'/}"
    m="${m//$'\n'/%0A}"
    echo "::error title=$1::$m"
  fi
  printf '%s\n%s\n' "$1" "$2" >&2
}
