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

# NAME TITLE MESSAGE: a GitHub error annotation in CI, plain text elsewhere.
# Titles and messages carry data from the commit under test (subjects,
# paths). The title is escaped as a command property and the message as
# command data, so neither can end the command early or start a new line.
# RT-TPGATE5: CI runs the gates between `::stop-commands::<token>` and
# `::<token>::` (GATE_CMD_TOKEN, random per step), so a line of commit data
# that starts with `::` is never a workflow command; only this function
# resumes commands, for the one annotation line, and stops them again.
gate_annotate() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    local m="${2//'%'/%25}" t="${1//'%'/%25}"
    m="${m//$'\r'/%0D}"
    m="${m//$'\n'/%0A}"
    t="${t//$'\r'/%0D}"
    t="${t//$'\n'/%0A}"
    t="${t//:/%3A}"
    t="${t//,/%2C}"
    if [ -n "${GATE_CMD_TOKEN:-}" ]; then
      printf '::%s::\n::error title=%s::%s\n::stop-commands::%s\n' \
        "$GATE_CMD_TOKEN" "$t" "$m" "$GATE_CMD_TOKEN"
      printf '%s\n%s\n' "$1" "$2"
      return 0
    fi
    echo "::error title=$t::$m"
  fi
  printf '%s\n%s\n' "$1" "$2" >&2
}

# The waiver horizon (RT-TPGATE2). A waiver (.github/consensus-gate-waivers.txt,
# .github/lockfile-gate-waivers.txt) applies only to a commit that is an
# ancestor of this published rebuild/core head, so a waiver can never cover a
# commit written after it was granted. GATE_WAIVER_HORIZON overrides it
# (fixture tests only). Moving it is a reviewed change of the gate.
# d5c20f7: rebuild/core when the horizon was set (2026-10-04).
GATE_WAIVER_HORIZON_DEFAULT=d5c20f74ec2337cfd01f54af6b3dbf2a5226d517

# gate_waivable SHA: 0 when SHA is an ancestor of (or is) the waiver horizon.
gate_waivable() {
  local h="${GATE_WAIVER_HORIZON:-$GATE_WAIVER_HORIZON_DEFAULT}"
  git cat-file -e "$h^{commit}" 2>/dev/null ||
    gate_die "waiver horizon $h is not in this clone (use fetch-depth: 0)"
  git merge-base --is-ancestor "$1" "$h"
}

# gate_waiver FILE SHA: prints the waiver value FILE records for SHA (lines
# "<full sha> <value>", '#' comments), if SHA is within the horizon.
gate_waiver() {
  local f="$1" sha rest
  [ -f "$f" ] || return 0
  while IFS=' ' read -r sha rest; do
    sha="${sha%$'\r'}"
    rest="${rest%$'\r'}"
    case "$sha" in '' | '#'*) continue ;; esac
    if [ "$sha" = "$2" ]; then
      gate_waivable "$2" || { echo "gate: waiver for $2 ignored: not an ancestor of the waiver horizon" >&2; return 0; }
      printf '%s\n' "$rest"
      return 0
    fi
  done <"$f"
}
