#!/usr/bin/env bash
# Boundary mutation pass (run C, decisions "W4-MUT and RT-MUT"; RT-MUTC).
#
# cargo-mutants 27.1 never mutates `>=` into `>` or `<=` into `<`: the off-by-one
# at an inclusive bound, which is where consensus limits live. This script
# generates exactly those mutants, one per `>=` / `<=` in the non-test code of
# the given files, and runs an oracle command on each.
#
# What counts: an operator outside comments, string literals and `#[cfg(test)]`
# items; `>>=` and `<<=` (shift-assign) are not comparisons and are left out.
#
# Each mutant is applied to a scratch copy of HEAD (`git archive`), never to
# this tree. The oracle runs under a time limit; on Windows (Git Bash) through
# tools/run-with-timeout.ps1, which kills only the process tree it started.
#
# Usage:
#   tools/boundary-mutants.sh list FILE...
#       print the mutants (FILE:LINE:COL: replace OP with OP')
#   tools/boundary-mutants.sh run SCRATCH TIMEOUT_S FILE... -- CARGO_ARGS...
#       run `cargo CARGO_ARGS` in SCRATCH/src on each mutant of the files
#       (CARGO_TARGET_DIR defaults to SCRATCH/target). Results:
#       SCRATCH/out/outcomes.txt, one line per mutant:
#         caught | missed | timeout | unviable, then the mutant;
#       SCRATCH/out/<n>.log, the oracle's output per mutant.
#       BM_FILTER=REGEX restricts the run to the mutants it matches.
# Exit: 0 when no mutant is missed, 1 otherwise, 2 on a usage error or a failing
# unmutated baseline.
set -euo pipefail

usage() { sed -n '2,30p' "$0" >&2; exit 2; }

# Lists FILE:LINE:COL:OP for every boundary operator of FILE's non-test code.
list_file() {
  awk -v F="$1" '
    function mask(s,   out, i, c, n, instr) {
      out = ""; instr = 0; n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (instr) {
          if (c == "\\") { out = out "  "; i++; continue }
          if (c == "\"") instr = 0
          out = out " "; continue
        }
        if (c == "\"") { instr = 1; out = out " "; continue }
        if (c == "/" && substr(s, i + 1, 1) == "/") {
          while (length(out) < n) out = out " "
          return out
        }
        out = out c
      }
      return out
    }
    {
      m = mask($0)
      if (!skipping && $0 ~ /^[ \t]*#\[cfg\(test\)\]/) { skipping = 1; depth = 0; opened = 0; next }
      if (skipping) {
        o = gsub(/\{/, "{", m); cl = gsub(/\}/, "}", m)
        depth += o - cl
        if (o > 0) opened = 1
        if ((opened && depth <= 0) || (!opened && m ~ /;[ \t]*$/)) skipping = 0
        next
      }
      gsub(/>>=/, "   ", m); gsub(/<<=/, "   ", m)
      s = m; base = 0
      while ((p = match(s, />=|<=/)) > 0) {
        op = substr(s, p, 2)
        printf "%s:%d:%d:%s\n", F, NR, base + p, op
        s = substr(s, p + 2); base += p + 1
      }
    }' "$1"
}

describe() { # FILE:LINE:COL:OP
  local op="${1##*:}" rest="${1%:*}"
  local to; [ "$op" = ">=" ] && to=">" || to="<"
  echo "$rest: replace $op with $to"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  list)
    [ "$#" -ge 1 ] || usage
    for f in "$@"; do list_file "$f" | while read -r m; do describe "$m"; done; done
    ;;
  run)
    [ "$#" -ge 4 ] || usage
    scratch="$1"; limit="$2"; shift 2
    files=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do files+=("$1"); shift; done
    [ "${1:-}" = "--" ] || usage
    shift
    repo="$(git rev-parse --show-toplevel)"
    mkdir -p "$scratch"
    scratch="$(cd "$scratch" && pwd)"
    src="$scratch/src"; out="$scratch/out"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/target}"
    unset BLACKSILK_BUILD_COMMIT
    rm -rf "$src"; mkdir -p "$src" "$out"
    (cd "$repo" && git archive HEAD) | tar -x -C "$src"
    echo "commit $(cd "$repo" && git rev-parse --short HEAD); cargo $*" > "$out/outcomes.txt"

    oracle() { # LOG -> exit code (124 on timeout)
      local log="$1" rc=0
      if [ -n "${WINDIR:-}" ]; then
        # The arguments go as one string (no argument may contain a space).
        powershell -NoProfile -ExecutionPolicy Bypass \
          -File "$(cygpath -w "$repo/tools/run-with-timeout.ps1")" \
          -TimeoutSec "$limit" -WorkDir "$(cygpath -w "$src")" -Log "$(cygpath -w "$log")" \
          -Exe cargo -ArgLine "$*" || rc=$?
      else
        (cd "$src" && timeout -k 10 "$limit" cargo "$@" >"$log" 2>&1) || rc=$?
      fi
      return "$rc"
    }

    rc=0; oracle "$out/baseline.log" "$@" || rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "baseline failed (exit $rc), see $out/baseline.log" | tee -a "$out/outcomes.txt" >&2
      exit 2
    fi
    echo "baseline ok" >> "$out/outcomes.txt"

    n=0; missed=0
    for f in "${files[@]}"; do
      while read -r m; do
        name="$(describe "$m")"
        if [ -n "${BM_FILTER:-}" ] && ! [[ "$name" =~ $BM_FILTER ]]; then continue; fi
        n=$((n + 1))
        IFS=: read -r file line col op <<<"$m"
        to=">"; [ "$op" = "<=" ] && to="<"
        cp "$src/$file" "$src/$file.orig"
        awk -v L="$line" -v C="$col" -v T="$to" \
          'NR == L { $0 = substr($0, 1, C - 1) T substr($0, C + 2) } { print }' \
          "$src/$file.orig" > "$src/$file"
        log="$out/$n.log"
        { echo "*** $name"; diff "$src/$file.orig" "$src/$file" || true; } > "$log.head"
        rc=0; oracle "$log.body" "$@" || rc=$?
        cat "$log.head" "$log.body" > "$log"; rm -f "$log.head" "$log.body"
        mv "$src/$file.orig" "$src/$file"
        if [ "$rc" -eq 0 ]; then verdict=missed; missed=$((missed + 1))
        elif [ "$rc" -eq 124 ]; then verdict=timeout
        elif grep -q -E "^error(\[E[0-9]+\])?:|could not compile" "$log"; then verdict=unviable
        else verdict=caught
        fi
        echo "$verdict $name ($n.log)" | tee -a "$out/outcomes.txt"
      done < <(list_file "$f")
    done
    echo "done: $n mutants, $missed missed" | tee -a "$out/outcomes.txt"
    [ "$missed" -eq 0 ]
    ;;
  *) usage ;;
esac
