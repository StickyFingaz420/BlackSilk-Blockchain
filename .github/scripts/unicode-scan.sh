#!/usr/bin/env bash
# Invisible and bidirectional Unicode scan (F48-3, decisions "Agent 48").
#
# Fails if a tracked text file contains a character that renders invisibly or
# reorders the displayed text, so a reviewer could read something other than
# what the compiler or shell sees ("Trojan Source", CVE-2021-42574):
#   U+00AD          soft hyphen
#   U+200B..U+200F  zero-width space/joiners, LRM, RLM
#   U+202A..U+202E  bidi embeddings and overrides
#   U+2060..U+2069  word joiner, invisible operators, bidi isolates
#   U+FEFF          zero-width no-break space / byte order mark
#
# Scope: every file `git ls-files` lists, except the research/
# tree (not built, not reviewed as code). Files with a NUL byte in their
# first 8000 bytes are binary (git's own heuristic) and are skipped.
#
# Usage: unicode-scan.sh [<path>...]   (default: the whole tracked tree)
# Exit: 0 clean, 1 findings (one `file:line:col U+XXXX NAME` line each, plus a
# GitHub annotation), 2 usage or environment error.
# Needs git and python3 (stdlib only).
set -euo pipefail

py=""
for c in python3 python; do
  # The Windows Store stub named python3 exists but does not run.
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
    py="$c"
    break
  fi
done
[ -n "$py" ] || { echo "unicode-scan: python3 not found" >&2; exit 2; }

git ls-files -z -- "$@" | "$py" -c '
import os, sys, unicodedata

BAD = {0x00AD, 0xFEFF}
BAD.update(range(0x200B, 0x2010))
BAD.update(range(0x202A, 0x202F))
BAD.update(range(0x2060, 0x206A))
EXCLUDED = ("research/",)

found = 0
scanned = 0
for path in sys.stdin.buffer.read().split(b"\0"):
    if not path:
        continue
    name = path.decode("utf-8", "surrogateescape")
    if name.startswith(EXCLUDED):
        continue
    try:
        with open(path, "rb") as f:
            data = f.read()
    except (FileNotFoundError, IsADirectoryError):
        continue  # deleted in the working tree, or a submodule
    if b"\0" in data[:8000]:
        continue
    scanned += 1
    text = data.decode("utf-8", "replace")
    for lineno, line in enumerate(text.split("\n"), 1):
        for col, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp in BAD:
                found += 1
                label = unicodedata.name(ch, "U+%04X" % cp)
                print("%s:%d:%d U+%04X %s" % (name, lineno, col, cp, label))
                if os.environ.get("GITHUB_ACTIONS") == "true":
                    print("::error file=%s,line=%d,col=%d::invisible or bidi character U+%04X %s"
                          % (name, lineno, col, cp, label))
print("unicode-scan: %d files scanned, %d findings" % (scanned, found), file=sys.stderr)
sys.exit(1 if found else 0)
'
