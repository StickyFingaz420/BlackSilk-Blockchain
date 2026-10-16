#!/usr/bin/env python3
"""Generates THIRD-PARTY-NOTICES.md for the BlackSilk release binaries.

RELEASE TOOLING, NOT CORE. Nothing in the node, miner, wallet or genesis tool
runs this file. Standard-library Python, like tools/vectors/.

Scope: the binaries of tools/release-build.sh's default set (blacksilk-node,
blacksilk-miner, blacksilk-wallet, blacksilk-genesis; the Docker image ships
the first three). The crate set is the union, over the release targets of
deny.toml [graph], of
    cargo tree --locked -e normal,build --target <t> -p <the four packages>
with -e normal,build, so features and target-specific dependencies are
resolved as the release build resolves them. Build-dependencies and
proc-macros are not shipped in the binaries but are listed, marked by kind
(over-inclusion is the safe side); dev-dependencies are left out.

For each crate: name, version, licence expression (Cargo.toml), source and
the copyright lines of its licence files. Then the licence texts: the
Apache-2.0 text once (root LICENSE-APACHE) for every crate whose Apache file
has the standard terms, and every other licence or notice file verbatim,
deduplicated. Text is normalized (LF line ends, no trailing spaces), so the
output is byte-identical on every OS.

Supplements the published crates lack: Plonky3's MIT notice (the p3-* crates
ship no licence files; text from the Plonky3 repository's LICENSE-MIT, read
2026-10-17), randomx/LICENSE and the BIP-39 word list's MIT terms.

Usage (repository root or anywhere in it):
    python3 tools/third-party-notices.py           # write THIRD-PARTY-NOTICES.md
    python3 tools/third-party-notices.py --check   # exit 1 if the file is stale
Needs cargo and the crate sources (cargo fetches them if they are missing).
Exit: 0 ok, 1 stale (--check), 2 error.
"""

import json
import os
import re
import subprocess
import sys

OUT = "THIRD-PARTY-NOTICES.md"
PACKAGES = ["blacksilk-node", "blacksilk-miner", "blacksilk-wallet", "blacksilk-genesis"]
# deny.toml [graph] targets (also .github/scripts/sys-crates.sh).
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
]
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)", re.I)
END_OF_TERMS = "END OF TERMS AND CONDITIONS"

PLONKY3_MIT = """The MIT License (MIT)

Copyright (c) 2022 The Plonky3 Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

MIT_TERMS = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def die(msg):
    print(f"third-party-notices: {msg}", file=sys.stderr)
    sys.exit(2)


def run(cmd, cwd):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, check=True)
    except FileNotFoundError:
        die(f"{cmd[0]} not found")
    except subprocess.CalledProcessError as e:
        die(f"{' '.join(cmd)} failed:\n{e.stderr.decode('utf-8', 'replace')}")
    return r.stdout.decode("utf-8")


def norm(text):
    """LF line ends, no trailing spaces, no leading or trailing blank lines."""
    lines = [l.rstrip() for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(lines).strip("\n") + "\n"


def squash(text):
    return " ".join(text.split())


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def copyright_lines(text):
    out = []
    for l in text.split("\n"):
        s = l.strip()
        if not re.match(r"(?i)^(\(c\)\s*)?copyright\b", s):
            continue
        low = s.lower()
        if "[yyyy]" in low or "copyright notice" in low or "copyright holder" in low:
            continue
        if not re.search(r"(?i)(\(c\)|©|\d{4})", s):
            continue
        s = re.sub(r"\s*<[^>]*@[^>]*>", "", s)  # e-mail addresses
        out.append(" ".join(s.split()))
    return out


def cell(s):
    return s.replace("|", "\\|")


def fence(text):
    f = "~~~~"
    while f in text:
        f += "~"
    return f"{f}text\n{text}{f}\n"


def tree(root, edges):
    """(name, version) -> kind, over every release target."""
    keys = {}
    for t in TARGETS:
        cmd = ["cargo", "tree", "--locked", "-e", edges, "--target", t,
               "--prefix", "none", "-f", "{p}"]
        for p in PACKAGES:
            cmd += ["-p", p]
        for line in run(cmd, root).splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                macro = "(proc-macro)" in line
                keys[(parts[0], parts[1][1:])] = "proc-macro" if macro else "linked"
    return keys


def crate_set(root):
    """Normal edges (linked code and proc-macros) plus build-only crates."""
    normal = tree(root, "normal")
    full = tree(root, "normal,build")
    for k in full:
        if k not in normal:
            normal[k] = "build only"
    return normal


def generate(root):
    canon_apache = norm(read(os.path.join(root, "LICENSE-APACHE")))
    canon_terms = squash(canon_apache.split(END_OF_TERMS)[0])
    meta = json.loads(run(["cargo", "metadata", "--locked", "--format-version", "1"], root))
    members = set(meta["workspace_members"])
    pkgs = {(p["name"], p["version"]): p for p in meta["packages"]}
    kinds = crate_set(root)
    keys = set(kinds)
    missing = sorted(k for k in keys if k not in pkgs)
    if missing:
        die(f"not in cargo metadata: {missing}")

    own, third = [], []
    for k in sorted(keys):
        (own if pkgs[k]["id"] in members else third).append(pkgs[k])

    apache_users = []  # crates whose Apache file has the standard terms
    texts = {}  # normalized text -> set of "name version (file)"
    rows = []
    for p in third:
        name, ver = p["name"], p["version"]
        d = os.path.dirname(p["manifest_path"])
        rel = os.path.relpath(d, root).replace(os.sep, "/")
        if p["source"] is None:
            source = f"path `{rel}` (patched copy of the crates.io release)"
        elif p["source"].startswith("registry+https://github.com/rust-lang/crates.io-index"):
            source = "crates.io"
        else:
            source = p["source"]
        files = sorted(f for f in os.listdir(d)
                       if LICENCE_FILE.match(f) and os.path.isfile(os.path.join(d, f)))
        cr = []
        for f in files:
            t = norm(read(os.path.join(d, f)))
            cr += copyright_lines(t)
            if END_OF_TERMS in t and squash(t.split(END_OF_TERMS)[0]) == canon_terms:
                apache_users.append(f"{name} {ver}")
                continue
            texts.setdefault(t, set()).add(f"{name} {ver} ({f})")
        if not files and name.startswith("p3-"):
            texts.setdefault(norm(PLONKY3_MIT), set()).add(
                f"{name} {ver} (supplied: Plonky3 repository LICENSE-MIT)")
            apache_users.append(f"{name} {ver} (supplied)")
            cr.append("Copyright (c) 2022 The Plonky3 Authors")
            note = " (no licence files in the published crate; texts supplied below)"
        elif not files:
            note = " (no licence files found)"
        else:
            note = ""
        if not cr:
            authors = [re.sub(r"\s*<[^>]*>", "", a).strip() for a in p.get("authors") or []]
            cr = [f"not stated in its licence files; authors (Cargo.toml): {', '.join(authors)}"
                  if authors else "not stated in its licence files"]
        seen = []
        for c in cr:
            if c not in seen:
                seen.append(c)
        rows.append((name, ver, kinds[(name, ver)], p.get("license") or "(none declared)",
                     source + note,
                     "; ".join(seen)))

    o = []
    o.append("# Third-party notices\n\n")
    o.append("<!-- Generated by tools/third-party-notices.py; do not edit by hand. "
             "Check: python3 tools/third-party-notices.py --check -->\n\n")
    o.append("Notices for the BlackSilk release artifacts: the binaries `blacksilk-node`, "
             "`blacksilk-miner`, `blacksilk-wallet` and `blacksilk-genesis` built by "
             "tools/release-build.sh (its default set; deploy/scripts/install-linux.sh builds "
             "the first three with it), and the Docker image of deploy/docker/Dockerfile (the "
             "first three). No CI workflow publishes binaries; `testnet-*` tags only run CI. "
             "This file is a record for redistribution, not legal advice.\n\n")
    o.append("**Method.** The crate set is the union, over the release targets "
             f"({', '.join('`' + t + '`' for t in TARGETS)}; deny.toml [graph]), of "
             "`cargo tree --locked -e normal,build --target <t> -p <the four packages>`, so "
             "features and target-specific dependencies (for example `windows-sys` on "
             "Windows, `libc` on Unix) are resolved as the release build resolves them. "
             "Build-dependencies and proc-macros are not shipped in the binaries; they are "
             "listed anyway, marked, because they are part of the build that produces them. "
             "Dev-dependencies are left out. Licence expressions are those the crates "
             "declare; copyright lines are extracted from their licence files (lines starting "
             "with \"Copyright\"), e-mail addresses removed; the full licence and notice "
             "texts are in §3 and §4.\n\n")
    o.append("**Limitations.** The list is a union: a given binary or target may not contain "
             "every crate. The copyright column is extracted mechanically; the verbatim "
             "texts in §3 and §4 are authoritative. A crate whose licence files state no "
             "copyright line shows its Cargo.toml authors instead. Copyright notices inside "
             "source files that are not repeated in a crate's licence files are not collected. "
             "Regenerate after every Cargo.lock change (the CI job `deny` runs `--check`).\n\n")
    o.append("## 1. BlackSilk's own code\n\n")
    o.append("BlackSilk's crates are licensed `MIT OR Apache-2.0` (LICENSE-MIT, LICENSE-APACHE; "
             "copyright The BlackSilk developers), except:\n\n")
    o.append("- `blacksilk-randomx` is a Rust port of tevador/RandomX under its `BSD-3-Clause` "
             "licence, reproduced in §4.1.\n")
    o.append("- The English word list in `blacksilk-crypto` (crypto/src/wordlist.rs) is the "
             "BIP-39 list; BIP-39 is published under the MIT licence (§4.2).\n\n")
    o.append("| Crate | Version | Licence |\n|---|---|---|\n")
    for p in own:
        o.append(f"| {p['name']} | {p['version']} | {cell(p.get('license') or '(none)')} |\n")

    o.append(f"\n## 2. Third-party crates ({len(rows)})\n\n")
    o.append("Kind: `linked` (compiled into the binaries), `proc-macro` (runs in the "
             "compiler at build time), `build only` (a build-dependency: runs at build time, "
             "not shipped).\n\n")
    o.append("| Crate | Version | Kind | Licence | Source | Copyright |\n"
             "|---|---|---|---|---|---|\n")
    for r in rows:
        o.append("| " + " | ".join(cell(x) for x in r) + " |\n")

    o.append("\n## 3. Apache License 2.0\n\n")
    o.append("The crates below include the Apache License 2.0 with the standard terms "
             "(their files differ at most in whitespace and in the appendix, whose filled-in "
             "copyright lines are in §2). None of the listed crates ships a NOTICE file. "
             "The text follows the list.\n\n")
    o.append(", ".join(sorted(apache_users)) + "\n\n")
    o.append(fence(canon_apache))

    o.append("\n## 4. Other licence and notice texts\n\n")
    o.append("### 4.1 blacksilk-randomx (randomx/LICENSE)\n\n")
    o.append(fence(norm(read(os.path.join(root, "randomx", "LICENSE")))))
    o.append("\n### 4.2 BIP-39 English word list (crypto/src/wordlist.rs)\n\n")
    o.append("From BIP-39, \"Mnemonic code for generating deterministic keys\", by Marek "
             "Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe, whose header states "
             "`License: MIT` (github.com/bitcoin/bips, bip-0039.mediawiki). BIP-39 states no "
             "copyright line; the MIT terms:\n\n")
    o.append(fence(norm(MIT_TERMS)))
    n = 3
    for t in sorted(texts, key=lambda t: (sorted(texts[t])[0], t)):
        o.append(f"\n### 4.{n} {', '.join(sorted(texts[t]))}\n\n")
        o.append(fence(t))
        n += 1
    return "".join(o)


def main():
    args = sys.argv[1:]
    if args not in ([], ["--check"]):
        die("usage: third-party-notices.py [--check]")
    root = run(["git", "rev-parse", "--show-toplevel"], os.getcwd()).strip()
    text = generate(root)
    path = os.path.join(root, OUT)
    data = text.encode("utf-8")
    if args == ["--check"]:
        try:
            with open(path, "rb") as f:
                old = f.read().replace(b"\r\n", b"\n")
        except FileNotFoundError:
            old = None
        if old != data:
            print(f"third-party-notices: {OUT} is stale; run python3 tools/third-party-notices.py "
                  "and commit it", file=sys.stderr)
            return 1
        print(f"third-party-notices: {OUT} is current")
        return 0
    with open(path, "wb") as f:
        f.write(data)
    print(f"third-party-notices: wrote {OUT} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
