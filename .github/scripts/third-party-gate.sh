#!/usr/bin/env bash
# Third-party patch gate (RT-PXDET finding 1; hardened after RT-TPGATE, RT-TPGATE2, RT-TPGATE3).
#
# Every crate directory under third_party/ (a directory with a Cargo.toml) is a
# patched copy of a published crate, used through [patch.crates-io]. This gate
# checks three things.
#
# A. Each crate is exactly the published crate plus its allow-listed diff:
#   1. name and version come from third_party/<crate>/Cargo.toml; <crate> must
#      equal the package name;
#   2. the pristine <name>-<version>.crate comes from the local cargo cache
#      (~/.cargo/registry/cache/*/) or static.crates.io, and its sha256 must
#      equal the pin in third_party/PRISTINE.sha256 (the checksum Cargo.lock
#      carried before the crate was patched);
#   3. the .crate is unpacked and the packaging differences documented in
#      third_party/README.md are dropped (top level only: Cargo.toml.orig,
#      .cargo_vcs_info.json and Cargo.lock from the published side, cargo's
#      unpack marker .cargo-ok from ours);
#   4. `diff -a -ruN --strip-trailing-cr` of the two trees (text mode, so a NUL
#      byte cannot turn a file into an opaque "Binary files differ" line),
#      with timestamps and CRs removed, must equal
#      third_party/patches/<crate>.patch byte for byte (CRs stripped from it);
#   5. third_party/patches/<crate>.sha256 lists sha256, mode and path of every
#      tracked file of the crate, from the committed (index) bytes: it pins the
#      exact bytes, CRs and data files included, that step 4 normalizes;
#   6. the crate's working tree equals the index (nothing modified or
#      untracked), so what cargo builds is what steps 4 and 5 checked;
#   7. the patch has no "Binary files" line and adds or changes no build.rs;
#      an escape lint rejects added lines with an include*! macro, a path
#      attribute or `path =` key, a `..` path segment or a build/proc-macro/
#      links key. The lint is a reviewer aid, not a guarantee;
#   8. every tracked file under third_party/ (patches and pins included) has
#      no NUL or other control byte (DEL too) except TAB, LF and CR, so git
#      and GitHub always show its changes as text; except the files
#      third_party/BINARY-ALLOWLIST names with a reason, which must lie in a
#      crate directory (not patches/, upstream/ or the top level) and have
#      the same sha256 as in the published crate (RT-TPGATE3);
#   9. `git check-attr diff` is `set` for every tracked file under
#      third_party/ except BINARY-ALLOWLIST entries, and no .gitattributes
#      lies inside third_party/ (RT-TPGATE3).
#   Stale allow-list entries (a patch, manifest, pin or binary entry without
#   its file) fail.
#
# B. Dependency identity, by tools/tpgate (Rust; cargo's own view, parsed as
#    JSON and TOML, failing closed): for every tracked Cargo.lock's workspace,
#    `cargo metadata --no-deps --offline` gives the members and their declared
#    dependencies. No member is named like a third_party/ crate; every path
#    dependency is a member (of any workspace), a standalone crate listed in
#    STANDALONE below (no dependencies allowed) or third_party/<its name>; no
#    third_party/ crate is aliased by a rename; every source is crates.io;
#    every sourceless Cargo.lock entry is a member or third_party/ crate; no
#    workspace locks a patched version from the registry. It also parses the
#    [patch] and [replace] tables of every root and member manifest (only a
#    root's [patch.crates-io] with `{ path = third_party/<name> }` entries)
#    and every tracked .cargo/config (only build.target and
#    target.<triple>.rustflags). The exact bytes of every tracked
#    .cargo/config are pinned in .github/cargo-config.sha256.
#
# C. A second, textual layer over every tracked Cargo.toml and
#    .cargo/config[.toml], with comments and multi-line strings skipped and
#    quotes and spaces removed from table headers and keys:
#   - no table header or key starting with patch, replace, paths or source
#     (configs also: registries, registry, env, alias, and no key ending in
#     runner, linker, target-dir, rustc* or rustdoc*), except, in a workspace
#     root manifest (a Cargo.toml next to a tracked Cargo.lock), the exact
#     header `[patch.crates-io]` whose every entry is
#     `<name> = { path = "<to repo root>third_party/<name>" }`;
#   - no escape sequence (backslash) in a header or key.
#   Within the repository these are the places where cargo reads [patch],
#   [replace], [paths] and [source]. Cargo configuration outside the
#   checkout (CARGO_HOME, parent directories), environment variables and
#   --config flags are outside this gate.
#
# Trust (RT-TPGATE3/4): in CI this script, tools/tpgate, the waiver files and
# the cargo config pins run from a trusted revision (ci.yml job `gates`:
# the previous rebuild/core head for a push to rebuild/core, else the merge
# base with origin/rebuild/core; gates-trusted.yml: the pull request's base),
# extracted outside the checkout, in a job that runs no code of the commit
# under test. A commit that changes the gate is judged by the old gate; the
# new gate applies from the next commit. When no trusted revision has the
# gate yet (bootstrap), the commit's own copy runs with a warning. The
# allow-lists, manifests and patches are read from the commit under test
# (reviewed data); the cargo config pins from the trusted copy
# (CARGO_CONFIG_PINS overrides, for tests).
#
# The allow-list certifies itself: a commit may change a third_party/ crate
# and regenerate its patch and manifest together. The gate makes every such
# change visible and exact; human review of third_party/ diffs (a consensus
# path: consensus-gate.sh) is the control (SECURITY.md).
#
# After a reviewed change of a patched crate, stage it (git add), then:
#   bash .github/scripts/third-party-gate.sh --write <crate>
# which rewrites patches/<crate>.patch and patches/<crate>.sha256.
#
# Usage: third-party-gate.sh            check everything (from the repo)
#        third-party-gate.sh --selftest tampered fixtures must fail
#        third-party-gate.sh --write C  regenerate C's patch and manifest
# Environment: THIRD_PARTY_GATE_FETCH=1 always downloads (ignores the cache);
# TPGATE_TARGET_DIR reuses a tpgate build directory (local speed; default: a
# fresh one per run); TPGATE_DIR, CARGO_CONFIG_PINS: other checker and pins.
# Exit: 0 pass, 1 a check failed, 2 usage error.
set -euo pipefail
export LC_ALL=C

die() {
  echo "third-party-gate: $*" >&2
  exit 2
}

# annotate TITLE MESSAGE: a GitHub error annotation in CI, plain text elsewhere.
annotate() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    local m="${2//'%'/%25}"
    m="${m//$'\r'/}"
    m="${m//$'\n'/%0A}"
    echo "::error title=$1::$m"
  fi
  printf '%s\n%s\n' "$1" "$2" >&2
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

REGISTRY="registry+https://github.com/rust-lang/crates.io-index"

# toml_package_field FILE FIELD: the value of FIELD in the [package] table.
toml_package_field() {
  tr -d '\r' < "$1" | awk -v f="$2" '
    /^\[/ { inpkg = ($0 == "[package]"); next }
    inpkg && $1 == f && $2 == "=" { v = $3; gsub(/"/, "", v); print v; exit }'
}

# fetch_crate NAME VERSION: prints the path of the .crate file (unverified).
fetch_crate() {
  local name="$1" ver="$2" f c
  f="$name-$ver.crate"
  if [ "${THIRD_PARTY_GATE_FETCH:-0}" != "1" ]; then
    for c in "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$f"; do
      [ -f "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
  fi
  mkdir -p "$WORK/dl"
  if [ ! -f "$WORK/dl/$f" ]; then
    curl -fsSL --retry 3 --proto '=https' -o "$WORK/dl/$f.part" \
      "https://static.crates.io/crates/$name/$f" ||
      { echo "third-party-gate: download of $f failed" >&2; return 1; }
    mv "$WORK/dl/$f.part" "$WORK/dl/$f"
  fi
  printf '%s\n' "$WORK/dl/$f"
}

# crate_diff ROOT CRATE OUT: writes the normalized diff of ROOT/third_party/CRATE
# against its pinned pristine crate to OUT. Returns 1 (after an annotation) when
# the pristine crate cannot be obtained or verified.
crate_diff() {
  local root="$1" crate="$2" out="$3" tp name ver file want got d
  tp="$root/third_party"
  name="$(toml_package_field "$tp/$crate/Cargo.toml" name)"
  ver="$(toml_package_field "$tp/$crate/Cargo.toml" version)"
  if [ -z "$name" ] || [ -z "$ver" ] || [ "$name" != "$crate" ]; then
    annotate "third-party crate $crate: bad Cargo.toml" \
      "third_party/$crate/Cargo.toml must have [package] name = \"$crate\" and a version (got '$name' '$ver')."
    return 1
  fi
  want="$(tr -d '\r' < "$tp/PRISTINE.sha256" | awk -v f="$name-$ver.crate" '$2 == f { print $1 }')"
  if [ -z "$want" ]; then
    annotate "third-party crate $crate: no pinned pristine checksum" \
      "third_party/PRISTINE.sha256 has no line for $name-$ver.crate (sha256 of the published crate, as in Cargo.lock before the patch)."
    return 1
  fi
  file="$(fetch_crate "$name" "$ver")" || {
    annotate "third-party crate $crate: pristine crate unavailable" "Could not obtain $name-$ver.crate."
    return 1
  }
  got="$(sha256sum < "$file" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    annotate "third-party crate $crate: pristine checksum mismatch" \
      "$name-$ver.crate has sha256 $got, third_party/PRISTINE.sha256 pins $want."
    return 1
  fi
  d="$WORK/diff-$crate"
  rm -rf "$d"
  mkdir -p "$d/x" "$d/b"
  tar -xzf "$file" -C "$d/x"
  [ -d "$d/x/$name-$ver" ] || { annotate "third-party crate $crate: unexpected .crate layout" "$name-$ver.crate has no $name-$ver/ directory."; return 1; }
  mv "$d/x/$name-$ver" "$d/a"
  rm -f "$d/a/Cargo.toml.orig" "$d/a/.cargo_vcs_info.json" "$d/a/Cargo.lock"
  cp -R "$tp/$crate/." "$d/b/"
  rm -f "$d/b/.cargo-ok"
  # diff exits 1 when the trees differ; only >1 is an error.
  (cd "$d" && diff -a -ruN --strip-trailing-cr a b) > "$d/raw" || [ "$?" = 1 ] ||
    { annotate "third-party crate $crate: diff failed" "diff -ruN failed for third_party/$crate."; return 1; }
  tr -d '\r' < "$d/raw" | sed -E 's/^(---|\+\+\+) ([^\t]*)\t.*$/\1 \2/' > "$out"
}

# crate_manifest ROOT CRATE: "sha256 mode path" of every tracked file of the
# crate, from the index bytes (no line-ending conversion), path relative to it.
crate_manifest() {
  local root="$1" crate="$2" meta path mode sha h
  git -C "$root" -c core.quotepath=false ls-files -s -- "third_party/$crate" |
    while IFS=$'\t' read -r meta path; do
      read -r mode sha _ <<< "$meta"
      h="$(git -C "$root" cat-file blob "$sha" | sha256sum | cut -d' ' -f1)"
      printf '%s %s %s\n' "$h" "$mode" "${path#third_party/"$crate"/}"
    done
}

# first_file PATCH LINE: the file named by the last diff header at or before LINE.
first_file() {
  awk -v n="$2" 'NR > n { exit } /^diff / { f = $NF; sub(/^b\//, "", f) } END { print f }' "$1"
}

# crates ROOT: the crate directories under ROOT/third_party, one per line.
crates() {
  local d
  for d in "$1"/third_party/*/; do
    [ -f "$d/Cargo.toml" ] && basename "$d"
  done
  return 0
}

# patch_rules CRATE PATCH: 0 when the patch has no opaque binary hunk, adds no
# build script, and no added line trips the escape lint. The lint is a
# reviewer aid, not a guarantee: code can reach outside the diff in ways no
# regular expression sees (third_party/README.md).
patch_rules() {
  local crate="$1" p="$2" hit
  if grep -q '^Binary files ' "$p"; then
    annotate "third-party crate $crate: binary difference" \
      "The diff of third_party/$crate has a 'Binary files ... differ' line; every change must be reviewable text."
    return 1
  fi
  hit="$(grep -a -n -E '^(diff .* b/(.*/)?build\.rs|\+\+\+ b/(.*/)?build\.rs)$' "$p" | head -1 || true)"
  if [ -n "$hit" ]; then
    annotate "third-party crate $crate: build script changed" \
      "third_party/patches/$crate.patch adds or changes a build.rs (line ${hit%%:*}); a patched crate may not run build code."
    return 1
  fi
  # Added lines only ("+", not the "+++ " file header).
  hit="$(grep -a -n -E '^\+([^+]|\+[^+]|\+\+[^ ]|$)' "$p" |
    grep -a -E 'include[A-Za-z0-9_]*[[:space:]]*!|#!?[[:space:]]*\[.*path|(^|[^A-Za-z0-9_])path[[:space:]]*=|(^|["/\])\.\.($|["/\])|^[0-9]+:\+[[:space:]]*(build|proc-macro|links)[[:space:]]*=' |
    head -1 || true)"
  if [ -n "$hit" ]; then
    annotate "third-party crate $crate: patch trips the escape lint" \
      "third_party/patches/$crate.patch line ${hit%%:*} adds an include*! macro, a path attribute or key, a .. path segment or a build/proc-macro/links key. Not allowed in a patched crate (third_party/README.md)."
    return 1
  fi
}

# check_bytes ROOT: every tracked file under third_party/ is control-free text
# (no NUL or other C0/DEL byte except TAB, LF and CR), so git and GitHub show
# every change as a text diff; except the files third_party/BINARY-ALLOWLIST
# names (path and reason), which must exist.
check_bytes() {
  local root="$1" bad=0 meta path sha n allow
  allow="$root/third_party/BINARY-ALLOWLIST"
  [ -f "$allow" ] || { annotate "third-party gate: no BINARY-ALLOWLIST" "third_party/BINARY-ALLOWLIST is missing."; return 1; }
  tr -d '\r' < "$allow" | awk '!/^#/ && NF { print $1 }' > "$WORK/binary-allow"
  while IFS= read -r path; do
    git -C "$root" ls-files --error-unmatch -- "$path" > /dev/null 2>&1 || {
      annotate "third-party gate: stale BINARY-ALLOWLIST entry" "third_party/BINARY-ALLOWLIST names $path, which is not a tracked file."
      bad=1
    }
    local c="${path#third_party/}"; c="${c%%/*}"
    case "$path" in
      third_party/patches/* | third_party/upstream/*) c="" ;;
      third_party/*/*) [ -f "$root/third_party/$c/Cargo.toml" ] || c="" ;;
      *) c="" ;;
    esac
    if [ -z "$c" ]; then
      annotate "third-party gate: BINARY-ALLOWLIST outside a crate" "$path: only files inside a third_party/<crate>/ directory (not patches/, upstream/ or top-level files) may be binary."
      bad=1
    fi
  done < "$WORK/binary-allow"
  while IFS=$'\t' read -r meta path; do
    read -r _ sha _ <<< "$meta"
    n="$(git -C "$root" cat-file blob "$sha" | tr -d '\011\012\015\040-\176\200-\377' | head -c 1 | wc -c)"
    [ "$n" = 0 ] && continue
    grep -Fqx -- "$path" "$WORK/binary-allow" && continue
    annotate "third-party gate: control bytes in $path" \
      "$path has a NUL or other control byte, so git and GitHub may show it and its patch as binary. Remove it, or list the file in third_party/BINARY-ALLOWLIST with the reason (a reviewed change)."
    bad=1
  done < <(git -C "$root" -c core.quotepath=false ls-files -s -- third_party)
  return "$bad"
}

# binary_pristine ROOT CRATE: every BINARY-ALLOWLIST file of CRATE has the
# same bytes as in the published crate (unpacked by crate_diff), so the
# allow-list can only admit upstream's own binary files.
binary_pristine() {
  local root="$1" crate="$2" path rel want got bad=0
  while IFS= read -r path; do
    case "$path" in "third_party/$crate/"*) ;; *) continue ;; esac
    rel="${path#third_party/"$crate"/}"
    got="$(git -C "$root" cat-file blob ":$path" | sha256sum | cut -d' ' -f1)"
    if [ -f "$WORK/diff-$crate/a/$rel" ]; then
      want="$(sha256sum < "$WORK/diff-$crate/a/$rel" | cut -d' ' -f1)"
    else
      want="(not in the published crate)"
    fi
    if [ "$got" != "$want" ]; then
      annotate "third-party gate: allow-listed binary differs from the published crate" \
        "$path has sha256 $got; the published crate's copy: $want. BINARY-ALLOWLIST admits only upstream's unchanged files."
      bad=1
    fi
  done < "$WORK/binary-allow"
  return "$bad"
}

# check_tree ROOT: section A. 0 when every crate matches its allow-list.
check_tree() {
  local root="$1" tp="$1/third_party" bad=0 crate exp act first n p line dirty
  [ -f "$tp/PRISTINE.sha256" ] || { annotate "third-party gate: no PRISTINE.sha256" "third_party/PRISTINE.sha256 is missing."; return 1; }
  check_bytes "$root" || bad=1
  check_attributes "$root" || bad=1
  n=0
  for crate in $(crates "$root"); do
    n=$((n + 1))
    exp="$tp/patches/$crate.patch"
    if [ ! -f "$exp" ] || [ ! -f "$tp/patches/$crate.sha256" ]; then
      annotate "third-party crate $crate: no allow-list" \
        "third_party/patches/$crate.patch and $crate.sha256 are required for every patched crate (third-party-gate.sh --write $crate)."
      bad=1
      continue
    fi
    # Working tree against the index: modified or untracked files.
    dirty="$({ git -C "$root" -c core.quotepath=false diff --name-only -- "third_party/$crate"
      git -C "$root" -c core.quotepath=false ls-files --others --exclude-standard -- "third_party/$crate"; } | head -3)"
    if [ -n "$dirty" ]; then
      annotate "third-party crate $crate: uncommitted changes" \
        "third_party/$crate differs from the index (commit or stage first): $dirty"
      bad=1
      continue
    fi
    crate_manifest "$root" "$crate" > "$WORK/$crate.manifest"
    if ! tr -d '\r' < "$tp/patches/$crate.sha256" | cmp -s - "$WORK/$crate.manifest"; then
      first="$(tr -d '\r' < "$tp/patches/$crate.sha256" | diff - "$WORK/$crate.manifest" | grep -m1 '^[<>]' | awk '{ print $NF }' || true)"
      annotate "third-party crate $crate differs from its file manifest" \
        "third_party/$crate does not match third_party/patches/$crate.sha256; first differing file: ${first:-?}. Review the change, then regenerate with third-party-gate.sh --write $crate."
      bad=1
      continue
    fi
    act="$WORK/$crate.actual"
    crate_diff "$root" "$crate" "$act" || { bad=1; continue; }
    binary_pristine "$root" "$crate" || { bad=1; continue; }
    tr -d '\r' < "$exp" > "$WORK/$crate.expected"
    if ! cmp -s "$WORK/$crate.expected" "$act"; then
      line="$(diff -a "$WORK/$crate.expected" "$act" | head -1 || true)"
      # "LcR", "LaR", "LdR" (ranges allowed): the first differing line on each side.
      p="${line#*[acd]}"; p="${p%%,*}"
      first="$(first_file "$act" "$p")"
      [ -n "$first" ] || { p="${line%%[acd,]*}"; first="$(first_file "$WORK/$crate.expected" "$p")"; }
      annotate "third-party crate $crate differs from its allow-listed patch" \
        "third_party/$crate is not the published crate plus third_party/patches/$crate.patch; first differing file: ${first:-?}. Review the change, then regenerate with third-party-gate.sh --write $crate."
      bad=1
      continue
    fi
    patch_rules "$crate" "$act" || { bad=1; continue; }
    echo "ok   third_party/$crate: published crate + patches/$crate.patch ($(grep -c '^diff ' "$act" || true) files changed, $(wc -l < "$WORK/$crate.manifest") files pinned)"
  done
  # Stale allow-list entries: a patch, manifest or pinned checksum without a crate.
  for p in "$tp"/patches/*; do
    [ -f "$p" ] || continue
    crate="$(basename "$p")"
    case "$crate" in
      *.patch) crate="${crate%.patch}" ;;
      *.sha256) crate="${crate%.sha256}" ;;
      *) annotate "third-party gate: unexpected file" "third_party/patches/$crate is neither a .patch nor a .sha256 file."; bad=1; continue ;;
    esac
    [ -f "$tp/$crate/Cargo.toml" ] || {
      annotate "third-party gate: stale allow-list file" "third_party/patches/$(basename "$p") has no third_party/$crate crate; remove it with the crate."
      bad=1
    }
  done
  while read -r _ p; do
    [ -n "$p" ] || continue
    crate="$(printf '%s\n' "$p" | sed -E 's/-[0-9]+\.[0-9]+\.[0-9]+[^/]*\.crate$//')"
    [ -f "$tp/$crate/Cargo.toml" ] || {
      annotate "third-party gate: stale PRISTINE.sha256 line" "third_party/PRISTINE.sha256 pins $p but there is no third_party/$crate crate."
      bad=1
    }
  done < <(tr -d '\r' < "$tp/PRISTINE.sha256" | grep -v '^#' || true)
  echo "third-party-gate: $n crates checked, $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

# Path crates outside every workspace that path dependencies may name
# (blacksilk-tpgate --standalone: no dependency tables allowed). Changing this
# list is a reviewed change of the gate.
STANDALONE=(zkvm/sdk)

# The checker: tools/tpgate next to this script (in CI, the trusted copy, not
# the checkout under test). Built and run with the working directory outside
# any repository, so no repository .cargo/config or rust-toolchain file is
# read; RUSTUP_TOOLCHAIN defaults to the installed stable.
TPGATE_DIR="${TPGATE_DIR:-$(cd "$here/../.." && pwd)/tools/tpgate}"
TPGATE_BIN=""

tpgate_build() {
  [ -z "$TPGATE_BIN" ] || return 0
  [ -f "$TPGATE_DIR/Cargo.toml" ] && [ -f "$TPGATE_DIR/Cargo.lock" ] ||
    { annotate "third-party gate: no checker" "$TPGATE_DIR has no standalone tools/tpgate (Cargo.toml and Cargo.lock)."; return 1; }
  # A fresh target directory per run (RT-TPGATE4: never a fixed, shared path
  # that other code could have planted a binary in); TPGATE_TARGET_DIR
  # overrides it for local speed.
  local td="${TPGATE_TARGET_DIR:-$WORK/tpgate-target}" out
  out="$(cd "$WORK" && RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" \
    cargo build -q --locked --manifest-path "$TPGATE_DIR/Cargo.toml" --target-dir "$td" 2>&1)" ||
    { annotate "third-party gate: building tools/tpgate failed" "$out"; return 1; }
  TPGATE_BIN="$td/debug/blacksilk-tpgate"
  [ -f "$TPGATE_BIN" ] || TPGATE_BIN="$TPGATE_BIN.exe"
}

# cargo_configs ROOT: the tracked cargo configuration files.
cargo_configs() {
  git -C "$1" -c core.quotepath=false ls-files -- '.cargo/config' '.cargo/config.toml' \
    '*/.cargo/config' '*/.cargo/config.toml'
}

# check_identity ROOT: section B, by tools/tpgate.
check_identity() {
  local root="$1" out rc lock s
  local -a roots=() sa=() cfg=()
  while IFS= read -r lock; do
    roots+=("$(dirname "$lock")")
  done < <(git -C "$root" ls-files -- Cargo.lock '*/Cargo.lock')
  [ "${#roots[@]}" -gt 0 ] || { annotate "third-party gate: no Cargo.lock" "No tracked Cargo.lock under $root."; return 1; }
  for s in "${STANDALONE[@]}"; do
    [ -f "$root/$s/Cargo.toml" ] && sa+=("$s")
  done
  while IFS= read -r s; do cfg+=("$s"); done < <(cargo_configs "$root")
  tpgate_build || return 1
  rc=0
  out="$(cd "$WORK" && RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" \
    "$TPGATE_BIN" "$root" "${roots[@]}" ${sa[@]+--standalone "${sa[@]}"} ${cfg[@]+--config "${cfg[@]}"} 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then
    printf '%s\n' "$out"
    return 0
  fi
  annotate "third-party gate: dependency identity (tools/tpgate)" "$out"
  return 1
}

# check_config_pins ROOT PINS: every tracked cargo configuration file of ROOT
# has its sha256 (committed bytes) and path listed in PINS. In CI, PINS is the
# TRUSTED revision's .github/cargo-config.sha256 (RT-TPGATE4), so a commit
# cannot pin its own config change: a new or changed config needs the pin
# merged first, in its own change, then the config. Extra pin lines (an old
# and a new hash during that transition) are allowed.
check_config_pins() {
  local root="$1" pins="$2" f h
  [ -f "$pins" ] || { annotate "third-party gate: no config pins" "$pins is missing."; return 1; }
  tr -d '\r' < "$pins" | grep -v '^#' | sed '/^$/d' | sort -u > "$WORK/config-pins.expected"
  while IFS= read -r f; do
    h="$(git -C "$root" cat-file blob ":$f" | sha256sum | cut -d' ' -f1)"
    printf '%s  %s\n' "$h" "$f"
  done < <(cargo_configs "$root") | sort > "$WORK/config-pins.actual"
  f="$(comm -23 "$WORK/config-pins.actual" "$WORK/config-pins.expected" | head -4)"
  if [ -n "$f" ]; then
    annotate "third-party gate: cargo configuration not pinned" \
      "These tracked .cargo/config files are not in the trusted .github/cargo-config.sha256:
$f
Merge the reviewed pin first (a consensus path), then the config change."
    return 1
  fi
}

# check_attributes ROOT: git shows every third_party/ file as text (diff set),
# except BINARY-ALLOWLIST entries; no .gitattributes inside third_party/.
check_attributes() {
  local root="$1" bad=0 p
  p="$(git -C "$root" ls-files -- 'third_party/.gitattributes' 'third_party/*/.gitattributes' | head -1)"
  if [ -n "$p" ]; then
    annotate "third-party gate: .gitattributes inside third_party/" "$p: attributes for third_party/ live only in the root .gitattributes."
    bad=1
  fi
  [ -f "$WORK/binary-allow" ] || : > "$WORK/binary-allow"
  p="$(git -C "$root" -c core.quotepath=false ls-files -- third_party |
    git -C "$root" check-attr --stdin diff | awk -F': ' '$3 != "set" { print $1 }' |
    grep -Fvx -f "$WORK/binary-allow" | head -3 || true)"
  if [ -n "$p" ]; then
    annotate "third-party gate: third_party/ file not diffed as text" \
      "git check-attr diff is not 'set' for: $p (the root .gitattributes must keep 'third_party/** diff')."
    bad=1
  fi
  return "$bad"
}

# toml_events KIND PREFIX: a TOML file on stdin; prints one line per problem.
# KIND is "manifest" (PREFIX set: a workspace root, whose canonical
# [patch.crates-io] is allowed with paths "<PREFIX>third_party/<name>") or
# "config". Comments, strings and multi-line strings are skipped.
toml_events() {
  tr -d '\r' | awk -v kind="$1" -v prefix="$2" -v root="$3" '
    function forbidden(s,   f, l) {
      f = s; sub(/\..*/, "", f)
      if (f == "patch" || f == "replace" || f == "paths" || f == "source") return 1
      if (kind == "config" && (f == "registries" || f == "registry" || f == "env" || f == "alias")) return 1
      l = s; sub(/.*[.]/, "", l)
      if (kind == "config" && (l == "runner" || l == "linker" || l == "target-dir" || l ~ /^rustc/ || l ~ /^rustdoc/)) return 1
      return 0
    }
    {
      raw = $0
      if (ml != "") { if (index(raw, ml)) ml = ""; next }
      # Strip comments and find the first "=" outside strings.
      out = ""; st = ""; eq = 0; L = length(raw)
      for (i = 1; i <= L; i++) {
        c = substr(raw, i, 1)
        if (st == "") {
          if (c == "#") break
          if (substr(raw, i, 3) == "\"\"\"" || substr(raw, i, 3) == "'\'''\'''\''") {
            d = substr(raw, i, 3)
            rest = substr(raw, i + 3)
            if (index(rest, d)) { out = out d "S" d; i = i + 2 + index(rest, d) + 2; continue }
            ml = d; out = out d; break
          }
          if (c == "\"" || c == "'\''") st = c
          else if (c == "=" && eq == 0) eq = length(out) + 1
          out = out c
        } else {
          if (st == "\"" && c == "\\") { out = out c substr(raw, i + 1, 1); i++; continue }
          if (c == st) st = ""
          out = out c
        }
      }
      line = out; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      if (line == "") next
      if (substr(line, 1, 1) == "[") {
        h = line; gsub(/[][ \t"'\'']/, "", h)
        if (index(line, "\\")) { print "escape in table header: " line; inpatch = 0; next }
        if (line == "[patch.crates-io]" && kind == "manifest" && root == "1") { inpatch = 1; next }
        inpatch = 0
        if (forbidden(h)) print "table: " line
        next
      }
      if (eq == 0) next
      k = substr(out, 1, eq - 1); gsub(/[ \t"'\'']/, "", k)
      if (index(k, "\\")) { print "escape in key: " line; next }
      if (inpatch) {
        n = k
        want = n " = { path = \"" prefix "third_party/" n "\" }"
        if (line != want || n !~ /^[A-Za-z0-9_-]+$/) print "non-canonical [patch.crates-io] entry: " line
        next
      }
      if (forbidden(k)) print "key: " line
    }'
}

# check_cargo_files ROOT: section C.
check_cargo_files() {
  local root="$1" bad=0 f dir prefix isroot ev
  while IFS= read -r f; do
    case "$f" in
      Cargo.toml | */Cargo.toml)
        dir="$(dirname "$f")"
        prefix=""; isroot=0
        if [ "$dir" = . ]; then
          [ -n "$(git -C "$root" ls-files -- Cargo.lock)" ] && isroot=1
        else
          [ -n "$(git -C "$root" ls-files -- "$dir/Cargo.lock")" ] && isroot=1
          prefix="$(printf '%s\n' "$dir" | sed -E 's#[^/]+#..#g')/"
        fi
        ev="$(toml_events manifest "$prefix" "$isroot" < "$root/$f")"
        ;;
      *) ev="$(toml_events config "" 0 < "$root/$f")" ;;
    esac
    if [ -n "$ev" ]; then
      annotate "third-party gate: cargo source redirection in $f" \
        "$(printf '%s' "$ev" | head -3)
Only a workspace root's exact [patch.crates-io] with { path = \"<to root>third_party/<name>\" } entries may redirect a crate (third_party/README.md)."
      bad=1
    fi
  done < <(git -C "$root" -c core.quotepath=false ls-files -- Cargo.toml '*/Cargo.toml' \
    '.cargo/config' '.cargo/config.toml' '*/.cargo/config' '*/.cargo/config.toml')
  return "$bad"
}

# write_allowlist ROOT CRATE: regenerate the crate's patch and manifest.
write_allowlist() {
  local root="$1" crate="$2"
  mkdir -p "$root/third_party/patches"
  crate_diff "$root" "$crate" "$root/third_party/patches/$crate.patch" || return 1
  crate_manifest "$root" "$crate" > "$root/third_party/patches/$crate.sha256"
}

# fixture_repo DIR: an empty git repository that converts nothing.
fixture_repo() {
  mkdir -p "$1"
  git -C "$1" init -q .
  git -C "$1" config core.autocrlf false
  git -C "$1" config user.email selftest@invalid
  git -C "$1" config user.name selftest
}

selftest() {
  local root bad=0 crate f t r
  root="$(git rev-parse --show-toplevel)"
  crate="$(crates "$root" | sed -n 1p)"
  [ -n "$crate" ] || die "selftest: no crate under third_party/"
  # A: a fixture repository holding the index copy of third_party/.
  run_case() { # NAME EXPECT(0|1) [nostage]
    t="$WORK/st-$1"
    fixture_repo "$t"
    git -C "$root" ls-files -z -- third_party .gitattributes |
      (cd "$root" && xargs -0 git -c core.autocrlf=false checkout-index --prefix="$t/" --)
    git -C "$t" add -A
    "tamper_$1" "$t"
    [ "${3:-}" = nostage ] || git -C "$t" add -A
    if check_tree "$t" > "$WORK/st.log" 2>&1; then r=0; else r=1; fi
    if [ "$r" = "$2" ]; then
      echo "selftest ok   $1 (exit $r)"
    else
      echo "selftest FAIL $1: expected exit $2, got $r"; sed 's/^/  /' "$WORK/st.log"; bad=1
    fi
  }
  src1() { find "$1/third_party/$crate/src" -name '*.rs' | sort | sed -n 1p; }
  tamper_clean() { :; }
  tamper_edit() { printf '// tampered\n' >> "$(src1 "$1")"; }
  tamper_unstaged() { printf '// tampered\n' >> "$(src1 "$1")"; }
  tamper_untracked() { printf 'x\n' > "$1/third_party/$crate/src/extra.rs"; }
  tamper_newfile() { printf 'x\n' > "$1/third_party/$crate/src/extra.rs"; }
  tamper_delfile() { rm -f "$1/third_party/$crate/README.md"; }
  tamper_pkgfile() { printf 'x\n' > "$1/third_party/$crate/Cargo.toml.orig"; }
  tamper_pin() { sed -i.bak "s/^[0-9a-f]\{4\}/0000/" "$1/third_party/PRISTINE.sha256"; rm -f "$1/third_party/PRISTINE.sha256.bak"; }
  tamper_nopatch() { rm -f "$1/third_party/patches/$crate.patch"; }
  tamper_nomanifest() { rm -f "$1/third_party/patches/$crate.sha256"; }
  tamper_stale() { cp "$1/third_party/patches/$crate.patch" "$1/third_party/patches/no-such-crate.patch"; }
  tamper_crlf() { f="$(src1 "$1")"; sed -i.bak 's/$/\r/' "$f"; rm -f "$f.bak"; }
  tamper_mode() { git -C "$1" update-index --chmod=+x "third_party/$crate/README.md"; }
  # A NUL byte, accepted into the allow-list by a regeneration, then a later
  # edit of the same file: must still fail (diff -a, and the manifest).
  tamper_nul_regen() {
    f="$(src1 "$1")"; printf '// \000 nul\n' >> "$f"
    git -C "$1" add -A; write_allowlist "$1" "$crate" > /dev/null
  }
  tamper_nul_then_edit() {
    tamper_nul_regen "$1"; git -C "$1" add -A
    printf '// edited after the NUL\n' >> "$f"
  }
  tamper_include() {
    f="$(src1 "$1")"; printf 'const X: &str = include_str!("../../secret");\n' >> "$f"
    git -C "$1" add -A; write_allowlist "$1" "$crate" > /dev/null
  }
  regen() { git -C "$1" add -A; write_allowlist "$1" "$crate" > /dev/null; }
  tamper_nul_patchfile() { printf '\000\n' >> "$1/third_party/patches/$crate.patch"; }
  tamper_nul_readme() { printf '\001\n' >> "$1/third_party/README.md"; }
  tamper_binary_stale() { printf 'third_party/%s/no-such.bin  test\n' "$crate" >> "$1/third_party/BINARY-ALLOWLIST"; }
  tamper_include_spaced() { printf 'const X: &str = include_str !("x");\n' >> "$(src1 "$1")"; regen "$1"; }
  tamper_cfg_attr_path() { printf '#[cfg_attr(all(), path = "x.rs")]\nmod m;\n' >> "$(src1 "$1")"; regen "$1"; }
  tamper_dotdot() { printf 'const P: &str = "..";\n' >> "$(src1 "$1")"; regen "$1"; }
  tamper_build_rs() { printf 'fn main() {}\n' > "$1/third_party/$crate/build.rs"; regen "$1"; }
  tamper_build_key() { sed -i.bak 's/^build = false/build = "b.rs"/' "$1/third_party/$crate/Cargo.toml"; rm -f "$1/third_party/$crate/Cargo.toml.bak"; regen "$1"; }
  tamper_attr_nested() { printf '* -diff\n' > "$1/third_party/.gitattributes"; }
  tamper_attr_root() { printf 'third_party/%s/** -diff\n' "$crate" >> "$1/.gitattributes"; }
  allow() { printf '%s  selftest\n' "$2" >> "$1/third_party/BINARY-ALLOWLIST"; }
  # The patched source file differs from the published crate.
  tamper_binary_changed() {
    allow "$1" "third_party/$crate/$(sed -n 's#^+++ b/##p' "$1/third_party/patches/$crate.patch" | sed -n 1p)"
  }
  tamper_binary_unchanged() { allow "$1" "third_party/$crate/README.md"; }
  tamper_binary_patchdir() { allow "$1" "third_party/patches/$crate.patch"; }
  tamper_binary_upstream() {
    allow "$1" "$(git -C "$1" ls-files -- third_party/upstream | sed -n 1p)"
  }
  run_case clean 0
  run_case edit 1
  run_case unstaged 1 nostage
  run_case untracked 1 nostage
  run_case newfile 1
  run_case delfile 1
  run_case pkgfile 1
  run_case pin 1
  run_case nopatch 1
  run_case nomanifest 1
  run_case stale 1
  run_case crlf 1
  run_case mode 1
  run_case nul_regen 1
  run_case nul_patchfile 1
  run_case nul_readme 1
  run_case binary_stale 1
  run_case include_spaced 1
  run_case cfg_attr_path 1
  run_case dotdot 1
  run_case build_rs 1
  run_case build_key 1
  run_case nul_then_edit 1
  run_case include 1
  # RT-TPGATE3: attributes and the binary allow-list.
  run_case attr_nested 1
  run_case attr_root 1
  run_case binary_changed 1
  run_case binary_unchanged 0
  run_case binary_patchdir 1
  run_case binary_upstream 1

  # An allow-listed binary file passes the byte check (it must also be
  # unchanged from the published crate, or its bytes reach the patch file).
  t="$WORK/st-binary-allowed"
  fixture_repo "$t"
  mkdir -p "$t/third_party/c/tests"
  printf 'x\000y' > "$t/third_party/c/tests/fixture.bin"
  printf '[package]\nname = "c"\nversion = "1.0.0"\n' > "$t/third_party/c/Cargo.toml"
  printf '# path  reason\nthird_party/c/tests/fixture.bin  selftest fixture\n' > "$t/third_party/BINARY-ALLOWLIST"
  git -C "$t" add -A
  if check_bytes "$t" > "$WORK/st.log" 2>&1; then
    echo "selftest ok   binary_allowlisted (exit 0)"
  else
    echo "selftest FAIL binary_allowlisted"; sed 's/^/  /' "$WORK/st.log"; bad=1
  fi

  # B and C: synthetic workspaces, checked by tools/tpgate and the text scan.
  local reg="$REGISTRY" n=0
  pkg() { # DIR NAME [EXTRA]: a crate with a library target
    mkdir -p "$1/src"; : > "$1/src/lib.rs"
    printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n%s' "$2" "${4:-0.1.0}" "${3:-}" > "$1/Cargo.toml"
  }
  res_case() { # NAME EXPECT(0|1) SETUP-FN
    n=$((n + 1))
    t="$WORK/rs-$n"
    fixture_repo "$t"
    pkg "$t/third_party/p3-x" p3-x "" 1.0.0
    printf '[workspace]\nmembers = ["a"]\nresolver = "2"\n\n[patch.crates-io]\np3-x = { path = "third_party/p3-x" }\n' > "$t/Cargo.toml"
    pkg "$t/a" blacksilk-a
    printf 'version = 4\n\n[[package]]\nname = "blacksilk-a"\nversion = "0.1.0"\n\n[[package]]\nname = "p3-x"\nversion = "1.0.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "%s"\nchecksum = "00"\n' "$reg" > "$t/Cargo.lock"
    "$3" "$t"
    git -C "$t" add -A
    r=0
    check_identity "$t" > "$WORK/st.log" 2>&1 || r=1
    check_cargo_files "$t" >> "$WORK/st.log" 2>&1 || r=1
    if [ "$r" = "$2" ]; then
      echo "selftest ok   $1 (exit $r)"
    else
      echo "selftest FAIL $1: expected exit $2, got $r"; sed 's/^/  /' "$WORK/st.log"; bad=1
    fi
  }
  addlock() { printf '\n[[package]]\nname = "%s"\nversion = "%s"\n%s' "$2" "$3" "${4:+source = \"$4\"
}" >> "$1/Cargo.lock"; }
  setroot() { printf '%s\n' "$2" > "$1/Cargo.toml"; }
  s_clean() { :; }
  s_git() { addlock "$1" rand 0.8.5 "git+https://example.invalid/rand#abc"; }
  s_altreg() { addlock "$1" rand 0.8.5 "registry+https://example.invalid/index"; }
  s_pathrogue() { addlock "$1" serde-fork 1.0.0; }
  s_bypass() { addlock "$1" p3-x 1.0.0 "$reg"; }
  s_bypass_othver() { addlock "$1" p3-x 0.9.0 "$reg"; }
  # A second copy as a workspace member, written without spaces.
  s_dupe() {
    mkdir -p "$1/vendor/p3-x/src"; : > "$1/vendor/p3-x/src/lib.rs"
    printf "[package]\nname='p3-x'\nversion=\"1.0.0\"\nedition=\"2021\"\n" > "$1/vendor/p3-x/Cargo.toml"
    setroot "$1" $'[workspace]\nmembers = ["a", "vendor/p3-x"]\nresolver = "2"\n\n[patch.crates-io]\np3-x = { path = "third_party/p3-x" }'
  }
  # p3-x = { package = "blacksilk-fri", path = "../evil" }: a renamed path copy.
  s_rename() {
    pkg "$1/evil" blacksilk-fri
    pkg "$1/a" blacksilk-a $'[dependencies]\np3-x = { package = "blacksilk-fri", path = "../evil" }\n'
    addlock "$1" blacksilk-fri 0.1.0
  }
  # An ordinary path dependency on a crate outside every workspace (cargo makes
  # a path crate under the workspace root a member, unless excluded).
  s_outside() {
    setroot "$1" $'[workspace]\nmembers = ["a"]\nexclude = ["vendor"]\nresolver = "2"\n\n[patch.crates-io]\np3-x = { path = "third_party/p3-x" }'
    pkg "$1/vendor/util" blacksilk-util
    pkg "$1/a" blacksilk-a $'[dependencies]\nblacksilk-util = { path = "../vendor/util" }\n'
    addlock "$1" blacksilk-util 0.1.0
  }
  s_spaced() { setroot "$1" $'[ patch.crates-io ]\np3-x = { path = "vendor/p3-x" }'; }
  s_quoted() { setroot "$1" $'["patch".crates-io]\np3-x = { path = "vendor/p3-x" }'; }
  s_bare() { setroot "$1" $'[patch]\ncrates-io.p3-x = { path = "vendor/p3-x" }'; }
  s_dotted() { setroot "$1" $'patch.crates-io.p3-x.path = "vendor/p3-x"\n[workspace]'; }
  s_inline() { setroot "$1" $'patch = { crates-io = { p3-x = { path = "vendor/p3-x" } } }'; }
  s_escape() { setroot "$1" $'"\\u0070atch".crates-io.p3-x.path = "vendor/p3-x"'; }
  s_replace() { setroot "$1" $'[replace]\n"p3-x:1.0.0" = { path = "vendor/p3-x" }'; }
  s_gitpatch() { setroot "$1" $'[patch.crates-io]\np3-x = { git = "https://example.invalid/p3" }'; }
  s_otherpath() { setroot "$1" $'[patch.crates-io]\np3-x = { path = "vendor/p3-x" }'; }
  s_renamed() { setroot "$1" $'[patch.crates-io]\np3-x = { path = "third_party/p3-y" }'; }
  s_urlpatch() { setroot "$1" $'[patch."https://github.com/x/y"]\np3-x = { path = "third_party/p3-x" }'; }
  s_nonroot() { printf '[package]\nname = "blacksilk-a"\nversion = "0.1.0"\n\n[patch.crates-io]\np3-x = { path = "../third_party/p3-x" }\n' > "$1/a/Cargo.toml"; }
  s_comment() { setroot "$1" $'[workspace] # [patch.evil]\nmembers = ["a"] # patch = 1\n# [patch.crates-io]\ndescription = """\n[patch.crates-io]\n"""\n\n[patch.crates-io]\np3-x = { path = "third_party/p3-x" }'; }
  s_cfg_paths() { mkdir -p "$1/.cargo"; printf 'paths = ["vendor/p3-x"]\n' > "$1/.cargo/config.toml"; }
  s_cfg_source() { mkdir -p "$1/a/.cargo"; printf '[source.crates-io]\nreplace-with = "v"\n' > "$1/a/.cargo/config.toml"; }
  s_cfg_patch() { mkdir -p "$1/.cargo"; printf '[patch.crates-io]\np3-x = { path = "third_party/p3-x" }\n' > "$1/.cargo/config"; }
  s_cfg_ok() { mkdir -p "$1/.cargo"; printf '[build]\ntarget = "riscv32i-unknown-none-elf"\n[target.x86_64-pc-windows-msvc]\nrustflags = ["-C", "link-arg=-Brepro"]\n' > "$1/.cargo/config.toml"; }
  s_cfg_flags() { mkdir -p "$1/.cargo"; printf '[target.x86_64-pc-windows-msvc]\nrustflags = ["-C", "link-arg=-Brepro", "-C", "link-arg=/evil"]\n' > "$1/.cargo/config.toml"; }
  s_cfg_runner() { mkdir -p "$1/.cargo"; printf '[target.x]\nrunner = "evil"\n' > "$1/.cargo/config.toml"; }
  s_cfg_wrapper() { mkdir -p "$1/.cargo"; printf '[build]\nrustc-wrapper = "evil"\n' > "$1/.cargo/config.toml"; }
  s_cfg_linker() { mkdir -p "$1/a/.cargo"; printf '[target.x]\nlinker = "evil"\n' > "$1/a/.cargo/config.toml"; }
  s_cfg_env() { mkdir -p "$1/.cargo"; printf '[env]\nRUSTC_BOOTSTRAP = "1"\n' > "$1/.cargo/config.toml"; }
  s_cfg_targetdir() { mkdir -p "$1/.cargo"; printf '[build]\ntarget-dir = "x"\n' > "$1/.cargo/config"; }
  res_case "resolution clean" 0 s_clean
  res_case "lock: git source" 1 s_git
  res_case "lock: other registry" 1 s_altreg
  res_case "lock: unknown path crate" 1 s_pathrogue
  res_case "lock: registry copy of a patched crate" 1 s_bypass
  res_case "lock: other version of a patched crate" 0 s_bypass_othver
  res_case "member named like a patched crate (no spaces)" 1 s_dupe
  res_case "renamed path copy of a patched crate" 1 s_rename
  res_case "path dependency outside every workspace" 1 s_outside
  res_case "manifest: [ patch.crates-io ]" 1 s_spaced
  res_case "manifest: [\"patch\".crates-io]" 1 s_quoted
  res_case "manifest: [patch] + dotted key" 1 s_bare
  res_case "manifest: top-level dotted patch key" 1 s_dotted
  res_case "manifest: inline patch table" 1 s_inline
  res_case "manifest: escaped key" 1 s_escape
  res_case "manifest: [replace]" 1 s_replace
  res_case "manifest: git patch" 1 s_gitpatch
  res_case "manifest: patch to another path" 1 s_otherpath
  res_case "manifest: patch to another crate dir" 1 s_renamed
  res_case "manifest: patch of a git source" 1 s_urlpatch
  res_case "manifest: patch outside a workspace root" 1 s_nonroot
  res_case "manifest: comments and strings ignored" 0 s_comment
  res_case "config: paths override" 1 s_cfg_paths
  res_case "config: source replacement" 1 s_cfg_source
  res_case "config: patch" 1 s_cfg_patch
  res_case "config: build settings" 0 s_cfg_ok
  res_case "config: runner" 1 s_cfg_runner
  res_case "config: rustc-wrapper" 1 s_cfg_wrapper
  res_case "config: linker" 1 s_cfg_linker
  res_case "config: env" 1 s_cfg_env
  res_case "config: target-dir" 1 s_cfg_targetdir
  res_case "config: rustflags not on the allow-list" 1 s_cfg_flags

  # Config pins: a pinned config passes; a changed or an unpinned one fails.
  pin_case() { # NAME EXPECT(0|1) SETUP-FN
    t="$WORK/pin-$1"
    fixture_repo "$t"
    mkdir -p "$t/.github" "$t/.cargo"
    printf '[target.x]\nrustflags = ["-C", "a"]\n' > "$t/.cargo/config.toml"
    git -C "$t" add -A
    printf '%s  .cargo/config.toml\n' "$(git -C "$t" cat-file blob :.cargo/config.toml | sha256sum | cut -d' ' -f1)" > "$t/.github/cargo-config.sha256"
    "$3" "$t"
    git -C "$t" add -A
    if check_config_pins "$t" "$t/.github/cargo-config.sha256" > "$WORK/st.log" 2>&1; then r=0; else r=1; fi
    if [ "$r" = "$2" ]; then
      echo "selftest ok   pins: $1 (exit $r)"
    else
      echo "selftest FAIL pins: $1: expected exit $2, got $r"; sed 's/^/  /' "$WORK/st.log"; bad=1
    fi
  }
  p_none() { :; }
  p_changed() { printf '[target.x]\nrustflags = ["-C", "b"]\n' > "$1/.cargo/config.toml"; }
  p_new() { mkdir -p "$1/sub/.cargo"; printf '[target.x]\nrustflags = []\n' > "$1/sub/.cargo/config"; }
  pin_case pinned 0 p_none
  pin_case changed 1 p_changed
  pin_case unpinned 1 p_new
  p_extra() { printf '%064d  .cargo/config.toml\n' 0 >> "$1/.github/cargo-config.sha256"; }
  pin_case "old and new hash listed (transition)" 0 p_extra
  echo "third-party-gate selftest: $([ "$bad" = 0 ] && echo pass || echo FAIL)"
  return "$bad"
}

main() {
  local root
  root="$(git rev-parse --show-toplevel)" || die "not in a git checkout"
  case "${1:-}" in
    --selftest) [ "$#" = 1 ] || die "usage"; selftest ;;
    --write)
      [ "$#" = 2 ] && [ -f "$root/third_party/$2/Cargo.toml" ] || die "usage: --write <crate under third_party/>"
      write_allowlist "$root" "$2" || exit 1
      echo "wrote third_party/patches/$2.patch and $2.sha256 (from the staged files)"
      ;;
    "")
      local bad=0
      check_cargo_files "$root" || bad=1
      check_identity "$root" || bad=1
      check_config_pins "$root" "${CARGO_CONFIG_PINS:-$here/../cargo-config.sha256}" || bad=1
      [ "$bad" = 1 ] || echo "ok   lockfiles, manifests and .cargo/ configs: crates.io or third_party/ only"
      check_tree "$root" || bad=1
      exit "$bad"
      ;;
    *) die "usage: third-party-gate.sh [--selftest | --write <crate>]" ;;
  esac
}

main "$@"
