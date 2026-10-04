#!/usr/bin/env bash
# Third-party patch gate (RT-PXDET finding 1).
#
# Every crate directory under third_party/ (a directory with a Cargo.toml) is a
# patched copy of a published crate, used through [patch.crates-io]. This gate
# proves that each one is exactly the published crate plus its reviewed diff:
#
#   1. name and version come from third_party/<crate>/Cargo.toml; <crate> must
#      equal the package name;
#   2. the pristine <name>-<version>.crate is taken from the local cargo cache
#      (~/.cargo/registry/cache/*/) or downloaded from static.crates.io, and its
#      sha256 must equal the line pinned in third_party/PRISTINE.sha256 (the
#      checksum Cargo.lock carried before the crate was patched);
#   3. the .crate is unpacked; the packaging differences documented in
#      third_party/README.md are dropped (top level only: Cargo.toml.orig,
#      .cargo_vcs_info.json and Cargo.lock from the pristine side, cargo's
#      unpack marker .cargo-ok from the patched side);
#   4. `diff -ruN --strip-trailing-cr` of the two trees, with timestamps
#      removed and CRs stripped, must equal third_party/patches/<crate>.patch
#      byte for byte (CRs stripped from that file too).
#
# It also fails when a patch file or PRISTINE line has no crate directory (a
# stale allow-list), and when a [patch.*] entry in Cargo.toml or
# fuzz/Cargo.toml is anything but a path into third_party/<same name>.
#
# Regenerate a patch file after a reviewed change of a patched crate:
#   bash .github/scripts/third-party-gate.sh --write <crate>
# (then review the diff of the patch file like any other code change).
#
# Usage: third-party-gate.sh            check every crate (from the repo root)
#        third-party-gate.sh --selftest tampered copies must fail
#        third-party-gate.sh --write C  rewrite third_party/patches/C.patch
# Environment: THIRD_PARTY_GATE_FETCH=1 always downloads (ignores the cache).
# Exit: 0 pass, 1 a crate differs from its allow-listed patch, 2 usage error.
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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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
  (cd "$d" && diff -ruN --strip-trailing-cr a b) > "$d/raw" || [ "$?" = 1 ] ||
    { annotate "third-party crate $crate: diff failed" "diff -ruN failed for third_party/$crate."; return 1; }
  tr -d '\r' < "$d/raw" | sed -E 's/^(---|\+\+\+) ([^\t]*)\t.*$/\1 \2/' > "$out"
}

# first_file PATCH LINE: the file named by the last diff header at or before LINE.
first_file() {
  awk -v n="$2" 'NR > n { exit } /^diff -ruN / { f = $NF; sub(/^b\//, "", f) } END { print f }' "$1"
}

# crates ROOT: the crate directories under ROOT/third_party, one per line.
crates() {
  local d
  for d in "$1"/third_party/*/; do
    [ -f "$d/Cargo.toml" ] && basename "$d"
  done
  return 0
}

# check_tree ROOT: 0 when every crate matches its patch file, 1 otherwise.
check_tree() {
  local root="$1" tp="$1/third_party" bad=0 crate exp act first n p line
  [ -f "$tp/PRISTINE.sha256" ] || { annotate "third-party gate: no PRISTINE.sha256" "third_party/PRISTINE.sha256 is missing."; return 1; }
  n=0
  for crate in $(crates "$root"); do
    n=$((n + 1))
    exp="$tp/patches/$crate.patch"
    if [ ! -f "$exp" ]; then
      annotate "third-party crate $crate: no allow-listed patch" \
        "third_party/patches/$crate.patch is missing; every patched crate needs its reviewed diff (third-party-gate.sh --write $crate)."
      bad=1
      continue
    fi
    act="$WORK/$crate.actual"
    crate_diff "$root" "$crate" "$act" || { bad=1; continue; }
    tr -d '\r' < "$exp" > "$WORK/$crate.expected"
    if cmp -s "$WORK/$crate.expected" "$act"; then
      echo "ok   third_party/$crate: published crate + patches/$crate.patch ($(grep -c '^diff -ruN ' "$act" || true) files)"
    else
      line="$(diff "$WORK/$crate.expected" "$act" | head -1 || true)"
      # "LcR", "LaR", "LdR" (ranges allowed): the first differing line on each side.
      p="${line#*[acd]}"; p="${p%%,*}"
      first="$(first_file "$act" "$p")"
      [ -n "$first" ] || { p="${line%%[acd,]*}"; first="$(first_file "$WORK/$crate.expected" "$p")"; }
      annotate "third-party crate $crate differs from its allow-listed patch" \
        "third_party/$crate is not the published crate plus third_party/patches/$crate.patch; first differing file: ${first:-?}. Review the change, then regenerate with third-party-gate.sh --write $crate."
      bad=1
    fi
  done
  # Stale allow-list entries: a patch file or pinned checksum without a crate.
  for p in "$tp"/patches/*.patch; do
    [ -f "$p" ] || continue
    crate="$(basename "$p" .patch)"
    [ -f "$tp/$crate/Cargo.toml" ] || {
      annotate "third-party gate: stale patch file" "third_party/patches/$crate.patch has no third_party/$crate crate; remove it with the crate."
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

# check_patch_tables ROOT: every [patch.*] entry is { path = "<prefix>third_party/<name>" }.
check_patch_tables() {
  local root="$1" bad=0 toml prefix entry
  for toml in Cargo.toml fuzz/Cargo.toml; do
    [ -f "$root/$toml" ] || continue
    prefix=""; [ "$toml" = fuzz/Cargo.toml ] && prefix="../"
    while IFS= read -r entry; do
      [ -n "$entry" ] || continue
      if ! printf '%s\n' "$entry" | grep -Eq "^([A-Za-z0-9_-]+) = \\{ path = \"${prefix//./\\.}third_party/\\1\" \\}\$"; then
        annotate "third-party gate: unreviewed [patch] entry in $toml" \
          "'$entry': a patch must be { path = \"${prefix}third_party/<same name>\" } (a gate-checked copy), never git or another path."
        bad=1
      fi
    done < <(tr -d '\r' < "$root/$toml" | awk '
      /^\[/ { inpatch = ($0 ~ /^\[patch[.]/); next }
      inpatch && /[^[:space:]]/ && !/^[[:space:]]*#/ { print }')
  done
  return "$bad"
}

selftest() {
  local root bad=0 crate f
  root="$(git rev-parse --show-toplevel)"
  crate="$(crates "$root" | sed -n 1p)"
  [ -n "$crate" ] || die "selftest: no crate under third_party/"
  run_case() { # NAME EXPECT(0|1): copy third_party, apply the tamper fn, check.
    local t="$WORK/st-$1"
    mkdir -p "$t"
    cp -R "$root/third_party" "$t/third_party"
    "tamper_$1" "$t/third_party"
    if check_tree "$t" > "$WORK/st.log" 2>&1; then r=0; else r=1; fi
    if [ "$r" = "$2" ]; then
      echo "selftest ok   $1 (exit $r)"
    else
      echo "selftest FAIL $1: expected exit $2, got $r"; sed 's/^/  /' "$WORK/st.log"; bad=1
    fi
  }
  tamper_clean() { :; }
  tamper_edit() { f="$(find "$1/$crate/src" -name '*.rs' | sort | head -1)"; printf '// tampered\n' >> "$f"; }
  tamper_newfile() { printf 'x\n' > "$1/$crate/src/extra.rs"; }
  tamper_delfile() { rm -f "$1/$crate/README.md"; }
  tamper_pkgfile() { printf 'x\n' > "$1/$crate/Cargo.toml.orig"; }
  tamper_pin() { sed -i.bak "s/^[0-9a-f]\{4\}/0000/" "$1/PRISTINE.sha256"; rm -f "$1/PRISTINE.sha256.bak"; }
  tamper_nopatch() { rm -f "$1/patches/$crate.patch"; }
  tamper_stale() { cp "$1/patches/$crate.patch" "$1/patches/no-such-crate.patch"; }
  tamper_crlf() { f="$(find "$1/$crate/src" -name '*.rs' | sort | head -1)"; sed -i.bak 's/$/\r/' "$f"; rm -f "$f.bak"; }
  run_case clean 0
  run_case crlf 0
  run_case edit 1
  run_case newfile 1
  run_case delfile 1
  run_case pkgfile 1
  run_case pin 1
  run_case nopatch 1
  run_case stale 1
  # [patch] table: a git source, a path outside third_party, a renamed path.
  local t="$WORK/st-toml"
  mkdir -p "$t"
  for entry in 'p3-fri = { git = "https://example.invalid/p3" }' \
    'p3-fri = { path = "vendor/p3-fri" }' 'p3-fri = { path = "third_party/p3-dft" }'; do
    printf '[patch.crates-io]\n%s\n' "$entry" > "$t/Cargo.toml"
    if check_patch_tables "$t" > /dev/null 2>&1; then
      echo "selftest FAIL patch table accepted: $entry"; bad=1
    else
      echo "selftest ok   patch table rejected: $entry"
    fi
  done
  printf '[patch.crates-io]\np3-fri = { path = "third_party/p3-fri" }\n' > "$t/Cargo.toml"
  check_patch_tables "$t" > /dev/null 2>&1 || { echo "selftest FAIL patch table rejected a valid entry"; bad=1; }
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
      mkdir -p "$root/third_party/patches"
      crate_diff "$root" "$2" "$root/third_party/patches/$2.patch" || exit 1
      echo "wrote third_party/patches/$2.patch"
      ;;
    "")
      local bad=0
      check_patch_tables "$root" || bad=1
      check_tree "$root" || bad=1
      exit "$bad"
      ;;
    *) die "usage: third-party-gate.sh [--selftest | --write <crate>]" ;;
  esac
}

main "$@"
