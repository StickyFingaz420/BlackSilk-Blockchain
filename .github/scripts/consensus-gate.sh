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
# configuration pins. v12-caps-single-definition added px/src/deploy_caps.rs,
# the single definition of the deploy-time row caps and the deploy rules on
# them (tx re-exports them). px-fixture-2fn added the two-function PX
# fixture's files (node/tests/fixtures). gate-manifest-paths (record
# "gate-manifest-paths", red team F3 of v12-caps-single-definition) added
# what decides which files the gated modules are and how they are built: the
# workspace manifest (members, [patch], profiles) and a root toolchain file;
# the manifest and any build script of every crate the release build builds
# with the node binary (tools/release-build.sh: node, miner, wallet, genesis
# and their workspace dependencies) that is not gated whole (a dependency
# path, a feature, unified into the node binary, `[lib] path` or `build =`
# there can swap or alter gated code); and the module roots that
# declare gated modules (a `#[path]`, `cfg` or `include!` there redirects
# them). The commits before it that touch them are in the waiver file.
# gate-coverage-2 (record "gate-coverage-2") added the submodule directories
# of the gated file modules, the ungated modules gated code computes
# consensus values with (px/src/perm.rs, px/src/delivery.rs, zkvm/src/isa.rs),
# the chain store, sync policy and build flags, the fingerprint, fixture,
# circuit and vector pins, every CI script, the test-feature checks and the
# cargo-deny policy; and reads paths NUL-separated, so a name git quotes is
# matched as it is. The commits before it that touch them are waived.
#
# The match ignores case (red team F1 of gate-manifest-paths): checkouts on
# Windows and macOS are case-insensitive, where `px/Build.rs` is the crate's
# build script and `px/src/LIB.rs` is `px/src/lib.rs`. nocasematch is set
# only around the match and restored after it.
is_consensus_path() {
  local restore r=0
  restore="$(shopt -p nocasematch || true)"
  shopt -s nocasematch
  consensus_path_match "$1" || r=1
  eval "$restore"
  return "$r"
}

# The path list; call it through is_consensus_path (case-insensitive).
consensus_path_match() {
  case "$1" in
    consensus/* | px-core/* | zk/* | zkvm/src/air/*) return 0 ;;
    tx/src/validate.rs | tx/src/px.rs | tx/src/params.rs) return 0 ;;
    tx/src/types.rs | tx/src/codec.rs | tx/src/state.rs) return 0 ;;
    tx/src/mmr.rs) return 0 ;; # the output range of the headers (output-root)
    zkvm/src/prove.rs | node/src/fingerprint.rs | px/src/fingerprint.rs) return 0 ;;
    zkvm/src/program.rs | zkvm/src/exec.rs) return 0 ;; # program id, image (red team I3)
    node/src/fingerprint_fixture.txt) return 0 ;;
    node/src/px_fixture.bin | node/src/px_fixture.txt) return 0 ;;
    # The two-function PX fixture: test-pinned, not a consensus input, but a
    # change of its bytes is reviewed like the golden fixture's (decisions,
    # "Two-function PX fixture: test-pinned").
    node/tests/fixtures/px_fixture_2fn.bin | node/tests/fixtures/px_fixture_2fn.txt) return 0 ;;
    chain/src/block.rs | chain/src/emission.rs | chain/src/manager/*) return 0 ;;
    px/*.elf | px/*.id) return 0 ;;
    px/src/prove.rs | px/src/state.rs | px/src/tree.rs) return 0 ;;
    px/src/deploy_caps.rs) return 0 ;; # the V12 deploy caps and rules
    crypto/* | randomx/* | third_party/*) return 0 ;;
    .github/scripts/consensus-gate.sh | .github/scripts/gate-range.sh) return 0 ;;
    .github/scripts/lockfile-gate.sh | .github/scripts/third-party-gate.sh) return 0 ;;
    .github/consensus-gate-waivers.txt | .github/lockfile-gate-waivers.txt) return 0 ;;
    .cargo/* | */.cargo/* | tools/tpgate/*) return 0 ;;
    .gitattributes | */.gitattributes | .github/cargo-config.sha256) return 0 ;;
    .github/workflows/* | tools/release-build.sh | deploy/docker/Dockerfile) return 0 ;;
    zkvm/guests/build.sh | zkvm/guests/reproduce.sh | .github/scripts/guests-reproduce.sh) return 0 ;;
    # gate-manifest-paths. `Cargo.toml` is the root manifest only.
    Cargo.toml | rust-toolchain | rust-toolchain.toml) return 0 ;;
    chain/Cargo.toml | node/Cargo.toml | p2p/Cargo.toml | px/Cargo.toml) return 0 ;;
    rpc/Cargo.toml | tx/Cargo.toml | zkvm/Cargo.toml) return 0 ;;
    miner/Cargo.toml | wallet/Cargo.toml | tools/genesis/Cargo.toml) return 0 ;;
    chain/build.rs | node/build.rs | node/build_id.rs | p2p/build.rs | px/build.rs) return 0 ;;
    rpc/build.rs | tx/build.rs | zkvm/build.rs) return 0 ;;
    miner/build.rs | wallet/build.rs | tools/genesis/build.rs) return 0 ;;
    chain/src/lib.rs | chain/src/manager.rs | node/src/lib.rs | px/src/lib.rs) return 0 ;;
    tx/src/lib.rs | zkvm/src/lib.rs) return 0 ;;
    # gate-coverage-2 (proposed). (a) The submodule directory of every gated
    # file module: a `mod x;` in tx/src/validate.rs is tx/src/validate/x.rs.
    tx/src/validate/* | tx/src/px/* | tx/src/params/* | tx/src/types/*) return 0 ;;
    tx/src/codec/* | tx/src/state/* | tx/src/mmr/*) return 0 ;;
    chain/src/block/* | chain/src/emission/* | node/src/fingerprint/*) return 0 ;;
    px/src/prove/* | px/src/state/* | px/src/tree/* | px/src/deploy_caps/*) return 0 ;;
    px/src/fingerprint/* | zkvm/src/prove/* | zkvm/src/program/* | zkvm/src/exec/*) return 0 ;;
    # (b) Code the gated modules compute consensus values with: the host
    # Poseidon2 of the PX state root (px/src/state.rs), the ciphertext length
    # of the PX codec (tx/src/px.rs), the BVM-1 decoder (exec.rs, air/).
    px/src/perm.rs | px/src/perm/* | px/src/delivery.rs | px/src/delivery/*) return 0 ;;
    zkvm/src/isa.rs | zkvm/src/isa/*) return 0 ;;
    # (c) What decides which blocks are verified and how a restart trusts the
    # store (invalid markers, stored PoW, checkpoints), the anti-DoS verify
    # threshold and seed policy, and the test-hook network refusal.
    chain/src/store.rs | chain/src/store/* | chain/src/sync_policy.rs) return 0 ;;
    chain/src/sync_policy/* | chain/src/build_flags.rs | chain/src/build_flags/*) return 0 ;;
    # (d) The pins that say a change of them is a consensus change: the
    # fingerprint, fixture, circuit and vector tests and their data.
    node/tests/deploy_configs.rs | node/tests/fingerprint_fixture.rs) return 0 ;;
    node/tests/px_fixture.rs | px/tests/consensus_fingerprint.rs) return 0 ;;
    px/tests/hk_vectors.rs | px/tests/data/hk_vectors.txt | tools/vectors/*) return 0 ;;
    zkvm/tests/circuit_fingerprint.rs | zkvm/tests/circuit_id.rs) return 0 ;;
    # (e) Every CI script, and the checks CI runs from the commit's own code
    # (build guard, test-feature markers), and the cargo-deny policy.
    .github/scripts/* | tools/check-build-flags.sh | tools/check-test-features.sh | deny.toml) return 0 ;;
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
# for a merge the paths its dense combined diff shows plus the paths it
# reverts. NUL-terminated (-z): a name git would quote (a `"`, `\`, tab,
# newline or control character) is matched as it is, never as
# `"consensus/a\"b.rs"` (gate-coverage-2). For a merge:
# - dense: `--cc --name-only` lists every path that differs from all parents
#   (a superset); a path is kept when its dense combined diff is not empty
#   (new content written in the merge);
# - reverts (red team F1 of gate-coverage-2): a path whose merge version
#   differs from the first parent's and equals its version at a merge base of
#   the first parent and another parent (`merge-base --all`, any base, every
#   other parent of an octopus): the merge undoes a change of the first
#   parent's history, which no checked commit shows. A side's own change taken
#   as it is (differs from the base) is not one; that commit was checked.
# Fails closed (red team F2): any git failure prints why and returns 2.
changed_paths() {
  local c="$1" ids parents p1 k b bases out p n
  ids="$(git rev-list --parents -n 1 "$c")" || { echo "gate: cannot read the parents of $c" >&2; return 2; }
  read -r -a parents <<<"$ids"
  if [ "${#parents[@]}" -le 2 ]; then
    git diff-tree -r --root --no-renames --name-only -z --no-commit-id "$c" ||
      { echo "gate: git diff-tree failed on $c" >&2; return 2; }
    return 0
  fi
  out="$(mktemp)" || return 2
  git diff-tree -r --cc --name-only -z --no-commit-id "$c" >"$out" ||
    { echo "gate: git diff-tree --cc failed on $c" >&2; rm -f "$out"; return 2; }
  while IFS= read -r -d '' p; do
    n="$(git diff-tree --cc -p --no-commit-id "$c" -- ":(literal)$p")" ||
      { echo "gate: git diff-tree --cc -p failed on $c: $p" >&2; rm -f "$out"; return 2; }
    [ -z "$n" ] || printf '%s\0' "$p"
  done <"$out"
  # Reverts: D(p1, c) minus D(base, c), for each other parent and base.
  p1="${parents[1]}"
  local -A from_p1=()
  git diff-tree -r --no-renames --name-only -z "$p1" "$c" >"$out" ||
    { echo "gate: git diff-tree failed on $p1 $c" >&2; rm -f "$out"; return 2; }
  while IFS= read -r -d '' p; do from_p1["$p"]=1; done <"$out"
  if [ "${#from_p1[@]}" -gt 0 ]; then
    for k in "${parents[@]:2}"; do
      local rc=0
      bases="$(git merge-base --all "$p1" "$k")" || rc=$?
      # Exit 1 with no output: unrelated histories, no base (the other
      # parent's own commits are checked, from their root).
      if [ "$rc" != 0 ]; then
        [ "$rc" = 1 ] && [ -z "$bases" ] && continue
        echo "gate: git merge-base failed on $p1 $k" >&2; rm -f "$out"; return 2
      fi
      for b in $bases; do
        [ "$b" != "$p1" ] || continue
        local -A from_b=()
        git diff-tree -r --no-renames --name-only -z "$b" "$c" >"$out" ||
          { echo "gate: git diff-tree failed on $b $c" >&2; rm -f "$out"; return 2; }
        while IFS= read -r -d '' p; do from_b["$p"]=1; done <"$out"
        for p in "${!from_p1[@]}"; do
          [ -n "${from_b[$p]:-}" ] || printf '%s\0' "$p"
        done
        unset from_b
      done
    done
  fi
  rm -f "$out"
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

# The paths gate-manifest-paths added, and paths next to them that stay
# ungated (the list must not grow past what the record justifies).
GATE_MANIFEST_PATHS="Cargo.toml rust-toolchain rust-toolchain.toml
chain/Cargo.toml node/Cargo.toml p2p/Cargo.toml px/Cargo.toml rpc/Cargo.toml
tx/Cargo.toml zkvm/Cargo.toml miner/Cargo.toml wallet/Cargo.toml
tools/genesis/Cargo.toml chain/build.rs node/build.rs node/build_id.rs
p2p/build.rs px/build.rs rpc/build.rs tx/build.rs zkvm/build.rs miner/build.rs
wallet/build.rs tools/genesis/build.rs
chain/src/lib.rs chain/src/manager.rs node/src/lib.rs px/src/lib.rs
tx/src/lib.rs zkvm/src/lib.rs"
GATE_UNGATED_NEIGHBOURS="README.md docs/STATUS.md Cargo.lock tools/daa-sim/Cargo.toml
tools/labnet/Cargo.toml tools/supply-audit/Cargo.toml fuzz/Cargo.toml contracts/Cargo.toml
zkvm/guests/Cargo.toml zkvm/sdk/Cargo.toml p2p/src/lib.rs rpc/src/lib.rs
node/src/main.rs miner/src/main.rs px/src/vault.rs chain/src/mempool.rs
chain/src/manager.rs.orig src/lib.rs px/src/lib.rs.bak docs/Cargo.toml
chain/src/actor.rs chain/src/address.rs chain/src/mempool/reorg.rs px/src/wallet.rs
px/src/share.rs tx/src/builder.rs tx/src/decoy.rs tx/src/scan.rs tx/src/px_builder.rs
tx/src/validate_notes.md zkvm/src/asm.rs node/src/config.rs node/tests/rpc_security.rs
px/tests/proof.rs zkvm/tests/vm.rs tools/vectors.md .github/ISSUE_TEMPLATE/bug_report.md
tools/release-build.sh.bak zkvm/guests/kernel/src/main.rs zkvm/sdk/src/lib.rs"
# The paths gate-coverage-2 adds (one example per pattern).
GATE_COVERAGE2_PATHS="tx/src/validate/rules.rs tx/src/px/codec.rs tx/src/params/x.rs
tx/src/types/x.rs tx/src/codec/x.rs tx/src/state/x.rs tx/src/mmr/x.rs chain/src/block/x.rs
chain/src/emission/x.rs node/src/fingerprint/x.rs px/src/prove/x.rs px/src/state/x.rs
px/src/tree/x.rs px/src/deploy_caps/x.rs px/src/fingerprint/x.rs zkvm/src/prove/x.rs
zkvm/src/program/x.rs zkvm/src/exec/x.rs px/src/perm.rs px/src/perm/x.rs
px/src/delivery.rs px/src/delivery/x.rs zkvm/src/isa.rs zkvm/src/isa/x.rs
chain/src/store.rs chain/src/store/x.rs chain/src/sync_policy.rs chain/src/sync_policy/x.rs
chain/src/build_flags.rs chain/src/build_flags/x.rs node/tests/deploy_configs.rs
node/tests/fingerprint_fixture.rs node/tests/px_fixture.rs px/tests/consensus_fingerprint.rs
px/tests/hk_vectors.rs px/tests/data/hk_vectors.txt tools/vectors/output_mmr.py
zkvm/tests/circuit_fingerprint.rs zkvm/tests/circuit_id.rs .github/scripts/build-guard.sh
.github/scripts/unicode-scan.sh tools/check-build-flags.sh tools/check-test-features.sh deny.toml"
# Case variants of gated paths (red team F1): gated, since a case-insensitive
# checkout uses them as the gated file.
GATE_CASE_VARIANTS="PX/SRC/LIB.RS px/Build.rs rpc/BUILD.rs Cargo.TOML TX/Cargo.toml"

selftest_paths() {
  local p bad=0
  for p in $GATE_MANIFEST_PATHS $GATE_COVERAGE2_PATHS consensus/Cargo.toml crypto/Cargo.toml \
    PX/SRC/PERM.RS Chain/Src/Store.rs ZKVM/src/ISA.rs \
    px-core/src/lib.rs zk/build.rs randomx/Cargo.toml px/src/deploy_caps.rs \
    $GATE_CASE_VARIANTS Consensus/src/lib.rs TX/SRC/VALIDATE.RS; do
    is_consensus_path "$p" || { echo "selftest: $p should be a consensus path"; bad=1; }
  done
  for p in $GATE_UNGATED_NEIGHBOURS; do
    if is_consensus_path "$p"; then echo "selftest: $p should not be a consensus path"; bad=1; fi
    # Ignoring case gates no neighbour.
    if is_consensus_path "${p^^}"; then echo "selftest: ${p^^} should not be a consensus path"; bad=1; fi
  done
  # The match leaves the caller's nocasematch setting as it was.
  if shopt -q nocasematch; then echo "selftest: nocasematch left on"; bad=1; fi
  shopt -s nocasematch
  is_consensus_path README.md || true
  shopt -q nocasematch || { echo "selftest: nocasematch turned off"; bad=1; }
  shopt -u nocasematch
  return "$bad"
}

# The gate itself on a fixture repository (gate-manifest-paths): a commit
# that touches a newly gated path fails without a trailer and passes with
# one; a waived commit within the waiver horizon passes, the same waiver past
# the horizon does not; an ungated file needs no trailer. The gate runs from
# a copy outside the fixture with its own waiver file, so the fixture's
# commits touch no gate path, and with GITHUB_ACTIONS unset, so an expected
# failure prints no CI annotation.
selftest_history() {
  local t bad=0 old new p rc
  t="$(mktemp -d)"
  mkdir -p "$t/gate/scripts" "$t/repo"
  cp "$here/consensus-gate.sh" "$here/gate-range.sh" "$t/gate/scripts/"
  # The base commit (the fixture's cut-over), then a "historical" commit that
  # touches px/src/lib.rs without a trailer: the waiver horizon, waived.
  old="$(cd "$t/repo" &&
    git -c init.defaultBranch=main init -q &&
    git config user.name selftest &&
    git config user.email selftest@invalid &&
    git config commit.gpgsign false &&
    git config core.autocrlf false &&
    git config core.hooksPath /dev/null &&
    echo base >README.md &&
    git add -A &&
    git commit -q -m base &&
    mkdir -p px/src &&
    echo 'pub mod prove;' >px/src/lib.rs &&
    git add -A &&
    git commit -q -m 'px: module list' &&
    git rev-parse HEAD 2>/dev/null)" || old=""
  [ -n "$old" ] || { echo "selftest: fixture repository setup failed"; rm -rf "$t"; return 1; }
  printf '%s none: fixture waiver\n' "$old" >"$t/gate/consensus-gate-waivers.txt"
  # gate_run BASE HEAD: the gate's exit status on the fixture.
  gate_run() {
    (cd "$t/repo" && env -u GITHUB_ACTIONS -u GATE_CMD_TOKEN \
      GATE_CUTOVER="$(git rev-list --max-parents=0 HEAD)" GATE_WAIVER_HORIZON="$old" \
      bash "$t/gate/scripts/consensus-gate.sh" "$1" "$2") >/dev/null 2>&1
  }
  # fixture_commit PATH MESSAGE: a commit that changes PATH; prints its id.
  fixture_commit() {
    (cd "$t/repo" &&
      mkdir -p "$(dirname "$1")" &&
      echo "$RANDOM $2" >>"$1" &&
      git add -A &&
      git commit -q -m "$2" &&
      git rev-parse HEAD) 2>/dev/null
  }
  # expect WANT PATH MESSAGE: commit, run the gate on that commit alone.
  expect() {
    local want="$1" path="$2" msg="$3" c rc=0
    c="$(fixture_commit "$path" "$msg")" || { echo "selftest: fixture commit on $path failed"; bad=1; return; }
    gate_run "$c~1" "$c" || rc=$?
    if [ "$rc" != "$want" ]; then
      echo "selftest: gate exit $rc (want $want) on $path: $(printf '%s' "$msg" | head -n 1)"
      bad=1
    fi
  }
  local trailer=$'\n\nConsensus-Change: none: selftest fixture'
  # (c) the waived commit before the horizon passes.
  rc=0
  gate_run "$old~1" "$old" || rc=$?
  [ "$rc" = 0 ] || { echo "selftest: a waived commit within the horizon failed (exit $rc)"; bad=1; }
  # Case variants of gated paths (red team F1), before the loop below creates
  # the paths themselves (on a case-insensitive checkout they would merge).
  for p in px/Build.rs rpc/BUILD.rs Cargo.TOML TX/Cargo.toml; do
    expect 1 "$p" "touch $p"
  done
  # (a), (b) every newly gated path: no trailer fails, a trailer passes.
  for p in $GATE_MANIFEST_PATHS $GATE_COVERAGE2_PATHS; do
    expect 1 "$p" "touch $p"
    expect 0 "$p" "touch $p$trailer"
  done
  # gate-coverage-2: history shapes. want_rc WANT BASE HEAD WHAT.
  want_rc() {
    local rc=0
    gate_run "$2" "$3" || rc=$?
    [ "$rc" = "$1" ] || { echo "selftest: gate exit $rc (want $1): $4"; bad=1; }
  }
  local c b q root
  g() { git -C "$t/repo" "$@"; }
  # A rename out of a gated path and a deletion are changes of the gated path.
  # (Paths outside the case-variant directories above, which a
  # case-insensitive checkout records under their first spelling.)
  if g mv chain/src/block/x.rs chain/src/moved.rs && g commit -q -m 'rename out'; then
    want_rc 1 HEAD~1 HEAD "rename of a gated file to an ungated path"
  else
    echo "selftest: rename fixture failed"; bad=1
  fi
  if g rm -q chain/src/moved.rs px/src/perm.rs && g commit -q -m 'delete'; then
    want_rc 1 HEAD~1 HEAD "deletion of a gated file"
  else
    echo "selftest: deletion fixture failed"; bad=1
  fi
  # A name git quotes (`"` here; tabs and newlines likewise) is still matched.
  # Built with plumbing: such a name cannot be checked out on Windows.
  b="$(echo quoted | g hash-object -w --stdin)"
  q="$(printf '100644 blob %s\tq"x.rs\n' "$b" | g mktree)"
  root="$( { g ls-tree HEAD | grep -v "$(printf '\t')consensus\$"; printf '040000 tree %s\tconsensus\n' "$q"; } | g mktree)"
  c="$(g commit-tree "$root" -p HEAD -m 'quoted name')"
  want_rc 1 "$c~1" "$c" "a consensus/ file whose name git quotes"
  # Merges: an edit made in the merge itself fails; a clean merge of two
  # trailered sides passes; a merge that takes one side's file as it is passes.
  g checkout -q -b side
  expect 0 chain/src/store.rs "side$trailer"
  g checkout -q main
  expect 0 README.md main
  g merge -q --no-ff -m 'clean merge' side >/dev/null
  want_rc 0 HEAD^1 HEAD "a clean merge of checked commits"
  g reset -q --hard HEAD^1
  g merge -q --no-ff --no-commit side >/dev/null 2>&1
  echo evil >>"$t/repo/chain/src/store.rs"
  g add -A && g commit -q -m 'evil merge'
  want_rc 1 HEAD^1 HEAD "an edit of a gated file inside a merge"
  g reset -q --hard HEAD^1
  # Both sides change one gated file in different places: the merged file
  # differs from both parents, but every hunk is one side's (the dense
  # combined diff is empty), so the clean merge passes.
  printf 'a\nb\nc\nd\ne\nf\ng\nh\n' >"$t/repo/chain/src/emission/m.rs"
  g add -A && g commit -q -m "lines$trailer"
  g checkout -q -b d1 && sed -i 's/^a$/A/' "$t/repo/chain/src/emission/m.rs" &&
    g commit -q -a -m "d1$trailer"
  g checkout -q main && sed -i 's/^h$/H/' "$t/repo/chain/src/emission/m.rs" &&
    g commit -q -a -m "d2$trailer"
  g merge -q --no-ff -m 'clean merge, both sides' d1 >/dev/null 2>&1
  if [ "$(g rev-list --parents -n 1 HEAD | wc -w)" = 3 ]; then
    want_rc 0 HEAD^1 HEAD "a clean merge of two changes to one gated file"
  else
    echo "selftest: two-sided merge fixture failed"; bad=1
  fi
  # A conflict in a gated file: resolved to one side's version, the merge
  # adds nothing and passes; resolved to new content, it fails without a
  # trailer and passes with one.
  g checkout -q -b c1 && printf 'one\n' >"$t/repo/chain/src/sync_policy.rs" &&
    g commit -q -a -m "c1$trailer"
  g checkout -q main && printf 'two\n' >"$t/repo/chain/src/sync_policy.rs" &&
    g commit -q -a -m "c2$trailer"
  conflict_merge() { # CONTENT MESSAGE: merge c1 into main, resolve to CONTENT
    g merge -q --no-ff --no-commit c1 >/dev/null 2>&1
    printf '%s\n' "$1" >"$t/repo/chain/src/sync_policy.rs"
    g add -A && g commit -q -m "$2"
  }
  conflict_merge two 'resolved to ours'
  want_rc 0 HEAD^1 HEAD "a conflict resolved to the first parent's version"
  g reset -q --hard HEAD^1
  # Resolved to the side's version, which differs from the base: the side's
  # checked change, taken as it is, passes.
  conflict_merge one 'resolved to theirs'
  want_rc 0 HEAD^1 HEAD "a conflict resolved to the side's version"
  g reset -q --hard HEAD^1
  # Resolved to the base's version after the first parent changed it: the
  # merge reverts a change no checked commit undoes (red team F1).
  conflict_merge "$(g show "$(g merge-base main c1):chain/src/sync_policy.rs")" 'resolved to the base'
  want_rc 1 HEAD^1 HEAD "a conflict resolved to the base's version"
  g reset -q --hard HEAD^1
  # A side that does not touch the file, merged with the file set back to
  # the base: a silent revert of the first parent's change (red team F1).
  g checkout -q -b r1 "$(g merge-base main c1)" && expect 0 notes/r1.txt 'side, no gated file'
  g checkout -q main
  g merge -q --no-ff --no-commit r1 >/dev/null 2>&1
  g show "$(g merge-base main r1):chain/src/sync_policy.rs" >"$t/repo/chain/src/sync_policy.rs"
  g add -A && g commit -q -m 'merge reverting a gated change'
  want_rc 1 HEAD^1 HEAD "a clean merge that reverts the first parent's gated change"
  g reset -q --hard HEAD^1
  # Unrelated histories: an orphan root holding a gated file, merged in. The
  # root itself is checked (diff-tree --root), so the range fails (red team F3).
  b="$(echo orphan | g hash-object -w --stdin)"
  q="$(printf '100644 blob %s\tx.rs\n' "$b" | g mktree)"
  c="$(g commit-tree "$(printf '040000 tree %s\tconsensus\n' "$q" | g mktree)" -m 'orphan root')"
  c="$(g commit-tree "$(g rev-parse 'HEAD^{tree}')" -p HEAD -p "$c" -m 'merge an orphan root')"
  want_rc 1 "$c^1" "$c" "an orphan root with a gated file, merged in"
  conflict_merge three 'resolved anew'
  want_rc 1 HEAD^1 HEAD "a conflict resolved to new content, no trailer"
  g reset -q --hard HEAD^1
  conflict_merge three "resolved anew$trailer"
  want_rc 0 HEAD^1 HEAD "a conflict resolved to new content, with a trailer"
  g reset -q --hard HEAD^1
  # An octopus merge: clean passes; an edit inside it fails.
  for p in o1:chain/src/store/o1.rs o2:px/src/tree/o2.rs o3:zkvm/src/isa/o3.rs; do
    g checkout -q -b "${p%%:*}" main && expect 0 "${p#*:}" "${p%%:*}$trailer"
  done
  g checkout -q main
  g merge -q --no-ff -m 'octopus' o1 o2 o3 >/dev/null 2>&1
  if [ "$(g rev-list --parents -n 1 HEAD | wc -w)" = 5 ]; then # the merge and its 4 parents
    want_rc 0 HEAD^1 HEAD "a clean octopus merge of checked commits"
    g reset -q --hard HEAD^1
    g merge -q --no-ff --no-commit o1 o2 o3 >/dev/null 2>&1
    echo evil >>"$t/repo/px/src/tree/o2.rs"
    g add -A && g commit -q -m 'evil octopus'
    want_rc 1 HEAD^1 HEAD "an edit of a gated file inside an octopus merge"
    g reset -q --hard HEAD^1
  else
    echo "selftest: octopus merge fixture failed"; bad=1
  fi
  # A file renamed into a gated path, and a mode-only change of one.
  expect 0 notes/n.rs 'an ungated file'
  g mv notes/n.rs chain/src/block/n.rs && g commit -q -m 'rename in'
  want_rc 1 HEAD~1 HEAD "a rename of an ungated file into a gated path"
  g update-index --chmod=+x chain/src/block/n.rs && g commit -q -m 'mode only'
  want_rc 1 HEAD~1 HEAD "a mode-only change of a gated file"
  # Names with a tab or a newline, built with plumbing (`mktree -z`, which
  # also works on Windows git; such a name is never checked out). The
  # fixture has no crypto/ or randomx/ tree, so the commit adds one file.
  for q in "$(printf 'crypto/t\tx.rs')" "$(printf 'randomx/n\nx.rs')"; do
    b="$(printf '%s\n' "$q" | g hash-object -w --stdin)"
    root="$( { g ls-tree -z HEAD
      printf '040000 tree %s\t%s\0' "$(printf '100644 blob %s\t%s\0' "$b" "${q#*/}" | g mktree -z)" "${q%%/*}"; } | g mktree -z)"
    if c="$(g commit-tree "$root" -p HEAD -m 'odd name')" && [ -n "$c" ]; then
      want_rc 1 "$c~1" "$c" "a gated file whose name has a tab or a newline"
    else
      echo "selftest: odd-name fixture failed"; bad=1
    fi
  done
  # A record citation the record does not have is no trailer.
  expect 1 px/src/lib.rs $'cite\n\nConsensus-Change: docs/reviews/v3-consensus-changes.md#no-such-section'
  # (d) ungated paths need no trailer.
  for p in $GATE_UNGATED_NEIGHBOURS; do
    expect 0 "$p" "touch $p"
  done
  # The waiver horizon: a waiver for a commit after it is ignored.
  new="$(fixture_commit px/src/lib.rs 'after the horizon')" || { echo "selftest: fixture commit failed"; bad=1; }
  if [ -n "$new" ]; then
    printf '%s none: fixture waiver\n' "$new" >>"$t/gate/consensus-gate-waivers.txt"
    rc=0
    gate_run "$new~1" "$new" || rc=$?
    [ "$rc" = 1 ] || { echo "selftest: a waiver past the horizon was honoured (exit $rc)"; bad=1; }
  fi
  # The whole fixture range: the unwaived, untrailered commits fail it.
  rc=0
  gate_run "" HEAD || rc=$?
  [ "$rc" = 1 ] || { echo "selftest: the whole fixture range passed (exit $rc)"; bad=1; }
  # Fails closed (red team F2): a merge whose gated blob is missing from the
  # object store (a damaged or partial clone) stops the gate with exit 2 and
  # a message, never a pass. Last, as it damages the fixture.
  local msg
  g checkout -q -b f2 main~0 && expect 0 notes/f2.txt 'side'
  g checkout -q main
  g merge -q --no-ff --no-commit f2 >/dev/null 2>&1
  echo "f2 evil $RANDOM" >>"$t/repo/chain/src/store.rs"
  g add -A && g commit -q -m 'evil merge, blob to be lost'
  b="$(g rev-parse HEAD:chain/src/store.rs)"
  rm -f "$t/repo/.git/objects/${b:0:2}/${b:2}"
  rc=0
  msg="$(cd "$t/repo" && env -u GITHUB_ACTIONS -u GATE_CMD_TOKEN \
    GATE_CUTOVER="$(git rev-list --max-parents=0 HEAD)" GATE_WAIVER_HORIZON="$old" \
    bash "$t/gate/scripts/consensus-gate.sh" HEAD^1 HEAD 2>&1)" || rc=$?
  if [ "$rc" != 2 ] || ! printf '%s\n' "$msg" | grep -q 'failing closed'; then
    echo "selftest: a missing blob gave exit $rc, not a fail-closed stop: $(printf '%s' "$msg" | tail -n 1)"
    bad=1
  fi
  rm -rf "$t"
  return "$bad"
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
  # RT-TPGATE5: commit data in an annotation cannot start a workflow command.
  v="$(GITHUB_ACTIONS=true GATE_CMD_TOKEN=tok gate_annotate $'s::x,\n::add-mask::t' $'m\n::add-mask::y' 2>/dev/null | sed -n 1,3p)"
  [ "$v" = $'::tok::\n::error title=s%3A%3Ax%2C%0A%3A%3Aadd-mask%3A%3At::m%0A::add-mask::y\n::stop-commands::tok' ] ||
    { echo "selftest: annotation escaping or command bracketing broken"; bad=1; }
  selftest_paths || bad=1
  selftest_history || bad=1
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
  # The paths go through a file, so a git failure stops the gate (red team
  # F2 of gate-coverage-2): it never reads a short list as a clean commit.
  GATE_PATHS_FILE="$(mktemp)" || gate_die "cannot create a temporary file"
  trap 'rm -f "${GATE_PATHS_FILE:-}"' EXIT
  for c in $commits; do
    n=$((n + 1))
    hits=""
    local p
    local -A seen=()
    changed_paths "$c" >"$GATE_PATHS_FILE" || gate_die "cannot list the paths of commit $c; failing closed"
    while IFS= read -r -d '' p; do
      [ -n "$p" ] || continue
      [ -z "${seen[$p]:-}" ] || continue
      seen["$p"]=1
      if is_consensus_path "$p"; then hits+="${hits:+, }$p"; fi
    done <"$GATE_PATHS_FILE"
    unset seen
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
