# 43 ci-reproducibility: CI, reproducible guest and node builds, release integrity

**Specialist 43, phase 2, phase 1 (research and briefing).** Internal engineering work,
not an audit. Nothing here claims that BlackSilk or its build is secure, audited or
production-ready. Read-only on the repository; no builds, no tests. The kernel ELF was
parsed read-only with a few lines of Python to measure its sections.

Evidence classes: **[math]**, **[tested: name]**, **[src]** source-read, **[web]**
observed on a public page or the public GitHub API, **[meas]** measured read-only from a
committed file, **[assumed]**, **[unknown]**.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`), branch `rebuild/core`, clean tree.
`origin/rebuild/core` = `65bcec1`. **The local branch is 18 commits ahead of it**; the
v3 merge with the platform-neutral kernel is not pushed [src: `git rev-list --count`].

**Repository files, read in full:**
- `.github/workflows/ci.yml` (7 jobs) and `.github/scripts/annotate-tests.sh`;
- `zkvm/guests/{build.sh, reproduce.sh, README.md, rust-toolchain.toml, Cargo.toml, Cargo.lock, .cargo/config.toml}`, `zkvm/guests/kernel/{Cargo.toml, src/main.rs}`;
- `px/tests/elf_paths.rs`, `px/kernel.id`, `px/vault.id`, and the ids' consumers (`px/src/prove.rs:32-35`, `px/src/vault.rs:42-43`, `px/src/fingerprint.rs:217`, `px/tests/proof.rs:17-25`);
- `deploy/docker/Dockerfile`, `.dockerignore`, `.gitattributes`, `deploy/scripts/install-linux.sh`;
- the root `Cargo.toml` (profiles, `[patch]`), `node/build.rs`, the `BUILD_COMMIT` sites (`node/src/fingerprint.rs:19`, `miner/src/main.rs:54-58`);
- `fuzz/run_campaign.sh`, `third_party/README.md` (first 100 lines);
- the `main` branch's `ci.yml` (`git show origin/main:…`).

**Documents:**
- `docs/reviews/full-review-2026-09-27.md` §1, §3.13, §5.1, §7.4 (C1) and the register rows for T-2, T-10, T-11, R15-5, R15-6 and R16-13;
- `docs/reviews/autonomous-session-2026-09-27.md` (all of it);
- source reports: `R13-testing-supplychain.md` (all of it), `R15-testnet-decentralization.md` (R15-5, R15-6, §3 B, §5.4, §5.6), `SX2-systems-crossreview.md` (C1, T-10, R16-3, P0-11), `R14-docs-dx.md` (D-6, D-9);
- `docs/testnet-v3-genesis.md` §5–§8 and `docs/testnet.md` §2;
- `C:/bszkeval/p2/{brief,roster,decisions}.md`;
- every dossier in `C:/bszkeval/p2/research/` (01–21, 25, 28, 30), searched for CI and rebuild requests. §6 lists them all.

**Public state, read-only:**
- GitHub Actions runs through the public API: the last run is #83 at `65bcec1`, and there are **0 `schedule` runs ever**;
- the repository's default branch is `main` (`origin/HEAD -> origin/main`).

---

## 2. Current state

### 2.1 What exists and is well designed

| Item | Evidence |
|---|---|
| Actions are SHA-pinned, the default token is `contents: read`, `persist-credentials: false` | [src ci.yml:14-35] |
| The toolchain is pinned to 1.98.1 in every job; the fuzz job uses a dated nightly; cargo-audit and cargo-fuzz are installed with pinned versions and `--locked` | [src ci.yml] |
| `--locked` is used in every cargo build and test | [src] |
| An overflow/debug-assertion job over the non-PX crates | [src ci.yml:86-115] |
| Failed tests become annotations (the logs need admin access) | [src annotate-tests.sh] |
| The **guest build is exemplary**: one source of flags (`GUEST_FLAGS`), a drift check against `.cargo/config.toml`, an exact rustc release **and commit** check, refusal of env overrides (`RUSTFLAGS`, `CARGO_PROFILE_*`, wrappers …), `--locked`, and no external dependencies in the guest lock | [src build.sh:23-96; guests Cargo.lock] |
| `reproduce.sh` checks **three** things per guest: the rebuilt id = the pinned id, the committed ELF's id = the pinned id, and the rebuilt bytes = the committed bytes (sha256). So a green Linux leg *is* cross-OS byte equality with the Windows-built ELF | [src reproduce.sh:31-56] |
| Path independence by design: `--strip-all` (no symbol table carrying crate hashes) and no located panics on the guest paths (`Permutation::invalid_input` → `sdk::halt(1)`) | [src kernel/src/main.rs:21-24; README "Path independence"] |
| A guard test against path strings and `.symtab` in the pinned ELFs | [tested: `pinned_guests_contain_no_path_strings`, `the_detector_finds_a_source_path`] |
| The ids enter consensus through `include_str!` of `px/*.id` (one source), and a test checks the ELF against the id | [src prove.rs:35; tested: `px/tests/proof.rs:25`] |
| `.gitattributes`: `*.elf binary`, `*.id -text` (no CRLF damage on Windows) | [src] |
| Docker: pinned `rust:1.98.1-bookworm` tag, `.dockerignore` (no `target/`, `.git`, `.claude`, corpora), the build commit passed as a build arg | [src Dockerfile:11-16] |
| No root `rust-toolchain.toml`, a deliberate choice (SX2 C1: a GNU default host breaks the workspace). **Correct; keep it.** | [src README:27-29] |

### 2.2 What the evidence actually proves

- **The v2 kernel reproduced on `windows-latest`** in CI runs 78, 79 and 81–83 (green). That
  was the fixed-path build [web: API runs; session report §7].
- **The v3 platform-neutral kernel (`0577e667…`) and vault (`666f7aab…`)** were reproduced
  byte-identically **only on Windows**, from three directories (V3-B) [src README:76-92].
  - The `ubuntu-latest` leg of `guests` was added in `53d3b49`. It exists only in the 18
    unpushed commits, and `v3/candidate` pushes never trigger CI (`push.branches` is
    `[main, rebuild/core]`).
  - **So no Linux build of the neutral kernel has ever happened** [src + web]. The
    README's "Not yet verified here: a Linux build" is still true.
- **The "weekly" `audit` and `randomx-full` runs have never run.**
  - Scheduled workflows run from the default branch [web: GitHub docs].
  - The default branch is `main`, and `main`'s `ci.yml` has no `schedule` trigger (it is
    the old unpinned file).
  - The API reports `total_count: 0` for `event=schedule` [web].
  - The session report's "weekly audit" is therefore an unexecuted claim.
- **What the program id binds, measured on `px/kernel.elf`** [meas]:
  - The first `PT_LOAD` segment starts at file offset 0 (304 bytes: ELF header,
    program headers, `.eh_frame`). So the id covers the ELF header, including `e_shoff`
    (15120).
  - `e_shoff` lies after the non-loaded sections `.comment` (153 bytes: `rustc version
    1.98.1 (48a229cea 2026-09-01)` and `Linker: LLD 22.1.8 (…llvm-project.git
    52ed14fc…)`) and `.riscv.attributes`.
  - **So the consensus id depends on the exact rustc and LLD identification strings**,
    even for identical code. The vault is the same.
- **The node, miner and wallet binaries are not reproducible, and nothing tests this.**
  No release artifacts exist, and there are no tags [src: `git tag -l` empty; HEAD
  unsigned, `%G? = N`].

### 2.3 CI inventory (the current `ci.yml`, local HEAD)

| Job | Trigger | Runner | What it proves |
|---|---|---|---|
| lint | push/PR | ubuntu | fmt (workspace and fuzz); clippy `-D warnings`; a hand list of `forbid(unsafe_code)` roots |
| test | push/PR | ubuntu | the full workspace in release (35–68 min) |
| overflow | push/PR | ubuntu | 10 non-PX crates with overflow checks and debug assertions |
| randomx-full | push/PR/(schedule: dead) | ubuntu | full mode = light mode, official vectors |
| guests | push/PR | windows + ubuntu | kernel and vault byte reproduction; randomx vectors on Windows |
| audit | push/PR/(schedule: dead) | ubuntu | RustSec, root and fuzz locks |
| fuzz-smoke | push/PR | ubuntu | 120 s per target, `-O -a`, fails on zero executions |

**Missing:**
- CI on tags;
- aarch64, and a macOS run;
- a Windows test suite (only the randomx vectors run on Windows);
- a release workflow;
- a reproducibility check of the host binaries;
- cargo-deny;
- `third_party` tests;
- the nightly tier.

---

## 3. Problems in scope

### 3.1 Cross-OS (and cross-arch) reproduction of the consensus guests

**Problem.** `kernel.id` is consensus. The v3 build is path-neutral by construction and
by the Windows evidence, but three host-dependent inputs remain untested off Windows:
1. **Cargo's `-C metadata`** includes the host triple (cargo #13922) and the absolute
   path of path dependencies outside the workspace (cargo #7645: `px-core` and `sdk` are
   outside the guest workspace).
   - `StableCrateId` is a hash of the crate name and all `-C metadata` values
     [web: rustc docs].
   - The stripped ELF showed no effect across 3 paths on one host, which is strong
     evidence that the hash does not reach the loaded bytes. The host-triple component
     has not been exercised [assumed until CI runs].
2. **The host's LLVM/LLD binaries.** They are the same source commit for every host
   build of 1.98.1 (the `.comment` string embeds it). Codegen should be
   host-independent, but only a run proves it [assumed].
3. **The precompiled `core`/`compiler_builtins` rlibs** of `rust-std-riscv32i-…` are one
   artifact for all hosts [assumed: the rustup dist model].

- **Why it exists:** the neutral build was finished on the candidate branch, which CI does
  not run on.
- **Consequences:** if Linux differs, every non-Windows operator fails `reproduce.sh`.
  - Worse, the network would depend on one OS's rustc to define consensus.
  - Classification: consensus-critical (identity), verifiability, not privacy.
- **Prior art:**
  - Bitcoin Core Guix builds many HOSTS and compares `SHA256SUMS` across builders
    (`guix-attest`/`guix-verify`), with fixed paths and `SOURCE_DATE_EPOCH`;
  - Monero uses the same Guix flow;
  - reproducible-builds.org defines success as bit-by-bit identical artifacts from the
    same source, environment and instructions.
- **Fix:** push now and get the `ubuntu-latest` leg green **before** the single v3
  rebuild. Then add an `ubuntu-24.04-arm` leg (a third host arch, free for public repos)
  and a weekly `macos-15` leg.
- **Trade-off:** a Linux failure found now costs a redesign before the rebuild, not
  after it.
- **Tests:** the `guests` job on 3–4 hosts; one manual operator reproduction (R15 A4).
- **Invariant:** the committed ELF is the consensus artifact. Reproduction compares
  **bytes**, not just ids.

### 3.2 The single v3 kernel and vault rebuild (owned by 43)

**Problem.** Several accepted v3 items change guest inputs:
- F-20-1 `ApprovalConflict` (`px-core/src/kernel.rs`);
- W28-1 `ABI_VERSION` and the PX6 validity-window words (`px-core/src/call.rs::function_prefix`, used by the vault guest at `vault/src/main.rs:116`; whether the kernel changes depends on where the window words are checked);
- W28-4 (the vault lock hash binds the contract id, and hedged blinds);
- 19's comment and lint-attribute edits in `px-core` (no codegen, but they touch guest inputs).

Each rebuild creates new ids, which must be re-pinned downstream:
- the fingerprint (40);
- the budgets (20 W5);
- the widest proof and ZK-F4 (22/25);
- P-5 (26);
- the golden PX proofs (01/40).

**Solution: exactly one rebuild, gated.**
1. **Guest-input freeze list:** `px-core/**`, `zkvm/sdk/**`,
   `zkvm/guests/{kernel,vault}/**`, `zkvm/guests/{Cargo.toml,Cargo.lock,.cargo/config.toml,rust-toolchain.toml,build.sh}`.
2. **Gate:** the coordinator declares "all guest-affecting v3 items merged": 20 W1, 28
   W28-1/PX6/W28-4, and 19 items 1/4. Anything later needs another rebuild and a new id.
3. **Build:** once, on the owner's Windows machine (the evidence machine), with `build.sh`
   at the gated commit. Commit `px/kernel.elf`, `px/kernel.id`, `px/vault.elf`,
   `px/vault.id` and the README evidence table in **one commit**, with nothing else in it.
4. **Reproduce:**
   - CI `guests` on `windows-latest`, `ubuntu-latest` and `ubuntu-24.04-arm` (new) at
     that commit;
   - a local Linux container build (Docker Desktop/WSL2, `rust:1.98.1` digest-pinned),
     giving two host families on the owner's side;
   - one operator before the rc tag (R15 A4).
5. **Only then:** 20 re-measures the budgets. The budgets are host constants in
   `px/src/prove.rs`, **not in the ELF**, so re-pinning them needs no second rebuild.
   After that: the widest proof, P-5, the fingerprint, and the golden vectors.

**Rehearsal.** Run a throw-away rebuild in a worktree first (no commit). It proves the
tooling at the gated commit and measures the time. Native-vs-guest differential tests
(`px/tests/kernel.rs`, `unified.rs`, `kernel_diff`) catch semantic drift between px-core
and the ELF locally. Non-semantic codegen drift is caught only by `reproduce.sh`, so the
coordinator's merge checklist must run `reproduce.sh` for any diff touching the freeze
list (under 1 min).

- **What could go wrong:**
  - a late px-core edit after the rebuild (CI `guests` fails; this is by design);
  - a Linux mismatch (found early by §3.1);
  - a user-level cargo config silently altering the canonical build (§3.4, CI-6).
- **Invariants:**
  - one rebuild, one id pair per identity;
  - error codes are append-only;
  - never upgrade the guest toolchain without a new identity (CI-7).

### 3.3 Signed tags and the release procedure

**Problem.** There are no tags, signatures or artifacts (T-10, R15-5, still open).
Operators build from a commit id received over chat, so a compromised channel can
announce a different commit.

**Options:**
- **(a) GPG-signed tags.**
- **(b) SSH-signed tags** (git ≥ 2.34; `gpg.format=ssh`, `gpg.ssh.allowedSignersFile`
  with `valid-after`/`valid-before`, and a revocation file). GitHub verifies SSH signing
  keys, and a verification recorded once stays verified after key rotation.
- **(c) sigstore gitsign.** Keyless OIDC. The signing certificate, **including the
  identity email**, goes to the public Rekor log. GitHub shows gitsign signatures as
  "Unverified".

**Recommendation: (b)**, with a hardware-backed `ed25519-sk` key if the owner has a FIDO2
token [assumed: GitHub accepts sk keys for signing; verify], and a **pseudonymous
principal** in `allowed_signers`. (c) is rejected: it publishes an identity in a
permanent public log, which is a privacy cost for a privacy-first project, and it is
unverifiable in GitHub's UI.

**Procedure (maps R15 B1–B3 and genesis §6):**
1. **`testnet-v3-rc` (signed, annotated).**
   - The tag message contains: the full commit, kernel and vault ids, the consensus
     fingerprint, the rustc `-vV` line, the CI run URL, and `sha256` of
     `git archive --format=tar <tag>` [assumed stable across git versions for `tar`;
     not for gzip].
   - The archive hash gives a SHA-256 anchor, since git objects are SHA-1 (hardened with
     collision detection) [web: git hash-function-transition].
2. The CI run of the tag must be green: add `tags: ['testnet-*']`. Today a tag push
   triggers **nothing** (CI-3).
3. The genesis ceremony, then the final commit: constants only (`git diff rc..final`
   limited to the genesis files, checked by a script).
4. **`testnet-v3` (signed).**
5. Publish the signing-key fingerprint and the consensus fingerprint in-repo
   (`SECURITY.md`) **and** in a second channel.
6. Enable GitHub **immutable releases**: tags and assets are locked after publication,
   and release attestations are created.
7. Branch/tag rulesets: no force-push on `rebuild/core`; tag deletion restricted.

**Tests:**
- a `verify-tag` step in the release workflow (`git verify-tag` against the committed
  `allowed_signers`: a consistency check, not the root of trust);
- a `diff-constants-only` script with unit tests.

**Invariants:**
- no admin keys or kill switch (never-change 9); the signing key signs releases only,
  never consensus data;
- no maintainer-signed checkpoints.

### 3.4 Reproducible node, miner and wallet binaries

**Problem.** A released binary should be rebuildable bit for bit by an independent
builder. Today there is no pipeline, and three mechanisms defeat it [src + web;
magnitude assumed until measured]:
1. **Absolute paths in `.rodata`:**
   - panic `Location`s of registry crates carry `$CARGO_HOME/registry/src/…`;
   - `strip = true` removes symbols, not these strings.
   - A binary built by the owner therefore contains `C:\Users\<name>\.cargo\…`. That is
     non-reproducible, and a **small privacy leak** of the builder's account name into
     every binary they distribute (CI-5).
2. **Path deps outside the workspace:** `third_party/p3-*` is `exclude`d and used via
   `[patch]`. Its absolute path is hashed into `-C metadata` (cargo #7645), and so into
   `StableCrateId`, which feeds `TypeId` constants and v0-mangled data.
3. **The host triple** in the metadata hash (cargo #13922) only matters for cross-host
   builds.

**Stable tools available in 1.98.1:**
- `--remap-path-prefix` via `RUSTFLAGS`. Cargo does **not** put `RUSTFLAGS` into
  `-C metadata` [web: cargo PR #14898 docs];
- `profile.trim-paths` is **not** stable (FCP to stabilize "assumed 1.101", with no
  default for `release`) [web: cargo PR #17488];
- `-Zsbom` is unstable.

**Solution (the Bitcoin Core/Monero principle, not their Guix stack):**
- build in a **digest-pinned `rust:1.98.1-bookworm` container at a fixed path**
  (`/src`, `CARGO_HOME=/usr/local/cargo`);
- `RUSTFLAGS="--remap-path-prefix=/src=/blacksilk --remap-path-prefix=/usr/local/cargo/registry/src=/registry"`;
- `BLACKSILK_BUILD_COMMIT=<full sha>`, `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)`
  (for the archives);
- `cargo auditable build --locked --release`.

A `repro-check` job builds twice (two runners, or two paths plus two clean `target/`
directories) and compares `sha256`. Windows MSVC binaries use the non-Rust `link.exe`
(PE timestamps unless `/Brepro`) [assumed]. They are **attested but not claimed
reproducible**.

- **Trade-offs:**
  - container builds exclude operators' native toolchains, which is fine: operators may
    still build from source, with the recorded rustc;
  - Guix-level bootstrappability (a trusted rustc: mrustc/Guix) is XL and P3. Record the
    toolchain manifest hash instead (CI-13).
- **Tests:** the `repro-check` job; the second-builder comparison before each tag.
- **Invariant:** product binaries contain no C/FFI code (`cargo-auditable` is a
  build-time tool; its `.dep-v0` section is sorted, timestamp-free JSON, under 4 kB).

### 3.5 SBOM, provenance and attestations

**Options:**
- **cargo-auditable 0.7.6:** the dependency list embedded in the binary, readable by
  `cargo audit bin`, syft, trivy, osv-scanner and grype;
- **cargo-cyclonedx 0.5.9:** a CycloneDX file per binary (`--describe binaries`). Its
  serial number and timestamp handling is [unknown], so the SBOM is a release asset
  **outside** the bit-for-bit set; a fallback is `auditable2cdx` from the embedded data;
- **GitHub artifact attestations** (`actions/attest`, v4; `attest-build-provenance` is
  now a wrapper):
  - SLSA v1 Build L2 by default, L3 with an isolated reusable workflow;
  - public repositories sign through the Sigstore public-good instance and log to the
    public Rekor.
  - Privacy: the log reveals only the repository, the workflow and the commit, which are
    already public. Acceptable.

**SLSA levels:**
- L1 (provenance exists) and L2 (hosted, signed provenance) are reachable in one
  workflow.
- L3 needs a reusable workflow with isolated signing. That is P2.
- The attestation says *where* an artifact was built, not that it is *good* (GitHub's
  own caveat). The user-side check stays the signed `SHA256SUMS` plus reproduction.

**Permissions:** only the release job gets `id-token: write`, `attestations: write` and
`artifact-metadata: write`. Every other job keeps `contents: read`.

**No caches in the release workflow:** cache poisoning from other runs.

### 3.6 aarch64

Native `ubuntu-24.04-arm`/`windows-11-arm` runners are free for public repositories
(4 vCPU) [web]. They serve three purposes:
1. 08's RandomX determinism (their workflow);
2. a guests reproduction leg (§3.1);
3. aarch64 Linux release binaries built natively in the arm64 digest of the same
   container, compared across two builds.

A weekly full workspace suite on arm64 closes "consensus code never executed on aarch64"
beyond RandomX (tx, crypto, zk). The `u128`/soft-AES paths are 08's scope.

### 3.7 What must never change

1. SHA-pinned actions; the default token `contents: read`; write permissions only in the
   release job; no `pull_request_target`.
2. `--locked` for every build, test and tool install.
3. The committed ELF is the consensus artifact; CI compares **bytes** on every push, on
   ≥ 2 host OSes.
4. The guest toolchain is pinned by release **and** commit; no root `rust-toolchain.toml`
   (SX2 C1).
5. `fuzz/` stays a separate workspace (its C++ never enters a product build).
6. No caches restored into release builds; release binaries are built only from a signed
   tag.
7. No gitsign, and no identity-bearing public log entries for the maintainer.

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **CI-1** | **High** (P0 evidence; consensus identity) | Not implemented (never executed) | `.github/workflows/ci.yml:3-5,138-156` (branch filter; the Linux leg only local); `zkvm/guests/README.md:91-92` | The platform-neutral kernel and vault ids have never been built on Linux. The dual-OS matrix exists only in 18 unpushed commits, and `v3/candidate` pushes trigger nothing (API: last run #83 at `65bcec1`). If Linux differs, the "neutral" design fails after the single rebuild, and non-Windows operators cannot reproduce consensus. | high (gap); low–medium (that Linux actually differs) |
| **CI-2** | **Medium** | Not implemented | ci.yml:9-10; default branch `main` (`origin/HEAD`); `main`'s ci.yml has no `schedule` | Scheduled workflows run from the default branch: **0 scheduled runs ever**. The weekly RustSec audit and weekly full-mode RandomX never happen, and every weekly leg planned by 05/08/41/42 would be dead. The session report's "weekly audit" is false. | high |
| **CI-3** | Low–Medium | Not implemented | ci.yml:3-5 (`branches` only) | A tag push runs nothing (GitHub docs). R15 B1, "CI green on the exact tag", holds only if the same SHA was pushed on a branch. The constants-only final commit could be tagged without its own run. | high |
| **CI-4** | Medium (High for a public testnet) | Not implemented (known T-10/R15-5; still open) | no `release.yml`, no `allowed_signers`, `git tag -l` empty, HEAD `%G? = N` | Operators cannot authenticate the commit or the binaries: a compromised chat or account announces a different commit. | high |
| **CI-5** | Medium (reproducibility); Low (privacy) | Not implemented | `Cargo.toml:25,27-35,60-63` (`strip` only; `third_party` outside the workspace); no remap anywhere | Two builders at different paths get different node binaries (registry paths in panic locations; out-of-workspace path deps hashed into `-C metadata` → `StableCrateId`). A binary the owner builds on Windows embeds `C:\Users\<account>\.cargo\…`. | medium (mechanism [src/web]; magnitude unmeasured) |
| **CI-6** | Low | Partially implemented | `zkvm/guests/build.sh:38-57` | `guest_check_env` refuses env overrides but not **cargo config files**: ancestor `.cargo/config.toml` or `$CARGO_HOME/config.toml` with `[profile.release]` (config profiles override the manifest), `build.rustc-wrapper` (e.g. sccache), or `target.riscv32i….linker`. The result is a false mismatch for an operator, or a non-canonical build by the rebuilder. CI catches the latter. | high (mechanism, Cargo docs); low (likelihood) |
| **CI-7** | Informational | Accepted limitation (document) | measured: `px/kernel.elf` `e_shoff` 15120 after `.comment` (153 B, rustc + LLD commit strings); first `PT_LOAD` at offset 0 | The consensus id binds the toolchain identification strings. Any rustc or LLD change gives a new id even for identical code. That is a useful provenance property, but it must be stated: the guest toolchain can never change within an identity. | high [meas] |
| **CI-8** | Low | Partially implemented | `deploy/docker/Dockerfile:11,23` | `rust:1.98.1-bookworm` and `debian:bookworm-slim` are tags, not digests, contrary to the SX2 C1 resolution. Images drift with Debian rebuilds, so the image is not reproducible. There is no `STOPSIGNAL`/`HEALTHCHECK` (R10-9). | high |
| **CI-9** | Low | Partially implemented | ci.yml:49-50 | The `forbid(unsafe_code)` crate list is hand-maintained and **omits `tools/supply-audit`** (which has the attribute today). A new crate can land without the check. | high |
| **CI-10** | Low | Partially implemented | ci.yml:104-108 | The overflow job excludes `zk`, `zkvm` (the interpreter), `px`, `wallet` (8 `debug_assert!`s), `rpc` and the tools. These are T-2's named overflow surfaces. | high |
| **CI-11** | Low | Not implemented | ci.yml | The workspace suite never runs on Windows (only the randomx vectors) or on aarch64. The Windows evidence is local only. 13 asks for Windows plus Linux. | high |
| **CI-12** | Informational | — | ci.yml:21-22 | `actions/checkout` v4.4.0 declares Node 20, which GitHub removed on 2026-09-23. Runs 81–83 are still green (forced Node 24). Bump to a Node 24 major, SHA-pinned. `dtolnay/rust-toolchain` is pinned to a `master` SHA (provenance note, R15 §5.4). | medium |
| **CI-13** | Low | Not implemented | toolchain installs (dtolnay action, rustup, Docker) | rustup verifies only the SHA-256 of the channel manifest from the same server; GPG checking was removed in 1.26. The trusted compiler has no recorded manifest hash, so a CDN-level substitution would go unnoticed. | medium |
| **CI-14** | Low | Partially implemented | `deploy/scripts/install-linux.sh:23`; `docs/testnet.md:41-47` | Operator builds do not check the rustc version (the docs' command lacks `--locked`). R15 B3's "record rustc per device" has no tool support. | high |
| **CI-15** | Informational | Not implemented (known) | `third_party/README.md` | The patched Plonky3 crates' tests run only in a manual upstream checkout, never in CI (owner 44 for the verification script). | high |
| **CI-16** | Informational (privacy) | Decision | — | gitsign would publish the signer's OIDC e-mail permanently in Rekor. Reject; use SSH signing with a pseudonymous principal. | high [web] |
| **CI-17** | Informational | — | `reproduce.sh:29` (`sha256sum`) | Not on stock macOS (`shasum -a 256`) [assumed]. A macOS guests leg needs a fallback, or the id tool should print sha256. | medium |

---

## 5. Implementation plan for phase 2

All items change **nothing externally visible** in consensus, except W4, which executes
the already-decided v3 identity change.

| # | Item | Files (ownership) | Visible? | Identity | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| **W1** | **Get CI-1 evidence now:** push HEAD (routine push, delegated); confirm `guests` green on `ubuntu-latest` for `0577e667…`/`666f7aab…` **before** any kernel change; if red, diagnose (diffoscope-style section compare) before the rebuild | none (coordinator/owner push) | none | none | the `guests` job | README "Verified" row | S | **P0, first** |
| **W2** | **Make schedules and tags real:** the owner sets the default branch to `rebuild/core` (repository setting), or `main` gets the same workflow; add `tags: ['testnet-*']` to `push`; a `concurrency` group; checkout bumped to a Node 24 major (SHA-pinned, verified) | `.github/workflows/ci.yml` (**43**) | none | none | a scheduled run appears (API `event=schedule` > 0) | session report / checklist G3 claims (**47**) | S | **P0** |
| **W3** | **ci.yml restructure:** lint derives the crate list from `cargo metadata --no-deps` plus `jq` (CI-9); overflow adds `zkvm` (non-proving tests), `wallet` (skip PX e2e), `rpc`, `tools/*` (CI-10); `guests` adds `ubuntu-24.04-arm` (per push) and `macos-15` (weekly, CI-17 fallback); `randomx-full` gets 05's 1,024-hash per-push subset and 06's W2 digest; a `deny` job (44's `deny.toml`); a Windows `test` leg per push to `rebuild/core` (not PRs); an aarch64 full suite weekly (CI-11) | `.github/workflows/ci.yml`, `.github/scripts/*` (**43**) | none | none | CI itself | `docs/testnet-launch-checklist.md` G3 job list (**47**) | M | **P0** (arm guests, deny, crate list) / P1 (the rest) |
| **W4** | **The single v3 kernel and vault rebuild** (§3.2): gate, rehearsal, one commit with the ELFs, ids and README table; reproduction on 3 CI hosts plus a local Linux container plus one operator | `px/kernel.elf`, `px/kernel.id`, `px/vault.elf`, `px/vault.id`, `zkvm/guests/README.md` (**43**). Downstream re-pins by others: `px/src/fingerprint.rs` pins (**40**), `px/src/prove.rs::kernel_budget` (**20**), golden PX proofs (**01/40/22**) | **CONSENSUS** (decided v3 items) | new kernel and vault ids (v3) | `px/tests/proof.rs` pin, `elf_paths`, `unified`, `kernel`, `kernel_diff` (native = guest), `reproduce.sh` on every host | px.md §4.3 id, `v3-upgrade-mechanism.md` (**47**) | M | **P0** |
| **W5** | **Harden the guest scripts:** refuse ancestor and `$CARGO_HOME` cargo config files that set `profile`, `build.rustc-wrapper`, `build.rustc` or `target.riscv32i-unknown-none-elf.*` (CI-6); a sha256 fallback (CI-17); print the toolchain manifest hash and check it against a committed `zkvm/guests/toolchain.sha256` (CI-13); document CI-7 in the README | `zkvm/guests/{build.sh, reproduce.sh, README.md, toolchain.sha256}` (**43**) | none | **none: must land before W4** (the build script is not an ELF input, but keep one ordering) | a script self-test in CI (a fake config makes `build.sh` refuse) | README | S | **P0** (before W4) |
| **W6** | **Signed tags and the release procedure:** `docs/release.md` (new: key type, `allowed_signers`, tag message template, rc→final flow, constants-only diff check, two-channel fingerprint, immutable releases, rulesets); `.github/allowed_signers` (owner's public key, pseudonymous principal); a `SECURITY.md` "Release signing" section; `tools/release/check-final-diff.sh` | `docs/release.md`, `.github/allowed_signers`, `tools/release/*` (**43**); `SECURITY.md` section (**43** content, **47** review) | none | none | the diff-check script tests (allowed and forbidden paths); a `verify-tag` dry run on a test tag in a fork | testnet-v3-genesis.md §6 cross-links (**40**) | S | **P0** (before `testnet-v3-rc`) |
| **W7** | **`release.yml`:** on a signed `testnet-*` tag plus dispatch → verify-tag → Linux x86_64 and aarch64 builds in the digest-pinned container at a fixed path, `cargo auditable` (0.7.6, `--locked`), remap flags, full-sha `BLACKSILK_BUILD_COMMIT` → smoke (`--version` shows the expected fingerprint and kernel id; 08's `--randomx-self-test`) → CycloneDX SBOM (0.5.9) → `SHA256SUMS` → `actions/attest` (provenance plus SBOM; SHA-pinned) → **draft** release. The owner's second build (W8) and an `ssh-keygen -Y sign -n file` signature over `SHA256SUMS` come before publishing. Windows binaries: attested only | `.github/workflows/release.yml`, `deploy/release/{build.sh, Dockerfile.release}` (**43**) | none | none | a dry run on a rehearsal tag; `gh attestation verify`; `cargo audit bin` on the output | `docs/release.md`, `docs/testnet.md` §2 (**47** review) | M | **P1** (P0 if outside operators get binaries rather than building from the tag) |
| **W8** | **Reproducibility check (CI-5):** a `repro-check` job (weekly and pre-release) builds node, miner and wallet twice (different runner, different path, clean target) in the W7 container and compares sha256; plus the owner's local second-builder recipe (Docker Desktop/WSL2). Measure the effect of `third_party` path hashing and of the remap | `.github/workflows/release.yml` (job) or `nightly.yml` (**43**); `deploy/release/*` | none | none | the job itself (red until it matches); record the first measurement as evidence | `docs/release.md` "what is reproducible" | M | **P1** |
| **W9** | **Docker:** digest-pin both bases (amd64 and arm64 index digest), `STOPSIGNAL SIGTERM`, a `HEALTHCHECK` once `/health` exists (R10-9), `SOURCE_DATE_EPOCH`, full-sha build arg in the docs | `deploy/docker/Dockerfile` (**43**; HEALTHCHECK endpoint from **36**) | none | none | `node/tests/deploy_configs.rs` unaffected; build in CI (weekly) | Dockerfile header | S | **P1** |
| **W10** | **Toolchain recording for operators (CI-14):** `install-linux.sh` refuses a non-1.98.1 rustc without `--allow-toolchain`; the node embeds `rustc -vV`'s release and commit (from `$RUSTC -vV` in `node/build.rs`, pure Rust, no new dependency) and shows it in `--version` and `/info` next to the build commit; the docs add `--locked` | `deploy/scripts/install-linux.sh` (**43**); `node/build.rs` (**43**, coordinate **40**, who owns `node/src/fingerprint.rs`, and **36** for `/info`) | policy (the info output) | none | `node/tests/build_id.rs` extension | testnet.md §2/§2.1 (**47**) | S | P1 |
| **W11** | **Workflow files requested by other dossiers** (43 writes or reviews the pins; content from the requester): `randomx-determinism.yml` (**08** spec; aarch64, soft-AES, v3 and QEMU legs); `randomx-conformance.yml` (**05**: the refgen C++ oracle fetched at a pinned tevador SHA, `workflow_dispatch`/pre-release only, shards < 6 h); `nightly.yml` (**41** corpus replay and 1–2 h fuzz; **42** `cargo-mutants --in-diff`; weekly `llvm-cov`); `third_party` test job (**44**) | `.github/workflows/{randomx-determinism,randomx-conformance,nightly}.yml` (**43**, specs by 05/08/41/42/44) | none | none | the jobs | CI section of docs (**47**) | M | P1 (determinism core, refgen) / P2 |
| **W12** | **`clippy.toml`** at the root with 19's `disallowed-methods` entry for `blacksilk_px_core::hash::node`; clippy for the guests workspace (`--target riscv32i-unknown-none-elf`) in the `guests` job | `clippy.toml` (**43**, content **19**); ci.yml | none | none (attributes only; W4 follows anyway) | clippy | registry doc (**19**) | S | P1 (**before W4** if a px-core attribute is needed) |
| **W13** | 06 W11 PGO miners; SLSA L3 reusable workflow; Guix/mrustc bootstrapped toolchain; bit-reproducible Windows binaries (`/Brepro`, lld-link) | — | none | none | — | — | L–XL | P3 |

**Order:** W1 → W2 → W5 → W12 (if px-core is touched) → the guest-affecting consensus
items (20/28/19) → **W4** → re-measurements (20/22/25/26) → the fingerprint (40) → W6 →
`testnet-v3-rc`. W3, W7–W11 run in parallel with the consensus work.

**Benchmarks:**
- CI wall time per tier;
- the W4 rebuild time (about 1 min per guest [assumed]);
- W8: the build time in the container.

**CI budget:** the repository is public, so standard and arm64 runners cost nothing.
- Limits: 6 h per job, 20 concurrent jobs, 5 on macOS [web].
- The added per-push cost is about 3 jobs: the arm guests leg (about 5–10 min), deny
  (about 2 min), and Windows tests (about 60–90 min [assumed]).

---

## 6. Dependencies, conflicts and every CI request from the dossiers

| From | Request | Where it lands |
|---|---|---|
| 01 | CI jobs for the frozen vector files; `cargo-mutants` on consensus (item 11, P2) | normal `test`; W11 `nightly.yml` (42) |
| 02 | proptest reference model (W-1) | normal `test`; the fixed seed is set in the tests |
| 03 | `tools/daa-sim` workspace member; the reduced harness test in CI | normal `test`; W3 crate-list auto-derivation covers it |
| 05 | a 1,024-hash subset per push; full tiers pre-release and dispatch, sharded < 6 h (coordinator: not weekly); refgen C++ via a pinned SHA as a separate dispatch workflow; the `randomx-full` extension | W3 (`randomx-full`), W11 (`randomx-conformance.yml`) |
| 06 | `randomx-full` W2 digest; W11 PGO (P3); no x86-64-v3 release variant (decided) | W3; W13 |
| 08 | `randomx-determinism.yml` (approved, separate file; reuse 43's pins); aarch64 release builds run `--randomx-self-test`; D-11 expected-failure i586/i686 checks | W11; W7 smoke step |
| 12 | the stateful mempool test under 60 s in CI | normal `test` |
| 13 | the whole workspace on Windows and Linux CI | W3 Windows leg |
| 19 | `clippy.toml` `disallowed-methods`; ELF-id reproduction after the comment edits | W12; W4 covers it (one rebuild after all edits) |
| 20 | the single rebuild (43 builds, 20 re-measures); a guest-interpreter proptest sample in CI, bounded | W4; normal `test` |
| 28 | one rebuild of the kernel **and vault** after all v3 items; confirm that the `function_prefix` edit leaves the kernel ELF unchanged | W4. The kernel does not call `function_prefix` [src grep: only `px/src/prove.rs`, `vault/src/main.rs`]; if the window check puts prefix words into the kernel, the kernel changes too. Either way it is covered by the single rebuild |
| 41 | corpus replay, nightly campaigns (dossier pending) | W11 `nightly.yml` |
| 42 | `cargo-mutants` feasibility and `--in-diff` | W11 |
| 44 | `cargo-deny` job, `third_party` verification, the `cross` pin, dev-dependency checks | W3 `deny` job (44 owns `deny.toml`); W11 |
| 36 / 35 | `/health` for the Docker HEALTHCHECK; SIGTERM (R10-9) | W9 |
| 40 | the fingerprint re-pin after W4; the genesis procedure's tag steps | W4 downstream; W6 |
| 47 | stale CI claims (weekly audit, G3 job count, AUDIT "four jobs", consensus.md §9) | W2/W3 docs |
| 50 | red-team the rebuild gate and the release flow (tag substitution, cache poisoning, workflow permission escalation) | review of W4/W6/W7 |

**Conflicts:**
- `ci.yml` has a single owner (43). Every requester sends a spec, not an edit.
- `node/build.rs` (W10) touches the same build-identity path as 40's fingerprint work, so
  serialize the two.
- `px/*.elf|id` must never be edited by anyone else after W4.

---

## 7. Open questions for the coordinator

1. **The default branch (CI-2):** may the owner switch GitHub's default branch to
   `rebuild/core`? That is the only change that makes any `schedule` trigger work. The
   alternative is keeping `main` in sync (a merge per release).
2. **Push now (W1):** 18 local commits, including the v3 merge. The Linux evidence for the
   neutral kernel should exist before the rebuild gate. Is that a routine push under the
   delegated policy?
3. **Signing key:** does the owner have a FIDO2 token (`ed25519-sk`), or a software SSH
   key with a passphrase? What is the second channel for the fingerprints? A
   pseudonymous principal in `allowed_signers` is proposed.
4. **Trial distribution:** do the 7 trial operators build from the signed tag (then W7 is
   P1), or receive binaries (then W7 and W8 are P0)?
5. **Workflow ownership:** confirm that 43 authors all new workflow files (release,
   determinism, conformance, nightly) from the specs of 05/08/41/42/44, or whether 08
   keeps authoring `randomx-determinism.yml` with 43 reviewing the pins.
6. **CI on all pushed branches** (for example `v3/*` or agent branches), so a candidate
   branch can never again skip the Linux legs? This costs minutes, not money, on a public
   repository.
7. **Windows release binaries:** publish them attested but "not reproducible", or not at
   all for the trial?

---

## 8. Sources

**Reproducible builds and Rust:**
- reproducible-builds.org, *Definitions*: https://reproducible-builds.org/docs/definition/
- reproducible-builds.org, *SOURCE_DATE_EPOCH*: https://reproducible-builds.org/docs/source-date-epoch/
- reproducible-builds.org, *Build path*: https://reproducible-builds.org/docs/build-path/
- Cargo issue #7645, path dependencies outside the workspace get hashed: https://github.com/rust-lang/cargo/issues/7645
- Cargo issue #13922, host triple in the metadata hash: https://github.com/rust-lang/cargo/issues/13922
- Cargo issue #6914 (RUSTFLAGS and `--remap-path-prefix` vs metadata): https://github.com/rust-lang/cargo/issues/6914 ; Cargo PR #14898 (RUSTFLAGS do not affect `-C metadata`): https://github.com/rust-lang/cargo/pull/14898
- rustc `StableCrateId` (a hash of the crate name and all `-Cmetadata`): https://doc.rust-lang.org/nightly/nightly-rustc/rustc_span/def_id/struct.StableCrateId.html
- RFC 3127 trim-paths: https://rust-lang.github.io/rfcs/3127-trim-paths.html ; Cargo stabilization PR #17488 (FCP, "assumed 1.101", no release default): https://github.com/rust-lang/cargo/pull/17488 ; tracking: https://github.com/rust-lang/cargo/issues/12137
- Cargo unstable features (trim-paths, `-Zsbom`): https://doc.rust-lang.org/cargo/reference/unstable.html
- Cargo configuration (hierarchy, `[profile]` precedence, `rustc-wrapper`, rustflags order, linker): https://doc.rust-lang.org/cargo/reference/config.html
- rustup GPG verification removed; SHA-256 of the manifest only (issue #2028, changelog): https://github.com/rust-lang/rustup/issues/2028 ; https://github.com/rust-lang/rustup/blob/main/CHANGELOG.md
- mrustc (an alternative rustc bootstrap, P3): https://github.com/thepowersgang/mrustc

**SBOM, provenance and attestations:**
- cargo-auditable (`.dep-v0`, reproducible, readers): https://github.com/rust-secure-code/cargo-auditable ; crates.io 0.7.6: https://crates.io/crates/cargo-auditable
- cargo-cyclonedx: https://github.com/CycloneDX/cyclonedx-rust-cargo ; crates.io 0.5.9: https://crates.io/crates/cargo-cyclonedx
- SLSA v1.1 build levels: https://slsa.dev/spec/v1.1/levels
- GitHub artifact attestations (Build L2, L3 with reusable workflows, public-good Sigstore): https://docs.github.com/en/actions/concepts/security/artifact-attestations
- `actions/attest` (v4; permissions `id-token`, `attestations`, `artifact-metadata`): https://github.com/actions/attest ; `attest-build-provenance` as a wrapper: https://github.com/actions/attest-build-provenance
- GitHub immutable releases (GA 2025-10-28): https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/
- Docker reproducible builds with `SOURCE_DATE_EPOCH`: https://docs.docker.com/build/ci/github-actions/reproducible-builds/

**Signing:**
- git-config `gpg.format=ssh`, `gpg.ssh.allowedSignersFile`, `revocationFile` (git 2.34): https://git-scm.com/docs/git-config
- GitHub commit and tag signature verification (SSH, persistent verification): https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification
- sigstore gitsign (Rekor publishes the certificate identity; GitHub shows it "Unverified"): https://github.com/sigstore/gitsign
- git SHA-1 to SHA-256 transition: https://git-scm.com/docs/hash-function-transition

**GitHub Actions:**
- Events: `schedule` runs on the default branch; branch-only filters skip tags; 60-day schedule disable: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- arm64 hosted runners for public repositories (`ubuntu-24.04-arm`, `windows-11-arm`, 4 vCPU, free): https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/
- Limits (6 h per job; 20 concurrent, 5 macOS): https://docs.github.com/en/actions/reference/limits
- Node 20 removed from runners (2026-09-23): https://github.blog/changelog/2026-09-23-node-20-is-no-longer-available-in-github-actions/ ; deprecation notice: https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
- SHA-pinning policy enforcement (2025-08-15): https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/ ; tj-actions compromise, CVE-2025-30066: https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- Public run data (read-only): https://api.github.com/repos/StickyFingaz420/BlackSilk-Blockchain/actions/runs (last run #83 `65bcec1`; `event=schedule` total 0)

**Established projects:**
- Bitcoin Core Guix builds (HOSTS, `guix-attest`/`guix-verify`, `SHA256SUMS`, fixed paths, `SOURCE_DATE_EPOCH`): https://github.com/bitcoin/bitcoin/tree/master/contrib/guix
- Monero Guix builds: https://github.com/monero-project/monero/tree/master/contrib/guix

**Repository** (source-read at `9e422d8`): the files in §1. No build or test was run. The
ELF section measurements come from reading `px/kernel.elf` and `px/vault.elf` read-only.
