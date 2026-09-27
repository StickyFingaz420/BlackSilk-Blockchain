# 48 threat-model-adversarial: research dossier (phase 2, phase 1)

Agent 48. Internal engineering research, not an audit. Read-only on the repository; no
builds or tests were run. Nothing here claims that BlackSilk is secure, audited,
production-ready or perfectly zero-knowledge. Web research used public primary sources
only; no repository content was sent anywhere.

Evidence tags: **[math]**, **[test: name]**, **[src]** source-read by me, **[doc]** read in
a project document, **[ext]** external primary source (§8), **[assumed]**, **[unknown]**.

---

## 1. Scope and what I read

- **Commit:** `rebuild/core` @ **`9e422d8`** (`git rev-parse --short HEAD`), clean tree.
- **Required reading:** `C:/bszkeval/p2/brief.md`; `roster.md` (all 50 entries: my scope is
  the whole system); `decisions.md` (all); `docs/reviews/full-review-2026-09-27.md` (all
  1,421 lines); `docs/reviews/autonomous-session-2026-09-27.md` (all).
- **Every dossier present in `research/` at writing time:** 01–43, 45, 49 (44, 46, 47, 50 not
  yet written). 01–09 read in full; 10–43, 45, 49 read at their findings sections (§4) and,
  where my attack paths led, their problem sections (30 §3, 36 §3, 38 §3.3, 39 §3, 40 §4).
  I use them to mark what is **already covered**, so that this dossier reports only gaps.
- **Code read, following attack paths:**
  - `p2p/src/transport.rs` (handshake, KDF inputs, lines 1–80), `p2p/src/net.rs` (stem keys
    2140–2155, logging sites 380–1820, accept loop);
  - `chain/src/manager.rs` 600–705 (`submit_inner`: store append before validation) and the
    `expect`/`assert` inventory; `tx/src/state.rs` 150–256 (`apply_block`, `undo_block`);
    `px/src/state.rs` 100–145 (`apply_inner`); `tx/src/validate.rs` arithmetic (969–1055),
    nullifier rules (513–525); `tx/src/px.rs` 483–620 (`contract_id`, `load_programs`);
  - `wallet/src/wallet.rs` 995–1135 (`sync`, trust in node data);
  - `tools/supply-audit/src/main.rs` (inputs), `docs/testnet.md` §7.1 and §12;
  - `zkvm/sdk/src/lib.rs` (`entry!`, panic handler, `halt`), `zkvm/guests/kernel/src/main.rs`,
    `px/src/prove.rs` 130–205 (exit-code and output checks), `zk/src/lib.rs` 430–455
    (transcript observations);
  - `.github/workflows/ci.yml` (triggers, permissions, pins, `guests` job),
    `zkvm/guests/reproduce.sh`, workspace `Cargo.toml` profiles, `Cargo.lock` (build-script
    and proc-macro census against the local registry).
- **Repository metadata:** `git log --format=%G?` (452 unsigned `N`, 7 `E`), `git tag`
  (empty), no `.github/CODEOWNERS`; a scan of tracked `*.rs|md|toml|yml|sh` for bidi and
  invisible Unicode (none found).

---

## 2. Current state (the defended perimeter)

What an attacker faces today, with the evidence class of each claim. I list only what
bears on the attack tree; the domain dossiers hold the detail.

| # | Property | Evidence |
|---|---|---|
| S1 | Header rules written once (`check_rules`), PoW last, strictly-greater most-work, body-complete fork choice, invalidity propagated. | [test] (01, 02) |
| S2 | Block validation arithmetic is overflow-safe: weight and fees summed in `u128`, PX pool `u128` with `checked_sub`, same formula in validation (`validate.rs:1054`) and apply (`px/src/state.rs:131-134`). | [src] |
| S3 | The PX proof cache (PX5 skip) is gated on the rule domain, and the contract id commits to the deploy's programs (`px.rs:593-606` hashes `deploy_payload_bytes(salt, programs)`), so the Zebra CVE-2026-34377/40880 "same id, different authorizing data" swap does not apply to registrations across branches today. | [src] |
| S4 | zkVM statement: the PX verifier requires exit code 0 and the exact expected output words (`px/src/prove.rs:192-203`); a guest panic halts with 1 (`zkvm/sdk/src/lib.rs:79-82`). The SP1-2.1 class (early halt with unconstrained committed values) does not transfer. | [src] |
| S5 | Transcript: instance count, per-instance binding and public values are observed before challenges (`zk/src/lib.rs:435-454`); `CIRCUIT_ID` and the statement digest are in the transcript (22, 23, 24). | [src] (deep checks owned by 22/24) |
| S6 | Guest ELFs are consensus artefacts, but CI rebuilds them on Windows and Linux and requires byte identity with the committed files (`reproduce.sh`, `ci.yml:138-158`). | [src] |
| S7 | CI hygiene: SHA-pinned actions, explicit `permissions`, `--locked`, pinned tool versions, `persist-credentials: false` on the guest job. | [src] |
| S8 | No bidi or invisible Unicode in tracked text files at `9e422d8`. | [src] (my scan; no CI check exists) |
| S9 | Stem-pool conflict keys are key images and PX nullifiers only (`net.rs:2146-2152`), so relay-level output-key griefing does not exist even after D8-B. | [src] |

**What the perimeter does not include:** peer authentication, a signed release, any
branch protection or code-ownership rule, any control over the development pipeline
itself (people, agents, build machine), and any custody rule for the trial's supply
audit. Those are where §4's new findings sit.

---

## 3. Attack tree, ranked

### 3.1 Method

- One root: **"break BlackSilk's security, privacy or liveness during the v3 trial, or plant
  something that survives into a public testnet"**.
- Nine branches (A–I below). Each leaf gets **feasibility** (F: 1 = needs a research
  breakthrough … 5 = one person, one day, public tools) and **impact** (I: 1 = nuisance …
  5 = silent consensus/value/privacy failure for everyone), for the **trial** model (7
  trusted devices, explicit `--peer` lists, Windows desktops, one maintainer, an agent
  swarm doing the engineering) and, where different, for a **public** testnet.
- **Rank = F × I** (trial). **Coverage** names the dossier that owns the leaf; "**GAP**"
  marks leaves no dossier covers, which §4 develops.

### 3.2 The tree

| Leaf | Attack | F | I | Rank | Coverage |
|---|---|---|---|---|---|
| **A. Consensus** | | | | | |
| A1 | Rent/redirect JIT rx/0 hash power, rewrite history (K1 fails) | 5 | 4 | 20 | R1-C2, accepted; 02 W-7 park policy |
| A2 | Difficulty-raising (Bahack) private branch at 30–40 % | 3 | 4 | 12 | 03-F1, decided fix |
| A3 | Deep withheld heavier branch starves downloads | 3 | 3 | 9 | 02 F-1, 31 |
| A4 | Invalid-body block of ~12k CLSAGs before rejection | 4 | 3 | 12 | 10 F10-2, 14 FE-1 |
| A5 | **Any panic/abort reachable from one PoW-valid block → every node exits and crash-loops on restart** | 2 | 5 | 10 | 35 F35-6 (Low, trigger unknown); **GAP in severity and mitigation → F48-5** |
| A6 | Validity split between build variants (FMA/AVX, aarch64 NEON verifier, soft AES) | 2 | 5 | 10 | 08 D-1/D-2, 27 F27-2 |
| A7 | Rule dropped silently in a refactor (Zebra #11383 class) | 3 | 5 | 15 | 01 F-02, 42, 11 F11-5; **amplified by the agent pipeline → F48-3** |
| A8 | Proof-cache key too narrow (CVE-2026-34377/40880 class) | 2 | 5 | 10 | 10 F10-6/F10-7; **new v3 items (validity window, ABI) → F48-6** |
| A9 | Seed-cache thrash, `/block` RPC bypass | 3 | 2 | 6 | 07, 36 |
| A10 | Timestamp/clock attacks | 2 | 2 | 4 | 03, 04 |
| **B. P2P** | | | | | |
| B1 | Addrman poisoning / eclipse (public) | 4 | 4 | 16 (pub) | 32 |
| B2 | **On-path MITM of the explicit `--peer` trial mesh: eclipse + stem-origin capture** | 3 | 4 | 12 | 30 T-7 (Low, "detect MITM"), 30 T-2; the trial premise "eclipse unreachable in an explicit mesh" (full review §1.4, SX2 §5) is unchallenged → **F48-1** |
| B3 | Chain-lock convoy stalls peers (pings unanswered) | 4 | 3 | 12 | 34 F34-1 |
| B4 | Low-work header floods on a fresh node | 4 | 2 | 8 | 31 F31-1 |
| B5 | Pre-Verack frames, outbox bytes, OOM | 4 | 3 | 12 | 30 T-1, R8-10 |
| B6 | Log-file disk fill (Bitcoin CVE-2025-54604/54605 class) | 3 | 2 | 6 | **GAP → F48-8** |
| **C. PX / ZK** | | | | | |
| C1 | One contract input approved by two functions | 3 | 3 (latent) | 9 | 20 F-20-1, decided |
| C2 | FS-binding omission (OtterSec "unfaithful claims", SP1 GHSA-c873) | 1 | 5 | 5 | 22, 24 (S5 above) |
| C3 | zkVM under-constraint (RISC Zero CVE-2025-52484 class) | 1 | 5 | 5 | 23, R4 |
| C4 | Proof padding / length fingerprint | 3 | 2 | 6 | 22 F22-1, 26 N1, decided |
| C5 | Poseidon2 cryptanalysis break | 1 | 5 | 5 | 19 F8 (hash agility) |
| C6 | Compiler in the trusted base (the ELF, not the source, is the rule) | 1 | 5 | 5 | 20 F-20-4; accepted (S6 mitigates tampering, not miscompilation) |
| **D. Wallet** | | | | | |
| D1 | Malicious remote node poisons decoys / backfill / distribution | 4 | 4 | 16 | 38 F38-1/2, 39 F39-10 |
| D2 | Seed not bound to network: cross-network key linkage | 3 | 3 | 9 | 37 F37-1 |
| D3 | Broken or cloned RNG | 2 | 4 | 8 | 18 |
| **E. RPC** | DNS rebinding, cross-site GET convoy, slowloris | 4 | 3 | 12 | 36 |
| **F. Supply chain and build** | | | | | |
| F1 | Typosquat/compromised crate executes at build time on the owner's workstation (54 build scripts, 16 proc macros in the lockfile) and steals push credentials or the future tag-signing key | 2 | 5 | 10 | 43 (key on FIDO2), 44 (not yet written); **the co-location threat → F48-4** |
| F2 | Compromised GitHub Action (tj-actions class) | 1 | 4 | 4 | S7 (SHA pins) |
| F3 | Malicious ELF swap with its id pin | 1 | 5 | 5 | S6 (byte-identity CI gate) |
| **G. Operations and people** | | | | | |
| G1 | **Prompt injection into the ~50-agent engineering swarm → subtle consensus/privacy change merged under the owner's identity; fabricated evidence** | 3 | 5 | **15** | review-status §3 names only "same-model blind spots"; **GAP → F48-3** |
| G2 | Single maintainer: account takeover, unsigned commits, no tags, no CODEOWNERS | 2 | 5 | 10 | R15-5, 43 (tags); **pipeline side → F48-3** |
| G3 | Social engineering of trial operators ("run this hotfix", "add `--skip-randomx-self-test`") | 3 | 3 | 9 | **GAP → F48-9** |
| **H. Trial-specific** | | | | | |
| H1 | **Supply audit concentrates every wallet file + password (all spend keys, all history) on one machine, twice** | 4 | 3 | **12** | **GAP → F48-2** |
| H2 | **Windows endpoint leakage: Recall snapshots of `seed` output, clipboard history, WER dumps** | 3 | 3 | 9 | 37 F37-6/F37-11 (memory, UX); **endpoint channel → F48-7** |
| H3 | Insider operator runs xmrig bridge and 51 %-attacks | 4 | 3 | 12 | R1-C2, accepted |
| H4 | Clock jump on the majority device | 3 | 3 | 9 | 04 F2 |
| **I. Privacy (network/metadata)** | PX size reveals origin; Dandelion++ small sets; ProxyMark over Tor | 5 | 3 | 15 | R8-18 (accepted), 33 |

### 3.3 Reading the ranking

- The highest-ranked leaves that **no dossier owns** are G1 (15), H1 (12), B2 (12, owned
  only as "Low" and only for detection), A5 (10, owned as "Low, trigger unknown") and F1
  (10, owned for the key only). §4 develops each.
- The highest-ranked leaves overall (A1 20, B1/D1 16) are owned and either accepted or
  scheduled. I have nothing to add to them beyond agreeing with the owners' plans.

---

## 4. New findings

| ID | Title | Severity | Status | Location | Confidence |
|---|---|---|---|---|---|
| **F48-1** | The explicit-peer trial mesh is not an eclipse or origin-privacy boundary against an on-path attacker; a closed-network PSK closes it cheaply | **Medium** (trial); High if devices run on untrusted networks | Not implemented | `p2p/src/transport.rs:1-16` (KDF inputs all public; "Peers are *not* authenticated"); full-review §1.4 and SX2 §5 ("not reachable in an explicit `--peer` mesh") | High (mechanism) |
| **F48-2** | The closed-set supply audit concentrates all trial spend keys, passwords and transaction history on one machine, including mid-trial | **Medium** (trial security and privacy) | Not implemented | `docs/testnet.md:306-323` (§7.1 steps 2–3); `tools/supply-audit/src/main.rs:31-38` (`--wallet`, `--password-file`); composes with 37 F37-1 | High |
| **F48-3** | The agent-based engineering pipeline is an unmodelled attack surface: indirect prompt injection, fabricated evidence and correlated edits, with no code-ownership, signing or consensus-path gate | **High** (process; impact is silent consensus/privacy regression) | Not implemented | no `.github/CODEOWNERS`; `git log %G?` 452 N / 7 E; no tags; no invisible-Unicode CI check; decisions.md delegates pushes | Medium on feasibility, high on the gap |
| **F48-4** | Build-time code execution and credential co-location: ~70 crates run code at build time on the machine that also holds push credentials, runs the agent swarm and will hold the tag key | **Medium** | Not implemented (key placement: 43 W-sign; vetting: 44) | `Cargo.lock` census (54 `build.rs`, 16 proc-macro crates); planned off-tree tools (05 C5/C6, 15 W10, 08 W2 `cross`) | High (census), medium (likelihood) |
| **F48-5** | Panic-to-global-halt amplifier: store-before-validate + fail-stop + full re-validation on restart turn any deterministic panic or abort from one PoW-valid block into a network-wide, restart-persistent halt | **Medium** (raises 35 F35-6 from Low) | Partially implemented (fail-stop exists; no quarantine) | `chain/src/manager.rs:664-703` (append at :672 before `drain_ready` :703); `tx/src/state.rs:193, 220` (`expect`); `manager.rs:917` (`assert!`); 11 F11-2 / 21 F21-1 (capacity); abort classes outside `catch_unwind` | High (mechanism); trigger [unknown] |
| **F48-6** | New v3 items make PX proof validity height- and registration-dependent; the PX5 skip needs tests for the CVE-2026-40880 class before the freeze | Low (no bug today; freeze-blocking evidence) | Complete but requires further testing | `chain/src/manager.rs:944-953`; `tx/src/validate.rs:894-905`; decisions (28: PX6 window, F-28-1 ABI) | High |
| **F48-7** | Windows trial endpoints leak seeds and wallet secrets through OS features (Recall snapshots, clipboard history/sync, WER dumps, redirected logs) | Low–Medium (trial) | Not implemented (docs and a small wallet guard) | `wallet/src/main.rs:756-759` (`seed` prints, F37-11); `docs/testnet.md` §12 (no endpoint steps) | Medium |
| **F48-8** | Unrate-limited per-event logging enables disk fill where stderr is redirected to files (Bitcoin CVE-2025-54604/54605 class) | Low | Not implemented | `p2p/src/net.rs:630, 1112-1116, 1203, 1812`; `chain/src/manager.rs:821` | Medium |
| **F48-9** | Diagnostic override flags and unsigned releases are social-engineering levers against trial operators | Low | Not implemented | flags decided in `decisions.md` (08: `--skip-randomx-self-test`; 04: `--allow-clock-skew`; `--repair-store`); `git tag` empty | Medium |

**Checked and not a finding** (so that others need not re-check): S3 (contract id commits
to programs); S4 (SP1-2.1 early-halt class); S9 (no output keys in stem keys); validation
and apply use the same `u128` pool arithmetic and the same nullifier-repeat rules
(`validate.rs:518-525` vs `px/src/state.rs:125-128`), so the Zebra CVE-2026-52738
"credit-first overflow on a valid block" pattern has no instance that I found.

### F48-1: the explicit-peer mesh does not stop an on-path attacker

**Problem and why it exists.**
- The handshake is ephemeral Ristretto ECDH; the key is
  `H64("p2p/session", network_id ‖ genesis_id ‖ A ‖ B ‖ S)` (`transport.rs:4-5`). Every input
  except the ECDH secret is public, so anyone who terminates both TCP legs derives both
  session keys. The code says so: "protects against passive observers, not against an
  active man in the middle" (`transport.rs:14-16`).
- The trial's defence against eclipse is the explicit `--peer` list over the internet
  (`docs/testnet.md:508-518`). The consolidated review therefore classes R8-3/R8-5 as
  "not reachable in an explicit `--peer` mesh". That holds for **off-path** attackers only.

**Concrete exploit (trial model).**
1. The attacker is on path for one device: hostile Wi-Fi, a compromised home router, the
   device's ISP, a VPS provider, or a BGP hijack of the /24 (the Monero CCS'26 and Heilman
   eclipse papers assume less).
2. It accepts the device's outbound TCP to each listed peer, runs the BlackSilk handshake
   itself toward both sides, and relays. Nothing in `Version` identifies the peer.
3. It now reads every `StemTx` the device originates in the clear, which is **deterministic
   origin attribution** (Dandelion++ gives no protection against the first hop), and it
   controls which blocks the device sees and when: eclipse, time dilation and a
   double-spend window against that operator, and a fake-chain feed to its wallet (compare
   38 F38-1/F38-2 and 39 F39-10, which need only a malicious node).
4. Per 30 T-2 it can also flip one bit to make both ends ban each other for 24 h.

**Consequences.** Privacy-critical (origin), liveness and double-spend against the
eclipsed device. Not consensus-critical.

**Prior art.** BIP 324 is deliberately unauthenticated and states that authentication is
a separate layer; Lightning's BOLT 8 uses Noise_XK with a known responder key; WireGuard
offers an optional 32-byte pre-shared key mixed into the handshake, and a peer without it
gets no response at all; Tor bridges (obfs4) use a per-bridge secret. [ext]

**Recommendation (policy, not consensus).**
- **Closed-network PSK for the trial:** `--network-psk-file <path>` (32 random bytes shared by
  the 7 operators out of band). Mix it into the KDF as an extra input
  (`H64("p2p/session", nid ‖ genesis ‖ psk ‖ A ‖ B ‖ S)`). A peer without the PSK fails the
  first frame; per 30 T-2 that must disconnect **without a ban**.
- Side benefit: the P2P port becomes useless to everyone outside the trial, which removes
  most of branch B from the trial's attack surface.
- Longer term: pinned responder keys with transport v2 (30 W6), for public manual links.

**Trade-offs.** One leaked PSK re-opens the hole (insider or a lost laptop); it gives no
identity among members, so an insider who is also on path can still MITM (low relevance
with 7 trusted operators). It adds a distinguishable config knob, but the knob is not
visible on the wire. It must never be required on a public network.

**Tests (AT-1).** `p2p/tests/mitm.rs`: an in-process relay that terminates both handshakes.
Without a PSK it reads a `StemTx` in the clear (this is the demonstration of failure). With
a PSK on both honest ends the relay's frames fail and **no ban** is recorded. A peer with
the PSK and a peer without it never exchange a decoded message.

**Invariants.** No plaintext magic; `network_id` and genesis in the KDF; decryption failure
never scored (30 T-2).

### F48-2: supply-audit custody

**Problem.** The procedure (`docs/testnet.md:314-323`) collects **every wallet file and its
password on one machine**, "at the end, and once in the middle". Wallet files hold the
full seed (spend keys). This is the only end-to-end inflation check the project has
(R15-7), so it cannot simply be dropped.

**Exploit paths.**
1. **Cross-network key exposure.** 37 F37-1: seeds carry no network binding, so a seed
   reused on another network has identical keys. An operator who reuses a mnemonic or a
   password hands the auditor (or whoever compromises the audit machine) those funds too.
2. **Privacy of the trial itself.** After the mid-trial audit the auditor can scan and link
   every later transaction of every participant (v1 key images and PX records). Any
   privacy measurement in the second half of the trial is void against the auditor, and
   the report must say so.
3. **Theft and disruption.** Whoever controls the audit machine can spend any trial output
   (double-spend races against the owners, deliberately failing the audit), or silently
   keep copies.
4. **Transport of the files.** Operators will send wallet files and passwords over chat or
   e-mail unless told otherwise.

**Prior art.** Monero's view-only wallet plus `export_key_images`/`import_key_images`
separates the audit (balances and spent status) from spend authority [ext]. BlackSilk has
no v1 view-only wallet (R11-W15; 37 F37-12 notes that a v1 view key cannot see spends
without key images).

**Recommendation.**
- **P0 (docs + tool banner, trial):** trial-only seeds generated fresh on the trial build and
  never reused; unique passwords; files handed over on removable media or an encrypted
  channel; the audit machine offline except for its own node; all copies wiped afterwards;
  the report states that privacy results after the mid-trial audit exclude the auditor.
  Consider dropping the central mid-trial run in favour of a **per-operator local run** that
  publishes only its per-wallet totals and a hash of the JSON report, with the central run
  only at the end.
- **P2 (design):** a key-image export file plus a view-only audit mode, so the auditor never
  receives spend keys. This aligns with 37's key hierarchy (K1) and R11-W15.

**Tests (AT-2).** A supply-audit test that the tool warns when a wallet's network or
genesis differs from the node (already enforced for genesis per 40) and prints the custody
banner; later, a view-only audit that produces the same totals as the full-wallet audit on
the regtest supply test.

### F48-3: the engineering pipeline as an attack surface

**Problem and why it exists.**
- Phase 2 is carried out by about 50 AI agents that fetch web pages, read third-party
  crate sources and GitHub issues, and then edit consensus code in parallel; routine
  commits and pushes are delegated. The only recorded pipeline risk is "same-model review,
  correlated blind spots" (review-status §3; full review §2.3).
- **Indirect prompt injection** is a demonstrated class: instructions planted in content
  an agent reads (web pages, source comments, issues), sometimes in invisible Unicode, can
  steer its actions (Greshake et al. 2023). CVE-2025-53773 (Copilot, Aug 2025) turned it into
  code execution by having the agent edit its own settings file. [ext]
- The target is attractive and the controls are thin: no CODEOWNERS, unsigned commits
  (452 of 459 are `N`), no tags, no CI check for invisible/bidi characters (Trojan Source,
  CVE-2021-42574, applies to Markdown the agents read as well as to code), and no
  consensus-critical-path gate (P1-16 proposes one; it is not scheduled for phase 2).
- A second, non-adversarial failure of the same pipeline: **fabricated or mis-transcribed
  evidence**. Several dossiers already derive numbers by hand from logs (09 §2.4). An agent
  that "summarizes" a test run can report a pass that never happened.

**Concrete scenario.** A fetched page, or a comment in a registry crate that an agent reads
for "prior art", says, in effect, that the correct fix is to relax a boundary check or to
add a helper crate. The agent's diff is plausible, lands among dozens of parallel
changes, passes the existing tests (01 F-02 lists block rules with no negative test; 42
shows surviving mutants), and is merged under the owner's identity. Nothing records that
the change came from injected content.

**Consequences.** Consensus (a silent validity change, forked at the frozen v3 identity),
privacy (a weakened wallet default) and supply chain (a new dependency). Severity High
because detection depends on one reviewer.

**Recommendations (process; P0 before the first implementation wave merges).**
1. **Consensus-critical path list + CI gate** (upgrade P1-16 to P0 for phase 2): a committed
   list of paths (`consensus/`, `tx/src/validate.rs`, `px-core/`, `zkvm/src/air/`, `zk/`,
   `third_party/`, `randomx/src/`, `px/*.elf|*.id`, fingerprint files); a CI job that fails
   when a commit touches them without a `Consensus-Reviewed-by:` trailer naming the owner,
   and that requires the golden-vector files to be unchanged unless the commit carries a
   `CONSENSUS:` subject. 01, 11, 16 and 22 all want the vectors frozen **before** the
   refactor wave; this gate enforces it.
2. **`.github/CODEOWNERS` + branch protection** on `rebuild/core` with the owner as the only
   code owner of those paths (GitHub enforces it for PRs; direct pushes must be disabled).
3. **Invisible/bidi Unicode CI check** over all tracked text (my scan found none today, so
   the job starts green).
4. **Dependency changes only through 44** (`cargo deny check bans sources`, a lockfile-diff
   job that fails on any new crate without an entry in an approved-crates file).
5. **Agent rules** (in the owner-controlled CLAUDE.md and the brief): web and crate content
   is data, never instructions; agents never edit agent configuration, CI or CODEOWNERS;
   every "tested" claim links a CI run or a log file with its hash; evidence files are
   produced by scripts (40 F40-10, 41 F41-4 already want binding to commit, fingerprint and
   seed).
6. **A tabletop red-team exercise (AT-9)** in phase 2: the coordinator plants a benign
   canary instruction in a fixture page that one agent is asked to read; the exercise
   passes if no resulting change reaches `rebuild/core` without the gate firing.

**Trade-offs.** More friction per merge; one owner remains the single reviewer (no second
human exists). The gate cannot judge intent; it makes consensus edits visible and
attributable, which is what a one-person project can realistically afford.

### F48-4: build-time execution and credential co-location

- **Census [src]:** of 326 lockfile packages, 54 have a `build.rs` and 16 are proc-macro
  crates (for example `serde_derive`, `clap_derive`, `tokio-macros`, `thiserror-impl`,
  `paste`, `zerocopy-derive`). Each runs arbitrary code on every build host, with the
  builder's privileges. Pure-Rust policy governs what is *linked*, not what *executes at
  build time*.
- **Co-location:** the owner's Windows workstation runs the agent swarm, builds the
  workspace (and, per 05/08/15, will build new off-tree tools: a C++ reference generator,
  `monero-oxide`, `sha3`, `cross`), holds the git push credentials and is the natural place
  for the future tag-signing key.
- **Precedent [ext]:** the crates `faster_log`/`async_println` (crates.io, removed Sept 2025)
  scanned the builder's files for private keys and exfiltrated them; the xz backdoor
  (CVE-2024-3094) was a multi-year maintainer-takeover operation; tj-actions/changed-files
  (CVE-2025-30066) was a compromised CI dependency.
- **Recommendations:** the tag key on a FIDO2 token with touch (agree with 43); signing on a
  machine or VM that never builds dependencies; new tool builds in a container without
  credentials; `cargo vet` (with imported audits) or at least a reviewed-crates list for
  any lockfile change (44). No consensus impact.

### F48-5: panic-to-global-halt amplifier

**Mechanism [src].**
1. `submit_inner` appends a block to `blocks.dat` **before** validating it
   (`manager.rs:672` append, `:703` `drain_ready`).
2. Validation and state application run under the chain lock. A panic poisons it, and the
   node deliberately exits (fail-stop, `35b7cb9`, R10-2).
3. On restart, replay re-validates every stored body (35 F35-3), hits the same panic and
   exits again: a crash loop with no quarantine and no invalidate tool (35 F35-6).
4. Only the Plonky3 verifier runs inside `catch_unwind` (`zk/src/lib.rs:158, 278`). Aborts
   bypass it anyway: allocation failure and stack overflow abort the process in Rust.

**Trigger classes (none known today).** A validate/apply mismatch (`tx/src/state.rs:193,
220` `expect`, `manager.rs:917` `assert!`); the tree-capacity panic (11 F11-2, 21 F21-1); a
verify-path assert outside `catch_unwind` (23 F23-9); an allocation driven by
attacker-controlled lengths; a deep recursion on a small thread stack (Windows main thread
1 MiB). The decode layer is fuzzed; the **block-level validate→apply pair is not** (41 lists
stateful targets as open).

**Why Medium.** Zebra CVE-2026-52738 (published 2026-05-29) is exactly this: a
consensus-valid block made the state writer panic, and "upon restart, nodes would
re-encounter the consensus-valid block and crash again, creating a persistent chain halt
that can only be resolved by a software patch" [ext]. Bitcoin CVE-2018-17144 is the
assertion variant. Here one PoW-valid block (cheap at testnet difficulty) reaches every
node that stores it.

**Recommendations.**
- (a) **Quarantine journal (35 owns the store):** write a tiny "validating `<id>`" marker
  before body validation and clear it after. On start, if the marker names a block, do not
  re-validate it automatically: start in a "halted: suspect block `<id>`" state with an
  ERROR, a `/info` field, and an operator command `--invalidate-block <id>` (the R1-C12
  `reconsider` pair). This turns a crash loop into a diagnosable halt without making
  validity depend on local history.
- (b) **Make apply infallible by construction** where validation already decided (R16-6
  effects model, 46), and move the capacity rule into validation (11, decided).
- (c) Keep fail-stop; do **not** convert panics into "invalid" (that would make a
  platform-specific panic a node-local consensus verdict, R1-C12).

**Tests (AT-3, AT-4).**
- AT-3: a `#[cfg(feature = "fault-injection")]` hook panics while validating a chosen id.
  Assert: the node exits; restart does not loop; `--invalidate-block` recovers; the
  replayed state equals a fresh node's.
- AT-4: a property test: for every block that `validate_block_transactions_cached` accepts,
  `apply_block` returns without panicking (random PX pool edges, deploys, duplicate-key
  cases after D8-B, a feature-reduced tree depth to reach capacity).

### F48-6: the PX5 skip after the v3 items

- **Today:** sound for the reasons in S3 and 02 §2.2 (keyed by full tx id and rule domain;
  registrations immutable and content-addressed).
- **Change coming:** 28's validity window (PX6) makes validity height-dependent; F-28-1's
  ABI word and verifier dispatch make it registration- and verifier-dependent. Zebra's
  CVE-2026-40880 was precisely "valid for one height, invalid for another" behind a
  verification cache [ext].
- **Tests (AT-5), P0 with those items:** (a) the F10-6 tamper test (same id, different
  proof bytes, including a prefix-only id regression); (b) a pooled PX transaction whose
  window has closed at the mined height is rejected even though it is pooled; (c) a reorg
  that removes and re-mines a deploy keeps verdicts identical to a cold node; (d) the same
  across an activation (02 W-6). The window check must stay outside the skipped code path.

### F48-7: Windows endpoint leakage (trial)

- `seed` prints the mnemonic with no confirmation (37 F37-11). On Copilot+ PCs, **Windows
  Recall** snapshots the screen; Microsoft's own documentation says its sensitive-content
  filter is best effort, and independent tests report misses [ext]. Clipboard history
  (Win+V) and cloud clipboard sync copy anything the operator copies. Windows Error
  Reporting can collect memory dumps of a crashed wallet (37 F37-6 describes what memory
  holds). Redirected logs keep peer IPs (R10-10).
- **Recommendations:** the trial checklist (P0 docs, owner 40/47): Recall off, clipboard
  history and sync off, full-disk encryption on, WER dumps disabled for the wallet binary,
  logs not redirected to synced folders. Wallet: `seed` requires an explicit confirmation
  and warns about screen capture (37 K1 already plans a confirmation).

### F48-8: log-fill

- Per-connection INFO lines (`net.rs:1112-1116, 1203`), per-misbehaviour lines (`:630`),
  per-invalid-parent lines (`:1812`), per-invalid-body WARN (`manager.rs:821`), with no rate
  limit. Stderr is harmless on a console; under a service wrapper or Docker without
  rotation, connection churn from rotating IPs, or PoW-valid invalid blocks, grows files
  without bound. Bitcoin Core fixed the same class in 30.0 (CVE-2025-54604 and
  CVE-2025-54605) [ext].
- **Fix:** a per-category token bucket for log lines (with a "N suppressed" line), and log
  rotation in `deploy/` configs. **Test (AT-10):** 10,000 connection cycles produce at most
  a bounded number of log bytes.

### F48-9: override flags and unsigned releases as social-engineering levers

- The decided diagnostics (`--skip-randomx-self-test`, `--allow-clock-skew`,
  `--repair-store`, `--verify-store-pow` off) are exactly what an attacker in a trial chat
  would ask an operator to add, together with "download this hotfix". There are no tags and
  no signed commits yet.
- **Fix:** every active override logs at WARN every 10 minutes and appears in `/info` and in
  the fingerprint output as `overrides: [...]`, so the identity check of testnet.md §2.1
  fails visibly; the incident-response plan states that no binary or flag is ever accepted
  from chat without the signed tag and the published fingerprint.

---

## 5. Answers to the brief's questions for the top problems

| | F48-1 | F48-2 | F48-3 | F48-5 |
|---|---|---|---|---|
| Consensus-critical? | No | No | Indirectly (it is how a consensus bug gets in) | No (a liveness failure of every node) |
| Privacy-critical? | Yes (stem origin) | Yes (all trial history) | Possibly | No |
| Literature / practice | BIP 324, BOLT 8, WireGuard PSK, obfs4 | Monero view-only + key-image export | Greshake 2023; CVE-2025-53773; Trojan Source; OWASP LLM01 | Zebra CVE-2026-52738; Bitcoin CVE-2018-17144 |
| What could go wrong with the fix | PSK leak; must not become a public-network requirement | local runs trust operators | friction; one reviewer | a quarantine that auto-invalidates would create node-local verdicts, so it must halt, never invalidate |
| Invariant never to change | no plaintext magic; decryption failures unscored | wallets never send spend keys to a node | owner gate on consensus changes (never-change 31) | fail-stop on poisoned state; validity depends only on ancestors |

---

## 6. Mapping of 2024–2026 incidents to BlackSilk

| Incident (primary source in §8) | Pattern | BlackSilk status |
|---|---|---|
| Zebra CVE-2026-34377 (Mar 2026) | verification cache keyed by an id that excludes authorization data | Not present: tx id covers every byte (R1 V9). Tamper test missing (10 F10-6) → AT-5 |
| Zebra CVE-2026-40880 | cached verdict valid at one height, invalid at another | Not present today; becomes relevant with PX6 and ABI dispatch → F48-6 |
| Zebra CVE-2026-52738 (May 2026) | panic on a consensus-valid block; crash loop after restart | Same amplifier exists (store-before-validate + fail-stop) → F48-5 |
| Zebra CVE-2026-41583, #11383 | rule lost or changed in a refactor | 01 F-02, 42; amplified by parallel agents → F48-3 |
| Bitcoin Core CVE-2025-54604/54605 (Oct 2025) | disk fill via logs (spoofed self-connections, invalid blocks) | Per-event unrate-limited logging → F48-8 |
| Bitcoin Core CVE-2025-46598 | seconds of CPU per crafted unconfirmed tx | 10 F10-2, 12 M12-1, 34 F34-5 (owned) |
| Bitcoin Core CVE-2025-46597 | 32-bit-only crash on a pathological block | Not applicable: non-64-bit builds refused (`8097f66`) |
| Monero Feb 2025 RPC memory-exhaustion 0-day | exposed RPC OOM | RPC loopback default; 36 W2 resource controls (owned) |
| Monero Qubic 2025 (selfish mining, 18-block reorg) | rented/redirected majority | R1-C2 accepted; 02 W-7 park policy |
| Monero eclipse (NDSS 2025, CCS'26) and ProxyMark (arXiv 2607.07062, Jul 2026) | peer-list poisoning; Tor proxy-node capture | 32, 33 (owned) |
| Monero 10-block decoy bug (#8872) | off-by-one decoy eligibility | Absent; regression test owned by 38 (F38-10) |
| SP1 (Jan 2025): early halt + unchecked `next_pc` | public values unconstrained after an early halt | Not present (S4) |
| SP1/Plonky3 GHSA-c873-wfhp-wx5m | evaluation claims not observed before batching challenge | Owned by 24; 0.7 status must be confirmed there |
| OtterSec "unfaithful claims" (Sep–Dec 2025, six zkVMs) | public claims not bound in Fiat–Shamir | S5; per-field transcript mutation tests are 22/24's |
| RISC Zero CVE-2025-52484 | missing constraint in an rv32im circuit | 23 F23-5 (owned) |
| crates.io `faster_log`/`async_println` (2025), xz (CVE-2024-3094), tj-actions (CVE-2025-30066) | build-time and maintainer supply-chain compromise | F48-4, F48-3 |
| Copilot CVE-2025-53773 (Aug 2025) | prompt injection → agent edits its own config → code execution | F48-3 |

---

## 7. Adversarial test proposals

| ID | Test | Proves | Owner file (proposed) | Pri |
|---|---|---|---|---|
| AT-1 | In-process MITM relay; without PSK it reads `StemTx`; with PSK it fails and no ban is recorded | F48-1 attack and fix | `p2p/tests/mitm.rs` (30) | P1 |
| AT-2 | Supply-audit custody banner and network/genesis checks; later a view-only audit equal to the full audit | F48-2 | `tools/supply-audit/tests/` (40) | P1 / P2 |
| AT-3 | Fault injection: panic during validation of a chosen block; restart halts with "suspect block", no loop; `--invalidate-block` recovers | F48-5 | `chain/tests/fault_injection.rs` (35) | P1 |
| AT-4 | Property: every block accepted by validation applies without panic (pool edges, deploys, duplicate `O` after D8-B, reduced-depth capacity edge) | F48-5 | `chain/tests/validate_apply_props.rs` (10/11, harness 41) | P1 |
| AT-5 | PX5-cache suite: same-id tamper; window closed at mined height; deploy reorg; activation | F48-6 | `chain/tests/px_cache_adversarial.rs` (10, 02) | P0 with PX6/ABI |
| AT-6 | After D8-B: reorg across blocks sharing an `O`; state and index equal a fresh replay; no layer treats `O` as a conflict | D8 integration | `chain/tests/duplicate_output_keys.rs` (13) | P0 with D8 |
| AT-7 | Verify the widest adversarial proof and load the largest deploy ELF on a 1 MiB-stack thread and on a tokio blocking thread | abort class of F48-5 | `zk/tests/stack.rs`, `tx/tests` (22, 11) | P1 |
| AT-8 | CI: invisible/bidi Unicode scan; consensus-path trailer gate with a fixture commit that must fail | F48-3 | `.github/workflows/ci.yml` (43) | P0 |
| AT-9 | Tabletop: canary injected instruction in a fixture page read by one agent; gate must fire | F48-3 | process (coordinator) | P1 |
| AT-10 | 10,000 connection cycles → bounded log bytes | F48-8 | `p2p/tests/network.rs` (31) | P2 |
| AT-11 | `/info` and `--version` show active overrides; the identity check fails when one is set | F48-9 | `node/tests/info_identity.rs` (36/40) | P2 |

---

## 8. Implementation plan for phase 2

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|
| W1 | Consensus-path gate, CODEOWNERS, branch protection, Unicode scan, lockfile-diff gate, agent rules | `.github/CODEOWNERS` (owner), `.github/workflows/ci.yml` (43), `consensus-paths.txt` (46/43), `CLAUDE.md` + brief (owner only) | none | none | AT-8, AT-9 | CONTRIBUTING consensus pipeline (47) | S–M | **P0** |
| W2 | Supply-audit custody procedure and tool banner | `docs/testnet.md` §7.1 (40, with 47), `tools/supply-audit/src/main.rs` (40) | none | none | AT-2 | §7.1, incident plan | S | **P0** (docs) / P2 (view-only audit, with 37) |
| W3 | Trial PSK in the transport KDF, no-ban on failure | `p2p/src/transport.rs`, `p2p/src/net.rs` handshake (30), `node/src/config.rs` (36/40) | policy (P2P protocol, closed networks only) | none | AT-1 | `docs/p2p.md` §3, testnet.md §12 | S | **P1** (P0 if any trial device is on an untrusted network) |
| W4 | Build/sign separation: key on FIDO2, signing host without builds, containerized tool builds, cargo-vet or reviewed-crates list | release procedure (43), `supply-chain/` (44) | none | none | CI job (44) | release doc | S | **P0** before the rc tag |
| W5 | Quarantine journal + `--invalidate-block`; apply-infallible direction | `chain/src/store.rs`, `chain/src/manager.rs` replay (35), `node/src/main.rs` (flag) | none (policy) | none | AT-3, AT-4, AT-7 | blocks.md §8, incident plan | M | **P1** |
| W6 | PX5-cache and D8 adversarial suites | tests only (10, 02, 13) | none | none | AT-5, AT-6 | — | S | **P0** with the v3 items |
| W7 | Windows trial endpoint checklist; `seed` confirmation | `docs/testnet.md` §12 (40/47); `wallet/src/main.rs` (37) | none | none | wallet CLI test | §12 | S | **P0** (docs) |
| W8 | Rate-limited logging and log rotation | `p2p/src/net.rs` (31/30 slices), `chain/src/manager.rs` log sites (02), `deploy/` (43) | none | none | AT-10 | operator docs | S | P2 |
| W9 | Visible overrides in `/info`, `--version`, fingerprint output; incident-plan rule | `node/src/lib.rs`, `node/src/fingerprint.rs` (40), `docs/testnet-incident-response.md` (47) | none | none | AT-11 | incident plan | S | P2 |

No item changes consensus or the testnet identity. Benchmarks: none.

---

## 9. Dependencies and conflicts

- **30 p2p-transport:** W3 lives in their KDF; it must compose with transport v2 (W6) and
  with T-2 (no ban on decryption failure).
- **35 storage-recovery:** W5 is their store and replay path; F48-5 raises their F35-6.
- **37 wallet-keys / 40 testnet-genesis:** W2 (custody; seed network binding K1) and W7.
- **43 ci-reproducibility / 44 supply-chain / 46 architecture:** W1 and W4 (key placement,
  vetting, the consensus-path list).
- **10, 02, 13, 28:** W6 test ownership; the PX6 window and ABI dispatch must keep the
  window check outside the PX5 skip.
- **41 fuzzing:** AT-4 uses their shared test-support crate (F41-7).
- **50 red-team:** should run AT-5, AT-6 and AT-9 against the merged v3 diff.

## 10. Open questions for the coordinator

1. Accept a closed-network PSK for the trial (W3), and is it P0 (devices on untrusted
   networks) or P1?
2. Keep the central **mid-trial** supply audit, or replace it with per-operator local runs
   and a central run only at the end (F48-2)?
3. May W1 (consensus-path gate, CODEOWNERS, branch protection) be enabled **before** the
   first phase-2 implementation wave merges? It slows merges; it is the only structural
   control against F48-3.
4. Where will the tag-signing key live, and can signing happen on a machine that never
   builds third-party crates (F48-4, with 43)?
5. Is the quarantine behaviour of F48-5 ("halt with a suspect block, never auto-invalidate")
   acceptable as node policy?

## 11. Sources

**Blockchain incidents and advisories**
- Zebra CVE-2026-34377, GHSA-3vmh-33xr-9cqh: https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-3vmh-33xr-9cqh
- Zebra CVE-2026-52738, GHSA-w834-cf6p-9m9w: https://github.com/advisories/GHSA-w834-cf6p-9m9w
- Zebra CVE-2026-40880: https://app.opencve.io/cve/CVE-2026-40880
- Zebra CVE-2026-41583 (pointer): https://www.endorlabs.com/vulnerability/cve-2026-41583 ; issue #11383: https://github.com/ZcashFoundation/zebra/issues/11383
- Bitcoin Core security advisories (CVE-2025-54604, -54605, -46597, -46598; fixed in 30.0): https://bitcoincore.org/en/security-advisories/ ; disclosure mail: https://groups.google.com/g/bitcoindev/c/sBpCgS_yGws ; CVE-2025-54605: https://github.com/advisories/GHSA-v4c2-68g7-mpcf
- Bitcoin Core CVE-2018-17144 full disclosure: https://bitcoincore.org/en/2018/09/20/notice/
- Monero Feb 2025 RPC DoS disclosure (pointer): https://seclists.org/fulldisclosure/2025/Feb/13
- Monero 10-block decoy bug post-mortem #8872: https://github.com/monero-project/monero/issues/8872
- Monero untrusted remote node tracing warning #3404: https://github.com/monero-project/monero/issues/3404
- Monero eclipse attacks (NDSS 2025): https://www.ndss-symposium.org/wp-content/uploads/2025-95-paper.pdf
- Shi et al., "Deanonymizing Monero Transactions in Tor Network" (ProxyMark), arXiv 2607.07062: https://arxiv.org/abs/2607.07062
- "Monero Traceability Heuristics: Wallet Application Bugs…", IEEE ICBC 2024, arXiv 2408.05332: https://arxiv.org/abs/2408.05332
- Halborn, Monero 51 % attack Aug 2025 (pointer): https://www.halborn.com/blog/post/explained-the-monero-51-percent-attack-august-2025

**zkVM / proof-system exploits**
- LambdaClass/3MI/Aligned, SP1 exploit disclosure (Jan 2025): https://blog.lambdaclass.com/responsible-disclosure-of-an-exploit-in-succincts-sp1-zkvm-found-in-partnership-with-3mi-labs-and-aligned-which-arises-from-the-interaction-of-two-distinct-security-vulnerabilities/
- SP1 advisory GHSA-c873-wfhp-wx5m (missing verifier checks and FS observations): https://github.com/succinctlabs/sp1/security/advisories/GHSA-c873-wfhp-wx5m
- OtterSec, "Unfaithful claims: breaking 6 zkVMs": https://osec.io/blog/zkvms-unfaithful-claims/
- Plonky3 issues #2242 (differential verification, backend gates) and #2271: https://github.com/Plonky3/Plonky3/issues/2242 , https://github.com/Plonky3/Plonky3/issues/2271

**Transport authentication**
- BIP 324: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
- BOLT 8 (Noise_XK): https://github.com/lightning/bolts/blob/master/08-transport.md
- WireGuard protocol (pre-shared key): https://www.wireguard.com/protocol/

**Supply chain and agent pipeline**
- Rust blog, malicious crates `faster_log` and `async_println` (2025-09-24): https://blog.rust-lang.org/2025/09/24/crates.io-malicious-crates-fasterlog-and-asyncprintln ; Socket analysis: https://socket.dev/blog/two-malicious-rust-crates-impersonate-popular-logger-to-steal-wallet-keys
- xz backdoor CVE-2024-3094: https://nvd.nist.gov/vuln/detail/CVE-2024-3094
- tj-actions/changed-files CVE-2025-30066: https://nvd.nist.gov/vuln/detail/CVE-2025-30066
- CVE-2025-53773 (Copilot prompt injection → RCE): https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53773 ; write-up: https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/
- Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", arXiv 2302.12173: https://arxiv.org/abs/2302.12173
- OWASP Top 10 for LLM Applications 2025, LLM01 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- Trojan Source, CVE-2021-42574: https://trojansource.codes/

**Endpoint**
- Microsoft, filtering sensitive information in Recall: https://support.microsoft.com/en-us/windows/filtering-apps-websites-and-sensitive-information-in-recall-a4c28bee-e200-4a4a-b60d-c0522b404a5b ; managing Recall: https://learn.microsoft.com/en-us/windows/client-management/manage-recall

**Internal:** the dossiers in `C:/bszkeval/p2/research/` cited by number;
`docs/reviews/full-review-2026-09-27.md`; `docs/testnet.md`; `decisions.md`.
