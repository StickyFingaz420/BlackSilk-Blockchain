# R14: documentation architecture, developer experience and operator experience

Reviewer: R14 (internal review, not an audit). Date: 2026-09-27.
Repository state read: branch `rebuild/core`, HEAD `9578517` (three commits past the
brief's `f677e55`). This review was read-only: no builds, no changes to the repository.

**Scope.** The documentation set treated as one system: its structure, what is normative,
how people find their way through it, and whether a developer or an operator can work from
it. I do not list individual stale sentences; A16b is fixing those. I cite a few only as
symptoms of a structural cause.

**Evidence tags:**
- **[SR]** source-read (file:line given);
- **[T:name]** tested, with the test named;
- **[A]** assumed;
- **[U]** unknown;
- **[EXT]** an external reference, cited from my own knowledge of it. I did not fetch it
  in this session.

---

## 0. Executive summary

The documentation is unusually honest and detailed for a project at this stage:
- it separates claims from evidence;
- it states its limitations plainly;
- the crate-level rustdoc maps modules to spec sections.

The **v1 layer is specified well enough for a second implementation**, with one gap:
frozen test vectors are missing. That layer covers the header chain, v1 transactions,
emission and the P2P framing.

The **PX/ZK layer is not.** Its consensus rules are defined by the code:
- Plonky3 0.7.0 with three local patches;
- the `postcard` serialization of third-party structs;
- a pinned RISC-V ELF.

zk.md says this outright (zk.md:528, "The parameter set is code"). The unbound
FRI-witness malleability (A14 M1) is exactly the kind of bug that a normative wire-format
spec would have exposed.

Structurally, three things hurt most:
1. **Nothing is the single source of truth for status.** At least eight documents carry
   their own dated status line and "authoritative" claim. The latest readiness report is
   an orphan that no other document links to.
2. **No governance record exists:**
   - there is no decision log, even though 24 owner decisions are scattered across 13
     files;
   - no written consensus-change process is in the repository;
   - no changelog, no tags, no versioning (every crate is `0.1.0`, and `--version` cannot
     tell builds apart);
   - no licence at the repository root.
3. **Operators cannot verify what they run.** The identity check covers the genesis id
   only; it does not cover the consensus rule set. There is no build fingerprint, no
   upgrade guide and no backup guide. The issue template asks for logs without any
   redaction guidance, on a privacy chain.

**Recommended target:**
- a **BlackSilk Improvement Proposal (BIP-style, "BSIP") process**;
- a normative `spec/` tree with RFC 2119 language and **machine-readable test vectors**;
- a single `STATUS.md` generated from a findings register;
- an operator handbook;
- a developer guide.

The P0 items before the testnet are cheap:
- a consensus fingerprint in `/info` and in the logs;
- build identification;
- one status source;
- a licence;
- template and redaction fixes;
- a frozen-vector minimum.

---

## 1. Findings

IDs are R14-D*n*. Severity is judged for a *controlled experimental testnet*. Several items
would be higher before mainnet.

### D-1: The PX/ZK consensus layer has no implementation-independent normative spec
- **Classification:** Partially implemented.
- **Severity:** high (mainnet: critical).
- **Confidence:** high.
- **Where [SR]:**
  - zk.md:528, "The parameter set is code (`zk/src/params.rs`)";
  - zk/src/lib.rs:170-181, the proof wire format is `PROOF_VERSION ‖ postcard(proof)`,
    where `Proof` is Plonky3's own serde struct;
  - px.md:470-478, the PX tx format is a one-line text sketch without field widths,
    count encodings or ordering rules for `functions[]`;
  - px.md has no "normative" marker at all (`grep -c normative docs/px.md` = 0);
  - zkvm.md:9-13 declares itself normative, but the AIR constraints themselves live only in
    `zkvm/src/air/`.
- **Scenario:**
  - A second implementation, or a future Rust rewrite after a Plonky3 upgrade, cannot know
    the exact transcript order, the proof byte layout, the FRI folding schedule (A14 M3) or
    which witness values are fixed (A14 M1).
  - The canonical encoding depends on postcard and serde behaviour. postcard is
    caret-pinned (A14), so a lockfile refresh could change consensus bytes. Nothing would
    detect it except the round-trip check, and only if encode and decode both changed
    consistently.
  - Nothing states the bytes. That is also why the unbound commit-phase PoW witness at
    `COMMIT_POW_BITS = 0` went unnoticed: a spec line of the form "`pow_witness` MUST equal
    0" would have forced the question.
- **Assessment:**
  - For STARK systems, normative-by-reference is common and acceptable. Zcash's Halo2
    circuits are specified in part by the code.
  - It must then be **explicit and pinned**:
    - the spec names the exact crate versions and patch hashes;
    - it gives the byte layout of the proof as a grammar;
    - it states every "MUST equal" constraint;
    - it ships golden proofs (valid and invalid) as vectors.

### D-2: Frozen known-answer vectors are largely missing, and none exist outside Rust tests
- **Classification:** Partially implemented.
- **Severity:** medium (mainnet: high).
- **Confidence:** high.
- **Where [SR]:**
  - transactions.md:987 requires "Fixed known-answer vectors for `Hs`, `Hp` and the
    generators".
  - crypto/src/generators.rs:56 only checks that the generators are distinct.
  - crypto/src/hash.rs:283 `kat_matches_definition` recomputes Blake2b from the definition
    inside the test. It is self-referential: it would pass even if a domain tag string or
    the tag-length encoding changed on both sides. It is not a frozen vector.
  - Real pins exist:
    - RandomX (randomx/src/lib.rs:79-186);
    - a CLSAG nonce/transcript vector (crypto/src/clsag.rs:979-1001);
    - the genesis ids ([T:consensus::params::genesis_ids_are_pinned]);
    - Poseidon2 ([T:zk/tests/pins.rs poseidon2_is_the_pinned_permutation]);
    - the kernel and vault program ids ([T:px/tests/proof.rs the_kernel_program_id_is_pinned]).
  - No vectors exist for:
    - tx serialization and hash;
    - `sig_message`;
    - address encoding;
    - the emission schedule beyond the first rewards;
    - LWMA sequences;
    - the MTP/FTL edge cases;
    - the Merkle `tx_root`;
    - the P2P handshake transcript;
    - `Hk` domains, nullifier and commitment derivations;
    - the PX binding `h_tx`.
  - No `vectors/` directory or JSON vectors exist anywhere.
- **Scenario:** a harmless-looking refactor of a domain-tag constant, or of the varint
  helper, changes the tx hash for all nodes built from it. The existing tests still pass,
  because they build and verify with the same code. The first detection is a chain split on
  the testnet. The same applies to wallets written by third parties.
- **Relation to known items:** this deepens "No external test vectors for Ristretto-based
  CLSAG/BP+" and "no known-answer vectors for schnorr/membership/claims". The gap is
  project-wide, not per primitive.

### D-3: There is no single source of truth for status; the reports compete and some are orphans
- **Classification:** Partially implemented.
- **Severity:** medium.
- **Confidence:** high.
- **Where [SR]:** status lines are dated and maintained independently in:
  - README.md:5-10;
  - AUDIT.md:3 ("Status (2026-09-25)… Consensus integration remains", which contradicts
    px.md:3 and zk.md);
  - testnet-launch-checklist.md:3;
  - testnet-roadmap.md:3;
  - testnet-reset-plan.md:1-3;
  - testnet-v2-validation.md;
  - review-status.md:3 ("authoritative… where another document suggests otherwise, this
    one is correct");
  - reviews/completion-readiness-2026-09-26.md.
- **Orphans and missing links [SR]:**
  - `completion-readiness-2026-09-26.md` and `contracts-completion-assessment.md` are
    referenced by **no** other markdown file.
  - The README links neither px.md, zkvm.md, SECURITY.md, the launch checklist, nor the
    roadmap.
  - The README layout table (README.md:39-55) omits `zk/`, `zkvm/`, `px-core/`, `px/`,
    `third_party/` and `fuzz/`. Those are the crates that carry the highest consensus risk.
- **Scenario:**
  - An operator reads AUDIT.md's top status and believes PX is not in consensus.
  - A reviewer reads the README and never learns that the zkVM exists.
  - A readiness decision is made against one document while another says something
    different.
  - Because each file carries its own date, "which one is newer" is a manual comparison.
- **Root cause:** status is written as prose at points in time, not derived from one
  register.

### D-4: Finding identifiers and evidence taxonomies are fragmented, with no central register
- **Classification:** Partially implemented.
- **Severity:** medium.
- **Confidence:** high.
- **Where [SR]:**
  - **Finding namespaces:** F1-F3, M1-M3 (collides between A14's dependency findings and
    the M1 genesis item), H1, N-4…N-9, PX-F1…F5, ZK-F3…F30, ZK-6, W-1…W-5, W-F6…F15, M-1,
    M-2, C-1…C-5, P-1/P-2, P-5…P-9, S3, K4.
  - **Other namespaces:** gates G1…G14, rounds R1…R13, and decision records DR-2…DR-7.
    They live in AUDIT.md (1,565 lines), in docs/reviews/*, and in agent reports outside
    the repository.
  - **Three evidence taxonomies:**
    - review-status.md §2 uses T/S/C/U/O;
    - assumptions.md:12-17 uses Standard/Tested/Argued/Unverified/**External**;
    - the review brief uses mathematically established / tested / source-read / assumed /
      unknown.
  - "External" (assumptions.md:17, :38, :39) now denotes items for a review that the owner
    has decided will not take place (review-status.md §1). So the column no longer tells
    anyone who checks them.
- **Scenario:**
  - "M1" in a commit message is ambiguous.
  - A finding closed in AUDIT.md prose stays "open" in a review file.
  - Nobody can query "all open consensus-impacting findings".
  - The readiness report cannot be generated. It has to be hand-written, and so it drifts
    (D-3).

### D-5: The governance and decision process is not recorded in the repository
- **Classification:** Not implemented.
- **Severity:** medium.
- **Confidence:** high.
- **Where [SR]:**
  - There are 24 "owner decision / approved by the owner" statements across 13 files, and
    no decision log.
  - The mandatory consensus-change pipeline appears in no repository file. It runs:
    analysis → evidence → proposal → security review → tests → implementation →
    integration review, with explicit approval. `git grep` finds no occurrence. It exists
    only in the review brief and the agent memory.
  - AUDIT.md:33 "tracks the audit defined in `Claude.md`". The committed `Claude.md` is an
    AI-agent instruction file, and AUDIT.md is titled "Testnet Readiness **Audit**", while
    owner policy forbids presenting internal work as an audit. That is a naming
    contradiction at the top of the most-read file.
  - Decision records (DR-n) exist only inside zk.md.
- **Scenario:**
  - A contributor, or a future agent, changes a consensus constant with a passing test and
    a plausible commit message.
  - No document tells them that this requires a proposal and the owner's sign-off.
  - Nothing links the decision to its analysis.
  - Later, nobody can reconstruct *why* K4, BS-ZK-2's unique-decoding target, or the
    exact PX fee were chosen, except by archaeology in commit history and prose.

### D-6: Releases, versioning and build identification do not exist
- **Classification:** Not implemented.
- **Severity:** high for the testnet's operability.
- **Confidence:** high.
- **Where [SR]:**
  - `git tag` is empty.
  - Every crate is `version = "0.1.0"`.
  - There is no CHANGELOG, and no release notes.
  - `blacksilk-node --version` comes from clap `version` (node/src/config.rs:27), so it
    prints `0.1.0` for every build.
  - The node's start-up log gives only the network and an 8-byte genesis prefix
    (node/src/main.rs:68-73). It gives no commit, no consensus-rule fingerprint, no kernel
    id and no proof version.
  - P2P `PROTOCOL_VERSION = 1` (p2p/src/message.rs:9) has never been bumped across the v1
    to v2 consensus changes. Only the network id separates them.
  - Yet incident-response.md:167-178 and §5 rely on "tag the commit", "the exact binaries
    and their version (`--version`)", and "operators keep the previous binaries".
- **Scenario:**
  - During the seven-device trial, one operator builds from a local tree with the pending
    M1 or H1 fix, or without it.
  - The genesis and network id match, so testnet-v2-validation.md:29-31 V1 passes.
  - The nodes then fork on the first PX transaction whose proof exercises the difference.
    The incident evidence collected shows `0.1.0` everywhere.
  - Proving which rule set each node ran requires `git rev-parse HEAD` records typed in by
    hand. Those miss a dirty tree.
- **Relation to known items:** this deepens the CI item "no consensus fingerprint pin" into
  an *operator-facing* requirement.

### D-7: Operator documentation lacks upgrade, backup, hardware sizing, monitoring and log-privacy guidance
- **Classification:** Partially implemented.
- **Severity:** medium.
- **Confidence:** high.
- **What exists and is good [SR]:**
  - testnet.md: install, configure, Tor, Docker, systemd, a troubleshooting table
    (testnet.md §9, including `--repair-store`);
  - check-node.sh;
  - incident response and reset plans with rollback;
  - the seven-device checklist with pass criteria.
- **Missing [SR]:**
  1. **Upgrade.** There is no procedure for a non-consensus upgrade: stop order,
     data-directory compatibility, restart replay time. Restart re-validates every PX proof
     (PX-F3). At about 0.21 s per proof that is minutes to hours, and it is undocumented as
     an operator expectation.
  2. **Backup.** There is no node or wallet backup guide. Wallet facts that matter for
     recovery are scattered: 24 words; rings lost on restore; delivered contract records
     only in the wallet file (px.md §13.4); a wallet rollback loses records
     (incident-response.md §6).
  3. **Hardware sizing.** There is no consolidated requirements table. The only hint is
     "add --light on machines with < 3 GB RAM" (testnet.md:46). Missing:
     - PX proving peak of 3.8 GB and about 45-53 s;
     - the full-mode dataset of 2.3 GiB, with a stall at every seed switch;
     - node RAM growing without bound (PX-F1, PX-F2);
     - disk growth of up to about 9.4 MB per block.
  4. **Monitoring.** It is `/info` polling plus log grepping. There is no metrics endpoint
     and no documented list of log lines with meanings and severities. Alerts are
     described only in incident-response §3.
  5. **Log privacy.** Peer IPs are logged at info level (p2p/src/net.rs:408, :768). The
     incident doc warns about this (testnet-incident-response.md:188), but the guide
     operators actually read (testnet.md) has no redaction procedure.
  6. **The RPC reference is split** between blocks.md §9 (7 endpoints) and px.md §11.4
     (2 more). The `/info` fields are not enumerated. There is no RPC versioning.
- **Scenario:**
  - A home operator with 4 GB RAM runs node, miner and a `px-send` together and hits OOM.
  - An operator posts a log with peer IPs and `.onion` peers to a public issue (see D-8).
  - After an emergency release, an operator restarts and sees a long silent replay.
    Believing the node hung, they kill it repeatedly.

### D-8: The GitHub issue templates are legacy and privacy-unsafe
- **Classification:** Not implemented (never updated for the rebuild).
- **Severity:** medium, given privacy-first.
- **Confidence:** high.
- **Where [SR]:** .github/ISSUE_TEMPLATE/bug_report.md, last changed 2025-06-03:
  - its component list includes "Marketplace Backend/Frontend" and "Node.js version";
  - its network list includes "Mainnet";
  - its version example is "v1.0.0";
  - it asks for "Relevant Log Output", "Node configuration", "Number of peers" and
    screenshots;
  - it gives no redaction warning and does not point to SECURITY.md for vulnerabilities.
- **Scenario:** a tester files a sync bug and pastes `--log debug` output. That output holds
  peer IPs, their own public address or onion, Dandelion stem decisions and tx ids. This
  deanonymises both the tester and their peers, permanently, in a public tracker.

### D-9: Developer onboarding is incomplete across platforms and for contract authors
- **Classification:** Partially implemented.
- **Severity:** low-medium.
- **Confidence:** high.
- **Where [SR]:**
  1. **Toolchain story.**
     - README.md:62 says "Rust stable (tested with 1.98)".
     - CI pins 1.98.1.
     - zkvm/guests/rust-toolchain.toml pins 1.98.1 plus riscv32i.
     - The fuzz job uses nightly-2026-09-24.
     - The Dockerfile uses a floating `rust:1-bookworm` (deploy/docker/Dockerfile:8).
     - The root has deliberately no rust-toolchain.toml (zkvm/guests/README.md explains
       why).
     - No single "supported toolchains and platforms" table exists.
     - macOS is never mentioned or tested. CI covers Linux and, for guests and RandomX,
       Windows only.
  2. **Guest target is inconsistent.**
     - zkvm/sdk/src/lib.rs:3 says `riscv32im-unknown-none-elf`.
     - zkvm/guests/README.md and the workspace comment say `riscv32i` + Zmmul.
     - zkvm/src/lib.rs:10 says the AIR is "ZK-3, in progress".
     - This is a symptom of rustdoc not being part of the doc-drift checks.
  3. **Contract authoring is not self-service.**
     - px.md:683: "The wallet can call a contract only through a host-side helper like
       `px::vault`". A third-party author must write a guest *and* patch the wallet crate.
     - There is no tutorial, no template guest, and no "contract author security
       checklist". The checklist would cover the known footguns: approval not tied to
       value, PX-F5 burnable records, budget sizing, and the rcm choice in PX-F4.
  4. **Docker build context.**
     - There is no `.dockerignore`, and the Dockerfile uses `COPY . .`.
     - The build context therefore includes `target/` (about 1.8 GB here), `.claude/`
       (about 1.3 GB of agent worktrees and local settings) and `legacy/`.
     - The final image copies only the binaries, so the leak is confined to the build stage
       and to any remote builder [SR, A].
  5. **Clutter.**
     - `legacy/` holds 521 tracked files, including JS/TS marketplace code and tracked
       build artefacts (`legacy/smart-contracts/target/...`).
     - It dilutes search results, repository language statistics and the "pure Rust"
       message.
  6. The README's "~175 tests" (README.md:67) is off by a factor of more than 2 (the R9
     full suite had 399). This is a symptom of hand-maintained numbers.
- **Positive:**
  - README regtest quick start;
  - labnet (testnet.md §8);
  - guest reproduction scripts;
  - the Windows MSVC and dlltool explanation.
  - A developer on Linux can very likely build, test and run a local network from the
    docs [A].

### D-10: There is no licence at the repository root; the licensing of the patched third-party crates is incomplete
- **Classification:** Not implemented.
- **Severity:** medium, legal and process.
- **Confidence:** high.
- **Where [SR]:**
  - No `LICENSE`/`COPYING` exists at the root.
  - No workspace crate declares `license` except `randomx` (BSD-3-Clause, with its own
    LICENSE).
  - `third_party/p3-*` declare "MIT OR Apache-2.0" but contain no licence text files.
- **Scenario:** the code is by default all-rights-reserved. Operators, testers and a
  prospective second implementer have no grant to run, modify or redistribute it. That
  blocks the decentralisation goal and any outside contribution. It is also an ambiguous
  position for the RandomX port's BSD notice obligations.

### D-11: Architecture documentation (cross-crate) is missing, though the crate-level docs are good
- **Classification:** Partially implemented.
- **Severity:** low-medium.
- **Confidence:** high.
- **Good [SR]:**
  - lib.rs module tables mapping modules to spec sections (crypto, tx, p2p, px, zk);
  - explicit invariants (chain/src/manager.rs:1-12 connected-chain invariant);
  - px-core's "one source for every party" rationale.
- **Missing:**
  - no ARCHITECTURE.md with the crate dependency graph;
  - no threading and locking model. Which locks exist, their order, and which run on async
    threads: the known "chain lock on async threads" and "block processing on the read
    loop" issues are architectural and undocumented;
  - no data-flow for a block or a tx from socket to store;
  - no trust boundaries (untrusted: P2P and RPC input, proofs; trusted: store after
    replay);
  - no list of consensus-critical files, i.e. which files require the consensus-change
    process;
  - no `missing_docs` lint;
  - no `cargo doc` in CI, so intra-doc links and stale module docs are not checked.
- **Scenario:** a reviewer or contributor adds a blocking chain-lock call inside a tokio
  task. Nothing documents that this is forbidden, so review does not catch it.

### D-12: Evidence is not bound to exact builds
- **Classification:** Partially implemented.
- **Severity:** low-medium.
- **Confidence:** medium-high.
- **Where [SR]:** docs/evidence/labnet-2026-09-26/README.md: "Build: the Option A working
  tree on top of `b4262e1`, committed afterwards". That is evidence from a dirty tree, with
  no binary hash and no consensus fingerprint.
- **Scenario:** evidence cited in the readiness report cannot be reproduced exactly, and a
  reader cannot tell whether a later fix invalidates it.

### D-13: Placement and duplication of specification
- **Classification:** Partially implemented.
- **Severity:** low.
- **Confidence:** high.
- **Where [SR]:**
  - Normative, descriptive, measured and planning content are mixed in one file:
    - px.md holds spec, performance, security analysis, roadmap, CLI reference and a
      wallet guide in 742 lines;
    - zk.md holds decision records, a superseded format (zk.md:254 "superseded by px.md
      §11.1"), the normative §9.3 and prior art;
    - contracts.md (1,111 lines) specifies a non-integrated engine whose kinds 2 and 3
      conflict with PX.
  - blocks.md sensibly marks §1-6 normative and §7-9 policy. consensus.md and
    transactions.md declare normativity. Other files do not.
  - transactions.md:20 still says "P2P spec, pending", although p2p.md exists.
- **Scenario:**
  - An implementer cannot tell which sentence is a rule and which is commentary.
  - Superseded text stays in place, and duplicated constants drift. Example: "about 4 PX
    transactions per block" (testnet.md, px.md) against about 3 measured (brief).

### What is correct and well-designed (to keep)
- **The claims discipline [SR]:**
  - review-status.md §1-§3 (no audit claims, the evidence classes, the limits of
    same-model review);
  - assumptions.md as a register;
  - the "not production-ready" framing throughout.
- **v1 specs:**
  - transactions.md §4 is a byte-level grammar with strict-decoding rules;
  - the Δ-Monero list (§14);
  - normative Janus sections (§12.3, §12.5);
  - consensus.md parameter tables;
  - blocks.md's normative/policy split.
  - These are close to what a second implementation needs.
- **Reproducibility:** zkvm/guests/README.md is a model document. It gives the exact
  toolchain, the reason for no root toolchain file, the verification steps, the known
  limitation and the consensus impact.
- **SECURITY.md:** a private channel with a fallback that leaks no details, timelines, and
  scope.
- **Operations:**
  - the incident-response roles are honest about one-owner capacity (§1b);
  - the rollback distinguishes consensus from non-consensus releases;
  - the seven-device checklist has concrete pass criteria and evidence requirements.
- **Rustdoc:** module-to-spec maps and stated invariants.
- **CI** comments explain every pin.

---

## 2. Per-area answers to the brief's 13 questions

### 2.1 Normative protocol specification
1. **Implemented.**
   - v1 byte-level specs: consensus, transactions, blocks §1-6, p2p framing;
   - zkvm ISA and syscalls;
   - PX statement semantics.
2. **Correct and well-designed.**
   - transactions.md grammar and strict decoding;
   - domain-separation tables;
   - Δ-Monero justification;
   - the network-id binding in `sig_message`.
3. **Incomplete.**
   - the PX tx byte grammar;
   - the proof grammar;
   - the AIR constraints in prose or math;
   - an explicit list of the Plonky3 transcript and configuration;
   - frozen vectors (D-1, D-2).
4. **Fragile.** Consensus bytes depend on serde derives in third-party crates and on a
   caret-pinned postcard (D-1).
5. **Exploitable.** Only indirectly: the M1 malleability class survives when bytes are
   unspecified.
6. **Inefficient.** Specs mix normative and descriptive content, so review cost is high
   (D-13).
7. **Does not scale.** One author holds the implicit knowledge. A second client or a
   language binding is impossible for PX.
8. **Missing.**
   - RFC 2119 conventions;
   - a spec version per layer;
   - a consensus-parameter manifest;
   - vectors.
9. **Redesign.** Move to a `spec/` tree (§3).
10. **Innovate.**
    - A **consensus manifest**: one canonical TOML/JSON listing every consensus constant,
      domain tag, pinned artefact hash (kernel.elf, the Poseidon2 constants hash) and the
      proof-system parameters. It is hashed into a **consensus fingerprint**, checked by a
      test against the code, printed by the node, and served in `/info`.
    - The manifest is both documentation and a pin.
    - Prior art [EXT]: the Zcash protocol spec's constants appendix, and Ethereum's
      `execution-spec-tests` fixtures.
11. **Pre-testnet.**
    - the fingerprint (D-6);
    - a minimum vector set for tx hash, `sig_message`, address, emission and `Hk` domains;
    - an explicit "normative by reference" section for the proof system listing crate
      versions, patch hashes and MUST-constraints (the witness == 0 rule if chosen).
12. **Deferrable.**
    - full AIR prose spec;
    - an independent verifier;
    - vectors for P2P.
13. **Never change.**
    - Do not "clean up" encodings to match a spec written afterwards. Where the spec and
      the code differ today, document the code's behaviour as the rule and pin it with
      vectors.
    - Rewriting the encoding is a hard fork with no benefit.

### 2.2 Navigability and single source of truth
1. **Implemented.**
   - README → specs;
   - review-status as the policy anchor;
   - evidence directories with READMEs.
2. **Correct.** The evidence READMEs state what they are *not*.
3. **Incomplete.**
   - no docs index;
   - orphaned reports;
   - the README omits the ZK crates and documents (D-3).
4. **Fragile.** Hand-maintained status in eight places.
5. **Exploitable.** No.
6. **Inefficient.** Readers must reconcile dates across files.
7. **Does not scale.** AUDIT.md at 1,565 lines grows forever.
8. **Missing.**
   - `docs/README.md` (index);
   - `STATUS.md`;
   - a findings register (D-4).
9. **Redesign.**
   - Findings are kept as structured records: one file or table row each, with ID,
     component, severity, classification, consensus impact, status, fix commit and test.
   - STATUS and the readiness report are generated from those records.
   - AUDIT.md is frozen as history and renamed to avoid "audit" (e.g. `docs/history/
     internal-review-rounds-R1-R13.md`).
10. **Innovate.** A CI check: every `docs/**/*.md` is linked from the index; every finding
    ID referenced exists in the register.
11. **Pre-testnet.** STATUS.md as the one status source, the others pointing to it; the
    README index fix.
12. **Deferrable.** Migrating historical findings into the register (start with the open
    ones).
13. **Never change.** Keep review-status.md's policy text. Its wording is precise and
    matches owner policy.

### 2.3 Developer onboarding
1. **Implemented.**
   - build/test commands;
   - regtest quick start;
   - labnet;
   - guest reproduction;
   - the Windows MSVC note.
2. **Correct.** The toolchain rationale in zkvm/guests/README.md.
3. **Incomplete.**
   - platform matrix;
   - contract-author path;
   - a single toolchain table (D-9).
4. **Fragile.**
   - Windows-only kernel reproducibility (known);
   - the floating Docker toolchain.
5. **Exploitable.** The Docker context sweep (D-9.4) is a low-grade local-data leakage
   risk.
6. **Inefficient.** Tests run in release only, because PX proofs are slow. A developer's
   first `cargo test --workspace` (as the README says) runs in debug and will appear to
   hang. The README should say `--release`, as CI does [SR: ci.yml "tests run in release"].
7. **Does not scale.** Contract authors must fork the wallet.
8. **Missing.**
   - CONTRIBUTING.md (branching, commit style, the consensus-change rule, how to run CI
     locally);
   - a template guest;
   - a contract author checklist.
9. **Redesign.** A generic wallet contract-call interface. That is a product decision, P3.
10. **Innovate.** A `cargo xtask` for `doc-check`, `vectors`, `fingerprint` and `repro`,
    which gives one entry point on all OSes.
11. **Pre-testnet.**
    - the README test command;
    - a toolchain table;
    - `.dockerignore`;
    - the Docker toolchain pin.
12. **Deferrable.** The contract SDK and wallet plugin interface; macOS CI.
13. **Never change.** Do not add a root rust-toolchain.toml: the reasoning in
    zkvm/guests/README.md holds.

### 2.4 Code-level documentation and architecture
1. **Implemented.** Crate module maps and several invariants.
2. **Correct.** Module ↔ spec-section tables.
3. **Incomplete.** ARCHITECTURE.md, the concurrency model, trust boundaries (D-11).
4. **Fragile.** Stale crate docs (zkvm/src/lib.rs:10, sdk:3) are unchecked by CI.
5. **Exploitable.** Indirectly, when a contributor violates an undocumented locking rule.
6. **Inefficient.** No.
7. **Does not scale.** net.rs has 1,781 lines with its invariants implicit.
8. **Missing.**
   - `#![warn(missing_docs)]` on the public API of consensus-critical crates;
   - `cargo doc -D warnings` in CI;
   - a list of consensus-critical files (for CODEOWNERS-like review).
9. **Redesign.** None; add documents.
10. **Innovate.** `// CONSENSUS:` markers on consensus-critical constants and functions,
    checked by a script against the manifest.
11. **Pre-testnet.** A short ARCHITECTURE.md (1-2 pages). It is cheap and helps reviewers
    of the P2P and threading fixes now in flight.
12. **Deferrable.** `missing_docs` everywhere.
13. **Never change.** px-core's single-source design. Documentation must never introduce a
    second description that could drift from it.

### 2.5 Operator documentation
1. **Implemented.**
   - install (systemd, Docker, Tor);
   - config;
   - troubleshooting;
   - incident response;
   - reset;
   - rollback;
   - the seven-device checklist.
2. **Correct.**
   - the RPC-exposure warnings;
   - the Tor proxy-only DNS note;
   - the `--repair-store` procedure;
   - the store-failure exit semantics.
3. **Incomplete.** Upgrade, backup, sizing, monitoring, log privacy, the RPC reference
   (D-7).
4. **Fragile.** Build identity (D-6).
5. **Exploitable.** Log and issue deanonymisation (D-7.5, D-8).
6. **Inefficient.** Monitoring by grepping logs.
7. **Does not scale.** Seven operators coordinated by prose and hand-typed commit ids.
8. **Missing.**
   - an operator handbook;
   - release notes per build;
   - checksums;
   - a structured `/info` with version and fingerprint.
9. **Redesign.** None.
10. **Innovate.** `/info` returns `{build_commit, dirty, consensus_fingerprint,
    kernel_id, proof_version, protocol_version}`, and check-node.sh compares them against
    an expected value passed on the command line.
11. **Pre-testnet.** D-6 and the D-7 items 1, 2, 3 and 5; D-8.
12. **Deferrable.** A Prometheus endpoint; dashboards.
13. **Never change.**
    - loopback-only RPC by default;
    - the refusal of unknown config keys.

### 2.6 Governance and process
1. **Implemented.**
   - SECURITY.md;
   - the review-status policy;
   - the internal review log;
   - the gates checklist.
2. **Correct.** The gate model (Passed / In progress / Accepted with a recorded reason).
3. **Incomplete.** Decision log, change process, releases, licence (D-5, D-6, D-10).
4. **Fragile.** Decisions exist in prose and agent memory.
5. **Exploitable.** An unreviewed consensus change can slip in through a normal PR (D-5).
6. **Inefficient.** No.
7. **Does not scale.** Any second maintainer.
8. **Missing.**
   - BSIP process;
   - DECISIONS log;
   - CHANGELOG;
   - versioning policy;
   - LICENSE;
   - CONTRIBUTING;
   - CODEOWNERS-equivalent for consensus paths;
   - GitHub private vulnerability reporting (pending per SECURITY.md).
9. **Redesign.** AUDIT.md naming (D-5).
10. **Innovate.** Each consensus-affecting PR must reference a BSIP number. A CI check
    fails if a file in the consensus-critical list changes without the `BSIP:` trailer in
    the commit.
11. **Pre-testnet.**
    - LICENSE (owner decision);
    - a DECISIONS log seeded from the 24 existing decisions;
    - the consensus-change process written into CONTRIBUTING;
    - versioning and tagging for the release commit;
    - enable private vulnerability reporting.
12. **Deferrable.** A full BSIP editorial process with numbered drafts.
13. **Never change.** The owner-approval gate for consensus, crypto and protocol changes.

---

## 3. Target documentation structure

It is modelled on:
- the Zcash ZIPs and protocol spec [EXT: https://zips.z.cash/zip-0000,
  https://zips.z.cash/protocol/protocol.pdf];
- Bitcoin BIP-2 [EXT: https://github.com/bitcoin/bips/blob/master/bip-0002.mediawiki];
- RFC 2119/8174 keywords;
- Keep a Changelog and SemVer [EXT];
- the Diátaxis split into tutorial / how-to / reference / explanation [EXT:
  https://diataxis.fr].

```text
README.md                  what it is, status one-liner → STATUS.md, doc index link
STATUS.md                  THE status: per-component maturity (L1–L6), open P0/P1 findings,
                           testnet gates. Generated from findings/ + gates; no other file
                           carries a status line (they link here)
SECURITY.md                (keep) + link to disclosure log
LICENSE, NOTICE            owner's choice; third-party notices (RandomX BSD, Plonky3 MIT/Apache)
CHANGELOG.md               per tagged release: consensus changes (BSIP ids), fixes (finding ids)
CONTRIBUTING.md            build, test (release), style, the consensus-change rule, commit trailers
ARCHITECTURE.md            crate graph, data flow, threading/lock model, trust boundaries,
                           consensus-critical file list

spec/                      NORMATIVE ONLY (RFC 2119), versioned per layer
  00-conventions.md        encodings, hashing, domain-tag registry, notation
  01-consensus.md          header chain (from consensus.md)
  02-blocks.md             blocks, emission, genesis (blocks.md §1–6)
  03-transactions-v1.md    (transactions.md normative sections)
  04-px.md                 PX statement, tx kinds 2/3 byte grammar, rules PX1–PX5, fee
  05-proof-system.md       normative-by-reference: Plonky3 0.7.0 + patch hashes, config,
                           transcript order, proof byte grammar, MUST-constraints
  06-zkvm.md               BVM-1 ISA, syscalls, program id, AIR tables (math)
  07-p2p.md                wire protocol (policy parts marked non-normative)
  manifest.toml            every consensus constant, tag, artefact hash → fingerprint
  vectors/                 JSON test vectors: primitives, tx, blocks, emission, LWMA,
                           addresses, Hk, PX binding, golden valid/invalid proofs, genesis
                           (consumed by Rust tests; usable by any implementation)

design/                    DESCRIPTIVE: rationale, threat models, decision records
  bsip/                    BlackSilk Improvement Proposals (process in bsip-0001.md)
  decisions.md             dated decision log (owner decisions, with links)
  zk-architecture.md, contracts-wasm.md (marked "not in consensus"), privacy-model.md

operators/                 OPERATOR HANDBOOK
  install.md, configure.md, hardware.md, monitoring.md (log catalogue, /info fields),
  upgrade.md, backup-restore.md, log-privacy.md, troubleshooting.md,
  incident-response.md, testnet-reset.md, rpc-reference.md

developers/                DEVELOPER GUIDE
  building.md (toolchain/platform matrix), testing.md, local-network.md (regtest, labnet),
  px-contracts.md (tutorial + author security checklist), reproducible-guests.md

reviews/                   internal review material (keep), + findings/ register
  findings/                one record per finding (id, component, severity,
                           classification, consensus impact, status, fix, test)
  evidence/                bound to commit + fingerprint + binary hashes
history/                   frozen: AUDIT.md rounds R1–R13 (renamed), superseded designs
```

**BSIP-0001 (process), minimal version for a one-owner project:**
- **Required sections:**
  - status (Draft / Proposed / Accepted / Final / Rejected / Withdrawn);
  - layer (consensus, P2P, wallet, process);
  - motivation;
  - specification (normative diff to `spec/`);
  - security, privacy, consensus and testnet-identity impact (the same fields as this
    brief);
  - test vectors;
  - an evidence plan;
  - the owner's approval, with a date.
- The stages map one-to-one onto the owner's pipeline: analysis → evidence → proposal →
  security review → tests → implementation → integration review.
- A consensus-affecting change merges only with `BSIP: n` in the commit message.

---

## 4. Prioritized plan, with the fields required for each recommendation

"Consensus impact" means impact on the protocol, not on the documents. None of these change
consensus unless stated otherwise.

| # | Recommendation | Why | Security | Privacy | Perf | Complexity | Consensus | Testnet identity | Diff. | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **Consensus fingerprint and build id.** A manifest-derived hash of all consensus constants, tags, kernel id, proof version and BS-ZK params, pinned by a test. The node logs and `/info` show it with commit and dirty flag, and `--version` prints it. check-node.sh compares against an expected value; testnet-v2-validation V1 checks it (D-6) | Operators cannot otherwise prove they run the same rules; a mixed-rule trial forks silently | High (detects rule divergence before it causes a split) | None (public constants; the commit id is public) | None | Low | None (policy; exposes data) | No | S-M | **P0** |
| 2 | **One status source.** Create STATUS.md; replace every other status line with a link; fix the README index and layout; link the orphan reports (D-3) | Readiness decisions need one truth | Medium (avoids wrong go/no-go reads) | None | None | Low | None | No | S | **P0** |
| 3 | **Releases.** Tag the release commit, add a CHANGELOG entry with finding and BSIP ids, set the workspace version (e.g. `0.2.0-testnet.2`), publish SHA-256 of release binaries built with `--locked` on the pinned toolchain (D-6) | Incident response §4.11 and §6 assume it | Medium | None | None | Low | None | No | S | **P0** |
| 4 | **Privacy-safe reporting.** Rewrite the issue templates (current components; no Mainnet or Node.js; a redaction warning; a pointer to SECURITY.md); add operators/log-privacy.md with a redaction procedure (IPs, onions, tx ids at debug); enable GitHub private vulnerability reporting (D-8, D-7.5) | A privacy chain must not solicit deanonymising logs | Low | **High** | None | Low | None | No | S | **P0** |
| 5 | **LICENSE and NOTICE** at the root plus `license` in the workspace crates; add licence texts to third_party (D-10). Owner chooses the licence | Legal ability to run and contribute; BSD notice for the RandomX port | None | None | None | Low | None | No | S (decision) | **P0** |
| 6 | **Minimum frozen vectors.** JSON under `spec/vectors/`, loaded by tests: `Hs`, `Hp`, `G`, `H`, the first BP generators, all domain tags; one coinbase and one transfer tx (bytes, prefix/base/prunable hashes, tx_hash, sig_message); an address string; the emission at heights 1, 10^3, 10^6 and at the tail switch; an LWMA run; `tx_root`; `Hk` for each PX domain; one PX `h_tx`; one golden valid proof and its tx id (D-2) | Catches accidental consensus changes that self-consistent tests miss; enables third-party wallets | High (fork prevention) | None | None | Low-medium | None, if the vectors capture current behaviour; a CONSENSUS bug if they reveal a mismatch with the spec, which then needs a BSIP | No | M | **P0** (tx, hash and `Hk` subset); rest P1 |
| 7 | **Proof-system normative-by-reference spec** (spec/05): exact crates, versions and patch hashes; the config; the transcript order; the proof byte grammar (postcard layout of every field); every "MUST equal" (including the M1 resolution); the folding-schedule rule (M3); a statement that any change is a hard fork (D-1) | The M1/M2/M3 class of issues needs a written rule to test against | High | Medium (proof-length privacy P-5 depends on the layout) | None | Medium | None to write; it documents the CONSENSUS rules the owner decides for M1 and M3 | Only if M1 or M3 are fixed by rule (owner decision, v3) | M | **P1** (before the trial if M1 is fixed for v3) |
| 8 | **Operator handbook, minimum:** hardware.md (RAM, CPU, disk, proving time, dataset switch stall, RAM growth PX-F1); upgrade.md (non-consensus upgrade, replay time with PX-F3, compatibility); backup-restore.md (node dir, wallet file vs seed, what the seed does not recover); rpc-reference.md (all 9 endpoints, `/info` fields); a log catalogue (D-7) | The seven operators need it to run V1–V16 reliably | Medium | Medium (the backup guidance touches wallet recovery privacy) | None | Low | None | No | M | **P1** |
| 9 | **Governance:** DECISIONS.md seeded from the 24 existing owner decisions; CONTRIBUTING.md with the consensus-change pipeline; BSIP-0001; a consensus-critical file list plus a CI check that requires a `BSIP:` or `Consensus-Approved:` trailer when those files change; rename AUDIT.md into history (D-4, D-5) | Makes the owner's gate enforceable, not remembered | High (blocks unreviewed consensus edits) | None | None | Medium | Policy | No | M | **P1** |
| 10 | **Findings register:** one record per finding, unified IDs (prefix by area: `CONS-`, `P2P-`, `ZK-`, `PX-`, `WAL-`, `STO-`, `DEP-`, …, with the old IDs kept as aliases); one evidence taxonomy (merge T/S/C/U/O with the brief's classes); retire "External" in assumptions.md in favour of "Unverified (no external review planned)" (D-4) | Queryable open-risk list; the generated STATUS | Medium | None | None | Medium | None | No | M | **P1** |
| 11 | **ARCHITECTURE.md:** crate graph, block and tx data flow, the thread and lock model (tokio vs blocking; chain-lock rules), trust boundaries, the consensus-critical list (D-11) | Reviewers of the in-flight P2P and threading fixes need the rules written down | Medium | Low | None | Low | None | No | S-M | **P1** |
| 12 | **Evidence binding:** every evidence README records commit (clean), fingerprint, binary SHA-256, toolchain and OS (D-12) | Reproducible readiness claims | Low | None | None | Low | None | No | S | **P1** |
| 13 | **Developer DX:** a toolchain and platform table; README `cargo test --release`; `.dockerignore` (target, .claude, legacy, fuzz corpora); pin the Docker base to 1.98.1; mark macOS untested; fix the zkvm crate-doc drift; `cargo doc -D warnings` in CI (D-9) | Onboarding; the build-context leak; drift detection | Low-medium (.dockerignore) | Low | Faster Docker builds | Low | None | No | S | **P2** |
| 14 | **Split the specs:** move normative text into `spec/` with RFC 2119 keywords; move rationale, performance and roadmap into `design/`; delete superseded sections (zk.md §5.1) and link instead; mark contracts.md "not consensus; kinds conflict with PX" at the top (D-13) | Implementers and reviewers need rule/commentary separation | Medium | None | None | Medium-high (a large edit) | None, but it must not change meaning. Review each moved rule against the code and vectors | No | L | **P2** (start with spec/03 and 04) |
| 15 | **PX contract developer guide:** a tutorial from template guest to deploy to call; a contract-author security checklist (approval vs value, PX-F5 burn, budgets, rcm/PX-F4, delivery); a documented limitation that wallet integration requires code changes (D-9.3) | Contract authors will otherwise write unsafe contracts | Medium-high (footguns) | Medium | None | Medium | None | No | M | **P2** (checklist P1 if third parties deploy on the testnet) |
| 16 | **Machine-readable conformance suite:** golden invalid vectors (one per rule T1–T11, C1–C4, B1–B7, PX1–PX5) as JSON; a Rust runner; a second-implementation readiness statement | Long-term decentralisation (multiple clients) | High | None | None | High | None | No | L-XL | **P3** |
| 17 | Metrics endpoint (Prometheus text, loopback) and a monitoring guide | Operations at scale | Low | Must avoid per-peer or per-tx labels | Negligible | Medium | None | No | M | **P3** |
| 18 | Move `legacy/` out of the main repository (an archive branch or tag), keeping a README pointer | Clarity, and the pure-Rust message | None | None | Smaller clones | Low | None | No | S | **P3** |

**Order of execution before the trial:**
1. Items 1-5, all small; item 1 is the only code change.
2. Item 6, the tx, hash and `Hk` subset.
3. Items 8, 11 and 12, then 9 and 10.
4. Item 7 in the same change set as the owner's M1/M3 decision, so the v3 identity changes
   only once.

---

## 5. What should never change (documentation-related)
- **Honesty.** review-status.md's policy wording, the evidence-class discipline, the
  "not an audit" framing, and "statistical and conditional" ZK wording. Any restructure
  must carry these over verbatim.
- **Code as the tie-breaker.** transactions.md states that where the spec and the code
  disagree, that is a bug. Once vectors exist, the vectors decide, and the vectors are
  generated from the deployed code. Do not "fix" code to match newly written prose without
  a BSIP.
- **Reproducibility.** The rationale for having no root rust-toolchain.toml, and the
  guest reproducibility procedure.
- **One-source kernel design.** px-core is both the native code and the guest. Never add a
  separate circuit description.
- **RPC defaults:** loopback-only RPC, strict config parsing, and no own-address
  advertisement by default. The operator docs rely on them.

---

## 6. Limits of this review
- The review was read-only and ran no builds. I did not execute `cargo doc`, the docs'
  commands, or the Docker build. The Docker context size comes from `du` on this machine's
  checkout, not from a build [SR/A].
- I did not verify that Linux or macOS builds succeed from the docs [U].
- I made no web fetches. External references are cited from my own knowledge [EXT].
- The count of "owner decisions" is a grep over wording. It is approximate, but its order
  of magnitude is reliable.
- Stale individual statements are cited only as symptoms. A16b owns their correction.
