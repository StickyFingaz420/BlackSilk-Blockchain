# Coordinator decisions log (phase 2)

Status: append-only coordinator log; later entries supersede earlier ones (for example
D1, the wallet's local decoy distribution, is built: `wallet/src/index.rs`). Current
state: [docs/STATUS.md](../../STATUS.md).

## Agent 07 dossier (randomx-cache-seed)

- **`miner/src/main.rs` ownership:** single owner is 09 (mining-templates). Agent 07 delivers `SeedPlanner` and the prebuild inside `miner/src/lib.rs`. Agent 09 wires `main.rs`.
- **Miner prebuild:** off by default, with the light-mode bridge as the fallback. This will be revisited when the trial device RAM is known (the trial needs at least 8 GB). `--prebuild` is enabled in the labnet evidence runs.
- **W2 (RPC `/block` gate):** a shared `worth_verifying` predicate in `chain`, used by both P2P (31) and RPC (36). One rule, one place (R16-5).
- **W1–W3 priority:** raised to P0 for the trial, because the 1–3 s chain-lock convoy occurs at every seed switch. Implemented in the first implementation wave, and coordinated with the 34 chain-actor design.

## Agent 14 dossier (fee-economics)
- **R12-2:** option (a′) is accepted provisionally: PX/deploy transactions with v1 inputs weigh `max_weight(n_in, n_out)` against `MAX_BLOCK_WEIGHT`.
  - This is a CONSENSUS change at the v3 genesis.
  - It is final only after agent 10's worst-block benchmark and the red-team review.
  - It lands before the next evidence labnet run.
  - Add weight samples to the fingerprint (also a general "rule samples" section, owner 40/01).
- **Template ordering:** PX first, and no cross-unit fee comparison (owner 12, with 09).
- **Sub-pools:** a deploy sub-pool of about 8 MiB that never evicts PX; PX kept first-seen; deploy expiry (owner 12). Random eviction is left to 12's research.
- **Exact v1 fee (fee == standard):** decided after agent 38 (wallet privacy) and agent 12 report; recorded as an open decision.

## Agent 12 dossier (mempool-architecture)
- **Re-ratings:** M12-1 re-rated to High for testnet liveness. W1 (ring-digest reorg revalidation) and W2 (cheap readmission) are P0.
  - On a digest mismatch the entry is dropped, not re-verified, because the ring is hashed into the CLSAG challenges.
  - The cheap contextual checks (key images, nullifiers, anchors, C4) still run.
- **Stateful test:** W6 (a stateful mempool test with real reorgs) is P0 and is required for W1/W2 merges.
- **proptest:** allowed as a dev-dependency after agent 44 confirms it has no C/unsafe-in-our-crates issue (proptest is pure Rust). Agent 41 owns adoption.
- **Digest tag:** registered in crypto/src/hash.rs by 19's domain registry (policy-only tag).
- **Expiry:** 2160 blocks for all classes, pending agent 38's rebroadcast analysis.
- **Eviction under exact fees:** ZIP-401-style random eviction is to be decided together with 14's sub-pools (P2).

## Agent 15 (CLSAG)
- **W1: reject D = identity.** `sign` refuses z = 0. A stateless (penalizable) error, as a consensus tightening at the v3 genesis. No honest transaction changes.
- **C6:** Monero's zero-challenge check is NOT adopted (probability 2^-252).
- **W10:** the Monero conformance harness is allowed as a crate outside the workspace (`tools/clsag-conformance`, excluded from the workspace). The dev-only RustCrypto `sha3` is pure Rust. Agent 44 must confirm it.
- **W3 vectors and W8 bench:** P0.

## Agent 01 (consensus-core)
- **Vector generator:** a test-only Python script committed under `tools/consensus-vectors/`, marked non-core. The pinned artifacts are the data files.
- **`consensus/src/params.rs` v3 genesis constants:** owner 40, with 01 reviewing.
- **F-05 reorder:** accepted before the freeze. It changes error classes and scoring, not validity. A vector covers it.
- **Startup PoW sampling:** on by default (48 samples), plus a `--verify-store-pow` flag for a full check.
- **Template self-check failure:** fall back to a coinbase-only template, log at ERROR, and export a metric. Liveness over refusal.
- **P0 set:** the rule table and doc fixes, a negative test for every block rule, and the vector files at the freeze.

## Agent 06 (randomx-performance)
- **New dependencies:** none with internal `unsafe` may enter the consensus crates for performance. SIMD crates, FMA-cfg paths and a JIT are all rejected.
- **Benchmark window:** an exclusive window after the research phase, before implementation waves start. W1 and W2 gate every optimization.
- **W3 (batched superscalar/dataset):** P1, because full-mode miners will run across 2113 in the evidence runs.
- **Release variants:** no x86-64-v3 release variant for now (reproducibility first).
- **Batching:** used in initial sync only. The tip header is always verified singly.

## Agent 10 (block-validation)
- **F10-2:** decode PX proofs early, shape-check them before any CLSAG, and resolve all rings first. P0, policy only. Changing the reported error is accepted: verdicts are identical, and vectors cover it.
- **R12-2:** 14's option (a′) and 10's option (a) are the same rule: the v1 part of PX and deploy transactions counts toward MAX_BLOCK_WEIGHT, and PX bytes stay in the PX budget. Adopted for the v3 genesis after item 3's benchmark.
- **`tx/src/validate.rs` ownership:** 10 owns the block-level functions; 11 owns the single-transaction rules.
- **Verification threads:** default `min(4, cores)`, with a `--verify-threads` flag.
- **Benchmark harness:** `#[ignore]` timing tests, no new dependency.
- **Verified-proof cache (item 6):** P0 before any second verifier.

## Agent 16 (Bulletproofs+)
- **BPP-3 (pinned vectors):** raised to P0.
- **Hedged batch weights:** policy only (outcome differs with probability ≤ 2^-128). Accepted without the consensus process.
- **Independent verifier:** written by a different agent (15's reference author, not 16).
- **Weights:** stay 128-bit.
- **`node/src/fingerprint.rs`:** owned by 40.

## Agent 17 (stealth-janus)
- **Result:** wallet-level burning-bug safety needs only within-transaction one-time-key uniqueness. This feeds the D8/C4 decision with 13.
- **API change:** allowed (`ScanOutcome::Rejected` loses the subaddress; `rejected` becomes local diagnostics).
- **Derivation vectors:** pinned now. The v1 formulas do not depend on seed versioning.
- **One-output-per-key-image wallet rule:** implemented whatever D8 decides (cheap, Monero parity).
- **proptest in crypto:** allowed as a dev-dependency (see 12).
- **docs/transactions.md:** 17 writes the §3/§12 content; 47 coordinates edits.

## D8 / C4: DECIDED, option B (agents 13 and 17 independently; prior art from Monero master, Carrot §4.3, ZIP 227)
- **Removed:** cross-transaction and chain one-time-key uniqueness (C4 against the chain and within the block, and `CoinbaseDuplicateOneTimeKey`), the state key set, and the mempool OutputKey namespace.
- **Kept:** within-transaction distinctness for every kind (transfer and deploy sort rules, coinbase sort, `PxDuplicateOutputKey`). Explicit tests are added. The existing variants stay; no new unified variant.
- **Order of work:**
  1. Attack tests first (they pass on current code, then are inverted).
  2. Wallet key-image dedupe (17 and 13) lands in the SAME change.
  3. Decoy selection must NOT exclude duplicate-key outputs (F13-7).
  4. Red-team (50) reviews the final diff.
- **Fingerprint:** gets a general rule-revision list (owner 40).
- **Test accessor:** a test-only p2p stempool accessor is allowed as `#[doc(hidden)] pub`.
- **Third-party wallets without the Janus check:** not a goal. Documented.

## Agent 08 (randomx-determinism)
- **Big-endian:** node builds are refused now (`compile_error!` in consensus/src/lib.rs, owner 01).
- **Repository:** public (the GitHub API is readable without auth), so standard runners are used and macOS legs are weekly.
- **Startup self-test failure:** stops the node, with a `--skip-randomx-self-test` override for diagnosis. `--randomx-self-test` is the P0-13 per-device check.
- **W3 digests:** may land as self-consistency first, then oracle-validated when 05's corpus exists.
- **CI:** a separate workflow file, `randomx-determinism.yml`, is approved.

## Agent 09 (mining-templates)
- **Prebuild default:** REVISED to `--prebuild auto`: on when the fallible allocation succeeds, otherwise the light bridge. Full mode only.
- **/template:** refuses while syncing or mid-drain (503). It does NOT refuse for zero peers.
- **/tip:** polled now; long-poll after 34's actor design.
- **Evidence:** the seedrun2 summary is committed as evidence (the light-mode switch at 2113). Full-mode runs A and B get exclusive machine windows after implementation wave 1.
- **Labnet instrumentation (I4):** P0 in wave 1.

## Agent 20 (px-kernel)
- **F-20-1 (a contract input can be approved by several functions):** ACCEPTED as a v3 consensus item. It adds an `ApprovalConflict` error (exit 18) and needs a new kernel id.
  - It lands in the SINGLE v3 kernel rebuild, together with the R2-C6 decision (19) and the budget re-pin (W5).
  - Agent 43 builds and reproduces the ELF and ids; agent 20 re-measures the budgets.
  - The red-team (50) reviews it.
- **proptest in px tests:** allowed. A guest-interpreter sample runs in CI, with a bounded case count.
- **docs/zk.md §6–§7:** rewritten to match the code. docs/px.md is the normative PX spec; zk.md points to it for kernel rules (owner 47, with content from 20).

## Agent 18 (crypto-randomness)
- **Never-change item 12 (HedgedRng input order):** it stays for consensus-adjacent pinned vectors. A versioned wallet-only v2 layout is NOT adopted now (P3); the accepted limitation is documented.
- **W3 hedged decoy selection (F18-4, Medium, privacy):** owner 38, implemented with 18's derivation spec. Keyed with `k_s`.
- **Public `HedgedStream: RngCore + CryptoRng`:** accepted (W2 enabler, owner 18).
- **Vault secret:** derived from the wallet's PX secret via `hedged_digest` (W4). Accepted, and recoverable from the seed, which is a plus.
- **Miner secret file:** optional, off by default (W5, with 09).
- **Hedge secret:** becomes a DERIVED hedge key (domain-separated from the spend key), decided together with 37's key hierarchy before the vector pin.
- **Membership nonce (W1):** P1 now, because the fix is cheap.

## R2-C6: DECIDED, option A (agent 19, reversing SX1/D9)
- **What:** keep the tree node (no feed-forward) for v3.
  - Basis: Coratger–Khovratovich–Mennink–Wagner, ePrint 2026/089 (CCS 2026), which proves binding and extractability of Plonky3-style truncated-permutation trees at about 122.6 bits.
  - Feed-forward buys no security level and costs +2,631 cycles and a new kernel id.
  - The STARK's own Merkle commitments use the same construction anyway.
- **Conditions:**
  - Agent 50 (red-team) must independently verify the citation, Theorem 3's applicability, and 19's adaptation argument (F3: the add-into-rate sponge, domain/len start, zero empty leaves).
  - Real-permutation vectors, the lint guard on node(), adversarial tests, and the Poseidon2 instance in the fingerprint.
  - A hash-agility plan is written (triggers monitored by the coordinator in phase 2; afterwards listed as an owner task).
- **Python independent vector scripts:** allowed as test tooling, non-core.
- **px-core attribute for the lint:** allowed only if the kernel ELF id is unchanged, verified with reproduce.sh.

## Agent 02 (fork-choice)
- **F-1 (withheld heavier branch starves downloads):** both a fair per-candidate `missing_bodies` (02) and per-peer targeted download (31). P1, raised to P0 for a public testnet.
- **W-7 park-on-deep-reorg:** adopted as policy. Default OFF for the 7-device trial (K4), 720 for a public testnet. Operator accept required.
- **W-1 reference model plus proptest:** P0 (proptest approved for chain).
- **F-4:** document it, do not change the behaviour.
- **LOW_WORK_MARGIN_BLOCKS:** stays 100, pending 31's presync design.
- **W-4:** skip re-verification of already-validated blocks on reconnect. Coordinated with 34 and 10.

## Agent 04 (timestamps)
- **Clock before the genesis time:** the node refuses to start.
- **Miner clock skew:** the miner refuses to mine on skew > FTL/2 by default (`--allow-clock-skew` override).
- **R1-C8:** downgraded to Low only after 03's Rust harness confirms it.
- **`--clock-offset-secs`:** regtest only.
- **W3 ClockMonitor:** P1 before the trial.

## Agent 11 (tx-validation)
- **D12 output words: CLOSED.** Words stay raw u32, now normative in the docs. No consensus change. A zkVM test with words ≥ p is owned by 23.
- **Tree-capacity rule (I3):** rides the v3 reset (free now), with the full consensus record. `apply_block` returns a Result, with no panic path.
- **Golden corpus:** tx-level vectors are owned by 11 in `tx/tests`; 01 aggregates them into the frozen vector files.
- **Penalizing invalid transactions:** kept (stateless-first order prevents masking). The reasoning is recorded in p2p.md §10.
- **Ownership split of validate.rs:** 11 owns the single-tx functions, TxError and classification. 10 owns the block phases. 13 owns the uniqueness function. Trait edits from 13 and I3 land in one commit.
- **I5 (all errors contextual within the activation grace window):** accepted (P2).

## Agent 05 (randomx-conformance)
- **C1 (vector 1f) and C10 docs:** P0, first in the RandomX queue.
- **Normative reference:** tevador/RandomX v1.2.3. v2.0.1 in default (v1) mode is a mandatory cross-check.
- **C++ reference generator:** allowed ONLY as off-tree oracle tooling.
  - `tools/randomx-reference/` holds scripts and a README that fetch tevador at a pinned SHA and build it outside cargo.
  - The C++ source is never vendored; there is only a small driver file for the corpus export.
  - It runs in a separate, manually triggered or pre-release CI workflow.
  - It is documented in the dependency policy as a test oracle, not core functionality; the node and wallet binaries never contain it.
  - In-tree checks are pure Rust over data files pinned by digest.
- **Fixtures:** compressed, ≤ 10 MB in git, pinned by digest, with PROVENANCE.md.
- **C6 Monero oracle:** P2. Running a monerod here is impractical. Public block data may be fetched later; the hash × difficulty check makes the source untrusted-safe.
- **CI budget:** a 1,024-hash subset per push. The full tiers run pre-release and on manual dispatch, sharded under 6 h per job; they are not weekly.
- **C3 FPU oracle:** P1. 06's FPU fast path (W6) is NOT planned before the freeze, so the oracle is not a P0 blocker.
- **Merge gate:** C1–C3 must be green before 06's W3–W7.

## Agent 21 (px-nullifiers-commitments)
- **Anchor depth:** `ANCHOR_MIN_DEPTH = 3` for all records, rounded down to a multiple of 16. This is wallet policy and P0 before the trial.
- **Tree capacity:** the frontier stores the full root at the last append (21-D). It merges before or with 11's capacity rule.
- **Shielded coinbase and asset issuance:** NOT in v3. When added, any new rho derivation must use its own domain and a chain-unique input. Documented now (21-G).
- **Undo compaction (21-F):** done now, since it is small and independent. It is sequenced with 11 in px/src/state.rs and gated by a property test.

## Agent 28 (private-contracts-px)
- **ADR-28-1: PX is the only consensus contract platform.** Accepted by the coordinator under delegated authority, to be recorded as owner decision D22 in the final report. Wasm freeze details are finalized with 29's dossier.
- **F-28-1 v3 part: ACCEPTED as a v3 consensus item.**
  - An `ABI_VERSION` word leads the function prefix.
  - The registry records `abi` and `out_words` for each program.
  - Verifier selection by (epoch, abi) is designed now (W28-9) and implemented with the second kernel generation.
- **Validity window, PX6: ACCEPTED for v3.**
  - Transactions carry `[not_before, not_after]` in the PX prefix, covered by h_tx and copied into each function prefix.
  - The rule is contextual and never scored.
  - Default (0,0) means unbounded, so the window does not fingerprint.
  - The vault gains a timeout and refund path (a known limitation today).
  - Needs the full consensus record, plus red-team review by 50.
- **W28-3 (prove and verify a two-function transaction):** P0 evidence, and it feeds the widest-proof measurement.
- **Vault changes (W28-4):** the lock hash includes the contract id, and blinds are hedged. The vault is rebuilt ONCE together with the kernel (43).
- **Author checklist:** lives in docs/contracts.md, which is rewritten as "Private contracts on PX". The Wasm spec moves to docs/research/.
- **Ownership:** as proposed. 28 owns `call.rs::function_prefix`, the prove statement (with 22), the vault guest and host, and docs/contracts.md.

## Agent 25 (zk-soundness)
- **Headline adopted:** "about 105 bits proven (89.7 statistical + 16 grinding), with a 123-bit hash-collision cap; the Johnson terms are ≥ 154". The figures come from two calculators and are not yet reproduced by a Rust test; W1/W2 make them tested.
- **Quantum claim:** the quantified sentence is withdrawn. The docs state rough estimates (about 53 bits unique-decoding, about 82 bits hash), explicitly labelled as estimates, not proofs.
- **W2:** an independent calculator lives in `zk` as a test module.
- **Random-codeword count (4 vs 8):** agent 26 decides before the freeze. Adopting 8 would be a new parameter set, allowed at the v3 reset if the ZK argument requires it.
- **Budget cap below 2^22:** not needed for soundness. It is left to 20 and 28 (cost and DoS).
- **ConjecturedSecurity:** never used for sizing (W6 test).
- **Ownership:** 25 owns `zk/src/params.rs` in phase 2; 26 reviews the eq. (17) change.

## Agent 03 (difficulty): 03-F1 difficulty-raising attack, HIGH, consensus. DECIDED to fix in v3.
- **Order of work:**
  1. W1: the pure-Rust `tools/daa-sim` harness is P0 FIRST (workspace member allowed; no new dependency).
  2. The harness reproduces F1 against the real `next_difficulty`, which is the demonstration of failure.
  3. W2: a bounded-rise rule `next ≤ parent + max(1, parent·R)`, with R chosen by the harness against 03's acceptance criteria.
     - Criteria: at attacker share ≤ 0.4 and 100 confirmations, the race is within +2% of the honest baseline; honest bias within ±1%; recovery from a 10× jump in ≤ 150 blocks; from 0.5×D0 in ≤ 40 blocks.
     - ASERT is evaluated in the same harness as the alternative. The simpler rule that meets the criteria wins.
- **Fixed parameters:** N stays 60 unless the harness shows the 90 variant is needed. The 99/100 factor is NOT bundled (it is a separate bias question; P3).
- **Deadline:** W2 lands BEFORE 01 freezes the golden vectors. New vectors come from an independent script. The fingerprint gains a difficulty-rule identifier (40).
- **Complementary policy:** 02's park-on-deep-reorg is defence in depth for a public testnet.
  - *Corrected 2026-10-04 (freeze-commit reconciliation):* park-on-deep-reorg does not cover the DAA raising-race residual. It is not implemented, its decided depth (720, public testnet; off for the trial, "Agent 02" W-7) is far beyond a race at 100 confirmations, and the inherited difficulty (RT-4) arises after the attacker's chain is accepted. The residual is accepted under K1 ("RES-FREEZE verified" item 1; record daa-lwma75-warm, correction 2026-10-02).
- **Never-change list:** the "LWMA floor" item is amended. The floor of 1 is kept; the rise rule changes before the freeze.
- **Red-team (50):** attacks the chosen rule, including hop-in/hop-out mining and the start-up window (03-F2).
- **R1-C8 (difficulty lowering):** downgraded to Low (03 and 04 agree independently); confirm with W1.

## Agent 30 (p2p-transport)
- **W1 (pre-Verack cap and handshake deadline) and W2 (decryption failure disconnects without a ban):** P0.
- **W5 (transport version in the KDF; MIN_PROTOCOL_VERSION raised to 2):** MANDATORY before v3.
- **W6 transport v2:** TARGETED for the v3 genesis, since the flag day is free before launch. It covers:
  - uniform key encoding (Elligator Squared);
  - ML-KEM-768 hybrid inside the channel (overrides D18's deferral: privacy priority, protects stem origins from harvest-now-decrypt-later);
  - garbage and terminator;
  - rekeying;
  - session id;
  - no fallback.

  If v2 is not complete and adversarially tested by the freeze, v3 ships v1 plus W5, and v2 activates later through the protocol version. There is no silent partial v2.
- **curve25519-dalek 5.0.0 in p2p only:** CONDITIONAL on 44's review (unsafe/backends, advisories, maturity). The consensus crates stay on =4.1.3.
- **AEAD:** stays AES-GCM (shared `aes` with randomx). Zeroize features on, aes-gcm ≥ 0.10.3.
- **Censorship resistance:** NOT a stated goal for v3. W10 is P3; the docs point censored users to Tor with pluggable transports.

## Agent 31 (p2p-sync)
- **RX-presync plus MIN_CHAIN_WORK (S7):** P1 for a public testnet, P2 for the 7-device trial.
  - Agent 50 reviews the sampling argument BEFORE implementation, and again after the prototype with tests.
  - Bitcoin's redownload release buffer is KEPT unless 50 shows it is unnecessary under sampling.
  - Synergy with the 03 rise cap: a fake chain can no longer inflate its claimed work 10× per block. 31 re-derives the r^32 bound under the chosen rule.
- **MIN_CHAIN_WORK:** a p2p `SyncParams` plus a `--min-chain-work` flag. Policy, not fingerprinted.
- **Staller disconnects:** enforced (disconnect, never ban). Manual peers are exempt. Not observe-only.
- **net.rs split:** done BEFORE the implementation waves, as a mechanical module split with no behaviour change. Owner 46, with a diff-review showing moved code only. Then 30/31/32/33/34 each own their modules.
- **Assume-valid PoW:** stays deferred.
- **S1 (shared `sync_policy.rs`) and S2 (chunk cap):** P0, in wave 1.

## Agent 36 (rpc-security)
- **W1 browser guard, W2 resource controls, W5 `/block` gate:** P0.
- **W3 cookie auth:** P0, BEFORE the trial, including `/info` (only a minimal unauthenticated liveness endpoint, if any).
- **Windows cookie:** it relies on per-user %APPDATA% permissions. There are no unsafe ACL calls; this is a documented limitation.
- **node/src/lib.rs split:** confirmed. 36 owns the router, guard, serve and the `/block` wiring. 09 owns `/template` and `/tip`. 34 owns `with_chain`.
- **Restricted/public RPC mode:** P3.
- **`/tip` long-poll:** its own admission class, with a higher connection cap. Defaults are tuned in W2 with 09.

## Agent 22 (px-proof-system)
- **W2 (exact NUM_RANDOM_CODEWORDS per hidden opening):** INCLUDED in the frozen v3 rule set. It is a consensus tightening that closes proof padding to 4 MiB and a proof-length fingerprint. P-5 is re-run afterwards (26).
- **`security()` fix in params.rs:** owned by 25.
- **Golden PX proof fixture (about 2.2 MB):** acceptable in the repo (one fixture, pinned by digest), generated after the kernel freeze.
- **If the widest proof measures above 3.8 MB:** a deploy-time proof-size bound, preferred over a larger cap (which would change the flat fee and weaken uniformity). Decided after W1.
- **W4 (AIR digest tied to CIRCUIT_ID) and W5 (budgets and table limits in the fingerprint):** P1, done before the freeze.
- **W1 measurement harness:** P0 evidence, run in an exclusive window after the kernel freeze.

## Agent 23 (zkvm-bvm)
- **W2 circuit fingerprint:** a P0 freeze gate. Any AIR change must bump CIRCUIT_ID and the digest in the same commit (it shares the fingerprint work with 22's W4).
- **Sail/LLVM (ACT4 flow):** allowed ONLY offline to generate committed test fixtures, under the same off-tree oracle policy as the RandomX reference. Never in the build or at runtime; provenance is documented.
- **W10 degree reduction:** NOT in the freeze. P3, only with a measured net win.
- **Nightly CI:** about 1 min for the 2^32 decoder sweep plus the fuzz campaign is OK.
- **R4-03:** resolved in the docs only (three documented exceptions).
- **W1 decoder census:** P0.

## Agent 27 (zk-performance)
- **F27-3 (grinding witness leaks the thread count; PX transactions linkable per device):** P0, privacy.
  - W6: deterministic smallest-nonce grinding.
  - Preferred: a wrapper challenger in zk/src/config.rs, if feasible without touching the verifier. A fourth patched crate only if no wrapper is possible (24 decides).
  - Test: demonstrate the leak first, then show identical witnesses across thread counts.
- **F27-2:** SIMD changes the VERIFIER's arithmetic, so there is no "prover-only SIMD".
  - W2 backend differential: P1.
  - W3 cross-build verdict corpus: P1. aarch64 devices are excluded from the trial until W3 is green on arm64.
  - W4: AVX-512 is refused at compile time unless opted in (accepted), and the backend shows in --version and /info.
- **x86-64-v3 wallet binary:** NOT shipped now.
- **Benchmarks (W1):** run by the coordinator in exclusive machine windows (no parallel agent builds), per 45's schedule.

## Agent 37 (wallet-keys)
- **Legacy formats:** the 24-word format and PX derivation V1 are REMOVED at the v3 reset (no launched users).
- **Seed format v1:** 27 words with 2 Reed–Solomon check words, a version, network, birthday (block-height epochs) and feature bits. The master is `H32(tag, version‖network‖features‖entropy)`.
- **Hedge keys:** derived from spend material only (`hk_v1`, `hk_px`). K2 is P0, BEFORE 18's vector pins.
- **CORRECTION of my earlier decision (agent 18 section):** the vault secret is NOT "hedged and seed-recoverable". It is derived deterministically: `H32("px/wallet/vault-secret/v1", hk_px, net, contract, rho_vault)`. It is unique on chain and recoverable on restore (K6).
- **PX account keys:** hardened per-account PX `sk`. This is wallet-side only (the kernel reads sk per input). It is decided before seed v1 is frozen. The wallet-wide nk limitation disappears across accounts; ranges within an account stay documented.
- **Passphrase:** the feature bit is reserved only.
- **Zeroize features (argon2, aes-gcm, bip39):** allowed if 44 approves.
- **K4 address-scoped incoming package:** P1. The docs overclaim is fixed now (F37-2).

## Agent 34 (chain-actor): P0-A
- **Stages 0–1 (liveness tests that fail today, then per-peer slow lane, summary snapshot, RPC PoW off-lock, RPC semaphore):** P0 now.
- **Stage 2 (single-writer actor plus snapshots):** INCLUDED in this phase. The owner named P0-A the top priority, so it is not deferred to a public testnet. It goes after Stages 0–1 and after 02 W-4, 10 items 1/5, and 12 W1/W2 in manager.rs.
- **Crates:** std-only primitives. arc-swap and the im/imbl/rpds crates are rejected, as 34 recommends.
- **Location:** the actor lives in the `chain` crate.
- **PONG_TIMEOUT:** unchanged.
- **net.rs order after 46's mechanical split:** 34 first (liveness), then 31, then 33, then 32. Each gets an exclusive window on its modules.
- **Readers:** RPC state queries may be up to one step late (documented).
- **Test-only actor command:** allowed behind a test feature that is never enabled in release. 43 adds a CI check.
- **Stage 4 (verification outside the writer):** P1 in this phase, after Stage 2.

## Agent 26 (zk-privacy)
- **ZP-7 (pin hidden widths):** merged with 22's W2 into ONE v3 canonical-form rule.
- **ZP-2 P-5 re-run:** on the frozen v3 kernel for n_fn = 0, 1 and 2. Exact assertions are primary; the statistics are a sanity check only. The coordinator owns the freeze signal.
- **zk-coverage §3 re-grading:** only after a second internal reviewer (50 or 25) checks the arguments.
- **Wording:** ADD the qualifier "the masks are PRG outputs (ChaCha), so the guarantee is computational in practice", and KEEP "statistical and conditional" for ideal randomness. This is more conservative and more accurate than before, and it will be reported to the owner.
- **ZP-1 docs and ZP-4/5/6 blinding hardening:** P0/P1.

## Agent 29 (wasm): D22, DECIDED "D-freeze" (coordinator under delegated authority; reported to the owner as a key architectural decision)
- **Freeze in place:** `contracts/` stays where it is, under `exclude` in the root Cargo.toml, with its own Cargo.lock (fuzz/ model). This removes wasmi and 15 other crates from the root lock. A CI check asserts wasmi is absent.
- **Research CI job:** none. `contracts/` is documented as not built by CI (only a manual-dispatch job, if any).
- **Wasm fuzz targets:** re-homed under `contracts/fuzz/`. Deleting would lose research value.
- **Wasm-only crypto (schnorr/membership/claims):** feature-gated off by default (`contracts-research`). This lands after 18's membership nonce fix. Tags stay reserved.
- **Audit-claim corrections (W-1, W-3, W-9):** P0.
- **Future public finalize:** only on BVM-1 (safe Rust), never wasmi; P3, only with evidence of demand.

## Agent 35 (storage)
- **F35-1 (refuse legacy headerless stores on testnet and mainnet):** P0.
- **S2 blocks.dat format v2:** typed records in the log (block, invalid marker, checkpoint), done BEFORE the freeze so v3 stores never migrate.
- **Checkpoints:** tied to the build commit and consensus fingerprint (one full replay after every upgrade). Checkpoint-covered replay KEEPS the contextual checks and skips only the cryptographic checks. `--verify-store` disables all own-store trust.
- **Testnet:** archival-only. redb is deferred to P3 (after 44's review). No database before the trial.
- **PX undo delta (S4):** P1, done in this phase (after D8's state.rs change); it is also 21's 21-F.
- **S5 markers plus --invalidate-block, S6 bodies out of RAM, S7 checkpoints:** P1 in this phase. S7 is red-teamed by 50.

## Agent 32 (eclipse-addrman)
- **N-7/N-8:** mapped into R8-3 (accepted).
- **P0 in this phase:**
  - W0 (quick hardening: penalize unsolicited batches over 10, ignore GetAddr from outbound, IP canonicalization);
  - W2 (NetGroup plus onion v3 checksum; sha3 pending 44);
  - W3 (the new timestamped, length-prefixed Addr format REPLACES message type 5 before launch; 30 agrees through the decisions log; the wire change lands before the freeze);
  - W8 (eclipse simulator baseline first);
  - W10 (docs).
- **W1 addrman v2 and W6 (/64 key, inbound eviction):** implemented in this phase (P0 before a public testnet). The trial topology is operator `--peer` meshes, so they are not trial blockers.
- **W4–W7 anchors, feelers, stale-tip rotation, seeds as one-shot fetch:** P1 in this phase.
- **Tuning:** the tried-bias and feeler rate are set from simulator results.
- **Tor-only nodes:** stay onion-only by default (no clearnet-over-Tor outbound mix). Revisit after SOCKS stream isolation (R8-6), as an owner privacy decision.
- **asmap:** P3.

## Agent 33 (dandelion-network-privacy)
- **F33-1 re-origination leak:** a forgotten local transaction is HELD silently before the expiry horizon (no re-origination). W2 (originated set plus persistence) is P0 for the trial (privacy first).
- **W7 (verification off the read loop):** owned by 34 (Stage 1a/4). 33 owns the gating timing-oracle test.
- **Trial P0:** W1 (privacy regression suite, including the timing oracle), W2, W10 (docs with quantified anonymity statements and the PX origin visible to the ISP).
- **P1 in this phase:** W3, W4, W5, W6. W6 is P0 for a public testnet with Tor.
- **W4 PX embargo:** the value is taken from labnet-measured PX stem latency (09/45 add it to the evidence runs).
- **W9:** a statistical `#[ignore]` test is allowed.
- **W8 private broadcast:** P2, after 32's addrman work.
- **Invariant for 10:** VerifiedCache must never be filled by stem-phase check_tx.

## Agent 40 (testnet-genesis)
- **T_g:** two-stage announcement (stage 1 at least 48 h ahead fixes everything except T_g; stage 2 at H−12). Deterministic fallback at H' = H+36.
- **Nonce:** derived IN CONSENSUS from the committed beacon (`consensus/src/genesis.rs`: GenesisSpec/Beacon). Finality is `genesis_is_final()`. No pasted nonce and no runtime override.
- **Trial:** closed to outsider inbound (`connect_only`, no inbound) during the reveal/start window and the trial.
- **Network ids:** final 0x0001D673; rehearsal ids reserved at 0x0001D6E0–EF; the KAT uses a reserved test-only id.
- **Aborted launch:** if H is reorged after a speculative start, the id is RETIRED and the launch restarts fresh.
- **Second independent computer at the reveal:** must be an operator's machine, not the owner's (an owner/operations task, listed in the final report).
- **Rules fingerprint:** also shown in /info (36 implements).
- **node/src/fingerprint.rs:** 40 lands ALL entries in ONE commit after every rule decision is in (13, 14, 16, 19, 22, 03 send entry specs). The digest is split into rules and identity, and `--print-manifest` is added.
- **Supply-audit PX test (F40-9):** P0.

## Agent 38 (wallet-privacy)
- **Exact v1 fee (W8), DECIDED for the v3 genesis:** `fee == FEE_PER_WEIGHT × max_weight(n_in, n_out)`, routed through `TxRules` so tiers can activate later. Needs the full consensus record: a demonstration test, golden max_weight vectors, and a property test that max_weight ≥ weight. Owner 11 (validate), 38 (wallet test).
- **Expiry:** 2160 blocks from admission height, uniform for ALL classes (deploys too).
  - The recently-expired guard (R = 30) ships in the SAME change (12).
  - Pool re-announcement with backoff (33/30).
  - Wallet rebroadcast redesign (W4).
- **Mempool persistence (35/12):** raised to P1 in this phase (F33-1 + F38-3).
- **`/tx/status` RPC (36):** accepted. The wallet no longer re-posts transactions as its check.
- **Spend delay:** default OFF on the testnet, with a young-spend warning ON (P1). Opt-in `--spend-delay` is P2. The mainnet default is an owner decision.
- **Docs correction (W9, P0):** guess-newest is about 84–89% on a mature chain for spends 12 blocks after receipt. The 52% figure holds only for a young chain.
- **W1 (distribution from the local index; drop the spend-time /distribution):** P1. P0 before a public testnet.
- **W5 SOCKS5 (socks5h forced, random credentials, fresh client per submit):** P1.

## Agent 39 (wallet-sync)
- **W1 (the wallet builds the PX tree from verified blocks and checks anchors against its own root window; fixes F39-1):** P1 in this phase. Not a blocker for the own-node trial; P0 before a public testnet.
- **Compact feed encoding:** the project codec served as application/octet-stream. `/blocks` (hex) stays for tools and older wallets.
- **W5 header PoW check:** ON by default for restores (sampled light-mode checks plus LWMA recompute), opt-in for routine sync. BOUNDS F39-10 (corrected 2026-09-28 after RT-W3: W3-39b adds the genesis-anchored feed and a dense check of the last 720 headers).
- **PX-root header commitment:** NOT in v3 (P3).
- **proptest in wallet tests:** allowed.
- **Ownership:** as listed by 39. wallet.rs edits are serialized with 37, 38, 17 and 18 in the order 37 → 17 → 18 → 38 → 39.
- **Incremental witness:** in-tree (about 300 lines). bridgetree is NOT adopted as a dependency.

## Agent 24 (plonky3-verifier)
- **F24-1 random codewords:** ADOPT 8 (= extension degree) at the v3 reset.
  - Reason: privacy first, conservative, matches upstream 0.8. The cost is about +10–13% size, time and memory.
  - The parameter set gets a new `PARAMS_ID`, P-5 is re-run, and the size is benchmarked.
  - Reversal would need 26's 4-codeword argument to pass 50's review BEFORE the freeze. Default is 8.
- **I2 canonical-form rules:** one root per Merkle cap, plus the exact hidden-opening count. Both are in the v3 rule set. 22 edits `check_canonical_form`; 24 supplies the rules and tests. This merges with 22's W2 / 26's ZP-7.
- **COLLISION_BITS:** changes to 122 now, citing ePrint 2026/089 (the fingerprint changes anyway before the freeze). The docs say "hash-bound, ≈122 bits".
- **Upstream contact:** the upstream livelock issue is NOT filed, and nobody contacts Plonky3 publicly. This follows the owner's earlier "do not submit the Plonky3 report" rule. Listed as an owner decision.
- **Proof-system changes:** ride a reset until launch. After launch, a second verifier arrives through the schedule's verifier id (two linked verifiers).
- **I3 advisory suite and I6 third_party checksums plus CI:** P1.

## Agent 41 (fuzzing)
- **Corpus storage:** minimized regressions are committed under `fuzz/regressions/`. Full corpora stay local for now. Creating a corpus repo or release assets on GitHub is an OWNER task (outward-facing), listed in the report.
- **`cfg(fuzzing)` exports:** allowed in consensus crates; they never affect release builds (CI check by 43).
- **Verifier grinding under `cfg(fuzzing)`:** may be disabled ONLY in fuzz builds. It is documented, and the evidence text says verifier fuzzing shows robustness, not soundness (F41-8).
- **`tools/testkit`:** approved as a workspace member. The coordinator edits the root members list at merge time.
- **E1 campaign (-O -a):** runs in Wave 4, after the consensus bundle, in an exclusive window. The Wasm targets move to `contracts/fuzz` (per 29) and are out of the main campaigns.
- **`proptest-state-machine`:** NOT adopted. Plain proptest 1.11 with default-features off, features = ["std"], plus an in-house runner.
- **Simnet check of 02's F-1 fix:** P1.
- **F41-1 (PX seed with a short proof blob) and F41-2 (sharpen the kernel oracle):** P0 before E1.

## Agent 43 (ci-reproducibility)
- **W1:** DONE by the coordinator. rebuild/core (9e422d8) was pushed; CI run #84 includes the Linux guests leg for the neutral kernel ids. The remote v3/candidate is deleted only after #84 and the local full suite are green.
- **Default branch:** switching it to rebuild/core is an OWNER action (repository setting). Until then, scheduled jobs don't run. Workaround: weekly jobs are also runnable via workflow_dispatch, and the coordinator triggers them manually (they need auth; listed as an owner task).
- **ci.yml triggers:** `tags: ['testnet-*']`, a concurrency group, Node 24 checkout, and CI on pushes to ALL branches (so candidate-style branches can never skip the Linux legs).
- **Signing:** SSH-signed annotated tags; an ed25519-sk (FIDO2) key preferred. The key and second publication channel are OWNER decisions. gitsign is rejected (it would publish the e-mail).
- **Trial operators:** build from the signed tag (reproducibility). No Windows release binaries for the trial.
- **Workflow files:** 43 authors all of them. 08, 05, 41 and 42 supply job content.
- **W4 single kernel/vault rebuild:** gated on all guest-affecting merges (20 F-20-1, 28 ABI/PX6/vault, 19 comments), plus W5 script hardening first. It is reproduced on Windows, Linux x86_64, Linux arm64 (CI) and one operator.
- **CI-7:** documented as an accepted limitation (the toolchain strings bind the kernel id).

## Agent 45 (benchmarks)
- **MACHINE FACT:** i7-6700 with 4 cores / 8 threads, 16 GB RAM. At most 3 building agents run concurrently from now on (revises waves.md rule 1).
- **Harness:** `tools/benchkit` and `tools/bench` are approved (runner may use clap and serde_json, already locked). criterion is rejected (alloca compiles C).
- **X0 baseline window:** after labnet seedrun2 finishes (planned 450 min; it passes 2400 first). Exclusive: no cargo/labnet/fuzz.
- **Power plan:** the runner may switch to High performance during exclusive windows and MUST restore the previous plan afterwards (it records the original).
- **Hardware counters:** no bare-metal Linux device is available (Windows only). Linux counters are an owner task and optional.
- **Claim rule:** accepted (95% CI outside the same-window noise floor of at least 2%; never below 3% on a single build).
- **Anchors:** imported into docs/evidence with provenance.
- **Toolchain pin:** NO root rust-toolchain.toml (it broke GNU-host machines, per SX2). The pin stays in CI/Docker/guests. A `profiling` cargo profile is allowed.
- **Peak memory:** measured from process peaks (VmHWM / PeakWorkingSet64). No counting GlobalAlloc (it would need unsafe).

## Agent 49 (innovation)
- **Invariants frozen now:**
  - (1) proof bytes live only in the prunable part of the tx hash;
  - (2) a compact feed carries the exact prefix and base bytes;
  - (3) PQ precondition 5: the mask `y = Hs("mask", S)` never changes (17 adds the vector);
  - (4) F49-5: any future verifiable state tree hashes leaves under a leaf domain the verifier recomputes.
- **PQ seed recovery:** the plan states it PUBLISHES the wallet's v1 keys. Voluntary early migration to PX is the recommended private path. The ZK variant, the turnstile race rule (first-come vs a claims window) and the Q-day policy are OWNER decisions (P3), recorded in docs/research/pq-migration.md.
- **Recursion route:** decided only after the off-tree spike (P3). No commitment now.
- **State commitment placement:** a v2 tx_root is preferred over a coinbase field (46 records it in its ADR; P3 consensus).
- **"Assume-valid proofs":** acceptable as a FUTURE policy (signed release hash; never skips double-spend rules). P3.
- **Docs:** W6 (Neptune Cash incidents in zk.md §17) is P0 via 47.

## Agent 42 (mutation/formal)
- **Freeze gate (P0):** ZERO unexplained missed mutants in `consensus` and `px-core`. Every survivor is killed or justified in writing.
- **Where runs happen:** A′ now (calibration). A and B run locally in exclusive windows. C (the tx rules) runs on GitHub Linux shards if a push-triggered workflow can do it; otherwise locally in overnight chunks.
- **F42-2 (equal-timestamp LWMA vector) and F42-3 (exact block-rule boundary vectors):** P0, owned by 01/03 and 10/11.
- **Kani:** harnesses only, in the separate `tools/formal/`, run weekly on Linux CI. Results are always described as "bounded model checking under stated abstractions". A local WSL distribution is an OWNER option.
- **Tooling:** `[profile.mutants]` in the root Cargo.toml is accepted. cargo-mutants and Kani/CBMC are recorded as outside-the-repo test tools (44).
- **Ordering:** the golden PX proof is scheduled BEFORE W4 (run C).

## Agent 47 (docs)
- **docs/STATUS.md:** APPROVED as the single status source. Other status blocks become links. AUDIT.md is retitled, not renamed.
- **tools/doc-lint:** APPROVED (pure Rust, workspace tool) as a BLOCKING CI step (43), landing before the wave-2 merges.
- **Stage-2 file moves:** wait until after the freeze.
- **Fingerprint values in testnet.md:** REMOVED. Operators compare against `blacksilk-node --print-manifest` and the signed release announcement. A pin test prevents any copied value from drifting.
- **v2 validation doc:** REPLACED by a v3 version owned by 40. The v2 doc moves to history at stage 2.
- **Proof-system spec (docs/proof-system.md):** P0, since several proof-format rules ride the reset (codewords, canonical form, FRI schedule, CIRCUIT_ID).
- **Coordination:** the same-commit rule (code plus spec plus rule row plus vector) is BINDING for every implementation agent. It is added to impl-brief.

## Agent 46 (architecture)
- **Move-only splits before wave 1:** net.rs (46's plan), `chain/src/manager.rs` and `wallet/src/wallet.rs`. validate.rs stays one file with ownership by function.
- **Commits:** S1 move-only, then S2 extract-only (approved as a SEPARATE commit), then S3 docs and .git-blame-ignore-revs.
- **Reviewer:** the COORDINATOR, mechanically (sorted line-multiset equality, the dimmed-zebra moved diff, same test counts, dependents compile unchanged). cargo-semver-checks is allowed as a dev tool if installable; otherwise the dependents-compile check suffices.
- **Node-local state digest:** P1 before the trial (35 S7).
- **Stage C (wallet crates out of tx/px, infallible commit, verifier dispatch):** after the trial, before a public testnet.
- **Overlap resolutions §5.3 D:** all accepted as written (07 owns next-seed, 14 owns R12-2, 35 owns tombstones, 35 writes the PX undo delta, 23 owns blinding type-state, 35's file is `state_snapshot.rs`, 36 merges /info fields, 40 does a single re-pin).
- **CachedPow recovery at manager.rs:76/83:** the last poison-recovery path; converted to fail-stop in wave 2 (34).

## Agent 48 (threat model)
- **F48-3 (the agent pipeline as an attack surface):** P0 BEFORE the wave-1 merges.
  - The untrusted-input rule is added to impl-brief.
  - 43 implements the CI gates:
    - a consensus-path gate: commits touching consensus/, tx/src/validate.rs, px-core/, zk/, zkvm/src/air, px/*.elf|*.id or fingerprint files need a "Consensus-Change:" trailer that references v3-consensus-changes.md;
    - an invisible/bidi Unicode scan;
    - a lockfile-diff gate: any Cargo.lock change must list the added crates in the commit message;
  - The coordinator reviews every diff line by line.
  - OWNER tasks: CODEOWNERS plus branch protection, and signed commits/tags.
- **F48-1 closed-network PSK:** ACCEPTED, P0 for the trial. An optional `--network-psk-file` is mixed into the transport KDF; policy only, not used on public networks. Decryption failure disconnects without a ban (30's W2). Owner 30.
- **F48-2 supply-audit custody:**
  - trial-only seeds;
  - mid-trial audits run per-operator and locally;
  - the central run happens only at the END, under an agreed custody procedure;
  - a view-only audit is P2.
- **F48-4 tag-signing key:** should live on a machine that never builds third-party crates (hardware key preferred). OWNER task.
- **F48-5:** ACCEPTED as node policy. Store a "validating <id>" quarantine marker, halt naming the suspect block, NEVER auto-invalidate, and provide `--invalidate-block` (35 S5, with 34/10). Apply becomes infallible (46 stage C; AT-4 property test now).
- **AT-5 (PX proof cache vs height-dependent validity):** P0 with the v3 items (10's VerifiedCache is keyed on the verifier, registry and window).
- **F48-7, F48-8, F48-9:** P1 (operator checklist, seed confirmation, log rate limiting, overrides shown in /info).

## Agent 50 (red team): verdicts ADOPTED as binding changes
- **RT-1:** UnknownUpgrade is returned only for PoW-valid headers. Disconnect without a ban after N; warn the operator only past a peer or work threshold. P0 (cheap).
- **RT-2:** the PX proof-cache gating tests (predicate unit test plus a manager-level PX test with a PX5 call counter). P0, and part of AT-5.
- **RT-3:** verifier_id is carried in TxRules with a startup assertion (P1). RT-4: `revalidate_between` is deleted or gets a reorg flag (P1). RT-5: after an activation, a rebuild respends the SAME key images, or inputs stay reserved until A+60 (P1). RT-6/RT-7 doc corrections: P0.
- **R2-C6 wording:**
  - cite Theorem 3 ONLY; 122.6 bits is OUR evaluation;
  - the adaptation (start state, zero empty leaves, zero-filled partial blocks) is "argued, not proven";
  - claim "extractable", not "binding", until position-binding is confirmed;
  - add invariants: no all-zero start state, and the record start state is never a tree value;
  - COLLISION_BITS = 122.
- **C4-B:** the wallet dedupe keeps the LARGEST amount, then the lowest index (RT-10). Test a copy mined BEFORE the genuine output. Never filter duplicates from decoys.
- **Difficulty cap:**
  - add hopper and emission acceptance criteria;
  - specify exact integer rounding (+1 per block at low difficulty);
  - re-derive the genesis-gap test;
  - hand the bound to 31.
- **F-20-1:** accepted, with the listed tests (double/triple approvals, crossed approvals allowed, error precedence, exit-code table).
- **PX6/ABI:**
  - the mempool refuses premature transactions;
  - `revalidate_after_extension` takes the height;
  - templates filter by the window;
  - the proof cache never skips PX6;
  - deploys reject an unsupported ABI;
  - the ABI and out_words are inside the contract-id payload hash.
- **Tree capacity:**
  - 21-D lands with or before the rule;
  - count leaves per output (not a literal 2);
  - templates enforce it;
  - an apply failure after validation stops the node, and must NOT mark the block invalid.
- **R12-2 (a′):** `Mempool::select` charges PX and deploys against BOTH budgets, in the SAME commit.
- **Random codewords (8):** the preprocessed-round exception is derived from the proof structure, not hard-coded. Mutation tests at every position. It is a new parameter set (PARAMS_ID, fingerprint, P-5).
- **RX-presync:**
  - RT-8: a fresh node presyncs EVERY peer's chain and redownloads only the most-claimed-work one; MIN_CHAIN_WORK > 0 in later releases.
  - RT-9: the redownload buffer is KEPT (or a keyed per-header commitment is checked before PoW).
- **RT-14: ADOPTED for v3.** The signature domain (v1 signature message and PX h_tx) binds the GENESIS ID next to network_id and branch_id. Free at the reset; it completes P0-D's "transaction domains bound to genesis". Owner CB-B1.
- **RT-15:** the wallet genesis check is a misconfiguration guard only. Documented; W5 header verification strengthens it.

## CI-1 CONFIRMED (coordinator, CI runs 84/85): the neutral kernel does NOT reproduce on Linux
- **Evidence:** ubuntu rebuilds of kernel/vault differ from px/*.elf in 297 bytes. The loaded sections (.eh_frame/.text) have identical offsets and sizes. The committed `.comment` is 153 B; the Linux build's is 14 B shorter, which shifts `e_shoff` in the ELF header. The first PT_LOAD starts at file offset 0 and so covers the header, which means the id depends on toolchain identification strings. Windows CI reproduces.
- **DECISION (P0, owner 43, BEFORE the single v3 rebuild):**
  - make the program id independent of non-loaded bytes;
  - preferred approach: the guest link layout keeps the ELF/program headers out of every PT_LOAD (the headers are not loaded), so the id covers only loaded code and data;
  - alternative: strip `.comment` and other non-alloc sections with the toolchain's own tools (no new C deps).
- **Acceptance:** identical ids on windows-latest, ubuntu-latest and ubuntu-24.04-arm in CI, plus one operator build. Diagnostics are already in CI annotations. If the id definition in zkvm changes, that is a consensus change: record it in v3-consensus-changes.md.

## Agent 44 (supply chain): all verdicts ADOPTED
- **S1 cargo-deny gate:** P0, BEFORE the wave-1 merges add dependencies.
- **Dependency verdicts:**
  - proptest `=1.11.0` (std only): approved.
  - rustc_apfloat `=0.2.3`: approved (dev, randomx).
  - sha3 `=0.11.0`: approved (out of workspace).
  - monero-oxide: REJECTED; port the small map instead.
  - dalek 5.0.0 + lizard: only in the commit that lands transport v2, with cargo-deny confining it to p2p.
  - ml-kem in p2p: approved, with hazmat blocked.
  - aes 0.9: DEFERRED (P3).
  - getrandom: target 0.4.3 (P2).
  - aes-gcm: `=0.10.3` with zeroize, plus aes/zeroize and polyval/zeroize (p2p and wallet).
  - blake2: no change before the freeze.
- **Contracts:** moved out of the workspace NOW (29's W29-2, confirmed).
- **cargo-vet criterion name:** `blacksilk-internal-review`, explicitly non-audit (P2).
- **Project LICENSE:** an OWNER decision. Third-party notices are prepared regardless (P1) for the BSD-3 and MPL-2.0 obligations.

## DAA update (after the W0-03 harness)
- **Harness result:** the first run found no candidate meeting all criteria.
  - A 2% rise cap cuts race excess to +4.2%, but its asymmetry lets a 100% miner gain +3.82% emission.
  - ASERT is too slow for a small testnet.
- **Revised acceptance criteria:**
  - race ≤ +5% at q = 0.4 and ≤ +1% at q ≤ 0.35;
  - emission gain ≤ +1%;
  - hopper within ±3 points of the fair share;
  - bias within ±1.5%;
  - 10× up and down both followed in ≤ 150 blocks;
  - from 0.5×D0 in ≤ 60 blocks;
  - genesis-gap recovery ≤ 120 blocks;
  - exact integer arithmetic.
- **Rule choice:** the rule is chosen from W0-03b's selection study (symmetric solvetime clamp, rise+fall caps, weighted-sum caps, ASERT 1 h, hybrids, adaptive attackers). CB-A implements only after that and red-team review.

## Open liveness item (labnet seedrun2, binaries 83fceee)
- **What happened:** one "stuck" incident. node1 stayed one block behind for more than 90 s while connected.
- **Why it is still open:** info-level logs cannot explain it.
- **Plan:**
  - Wave 4 evidence runs use debug logging for p2p::net blocks/headers, plus 09's labnet instrumentation.
  - 31 (download scheduling, F31-2 stall detection) and 02 (F-1) own the hypotheses.
  - The item must be closed or reproduced before the trial.

## Git task COMPLETE (v3/candidate eliminated)
- **Contained:** origin/v3/candidate is an ancestor of rebuild/core (merge 9e422d8). Checked with merge-base --is-ancestor.
- **Tests:**
  - local full suite on 9e422d8: 738 non-PX passed, 0 failed, 2 ignored; 11 PX-proving tests passed (single-threaded);
  - CI run 87: all jobs green except guests(ubuntu), the pre-existing CI-1 kernel-id issue that came with the candidate content.
- **Deleted:**
  - local v3/candidate, v3a/b/c-candidate and all agent worktrees and branches (after patch-equivalence checks);
  - REMOTE origin/v3/candidate.
- **Remaining refs:** main and rebuild/core, plus temporary agent branches that are removed after their merges.

## CI-1 fix DECIDED (W0-gates investigation)
- **Mechanism:** the guest linker script starts SECTIONS at 0x10000, so the first PT_LOAD sits at file offset 0x1000 and the headers are not loaded. A `/DISCARD/ : { *(.comment) }` rule removes both rustc and LLD identification strings.
- **Tested locally (kernel/vault):**
  - the id is independent of `.comment` rewrites;
  - native = guest tests pass;
  - Program::from_elf accepts the result.
- **Consequences:**
  - The zkvm id definition is UNCHANGED.
  - Ids change once, at the single v3 rebuild (43).
  - New tests: no PT_LOAD at offset 0, and no .comment section.
- **Acceptance:** byte-identical ELFs on windows, ubuntu and ubuntu-arm in CI at the rebuild commit.

## Gates live
- Consensus-path trailer, lockfile diff and unicode scan (cut-over 55f110e); cargo-deny for the main and fuzz workspaces; publish = false on every member.
- From now on, EVERY commit touching a consensus path needs a `Consensus-Change:` trailer. Every implementation agent prompt must say so.

## DAA DECIDED: LWMA-75 with counted-clock step T/2 (W0-03b selection)
- **Rule:** `this = max(ts, prev + max(1, T/2))` (was prev + 1), with N = 75 on all networks (was 60).
  - It is the only candidate of 29 that meets all 8 criteria on 2 seeds.
  - Race q=0.4 z=100: +3.8% (was +33.6%). Emission gain +0.69% (unchanged). Hopper +2.4 points. Bias +1.0%. 10× up/down in 113/130 blocks. The genesis-fork rewrite goes to 0.
  - The rise is bounded at 2× the window average; no overflow.
- **Approvals:** the coordinator approves N = 75 (delegated authority). The cost is a slower 10×-drop recovery (9.6 h vs 7.7 h), accepted.
- **Before CB-A implements it:** red team (50-style agent) attacks the rule (window boundaries, hopper margin, step interaction with MTP/FTL, adversarial histories).
- **CB-A then:**
  - implements it with new golden vectors from an independent script;
  - re-derives the genesis-gap and 1-second-block tests;
  - adds a fingerprint difficulty-rule identifier.
- **Residual:** about 4% at q=0.4 is left to the park-on-deep-reorg policy (02).
  - *Corrected 2026-10-04 (freeze-commit reconciliation):* a misattribution. Park-on-deep-reorg cannot act on a race measured at 100 confirmations (decided depth 720, off for the trial, not implemented) and does not touch the inherited difficulty of RT-4. The residual (+3.5 % at q = 0.4 after the warm-up, "DAA FINAL") is accepted under K1 for the testnet and reopened before mainnet ("RES-FREEZE verified" item 1; record daa-lwma75-warm, correction 2026-10-02).

## DAA FINAL (after RT-DAA)
- **Rule:**
  - LWMA, N = 75;
  - counted-clock step max(1, T/2);
  - counted clock WARMED over the 11 blocks before the window: `from = w0.saturating_sub(11); prev = ts[from]; for j in from+1..=w0 { prev = max(ts[j], prev + step) }`;
  - callers supply 87 ancestors;
  - fingerprint id `lwma1-n75-step-t/2-warm11-cap6t-floor20`;
  - golden vector from redteam.md (998,248 → 999,824 case) plus independent-script vectors.
- **Measured:**
  - race q=0.4: +3.5%;
  - emission: worst +0.66% (search), static +0.25%;
  - bias: +1.03%;
  - 10× up/down: 113/130 blocks;
  - genesis rewrite: 0.
- **Hopper criterion RELAXED to ±5 points for the TESTNET** (option a): a 100× hopper with FTL stamps measures +4.2. Documented, and must be reopened before any mainnet.
- **Also documented:** slow settling after 100×/1000× hash-rate increases (224/334 blocks); an arithmetic range invariant T < 2^51 (03-F6 ChainParams::check).
- **Implementation:** CB-A may now implement it.

## Fingerprint pins during the pre-freeze v3 window (Lead decision, 2026-09-27)
- **Policy:** each reviewed consensus merge re-pins `px/tests/consensus_fingerprint.rs` and `node/tests/deploy_configs.rs`, with a Consensus-Change trailer citing its record. The new network id and the final values come with fingerprint v3 (40).
- **Tooling constraint:** the Claude auto-mode classifier blocks the coordinator from editing these pinned values, both as a security-test change and as a bypass. The OWNER applies the re-pin, or adds a permission rule.
- **Until then:** the two tests are red, known and documented. Every other test must stay green.

## RPC (after W2-36), Lead decisions 2026-09-27
- **Dependencies:** hyper 1.11.1, hyper-util 0.1.20 and subtle 2.6.1 are APPROVED as direct dependencies of blacksilk-node. They were already in the lockfile at the same versions (transitive via axum/crypto), so no new crate enters.
- **/tx/status spec:** `GET /tx/status?id=<hex>` returns `{"status":"pooled"}`, `{"status":"confirmed","height":h}` or `{"status":"unknown"}`. It is cookie-authenticated.
  - NEVER report stem state: a stem transaction answers `unknown` (F36-11).
  - `expired` is added only with 12's recently-expired set.
- **Wiring:** the binary switches to `serve::run` (cookie auth plus connection limits), with `--rpc-allow-host`, in the miner, labnet, check-node.sh and testnet docs, as ONE follow-up owner (W2-36b). This is a launch blocker until done.

## Labnet deep reorgs (INV-REORG), Lead decisions 2026-09-27
- **Root cause:** regtest D0 = 1 combined with the v3 DAA's bounded rise. D stays at 1 for 76 blocks after the genesis gap, and equal-work lockstep mining gives deep equal-height splits. No sync, lock, RPC gate or template bug. The seedrun "stuck node" was a labnet detector false positive, now fixed (StuckDetector).
- **Regtest D0:** UNCHANGED. Regtest serves deterministic tests; D = 1 is intended there.
- **Labnet:** a warm-up phase (single miner until D is near equilibrium), with warm-up reorgs reported separately. Reorg metrics count only after warm-up. Owner 09. Runs shorter than about 10 minutes are not evidence.
- **Testnet D0: GENESIS GATE (F40-12 raised to P0).** D0 must be measured on reference hardware against the expected launch hash rate before the beacon is committed. Under v3 a 100× under-estimate takes about 197 blocks to ramp (pre-v3: 81). Document the ramp in docs/testnet.md.

## RT-W1b (CB-B1b red team), Lead decisions 2026-09-27
- **Verdicts:** T8 ACCEPT; expiry/guard ACCEPT WITH CHANGES; R12-2 ACCEPT; tree capacity ACCEPT.
- **RTW1B-1:** the recently-expired guard applies ONLY on the local origination path (`/tx` and wallet submit). Peer relay and stem admit normally, so no Dandelion black hole forms. Fix the docs/blocks.md claim.
- **RTW1B-2:** 33 W2 (originated set: never re-originate a forgotten local transaction) and 38 W4 (wallet rebroadcast redesign) are raised to the FRONT of Wave 2. No privacy claims about labnet or testnet until both land.
- **RTW1B-3:** templates rank deploys by the v1-part rate (`standard_fee / weight`); program-byte fees do not buy priority. Fix the docs sentence.
- **RTW1B-4:** a halt gets its own exit code, with `RestartPreventExitStatus` in the systemd unit.
- **RTW1B-5, 7, 8, 9:** fix (readmit keeps the guard entry on Err; halt log string; cfg-gate `with_px_state`; `max_weight` as a const fn with a const assert).
- **RTW1B-6:** a fee-grace window is required before any fee-changing epoch (none in v3). Logged for the schedule.
- **Owner:** FX-RTW1B, after FX-RTW1-TW frees the mempool and p2p admission files.

## W2-32 (addrman), Lead decisions 2026-09-27
- **sha3 0.11.0** (RustCrypto, pure Rust, default features off) is APPROVED as a direct dependency of blacksilk-p2p for the Tor v3 checksum. It was already in the lockfile via ml-kem. This supersedes the "out of workspace" note for this use; 44 reviews it in its supply-chain pass.
- **P2P PROTOCOL_VERSION = MIN_PROTOCOL_VERSION = 3:** accepted. The v3 reset has no v2 peers, and a clean handshake refusal is better than ban loops. 30 builds on MIN = 3.
- **Still open (Wave 3):** addrman v2 (W1); anchors, feelers and stale-tip rotation (W4, W5, W7); inbound /64 limits and eviction (W6). The simulator baseline stays as the regression metric.

## W2-37 (wallet keys), Lead decisions 2026-09-28
- **Out-of-ownership commit 7a6fe53:** ACCEPTED (crypto keys.rs/hash.rs, px wallet.rs; dossier 37 owns these functions; no consensus path).
- **PX account 0 is a hardened child of the root** (`sk_a = Hk(SK_ACCOUNT, root‖a)`): ACCEPTED. The root never enters a witness.
- **Registry tags frozen for v3:** `seed/master/v1`, `wallet/hedge-key/v1`, `px/wallet/hedge-key/v1`, `px/wallet/vault-secret/v1`.
- **Wallet never auto-applies seed corrections** (a two-word error can land on another valid seed, about 1.3%): ACCEPTED as designed.
- **Open:** removing px `Derivation::V1` (px owner, with CB-B2); a fuzz target for the seed parser (41); F37-11 confirmation prompt; K7 and K8.

## W2-09 (miner and labnet), Lead decisions 2026-09-28
- **Miner prebuild default:** `--prebuild auto` (the "Agent 09 REVISED" line wins). Prebuild in full mode whenever the fallible allocation succeeds; the light-mode bridge otherwise. Supersedes "off by default" for the miner. Labnet evidence runs force it on.
- **Miner exit 78** (configuration) with `RestartPreventExitStatus=78`: accepted.
- **W2-09b (after CB-B2 releases template.rs):**
  - the template readiness gate as designed by W2-09 (`template_ready`, slack 2, 503, no zero-peers rule);
  - tip notification I1 (stale work measured at about 21% of found blocks);
  - `next_seed_id` on `/template` (drops the `/blocks` lookup);
  - the first dataset build uses all threads when no context exists.
- **Evidence:** labnet-warmup-2026-09-28 run 2. After warm-up, depths are 1 to 2 outside the heal, and 13 twice at the heal after a 3-minute partition. Difficulty had not reached equilibrium (9 to 12 against about 20); longer runs are needed for Wave 4.

## RT-W1c (CB-B2 red team), Lead decisions 2026-09-28
- **Verdicts:** approval-conflict ACCEPT; px-call-abi ACCEPT; PX6 ACCEPT WITH CHANGES; vault-v3 ACCEPT WITH CHANGES; guest rebuild ACCEPT (layout and Windows reproducibility), with the budget claim to be corrected.
- **RTW1C-1 (Medium, liveness, pre-existing):** kernel budgets raised so every honest shape uses at most 95% of every table, verified by an exhaustive or property test over all shapes. This must land BEFORE the freeze.
- **RTW1C-2 and RTW1C-3:** vault windows must not reveal T (rounded windows, T rounded to 16), and the refund must be recoverable from seed.
- **RTW1C-4:** expiring-soon policy, margin 3 (Zcash). **RTW1C-5:** PX6 is checked before the range proof.
- **RTW1C-6:** the vault is NOT an HTLC; the docs must say so.
- **RTW1C-7:** new frozen tag `px/wallet/vault-refund/v1` (added to the W2-37 list).
- **RTW1C-8:** out_words dry-run in the author checklist and wallet policy.
- **Owner:** FX-RTW1C.

## CI-1 CLOSED (2026-09-28)
- **Result:** CI run 102 (5da354b): guests jobs green on windows-latest, ubuntu-24.04 and ubuntu-24.04-arm. The v3 kernel ef75a535… and vault 3fdec803… ELFs rebuild byte-identically on all three hosts.
- **Fix:** the guest.ld layout (CB-B2), plus the build.sh SIGPIPE fix (5da354b). The SIGPIPE bug dated from 097114a, so earlier Linux guests failures were partly that bug.
- **Still owed:** one operator build at the reveal (decisions 43 W4).

## FX-RTW1C, Lead decisions 2026-09-28
- **Accepted:** kernel budgets n_fn=1 bit 1850 / lt 18050 and n_fn=2 bit 2000 / lt 20550, verified exhaustively (1,766 shapes, at most 94.3%). The budgets are in the fingerprint manifest (`px.kernel.BUDGET.n_fn_*`). `prove` refuses an over-budget execution before proving.
- **Frozen registry tags (added to the W2-37 list):** `px/wallet/vault-refund/v1`, `px/wallet/vault-rcm/v1`.
- **Vault recovery design:** the seed-derived rcm for timed locks, plus the claim lock in the private change `data`. ACCEPTED.
- **Owed:** the p2p cheap-phase expiring-soon refusal (assigned to W2-34b); wallet CLI commands for timed locks, stored refunds and recovery (wallet owner, next wallet batch).

## W2-02/21, Lead decisions 2026-09-28
- **ANCHOR_MIN_DEPTH = 3 (rounded down to 16) in `wallet/src/px.rs::anchor_height`:** accepted. Every wallet switches together before the trial.
- **W2-02-F1 (restart pool not empty after a replay reorg): fix the CODE.** The manager empties the pool at the end of `open()`, matching blocks.md §7. Owner: the coordinator, after W2-34b (chain actor) merges; then un-ignore the reproducer and revert the docs exception.
- **proptest =1.11.0 as a dev-dependency (chain):** accepted. deny.toml skips for rand/rand_chacha/rand_core 0.9 are added only if they are dev-only. The bitflags 2.9.1 → 2.13.2 bump is accepted (semver-minor, reaches tower-http).

## RT-W2a (chain actor, slow lane, pool readmission), Lead decisions 2026-09-28
- **Verdicts:** all three ACCEPT WITH CHANGES. Soundness of unverified readmission holds (no unverified path into the pool; ring digest collision-only).
- **RTW2A-1 (Medium):** the per-peer relay byte budget must admit a maximum-size transaction behind small queued relay: at least MAX_ANY_TX_SIZE + 2 MiB. The PX share is charged only after a successful push. Regression test with real PX sizes. BLOCKS any PX relay or privacy claim until fixed.
- **RTW2A-2:** returned transactions' conflict keys are RESERVED while a bounded drain holds them: `precheck` refuses with `ReorgPending`, and the returned transaction wins.
- **RTW2A-3:** embargo fluffs run off the maintenance loop (spawned, or `try_call` with a retry), and `schedule_downloads` runs first.
- **RTW2A-4 (Medium):** a rate excess on relayed StemTx is DROPPED without penalty. It is not fluffed: forced fluffs would help deanonymization. The PX share is charged after the dedupe and recent-reject checks.
- **RTW2A-5:** correct the per-peer memory docs; decode once into an Arc.
- **RTW2A-6:** capture of returned transactions stops at the per-class budget (tip first).
- **RTW2A-7:** the ctx-reject cache is keyed by the tip returned from the cheap command.
- **Owner:** FX-RTW2A, after the coordinator merges w2-pool and applies the manager call-site diff. It must not touch the handshake parts of admission.rs or conn.rs (W2-30).

## FX-RTW2A and gate waivers, Lead decisions 2026-09-28
- **FX-RTW2A:** accepted as implemented. Relay budget = MAX_RELAY_FRAME + 2 MiB (strict); relay charges on the lane, all or nothing, after dedupe; rate excess dropped, not scored and not fluffed; `ReorgPending` reservation; fluffs off the maintenance loop; bounded capture.
- **Read-loop byte rate stays SCORED** (4 MB/s, burst 16 MB): an honest forwarder within the receiver's PX share (0.2/s, about 0.6 MB/s) stays far below it, so only floods reach it.
- **Consensus gate waivers:** `.github/consensus-gate-waivers.txt` lists published commits that lack the trailer, since shared history is never rewritten. First entry: b24a19a (test-only). Each new entry is a reviewed change.

## W3-44 and W3-39, Lead decisions 2026-09-28
- **W3-44 accepted:**
  - cargo-deny `-D warnings` on both workspaces, including dev duplicates;
  - `[bans.build]` allowlist;
  - no-C enforcement per release target (sys-crates.sh part 2);
  - hazmat-policy.sh (ml-kem hazmat confined to px, single-round AES to randomx);
  - dalek >= 5 banned until transport v2;
  - `unsafe` inventory as a report.
  - **Not adopted now:** ghash/zeroize, argon2/zeroize (it needs wallet code, dossier 37 Z1), cargo-vet (S9), getrandom 0.4.3 (P2).
- **W3-39 accepted:**
  - W1: own PX tree, root-window anchor checks, incremental witnesses;
  - W5: header check on restores;
  - the vault CLI;
  - PX6 drop in rebroadcast.
- **Unconfirmed backfill (W3-39 Q1):** privacy over liveness ACCEPTED. No anchor over backfill-only commitments for 100 blocks past the restore height unless confirmed. Documented UX workaround: restore from height 1.
- **Owed (wallet batch W3-39b):**
  - a header feed from genesis, so W5 is anchored at genesis for every restore;
  - verified contract registrations (from scanned deploys, not the node's `/px/contracts`);
  - the stale-tip relabel residual.

## W3-41, W2-09b, W3-35b, Lead decisions 2026-09-28
- **W3-41 accepted:** 4 fuzz targets (store records, seed words, transport recv, Addr v2), no findings. The seed target compiles `wallet/src/seed.rs` by path to keep reqwest, hyper and argon2 out of the fuzz graph (accepted). Longer campaigns in Wave 4.
- **W2-09b accepted:** template gate (503), `/tip` long poll (20 ms snapshot polling), `next_seed_id` via `rpc::MiningTemplate`, `--prebuild auto`. Stale blocks went from 21% to about 15% (indication). The all-thread synchronous first dataset build is accepted.
- **W3-35b accepted:** operator invalidate/reconsider (store record 0x03; 0x82 reserved for F48-5 quarantine), plus the runtime `invalidate_block` reorg.
  - **Owed (S5b):** refuse marked blocks at header time (`header_sync`, `header_added`); a runtime RPC or actor command for operators; a mempool-return test for operator reorgs; a red-team review of the S5 trust model.

## W3-32 (addrman v2), Lead decisions 2026-09-28
- **Accepted:** keyed two-stage bucketing (a source reaches at most 16 of 256 new buckets), test-before-evict, one tried entry per IP, anchors (2, anchors.json), Poisson feelers, /64 IPv6 limits, inbound eviction protection, stale-tip rotation. Out-of-ownership wiring in net.rs, state.rs and lib.rs accepted.
- **TRIED_BIAS = 0.7** (simulator-derived; the slot share is 10% for g=1 and 20% for g=4, against 16.6% and 33.8% at 0.5).
- **Owed (W3-32b):** eviction protection by ping and recent tx/block relay; block-relay-only connections; `--onion-inbound`; NetConfig interval knobs plus integration tests for feelers and stale-tip rotation; seeds as one-shot address fetches.
- **Accepted limitation:** a fresh node with an empty tried table gives the attacker about 61% of slots in small-network scenarios (F32-13). Documented.

## RT-W3, Lead decisions 2026-09-28
- **RTW3-1 (High):** the W2-09b template gate is REJECTED as designed. Replace it with a LATCHED catch-up gate (Bitcoin's IBD latch): templates may be refused only until the node first reaches "synced" (tip recent against the local clock, plus not sync_pending and a small header gap); once latched, a bodiless header lead never closes it again. Correct the blocks.md §9 risk text. NO PUSH of the gate until fixed.
- **RTW3-2 (High, pre-existing):** count a registered outbound address once, not in both `connecting` and registered. Regression test: refill after churn.
- **RTW3-3:** handshaking connections are eviction candidates first (oldest first); evict at registration, not at accept; cap handshaking at max_inbound/4, also per /16; consider a 5 s key-exchange timeout.
- **RTW3-4:** stale rotation picks the worst outbound peer by validated new-tip announcements (never by the Version height), and waits if that peer is younger than MIN_CONNECT_TIME.
- **RTW3-9:** feeler collision tests are exempt from the group and backoff filters; an untestable occupant is not evicted. **RTW3-10:** re-derive TRIED_BIAS after RTW3-2 and 9, with feelers and answering attacker IPs modeled.
- **RTW3-5 / RTW3-6 (wallet):** check PoW densely on the suffix after the restore height (at least the last 720 headers), plus the genesis feed; tip-age freshness against the local clock (warn, and refuse to build transactions past a bound; show the age). **RTW3-15:** no full commitments fetch after the backfill except at a fixed cadence. Owner W3-39b.
- **RTW3-7:** repair re-appends intact operator records from the moved region. **RTW3-8:** reword the halt message (the block is consensus-valid; the node leaves the network chain; reconsider undoes it); periodic WARN plus an /info field when a heavier chain is refused only because of an operator verdict; templates refused then unless overridden. **RTW3-11:** log verdict ids and heights at open.
- **RTW3-12:** PSK hygiene, P2.
- **RTW3-13 (process):** the coordinator's full check runs every crate's tests before any push; it caught this.

## W3-39b and FX-RTW3-P2P, Lead decisions 2026-09-28
- **W3-39b accepted:**
  - `/headers` feed with genesis-anchored checks;
  - registrations derived from deploys (vault ABI and out_words enforced);
  - backfill end check;
  - RTW3-5 (dense 720-header tail), RTW3-6 (tip age: warn at 10T+FTL, refuse transactions at 60T+FTL, `--allow-stale-tip`), RTW3-15.
- **Owed (W3-39c):** parallel PoW for the restore check (currently about 13 min single-threaded for 720 light hashes).
- **FX-RTW3-P2P accepted:** RTW3-2 (`pending_dials`), RTW3-3 (handshake caps and handshake-first eviction; 5 s/10 s key-exchange timeouts), RTW3-4 (rotation by `last_new_tip`), RTW3-9 (untested occupant kept), RTW3-12. TRIED_BIAS stays 0.7 (re-derived).
- **Open eclipse items (W3-32c):**
  - feelers drain honest addresses out of new;
  - onion attackers are uncapped in tried: cap tried entries per onion group;
  - model honest address inflow and regular-dial promotions in the simulator.
- **Watch:** one unexplained first-run failure of `px_transactions_travel_the_stem_and_confirm_everywhere` under heavy load (suspect: the 5 s key exchange under CPU starvation). Rerun in the full check with the panic captured.

## Engineering process, Lead decisions 2026-09-29 (owner granted full leadership)
- **Pure Rust is non-negotiable:** no C/C++ dependencies, no FFI, no `unsafe` in BlackSilk code, no exception for performance. Enforced by cargo-deny (cc, cmake, cxx and similar banned; `[bans.build]` allowlist), `sys-crates.sh` (no -sys crates, no C/C++/asm sources or compiler calls in any release target's graph), `hazmat-policy.sh`, and the tracked `unsafe` inventory.
- **Tiered verification:**
  - **Tier 1, every merge (local, before push):** workspace clippy `-D warnings`, fmt, gates, doc-lint, cargo deny, and every non-PX test of every crate.
  - **Tier 2 (GitHub CI, every push):** the PX-proving suites one at a time, overflow checks, guests reproducibility, fuzz smoke, full RandomX vectors.
  - **Tier 3 (local, before push):** consensus-path or PX/zk changes, and evidence runs, also run the local PX-proving suites.
  - **A red CI run stops the line:** fix before merging anything else.
- **Every agent must run the tests of every crate that depends on what it changed** (RTW3-13, the supply-audit break).

## W3-32c, Lead decisions 2026-09-29
- **Accepted (simulator-derived):** TRIED_PER_ONION_GROUP = 1; TRIED_PER_SOURCE_GROUP = 16; adaptive tried bias (0.9 once tried holds 64 entries, 0.7 below). Plus ping and relay eviction protection, 2 block-relay-only anchors, `--onion-inbound`, and seeds as one-shot address fetches.
- **Operator requirement:** seed nodes must set `--public-address` (docs/testnet.md).
- **Later:** a "fewer than 3 seeds" warning; the extra block-relay-only probe every 5 minutes (W5).

## CI cadence (Lead decision 2026-09-29)
- **Status:** CI run 110 was the first push run whose full test job (PX-proving included, one at a time) passed on the current code; its overflow job timed out (fixed by sharding in the commit after 1075bd9).
- **Cadence:** do not push again while a rebuild/core CI run is mid-way unless the push fixes CI. Batch merges, so that every push's run completes and serves as evidence for its commit.

## RT-FP3 (fingerprint v3 coverage), Lead decisions 2026-09-29
- **Verdict:** ACCEPT WITH CHANGES. The construction is sound; the COVERAGE is not: six demonstrated consensus mutations leave all fingerprints identical. **The fingerprint does not freeze until the P0 items land.**
- **P0:**
  - RTFP3-2: RandomX config read from the crate (`config_entries()`), plus a pinned RandomX KAT constant asserted by the vector tests (the CIRCUIT_DIGEST pattern).
  - RTFP3-1: a `tags::CONSENSUS` list in the manifest, plus samples (a fixture tx hash and signature message, a key image of a fixed secret, generator H).
  - RTFP3-8: a machine-readable `Revision:` line per record, a test equating the record revisions to REVISIONS, the consensus-gate tie-in, the record-template checklist item, and exact heading match.
  - RTFP3-10: extend consensus-gate paths to `crypto/`, `tx/src/{types,codec,state}.rs`, `chain/src/manager/`, `px/src/{prove,state,tree}.rs`, `randomx/`, `third_party/`.
  - RTFP3-9 and RTFP3-15: build.rs marks dirty trees (release builds refuse them unless explicitly allowed); reproducible binary hashes are the operator check; doc overclaims corrected.
- **P1:**
  - RTFP3-3/4/5/6/7 samples: `Transaction::weight` fixtures, verdict samples for pinned fixture txs (valid plus one per error class), the FTL boundary, the D=1 clamp, empty roots and a small fixed tree root.
  - RTFP3-14: `verify` accepts a registered id whose genesis matches.
  - RTFP3-13: reserved-id table, `--rehearsal` range, `--final` for 0x0001D673.
  - RTFP3-11/12: a zk transcript sample; exhaustive matches for exit codes and Epoch.
- **RTFP3-16:** the DAA floor n²T/20 is provably unreachable for T >= 2. KEEP it as a documented defensive floor (the rule id is unchanged); its mutants are recorded as equivalent-by-proof in the mutation exemptions.
- **Owner:** FX-RTFP3. Re-pin per procedure.

## W4-RX evidence (2026-09-29)
- **P0 EVIDENCE MET:** the real full-mode miner (`--prebuild auto`) crossed the first seed switch at 2113 on labnet regtest.
  - The prebuild finished at height 2070; block 2113 came 2.9 s after the key switch; no hash-rate drop and no node stall.
  - 2835 headers were independently verified (light mode, fresh processes) on all 5 nodes, byte-identical; full vs light agreed bit for bit on 61 blocks; the negative control was rejected.
  - Scope: one crossing, one machine, regtest; the verifier shares the randomx crate (reference conformance rests on the vectors).
- **Finding:** the late joiner stayed at 1 peer (no Addr, no dials); earlier labnets reached 3. A suspected P2P discovery regression, owned by INV-PEERS. It BLOCKS the next labnet evidence and any testnet claim about peer discovery.
- **Follow-ups:**
  - the miner logs background dataset build start and end (`miner/src/lib.rs`);
  - document the new labnet flags in docs/testnet.md §8;
  - test the regtest prebuild window versus default build threads (1 thread does not finish within 640 s) and the light bridge at a switch; consider scaling the default build threads when the window is short.

## INV-PEERS, Lead decisions 2026-09-29
- **Accepted:** labnet passes `--public-address`; a node no longer stores its own address relayed back. The labnet evidence run passes (the late joiner reached 2 peers in 2.4 s).
- **Small-network plateau:** GetAddr answers carry at least min(table, 8) non-terrible addresses (the 23% cap for large tables). Owner P2P-FIX2.
- **The PX stem test's "no peer penalized" flake under load** (twice now): root cause required, since penalizing honest peers because the NODE is slow is a bug. Owner P2P-FIX2.
- **Deploy templates:** unchanged (seed and lab set public_address; the ordinary-node template documents it, since NAT is possible).

## FX-RTFP3, Lead decisions 2026-09-29
- **Accepted:** all P0 and P1 items. `tools/fingerprint-mutations.sh`: all 7 red-team mutations change the rules fingerprint. Revision lines are machine-checked; the gate paths extended (18 historic waivers with reasons); dirty-build refusal (`BLACKSILK_ALLOW_DIRTY=1` for development only); the reserved genesis ids; the DAA floor exemption E1 in docs/reviews/mutation-exemptions.md.
- **Fingerprint v3 is now eligible for the FREEZE,** subject to the Wave 4 gate (mutation run, fuzz, benchmarks) and the second threat-model round.
- **Still sample-based (accepted, documented):** PX and deploy verdicts, block-level rules and canonical-proof rules are covered by REVISIONS plus the build commit and binary hash.
- **Owed:** reproducible node binaries (STATUS: Not implemented), the dirty check for untracked and staged-only files, the stale difficulty.rs comment.

## Wave 4 start (Lead, 2026-09-29)
- **Status of the owner's list:** peer discovery (late joiner) and fingerprint v3 coverage are closed in this log (INV-PEERS, P2P-FIX2, FX-RTFP3), but both are RE-CONFIRMED in Wave 4 on current code: a labnet late-joiner run after the GetAddr floor, and the fingerprint-mutation script as part of the freeze gate.
- **Schedule (4-core/16 GB machine):** phase 4a = W4-MUT (cargo-mutants, consensus then px-core, jobs <= 2) + W4-FUZZ (one libFuzzer process at a time, >= 1800 s per target, -O -a). Phase 4b = W4-LAB (adversarial labnet + late-joiner re-check) once W4-MUT frees the CPU, since labnet timing evidence needs a quiet machine. Benchmarks last, alone.
- **Amends "Agent 42" (exclusive windows):** runs A and B share the machine with a single-core fuzzer. Mitigation: generous timeouts, and every TIMEOUT mutant is re-run in isolation before it is classified.
- **Cross-review:** every W4 report goes to a separate red-team agent who tries to break its conclusions (unexplained exemptions, weak killing tests, fuzz coverage gaps) before the Lead accepts it.
- **CI:** run 115 = connection-cap race in node_binary (fixed d6f4609); the actor_order hang fix (ccff37c) held on Linux (non-PX step 28 min).

## W4-MUT and RT-MUT (Lead, 2026-09-29)
- **Mutation gate for consensus and px-core: ACCEPTED CONDITIONALLY.** RT-MUT confirmed E1–E7 (E1 for all window sizes ChainParams accepts), the counts, and that no mutant survives release arithmetic (the 24 overflow-only kills re-verified with overflow checks off). Merge after the Part 1 fixes land and are verified.
- **Part 1 (W4-MUT, test and doc only):**
  - T3 bound `peak <= 4`: the old `<= 5` let a doubled evicted-borrow allowance pass.
  - Bound the unbounded waits in the cache-store tests.
  - README timeout breakdown corrected: of the 21 cache-store timeouts, 10 fail an assertion and 11 only hang.
  - Record the release-arithmetic re-verification.
  - E7 check-order note.
  - Balanced witnesses in the spec-field test.
- **Part 2 (W4-MUT, product fix, P1 resource and liveness):** the RandomX cache store's transient footprint with a hot set is unbounded as stated, about (6 + H) × 256 MiB (≈3.5 GiB at H = 8). A trimmed 256 MiB cache is freed under the store mutex.
  - The fix is an explicit bound that also holds for hot builds and hot-set churn, with the free moved outside the mutex.
  - No hash, rule or fingerprint change. The fingerprints are re-checked with `--print-manifest`.
  - A new RT pass follows the fix.
  - The 2 GiB miner dataset is not affected: SeedPlanner owns it, and the ~4.4 GiB peak with prebuild is documented.
- **Run C (next mutation run, P0 before the freeze), in priority order:**
  - tx/src/validate.rs (138 mutants);
  - tx/src/px.rs (174);
  - chain/src/manager/fork_choice.rs reward check (on no list until now);
  - tx/src/params.rs (93);
  - crypto/ (CLSAG, BP+);
  - chain/src/block.rs and emission.rs (low).
  - Each run includes a release-arithmetic pass. It is scheduled after W4-FUZZ frees the CPU.

## W4-FUZZ and RT-FUZZ (Lead, 2026-09-30)
- **W4-FUZZ: ACCEPTED as robustness evidence only.**
  - 12 targets × 1800 s, `-O -a`, 0 findings.
  - RT replayed all 9,246 grown inputs in a plain release build: 0 panics, 0 hangs, bounded heap.
  - Harness fixes W4F-1, F41-1 and F41-2 accepted.
  - The claim is limited to "no panic on the reached surface". The depth reached is shallow: proof_decode decodes only its seed, 1 of 593 blocks carries PX, and there are no n_fn>0 kernel seeds.
- **RT-FUZZ-1 (Medium, remote DoS amplification): FIX NOW (W4-PXDOS).**
  - `decode_proof` accepts unbounded vectors: a 4 MiB padded proof takes 143 MB and 0.2 s inside the chain actor's `cheap_checks`.
  - The fix caps every vector before allocation, at caps implied by the shape check, so the valid set and the fingerprint are unchanged. Decoding moves out of the actor command where safe.
  - It gets a consensus-change record with a non-revision `Revision:` line. A red-team pass follows.
- **Fuzz follow-ups (W4-FUZZ2, after the CPU frees):**
  - lift `delivery_plain` from rt-fuzz, without the replay tool, which contains unsafe;
  - kernel_diff seeds for every honest shape (n_fn 0..2), plus the budget assertion in the committed oracle;
  - a structure-aware proof target and a structure-aware PX-tx target (edit the decoded value, then re-encode);
  - correct the evidence README;
  - rename or re-scope transport_handshake.
- **Stateful harnesses (P1 before the freeze):**
  - pre-Verack negotiation and the per-peer protocol, which needs the F41-9 sans-IO seam;
  - px_admission, a stateful mempool admission harness with amplification oracles;
  - scan_outputs, wallet scanning;
  - an executor-vs-AIR constraint check (P1 research).

## W4-LAB and RT-LAB (Lead, 2026-09-30)
- **W4-LAB: ACCEPTED** as evidence for honest runs, unequal partitions and withholding releases. RT confirmed:
  - fork choice is by strictly more work at each step (store-derived work 134 < 139 < 150 < 154);
  - 0 penalties;
  - every handshake failure falls inside a partition window;
  - report.json reproduces exactly.
- **Late-joiner re-confirmation: MET, with a caveat.**
  - The 5-node lab is a complete graph, so the 4/4 result proves little by itself.
  - RT's discriminating E2 run showed address relay working (3/3 learned the late-arriving nodes; 0/3 with relay disabled).
  - The floor shows only as time-to-5: 4.8–7.0 s without it against 2.4 s with it.
  - The labnet check becomes peers >= min(max_outbound + 1, nodes), with the E2 scenario added (W4-LAB fix pass).
- **RT-LAB F1 (Medium, liveness, fix before testnet): W4-SYNC.**
  - Header sync and announcements are height-gated, not work-gated. A lower-work branch of equal height stalled 12.5 s in run 4.
  - A longer-but-lighter branch never pulls a shorter-but-heavier one.
  - The fix goes by tip id or chain work, with DoS bounds; tests are written failing-first.
- **RT-LAB F2 (Medium, performance).** A hop costs about 0.6 s of light RandomX plus up to 250 ms of maintenance tick.
  - W4-SYNC makes announcements event-driven.
  - Header-first relay and light-VM optimisation are design notes for after W4-SYNC.
  - A multi-hop ring labnet is needed for real per-hop figures, scheduled in a quiet window after W4-SYNC.
- **F3–F6 (evidence, metric, test design, docs):** W4-LAB fix pass.
  - The logs get committed.
  - Propagation is reported both filtered and unfiltered.
  - A ring topology option is added.
  - No new runs until the quiet window.

## RT-POW, RT-PXDOS, RT-SYNC (Lead, 2026-09-30)
- **RandomX cache-store bound (W4-MUT Part 2): ACCEPTED and merged locally (6a2b3b7).**
  - RT-POW measured a peak of 1,298 MB, against 1,553 MB on base, with at most 5 caches alive.
  - No deadlock, no hash change, and every caller was checked.
  - L1–L3 and the Info item were fixed in 9bba1bd: the caller rule is now enforced (non-Clone handle plus a debug assert), the prebuild re-arm window is closed, and the documentation is updated.
- **PX proof decode bounds (W4-PXDOS): ACCEPTED WITH FIXES.**
  - RT-PXDOS found no parser differential over 1.15 M inputs.
  - Every cap was confirmed against the verifier, and all 9 PX-proving tests pass.
  - Fixes before merge:
    - F1: drop the decoded proof on the blocking thread and pass only the degree bits;
    - F2: the documented worst case becomes about 16 MB and about 40 ms;
    - RT's differential test (cd0249e) is adopted; its scratch allocator harness, which contains unsafe, is never taken.
- **Header sync by work (W4-SYNC): ACCEPTED WITH FIXES.** All of these land before merge:
  - F-A: the echo regression during drains;
  - F-B: a tip found during the handshake is never announced (pre-existing);
  - F-C: stale known-work after an invalid-body branch, fixed with a best-chain epoch (pre-existing);
  - F-D: documentation corrections;
  - the load-sensitive deep-fork test deadline.
- **Privacy decision:** no jitter on block announcements.
  - The per-hop cost of about 0.6 s dominates.
  - A delay raises stale rates, which favours large miners, for about zero anonymity gain. Monero and Bitcoin both relay blocks immediately.
  - docs/p2p.md §1 now lists block origin as NOT protected; miners who want origin privacy run the mining node proxy-only or over Tor.
  - To be revisited if header-first relay shrinks the per-hop cost.

## Run C and RT-MUTC (Lead, 2026-10-01)
- **Run C: ACCEPTED WITH FIXES.**
  - No consensus-rule bug found.
  - RT confirmed the proof cache:
    - the id commits to the proof;
    - the pool flushes on a rule change;
    - readmit drops entries from foreign rules;
    - 10 targeted mutants of that invariant: 9 caught, 1 unviable.
  - RT confirmed all 5 proving-only kills and exemptions E8–E12 and E14.
  - E16 was REFUTED; its mutant is now killed by a test.
  - The README counts are being corrected.
- **New gap closed: PX digest canonicality.** `read_digest`'s `>= P` check had no test.
  - It is defense in depth: without it, non-canonical words reach ids and conflict keys, and `HostPerm` asserts.
  - It is now tested.
- **Method gap, binding from now on:** cargo-mutants 27.1 never generates `>=`→`>` or `<=`→`<`.
  - Every mutation run now includes a scripted inclusive-bound pass: run C's scope, runs A/B (re-checked), and run D (especially zk/src/bounds.rs).
  - RT found 2 survivors this way: px.rs:141, and fork_choice.rs:66, the low-work margin, which now has a test.
  - Exemption numbering: run D uses E17–E19; run C's new entries start at E20.
- **Latent risk (P1 test now; design if ever needed):** `recent_rejects` is keyed by id and `FeeNotExact` is classed stateless.
  - A future change to the fee rate would permanently blacklist valid transactions.
  - A guard test fails if the epoch fee rules diverge while the class stays stateless.
- **Liveness hardening (P1, a separate agent with its own red-team pass):**
  - a progress assertion in `sync_state`'s outer loop;
  - a structural bound on the `fork_height` loop;
  - bounded signing loops;
  - non-zero `batch_verify` weights.
- **P0 still open: the golden PX proof fixture.** It would make 4 proving-only oracles cheap, and the freeze needs it anyway.
- **E15 (zeroize):** accepted as untestable for now. A P2 design: a single `Secret<T: Zeroize>` wrapper with a test-only wipe counter. It must not depend on zeroize_derive without approval.
- **Run E (before the freeze), consensus-critical code in no run yet:**
  - tx/src/types.rs, codec.rs and state.rs;
  - px/src/prove.rs, state.rs and tree.rs;
  - chain submission.rs and header_sync.rs;
  - the P2P admission classifier;
  - the wallet-side checks.

## Run D and stateful harnesses (Lead, 2026-10-01)
- **Run D (W4-MUTD):** no consensus or bound bug found. Every pre-scan cap held at its boundary.
  - Every survivor was killed or exempted.
  - PX5's shape step now has non-proving oracles, using a "hollow proof".
  - The W4-SYNC rules and the admission path are pinned.
  - RT-MUTD runs before the merge.
- **Exemption numbering (final):**
  - run D: E17–E22, renumbered from E17, E18, E19, E19a, E19b, E19c at merge;
  - run C's new entries: E23 onward.
- **E19 is an oracle limit, not an equivalence:** which thread decodes the PX proof in admission is not observable.
  - It is accepted for now.
  - A decode-in-actor counter for test hooks is P2 (it would be a product change).
- **INV-PEN (P0, possible honest-peer ban):** `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized` fails 1 in 3 alone on unmodified trees.
  - A root cause is required; a retry or a looser assertion is not acceptable.
  - The ping-during-header-verification timeout is investigated with it.
- **W4-STATEFUL:** three stateful harnesses (peer_protocol, px_admission, scan_outputs) plus the wallet header-feed twin.
  - No product bug found.
  - Each of the 8 injected bugs was caught.
  - The seam is `new_inner` plus the p2p `test-hooks` feature.
  - RT-STATEFUL is checking:
    - that the extraction preserves behaviour;
    - that the release node binary built with plain `cargo build` carries no hook code;
    - the strength of the oracles.
- **Binding:** evidence and genesis node binaries are built with plain `cargo build --release -p blacksilk-node` from a clean commit, never by a `cargo test` invocation, which unifies dev-dependency features such as test-hooks.

## RT-STATEFUL (Lead, 2026-10-01)
- **The seam is behaviour-preserving (CONFIRMED).** The `new_inner` extraction is identical code at the same point, and the p2p hooks are dead code in a node.
- **P0, W4-GUARD: a hooked binary can reach evidence or genesis.**
  - `cargo test --release` writes a node with chain, tx, px and p2p test-hooks enabled to target/release, the same path a plain release build uses.
  - The chain hooks are not inert: an undrained LogEntry Vec grows memory without bound.
  - The guard:
    - each hooked crate exposes a TEST_HOOKS marker;
    - the node prints the marker and refuses any network other than regtest when hooked; the genesis tool refuses unconditionally;
    - build.rs refuses CARGO_CFG_FUZZING;
    - CI checks the dependency tree, `--version` and the binary of a plain release build;
    - labnet and the evidence scripts assert the marker is absent;
    - an audit of the W4 labnet evidence hashes, rebuilt from their recorded commits.
  - The W4 labnet binaries' target dir was deleted in the 2026-10-01 cleanup, so their hooks can only be checked by rebuilding them.
  - The other evidence binaries still on disk (w4-rx, bin-83fceee) contain no hook marker.
- **Stateful harness follow-ups, before merge (queued for the W4-STATEFUL agent):**
  - adopt rt-stateful 8260a9f (a spec-constant frame limit; the coinbase, height and tx-hash scan oracles);
  - remove the remaining product imports from the oracles: a spec table of known types and protocol versions, and an independent list of stateless rules;
  - PX seeds for the scan twin;
  - a post-Verack scoring oracle, a spec table of message → expected score (P5 was missed);
  - explain the one-input counter difference in the px_admission twin (print a digest of the verdicts and diff two runs).
- **P1 design: a verifier-only grinding switch for deeper ZK fuzzing.**
  - It must absorb the witness and sample identically, so the transcript is unchanged, and return true.
  - Only under `cfg(all(fuzzing, feature = "zk-fuzz-no-grind"))`.
  - Guarded by the CARGO_CFG_FUZZING build refusal and a `GRINDING_ENFORCED` const asserted at node and genesis start.
  - It needs its own red-team pass before it lands.

## W4-GUARD (Lead, 2026-10-01)
- **The release-binary guard is implemented; RT-GUARD reviews it before merge.**
  - chain, tx, px and p2p export markers.
  - The node, miner and wallet refuse any network other than regtest when marked; the genesis tool refuses unconditionally.
  - node/build.rs, and `compile_error!` in miner, wallet and genesis, refuse cfg(fuzzing).
  - CI runs build-guard.sh on plain release binaries, checking the dependency tree, `--version` and the binary strings.
  - labnet refuses marked binaries and records their versions.
  - Fingerprint digests are unchanged; the `# build flags` manifest line sits outside every digest.
- **Labnet-W4 evidence build audit:** Windows builds are not bit-reproducible (24 bytes of linker timestamps and the PDB GUID), so the recorded hashes can neither confirm nor exclude hooks.
  - Runs 1–2 (64d89d4) are consistent with a plain build: a plain release build log exists 65 s before run 1.
  - Runs 3–4 (9b04827) are UNDETERMINED.
  - **Decision:** the quiet-window labnet reruns (ring topology, E2 relay, the late-joiner check), with guarded binaries and the version text recorded, supersede runs 3–4 as evidence. Runs 3–4 stay in the repo, labelled.
- **Reproducible Windows builds** (`/Brepro` or equivalent, plus the PDB record) move up the reproducibility backlog. RT-GUARD assesses them first.
- **supply-audit and labnet-report** are not guarded yet. Follow-up: they print the build flags.

## INV-PEN sweep (Lead, 2026-10-01)
- **Accepted and merged locally.** Every load-sensitive p2p failure traced was a test bug:
  - raw peers that never answered pings;
  - fixed deadlines that were really ordering assumptions;
  - an observer that sampled where it should have read the actor's log.
  - The product is unchanged. Each fixed test passed 20/20 ambient and 10/10 under 8 busy loops.
- **P1 product performance and liveness (W4-POWPOOL, next free slot):** `compute_parallel` spawns a scoped thread for every PoW chunk.
  - Under contention each spawn waits 13–130 ms. 300 one-thread chunks took 22–40 s under load, against 70–448 ms hashing inline.
  - The fix: hash inline when there is one thread, and use a persistent hashing pool when there are more.
  - It must be measured with real RandomX, and gets a red-team pass.
- **Backlog (P2):**
  - negative checks after fixed sleeps (they can only pass falsely);
  - Dandelion stem-epoch waits, which need a stem-count observable;
  - the liveness L1/L6 margins.

## RT-GUARD (Lead, 2026-10-01)
- **The guard is ACCEPTED WITH FIXES.** No bypass was found, clean builds are unchanged on all networks, and the digests are identical.
- **Medium:** regtest evidence is not protected by the network refusal. Fixes:
  - `--require-clean-build` for the node, miner and wallet;
  - labnet requires the flags line from every binary and records sha256 and version;
  - supply-audit and labnet-report check their flags.
- **Privacy (existed before this change; fixed now, before any release):** release binaries embed the build user's home path (58 copies, including the Windows username).
  - Fix: `--remap-path-prefix` for CARGO_HOME, the sysroot and the workspace.
  - No binary built before this fix may be published.
- **Reproducibility:** `-C link-arg=-Brepro` gives bit-identical node builds on the same Windows machine (RT demonstrated it).
  - It is adopted for windows-msvc.
  - Cross-host reproducibility also needs the remapped paths and the same toolchain; that stays open.
- **Small fixes:**
  - check-build-flags decides from the `--version` output, not the file name;
  - the miner and wallet print the build-flags line;
  - install-linux.sh runs the check as the build user, not as root;
  - the CI control is fatal and self-contained, and a cargo tree failure fails the check;
  - docs claims match the code at merge;
  - systemd's `RestartPreventExitStatus` gains exit 2;
  - check-test-features.sh (RT) is wired into CI.

## RT-MUTD (Lead, 2026-10-01)
- **Run D: ACCEPTED WITH FIXES.**
  - The decode bounds are confirmed: the boundary pass holds, and 38 of 39 cap and constant ±1 hand mutants are caught (the 39th, `[0usize;5]`→6, is equivalent).
  - The hollow proof is a sound stand-in up to the shape check, which reads only degree_bits.
- **P1 gap closed (honest-peer penalties):** the negative side of signature-penalty classification was untested.
  - 12 survivors, including mutants that would penalize honest relayers of young-ring or grace-window transactions.
  - Two RT tests (aea35cd) kill them; they are adopted into run D.
- **Run D fixes:**
  - exemptions renumbered E17–E22 after merging run C;
  - the token-test pin, or a reworded claim;
  - README corrections: the bare test name under `--exact`, and the p2p boundary list;
  - E18 becomes guarded by failing tests;
  - an n_fn=2 decode under PROOF_LIMITS in the unified proving test;
  - `.gitattributes eol=lf` for the evidence argument files.
- **Run E scope (final, before the freeze; about 330+ sync mutants never censused):**
  - tx/src/types.rs, codec.rs, state.rs;
  - px/src/prove.rs, state.rs, tree.rs;
  - chain submission.rs, header_sync.rs;
  - p2p net/headers.rs (verify_headers, on_headers, header_worker, precheck, penalized, header_queue_room, the grace functions);
  - conn.rs `run_connection`, maintenance.rs `maintenance_loop`, the rest of admission.rs;
  - the wallet-side checks.
  - With the boundary pass, constant ±1 hand mutants for the caps, and own target dirs.

## W4-POWPOOL and RT-POWPOOL (Lead, 2026-10-01)
- **The PoW hashing pool is ACCEPTED WITH FIXES.**
  - RT found no deadlock and no wrong hash: real RandomX under concurrency, more keys than MAX_CACHES, hot-set churn and panics gave identical results.
  - The caller rule holds; Drop joins every helper.
  - The one-thread gain reproduced: 0.6–0.9 s per header saved under load.
  - There is no reliable gain at 2 or more threads; under heavy load 2 threads were slower per header than 1.
- **Fixes:**
  - a second panic payload whose Drop panics hangs the caller (theoretical, not reachable with RandomX): notify before anything can panic, and drop extra payloads outside the lock;
  - the stress tests are adopted;
  - the timing logs are committed;
  - a doc correction (inline panics stop at once);
  - `notify_one` per ticket.
- **Default `pow_threads` unchanged** (the logical CPU count). It is to be measured on a real multi-core testnet host before any tuning.

## Threat model round 2: consensus and network lenses in (Lead, 2026-10-02; privacy lens pending)
- **TM2-CONS:** no consensus-rule bug, no x86_64 split path, no inflation path under the assumptions. The gaps are in evidence and in decided-but-unbuilt items.
- **TM2-NET:** P0 items for the trial and genesis, P1 items before a public testnet.
- **Started now: W4-MUTAIR (TM2-1, High, freeze blocker).** The first mutation census of the BVM-1 AIR.
  - The oracle is honest-trace checks plus negative/tamper traces. The circuit-fingerprint pins are excluded: they kill every mutant without proving soundness.
  - A real under-constrained rule found here is reported, not fixed: fixing it changes CIRCUIT_ID.
- **Queued after the privacy lens, to be prioritised together:**
  - golden PX fixture (TM2-2);
  - RandomX start-up self-test (TM2-3);
  - park-on-deep-reorg (TM2-4: before a public testnet);
  - recent_rejects flushed on a rule change, and a non-vacuous fee guard (TM2-5);
  - supply-audit PX test F40-9, and CLSAG/BP+ verifier fuzzing (TM2-8);
  - run F: replay.rs, store.rs, zk verify/config/params, randomx/, the fingerprint modules, supply-audit (TM2-9);
  - D0 and T_g (TM2-10, genesis gate);
  - GetTx > 64 ids disconnecting honest peers: reproduce first;
  - PSK required by the trial procedure;
  - originated.json privacy;
  - systemd StartLimit;
  - operator overrides shown in /info;
  - store PoW sampling at replay;
  - D1 per-peer hashing slow start, and D2 staller detection (P1).
- **Owner tasks re-confirmed:** signing key, signed tags, second fingerprint channel.
- **STATUS.md is stale** (as of e986250). A docs agent will reconcile it with decisions.md.

## Threat model round 2: merged plan and owner decisions (Lead, 2026-10-02)
- **OWNER DECISIONS (2026-10-02):**
  - **Trial release authentication: the two-channel commit id.** The owner publishes the exact commit id plus the consensus fingerprints on two separate channels. Every operator builds that commit with tools/release-build.sh, checks that both channels match, and recomputes the genesis. Signed tags are required before a public testnet.
  - **Supply-audit custody and incident data: a separate machine,** not the build/agent workstation.
- **Lead decisions (cross-check questions):**
  - TM2-P2P also covers the reorg-readmission case: the origin uses `admitted` like every node, and a persisted fluff height only on the Held-after-restart path. The GetTx fix asserts no stem-peer churn.
  - The PX ciphertext `R` canonical-point rule goes IN v3 at this reset (P0-freeze). It is a consensus change: a full record and its own red-team pass.
  - TM2-DOCS corrects the DAA freeze record: the residual is accepted under the majority-hash assumption. Park-on-deep-reorg does not cover it.
  - The AIR gate adds three parts: an all-table cell census including padding rows, lying-generator tests, and a spec-to-constraint table.
- **Merged plan (tm2-crosscheck.md):**
  - **P0-genesis:**
    - the origin re-announce fix, including the reorg case (TM2-P2P);
    - the GetTx >64 fix (TM2-P2P);
    - the PSK procedure (done in docs), plus "PSK loaded" in /info;
    - the RandomX start-up self-test (node and miner);
    - D0 measured per trial device, and a two-stage T_g;
    - origin data at rest: 0700/0600 permissions and the redaction rules;
    - the privacy regression suite (33 W1);
    - the supply-audit PX test F40-9;
    - the empty wallet password refused;
    - the authenticated release reference (owner decision above).
  - **P0-freeze:**
    - the AIR gate (W4-MUTAIR);
    - golden PX fixtures, a tamper sweep, and PX/block verdict samples in the fingerprint;
    - mutation run E (W4-MUTE), then run F;
    - the PX `R` rule.
  - **P1-public-testnet:**
    - D1 header slow start, and D2 staller detection;
    - stem black-hole fixes, PX and the Tx lane (local re-stem at the first embargo expiry);
    - local decoy distribution, and a hedged decoy RNG;
    - Tor: onion-only outbound with SOCKS isolation;
    - X4, header tagging;
    - recent_rejects flushed at an activation, and a non-vacuous fee guard;
    - systemd StartLimit, SIGTERM handling, overrides in /info, store PoW sampling, the F48-5 quarantine;
    - byte-bounded outboxes;
    - log rate limiting and IP redaction;
    - the network-namespace tests NS-1 to NS-9.

## TM2-P2P and RT-TM2P2P (Lead, 2026-10-02)
- **TM2-P1 / X6 confirmed fixed for the named cases:** a block during the stem, a reorg readmission, and a restart. The origin anchors at its pool height like every node.
- **TM2-17 confirmed for v1:** paced GetTx serving, duplicates answered once, no stem churn, per-announcer fairness.
- **ACCEPTED WITH FIXES (before merge; a second RT pass follows):**
  - **(1) A PX burst from one announcer is lost permanently** (2 of 6 pooled; this predates TM2-17). Fixes:
    - re-queue a dropped answer;
    - retry the same peer once on timeout;
    - byte-aware in-flight cap.
  - **(2) Eight silent first announcers censor a transaction** (predates TM2-17). Fixes:
    - prefer outbound announcers;
    - never push wanted for a peer not in the queue;
    - never forget an id while an announcer was refused a place.
  - **(3) Held copies are no longer pooled at all:** a local record only, so the origin behaves exactly like a restarted relay. This replaces the "held copy is never re-announced" decision, which a single InvTx probe could still expose.
  - **(4)** A test hook replaces the sleeps.
  - **(5)** originated.json is parsed per entry: it no longer fails open, and a duplicate id keeps the highest height.
  - **(6)** A node-wide GetTx serving byte budget. The real per-peer figure is about 21 MB.

## RT2-TM2P2P (Lead, 2026-10-02)
- **The flake root-caused:** a test timing assumption. Connection setup took more than 5 s under CPU starvation (1 in about 690 runs). Fix: precondition waits go to 30 s.
- **Held copies not pooled: CONFIRMED.** No cache writes, and no network-visible origin/relay difference.
- **Request scheduling is weak against adversaries:**
  - F1 (High): timed-out ids parked behind junk with no request or timer;
  - F2 (High): a Busy self-induction loop;
  - F4: tx_overflow can be filled;
  - F5: silent announcers cost 30 s each, sequentially;
  - F3: ServeBudget fairness.
- **DECISION:** redesign p2p transaction requests as a TxRequestTracker-style model (prior art: Bitcoin Core txrequest), design note first, with a stated worst-case bound:
  - preferred outbound announcers first;
  - one outstanding request plus a parallel fallback;
  - a per-txid deadline;
  - no request-less queues;
  - per-peer caps by count and bytes, with ungameable eviction;
  - Busy rotates to the next announcer;
  - the share is charged after the pooled check.
  - ServeBudget: size-accurate reservations, a per-peer cap, FIFO, an outbound slice, and a throughput disconnect.
  - A third RT pass follows.
- **Other fixes:** the originated.json torn-height salvage, and a directory fsync.
- **The PX-proving tests could not run locally** (memory under 7 GB for about 50 min). The two ignored RT PX tests are added to CI's PX job.

## RT-NODEOPS (Lead, 2026-10-02)
- **TM2-NODEOPS: ACCEPTED WITH FIXES.**
  - No false refusal across the real key switch, reorgs or side blocks, and with real RandomX across two switches.
  - The self-test and dataset check are deterministic.
  - /info adds no leak; the fingerprint is unchanged.
- **Fix (Medium-High):** the store-check tip region and samples are chosen by connected-chain HEIGHT, not storage order (a planted store escaped at 18 of 20 seeds). The docs drop "always" and add the detection table.
- **Other fixes:**
  - a gentler StartLimit, documented;
  - Docker on-failure:3 and stop-timeout;
  - the miner self-test runs once, with in-process reconnect;
  - tighten I/O errors become warnings;
  - fchmod with O_NOFOLLOW;
  - Unicode whitespace in the password check;
  - the miner's skip flag is reported loudly.
  - The originated.json owner-only writer goes to TM2-P2P.

## Run E (Lead, 2026-10-03)
- **W4-MUTE: no real bug.** Every survivor was killed or exempted (E29–E44), and the boundary, hand and release-arithmetic passes are complete.
  - Gaps closed with tests:
    - the CLSAG message's coverage of the range proof;
    - size caps at their exact edges;
    - the per-IP limit at registration;
    - the wallet's header-link check;
    - the idle timeout.
  - RT-MUTE runs before the merge.
- **Locator: decided to fix the DOCS.** The code's shape is the tip plus 9 one by one; docs/p2p.md §6 says 10. There is no behaviour change before the freeze. The ignored test becomes a test of the actual shape, so the boundary mutant is killed. RT-MUTE checks the protocol intent first.
- **E44:** the two unnamed maintenance delays (the first address save at 5 s and the outbound round at 2 s) become named constants, pinned by tests.
- **CLSAG / PX / tx-id message coverage:** RT-MUTE checks every binding message field for test coverage.
- **Remaining frozen-scope work:**
  - the AIR gate (W4-MUTAIR, in progress);
  - run F: replay.rs, store.rs, zk verify/config/params, randomx/, the fingerprint modules, supply-audit;
  - the golden PX fixtures;
  - the PX R canonical-point rule.

## INV-70 and RT3-TM2P2P (Lead, 2026-10-03)
- **INV-70: root-caused; merged locally.** `a_full_class_answers_busy_at_once` held the chain lock across timing asserts, and a load-induced assert failure poisoned it. The actor then exited 70 and the output was lost.
  - Fix: a HeldChain helper on its own thread, and fail-stop now writes directly to stderr.
  - The node's fail-stop policy is unchanged and correct.
- **RT3-TM2P2P, the request-tracker redesign:**
  - Confirmed: records, timers, salted priority, caps, ServeBudget accounting, originated.json.
  - Refuted: the bound against non-silent attackers.
  - Found:
    - F1 (High): parallel honest answers penalized as unrequested;
    - F1b (High): a slow honest peer's retry copy penalized;
    - F3 (High): ping/pong behind Tx answers drops honest slow and Tor links (~80–240 kB/s needed for 1–3 PX);
    - F2 (Medium): slow NotFound or Busy, and reconnecting attackers, defeat the bound (up to ~20 min, sometimes dropped);
    - F4: a node-wide lane stall is treated as a per-peer Busy;
    - F5: inbound serving-pool holders are not rate-checked;
    - F6: the shared tracker links clearnet and onion identities.
  - **DECISION:** fix all of them, adopting RT3's sketch for F1/F2 where right:
    - a ping/pong priority channel;
    - a PONG_TIMEOUT measured from the write;
    - size-aware timeouts;
    - a per-network-class tracker;
    - an adversarial property test.
  - RT3's failing tests must all pass. A fourth RT pass follows.

## RT-MUTE (Lead, 2026-10-03)
- **Run E: ACCEPTED WITH FIXES.** No product line changed. E29–E35, E36–E39, E41, E42 and E44 are confirmed.
- **F1 (Medium, test gap):** five parts of the transfer and deploy signed messages and ids were untested, including the deploy message's range-proof term (tx malleability). RT's tests are adopted. Deploy and PX fingerprint samples are added only if the consensus digest stays unchanged; otherwise a Lead decision is needed.
- **Withdrawn exemptions:** E40 and E43's 128:59 and 136:59 (they are testable).
- **Locator:** the docs and the header_sync.rs:11 comment follow the code (tip + 9 consecutive), and the test is exact (`dense == 9`). Not consensus-relevant; Bitcoin Core gives 11.
- **E44:** named constants, pinned.
- **Flakes:**
  - outbound_policy table_of port collisions;
  - liveness L7, now by drain steps.
- **Full-set kills by timing assertions are re-checked in isolation** (method note).
- **Run E follow-ups done** (w4-mute 95bc76c). The fingerprint samples for deploy, PX and the PX binding are DECIDED YES, as one fingerprint revision together with the golden PX fixtures and the PX/block verdict samples (P0-freeze), rather than a separate pin change. Run E is merged.

## RT4-TM2P2P (Lead, 2026-10-03)
- **Confirmed:**
  - F1b;
  - F2 as stated (size inflaters within the stated bound);
  - F3 (except the reconnect feature);
  - F4, F5;
  - the Busy exception.
  - No origin oracle in the reconnect re-announcement.
- **Found:**
  - **High:** a node-wide late_txs memory filled for free brings the F1 penalties back. Fix: per-peer quotas.
  - **High, privacy:** the reconnect whole-pool re-announcement leaks a node-identifying order. DECISION: remove it; a reconnecting host gets back only what its previous connection was owed, shuffled. Every InvTx flush is shuffled, and onion inbound peers are skipped.
  - **Medium:** deadline-cut requests are not remembered (a framing attack).
  - **Medium:** cheap size inflation through undecoded lane drops. Inflate from decoded answers only; count slots by request age; restore the silent bound.
  - **Low-Medium:** the F6 class must come from via_tor (the legacy hidden-service setup).
  - **Low:** a lost wakeup; the pong margin against kernel/Tor buffering.
- RT4's prototype for the slot rule was blocked by the permission system. It did not ask the Lead to run it; the P2P agent implements it through the normal path.
- **Process:** TM2-P2P has gone through four RT rounds, each finding fewer and smaller issues, but the new mechanisms keep adding surface. After this round:
  - a focused RT5;
  - if it finds only Low items, merge, and record the residuals as P1-public-testnet items rather than iterating further.

## W4-MUTAIR (Lead, 2026-10-03)
- **First AIR census: no soundness finding.** No false execution was accepted:
  - 1,977 mutants;
  - 62 hand mutants;
  - a 3.86 M-change cell census over every table, including padding rows;
  - lying-generator and forgery tests.
- **Closed:**
  - honest corner-case gaps (HALT on the last row, offset-3 bytes, an odd JALR sum, code at or above 2^27, Poseidon pointer bytes);
  - an untested oracle;
  - untested trace-generator checks.
- **Spec gap (decision pending RT-MUTAIR):** the input (2^16) and output (2^12) word limits are enforced only by the interpreter, not by the AIR. RT-MUTAIR determines whether any consumer relies on them, and recommends one of: an AIR constraint (a CIRCUIT_ID change), a verifier/statement rule, or a spec correction.
- **Exemption renumbering at merge:** AIR E40–E50 become E51–E61 (run E holds E29–E44; E40 is withdrawn and reserved).
- `poseidon::p2_width` is dead code. It rides with the next AIR revision, if one happens.
- **RT-MUTAIR:** no soundness finding.
  - The oracle matches eval. Three unmodelled aspects are argued harmless; the Fiat–Shamir-only binding rests on the proving tests.
  - The free-by-design cells cannot change the statement.
  - 10/11 exemptions confirmed. The old E49 `!=` was misclassified; it is now killed by zero-delta probes.
  - Lying-generator gaps closed: MULH vs MULHSU, I-type, store widths, offsets 1–3, misaligned accesses, x0.
- **Stream-limit decision: option (iii), correct the spec.**
  - The output count is bound exactly by the AIR; the input is private witness.
  - No consumer relies on the 2^16/2^12 limits (PX ≤ 277 output words; kernel CPU height ≤ 2^16).
  - tx/tests/px_io_limits.rs is the tripwire.
  - No CIRCUIT_ID change.
- p2_width becomes a width test.
- ECALL-variant and JAL/JALR link-value lie tests are to be added before the merge.
- **W4-MUTAIR merged locally** (57ee353):
  - exemptions renumbered E51–E61 (E54 withdrawn);
  - the ECALL and link-value lie tests added;
  - the stream limits documented as interpreter limits, with px_io_limits as the tripwire;
  - CIRCUIT_ID unchanged.
- **Run F started (W4-MUTF):** replay/store, zk verify/config/params, randomx/, both fingerprint modules, supply-audit. Exemptions from E62.

## Run F stopped: the permission-system block and the overload (Lead, 2026-10-04)
- **What happened:**
  - After the session restart, a run F queue script that had been edited while it ran launched a DUPLICATE RandomX census: PID 8564 under bash 17188, next to the real one, PID 16664.
  - Four more censuses were queued: runZ, runN, runX, runS, plus after-C2.
  - Together they would have meant 4 jobs at once, over the 2-job limit.
  - The machine ran out of process resources: 124 chain mutants and one tier-1 link step failed with Windows 0xC0000142 (STATUS_DLL_INIT_FAILED).
  - Those results are INVALID and will be re-run, not counted.
- **Permission system:** the auto-mode classifier denied W4-MUTF's attempt to stop its own duplicate ("Interfere With Workloads"), then two of its read-only commands. The agent asked the Lead to stop the process. **The Lead refused** (permission laundering) and took the question to the owner.
- **OWNER DECISION (2026-10-04):** stop all of run F for now. The owner then explicitly authorised the Lead to stop the confirmed run F processes and to resume the work sequentially.
- **Done by the Lead under that authorisation:**
  - stopped, by PID after re-verifying each command line: the trees of 23012 and 16308 (both runR, including 16664 and 8564), 11800 (runZ), 20260 (runN), 18572 (runX) and 19980 (runS);
  - 19412 (after-C2) had already exited;
  - also stopped two leftover tail watchers of the finished W4-MUTAIR, 12228 and 18728;
  - left alone: the Lead's bash shells (21424, 17128, 15120, 21960) and unrelated grep watchers.
- **Run F progress kept** (branch w4-mutf a049abc, tests only):
  - store.rs: 6 tests killing 12 survivors; 3 candidate equivalents (E62+, to be written);
  - tools/supply-audit/tests/px_scan.rs: the first PX-side supply-audit test (scan side). The wallet side of F40-9 still needs a proven PX transaction or the golden fixture.
- **Run F restart plan:**
  - one census at a time, --jobs 2, never alongside another heavy build;
  - check CPU, memory and process count before each;
  - order: chain re-run of the 124 → the boundary, hand and overflow passes → zk → randomx → node fingerprint → px fingerprint → supply-audit;
  - never edit a running script; use separate queue files.
- **Tier-1 policy for runs that overlapped the overload:**
  - a run with any build error or any load-explained failure is re-run on a quiet machine;
  - a clean pass is valid, because load causes false failures, not false passes.

## Owner authority extension (2026-10-04)
- **Authority:** the owner granted full authority over critical technical and strategic decisions (architecture, consensus, cryptography, privacy model, networking, roadmap), with one condition: deep, evidence-driven research from reliable current sources comes before every major decision.
  - Facts, findings, assumptions and conclusions are kept separate.
  - Prior work is not preserved for its own sake.
  - Pause only for irreversible actions that could destroy data, expose secrets, compromise security, or alter a publicly deployed network.
- **First application:** RES-FREEZE, a research dossier with primary sources on the open pre-freeze questions:
  1. the DAA raising race and selfish mining;
  2. the PX ciphertext R canonical-point rule;
  3. v1 decoy selection, and rings versus PX long term;
  4. relay privacy (Dandelion++, txrequest, Tor);
  5. the honesty of the FRI soundness claim.
- The Lead decides each topic from the dossier and records the evidence.

## RES-FREEZE dossier, first pass (Lead, 2026-10-04): PROVISIONAL until citations are verified
- **Status:** the dossier's external citations are marked "[lit, not re-fetched]". No decision rests on them until each is verified against its primary source (verification is under way).
- **Accepted now (repo facts and own measurements):**
  - M-A: the RT-4 stall after an 18× difficulty rise lasts about 17.5 h deterministic, 20.5 h median, 24 h at p90.
  - M-B: about 6.2% of random 32-byte strings are valid ristretto255 encodings.
- **Provisional directions (to be confirmed or revised after verification):**
  1. **DAA:** accept the raising-race residual for testnet "under K1"; do not change the DAA before the freeze. Add an RT-4 runbook entry with the measured stall (no emergency-drop rule; the BCH EDA precedent). Reopen the DAA, finality and a selfish-mining model before mainnet.
  2. **PX R:** the rule is "R decodes as canonical ristretto255 and R ≠ identity" (mirrors v1 T6). Its value is privacy uniformity: a random R exposes a non-reference output with probability 15/16. The KEM-combiner hardening (V, H(ek)) rides the same reset as a wallet-format change.
  3. **Decoys:**
     - P0 before a public testnet: the local distribution, a hedged decoy RNG, a one-year window, no spend-time /distribution request; gamma parameters inherited from Monero, labelled as such.
     - Rings stay in v3 as the weaker layer.
     - Long term: PX-to-PX as the default private payment, a bridge denomination/delay helper, and a v1 sunset after a shielded coinbase.
  4. **Relay before a public testnet:**
     - a per-class tracker (done on tm2-p2p);
     - a shared inbound trickle with shuffled inv (partly done);
     - onion-only mode plus SOCKS stream isolation;
     - local re-stem, and a PX embargo;
     - a per-network GetAddr cache;
     - the privacy regression suite as a gate;
     - Tor as the documented recommended path.
     - Before mainnet: private broadcast, then transport v2.
  5. **FRI:** about 105.7 bits (89.7 proven unique-decoding plus 16 grinding); no parameter change.
     - Reword "proven" to apply to the FRI component only.
     - List the assumptions: Poseidon2 as a random oracle, mixed-height batching, Merkle extractability, batch-STARK composition.
     - Add a ~5-bit mixed-height union-bound term to the independent calculator.
     - Long term: an end-to-end soundness write-up, or STIR/WHIR.

## RES-FREEZE verified (Lead, 2026-10-04): DECISIONS
Every external citation was verified against its primary source (res-freeze.md §8). Roughly 15 attributions were corrected and the unverifiable claims withdrawn. No direction changed. Decisions:
1. **DAA: no change before the freeze.**
   - The raising-race residual is accepted under K1 (majority-hash assumption) for the testnet.
     - GKL 2017 and Bahack 2013: a residual is inherent to any exponentially rising rule, and no proof exists for per-block DAAs.
     - Negy et al.: selfish mining is a fork-choice issue, not a DAA one.
     - Qubic 2025: burst-majority hash is the dominant real risk.
   - Now: an RT-4 runbook entry with the measured stall (~17.5–24 h from 18×), and no emergency-drop rule (the BCH EDA precedent).
   - Before mainnet: reopen the DAA plus a finality option (Publish-or-Perish, rolling checkpoints, or a finality layer) and model selfish mining.
2. **PX R: IN v3.** R decodes as canonical ristretto255 and R ≠ identity.
   - Precedent: Zcash Orchard §4.6 and §5.4.5.5. FIPS 203: nothing else in the ciphertext is checkable. RFC 9496: the identity check is separate.
   - Wallets treat every failure as "not mine"; the KDF hashes the R bytes as received.
   - The KEM-combiner hardening (bind V, H(ek)) rides the same reset as a wallet-format change.
   - Implemented together with the golden PX fixtures in ONE fingerprint revision.
3. **Decoys, P0 before a public testnet:**
   - the local distribution; a hedged decoy RNG; a one-year window; no spend-time /distribution request;
   - exact-boundary tests at 10 blocks and at coinbase maturity (this off-by-one class recurred three times in Monero);
   - the gamma 19.28/1.61 labelled "inherited, mis-fit even for Monero";
   - a partitioning sampler evaluated (Ronge et al.);
   - coinbase decoys handled.
   - Long term: PX as the default private payment (Zcash: only default or mandatory shielding makes a full-set pool work), and a v1 sunset after a shielded coinbase.
4. **Relay, before a public testnet:**
   - per-network-class inv timers and trackers (Bitcoin Core PR #33464);
   - onion-only mode plus random SOCKS credentials;
   - local re-stem;
   - the privacy regression suite as a gate;
   - originated and relayed transactions indistinguishable on Tor (ProxyMark);
   - any private-broadcast fallback fails CLOSED (the Bitcoin Core v31.0 advisory).
   - Before mainnet: private broadcast. The docs must not present Dandelion++ as strong protection (Sharma et al. NDSS 2023).
5. **FRI: keep BS-ZK-3; the claim is honest in method** (proven regimes; the capacity conjecture it avoided is now refuted: ePrint 2025/2010, 2025/2046). Follow-ups:
   - recompute the bits with ρ⁺;
   - LogUp p > total multiplicities;
   - confirm the Merkle theorem (2 or 3);
   - quote bits against a hash budget Q.
   - **URGENT (ZK-ADVISORY, started):** check Plonky3 GHSA-f69f-5fx9-w9r9 (an unsound mixed-height roll-in; BlackSilk uses mixed heights) and CVE-2026-46654 (the challenger), plus the other listed advisories, against our pinned versions and third_party patches.

## ZK-ADVISORY and the memory incident (Lead, 2026-10-04)
- **ZK-ADVISORY: none of the five published Plonky3 advisories affects BlackSilk** (docs/reviews/plonky3-advisories-2026-10-03.md, merged d5f7a83).
  - GHSA-f69f (mixed-height roll-in): fixed in v0.7.0, and our FRI verifier is byte-identical to upstream.
  - CVE-2026-46654: a different challenger type.
  - The other three: fixed in 0.7.0, or not reachable with our configuration.
  - The ρ⁺ recomputation gives 89.58 statistical / 105.58 bits, against the 100-bit floor.
  - docs/zk.md now says 89.6, not 89.7 (5e765d5).
  - The Merkle tree falls under Theorem 3 (~122 bits).
  - P2 follow-up: a census test that every LogUp count is constrained to {0, 1}.
- **Memory incident:** one run F chain mutant's test binary grew to 10.4 GB. Free memory fell to 0.6 GB, which led to the session crash (uv_spawn).
  - Under the owner's process-management authorisation, the Lead verified the process and stopped ONLY that one (PID 17240). Memory recovered to 10.7 GB.
  - That mutant's result is invalid. W4-MUTF re-runs it alone with a memory cap and judges whether the unbounded allocation is a real DoS finding in store/replay or a mutant artifact.
  - **Binding from now on:** every census has a per-test memory guard (stop above ~4 GB, own processes only).

## TM2-P2P merged after RT5 (2026-10-04)

- Decision: merge tm2-p2p (4fb8536) with RT5's tests (ff32aef). RT5's final pass found
  nothing above Low; all 7 RT4 claims hold in code and under adversarial tests
  (200 random and 168 grid strategy mixes, k up to 64, none over the stated bound; 7/7 PX
  tests; 20/20 loop iterations clean, iterations 16–17 re-run after an environmental
  memory incident).
- Merge resolution: the run E maintenance test written for the old 30 s pong timeout now
  checks the 192 s timeout, with the peer sending its own pings so the 180 s idle timeout
  cannot come first.
- Open, P1 before a public testnet:
  - RT5 F1 (Low): the 160-entry per-peer late memory is not a bound. A burst of requests
    ended by other announcers pushes entries out, and one honest slow peer can be
    penalized. Fix: no penalty for a `Tx` the peer itself announced lately, or size the
    memory to `PEER_TRACKED`. The docs' and comment's sizing derivation is corrected.
  - RT5 F2 (Low, performance): young-slot counting allows up to 12 parallel requests
    for a slow large transaction (4 before RT4). Fix: also cap old outstanding requests
    at `PARALLEL`.
  - RT5 F3 (Low or informational): the 192 s pong window holds dead connections about
    50% longer (ties to the byte-bounded-outbox P1); owed sets are about 4 MB worst case
    and can be churned by 256 IPs; one NAT IP shares an owed set; node-wide PX
    saturation is outside the stated bound (one sentence owed in docs/p2p.md).

## Run F memory incident: closed as mutant artifacts (2026-10-04)

- The three mutants that grew without bound (10.4 GB and 8.1 GB) were store.rs 303:9
  (`parse_frame` returns `used = 0`, twice with different leaked vectors) and 867:25
  (`pos *= used`). Each stops the record loop from advancing.
- The Lead confirmed by reading the source: `parse_frame` returns `used = 12 + len` with
  `len ≥ 1` by `Codec::lengths`, so `used ≥ 13` and the real loops always reach the end of
  the file. Not a product finding.
- cargo-mutants scored two of these as caught; those results are void. They are re-run
  alone under a memory cap, where a hang or the cap counts as caught.
- W4-MUTF's store tests and px_scan (a049abc) are merged after a read-only red-team review
  (all 12 targeted mutants killed by reasoning; no High or Medium). E62–E64 are recorded.

## Decoy and relay plan (2026-10-04)

- The plan for the P0 and P1 items is in the order: privacy regression suite and decoy
  statistics first, as the gates for every later change; then the wallet-side
  distribution, picker, stem, trickle, Tor, RT5 and wallet-SOCKS work in parallel by
  file ownership. No item changes consensus.
- **Decision (D7, coinbase decoys).** Coinbase outputs are not segregated now:
  dossier 38 §3.9 shows the non-coinbase pool is too small and segregation reveals the
  input type. "Handled" means (a) a test that coinbase members appear in proportion to
  their share of eligible outputs at each age, (b) a measured effective ring size under
  the research-lab #109 discount model on a labnet-like composition, and (c) a written
  threshold for segregation, to be revisited at about 10^5 non-coinbase outputs.
- **Decision (38 W11, verified backfill) raised from P2 to P1.** Deriving the
  distribution from the wallet's own index (D1) removes node skew only for the scanned
  range; a restored wallet still takes older heights from the node unverified.
- Docs drift found: STATUS.md still lists the TM2-P1 origin fix as open; it is merged.

## RT5 F1 and F2 fixed (A-RT5, 2026-10-04)

- **F1:** a request ended early (another announcer's answer, or the deadline) keeps its
  peer's slot until that peer's answer, its `NotFound`, or the request's expiry. One late
  copy is accepted per request (`take_late`), and the window counts from the expiry.
  - The per-peer late memory, 192 = 16 × (300 + 30) / 30 + 16, is now a proven bound.
    The tracker invariant asserts that nothing is ever pushed out.
  - It also removes a reception-timing signal: the old instant slot refill showed a peer
    a new `GetTx` the moment this node got the transaction elsewhere.
  - Rejected: a memory sized to `PEER_TRACKED` (not a bound) and accepting any announced
    `Tx` (drops the asked-only rule and gains nothing).
- **F2:** RT-ART5 reproduced a 67.9 s outbound-honest delay under the first 8-place cap.
  - **Decision: variant B.** Inbound candidates get 8 places; outbound (preferred)
    announcers get a 9th reserved place. Copies of one id are capped at 9 (12 before).
  - An outbound honest announcer is asked within 32 s whatever inbound attackers do
    (29.9 s measured in the worst shape).
  - Accepted fallback: inflated attackers among our own outbound peers can hold the
    reserved place. The bound is 70 s once they have been asked (proven); 67.5 s is the
    worst measured with 1, 2 or 4 of them.
  - The inbound bound is unchanged for T ≤ 60 s. With attackers inflated to the largest
    answer it is 2 s + max(30 s(1 + ⌈k/4⌉), T⌈k/8⌉): 786 s at k = 64 (tight). The
    20-minute deadline holds it up to k = 96.
- Rejected variant A (outbound exempt from the cap): copies grow with the number of
  outbound announcers, about 17 at worst.

## PX delivery combiner v2 (Lead, 2026-10-04)
- **Decision:** the delivery key is `H32("px/delivery-key/v2", ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ V ‖ H(ek) ‖ cm)` with `H(ek) = H32("px/delivery-ek", ek)`, through the project's own hash (no new dependency). `V` and `H(ek)` are cached in `DeliveryKeys`.
- **Rationale:** it binds the classical ciphertext and both recipient public keys into the combiner, in the style of the X-Wing and generic hybrid KEM combiners, so a hybrid share cannot be re-targeted to another key pair. Including `ct_kem` is redundant given ML-KEM's ciphertext binding, but harmless.
- A sender also refuses an address whose view key is the identity (R2-C9).
- Wallet-side only: neither tag is in `tags::CONSENSUS`, so no verdict and no fingerprint changes. It rides the v3 reset, which leaves no v1 ciphertext.

## PX-R phase 2 (Lead, 2026-10-04)
- **PX5 out of the manifest:** the full PX5 verdicts on the golden PX fixture stay out of the fingerprint manifest (verification costs about 0.2 s, paid at start-up, `--version` and `/info`). They are pinned by `node/tests/px_fixture.rs`. The manifest keeps the stateless PX verdicts (structure, balance, strict proof decoding), the ids and the binding.
- **Gate:** `node/src/px_fixture.{bin,txt}` are consensus paths of the gate.
- **Determinism finding:** the PX prover is not bit-reproducible for a fixed witness and seeded RNG (two generations differ from the prunable part on, and in length). The first output is pinned; the generator never runs in CI. Open: the source, and whether a varying proof length for one witness is a fingerprint (P-5).

## PXDET-1: PX proving made deterministic (2026-10-04)

- **Cause (reproduced):** `p3-batch-stark` 0.7.0 drew each table's quotient randomness
  from the shared hiding-PCS RNG inside a parallel loop, so which table got which values
  depended on thread scheduling. That changed the quotient commitment, every later
  challenge, the FRI query positions and so the pruned proof length.
- **Fix:** a local `p3-batch-stark` patch (third_party/README.md) makes the draws in
  table order; the DFTs stay parallel and there is no slowdown. Proofs are now
  identical across runs and thread counts (`zkvm/tests/reproducible.rs`; a full PX proof
  matched at default threads and at 3). The verifier and the set of accepted proofs are
  unchanged, and the pinned fixture still verifies. Red-team reviewed (RT-PXDET).
- **Privacy assessment:** the varying length was not a witness leak: it followed the
  public query positions only (P-5 stays "supported, not closed", resting on the random
  oracle model of Fiat–Shamir). There is no thread-count fingerprint.
- **Decision: no smallest-nonce consensus rule.** A prover that does not take the
  smallest proof-of-work nonce is distinguishable at about 2^16 permutations. Requiring
  the smallest nonce would make every verifier try all smaller nonces, about 2^16
  permutations per proof: a cheap amplification against verifiers. Taking the smallest
  nonce stays a prover rule (the reference prover does, F27-3); third-party provers are
  told so in docs/zk.md.
- **The golden fixture stays pinned** (`c9e05387…`, made before the fix; still valid).
  Regenerating it now gives `75357ff4…` reproducibly, but would mean one more re-pin
  for no consensus reason. It is regenerated only with a later reviewed revision.
- RT-PXDET finding 1 (the third_party allow-list was not checked in CI) is being closed
  by the third-party gate (branch tpgate, under review).

## Header output commitment (Lead decision, 2026-10-04)

- **Problem (RT-D1b N1/N2, F38-2, F39-6).** A restored wallet takes the global index of
  its first output and the whole older output set (for decoys) from a node,
  unverified. A lying restore node can shift every global index (the wallet's
  transactions become invalid on the real chain; a later honest re-spend enables a ring
  intersection) or fabricate decoy candidates. v3 headers commit to nothing about outputs.
- **Research (agent report, primary sources).** Grin headers commit `output_mmr_size`
  and `output_root`, and PIBD verifies every segment against them. Zcash commits its
  note-commitment root (hashFinalSaplingRoot, then ZIP-221/244 history MMR). Monero
  commits nothing in headers; FCMP++ binds its tree root through transactions. A count
  alone stops index shifting but not forged decoys; a root closes both. BlackSilk
  downloads the whole backfill anyway, so the wallet just recomputes the root: no
  per-output proofs, and no new request pattern.
- **Decision: v3 headers carry `output_count` (u64) and `output_root` (MMR over v1
  outputs in global-index order).** The header grows from 100 to 140 B; proof-of-work
  cost is unchanged. New rule B-OMR: a body whose outputs do not give the committed count
  and root makes the block invalid. Wallets check `first_output` and the backfill
  against the header before the restore point (verified backfill, 38 W11, closed by this
  rather than left at P1).
- **Why now:** after launch, a header field needs a hard fork and a migration of
  wallets and miners. The authorized testnet reset makes this the cheap moment.
- `px_root` in the header (removes the 100-block PX residual, px.md §11.4) is evaluated
  in the implementation, not assumed.
- Implementation: branch `omr`, one consensus revision with its record, rule samples
  and one re-pin, red-team reviewed before merge.
- Limits: a node that mines its own chain from genesis still passes the header check
  (the existing F39-10 bound); nothing above is implemented or tested yet.

## Proof of work: SKC-1 research, the RandomX salt, the mining blob, xmrig (2026-10-04)

- **SKC-1 (owner proposal, a BlackSilk-native CPU PoW).** Two independent research
  agents plus a fresh-context cross-check, all internal research (docs/pow/). The
  verdict on SKC-1 as proposed is REDESIGN REQUIRED, and a redesign has INSUFFICIENT
  EVIDENCE:
  - its 32 MiB per-nonce memory fits on-die SRAM (about 8–20 mm²), while RandomX forces
    ASICs onto DRAM;
  - it repeats CryptoNight's pattern;
  - its mixer and graph are unanalysed, and the nonce binding is unspecified.
  RandomX stays. SKC-1 is kept only as optional offline research.
- **The real threat is rented RandomX hashpower.**
  - Monero had an 18-block reorg on 2025-09-14 (Qubic).
  - Rental costs about $40 per MH/s-day.
  - No algorithm choice secures a small chain against a determined renter.
- **Decided (owner approved the proposal and delegated PoW decisions):**
  - BlackSilk's own RandomX salt, merged as RX-SALT (`68e6e66`).
  - Node-level header-verification anti-DoS (branch hdrdos, in review).
  - Safe-Rust interpreter speed-ups.
  - Confirmation guidance, reorg and hashrate alerts, and a halt-on-deep-reorg switch (off
    on testnet).
  - An optional pure-Rust stratum server for external miners.
  - Rejected: merge mining (any Monero pool could attack at zero cost, and it links blocks
    to pool identities), checkpoints (decentralisation), and multi-algorithm schemes.
- **The mining blob (research: docs/pow/xmrig-compatibility.md).**
  - Fact: xmrig hard-codes the RandomX nonce at byte 39 (4 bytes) per algorithm, and a
    stratum adapter cannot move it.
  - Decision: keep the v3 header layout (nonce last). RandomX hashes a fixed 47-byte blob:
    `"BSilk/1"` ‖ Blake2b(tagged network id ‖ header without the nonce) ‖ nonce (u64 LE)
    at 39..47.
  - So xmrig needs only an `rx/blacksilk` algorithm entry, and future header changes never
    touch xmrig.
  - The blob is fixed-length and node-derived (no Tari-style padding duplicates), and it
    commits to every field.
  - It lands in the same pre-freeze revision as the header output commitment (branch omr).
- **External contact:** an upstream xmrig pull request for `rx/blacksilk` is planned once
  the stratum server and a tested patch exist. It will be made openly, as AI-assisted
  work on behalf of the project. A pinned xmrig build is planned for the testnet because
  upstream merge latency has been long.

## output-root (Lead, 2026-10-04)

- **Decision:** v3 block headers commit to the v1 output set, Grin-style: `output_count`
  (LE64, cumulative outputs after the block) and `output_root` (a Merkle mountain range
  over every output in global-index order, leaf = `H32("output-mmr/leaf", one_time_key ‖
  commitment ‖ LE64 height ‖ u8 coinbase)`, peaks bagged with the count). New body rule
  B-OMR after B5; a mismatch makes the block invalid with its descendants (the body
  matching `tx_root` is the block's own).
- **PX root: included** in the same revision (`px_root`, rule B-PXR after B8), after
  evaluation: one field, one `root_after` per block in validation, nothing in the miner
  (the coinbase appends no PX commitment, so the node computes it for the template's
  transactions), and it removes the PX backfill's trust in one check. A later header
  revision would cost another reset and re-pin.
- **No header-only bound** on `output_count`: it would duplicate body-rule constants in
  the header crate and reject nothing the body check does not.
- Header 100 → 172 bytes, nonce at 164; every genesis id moves (testnet `b16090df…`).
  Record: docs/reviews/v3-consensus-changes.md#output-root. The wallet checks (each
  block's `first_output` against `output_count`, the output backfill against the
  synced header, the PX backfill against `px_root`) land as a separate commit, merged
  after the wallet-distribution branch.
- **Mining blob (same revision, Lead decision after the xmrig research):** the header
  layout stays (nonce last, 164..172); the PoW input becomes a derived 47-byte blob
  `"BSilk/1" ‖ H32("mining-hash", LE32(network_id) ‖ header[0..164]) ‖ LE64(nonce)`,
  nonce at byte 39 where stock xmrig writes its RandomX nonce (xmrig iterates 39..43, a
  pool's extranonce is 43..47). The block id stays the full header's hash. The revision
  id becomes `OMR:header-output-mmr-px-root-and-mining-blob` (one revision).

## RT-W1 (wave-1 red team): findings and verdict status (freeze-commit reconciliation, 2026-10-04)

- **Why this entry:** RT-W1b and RT-W1c have verdict sections above; the first wave-1
  red team (RT-W1, over CB-A, CB-B1a and CB-B3) has none. This entry collects what the
  repository and its history show. It reconstructs no verdict.
- **Findings and fixes (from the fix commits and records):**
  - RTW1-1 (Medium) and RTW1-10 (Info): the unknown-upgrade work gate and
    `seed_lag ≥ 1`; `2affc89`, merge `278dc60`; record rt1-unknown-upgrade-pow,
    Follow-up (RTW1-1).
  - RTW1-2 (Medium) and RTW1-7 (docs): PX proofs decoded and shape-checked before rings
    on every single-transaction path; `75ed1c9`, merge `2a69556`.
  - RTW1-3 (Medium), RTW1-6 (Low), RTW1-8 (Low/Info) and an Info item (canonical form
    in `zk::verify`): `be93f71`, merge `180d1ca`; records BS-ZK-3, Canonical proof shape
    and Soundness figures, Follow-up (RTW1-3/6/8).
  - RTW1-4 (Low) and RTW1-5 (Low): wallet duplicate outputs and foreign-genesis files;
    `d1e05bc`, merge `2a69556`.
  - RTW1-9: no commit, record or decision names it.
- **Verdicts: not recorded.** No per-record verdict (ACCEPT, ACCEPT WITH CHANGES, ...)
  of RT-W1 is in decisions.md, the records or any commit message, and the RT-W1 report
  is not in the repository. The re-review of FX-RTW1-ZK is not recorded either.
- **Records:** the step-15 lines of BS-ZK-3, Canonical proof shape and Soundness figures
  now cite the findings above and keep the verdict **open**. They no longer say
  "red-team review (agent 50) pending" without context: agent 50's verdicts above are
  design-stage verdicts, given before implementation.
- **Open (not a freeze gate by itself; record debt):** a red-team verdict on the three
  zk records and on FX-RTW1-ZK. If one is run before the freeze, its scope should
  include the mixed-height union term (below).
  - *Closed 2026-10-04:* RT-FREEZE-V gave the verdicts (entry "RT-FREEZE-V" below).

## RT-PXR, RT-PXR2 and RT-RXSALT (freeze-commit reconciliation, 2026-10-04)

- **RT-PXR** (phase 1 of px-ciphertext-r): nothing High. Follow-ups L1–L4 and L6 in
  `9f9ccb5` (the record's scope claim about pool revalidation corrected; identity-`R`
  open test; delivery v2 known answer; mock-chain `R`; wallet-review D-1 superseded).
- **RT-PXR2** (phase 2: golden PX fixture, samples, revision PX-R): nothing above Low.
  Follow-ups L1–L3 and I1 in `d5c20f7` (the fixture re-encodes byte for byte; binary and
  LF attributes; STATUS rows; the ciphertext binding probed at six offsets). Both passes
  are stated in merge `5d3d96f`.
- **RT-RXSALT** (rx-salt): verdict "merge", stated in merge `68e6e66`. Its findings are
  not in the repository. The reference-implementation cross-check of bs-1a..bs-1f is
  still not run (a freeze gate).
- The records px-ciphertext-r and rx-salt now cite these reviews.

## Mixed-height soundness term (freeze gate B6, 2026-10-04)

- **Done:** "RES-FREEZE dossier, first pass" item 5 asked for a ~5-bit mixed-height
  union-bound term in the independent calculator (research: res-freeze.md §5.4 (b),
  §8.6 item 5 (b)). `zk/tests/soundness_calc.rs` now charges every FRI term (batching,
  commit phase, query phase) log2(H) bits for H distinct input heights, with H
  over-counted as 32 (at most 23 tables, at most 15 heights): 5 bits.
- **Result:** unique decoding with the term is **≥ 100.58 bits over the whole envelope**
  (105.58 − 5; 100.65 at the largest shape), above the 100-bit floor
  `MIN_PROVEN_BITS` by about 0.6 bits. Johnson stays hash-bound at 122. Computed, not
  proven: the term is a heuristic stand-in for the missing roll-in theorem.
- **No parameter change.** The FRI parameters (BS-ZK-3) and `PARAMS_ID` are unchanged.
  The margin is thin: any later change that costs more than about 0.6 bits in this
  regime (fewer queries, a larger rate, a larger height count) needs a parameter
  decision, which is consensus.
- docs/zk.md §9.3 and §12 quote about 100.6 bits with the term; record "Soundness
  figures", Follow-up (mixed-height term).

## RT-FREEZE-V: red-team verdicts on the freeze-branch records (2026-10-04)

A fresh-context internal reviewer (RT-FREEZE-V) reviewed the records left without a
verdict by RT-W1, and the freeze-branch work. Internal review, not an audit.
- **Verdicts:**
  - BS-ZK-3: **ACCEPT**.
  - Canonical proof shape: **ACCEPT**.
  - Soundness figures: **ACCEPT WITH CHANGES** (docs): stale "BS-ZK-2 / ≥ 123 / ≥ 105"
    figures in assumptions.md (Z1, also Z3, Z7, Z13), review-package.md,
    external-review-scope.md and query-policy.md; the calculator's `TABLES` must be 33
    (BVM-1 with `MAX_EXECUTIONS` = 5 has 12 + 5·4 + 1 tables,
    `DecodeLimits::ENVELOPE.max_instances`), not 32; the non-query terms must be
    asserted ≥ 200 bits with the mixed-height term too.
  - FX-RTW1-ZK: **ACCEPT WITH CHANGES**: a comment in `px/src/fingerprint.rs` still named
    BS-ZK-2 (an RTW1-8 leftover); its item 12 (i) is done (`zkvm.CIRCUIT_DIGEST` is in the
    PX manifest).
  - FX-RTFP3: **ACCEPT**. Re-running `tools/fingerprint-mutations.sh` on the freeze
    commit stays a freeze gate.
  - The mixed-height term (`33387bb`): **ACCEPT**, keeping the framing "a heuristic; no
    theorem covers the construction".
  - RTW1-9: unknown, probably withdrawn or merged into another finding; the RT-W1
    report is unavailable. The "RT-W1 … verdict status" entry above stands.
- **Applied (one commit on the freeze branch):** every change above; with `TABLES` = 33
  the term is log2 33 = 5.04 bits and unique decoding with it is ≥ **100.54 bits** over
  the envelope (100.60 at the largest shape), still above the 100-bit floor. Also added:
  a completeness test that `blacksilk_randomx::config_entries` lists every constant of
  `randomx/src/config.rs` except `ARGON_SALT_MONERO`
  (`config_entries_list_every_config_constant`), and a test that a proof carrying a
  field element encoded at or above p is refused by decoding
  (`a_field_element_at_or_above_p_is_refused_by_decoding`). No fingerprint or pinned
  value changes.
- The records' step-15 lines now carry these verdicts; "verdict open" and "re-review
  pending" are replaced where a verdict was given.

## research/pqsignatures removed (owner decision, 2026-10-05)
- **2026-10-05:** `research/pqsignatures` removed from the tree (owner decision), as `legacy/` was on 2026-10-04.
  - Reasons: not built, not in any workspace, used pre-standard round-3 Dilithium (not FIPS 204) and young falcon crates, parts did not compile, parked since AUDIT.md finding S7.
  - It stays in git history (removed in `5038b1a`); a future post-quantum design would start fresh from FIPS 204 ML-DSA.
  - `research/` is gone with it: the root `Cargo.toml` `exclude`, `.dockerignore` and the doc-lint, unicode-scan, sys-crates and hazmat-policy gates no longer name it.

## BS-ZK-4 (Lead, 2026-10-04; approved by the owner)

- **Decision:** keep `NUM_QUERIES` = 108 and raise `QUERY_POW_BITS` from 16 to 20, as
  a new parameter set `BlackSilk/zk/BS-ZK-4` (a constant change is a new set, never an
  in-place edit). Revision `ZK:BS-ZK-4-query-grinding-20`, record
  docs/reviews/v3-consensus-changes.md#bs-zk-4.
- **Why:** with the mixed-height union term (H = 33), BS-ZK-3 sat about 0.5 bits above
  the 100-bit floor. The floor counts total bits, grinding included, and docs/zk.md
  §9.3 caps grinding at 20 bits. BS-ZK-4 gives 109.58 bits, 104.54 with the term, with
  no change to the proof format or its expected size and no verifier code change
  (every proof's bytes differ, and individual lengths vary with the query positions:
  the regenerated golden fixture is 4,704 bytes shorter). 112 queries (the eq. 17 ceiling at
  `MIN_LOG_HEIGHT` 8) would cost about 3.4 % proof bytes and leave about 1.2 % to the
  3.8 MB bound for the widest proof, which is still unmeasured (gate B2).
- **The term stays.** res-freeze.md §8.5's "absence" is narrowed: a close peer-reviewed
  analogue exists, Zhang et al., USENIX Security 2024, Protocol 1 / Theorem 3.1
  (rolling batch FRI, arity 2, unique decoding: the query term has no factor in the
  number of rolled-in polynomials). There is no theorem for the exact Plonky3
  construction, so the H = 33 union term is retained as the conservative figure.
- **Caveats, recorded:**
  - the statistical part stays 89.58 bits (84.54 with the term); the extra 4 bits are
    grinding, which is computational and worth less against cheap Poseidon2 hardware;
  - the 20-bit grinding cap is used up for the chain's life;
  - the smallest-nonce prover rule (F27-3) now costs about 2^20 permutations to check
    (docs/zk.md §11.3); the reference search stays sequential and deterministic;
  - prover grinding time, measured: 1.32 s mean, 0.95 s median, 25 ms to 5.2 s over 64
    transcripts (release, 4-core i7-6700, other builds running; record item 11).
- **Re-pins:** the golden PX fixture is regenerated here (deterministic since PXDET-1);
  `PX_SIDE_DIGEST` and `deploy_configs.rs` are re-pinned once, at the end of the branch,
  together with px-deploy-row-caps. A red-team pass is owed before the freeze.

## px-deploy-row-caps (V12) (Lead, 2026-10-04)

- **Why:** freeze gate B2 failed (`914b74f`, branch b23): under the R7-5 deploy rule
  the widest registrable two-function PX proof is about 4.09–4.13 MB expected (above
  the 3.8 MB bound of "Agent 22"), and its prover would need about 1 TB.
- **Decision (V12):** deploy-time caps, stateless, with `K = kernel_budget(MAX_FN)` and
  checked arithmetic: cycles ≤ 2^15, keys ≤ 2^14; `K.x + MAX_FN·b.x ≤ 2^H` with H = add
  16, lt 16, bit 14, shift 14, mul 14, Poseidon2 11; program table and padded image
  ≤ 2^14 (new `PxProgramTooLarge`). Defence in depth: PX5's shape check refuses a table
  above 2^16. Revision `B2:px-deploy-row-caps`, record
  docs/reviews/v3-consensus-changes.md#px-deploy-row-caps.
- **Effect (model):** widest PX proof 3.70 MB, 3.78 MB worst over the query positions;
  prover memory for the memory-widest pair 10.4 GB (13.1 GB pessimistic): a 16 GB
  proving class. 8 GB devices prove transfers, single calls and the vault pair
  (6.45 GB measured). The memory figure is modelled, not measured; a CI measurement of
  the memory-widest V12 pair is arranged separately.
- **Rejected:** V8 (the vault-pair heights; 6.45 GB): almost no headroom for any new
  contract (Poseidon2 ≤ 52, cycles ≤ 8,192, ≤ 4,096 instructions). A uniform height cap
  (2^16 gives 24–36 GB) cannot meet 8–16 GB.
- **Re-pins:** `PX_SIDE_DIGEST` and `deploy_configs.rs` once, at the end of the branch,
  for BS-ZK-4 and this change together. A red-team pass is owed before the freeze.

## Red team on bszk4: BS-ZK-4 and px-deploy-row-caps (2026-10-05)

- **Verdicts:** `ee0e96f` (BS-ZK-4) and `dcbcfe2` (px-deploy-row-caps) MERGE WITH FIXES;
  nothing blocking. Internal review, not an audit.
- **Applied as follow-up commits** (no amend, no rule or pin change): the BS-ZK-4
  labels and size wording, relation R7, the FRI-margin evidence summary and a 16-bit
  witness test (record "bs-zk-4", Follow-up); kernel-budget monotonicity, the cap
  assertion tied to `PX_MAX_LOG_HEIGHT`, `verify` running the shape check, R7-5 marked
  superseded, the budget-cap evidence summary, the prover's early stop at the cycle
  cap, and `zkvm/src/program.rs` and `exec.rs` as consensus-gate paths (record
  "px-deploy-row-caps", Follow-up).
