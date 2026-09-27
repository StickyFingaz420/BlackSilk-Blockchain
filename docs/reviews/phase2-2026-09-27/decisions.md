# Coordinator decisions log (phase 2)

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
- **W5 header PoW check:** ON by default for restores (sampled light-mode checks plus LWMA recompute), opt-in for routine sync. Closes F39-10.
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
