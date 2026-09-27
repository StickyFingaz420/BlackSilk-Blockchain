# 49 innovation: research dossier (phase 2, phase 1)

Internal engineering research, not an audit. Read-only: no repository file was changed and nothing was built or run. No repository content was sent to any web service; only public sources were searched and read.

**Evidence tags:**
- **[math]** mathematically established, or a simple calculation shown here;
- **[test: name]** covered by a named existing test (not run by me);
- **[src]** read in the source at the commit below;
- **[web]** a cited external source (§8);
- **[est]** my own estimate from stated anchors, still to be measured;
- **[assumed]**;
- **[unknown]**.

**Headline.** None of the proposals below is for immediate consensus. The most valuable near-term items need **no consensus change**:
1. a header-verifiable compact scan feed, which the existing transaction hash already allows (F49-1);
2. a written post-quantum migration plan that corrects I4-6's privacy claim (F49-3);
3. an off-tree recursion feasibility spike, which has a concrete blocker today (F49-2).

Everything that touches consensus (state commitment, aggregation, function-hiding wrappers, recovery transactions) is staged behind evidence and ranked P3.

---

## 1. Scope and what I read

**Commit:** `9e422d8` on `rebuild/core` (`git rev-parse --short HEAD`).

**Coordination inputs (read in full):**
- `C:/bszkeval/p2/brief.md`;
- the roster (entry 49, and 06, 19, 22, 27, 28, 31, 33, 35, 39, 46);
- `decisions.md`;
- `status.md`.

**Previous innovation reports (read in full):** I1 (private computation), I3 (network privacy) and I4 (sustainability, scaling, post-quantum). I2 (identity and governance) was read in the parts that concern state commitments (I2-F7, §4.2 gap tree). I build on these reports and do not repeat them. Where my evidence disagrees with them, I say so.

**Sibling dossiers already written (skimmed for overlap; I defer to them in their areas):**
- 06 randomx-performance (SoA batching, O4′ FPU; no SIMD crates or JIT);
- 19 hash-domain-separation (the node() misuse trap; R2-C6 option A);
- 22 px-proof-system;
- 25 zk-soundness;
- 27 zk-performance (SIMD, cross-build verdicts);
- 28 private-contracts-px (ADR-28-1: PX is the only contract platform);
- 30 p2p-transport (transport v2, ML-KEM hybrid);
- 31 p2p-sync (RX presync, FlyClient reference);
- 37 wallet-keys (seed v1 format, the 32-byte `master`).

**Reviews:** R16-architecture (R16-9, state commitment) and the consolidated review's register entries for R16-9 and P2-7.

**Source read [src]:**
- `consensus/src/header.rs` (the 100-byte header: `tx_root` at 60..92, nonce at 92);
- `consensus/src/merkle.rs`;
- `chain/src/block.rs:30-45` (`compute_tx_root`);
- `tx/src/types.rs:34-67` (Coinbase has no extra field), `:432-446` (`Transaction::hash` = prefix / base / prunable);
- `tx/src/px.rs:1-40`, `:228-293` (PX prefix, base and prunable bytes), `:370-390` (`prunable_hash`, `binding`), `:487-516` (deploy);
- `crypto/src/keys.rs:130-200` (`WalletKeys::from_seed`: `k_s = Hs("wallet/spend-key", seed)`, `k_v = Hs("wallet/view-key", seed)`);
- `crypto/src/hash.rs:1-30`, `:170-235` (Blake2b-512 `Hs` with length-prefixed tag);
- `crypto/src/stealth.rs:1-140` (the mask `y = Hs("mask", S)`, coinbase `Cm = G + a·H`);
- `px/src/delivery.rs:1-100`, `:149`, `:257`, `:292-297` (hybrid delivery, EC view tag, per-address keys);
- `zk/src/params.rs:30-110` (`EXTENSION_DEGREE = 8`, `CHALLENGE_FIELD_BITS = 247`, 108 queries, blow-up 8, `MAX_LOG_HEIGHT = 22`);
- `zk/Cargo.toml` (Plonky3 `=0.7.0`);
- the workspace `Cargo.toml:50-66` and `third_party/README.md` (patched p3-fri, p3-merkle-tree and p3-dft; "p3-fri and p3-merkle-tree are not [fixed] in 0.8.0");
- `randomx/src/vm.rs:45-110`, `:640-720` (a pre-decoded `Op` enum with match dispatch).

**Not read:** the zkVM AIR internals beyond what I1, 23 and 27 report; the contracts crate (not integrated; ADR-28-1).

---

## 2. Current state (what exists and what it supports)

| Claim | Evidence |
|---|---|
| The header is exactly 100 bytes and commits only to `tx_root`. No state root exists anywhere in the header or the coinbase | [src] `header.rs:6,17-25`; `types.rs:53-56`; R16-9 |
| The transaction hash is `H(prefix_hash, base_hash, prunable_hash)` for transfers and PX (Monero-style). The PX proof, the BP+ and the CLSAGs sit only in the prunable part | [src] `types.rs:432-446`; `px.rs:281-287, 379-381` |
| **So a block's `tx_root` can be recomputed from prefix and base bytes plus a 32-byte `prunable_hash` per transaction, without the proofs** | [math] from the two rows above |
| The PX proof is bound to `h_tx`, which covers everything except the prunable part, and includes network and branch | [src] `px.rs:382-390` |
| v1 spend and view keys are hash images of a 32-byte seed. `Hs` is Blake2b-512 over `len(tag) ‖ "BlackSilk/v1/" ‖ tag ‖ data`, reduced wide mod ℓ | [src] `keys.rs:153-158`; `hash.rs:1-30, 221-235` |
| The v1 output mask is deterministic in the shared secret: `y = Hs("mask", S)`, `S = k_v·R`. Coinbase uses mask 1 | [src] `stealth.rs:9-11, 74-75` |
| PX delivery is hybrid Ristretto ECDH + ML-KEM-768. The view tag comes from the ECDH secret only. Keys are per address, so scanning costs one scalar multiplication per output and per wallet address | [src] `delivery.rs:1-70` |
| The proof system is Plonky3 0.7 over BabyBear with a **degree-8** challenge extension (247-bit field), 108 queries, blow-up 8, 16 grinding bits, and traces up to 2^22 rows | [src] `params.rs:33-74` |
| Three Plonky3 crates are patched for prover livelocks. Per the repository's own note, the p3-fri and p3-merkle-tree fixes are not upstream in 0.8.0 | [src] `third_party/README.md`; `Cargo.toml:59` |
| There is no recursion, aggregation, pruning or state commitment anywhere | [src]; I1 §1 |
| The RandomX VM already pre-decodes each program into an `Op` enum and interprets it with one `match` per instruction | [src] `vm.rs:51-110, 692-720` |

**What is well designed and should be kept (in my assessment):**
- The prefix / base / prunable split is the right substrate for everything in §3.1, §3.4 and §3.5: pruning, compact feeds and proof replacement all work without touching the header [src + math].
- The field and hash are recursion-friendly (BabyBear, Poseidon2): a STARK can verify a STARK natively (I1 A5).
- Deterministic, hash-derived v1 keys and masks are exactly the preconditions that let a hash-preimage recovery bind **amounts** as well as ownership (§3.2) [math].
- Hash-based PX ownership, nullifiers and proofs need no post-quantum *signature* migration (I4 §3.3, agreed).

---

## 3. Problems and proposals in scope

Each subsection answers the brief's questions:
- the problem;
- security;
- the classification;
- the literature;
- the trade-offs;
- the tests;
- the invariants;

plus the roster's own questions:
- pure-safe-Rust feasibility;
- the benefit;
- the consensus impact;
- the staged path;
- what must be proven first.

### 3.1 Compact private sync (download-all, made cheap and header-verifiable)

**The problem.**
- Wallets download whole blocks as hex, proofs included (I1-F2, I3 §3.9).
- The "download everything" model is the strongest private-sync model: it is information-theoretically private against the server.
- Bandwidth is the only thing that makes it fail.
- I1 proposed a proof-free feed, but assumed that its **completeness** must be trusted, because "no header commits to the PX root".

**New point (F49-1).** A header-verifiable feed needs no new commitment.
- Serve per block:
  - the header;
  - for each transaction, its `prefix_bytes` and `base_bytes` verbatim, plus its 32-byte `prunable_hash`.
- The wallet recomputes each `Transaction::hash`, then `tx_root`, and compares it with the header [math, from `types.rs:432-446`, `block.rs:35-37`].
- **The result:** omission, insertion or modification of any output, nullifier, commitment or ciphertext is detected against the header chain. Integrity then reduces to the header chain itself: PoW-checked by the wallet (W-F6), or trusted.
- **Size [est]:**
  - a PX prefix is dominated by 2 ciphertexts of 1,241 B each [src R16 §6], plus nullifiers, commitments and the optional v1 part: about 3–4 KB;
  - the prunable part (about 2.2 MB) is replaced by 32 B;
  - roughly a 500× reduction for PX blocks.
- Deploys carry their programs in the prefix, so they are not compacted. They are rare and bounded by weight.

**Why the privacy is the same.** Every wallet receives identical bytes. There are no per-wallet filters and no server-side view-tag matching (I3 §3.9, I4 §4: never change).

**Beyond the feed: scaling the download-all model.**
- **At today's capacity**, wallet compute is trivial: about 3 PX transactions × 2 outputs × 720 blocks ≈ 4,300 PX outputs a day [math], each costing one scalar multiplication per wallet address.
- **Two costs grow linearly if recursion raises throughput 10–100×:**
  - (i) feed bandwidth: at 100 PX per block, about 350 KB per block and about 250 MB a day [est];
  - (ii) per-address scanning compute. PX keys are per address (`delivery.rs:62-66`); v1 subaddresses use a lookup table instead. This is R12-9 and belongs to 39.
- **Options, in order of privacy:**

| Option | Privacy vs server | Status of the art | Fit for BlackSilk |
|---|---|---|---|
| Download-all compact feed | Information-theoretic | Deployed pattern (Zcash compact blocks; the privacy issue there comes from queries, not from the format) | **Adopt** (P2, 39 owns) |
| Scan on the user's own node (the phone talks to its owner's node over Tor) | The server is the user | Trivial | Document as the recommended phone path |
| Single-server PIR over the compact feed or the output table (for decoys and records without full download) | Computational (LWE/RLWE) | YPIR about 5 GB/s server throughput on 8 GB databases [web: YPIR, USENIX Sec 2024]; InsPIRe (ePrint 2025/1352) about 5× smaller keys and up to 50% less online traffic [web]. The server cost is linear in database size per query | P3 research. Pure-Rust implementations exist only as research code [assumed]; YPIR's reference uses SIMD intrinsics (unsafe) [I3] |
| OMR (oblivious message retrieval) | Computational; clues are a consensus field | PerfOMR (USENIX Sec 2024), InstantOMR (USENIX Sec 2026), UnifOMR (CCS 2026) [web]. The cost is falling, but it still needs an FHE server stack and a per-output clue field (CONSENSUS) | P3 watch. Revisit only if throughput exceeds about 100 PX per block |
| FMD | Weak, tunable false positives | Rejected by I3 (agreed) | Reject |
| Tachyon oblivious synchronization (proof-carrying wallet state; payments out of band) | Strong against the sync service | **Ragu PCD is "under heavy development and not yet audited"** [web: Tachyon roadmap and repo]. Built on Halo-style curves (not post-quantum) | Watch the *idea* (a sync service learns only nullifiers). Its out-of-band delivery gives up BlackSilk's in-band guarantee (I1 §5) |

**Security consequences:**
- None if the feed is verified against `tx_root`.
- If a wallet skips the recompute, a malicious node can hide incoming records (a liveness and UX harm) or show fake ones. The Janus / commitment check already rejects fake PX records, because `cm` must recompute (`delivery.rs:52-55`).

**Classification:** privacy-enabling, performance. Not consensus.

**Tests (owner 39):**
- `compact_feed_recomputes_tx_root_for_every_kind` (coinbase, transfer, PX, deploy);
- `compact_feed_rejects_dropped_or_reordered_tx`;
- `compact_feed_rejects_modified_ciphertext`;
- `compact_feed_is_byte_identical_for_all_requesters`;
- a property test: `feed(block).recompute_root() == header.tx_root` over the random block corpus.

**Invariants:**
- the `Transaction::hash` three-part structure;
- the proof stays entirely inside the prunable part (no proof bytes may ever move into prefix or base);
- identical feed bytes for every client;
- no per-record or per-index query RPCs.

### 3.2 Post-quantum migration: seed-preimage recovery, corrected and completed

**The problem.** v1 is fully discrete-log based (I4 §3.1). After a CRQC (a cryptographically relevant quantum computer):
- CLSAG spends can be forged (theft);
- BP+ and Pedersen binding break (undetectable inflation);
- key images of past rings become computable (retroactive tracing).

I4-6 proposed a recovery proof of `k_s = Hs(spend, seed)` and `k_v = Hs(view, seed)`, with the elliptic-curve checks done natively. I verified its preconditions against the code and found two gaps and one correction.

**(a) Amount binding: it holds, but only through a precondition nobody has pinned.**
- **ZIP 2005:** Zcash had to change note encryption so that `rcm` hashes *all* note fields, because Orchard commitments "are not post-quantum binding" [web: ZIP 2005].
- **Monero:** jeffro256's post-quantum turnstile for Carrot binds the amount into the mask derivation (`k_a' = ScalarDerive("Carrot commitment mask" ‖ s_sr ‖ a ‖ K_s ‖ type)`) and **cannot recover legacy RingCT enotes** [web: gist].
- **BlackSilk:** once the verifier natively recomputes `S = k_v·R`, with `k_v` bound to the seed preimage, the mask `y = Hs("mask", S)` is fixed. Then `a·H = Cm − y·G` determines `a` uniquely mod ℓ, even with discrete logs broken [math]. The recovery checks `Cm == y·G + a·H` with `a < 2^64`, taking `a` from `enc_amount`. For coinbase outputs, `Cm = G + a·H` with a public `a`.
- **So BlackSilk v1 is recovery-ready for amounts today,** which Monero's legacy RingCT is not. This depends on the mask never becoming sender-random.
- **Add to the never-change list (new precondition 5):** the v1 output mask is a hash of the shared secret only. The coinbase mask is 1 (`stealth.rs:9-11, 74-75`).

**(b) Correction to I4-6: recovery is not privacy-free.**
- I4 says revealing `k_s` and `k_v` loses nothing "after Q-day". That is true only against the quantum adversary. At Q-day, a CRQC will plausibly be held by very few parties.
- Publishing `k_v` and `k_s` on chain hands **every classical observer** the wallet's complete incoming v1 history, and the spend key of any output not swept in the same transaction.
- **Can a cheaper partial reveal avoid this? No [math]:**
  - Suppose we keep `k_s` hidden and publish only per-output `p` (the one-time secret).
  - Anyone who knows `k_v` then computes `x` and `m`, and `k_s = p − x − m` follows.
  - Hiding `k_v` as well forces `S = k_v·R` into the circuit.
- **Cost of a zero-knowledge variant [est]:**
  - Proving the EC relations inside BVM-1 needs non-native Ristretto arithmetic over 255-bit integers on RV32:
    - a field multiplication is about 64 limb products plus reduction, roughly 150–250 cycles;
    - a point addition is about 10 field multiplications;
    - a variable-base scalar multiplication is about 380 group operations, so roughly 0.6–1M cycles.
  - About 2–3 scalar multiplications per output means **about 1.5–3M cycles per output**, at or above `MAX_CYCLES = 2^21`.
  - It is feasible only as a dedicated circuit or with continuations. That is L–XL work.
- **Consequence:** the privacy-preserving post-quantum migration path is **voluntary migration to PX before Q-day**, through ordinary `bridge_in` with CLSAG. Seed recovery is a last resort with a stated privacy cost. The docs should say so.

**(c) The turnstile must be bounded, and the claim race addressed.**
- Between Q-day and the freeze, an attacker can mint undetectable v1 value (forged BP+) and create "honest-looking" outputs to itself.
- Carrot's design also assumes "enotes must have been honestly constructed at time of creation" [web].
- **The v1 supply is exactly computable from public data** [src/math]:
  - coinbase amounts are public;
  - fees are public;
  - `bridge_in`, `bridge_out` and payouts are public amounts (`px.rs:234-244`).
- So the recovery turnstile is: **Σ recovered ≤ v1_supply(freeze height)**.
- Neptune Cash used the same idea after its 2026 soundness incident: a "Lustration Barrier" counts all pre-fork UTXOs in a global tally and accepts no more once the supply limit is reached [web: Neptune].
- **The fairness problem:** a first-come cap lets an attacker who inflated before the freeze exhaust it first. An owner-level design choice is needed between:
  - first come, first served (simple, unfair);
  - a claims window followed by pro-rata settlement (fair, complex).
- Specify it now; decide before mainnet.

**(d) Prior art:**
- Vitalik Buterin, "How to hard-fork to save most users' funds in a quantum emergency" (2024): revert to before visible theft, freeze EC-signature spends, and recover with a STARK of the BIP-32 seed preimage [web].
- BIP-361 (Lopp et al., April 2026): phase C is "zero knowledge proof of possession of a BIP-39 seed phrase" [web].
- ZIP 2005 (Proposed): about 7 Blake2b-512 compressions plus curve operations in a circuit, for a new recoverable-note format [web].
- Monero's Carrot post-quantum turnstile (legacy enotes excluded) [web].
- Neptune's Lustration Barrier [web].
- **Where BlackSilk differs:**
  - the witness is a single 32-byte `master`, which 37 keeps as the interface;
  - the circuit is **2 Blake2b-512 compressions plus 2 wide reductions**, because the tag, the 1-byte length and the 32-byte seed fit in one 128-byte block [src `hash.rs`] [est: about 15–25k RV32 cycles];
  - all EC checks are native.

**Consensus impact:**
- Now: none (spec and docs only).
- When activated: CONSENSUS (a freeze of CLSAG and `bridge_in`, a recovery transaction kind, and the turnstile), by activation height through the existing schedule.

**Staged path:**
- S0 (P1, docs): pin preconditions 1–5; state the privacy cost; "migrate early to PX" guidance.
- S1 (P3): a recovery-guest prototype and native checker off-consensus, with vectors.
- S2 (P3): a turnstile and claims-window spec with red-team review.
- S3: activation by height only on an explicit governance trigger.

**What must be proven first:**
- the uniqueness argument for (a), written out and red-teamed;
- that every spend-capable key path goes through `master`, including 37's future passphrase feature (Argon2id into `master`, so the witness stays `master`);
- the cycle count of the Blake2b-512 guest [est → measured].

**Tests (for S1):**
- `recovery_rejects_foreign_seed`;
- `recovery_amount_is_unique_given_mask_derivation` (random `S`, and adversarial `a` with a known log_G(H) in a test group);
- `recovery_rejects_spent_key_image`;
- `turnstile_caps_total_recovered`;
- `recovery_binding_covers_destination`.

**Invariants (never change):**
- I4 preconditions 1–4;
- **precondition 5 (new):** `y = Hs("mask", S)` and coinbase mask 1;
- `k_s` and `k_v` as `Hs(tag, master)` with a 32-byte `master`;
- public v1 coinbase, fee and bridge amounts (the supply must stay computable).

### 3.3 Proof-carrying synchronization and recursion (Plonky3-recursion status)

**The problem.** Everything that scales PX goes through recursion (I1 A5): pruning, aggregation, function hiding (P-8) and the network-level size leak (I3 §3.5).

**F49-2: Plonky3-recursion cannot verify today's BlackSilk proofs as-is.** Primary-source facts, retrieved 2026-09-27 [web]:
- The Plonky3-recursion README: "under active development and hasn't been audited yet … we do not recommend its use in any production software". It verifies `p3-uni-stark` and `p3-batch-stark` proofs, claims "Full support for Zero-Knowledge", and says: "**Field extensions are currently not fully parametrizable.**"
- Its examples offer `--field <koala-bear|baby-bear|goldilocks>` with `--quintic` for **KoalaBear only**. A developer guide describes the challenge field as the degree-4 extension (secondary source).
- Its workspace depends on **Plonky3 0.8.0** (all p3-* crates).
- **BlackSilk uses the BabyBear degree-8 extension** (`params.rs:61-63`) on patched 0.7.0.
- **Consequence:** adoption requires:
  - (i) degree-8 extension support in the recursive verifier (an upstream contribution, or a fork);
  - (ii) the Plonky3 0.8 migration, with the livelock patches re-applied to p3-fri and p3-merkle-tree (not fixed upstream per `Cargo.toml:59`);
  - (iii) a new soundness calculation for the *outer* proof's parameters.

  Moving BlackSilk down to a quartic challenge field is **not** an easy way out. A 124-bit field against traces of up to 2^22 rows leaves little margin under 25's accounting [est; 25 must confirm].

**F49-4: what proof-carrying sync actually saves.** The anchors, at PX capacity (3 PX per block):
- PX verification: 3 × 0.21 s ≈ 0.63 s per block [brief measurement];
- RandomX light verification: 0.45–0.75 s per block, or about 0.1 s in full mode [06];
- v1 verification: milliseconds.

So a proof-carrying sync that offloads only PX proofs cuts IBD CPU by at most about 2× with light-mode PoW, or about 7× with full-mode PoW [math]. Proving RandomX in a STARK is rejected (I1).

**The larger gains are elsewhere:**
- **storage and bandwidth:** proofs are about 92% of PX bytes, and 8 MiB × 720 ≈ 5.9 GB a day at capacity (I1);
- **the ISP-visible upload size** (I3 §3.5);
- **function hiding** (A5c).

**Rank consequence:** PCS is not an IBD-CPU fix. Pruning (§3.5) and wrappers (A5c) are the reasons to do recursion.

**Prior art beyond I1:**
- **RISC Zero:** production BabyBear + Poseidon2 STARK recursion ("lift / join" programs) with a quartic extension [assumed from public docs; not re-fetched].
- **SP1 and OpenVM:** STARK-to-STARK recursion over BabyBear or KoalaBear, then a curve-based final wrap. BlackSilk rejects the wrap (R4), so only the STARK-to-STARK layer is relevant [assumed].
- **leanMultisig / leanVM (Ethereum lean consensus):** a minimal hash-based zkVM "targeting recursion and aggregation of hash-based signatures", on KoalaBear with WHIR, LogUp and SuperSpartan. It targets 2-to-1 aggregation in about 200 ms [web]. This is the closest *post-quantum, hash-only* recursion effort, and a design reference for a narrow, dedicated recursion circuit instead of recursing through BVM-1 (I1: about 25M cycles, not viable).
- **Neptune Cash** (post-quantum, recursive, PoW) had two soundness incidents:
  - **July 2025:** an undetectable inflation bug. Neptune's response was a reboot from a new genesis with a UTXO snapshot [web].
  - **June 2026:** Triton VM v7.0.0 fixed AIR "constraints that were incorrectly gated or, in some cases, missing entirely", plus a flaw in `tasm-lib`'s **recursive verifier**. Neptune added a Lustration Barrier [web].
  - **Lesson for BlackSilk:** a recursion layer is a new soundness-critical circuit. Any design that lets nodes *discard* inner proofs turns an undetected recursion bug into permanent supply uncertainty. So:
    - keep the PX pool turnstile (containment) as a hard invariant;
    - keep inner proofs on archival nodes;
    - never make an aggregate the *only* evidence before a long evidence period.

**Staged path (none consensus until R3):**
- **R0: an off-tree feasibility spike** (policy: its own crate outside the workspace, like the RandomX oracle tooling).
  - Verify one real BlackSilk transfer proof (octic, BabyBear) inside a recursive circuit, either with Plonky3-recursion after porting octic, or with a narrow hand-built verifier AIR.
  - Measure recursive-trace rows, proving time and peak RAM, and the outer proof size under a recursion-friendly configuration (higher blow-up, fewer queries).
  - **Gate:** the outer proof at 100 proven bits under 25's calculator.
- **R1: A5a off-consensus.** Archival nodes publish range proofs that "every PX proof in blocks a..b verified". Nodes may use them only as policy, with full verification as the fallback.
- **R2: A5c wrapper** (function hiding), CONSENSUS, as a new transaction form through the verifier registry. The outer proof must itself be hiding (I1), and 26 must redo the zero-knowledge argument.
- **R3: A5b deferred aggregation plus pruning,** CONSENSUS, only after R1 has run for a long period and the Neptune lessons are designed in.

**What must be proven first:**
- octic support and its constraint count;
- an outer-proof soundness figure from 25's calculator;
- zero knowledge of the outer proof (26);
- an adversarial-proof cost bound for the recursive verifier (as ZK-F4);
- mutation testing of every recursive-verifier constraint (42).

**Pure Rust:** Plonky3-recursion is Rust. Its `unsafe` content (SIMD backends inherited from Plonky3) is third-party and must be counted by 44 [unknown for the new crates].

**Invariants:**
- hash-only soundness in every proof layer (no curve wrap);
- proving never on the mining critical path (I1 D3; A5d rejected);
- the PX pool turnstile;
- `h_tx` binding of inner proofs.

### 3.4 State commitments

**The problem** (R16-9, known):
- There is no committed state, so node divergence is silent.
- There is no trustless snapshot sync.
- There are no light-client membership or non-membership proofs.

R16 already proposes the staging (a node-local digest first, P2-7; activation after the effects model) and 46 owns it. I go further on **what to commit and how**, so that the commitment is post-quantum and privacy-neutral.

**Design space:**

| Component | Candidate | Post-quantum | Prior art | Notes |
|---|---|---|---|---|
| PX commitment tree | its existing root (already computed) | hash | Zcash `hashFinalOrchardRoot` | free |
| PX nullifier set | **indexed Merkle tree** (sorted linked leaves: value, next value, next index; non-membership through the "low leaf") | hash | Aztec nullifier tree [web]; I2's gap tree is the same idea | makes I2 §4.2 reserve proofs and polls consensus-anchored |
| v1 outputs | an append-only MMR of `(one_time_key, commitment, height, coinbase)` | hash | Utreexo-style forests; ZIP 221 MMR | enables verified decoy fetching and snapshots |
| v1 key images | an indexed Merkle tree | hash | as nullifiers | the key-image accumulator I4 called for |
| Header history | an MMR over headers with subtree work | hash | ZIP 221 (`hashChainHistoryRoot`, FlyClient) [web] | FlyClient light clients; a synergy with 31's RX presync sampling |
| Set hash (alternative) | MuHash3072 (Bitcoin assumeutxo) | **no** (discrete-log style) | Bitcoin Core | reject: not post-quantum. LtHash (lattice) is possible but has no membership proofs |

**F49-5: the node() misuse trap applies to every new state tree.**
- 19 showed that BlackSilk's truncated-permutation `node()` is forgeable at zero cost when two adjacent leaves are free: choose `(a, b) = P⁻¹(N ‖ u′)`.
- In the PX tree this is harmless only because every leaf is a commitment proven in the kernel.
- A state tree serving **proofs to light clients** has no such guarantee: the path verifier cannot know that leaves were constrained. An attacker could present a forged non-membership path in a gap tree or indexed tree.
- **Rule:**
  - every leaf of every new tree is `H_leaf(domain, payload)`, recomputed by the verifier from the payload;
  - or node hashing uses a construction that is collision-resistant as a compression function (a sponge with a capacity domain, as Tip5 or RPO do, or feed-forward).
- This must be in the spec before I2's gap tree or any state tree is built.
- **Confidence:** high (it follows directly from 19's argument).

**Where to commit without touching the 100-byte header.**
- Redefine `tx_root := H(TX_ROOT_V2, merkle(tx ids) ‖ state_commitment(parent))` at an activation height.
- Committing the **parent's** post-state (deferred by one) has two benefits:
  - miners need not execute the template to fill it;
  - templates and the block worker stay simple.
- The price: divergence is detected one block later.
- ZIP 221 likewise commits to the history of *prior* blocks [web].
- The alternative, a coinbase field (the contracts.md v2 pattern), changes the coinbase format.
- Both are CONSENSUS.

**Privacy:** the commitments are functions of already-public data. They add no new leakage. Membership *proof queries* to a server would leak: light clients must still fetch data identically (§3.1) or through PIR.

**Staged path:**
- **SC0 (46, P2):** node-local rolling effects digest, compared across labnet nodes (R16 option 1).
- **SC1 (P3, no consensus):** "shadow" accumulators computed by nodes and exposed read-only for tooling (snapshot tool, I2 gap-tree tools), with golden vectors.
- **SC2 (P3, CONSENSUS):** commit `H(px_root ‖ nf_root ‖ out_mmr ‖ ki_root ‖ hist_mmr)` through `tx_root` v2 at an activation height, after 46's effects model exists.

**Proven first:**
- determinism across OS and architecture (08-style digests);
- the leaf-domain rule (F49-5) with adversarial path tests;
- the RAM and IO cost of maintaining an indexed tree of key images (35).

**Tests:**
- `state_root_identical_across_replay_and_restart`;
- `forged_path_with_free_leaves_rejected`;
- `indexed_tree_non_membership_matches_set`;
- `tx_root_v2_commits_parent_state` (vectors).

### 3.5 Efficient verification and proof pruning

**What exists or is decided:** a verified-proof cache (10), parallel verification (10), and batched light RandomX in IBD (06).

**My additions:**
- **PX proof pruning is possible without consensus change** [math, F49-1]:
  - a pruned node keeps `prunable_hash` and drops the proof (Monero pruning precedent, where the tx hash also separates prunable data);
  - archival nodes keep proofs;
  - a service bit is needed (31 and 30);
  - this is the storage fix (about 5.9 GB a day at capacity) that does not wait for recursion.
- **"Assume-valid proofs"** (policy): below a release-embedded, signed block hash, skip STARK, CLSAG and BP+ verification during IBD (Bitcoin `assumevalid` skips scripts), but still check PoW and all contextual rules (key images, nullifiers, anchors, the turnstile).
  - This gives most of what A5a would give for CPU, today, with a stated trust assumption (the release).
  - 31 deferred assume-valid *PoW*; this is a different, smaller thing.
  - P3, policy.
  - I4 suggests SLH-DSA release signing (agreed).
- **Verifier cost structure [est]:**
  - verification is dominated by hashing the opened columns: about 108 queries × about 5,000 columns ≈ 540k field elements, about 67k Poseidon2 permutations;
  - this scales with **opened width**, exactly like proof size (I1-F4);
  - so width reduction (I1 A2; 23 W10) is also the verification lever. SIMD is 27's domain, with its cross-build verdict gate.

**Consensus:** none for pruning and assume-valid.

**Invariants:**
- a node that verifies fully must remain possible and default for archival nodes;
- assume-valid never skips contextual (double-spend) rules.

### 3.6 Efficient private contracts

28 (ADR-28-1) and I1 cover the platform, shape classes, multi-asset (B1), contract tags (B4) and operator-private state. I add only a sizing view.

**The cost driver is the generic zkVM width** (I1-F4). There are three architectural levers:

| Lever | What | Soundness risk | Gain [est] | Prior art |
|---|---|---|---|---|
| Precompile chips inside BVM-1 (a Merkle-path chip; u128 arithmetic) | Keeps "one Rust source" for the kernel logic; moves the hot loops (about 64 Poseidon2 permutations in two depth-32 paths) into narrow dedicated tables | a new AIR per chip | tens of % | SP1 and RISC Zero precompiles; Poseidon2 is already a syscall here |
| Dedicated transfer AIR (I1 A3) | A hand-written circuit for plain transfers | high: a new soundness-critical circuit | 3–8× | Orchard-class circuits |
| Recursion wrapper (A5c) with a narrow outer circuit | The user proves as today, then wraps | the recursion circuit | size down to a few hundred KB [assumed: STARK-to-STARK compressed receipts are hundreds of KB] | RISC Zero succinct receipts; leanVM |

**Recommendation:**
- measure first (27's per-phase profile);
- then the chip route, because it keeps the kernel source single and changes only AIR tables;
- no transfer AIR before R0 (§3.3) answers whether wrapping makes it unnecessary.

**Consensus:** all CONSENSUS (new kernel or zkVM ids through the registry). P3.

**Aztec's 2026 client proofs (Chonk)** are curve-based (I1): not an option under R4.

### 3.7 Privacy-preserving networking

I3, 30 and 33 cover this area in depth. I add one ranking argument and nothing else:
- **The only root fix for the ISP-visible upload** of a 2.2 MB PX transaction (I3 §3.5) is **a smaller transaction**.
- A recursion wrapper (§3.3 R2) is therefore also the network-privacy item with the largest effect: at a few hundred KB, Poisson cover traffic and mixnet transport become affordable [est from I3's arithmetic: cost ∝ cell size].
- Until then, private broadcast (I3 §3.3), transport v2 (30) and the D++ fixes (33) are the right policy work.

No new consensus. No new dependency. SOCKS remains the only anonymity-network boundary.

### 3.8 Safe-Rust RandomX optimization

06 owns this area and its plan is sound: SoA batching for superscalar and dataset work, the narrowed O2, word-indexed scratchpad, and O4′ exact FPU residuals. Decisions reject SIMD crates, a JIT and FMA cfg paths.

**One additional idea: closure compilation of VM programs.**
- The VM already pre-decodes into an `Op` enum with match dispatch (`vm.rs:692-720`).
- A safe-Rust alternative compiles each program once into a `Vec` of specialized closures or function pointers, with operands captured. Each program runs 2,048 iterations, so compilation is amortized.
- Prior art: Feeley & Lapalme, "Using closures for code generation" (1987) [assumed, from the literature]; closure compilation is a standard technique for interpreters written without a JIT.
- **Expected gain:** uncertain and possibly zero on modern branch predictors. Indirect calls replace a jump table.
- **Verdict:** a measurement spike only, after 06's W1/W2 harness, P3.
- It cannot close the JIT gap: about 1–2% of JIT throughput per core (I4 §2.5). That gap is inherent to "no unsafe", and the answer remains I4's J1 (a stratum bridge, owner decision).

**Invariants:** 06's list. Any variant must pass 05's corpus and 08's digests.

---

## 4. New findings

| ID | Severity | Status | Where | Scenario and substance | Confidence |
|---|---|---|---|---|---|
| **F49-1** | Informational (design enabler; corrects I1-F2's trust assumption) | Not implemented | `tx/src/types.rs:432-446`; `tx/src/px.rs:228-287, 379-381`; `chain/src/block.rs:35-37` | A compact feed of prefix + base bytes + `prunable_hash` lets a wallet recompute `tx_root` and detect any omitted or altered output, nullifier or ciphertext, with no new consensus commitment. The same split enables PX proof pruning without consensus | High |
| **F49-2** | Medium (roadmap blocker, not a vulnerability) | Blocked | `zk/src/params.rs:61-63`; `zk/Cargo.toml` (=0.7.0); `Cargo.toml:59` | Plonky3-recursion targets Plonky3 0.8.0 and does not support BabyBear degree-8 extensions ("not fully parametrizable"; quintic only for KoalaBear). BlackSilk's octic 0.7 proofs cannot be verified recursively without upstream or fork work plus a 0.8 migration that re-applies the livelock patches. I1 and I4 treated recursion as "adopt with 0.8"; it is more than a version bump | Medium-high (primary README and workspace Cargo.toml; the degree-4 detail is from a secondary guide) |
| **F49-3** | Medium (correctness of a stated plan; privacy) | Not implemented (spec) | I4-6; `crypto/src/keys.rs:153-158`; `crypto/src/stealth.rs:74-75` | (a) Amount recovery after a DL break is sound only because the mask is `Hs("mask", S)`. This precondition is not on the never-change list. (b) Seed recovery necessarily publishes `k_s` and `k_v`, exposing the wallet's full v1 history to classical observers, contrary to I4's "nothing is lost". A zero-knowledge variant needs about 1.5–3M cycles per output [est]. (c) The turnstile must be capped by the publicly computable v1 supply, and the claim race needs a design decision | High for (a) and (b) [math]; medium for the cost estimate |
| **F49-4** | Informational | Accepted limitation (analysis) | brief measurements; 06 | Proof-carrying sync that offloads PX proofs saves at most about 2× IBD CPU with light-mode PoW. Recursion's value is storage, bandwidth, function hiding and network privacy, not IBD CPU. This re-orders I1's "A5a first" | Medium |
| **F49-5** | Medium (future consensus trap) | Not implemented (spec rule) | 19 §3 (node()); I2 §4.2 (gap tree) | Any tree whose paths are verified by light clients or tools (gap tree, indexed nullifier tree, output MMR) must hash leaves under a leaf domain recomputed by the verifier, or use a compression-secure node. Otherwise non-membership and membership paths are forgeable at zero cost. The rule must precede I2 §4.2 and any state commitment | High |
| **F49-6** | Low (claims, P0 for docs) | Not implemented (docs) | docs/zk.md §17 (I1-F1) | The prior art must also record Neptune's two recursion and AIR soundness incidents (July 2025 reboot; June 2026 Triton VM v7 and `tasm-lib` recursive verifier) and the Lustration Barrier. They are direct evidence for keeping the PX turnstile and the archival inner proofs in any aggregation design | High |

---

## 5. Implementation plan for phase 2

All items are docs, specs or off-tree spikes unless marked. None changes consensus in phase 2.

| # | Item | Files (ownership) | External effect | Identity | Tests | Bench | Docs | Diff | Pri |
|---|---|---|---|---|---|---|---|---|---|
| W1 | **Header-verifiable compact feed** spec input (F49-1), handed to 39 | spec text for 39's design (39 owns `rpc/`, `wallet/` changes) | policy (RPC and wallet) | none | the tests in §3.1 (39) | 39's bandwidth bench | 39's feed spec; invariant "proof bytes only in prunable" in `docs/transactions.md` (47 coordinates) | S (for me) | **P2** (the P1 decision on the format should precede 39's implementation) |
| W2 | **Post-quantum migration plan** document: preconditions 1–5, privacy cost, "migrate early to PX", turnstile cap and claims-window options, recovery statement and cost | new `docs/research/pq-migration.md` (49); never-change entries in the consolidated list (coordinator) | nothing | none | none now; S1 test list recorded | none | yes | S | **P1** (docs) |
| W3 | Pin precondition 5 with a vector | `crypto/src/stealth.rs` tests (**17 owns the derivation vectors**; one added vector) | nothing | none | `mask_is_hash_of_shared_secret_only` plus a coinbase-mask-1 vector | — | the same doc | S | P1 |
| W4 | **Recursion feasibility spike R0** (octic support, rows, time, RAM, outer size, soundness) | new out-of-workspace `tools/recursion-spike/` (49), excluded like `tools/clsag-conformance` | nothing | none | the spike's own tests: verifies a pinned real proof; rejects mutated proofs from 22's corpus | exclusive-window measurement (45's methodology) | `docs/research/recursion-feasibility.md` | L | **P3** (start only after the kernel freeze; needs the golden PX proof fixture from 22) |
| W5 | **State-tree leaf-domain rule** (F49-5) and the accumulator design for SC1/SC2 | `docs/research/state-commitment.md` (49), reviewed by 19 and 46 | nothing | none | adversarial path tests specified for SC1 | — | yes | S–M | **P2** (rule), P3 (design) |
| W6 | Prior-art and claims corrections (Neptune incidents; recursion status; "recursion = 0.8 plus octic") | `docs/zk.md` §17 and §14 (**47 coordinates**, 49 supplies text) | nothing | none | — | — | yes | S | **P0** (claims) |
| W7 | Proof-pruning and assume-valid-proofs policy note | `docs/research/state-commitment.md` §pruning (49); implementation later by 35 and 31 | none | none | future: `pruned_node_serves_prunable_hash`, `assume_valid_never_skips_contextual_rules` | — | yes | S | P3 |
| W8 | RandomX closure-compilation spike | a branch-local benchmark after 06's W1/W2 (06 owns `randomx/`) | nothing | none | 05 corpus, 08 digests | 06's B2/B5 | — | M | P3 |

**Ordering:** W6 and W2 first (claims, then the plan), then W3, W5 and W1. W4 and W8 run after the freeze.

---

## 6. Dependencies and conflicts (by roster number)

- **17 stealth-janus:** W3 adds one vector to its derivation vector set. Precondition 5 constrains any future mask change.
- **19 hash-domain-separation:** F49-5 extends its node() misuse finding to state trees. It should review W5. The hash-agility triggers (19 asks 49): a move away from arithmetization-oriented hashing would re-key every tree and nullifier. The pool-migration pattern (I4 §3.5) is the answer. A recursion layer built on Poseidon2 raises the cost of such a move, and W4 must record it.
- **21 px-nullifiers-commitments:** the indexed nullifier tree in SC1 reuses its nullifier definitions. No change to nullifiers.
- **22 / 25 / 26:**
  - W4 needs 22's golden proof fixture;
  - W4 needs 25's calculator for the outer proof;
  - 26 must own the zero-knowledge argument of any wrapper.
- **23 / 27:** width and SIMD levers (§3.5, §3.6) stay theirs.
- **28:** A5c function hiding is its roadmap stage D. §3.6 levers feed its sizing.
- **30 / 33:** §3.7 only re-ranks. No overlap in files.
- **31:** the header-history MMR (SC2) complements its RX presync sampling. The pruning service bit is shared.
- **35:** pruning and the undo and indexed-tree RAM cost (SC1).
- **37:** keep `master` as the recovery witness (agreed). The passphrase design must mix into `master`, never replace a key derivation.
- **39:** owns the feed. F49-1 changes its trust model from "trusted completeness" to "verified against tx_root".
- **42:** mutation testing of any recursive verifier (W4 follow-up).
- **44:** the dependency review of Plonky3 0.8 and Plonky3-recursion (unsafe counts, no C) before any adoption.
- **46:** owns R16-9 and SC0. W5 is the input to its SC design. `tx_root` v2 placement is its ADR.
- **47:** W6 text.
- **50 red-team:** review W2's uniqueness argument (F49-3a) and the turnstile race; attack SC2's deferred-by-one commit.

**No file conflicts in phase 2:** my own writes are new files under `docs/research/` and the out-of-workspace spike.

---

## 7. Open questions for the coordinator

1. **Recovery privacy (F49-3b):** accept "seed recovery publishes the wallet's v1 keys" as the documented cost, with "migrate to PX early" as the privacy path? Or fund research into an in-circuit EC variant (L–XL)?
2. **Turnstile fairness (F49-3c):** first come, first served, or a claims window with pro-rata settlement? This decision is needed only before mainnet, but the spec should name the choice.
3. **Recursion path (F49-2):**
   - contribute octic support to Plonky3-recursion upstream;
   - fork it;
   - or build a narrow dedicated verifier circuit (leanVM-style)?

   The spike (W4) can compare the first and third options.
4. **The compact feed format (F49-1):** should "the proof lives only in the prunable part" and "the feed carries exact prefix and base bytes" be frozen as protocol invariants now? That is my recommendation.
5. **State commitment placement:** do you prefer `tx_root` v2 (commit the parent state inside `tx_root`, header unchanged) or a coinbase field, for 46's ADR?
6. **Assume-valid proofs (W7):** acceptable as a future policy, given the owner's stance on assume-valid PoW (deferred)?

---

## 8. Sources

**Repository (source-read at `9e422d8`):** listed in §1.

**Recursion and hash-based proof systems:**
- Plonky3-recursion repository and README (WIP, unaudited; batch-stark; "Field extensions are currently not fully parametrizable"; `--quintic` KoalaBear only): https://github.com/Plonky3/Plonky3-recursion ; https://raw.githubusercontent.com/Plonky3/Plonky3-recursion/main/README.md
- Plonky3-recursion workspace Cargo.toml (p3-* 0.8.0): https://raw.githubusercontent.com/Plonky3/Plonky3-recursion/main/Cargo.toml
- The Plonky3 recursion book: https://plonky3.github.io/Plonky3-recursion/
- A developer guide (secondary; degree-4 challenge field): https://hackmd.io/@aiv768/H16FHLn-fe
- leanMultisig / leanVM (hash-based aggregation zkVM; KoalaBear, WHIR): https://github.com/leanEthereum/leanMultisig ; the Lean Consensus 2026 plan: https://hackmd.io/@tcoratger/ryS1ElrWbx

**Neptune Cash:**
- Inflation bug (July 2025): https://neptune.cash/articles/inflation-bug-discovered
- Triton VM v7.0.0, closing soundness gaps (June 2026): https://neptune.cash/articles/triton-air-gaps
- Mutator sets: https://neptune.cash/articles/mutator-sets
- Whitepaper: https://neptune.cash/whitepaper

**Post-quantum migration:**
- ZIP 2005, Quantum Recoverability: https://zips.z.cash/zip-2005
- V. Buterin, "How to hard-fork to save most users' funds in a quantum emergency" (2024): https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901
- BIP-361, Post Quantum Migration and Legacy Signature Sunset: https://github.com/bitcoin/bips/blob/master/bip-0361.mediawiki ; https://bips.dev/361/
- jeffro256, Post-quantum turnstile design for Carrot/FCMP++ enotes: https://gist.github.com/jeffro256/146bfd5306ea3a8a2a0ea4d660cd2243
- Monero FCMP++ (the activation status in secondary sources conflicts, so it is not relied on): https://www.getmonero.org/2024/04/27/fcmps.html

**State commitments:**
- ZIP 221, FlyClient consensus-layer changes: https://zips.z.cash/zip-0221
- Aztec indexed Merkle tree: https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree
- Bitcoin Core assumeutxo and MuHash: cited from general knowledge [assumed]
- Utreexo: cited from general knowledge [assumed]

**Compact and private sync:**
- Project Tachyon roadmap: https://tachyon.z.cash/roadmap/ ; repository: https://github.com/tachyon-zcash/tachyon ; S. Bowe, oblivious synchronization: https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/
- YPIR (USENIX Security 2024): https://www.usenix.org/system/files/usenixsecurity24-menon.pdf
- InsPIRe, ePrint 2025/1352: https://eprint.iacr.org/2025/1352
- PerfOMR, ePrint 2024/204: https://eprint.iacr.org/2024/204
- InstantOMR, ePrint 2025/2317: https://eprint.iacr.org/2025/2317
- UnifOMR, ePrint 2026/910: https://eprint.iacr.org/2026/910
- Oblivious Signaling, ePrint 2026/1975: https://eprint.iacr.org/2026/1975
- OMR, Liu and Tromer: https://eprint.iacr.org/2021/1256

**Private contracts context:**
- Aztec client-side proving and roadmap: https://aztec.network/blog/aztec-network-roadmap-update ; https://aztec.network/blog/inside-an-aztec-transaction

**Interpreters (RandomX §3.8):** Feeley and Lapalme, "Using closures for code generation", Computer Languages 12(1), 1987 [assumed; not re-fetched].

**Previous internal reports relied on:** I1, I2 (F7, §4.2), I3 and I4 in `docs/reviews/full-review-2026-09-27/`; R16-architecture; the research dossiers 06, 19, 22, 25, 27, 28, 30, 31 and 37 in `C:/bszkeval/p2/research/`.
