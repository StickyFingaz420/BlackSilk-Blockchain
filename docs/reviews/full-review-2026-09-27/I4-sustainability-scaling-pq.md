# I4: Sustainability, scalability, post-quantum and decentralized mining (innovation research, internal review, 2026-09-27)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5); RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca). Current: [docs/consensus.md](../../consensus.md), [docs/STATUS.md](../../STATUS.md).

- **Reviewer:** I4 (innovation researcher). This is internal review, not an audit.
- **Tree:** `rebuild/core` family, read-only (the checkout I read is `42320ac` on `agent4b-tx-validation`; the files I cite do not differ from `f677e55` in the parts I read). No builds, no cargo.
- **Inputs:** the brief; R1 (consensus), R2 (crypto), R3 (privacy), R9 (RandomX), R12 (performance); the source files cited below; web sources listed at the end.
- **Evidence tags:**
  - **[math]**: mathematically established;
  - **[test: name]**: covered by the named existing test (not run by me);
  - **[src]**: source-read;
  - **[web]**: from a cited external source;
  - **[est]**: estimate from stated anchors;
  - **[assumed]**;
  - **[unknown]**.

---

## 0. Executive summary

**The single most useful thing to fold into the v3 genesis is the upgrade mechanism itself** (§7):
- an activation-height table;
- a consensus branch id bound into every signature message and the PX binding `h_tx`;
- non-banning handling of future versions.

It costs little now, because the signature message and `h_tx` already hash `network_id` [src: `tx/src/types.rs:276-287`, `tx/src/px.rs:387-404`], and because `h_tx` is a public input, so the kernel ELF and program ids do not change [src: docs/zk.md §5.2]. It changes the economics of everything else in this report: once v3 carries it, shielded coinbase, fee reform, a PoW switch and hash agility can all arrive by scheduled activation, without another identity reset.

**My answers to the six questions:**

| Topic | Recommendation (testnet v3) | Recommendation (mainnet) |
|---|---|---|
| (a) PoW | **Keep standard RandomX v1 (rx/0) for the testnet.** Document K1 as unattainable against any stock JIT miner (R1-C2). Build the "variant plumbing" (salt as a typed network parameter, with the official vectors still exercised) as P2 test-side work. | **Do not launch same-algorithm and non-merge-mined**: that is the worst quadrant for a small chain (I4-1). Choose a **BlackSilk-unique RandomX configuration** (a unique Argon2 salt, which the RandomX authors themselves recommend against hash-power rental), on RandomX v2 if Monero has activated it and the v2 vectors are stable, otherwise on v1. **Reject merge mining.** The JIT question is a separate owner decision (§2.5). |
| (b) Post-quantum | Write the v1 quantum-recovery rule as a spec draft, with a **cheaper construction than R2-C14 assumed**: no elliptic-curve arithmetic in the circuit (I4-6). Pin its preconditions as "never change". Decide R2-C6 (feed-forward) at v3. Optionally add a hybrid ML-KEM step to the P2P handshake (I4-7), which is cheapest now. | Emergency-switch rules specified in advance, PX as the primary store of value, SLH-DSA for signed release manifests, and a documented pool-migration pattern for hash agility. **No PQ signature scheme is needed for PX**: its authorization is already the hash-based STARK. |
| (c) Scalability | Policy-only items (R12): parallel verification, compact wallet scan, incremental wallet tree. | Persistent state and snapshots (mainnet blocker, R12-I5), pruning, assume-valid (policy), compact blocks **that never answer from the stempool** (I4-5), and recursion via Plonky3-recursion, bundled with the Plonky3 0.8 hard fork. **Reject state expiry** for v1. |
| (d) Shielded coinbase | Specify it now. Implement at v3 only if the full analysis → review → tests chain completes before launch; otherwise activate it later by height (needs §7). Wallet mitigations (R3 #4–#6) meanwhile. | **Adopt**, with an improvement over ZIP 213: **coinbase maturity by delayed tree insertion** (I4-8). Mandatory, not optional. Fallback if rejected: coinbase-segregated rings (Monero #6688). |
| (e) Fees and security budget | Nothing consensus-level. Document I4-2 (the PX lane can be congested at a fixed price). | Anchor-indexed uniform base fee (EIP-1559-like, but privacy-neutral), with a partial burn. Keep the fixed block size until persistent state exists. Keep the tail. |
| (f) Finality and upgrades | **Fold the upgrade table plus branch id into v3.** Schedule one **no-op activation** on the testnet to exercise the path. Finality: keep K4 (no limit, warn), and add a halt-on-deep-reorg *policy flag*, off by default. | Halt-on-deep-reorg at K ≥ 720 with an operator override, a finalized/non-finalized state split (bounds the undo held in RAM), and End-of-Service halts for old releases. **Reject** hybrid PoS finality (Crosslink-style) and external timestamping. |

**New findings (not in the brief or R1–R12):**
- **I4-1:** R9 rejects a salt tweak; the RandomX configuration documentation contradicts that. See §2.
- **I4-2:** the PX lane can be congested at a fixed price, with no priority escape. See §6.
- **I4-5:** compact-block reconstruction from the stempool would reveal stem membership. See §4.
- **I4-6:** quantum recoverability needs no in-circuit EC arithmetic. See §3.
- **I4-7:** the P2P transport is harvest-now-decrypt-later exposed. See §3.
- **I4-8:** delayed-insertion coinbase maturity for PX. See §5.
- **I4-10:** `MAX_COINBASE_OUTPUTS = 16` blocks a P2Pool-style decentralized pool. See §2.6.

### 0.1 "Fold into v3 now" versus "later"

**Principle.** The v3 reset is a *testnet* identity change, and mainnet gets its own genesis anyway. So "fold into v3" is justified only when:
- (i) the item is hard or impossible to add later by activation height (because the mechanism does not yet exist, or because it changes the hash of the commitment tree); or
- (ii) the item must be exercised on a real network before mainnet.

| Fold into v3 (low marginal cost) | Why now | Consensus | Diff |
|---|---|---|---|
| F1. Upgrade table (no-op) + branch id in the signature message and `h_tx`; future header versions not banned | Enables every later change without a reset; exercises it on testnet | CONSENSUS | M |
| F2. One scheduled no-op activation on the testnet (for example at v3 height 20,000) | The only way to test mempool flush, peer handling and wallet re-signing across a boundary | CONSENSUS (trivial) | S |
| F3. R2-C6 decision (feed-forward node compression), endorsed | The commitment-tree hash is the hardest thing to change later: it needs a pool migration | CONSENSUS (kernel id) | M |
| F4. R12-2 block-level verification-cost bound, endorsed (it also closes the cheap-deploy fee gap) | Security P1; activation-capable later, but P1 now | CONSENSUS | S |
| F5. Hybrid ML-KEM step in the P2P handshake (optional) | Compatibility with old nodes is irrelevant across the reset | policy (P2P) | S–M |
| F6. PoW: **no change** (keep rx/0) | See §2.4 | — | — |

**Later, by activation height once F1 exists:**
- shielded coinbase (if not ready at v3);
- fee reform;
- RandomX v2 or a unique salt (at mainnet genesis);
- the Hk round increase / pool migration;
- the v1 quantum-emergency rules;
- the finality policy.

---

## 1. Method

- I read the five cited reviews in full and the source files named below.
- I added arithmetic where I could.
- I checked the most load-bearing external claims against primary sources:
  - RandomX `configuration.md`;
  - ZIP 213;
  - ZIP 2005;
  - ZIP 200;
  - the Tari RFC;
  - the Plonky3-recursion book;
  - RustCrypto PQ crate status.
- Where I rely on memory, the claim is tagged [assumed].

---

## 2. (a) The proof-of-work question

### 2.1 What is implemented [src; R9]
- A spec-conformant RandomX v1 (salt `RandomX\x03`, `randomx/src/config.rs:4-7`), verified against the official vectors.
- A safe-Rust interpreter: about 100 ms per full hash and 450–750 ms per light hash per thread, against about 1.4 ms per full hash for the JIT reference.
- A 100-byte header with the nonce at offset 92, and no aux-PoW field.

### 2.2 The decision space

There are two independent axes:
- **algorithm identity:** shared with Monero, or unique;
- **hash-power relationship:** merge-mined, or isolated.

|  | **Merge-mined** | **Isolated** |
|---|---|---|
| **Same algorithm as Monero** | Borrows Monero's security, but a big pool can attack at zero opportunity cost; aux-PoW header; dependence on pools | **Worst quadrant for a small chain:** every rx/0 hash in the world (pools, rental markets, botnets, Qubic-style coordinators) can be redirected with a thin adapter, and nothing is borrowed in return |
| **Unique configuration** | not possible | Rental and redirection need a code change to the miner software and a new market; this is friction, not a guarantee. BlackSilk's security = its own honest hash rate |

BlackSilk today is in the top-right cell.

**I4-1 (MEDIUM, mainnet decision; Accepted limitation for the testnet; confidence high).**
- R9 rejects "parameter tweak (own salt)" because "xmrig adds variants in hours" and "a tweak forfeits the reference audits". R1 lists it as option (b).
- The RandomX authors' own configuration document says: *"We recommend each project using RandomX to select a unique configuration to prevent network attacks from hashpower rental services"*, and for `RANDOMX_ARGON_SALT`: *"Every implementation should choose a unique salt value."* [web: tevador/RandomX doc/configuration.md]
- A **salt-only** change is the variant the designers anticipate:
  - it only re-keys the Argon2d cache fill;
  - every instruction, program, dataset and VM rule stays as audited.
- So R9's "forfeits the audits" is overstated for the salt. It is correct for program-parameter changes (Wownero-style). **Change only the salt, never sizes or frequencies.**
- **R9 is right that a variant does not stop a determined attacker** who patches xmrig. The goal is narrower: stop *zero-effort* redirection of the world's rx/0 hash rate and its rental markets.

**Conclusion on the axes:**
- Merge mining is rejected (§2.3).
- So the coherent mainnet choice is **unique configuration, isolated**.
- Staying on rx/0 while isolated combines exposure with no benefit.

### 2.3 Merge mining: rejected (for mainnet and testnet)

| Risk | Detail |
|---|---|
| Header format | Aux PoW needs a Monero header, a coinbase and a Merkle branch per BlackSilk block: hundreds of bytes. It breaks the fixed 100-byte header, which R1 §4.5 lists as never-change. |
| Seed dependence | Merge-mined RandomX hashes are keyed by *Monero's* seed block. BlackSilk validators would have to track Monero chain data or trust aux fields. That is a cross-chain consensus dependency, which conflicts with determinism and pure self-containment. [src + assumed on the Tari mechanism] |
| Zero-cost attack | A large Monero pool can attack the auxiliary chain without losing any Monero revenue. There is a historical precedent: CoiledCoin, killed in 2012 by a merge-mining pool [assumed, from memory]. |
| Pool centralization | On Namecoin, F2Pool held a majority for prolonged periods [web: Tari Labs merged-mining introduction]. Solo and home miners rarely merge-mine. |
| Privacy | A pool's Monero coinbase carries the merge-mining tag. That links BlackSilk blocks to Monero pool identities and payout patterns: cross-chain miner clustering, the opposite of the R3-2 fix. |
| Precedent | Tari runs **both** a merge-mined RandomX lane and a Tari-native RandomX lane, among four PoW lanes of 25% each [web: Tari tokenomics; RFC-0131]. That is multi-algorithm complexity, which BlackSilk should not copy for a first mainnet. |

### 2.4 Testnet v3: keep rx/0 (no fold)

**Reasons:**
1. The trial is controlled: no seed nodes, explicit `--peer` lists [src: docs/testnet-reset-plan.md §3]. An outsider needs the binary, the genesis and peer addresses. The rental threat has no target of value.
2. The mainnet PoW is undecided. RandomX v2 was released on 2026-03-30, but Monero's v17 activation has no date [web: Monero PR #10038; Monero X post]. A salt change now would be churn if mainnet moves to v2.
3. rx/0 keeps the official vectors as the direct pin of the consensus path.
4. The testnet *should* observe the realistic threat (third-party JIT) rather than hide it.

**Actions:**
- P0 (docs, with R1): K1 is unattainable against stock rx/0 miners.
- P2: make the salt a typed per-network parameter, for example `enum PowConfig { Monero_v1, BlackSilk_v1 { salt } }`, so that the official vectors keep running in `Monero_v1` mode.
- P2: produce BlackSilk-salt vectors **offline** with the reference implementation compiled with the new salt. This is test tooling only, and nothing C/C++ enters the build. Cross-check the vectors with the Rust implementation.
- Consensus: none now. Identity: none now.

### 2.5 The JIT gap (R1-C2) and "an optional reviewed JIT miner"

- **Facts:**
  - Security depends on honest hash rate, not on which software produces it (R9 §4.4).
  - The node, which is the trust anchor, verifies every hash in safe Rust, so miner software is untrusted by design.
- **Consequence:** the official safe miner will earn about 1–2% of what a JIT miner earns on the same hardware. Rational honest miners will run JIT miners anyway.
- **Decentralization argument:** if only sophisticated actors can mine competitively, hash power concentrates in *them*. **Giving honest miners the same tool is decentralizing.**
- **The options for the owner (mainnet, P3):**
  - (J1) **Document and tolerate third-party miners.** Optionally ship a small pure-Rust *stratum bridge* in the miner crate, so that stock JIT miners can mine against a local node. It holds no unsafe code; the C/C++ stays in the user's own miner. Cheap (S–M), policy only. It also lowers the barrier for attackers, but they have no real barrier today anyway.
  - (J2) **An isolated Rust JIT crate** outside the consensus workspace, with `unsafe` confined to one module (W^X page mapping and a call into the generated code).
    - Consistent with CLAUDE.md §12.2 ("restrict unsafe to technically justified, reviewed, documented"), but **in conflict with the brief's "no unsafe in project crates"**. The owner must reconcile the two.
    - Safety design: **every found block is re-hashed by the safe interpreter before submission.** A JIT bug can then only cost the miner revenue; it can never produce an invalid block or touch consensus.
    - Effort: XL (porting about 3–5k lines of reference JIT per architecture) [assumed].
  - (J3) Faster safe interpreter (R9 O1–O6): 5–15× short of JIT. Do it anyway, because it also helps verification.
- **Recommendation:** J3 (P2) plus J1 (P3, owner). J2 only if the owner explicitly relaxes the unsafe rule for non-consensus binaries.

### 2.6 Decentralized mining beyond the algorithm

- **Pools.**
  - The miner already builds its coinbase locally, and the payout address never reaches the node [src: R3 §4.6]. That is the right primitive for Stratum V2-style job declaration (miners choose transactions) [assumed on SV2 details].
  - **I4-10 (INFO):** `MAX_COINBASE_OUTPUTS = 16` [src: `tx/src/params.rs:52`] rules out a Monero-P2Pool-style decentralized pool, which pays many miners directly in the coinbase. That is a privacy positive: Monero research-lab #109 documents the decoy waste P2Pool outputs cause. A decentralized pool for BlackSilk should instead pay through PX (after §5), in batches of 16 bridge-out payouts or as PX records.
  - Design this only after §5. P3.
- **Anchor miner** (R1): acceptable for the testnet if disclosed. Never for mainnet.

**Recommendation table (a):**

| Item | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff | Pri |
|---|---|---|---|---|---|---|---|---|---|
| Keep rx/0 on the testnet; document K1 | honest limitation | 0 | 0 | 0 | none | none | no | S | P0 (docs) |
| Typed PoW config plus offline salt-variant vectors | makes the mainnet choice cheap and safe | + | 0 | 0 | low | none | no | S–M | P2 |
| Mainnet: unique salt (on v2 if activated upstream), isolated | leaves the worst quadrant | + (friction against rental) | 0 | 0 | low | CONSENSUS | mainnet genesis | S | P3 (decide before mainnet) |
| Reject merge mining | header, seed dependence, centralization, privacy | + | + | — | — | — | — | — | — |
| J1 stratum bridge / J2 isolated JIT | decentralization of competitive mining | 0 / + (verify-before-submit) | 0 | + | low / very high | none | no | S–M / XL | P3, owner |

---

## 3. (b) Post-quantum migration

### 3.1 Exposure recap (R2 §11, R3-12; not repeated)
- v1 is fully DL-based: theft, inflation and retroactive tracing.
- PX ownership, nullifiers and the STARK are hash-based (PQ-plausible).
- PX delivery is hybrid; its view tag is EC-only (R2-C8).
- The v1 → PX bridge lets post-Q v1 inflation dilute PX.

### 3.2 I4-6: quantum recoverability without in-circuit EC arithmetic (refines R2-C14)

- **Classification:** Not implemented (research track). Positive finding.
- **Confidence:** high on soundness in the ROM [math sketch]; medium on cost [est].

**R2 §11.2 sketches a STARK proving** `O = (Hs(k_v·R) + k_s + m)·G`, which implies non-native Ristretto scalar multiplication inside a BabyBear circuit (very expensive). ZIP 2005 likewise requires EC additions in its recovery circuit [web: ZIP 2005]. For BlackSilk v1, a cheaper statement suffices, because **after Q-day `k_s` and `k_v` are not secret anyway**.

**Recovery statement** (one proof per wallet, reusable across its outputs):
- **Public:** `k_s`, `k_v`, and the destination binding (for example the PX output commitments, or `h_tx`).
- **Witness:** `seed` (32 bytes).
- **Proved:** `k_s = Hs("wallet/spend-key", seed)` and `k_v = Hs("wallet/view-key", seed)` [src: `crypto/src/keys.rs:153-158`].
- **Checked natively by consensus, for each claimed output `O` with tx key `R`, account `a` and index `i`:**
  - `m = Hs(k_v ‖ a ‖ i)`;
  - `S = k_v·R`;
  - `x = Hs(S, …)`;
  - `O == (x + k_s + m)·G`;
  - key image `I = (x + k_s + m)·Hp(O)` not in the key-image set.

**Soundness sketch [math, ROM]:**
- A DL-capable adversary knows every `p = log O`, and the victim's `k_s` and `k_v`. It does not know `seed`, and a hash preimage is needed (Grover ≈ 2^128 on a 256-bit seed; BlackSilk seeds are 32 bytes, 24 words [src: `wallet/src/wallet.rs:322-342`]).
- **Using its own seed\*** means satisfying `O = (Hs(k_v*·R…) + k_s* + m*)·G` for a victim's `O`. That is a random-oracle equation, succeeding with ≈ 2^-252 per trial.
- **Replay or redirect** is prevented by putting the destination into the proof binding.

**Cost [est]:**
- The circuit is two Blake2b-512 compressions plus two wide reductions mod ℓ in BVM-1: roughly 10–50k RV32 cycles, far below `MAX_CYCLES` = 2^21. So it is **an ordinary PX-class proof (~45 s)**, not the "expensive, emergency-only" circuit R2 assumed.
- The EC work (`k_v·R`, one multi-base check per output) is native and cheap.
- **Privacy:** revealing `k_v` and `k_s` links all of the wallet's outputs. After Q-day v1 privacy is already gone, so nothing is lost.

**Preconditions to pin as "never change" (P1, docs, now):**
1. Every spend-capable v1 key is `Hs(tag, seed)` from a 32-byte seed. Never add spend-capable raw-key import without flagging those outputs as non-recoverable (agrees with R2).
2. The `m(a, i)` and `x` derivations are fixed.
3. The seed is never derived from a low-entropy source (brain wallets are forbidden).
4. The PX `sk = Hk(SK, seed)` link is kept, so one seed recovers both layers.

**The emergency rule** (R2 phase 2, specified in advance and activated by height through F1):
- freeze CLSAG spends and `bridge_in`;
- allow v1 → PX only through the recovery proof.
- It must activate **before** a CRQC is credible. After that, theft through ordinary CLSAG spends is possible. This is a governance or monitoring question, not a crypto one.
- Consensus: CONSENSUS, later. Identity: no (with F1). Difficulty: M (guest + native checks + review). Priority: P1 for the spec draft; P3 for the implementation.

### 3.3 PQ signatures for PX: not needed; where PQ signatures do fit

- **PX already has PQ authorization.** Spend authority is a STARK proof of knowledge of `sk` with `owner = Hk(OWNER, ak‖nk‖d)`, bound to `h_tx` [src: docs/px.md §4, zk.md §5.2]. That is a hash-based signature in effect (Picnic-style). **Adding ML-DSA or SLH-DSA to PX would add bytes and a new unaudited primitive for no gain.** Reject.
- **Where a PQ signature does fit:**
  - **Release manifests and assume-valid / fast-sync hash lists** (§4, §7). Use SLH-DSA (FIPS 205): hash-based, stateless, the most conservative assumption. Its large signatures (~8–50 KB) do not matter off-chain.
  - RustCrypto `slh-dsa` and `ml-dsa` are pure Rust, tested against NIST vectors, and **never independently audited** [web: RustCrypto, docs.rs]. `libcrux-ml-dsa` (Cryspen) is a formally verified alternative [assumed on its pure-Rust status].
  - Consensus: none. Priority: P3 (with the release process).
- **Contracts:** membership tags are DDH-linkable and not PQ (R2 §7). If contracts ever integrate, prefer Hk-keyed tags in the PX style. P3.

### 3.4 I4-7: P2P transport is exposed to harvest-now-decrypt-later

- **Classification:** Accepted limitation (to document); optional fix.
- **Severity:** LOW (the global passive adversary is a stated non-goal, N2).
- **Evidence:** [src: `p2p/src/transport.rs:1-20`: unauthenticated ephemeral Ristretto DH plus AES-256-GCM].
- **Scenario:** an adversary records a node's links today. After Q-day it decrypts them and learns which peer first sent which transaction: the Dandelion++ stem origin, retroactively.
- **Fix:** hybrid handshake: `key = H(ss_dh ‖ ss_mlkem768 ‖ transcript)`. OpenSSH (mlkem768x25519) and Signal (PQXDH) did the same [assumed].
- **Cost:** about 1.2 KB of encapsulation key plus 1.1 KB of ciphertext per handshake, and tens of µs of CPU [assumed].
- **Dependency:** `ml-kem` is already in the tree (unaudited, R2-C12).
- **Attributes:**
  - fold into v3 (F5) if the A8 P2P work allows, since cross-version compatibility is irrelevant at a reset;
  - consensus: none (P2P);
  - identity: no;
  - difficulty: S–M;
  - priority: P3, or P2 if cheap.
- **Tor note:** Tor circuits are not PQ today, so onion users are not protected by this change [assumed].

### 3.5 Hash agility for Poseidon2 (R2-C7)

**Agility in practice means a pool migration:**
- The commitment tree and its records are defined by `Hk`.
- Changing `Hk` (more rounds, width 24, or feed-forward) produces a new tree. It cannot re-hash old records.
- The proven pattern is Zcash's **Sprout → Sapling → Orchard**: a new pool with its own tree, nullifier set and turnstile, and a migration transaction that spends an old-pool record and creates a new-pool record [assumed; well-known Zcash history].

**What v3 needs to make this cheap later:**
- **Nothing structural.** A new transaction kind (kind 4) with its own state already gives this. The PX pool turnstile (`px/src/state.rs`, "pool never negative") generalizes per pool.
- **Decide R2-C6 at v3 (F3).** A tree hash that must later be migrated because of a known structural caveat is the most expensive kind of agility. Fixing it now costs one kernel-id change, which the reset absorbs.
- **Version the domain constants** (`BASE`) and the kernel id in the docs, as R2 proposes. P2, S.

---

## 4. (c) Scalability without losing privacy

The binding constraints are R12's: RAM O(chain), restart revalidation, light-hash IBD, and 2.2 MB PX proofs. I evaluate each technique for privacy impact, which is my addition.

| Technique | Privacy impact | Feasibility (pure safe Rust) | Consensus | Verdict |
|---|---|---|---|---|
| **Pruning** of the prunable section (CLSAG, BP+, PX proof) after depth D | none; archival nodes needed for IBD | yes (M–L) | none | **Adopt for mainnet** (P3). Needs a service bit and enough archival nodes. |
| **State expiry, v1** | — | — | would break soundness | **Reject.** Rings reference outputs by global index forever, and key images must be kept forever or double spends become possible. |
| **State expiry, PX nullifiers** | neutral in principle | needs epoch-scoped anchors plus record migration (Tachyon-like) | CONSENSUS | **Defer (P3, research).** The PX consensus state is already small: a frontier, 100 roots and a 32-byte-per-spend nullifier set [src: `px/src/state.rs:40-46`]. The RAM problem is the logs and ciphertexts (R10-7), which are not consensus. |
| **Snapshots / assume-valid** | none | yes | policy | **Adopt as policy for mainnet** (P3): a release-embedded block hash below which PoW, signatures and proofs are skipped (Monero fast-sync style), signed with SLH-DSA (§3.3), overridable. A consensus-level state commitment (trustless snapshots) would need a key-image accumulator: defer. |
| **PX proof aggregation / recursion** | none (no witnesses move; aggregation-study §3.3) | Plonky3 now has a recursion project (`Plonky3-recursion`, batch-STARK verification in-circuit, a zero-knowledge FRI verifier) [web]. It tracks newer Plonky3, so adoption **couples with the 0.8 upgrade, which is already a hard fork** [assumed on version coupling] | CONSENSUS | **Plan as one milestone with the Plonky3 upgrade** (P3, XL): one hard fork, one review. |
| **Compact blocks** (BIP 152-style short ids) | **I4-5 (new): a privacy trap.** If a node rebuilds a compact block from its *stempool*, it does not request the stem transaction, so the relaying peer learns the node was on that transaction's stem before fluff. That is stem-membership disclosure. | yes | none (P2P) | **Adopt only with the rule "reconstruct from the fluff mempool only; stem transactions are requested like unknown ones"** (P3). How Monero's fluffy blocks treat stempool transactions is [unknown] to me; check before copying. |
| **Wallet compact-scan feed** (R12-7) | neutral **only if unfiltered**: every wallet gets every block's scan data. No per-wallet filters or view-tag server matching. ZIP 307 lightwalletd is the precedent for the format, and its privacy limits come from server-side queries [assumed]. | yes (S–M) | none | **Adopt** (P2). Long-term, look at Zcash Tachyon's oblivious synchronization [web]. |
| **Parallel verification** (R12-11) | none | yes (`std::thread::scope`) | none | **Adopt** (P2). The verdict is deterministic; report the lowest failing index. |
| **Dynamic block size** (Monero penalty) | none | yes | CONSENSUS | **Reject until persistent state exists.** RAM is O(chain) × 4.5 (R12-1); a growing block size multiplies the binding constraint. Revisit after I5. |

**Answers for (c):**
- **What should never change:** full validation of received blocks, and unfiltered wallet download.
- **Before the testnet:** nothing new beyond R12's list.

---

## 5. (d) Shielded coinbase into the PX pool (evaluating R3-11)

### 5.1 Design (a ZIP 213 analogue, adapted)

**Coinbase part.** The coinbase may carry k ≤ `MAX_COINBASE_OUTPUTS` **PX coinbase records**. Each publishes:
- `owner`, a fresh diversified owner tag per block;
- `value`;
- `rcm`.

**Fixed by consensus:**
- `contract = 0`, `asset = BLK`, `data = 0`;
- `rho = Hk(RHO_COINBASE, height ‖ j)`, in a new domain, distinct from the transfer `RHO`.

**Nodes:**
- recompute `cm = Hk(RECORD, …)` natively (a few Poseidon2 permutations);
- check B3 exactly: v1 coinbase outputs plus PX records = reward + fees;
- add `pool += value`.

**The kernel is unchanged** [src: docs/px.md §3–4]:
- a coinbase record is an ordinary leaf, spent by proving membership and `owner = Hk(OWNER, ak‖nk‖d)`;
- its nullifier `Hk(NULLIFIER, nk ‖ rho ‖ cm)` needs `nk`, so publishing `owner`, `rcm` and `value` does **not** link the later spend [math]. This is ZIP 213's argument [web: ZIP 213].

**Faerie Gold:** heights are unique on a chain, and the separate domain keeps `rho` disjoint from transfer `rho` values. `nf` covers `cm` [math].

**I4-8: maturity by delayed insertion (improves on ZIP 213).**
- ZIP 213 drops coinbase maturity for shielded outputs because enforcing it at consensus "would incur significant complexity" [web].
- But maturity protects *third-party payees*. A transfer can be re-mined after a reorg; a coinbase cannot.
- In BlackSilk the fix is simple: **append coinbase-record commitments to the tree only at height h + COINBASE_MATURITY**, from a consensus queue of at most 60 × 16 entries.
  - The queue is part of `PxState` and of its undo.
  - A record is unspendable until inserted, so no proof or kernel change is needed and no spend metadata is revealed.
- Cost: S on top of the design.

### 5.2 Benefits
- **v1 rings (R3-1, R3-3):** coinbase outputs leave the ring set entirely.
  - The "all 15 decoys are coinbase" failure (40% of rings on a quiet chain) and the maturity-induced young-decoy hole disappear at the root.
  - R3-2 (nonce clustering) no longer yields spend linkage.
- **PX anonymity set:** it grows by at least 720 records per day for free, versus about 40 per day at 20 PX/day (R3 §2.2).
- **Post-quantum:** new emission never touches the DL-based layer. That makes the §3.2 emergency rule matter only for legacy v1 value, and it makes PX the natural store of value (R2 phase 1).

### 5.3 Costs and risks
- **Miner spend cost.** Spending coinbase value needs a PX proof: ~45 s and 3.8 GB.
  - Fine for pools and for desktop miners.
  - It excludes low-RAM miners from spending without a helper, but proving is local-only (R12), so they need a bigger machine.
- **PX capacity.** 3 PX per block (R12-10); miners' spends compete with users.
  - Pools batch payouts: one PX transaction can carry 16 bridge-out payouts [src: `MAX_PAYOUTS = 16`]. About 1 PX transaction per pool per block suffices.
  - Solo miners consolidate: 2-in/2-out.
  - Under I4-2 congestion, miner spends are blocked too, so I4-2 must be solved before mainnet.
- **v1 bootstrapping.** New v1 outputs come only from PX withdrawals and v1 transfers. On a young chain the non-coinbase set is small, so rings are drawn from few outputs.
  - The wallet needs a minimum-set guard (R3 §6): refuse v1 spends while fewer than N eligible outputs exist, and route users to PX.
- **Bridge-out amount privacy.** Miners exiting to v1 publish amounts (R3-8). Same as today's clear coinbase amounts: no regression.
- **Pool containment.** The PX pool now includes emission, so "a proof-system break cannot withdraw more than was deposited" becomes "… more than deposits plus coinbase value". It is a weaker bound in absolute size, but still a bound.
- **New consensus surface:**
  - a value check without a proof;
  - the delayed queue and its undo;
  - B3 across two output types.
  - All need the full analysis → review → tests chain and adversarial tests: wrong `cm`, a reused `rho`, the queue across a reorg, and B3 off by one.

### 5.4 Mandatory or optional?
**Mandatory.**
- An optional PX coinbase keeps coinbase outputs in v1 rings, so the R3 problems remain.
- Zcash made shielded coinbase optional to allow gradual migration [web: ZIP 213]. BlackSilk has no installed base to migrate.

### 5.5 Alternative if the owner rejects shielded coinbase
- **Coinbase-segregated rings:** a consensus rule that a ring is either all-coinbase or all-non-coinbase (Monero issue #6688; research-lab #109) [web].
- Feasible at S: `OutputRecord` already has a `coinbase` flag [src: `tx/src/validate.rs:38,315`].
- It fixes R3-3 and the maturity hole, but it keeps DL-based emission. It shares the bootstrapping problem of §5.3.

### 5.6 Recommendation (d)

| Item | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff | Pri |
|---|---|---|---|---|---|---|---|---|---|
| Specify shielded coinbase with delayed insertion now; implement at v3 if the review chain completes, else activate by height (needs F1) | R3-1/-3 at the root; PX set growth; PQ | new surface, contained by B3 and the pool bound | **high +** | node: negligible; miners: +1 PX proof per spend | high | CONSENSUS | fits v3, or none with F1 | L | P2 (the decision at v3 is P1) |
| Fallback: segregated rings | if the above is rejected | 0 | + | 0 | low | CONSENSUS | v3 | S | P2 |
| Meanwhile: R3 #4–#6 wallet mitigations | no consensus | 0 | + | 0 | low | none | no | S–M | P1 (R3) |

---

## 6. (e) Fee market and the long-term security budget

### 6.1 What is implemented [src]
- **Emission:** a smooth curve to a 0.6 BLK/block tail from block 3,678,315 (about 14 years); 157,680 BLK/year, 0.77% in the first tail year and falling [src: `chain/src/emission.rs`, docs/blocks.md §2].
- **v1 fees:** a consensus minimum of 20 atomic units per weight unit; wallets pay a deterministic standard fee.
- **PX fees:** exactly `PX_STANDARD_FEE` = 0.089 BLK.
- **Deploys:** 2 atomic units per byte.
- **Block limits:** fixed at 600,000 weight plus 8 MiB PX.
- **Fees go to the miner:** B3 exact equality.

### 6.2 Assessment

**Security budget:**
- Early issuance is 14,400 BLK/day. At the tail it is 432 BLK/day.
- Maximum fee revenue at the consensus minimum, with full blocks: v1 0.119 + PX 0.267 = **0.386 BLK/block**, about **64% of the tail reward** [math, from R12 §2].
- The tail keeps the budget from being fee-dominated. That addresses the undercutting and instability results of Carlsten et al. (CCS 2016) [web], and it is Monero's rationale [web: Moneropedia].
- **Keep the tail and B3 exactness** (never change, agreeing with R1).

**I4-2: PX lane congestion at a fixed price.**
- **Severity:** MEDIUM for mainnet, LOW for the testnet.
- **Classification:** Partially implemented (no congestion mechanism).
- **Confidence:** high [src + math].
- **Mechanism:**
  - Every PX transaction pays the same exact fee.
  - Sizes vary by less than 1% (P-5).
  - The mempool admits a transaction into a full class only by evicting *strictly* cheaper entries, and templates order by rate, then first seen [src: `chain/src/mempool.rs:244-262, 354-356`].
  - So honest users cannot outbid a spammer.
- **Attack:**
  - An attacker keeps the 64 MiB PX class full (about 29 transactions) and refills the 3 slots per block.
  - Cost: **0.267 BLK/block ≈ 192 BLK/day** in fees, plus about 1.1 cores of proving [math; R12].
  - That is about 1.3% of early daily issuance, and about 44% of daily issuance at the tail.
  - A miner doing this in its own blocks pays nothing net: fees return to it (R12-1 self-stuffing).
- **Effect:** private payments are censored by congestion. After §5, miner spends are censored too.
- **This deepens but differs from the known items:** "global PX relay budget exhaustible" is P2P, and "deploys act as cheap transfers" is pricing.

**I4-3 (LOW, mainnet design):**
- Fees are fixed in atomic units, so their real cost scales with the BLK price, and nothing adapts.
- Monero moved from fixed to dynamic fees for exactly this reason [web: JollyMort dynamic block size/fee research].

### 6.3 Proposal: an anchor-indexed uniform base fee (mainnet, P3, CONSENSUS)

The goal is to keep the privacy property "every transaction in a class pays the same fee" (R3, P-7), while giving congestion a price and making self-stuffing costly.

**Rule:**
- `base_fee(h)` follows recent PX-lane (and v1-lane) fullness, EIP-1559-style.
- It is bounded per step, and computed only from ancestor blocks: deterministic, integers only.
- **A PX transaction must pay exactly `base_fee(anchor_height)`.** The anchor is already public, with 16-block granularity [src: R3 §4.2], so the fee reveals nothing beyond the anchor.
- A v1 transaction would need a declared fee epoch. That is a new public field with about the same information as its newest ring member's age; review it for fingerprinting first.

**Partial burn** (a fraction of the base fee is not paid to the miner):
- B3 becomes `coinbase = reward + fees − burned`, still exact and auditable.
- Burning makes self-stuffing cost real value. That fixes the R12-1 "free for the miner" gap.
- It reduces the security budget only in proportion to fees; the tail remains.

**Priority escape:** under sustained congestion, a small fixed set of multipliers (for example ×1, ×2, ×4, as Monero's priority levels) buys priority at a cost of ≤ 2 bits of fingerprint per transaction. **Owner trade-off.** The default is ×1 only.

**Before then:**
- document I4-2 (P2);
- consider mempool expiry (known) plus a per-source PX admission cap (policy) to raise the attacker's cost.

**What should never change:** the tail, B3 exactness, height-only `reward(h)`, and uniform fees within a class.

---

## 7. (f) Finality, deep-reorg policy and the upgrade mechanism

### 7.1 Upgrade mechanism: fold into v3 (F1, F2)

**Mechanism (ZIP 200 model [web]):**
- `ChainParams.upgrades = [(name, activation_height, header_version, branch_id)]`.
- `header.version == version_at(h)`.
- The branch id enters:
  - the v1 `signature_message`, next to `network_id` [src: `tx/src/types.rs:276-287`];
  - PX `signature_message` and `binding` (`h_tx`) [src: `tx/src/px.rs:387-404, 552-557`].

**Why the marginal cost is low now:**
- These hashes already include `network_id`, so the change is one more 4-byte field in the hash input.
- `h_tx` is a public input computed outside the circuit (zk.md §5.2), so **the kernel ELF and program ids do not change**.
- The v3 reset absorbs the identity change.

**Operational rules (from ZIP 200):**
- before activation, do not accept transactions valid only after it;
- at activation, clear the mempool of transactions bound to the old branch;
- validate every block under the branch expected at its height;
- R1-C10: an unknown *higher* header version is non-permanent and not banned, with a loud "upgrade required" WARN;
- End-of-Service: releases halt about N weeks after their expected lifetime, so un-upgraded nodes stop instead of following a minority chain (zcashd precedent) [assumed on the EOS details].

**Explicit branch-id field in transactions?** ZIP 225 puts it in the v5 transaction [assumed]. Here, implicit binding is enough: all transactions in an epoch carry the same value, and old-branch transactions fail cheaply at the mempool flush. Optional. If added, it is a constant per epoch, so it is not a fingerprint.

**Rejected: transaction expiry heights (ZIP 203-style).**
- A per-wallet expiry value is a fingerprint, like the `unlock_time` BlackSilk deliberately removed.
- Use policy-level mempool expiry instead.

**F2: exercise it.** Schedule one no-op activation on the testnet (for example at v3 height 20,000, about 28 days). The test plan:
- mempool flush;
- pre-built transactions signed for the old branch are refused after activation;
- wallet re-signing;
- a node without the upgrade entry stops with a clear message and is not banned.

**Privacy note (R1 §4.4):** a contentious split with shared history lets key images be spent on both chains with different rings. The wallet must reuse stored rings (W-5). The branch id prevents replay, not ring intersection. Document it.

| Attribute | F1 |
|---|---|
| Why | every later consensus change without a reset; replay protection |
| Security | + |
| Privacy | 0 (+ against replay) |
| Performance | 0 |
| Complexity | low–medium |
| Consensus | **CONSENSUS** |
| Identity | fold into v3 |
| Difficulty | M |
| Priority | **P1** (before the v3 genesis) |

### 7.2 Finality and deep reorgs

**Current (K4):** no depth limit, WARN at 10; all undo data in RAM. This is fine for the controlled testnet.

**The threat on the mainnet path:** with any rx/0 or small-chain PoW, a rented majority rewrites history cheaply (R1-C2, Qubic 2025). The options:

| Option | Assessment |
|---|---|
| No limit (K4) | Honest convergence, but no protection from a rented majority. Unbounded undo in RAM. |
| **Halt on deep reorg** (zcashd `MAX_REORG_LENGTH` = 99; Zebra finalizes below 99) [R1 sources] | Bounds rewrite damage and **bounds undo structurally**: a finalized/non-finalized split fixes PX-F2. Cost: a visible partition needing an operator decision. **Recommended for mainnet**, with K ≥ 720 (1 day), halt plus `--accept-deep-reorg <id>` rather than a silent refusal, and a decision on K from testnet data. |
| Checkpoints / assume-valid | Checkpoints add a trust point in validity. Keep assume-valid as a *sync* shortcut (§4), not as finality. |
| Hybrid PoS finality (Zcash Crosslink) | **Reject.** It adds staking, a validator set whose identities and stakes are a privacy and centralization surface, BFT networking and XL complexity. Crosslink itself has no ZIP number, activation height or mainnet date as of August 2026 [web]. |
| External timestamping (Bitcoin-anchored, Babylon-style) | **Reject.** It creates an external chain dependency and a new trust model; not self-contained. |

**For the testnet:** add the halt as a policy flag, **off by default**, so operators can rehearse the incident procedure. Consensus: policy. Identity: no. Difficulty: M. Priority: P3 (the flag P2).

---

## 8. Rejected ideas (with reasons)

| Idea | Reason |
|---|---|
| Merge mining with Monero | §2.3: breaks the 100-byte header, creates a Monero-seed dependency, zero-cost pool attacks, pool centralization, cross-chain miner linkage |
| RandomX program or size tweaks (Wownero-style) | Leaves the audited design; salt-only is the designer-endorsed variant |
| Equi-X or another algorithm as the consensus PoW | Agree with R9: not memory-hard at the RandomX level |
| Multi-algorithm PoW (Tari-style lanes) | Complexity; per-lane difficulty; the weakest lane sets security |
| PQ signatures (ML-DSA/SLH-DSA) inside PX | PX authorization is already hash-based via the STARK |
| Lattice ring signatures for v1 | Agree with R2: a large unreviewed construction; PX is the PQ path |
| State expiry for v1 outputs or key images | Breaks rings and double-spend protection |
| Dynamic block size before persistent state | Multiplies the binding RAM constraint |
| Transaction expiry-height field | A fingerprint; mempool expiry by policy instead |
| Optional (not mandatory) shielded coinbase | Keeps coinbase outputs in v1 rings |
| Hybrid PoS finality; Bitcoin timestamping | §7.2 |
| Delegated proving for PX | Agree with R12: breaks witness privacy |
| Compact blocks answering from the stempool | I4-5: stem-membership leak |

---

## 9. The 13 questions (condensed, for my topic group)

1. **Implemented:**
   - rx/0 RandomX, safe Rust;
   - fixed limits and fixed fees;
   - tail emission;
   - network-id binding in signatures and in `h_tx`;
   - a single header version;
   - the K4 no-limit policy;
   - hash-based PX ownership and a hybrid PQ delivery;
   - seed-derived v1 keys.
2. **Correct and well designed:**
   - the tail plus B3 exactness;
   - uniform PX fees;
   - the network id in every signature;
   - hash-derived keys, which make quantum recovery possible;
   - the small PX consensus state;
   - the 100-byte header;
   - miner-local coinbase construction.
3. **Incomplete:** the upgrade mechanism; PoW configuration typing; the recovery spec; fee congestion handling; the finality policy.
4. **Fragile:**
   - same-algorithm isolation (I4-1);
   - fixed-price PX lane (I4-2);
   - fees fixed in atomic units (I4-3).
5. **Exploitable:**
   - rented or redirected rx/0 majority (R1-C2, I4-1);
   - PX lane congestion (I4-2);
   - miner self-stuffing (R12-1).
6. **Inefficient:** safe interpreter mining (J3).
7. **Does not scale:** R12's list. PX consensus state scales well; logs, ciphertexts and v1 state do not.
8. **Missing:**
   - F1;
   - shielded coinbase;
   - SLH-DSA-signed release manifests;
   - a finality policy;
   - a hybrid P2P KEM.
9. **Redesign:** the fee rule for mainnet (§6.3); the coinbase (§5).
10. **Innovate:**
    - recovery without in-circuit EC (I4-6);
    - delayed-insertion maturity (I4-8);
    - an anchor-indexed uniform base fee (§6.3);
    - verify-before-submit JIT isolation (J2);
    - stempool-safe compact blocks (I4-5).
11. **Before the testnet:**
    - F1 and F2 (P1);
    - the F3 decision (P1, R2);
    - F4 (P1, R12);
    - K1 documentation (P0);
    - recovery-precondition "never change" docs (P1);
    - I4-2 documentation (P2).
12. **Defer:**
    - the mainnet PoW choice;
    - JIT options;
    - shielded coinbase if not ready;
    - fee reform;
    - finality;
    - recursion (bundled with Plonky3 0.8);
    - pruning and assume-valid;
    - the P2P hybrid KEM if A8 is busy.
13. **Never change:**
    - the tail, B3 and height-only rewards;
    - uniform fees within a class;
    - seed → key hashing for spend-capable keys (the recovery precondition);
    - the 100-byte header (so no aux PoW);
    - RandomX internals other than an explicit, versioned salt or v2 switch;
    - "never adjust consensus from peer time";
    - unfiltered wallet download.

---

## 10. Priority list

| Pri | Item | Consensus | Identity | Diff |
|---|---|---|---|---|
| P0 | Document K1 unattainable against rx/0 JIT miners on the testnet (with R1) | none | no | S |
| P1 | **F1** upgrade table + branch id (signature message, `h_tx`) + non-banning future versions | CONSENSUS | fold into v3 | M |
| P1 | F2 scheduled no-op activation on the testnet, with its test plan | CONSENSUS | fold into v3 | S |
| P1 | Endorse F3 (R2-C6 decision at v3) and F4 (R12-2 cost bound at v3) | CONSENSUS | fold into v3 | M / S |
| P1 | Recovery spec draft (I4-6) plus never-change preconditions in docs | none (spec) | no | S |
| P1 | Owner decision at v3: shielded coinbase (§5), or fallback segregated rings | CONSENSUS | v3 or by activation | L / S |
| P2 | Typed PoW config; offline salt-variant vectors | none | no | S–M |
| P2 | Document I4-2; mempool expiry plus a per-source PX cap (policy) | none | no | S |
| P2 | Halt-on-deep-reorg policy flag (off on the testnet) | policy | no | M |
| P2/P3 | F5 hybrid ML-KEM P2P handshake | policy | no (cheapest at v3) | S–M |
| P3 | Mainnet: unique salt (on v2 if activated upstream); reject merge mining; J1/J2 owner decision | CONSENSUS | mainnet | S / XL |
| P3 | Anchor-indexed base fee with partial burn | CONSENSUS | activation | M |
| P3 | Finalized-state split with halt at K ≥ 720; End-of-Service halts | policy | no | M |
| P3 | Pruning; SLH-DSA-signed assume-valid; stempool-safe compact blocks; recursion with Plonky3 0.8 | none / CONSENSUS | — | M–XL |
| P3 | Emergency v1 freeze plus recovery-proof rule (specified ahead, activated by height) | CONSENSUS | no (with F1) | M |

**Tests to add (named proposals):**
- `branch_id_is_bound_into_v1_and_px_messages`
- `old_branch_tx_rejected_after_activation_and_flushed_from_mempool`
- `future_header_version_not_banned`
- `coinbase_record_commitment_recomputed_and_b3_exact`
- `coinbase_record_inserted_only_after_maturity_and_undone_on_reorg`
- `coinbase_rho_domain_disjoint_from_transfer_rho`
- `recovery_proof_rejects_foreign_seed` (guest plus native check)
- `px_lane_congestion_simulation` (measures honest-inclusion latency under I4-2)
- `pow_config_monero_v1_still_passes_official_vectors`

---

## Sources

- **RandomX:**
  - [RandomX configuration.md](https://github.com/tevador/RandomX/blob/master/doc/configuration.md): "We recommend each project using RandomX to select a unique configuration to prevent network attacks from hashpower rental services"; "Every implementation should choose a unique salt value."
  - [Monero PR #10038: RandomX V2 and commitments in v17](https://github.com/monero-project/monero/pull/10038);
  - [Monero on X: "RandomX v2.0 has been released"](https://x.com/monero/status/2038689736307482760).
- **Tari and merge mining:**
  - [Tari RFC-0131 Mining](https://rfc.tari.com/RFC-0131_Mining);
  - [Tari tokenomics (four PoW lanes)](https://tari.com/tokenomics);
  - [Tari RFC-0132 Merge Mining Monero](https://rfc.tari.com/RFC-0132_Merge_Mining_Monero);
  - [Tari Labs: Merged Mining Introduction (Namecoin/F2Pool)](https://tlu.tarilabs.com/mining/MergedMiningIntroduction).
- **Zcash ZIPs:**
  - [ZIP 213 Shielded Coinbase](https://zips.z.cash/zip-0213);
  - [ZIP 2005 Quantum Recoverability](https://zips.z.cash/zip-2005);
  - [ZIP 200 Network Upgrade Mechanism](https://zips.z.cash/zip-0200);
  - ZIP 203 (expiry), ZIP 225 (v5 tx), ZIP 244 (sighash), ZIP 307 (light client): cited from memory [assumed].
- **Zcash finality and scaling:**
  - Crosslink status: [Messari overview](https://messari.io/report/understanding-zcash-a-comprehensive-overview), [bit2me](https://news.bit2me.com/en/zcash-crosslink-proof-of-stake-hybrid), [BlockOps (no ZIP/activation as of Aug 2026)](https://www.blockopsmining.com/zcash-proof-of-stake-mining-risk/);
  - [Project Tachyon overview](https://tachyon.z.cash/overview/); [Sean Bowe: oblivious synchronization](https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/).
- **Plonky3 recursion:** [Plonky3-recursion repository](https://github.com/Plonky3/Plonky3-recursion); [Plonky3 recursion book](https://plonky3.github.io/Plonky3-recursion/).
- **Post-quantum crates:**
  - [RustCrypto slh-dsa](https://github.com/RustCrypto/signatures/tree/master/slh-dsa); [ml-dsa docs](https://docs.rs/ml-dsa/) (not independently audited);
  - [Project Eleven: state of PQ crypto in Rust](https://www.projecteleven.com/blog/the-state-of-post-quantum-cryptography-in-rust-the-belt-is-vacant);
  - [libcrux-ml-dsa](https://crates.io/crates/libcrux-ml-dsa).
- **Fees and security budget:**
  - Carlsten, Kalodner, Weinberg, Narayanan, "On the Instability of Bitcoin Without the Block Reward", ACM CCS 2016: [ACM DL](https://dl.acm.org/doi/10.1145/2976749.2978408);
  - [Moneropedia: tail emission](https://www.getmonero.org/resources/moneropedia/tail-emission.html);
  - [JollyMort: Monero dynamic block size and dynamic minimum fee](https://github.com/JollyMort/monero-research/blob/master/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee%20-%20DRAFT.md).
- **Coinbase and decoys:**
  - [Monero issue #6688: separate coinbase and non-coinbase rings](https://github.com/monero-project/monero/issues/6688);
  - [research-lab #109: avoid selecting coinbase outputs as decoys](https://github.com/monero-project/research-lab/issues/109).
- **From memory, not re-fetched [assumed]:**
  - the CoiledCoin merge-mining attack (2012);
  - OpenSSH mlkem768x25519 and Signal PQXDH;
  - zcashd End-of-Service halt;
  - Stratum V2 job declaration;
  - how Monero fluffy blocks treat stempool transactions [unknown].
- **Local sources (read-only):**
  - `crypto/src/keys.rs`, `tx/src/types.rs`, `tx/src/px.rs`, `tx/src/params.rs`, `tx/src/state.rs`, `tx/src/validate.rs`;
  - `chain/src/emission.rs`, `chain/src/mempool.rs`;
  - `px/src/state.rs`, `p2p/src/transport.rs`, `consensus/src/header.rs`, `wallet/src/wallet.rs`;
  - docs/blocks.md, docs/px.md, docs/zk.md;
  - docs/reviews/k4-reorg-policy.md, docs/reviews/aggregation-study.md, docs/testnet-reset-plan.md.
