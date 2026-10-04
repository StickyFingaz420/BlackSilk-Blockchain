# Assumptions register

Status: **internal, 2026-09-25; updated 2026-09-27. Not independently reviewed.** One place listing every
assumption that BlackSilk's security, privacy or correctness depends on. It shows what
each assumption protects, where it is argued, and whether anything checks it.

Each detailed argument stays in its source document; this register points there. If
an entry here and its source disagree, the source is authoritative and this register
has a bug.

**Status column:**
- **Standard:** a widely studied assumption; the project does not re-examine it.
- **Tested:** the project has tests that would catch a violation in this code, but no
  proof.
- **Argued:** a written argument, no test that could fail.
- **Unverified:** relied on; neither tested nor argued here.
- **External:** beyond what the project can establish itself; it would be an item for
  an external reviewer if one were engaged (review-package.md). None is engaged or
  planned, and this is not a requirement or a testnet gate (owner decision
  2026-09-25, review-status.md). Until then these items rest on internal work only.

## 1. Cryptography: v1 layer (ring signatures, amounts, addresses)

Source: docs/transactions.md §9, §10.

| # | Assumption | Protects | Status |
|---|---|---|---|
| C1 | Discrete logarithm is hard in Ristretto255 (~126 bits) | Spend authority, amount binding | Standard |
| C2 | DDH is hard in Ristretto255 | Stealth-address unlinkability, ring anonymity | Standard |
| C3 | Blake2b-based `Hs`, `Hp`, `H32`, `H64` behave as random oracles | CLSAG and Bulletproofs+ security proofs | Standard |
| C4 | No one knows a discrete-log relation between `G`, `H`, `Gbp[i]` and `Hbp[i]` | Amount hiding and binding | Argued (hash-to-group generation) |
| C5 | Wallet randomness is hedged: a failing CSPRNG degrades to a deterministic derivation, not to key leakage | Keys and nonces | Tested (`crypto/src/nonce.rs::broken_rng_still_separates_contexts_and_secrets`) |
| C6 | **Quantum resistance is not assumed** for v1. A quantum adversary breaks C1 and C2 | — | Explicit non-goal (§11.6) |

## 2. Cryptography: ZK and private-execution layer

Source: zk-security-review.md §2; privacy-review.md §3a.3.

| # | Assumption | Protects | Status |
|---|---|---|---|
| Z1 | Knowledge soundness of the Plonky3 0.7 batch STARK (LogUp, hiding FRI) at BS-ZK-3 in the random-oracle model, computed (not proven) over the whole envelope: unique decoding ≥ 105.58 bits, and ≥ 100.54 (about 100.5) once the mixed-height union term (log2 33 bits; a heuristic, no theorem covers the roll-in) is charged; the Johnson regime is hash-bound at 122 (`COLLISION_BITS`, ePrint 2026/089 Theorem 3; algebraic bound ≥ 150). Figures updated 2026-10-04 (formerly BS-ZK-2, 123 / 105) | No forged PX proof (no inflation, no theft) | Tested (the bounds are computed over the envelope up to 65,536 batched columns, which covers the worst case of about 2 × 15,709 = 31,418 batched functions, zk.md §9.3); **External** (the calculator and Plonky3 itself) |
| Z2 | The Poseidon2 duplex challenger acts as a random oracle (Fiat–Shamir) | Z1; also the uniformity of query positions (privacy A1) | Standard in the literature; **External** |
| Z3 | Poseidon2 over BabyBear, width 16, standard round numbers: about 123-bit generic collision resistance of an 8-element digest (8 · log2 p / 2 ≈ 123.6); the Merkle trees are counted at the extractability bound of ePrint 2026/089 Theorem 3, about 122.6 (`COLLISION_BITS` = 122; formerly 123) and preimage resistance | Merkle trees, transcript, every `Hk` commitment and nullifier | **External. Young primitive; first review item** |
| Z4 | LogUp buses: multiplicities never wrap modulo p | Z1 | Tested (the largest statement reaches 63% of p) |
| Z5 | The BVM-1 tables constrain exactly the interpreter's semantics | Z1 for every function and the kernel | Tested (mutation, differential, oracle); **External** |
| Z6 | The kernel and function programs implement their specifications | Value conservation, contract rules | Tested (per-check rejection tests); **External** |
| Z7 | **Statistical** zero knowledge of the proofs as configured (BS-ZK-3); perfect zero knowledge is not claimed | Every private property of PX | **Partly covered, OPEN.** Each table meets the per-table conditions of the published construction (ePrint 2024/1037): randomization 2·(108 + 8·2) = 248 ≤ 256 with both opening points (Z13; formerly 232); a separate FRI mask `R` per table spanning the extension, which upstream calls only statistically ZK (its presence, public width and height are checked by the verifier; its full committed width by a test). The LogUp terminals are covered by our blinding. **Theorem 8 does not directly cover this system.** **Open:** many tables of mixed heights (O); the Appendix A leakage of LogUp arguments, estimated only (about N/\|F\|, U); preprocessed and periodic columns and per-table next points, outside the paper's model (O); multi-phase traces (O); ζ not rejected from H ∪ D (O, negligible); Plonky3 matching the paper, including the quotient chunk count (U); salted Merkle hiding (C); randomness (C). See zk-coverage.md. Never described as proven or complete |
| Z8 | The three local Plonky3 patches change only lock scope, not results | Z1 and Z7 | Tested (equivalence test; the upstream suites pass 208/208) |
| Z9 | The statement digest binds everything the verifier supplies as periodic columns before any commitment (ZK-F13) | Z1 | Tested; **External** |
| Z10 | Delivery: IND-CCA of the hybrid KEM (Ristretto ECDH with ML-KEM-768, X-Wing-style combiner) and of ChaCha20-Poly1305 with a zero nonce under fresh keys | Record contents in transit | Standard primitives; the combiner is **External** |
| Z11 | LogUp bus separation: messages on different buses never cancel, because each bus has its own offset (one power of the combiner above every payload term), sampled after the main commitment | Soundness of every bus, including the blinding bus | **U, C:** as documented and implemented in `p3-lookup` 0.7.0 (`Challenges`), read in the source; not proven by the project. Tested: the stand-in attack and unbalanced-bus tests (R12) |
| Z12 | The blinding values are uniform and secret: BLAKE2b seed (tag, witness digest, OS randomness) → ChaCha20 → rejection-sampled field elements | Hiding of the terminals (up to ~2^−124) | **C:** a standard PRF/PRG assumption; tested for freshness and non-degeneracy only |
| Z13 | The randomization bound of ePrint 2024/1037 §4.2, eq. (17): 2·(e·n_F + n_D) ≤ h ≤ \|H\|, i.e. 2·(108 + 8·2) = 248 ≤ 256 for every table, both opening points counted (formerly 232) | ZK-F30; the secrecy of the blinding values | **Met; checked in every build** (`const` assertion in zk/src/params.rs). The bound is the paper's (C); it holds per table, and the mixed-height composition is under Z7 |

## 3. Privacy (beyond the cryptography)

Source: privacy-review.md §1–§3b.

| # | Assumption | Protects | Status |
|---|---|---|---|
| P1 | Proof-length variation depends only on the public query positions, which are uniform whatever the witness (P-5) | Proof size reveals nothing about the witness | **Supported, not closed:** tested and argued (privacy-review.md §3a). Current evidence (docs/evidence/p5-2026-09-26b/, the final layout): the non-authentication parts are constant per shape (1,811,565 B transfer, 2,359,622 B vault); 260 proofs, 14 pairwise tests with p from 0.107 to 0.965, none significant at 0.05/14. Only large effects are detectable. **External** (internal review only) |
| P2 | Plonky3's proof layout is as in 0.7.0: only pruned Merkle paths vary | P1 | Tested (a regression test pins the constant parts) |
| P3 | The honest prover publishes the first proof it computes. A malicious wallet can re-prove to encode bits in the length: a covert channel from its own wallet | P1 | Argued; a wallet that leaks has easier channels |
| P4 | Users follow the timing and amount guidance (round amounts, random waits between related operations) | Deposit/withdrawal linkage; P-8 call timing | **Unverified:** depends on users (docs/px.md §12) |
| P5 | The reference wallet is used, or another wallet with the same canonical anchor and dummy behaviour | Anchor and dummy indistinguishability (P-2) | Tested for the reference wallet only; the fee is a consensus rule (P-7), the rest is wallet convention |
| P6 | Stem probing needs colluding stem nodes and yields partial routes, not origins (P-6) | Transaction origin | Argued (privacy-review §3b). **Weakened** (second threat-model round, 2026-10-02): spies that drain a relayer's PX relay budget, or flood its transaction lane, make it drop stems silently, so the origin's own embargo fluffs first (TM2-P4); the per-peer slow lane answers later while it verifies a stem transaction, a stempool-membership timing oracle (TM2-P6); no privacy regression suite tests any of this (STATUS.md §3) |
| P7 | The v1 decoy selection (gamma, ring of 16, Monero's picker) hides the real input among the ring members, and the node's output distribution is honest | Deposit inputs and v1 transfers | **Does not hold for young spends, and rests on the node** (corrected 2026-10-02; this row first read "resists the known heuristics", "not re-analysed"). On a mature chain a real input spent 12 blocks after receipt is the newest ring member in about 84–89 % of rings (a simulation estimate, dossier 38 §2.4; transactions.md §11.3.1). The wallet takes the decoy distribution from its node, checking only monotonicity and the total (F38-1; computing it locally is decided, not built, STATUS.md §3.1) |

## 4. Network

Source: docs/p2p.md §1, §12.

| # | Assumption | Protects | Status |
|---|---|---|---|
| N1 | A node has at least one honest outbound peer (not eclipsed) | Correct chain view, transaction propagation | Argued (bucketed address manager, network-group diversity, block-relay-only connections and anchors); not tested against a real Sybil attack (the labnet cannot exercise grouping, limits or bans). N-4 and N-9 are closed (p2p.md §9, §10); open: N-5 (a ban covers one IPv4 address or IPv6 /64), no chain-sync eviction, no built-in seeds (p2p.md §12) |
| N2 | There is no global passive adversary, and users who need more protection run their node over Tor (outbound SOCKS5; I2P is **not** supported; the wallet has no Tor or TLS support, so it must use a local node) | Transaction origin | **Explicit non-goal** (p2p.md §1). Even a single link observer (the node's ISP or Tor guard) sees which transactions the node originates, v1 and PX, since frames are not padded (p2p.md §1). Tor mode has no onion-only outbound (proxy-only dials clearnet peers through exits) and no stream isolation (p2p.md §11). Inbound Tor through the onion listener avoids N-6 (testnet.md §4.3) |
| N3 | Transport encryption only stops passive reading of contents. Peers are not authenticated, so an active MITM can read or drop traffic, inject invalid messages so that the victim bans the impersonated peer's IP, and eclipse a node whose connections it controls | Content confidentiality against passive observers | Explicit limitation on public networks; a closed network's pre-shared key keeps outsiders out (p2p.md §3; required for the trial, testnet.md §12.3) |
| N4 | Dandelion++ parameters tuned for Monero are adequate for BlackSilk's network size | Origin privacy | **Unverified** (p2p.md §12) |

## 5. Consensus and mining

Source: docs/consensus.md, docs/blocks.md.

| # | Assumption | Protects | Status |
|---|---|---|---|
| K1 | An honest majority of RandomX hash power | Chain immutability, double-spend resistance | Standard PoW assumption. A small testnet is easy to out-mine |
| K2 | RandomX is CPU-oriented and memory-hard as designed; the pure-Rust port matches the reference exactly | PoW validity agreement between nodes | Tested: the reference hash vectors `hash_1a`–`hash_1e` in light mode; in full mode, all 5 vectors plus full/light agreement on 1,024 random inputs, run locally 2026-09-25 and 2026-09-27 (opt-in test; the `randomx-full` CI job has not yet run on GitHub). The seed-key switch is exercised only with a short test epoch (16/4), not at height 2113. The port is **External** if in scope (v1) |
| K3 | Node clocks are roughly correct (within the 360 s future limit) | Timestamp rules, difficulty | Standard; not enforced beyond the rules. Operators are told to run NTP (testnet.md §12.2) |
| K4 | **No reorg-depth limit or checkpoint** (**provisional testnet policy**, accepted by the owner 2026-09-25; not a mainnet decision; docs/reviews/k4-reorg-policy.md): the most-work chain wins at any depth. Reorganizations of 10 blocks or more are logged as warnings and the deepest is tracked | Convergence of honest nodes | **Documented and accepted for the testnet.** Deep rewrites are possible for a hash-power majority (K1). A limit or checkpoints remain open for mainnet |
| K5 | Consensus arithmetic is deterministic across platforms (integers; RandomX floating point emulated exactly) | Nodes agree | Designed to be. Tested on Windows x86_64, and the full suite passes on Linux x86_64 in CI (2026-09-25). No ARM64, and no cross-platform comparison of identical outputs |

## 6. Implementation and operations

| # | Assumption | Protects | Status |
|---|---|---|---|
| I1 | The pinned dependencies are what they claim (Plonky3 `=0.7.0`, `ml-kem =0.3.2`, `wasmi =0.38.0`, others through `Cargo.lock`) | Everything | `cargo audit`: 0 vulnerabilities, 1 unmaintained (`paste`); dependency-review.md |
| I2 | The OS CSPRNG works (hedged where it matters: C5, Z7) | Keys, proof randomness | Standard; hedging bounds a failure |
| I3 | `wasmi` executes deterministically with exact fuel metering on every platform | Transparent-contract consensus (not integrated; not in consensus) | Tested (fuzzing: determinism across two executor instances in one process); cross-platform untested |
| I4 | The wallet host is not compromised | Keys and every private property | Explicit non-goal |
| I5 | Rust's memory safety holds: the project's own `unsafe` is minimal and reviewed; the dependencies' `unsafe` is trusted | Memory safety | dependency-review.md; not audited line by line |

## 7. Open items

1. **Z1, Z2, Z3, Z5–Z7, Z9, Z10 and P1:** internal review only. They would be the
   first items for an external reviewer if one were engaged (review-package.md §5);
   none is (owner decision 2026-09-25).
2. **K4:** documented and accepted for the testnet (no limit; a warning at 10 blocks).
   Revisit for mainnet with testnet data.
3. **N4:** re-tune the Dandelion++ parameters after measuring the testnet's size.
4. **K5 and I3:** a second platform. The first CI run covers Linux x86_64. There is no cross-platform comparison of the same hashes and roots yet (ARM64 if
   available).
