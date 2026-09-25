# Assumptions register

Status: **internal, 2026-09-25. Not independently reviewed.** One place listing every
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
- **External:** an item for the independent review (review-package.md).

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
| Z1 | Knowledge soundness of the Plonky3 0.7 batch STARK (LogUp, hiding FRI) at BS-ZK-2 in the random-oracle model: ≥ 123 bits (Johnson), ≥ 105 bits (unique decoding) over the whole envelope | No forged PX proof (no inflation, no theft) | Tested (the bounds are computed per shape); **External** (the calculator and Plonky3 itself) |
| Z2 | The Poseidon2 duplex challenger acts as a random oracle (Fiat–Shamir) | Z1; also the uniformity of query positions (privacy A1) | Standard in the literature; **External** |
| Z3 | Poseidon2 over BabyBear, width 16, standard round numbers: 124-bit collision and preimage resistance | Merkle trees, transcript, every `Hk` commitment and nullifier | **External. Young primitive; first review item** |
| Z4 | LogUp buses: multiplicities never wrap modulo p | Z1 | Tested (the largest statement reaches 63% of p) |
| Z5 | The BVM-1 tables constrain exactly the interpreter's semantics | Z1 for every function and the kernel | Tested (mutation, differential, oracle); **External** |
| Z6 | The kernel and function programs implement their specifications | Value conservation, contract rules | Tested (per-check rejection tests); **External** |
| Z7 | Zero knowledge: 4 random codewords and 4 salt elements hide the witness; the prover's randomness is fresh | Every private property of PX | **External.** Parameter sufficiency not established by the project |
| Z8 | The three local Plonky3 patches change only lock scope, not results | Z1 and Z7 | Tested (equivalence test; the upstream suites pass 208/208) |
| Z9 | The statement digest binds everything the verifier supplies as periodic columns before any commitment (ZK-F13) | Z1 | Tested; **External** |
| Z10 | Delivery: IND-CCA of the hybrid KEM (Ristretto ECDH with ML-KEM-768, X-Wing-style combiner) and of ChaCha20-Poly1305 with a zero nonce under fresh keys | Record contents in transit | Standard primitives; the combiner is **External** |

## 3. Privacy (beyond the cryptography)

Source: privacy-review.md §1–§3b.

| # | Assumption | Protects | Status |
|---|---|---|---|
| P1 | Proof-length variation depends only on the public query positions, which are uniform whatever the witness (P-5) | Proof size reveals nothing about the witness | Tested (campaign, all pairwise p ≥ 0.49) and argued (§3a); **External.** Supported, awaiting independent review |
| P2 | Plonky3's proof layout is as in 0.7.0: only pruned Merkle paths vary | P1 | Tested (a regression test pins the constant parts) |
| P3 | The honest prover publishes the first proof it computes. A malicious wallet can re-prove to encode bits in the length: a covert channel from its own wallet | P1 | Argued; a wallet that leaks has easier channels |
| P4 | Users follow the timing and amount guidance (round amounts, random waits between related operations) | Deposit/withdrawal linkage; P-8 call timing | **Unverified:** depends on users (docs/px.md §12) |
| P5 | The reference wallet is used, or another wallet with the same canonical anchor and dummy behaviour | Anchor and dummy indistinguishability (P-2) | Tested for the reference wallet only; the fee is a consensus rule (P-7), the rest is wallet convention |
| P6 | Stem probing needs colluding stem nodes and yields partial routes, not origins (P-6) | Transaction origin | Argued (privacy-review §3b) |
| P7 | The v1 decoy selection (gamma, ring of 16) resists the known heuristics | Deposit inputs and v1 transfers | Standard practice (as in Monero); not re-analysed |

## 4. Network

Source: docs/p2p.md §1, §12.

| # | Assumption | Protects | Status |
|---|---|---|---|
| N1 | A node has at least one honest outbound peer (not eclipsed) | Correct chain view, transaction propagation | Argued (bucketed address manager, network-group diversity); not tested against a real Sybil attack |
| N2 | There is no global passive adversary, and users who need more protection use Tor or I2P | Transaction origin | **Explicit non-goal** (p2p.md §1) |
| N3 | Transport encryption only stops passive reading. Peers are not authenticated, so an active MITM can read or drop traffic | Content confidentiality against passive observers | Explicit limitation |
| N4 | Dandelion++ parameters tuned for Monero are adequate for BlackSilk's network size | Origin privacy | **Unverified** (p2p.md §12) |

## 5. Consensus and mining

Source: docs/consensus.md, docs/blocks.md.

| # | Assumption | Protects | Status |
|---|---|---|---|
| K1 | An honest majority of RandomX hash power | Chain immutability, double-spend resistance | Standard PoW assumption. A small testnet is easy to out-mine |
| K2 | RandomX is CPU-oriented and memory-hard as designed; the pure-Rust port matches the reference exactly | PoW validity agreement between nodes | Tested (the reference hash vectors `hash_1a`–`hash_1e`; full mode opt-in); the port is **External** if in scope (v1) |
| K3 | Node clocks are roughly correct (within the 360 s future limit) | Timestamp rules, difficulty | Standard; not enforced beyond the rules |
| K4 | **No reorg-depth limit or checkpoint exists.** consensus.md §8 calls them node policy, but the node implements none. Any valid heavier chain is accepted, however deep | — | **Open.** A decision is needed before the testnet (roadmap) |
| K5 | Consensus arithmetic is deterministic across platforms (integers; RandomX floating point emulated exactly) | Nodes agree | Tested on Windows x86_64 only. The CI workflow runs the suite on Linux x86_64, but it has not run yet |

## 6. Implementation and operations

| # | Assumption | Protects | Status |
|---|---|---|---|
| I1 | The pinned dependencies are what they claim (Plonky3 `=0.7.0`, `ml-kem =0.3.2`, `wasmi =0.38.0`, others through `Cargo.lock`) | Everything | `cargo audit`: 0 vulnerabilities, 1 unmaintained (`paste`); dependency-review.md |
| I2 | The OS CSPRNG works (hedged where it matters: C5, Z7) | Keys, proof randomness | Standard; hedging bounds a failure |
| I3 | `wasmi` executes deterministically with exact fuel metering on every platform | Transparent-contract consensus | Tested (fuzzing: determinism across two executors, same platform); cross-platform untested |
| I4 | The wallet host is not compromised | Keys and every private property | Explicit non-goal |
| I5 | Rust's memory safety holds: the project's own `unsafe` is minimal and reviewed; the dependencies' `unsafe` is trusted | Memory safety | dependency-review.md; not audited line by line |

## 7. Open items

1. **Z1, Z2, Z3, Z5–Z7, Z9, Z10 and P1:** the independent review (review-package.md
   §5).
2. **K4:** decide on a reorg-depth policy for the testnet (for example, a warning plus
   operator confirmation above a depth), or document that none is intended.
3. **N4:** re-tune the Dandelion++ parameters after measuring the testnet's size.
4. **K5 and I3:** a second platform. The first CI run covers Linux x86_64. There is no cross-platform comparison of the same hashes and roots yet (ARM64 if
   available).
