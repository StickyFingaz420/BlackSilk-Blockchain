# v3 candidate plan (coordinator decision under autonomy, 2026-09-27)

## Rule
- Every consensus-changing item goes on branch `v3/candidate`. It is never merged into rebuild/core without the owner's review on return.
- rebuild/core receives policy-only changes.
- Each item is a separate commit, so the owner can drop any of them.
- Genesis is NOT generated. Only the tool and procedure are built; the genesis is produced at launch with the owner.

## Decided for v3 (owner: fresh genesis at launch; one identity)
1. **PX-F5:** the kernel enforces owner = 0 for contract outputs.
2. **Platform-neutral kernel build**, giving new kernel and vault ids.
3. **Canonical proofs:** FRI commit witness and empty openings. Done in 4b277cd (rebuild/core; a decode rule; harmless on v2, where no PX transactions exist yet).
4. **Genesis tool and procedure:** unpredictable data at launch, deterministic and reproducible construction, documented rationale.

## Proposed for v3 (low marginal cost now; each a separate commit)
| Item | Source | Why | Risk |
|---|---|---|---|
| R4-02 folding-schedule check in zk::verify | R4 | proof malleability (as with M1) | low |
| R4-11 circuit tag in the transcript | R4 | circuit revisions under one PARAMS_ID | low; all proofs change (P-5 rerun) |
| R6 uniqueness keyed on (output key, commitment) | R6 | stops cheap front-running and griefing: a copy needs the opening for BP+ | medium; mempool and wallet scan must handle duplicate keys |
| R12-2 v1 inputs of deploy/PX count toward v1 weight (or a sigop limit) | R12 | 12k CLSAG per block DoS | low |
| R5-1/R6 deploy byte cap, per-block deploy budget, deploy fee ≥ transfer per byte, ≤ 2 deploy outputs | R5, R6 | registry RAM DoS and PX-lane censorship | low |
| R5-7 reject duplicate program ids in one deploy | R5 | only the first is reachable | low |
| R2-C6 Hk node feed-forward (P(x)+x) | R2 | the collision-resistance claim is false without it | medium; px-core hash, wallet tree, kernel |
| R1-C6 compile_error on non-64-bit targets | R1 | decoding divergence | none (build) |

## Added after R15/R16/I4
| Item | Source | Notes |
|---|---|---|
| **Upgrade mechanism:** activation-height table (a single epoch at v3); branch id hashed into the v1 signature message and the PX `h_tx`; header version tied to the epoch; no ban for newer versions (P2P) | R16-1, I4, R1 | Highest-value v3 item: later changes arrive by height, with no reset. `h_tx` is a public input, so no kernel change. |
| **Genesis id bound into** the P2P session key and the wallet network check | R15-3 | Free at v3. |
| **Kernel neutrality:** no located panics in kernel paths (`px-core/src/hash.rs:81,82,102` asserts); a test that the ELF has no path strings; CI reproduces kernel.id on Windows and Linux | R15-6 | A remap alone is not enough. |
| **Genesis nonce** = `LE64(Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(net_id) ‖ LE64(H) ‖ BTC block hash H)[0..8])`; timestamp before the beacon; 6 confirmations; the 8 pinned tests | R15 §4 | The tool only; generated with the owner. |
| Hybrid ML-KEM P2P handshake (optional) | I4-7 | Transport, not consensus; cheapest at a reset; P3 unless time allows. |
| Shielded coinbase | I4 (adopt), R3 | Only with the full review chain; otherwise activate later by height (needs the upgrade mechanism). |

## Deferred (owner decision; not in v3 by default)
- PX-F4 option B′: with contract v1 work.
- Shielded coinbase into PX (R3, ZIP 213-style).
- Fee tiers (R6).
- ZIP-200 branch ids.
- PoW variant (R1-C2).
- Function height window (R5-3).
- Plonky3 0.8.

## Non-consensus items needed before the trial (rebuild/core)
- **Miner nonce:** done (f331642).
- **P2P (A8, then a follow-up agent):** R8 P0 set (unsolicited blocks, addrman per-source, /16 loop bug, onion groups, timeouts, byte outbox and upload budget, seeds fallback, tolerate unknown messages before v3, inbound /64 caps); Dandelion 0.2.
- **Chain lock:** two-phase admission (R6, R8-1).
- **Wallet:**
  - W1 vault secret (A7b);
  - decoy selection by block age with a coinbase-maturity redraw (R3-1);
  - PX view key and seed version (R11-W2/W3) before v3;
  - SOCKS5.
- **Hedging:** A21.
- **Tests and vectors:** A20. Fuzz with -O -a (A15b).
- **RandomX:** header presync (A8/R1-C1); cache built outside the lock; next-seed prebuild in the miner; non-SSE2 guard.
- **Storage/RPC:**
  - R10-2 poisoned-lock exit;
  - R10-4 RPC Host check and auth;
  - PX commitments index (A22).
- **Docs:** operator notes for R1-C2 (stock RandomX miners dominate), K1.

## Corrections after the SX1 cross-review (C:/bszkeval/review/SX1-core-crossreview.md)
- **R4-02:** the rationale was wrong. It is not relayer malleability: only a prover holding the witness can re-prove, and unconsumed openings are already rejected. Keep it as a canonical-schedule rule, with an honest-schedule test for every consensus shape.
- **R6 pair-keyed uniqueness:**
  - owner decision between option C (pair-keyed) and option B (drop C4);
  - if C, keep one-time-key uniqueness **within a transaction** across outputs and payouts (the burning-bug exploit otherwise);
  - re-key the state set and its undo, the block set, the mempool namespace and the extension check;
  - add a wallet rule: one credited output per key image.
  - Clear payouts stay griefable at the cost of their amount.
- **R2-C6 feed-forward:** a guest-code change only (no AIR change), about +2–3k kernel cycles. Include only if the fixed shapes' budgets hold after re-measurement; otherwise document the ~2^124 binding argument.
- **R1-C6:** removed from this list (not consensus; done in 8097f66).
- **Branch id:** part of the upgrade mechanism (the deferred list meant full ZIP-200 governance, not the id).
- **Missing items added:**
  - deploy-time caps (cycle and table budgets must not exceed the proving limits, MAX_CYCLES = 2^21; R7-5);
  - re-measure the kernel and the widest 2-function proof against MAX_PROOF_BYTES before pinning ids;
  - pin real-permutation Hk and node vectors plus a fingerprint CI pin;
  - the genesis tool takes a starting difficulty from measured honest hash rate (err low).
- **Out of v3:** hybrid P2P handshake, shielded coinbase, grinding changes, fee tiers, RandomX salt variant.
- **Order:** consensus rule changes first, the neutral kernel rebuild last (so ids are computed once), then fingerprints.
- **Wallet (not consensus, same release):** R2-C2 hedging (A21), the R2-C9 delivery v2 label with identity-V rejection, and the I2-R1/R11-W2/W3 derivation.
