# SX1: senior cross-review of the core reports (wave 2)

> Historical record (2026-09-27). Superseded where it conflicts with the code: RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca). Current: [docs/consensus.md](../../consensus.md), [docs/STATUS.md](../../STATUS.md).

- **Reviewer:** SX1. Internal review, not an audit. Read-only. No builds were run.
- **Code read at:** `rebuild/core` @ `58f25ec`.
- **Commits since `87278ac` that change the picture:**
  - `9578517`: the PoW cache is now keyed by (seed, header), and `accept_headers` syncs state before it returns an error. This closes R1-C4 and the keying part of R1-C5. The cache is still unbounded.
  - `8097f66`: R1-C6 is done, as a build guard plus a checked length.
  - `4b277cd`: M1 and M2 are done (canonical FRI witness, empty openings).
  - `16659ee`: F1 is done (output keys are conflict keys).
- **Reports challenged:** R1, R2, R4, R5, R6, R7, I1, I2. I also checked R12-2 against the code.
- **Evidence tags:** [src] file:line read by me; [math] re-derived by me; [est] my estimate.

---

## 1. Verdict table (major findings: severity ≥ medium, anything P0/P1, every CONSENSUS proposal)

| Finding | Verdict | Re-verification and correction |
|---|---|---|
| **R1-C1** difficulty-1 free headers | **CONFIRMED** (with a scope correction) | `check_hash` with d = 1: `(v·1 + carry) >> 64` is always 0, so every hash passes [`consensus/src/pow.rs:9-21`, math]. The LWMA floor is `clamp(1, …)` [`difficulty.rs:42`]. The minimum step is `avg_D/6` (6T cap, so L ≤ 3T·n(n+1)) [math]. Staying at 1 needs `L > 109 800`, i.e. a spacing above 60 s [math ✓]. From testnet D0 = 100 [`params.rs:60`], an early window reaches 1 within about 10 blocks [math]. No anti-DoS work gate exists yet: a grep finds no threshold in p2p, chain or consensus. The rx cache is still built under the mutex with 2 slots [`pow.rs:55-70`]. **Correction:** the problem is *any* low claimed work, not only D = 1. Headers at D = 2–10 cost only 2–10 hashes each, so the gate must be on claimed work (as R1 proposes), not on a difficulty floor. The v3 genesis must use a launch-time timestamp, or the free-fork depth budget (chain age / 61 s) is large from day one. |
| **R1-C2** stock RandomX makes K1 unattainable | **CONFIRMED** (accepted limitation) | The salt is Monero's. **Note:** option (b), a salt variant, stops only *unmodified* xmrig and rental. A recompiled xmrig is still ~50–100× the safe-Rust miner. So a variant does not restore K1 for the trial, and deferring it is right. |
| R1-C3 sync cost | CONFIRMED | 262 800 × 0.75 s ≈ 54.8 CPU-hours per chain-year [math ✓]. |
| R1-C8 LWMA weight shaping | CONFIRMED | L = 1 275 + 720·555 = 400 875 and 219 600 honest, giving 0.548·D; the span is 7 250 s against 7 200 s [math ✓]. The net gain is still unknown, as stated. |
| R1-C9 FTL skew stall | CONFIRMED | Policy only. |
| R1-C10 / §4.4 unknown versions ban peers; no upgrade table | **CONFIRMED; priority raised** | This is the item that decides whether any post-launch consensus change needs a v4 genesis (§3). The branch-id binding does **not** need to be in v3: it can be introduced at the activating upgrade itself (as Overwinter did). |
| **R2-C2** PX delivery not hedged | CONFIRMED | `rng.fill_bytes` for both `r` and `m` [`px/src/delivery.rs:145-152`]. A constant RNG lets anyone holding the address derive the AEAD key. The `a21-hedge` branch has no commits yet. |
| R2-C5 membership nonce | CONFIRMED | Unreachable today (no consumer, R7-10). |
| **R2-C6** Hk node without feed-forward | **CONFIRMED-WITH-CORRECTION** | **Collision claim:** `node` = `P(l‖r)[0..8]` [`px-core/src/hash.rs:144-152`]. P is invertible, so `P⁻¹(d‖u₁)` and `P⁻¹(d‖u₂)` give trivial standalone collisions [math ✓]. The comment at `:15-18` is false. **Binding:** I re-derived it independently. Top-down inversion yields arbitrary random children. Reaching a leaf needs the first sponge state's 8 capacity words to equal `(domain, len, 0…)` (CICO, ~2^248). A forged path from an accepted root is therefore a meet-in-the-middle on 248-bit nodes, ≈ 2^124. **The tree remains ≈ 124-bit binding** [math], resting on leaf anchoring plus fixed depth, as R2 says. **Correction to the cost estimate:** the fix is *not* an AIR or syscall change. `node` is guest code over the existing `POSEIDON2` syscall (`zkvm/src/lib.rs:48`), so feed-forward is 8 field additions in px-core, and host and guest share the function. The real cost is roughly +2–3k kernel cycles plus ALU/LT rows for 2 × 32 levels [est]. Budgets carry little headroom (R5 §3.1), so the fixed shapes must be re-measured. |
| R2-C7 Poseidon2 margin | CONFIRMED | Long-term. No v3 action beyond an agility note. |
| R2-C14 PQ exposure of v1 | CONFIRMED | The bridge dilution point is correct: the turnstile only bounds PX→v1. |
| **R4-01** calculator fed the pre-ZK height | **CONFIRMED-WITH-CORRECTION; severity inflated** | The off-by-one is real: `ProvenSecurity::compute(&p, 1 << shape.log_height)` [`zk/src/params.rs:153`], while under ZK `degree_bits = log2(h)+1` [`zk/src/lib.rs:142`], and p3 documents post-ZK degree bits [`p3-uni-stark-0.7.0/src/security.rs:249-250,326-330`]. **But:** the envelope loops degree bits 8..=22. Every consensus PX statement has an exact shape (`zkvm/src/prove.rs:190-203`), far below 2^21 rows (CPU 2^15–2^16, byte 2^16), so its true degree bits are inside the tested range. The untested region is the unshaped extreme: `limits()` lets non-CPU tables reach 2^22, i.e. degree bits 23 (`prove.rs:32-41`). The p3 0.7 accounting bugs (#2048) remain a genuine unknown. **Severity: low (claim accuracy). P1 for the documents only. No consensus impact.** |
| **R4-02** prover-chosen FRI schedule | **CONFIRMED-WITH-CORRECTION** | The arities come from the proof, and the schedule is observed after the betas [`third_party/p3-fri/src/verifier.rs:219-232,319-322`] ✓. **Missed by R4:** the verifier rejects unconsumed reduced openings [`:625-643`], so the freedom is limited to how arity is split *between* input heights. **Not third-party malleability:** only a witness-holder can re-prove. The v3-plan rationale "proof malleability (as with M1)" is therefore wrong: M1 was relayer malleability. The honest derivation already exists (`third_party/p3-fri/src/config.rs:180` `compute_log_arity_for_round`), so the check is S. |
| R4-06 / I1-F3 no SIMD | CONFIRMED | I1's split hazard is right: prover-only, or a differential-tested verifier. |
| R4-10 Plonky3 0.8 | CONFIRMED | Stay on 0.7 for the testnet. |
| R4-11 no circuit id in the transcript | CONFIRMED (low) | Free at the v3 reset. |
| **R5-1** deploy crowding and registry RAM | CONFIRMED | Deploy fee = 2/byte, `≥` rule [`tx/src/px.rs:595-597,726-731`]. The PX fee is exactly 8 912 896 [`params.rs:29`, `px.rs:681`]. 1 MiB cap [`params.rs:19`]. The arithmetic checks. Minor: a miner filling with its own deploys forgoes ~0.27 BLK of PX fees, so the cost is small but not quite zero. |
| R5-2 / R6 MP-5 no PX fee market | CONFIRMED | Consistent across both reports. |
| R5-3 / **R7-1** no clock in functions | CONFIRMED (capability) | **R7's "high" is a product-capability severity, not a security severity.** The two reports propose different mechanisms: R5-3 an anchor height, R7-1 a window against the block height. Choose one together with the contract-model redesign. It is not needed in v3 unless the trial includes non-vault contracts. |
| R5-4 share exposes cm and rho | CONFIRMED | `share = version ‖ cm ‖ rho ‖ ct`, and the doc says it "reveals nothing" [`px/src/share.rs:10,16-17,55-56`]. |
| R5-5, R5-9 / R7-4, R5-11 | CONFIRMED | Design and scaling limits; documentation. |
| R5-7 / R7-6 duplicate program ids | CONFIRMED (low) | `find` returns the first match [`tx/src/state.rs:273-283`]. |
| **R6 MP-7** C4 front-running | **CONFIRMED** | `stem_keys` holds only key images and nullifiers [`p2p/src/net.rs:1342-1348`]. The forge test exists [`chain/tests/revalidation.rs:247`]. |
| **R6 option C** (O, Cm) uniqueness | **CONFIRMED-WITH-CORRECTIONS** (see §2) | It stops free griefing of hidden outputs [math: balance plus the BP+ proof of knowledge need `y_v`]. Four corrections are required; see §2. |
| R6 TX-4 deploy underpricing | CONFIRMED | Same as R5-1. |
| R6 MP-1 admission crypto under the chain lock | CONFIRMED | `spawn_blocking(… inner.chain().submit_tx/check_tx …)` [`net.rs:303,1409,1476,1537`]. The global PX bucket is 2/s [`net.rs:263`]. |
| R6 TX-2 depth-based stateless signature failure | CONFIRMED (sound policy) | Ring indices below the fork point are branch-invariant. |
| **R12-2** weight-0 v1 inputs in deploys and PX | **CONFIRMED; broader than stated** | `weight() = 0` for PX and deploys [`tx/src/types.rs:452-458`]. `MAX_INPUTS = 64` applies to both [`px.rs:617`, and the deploy path through `check_structure`]. The ~12 100 CLSAGs per block [math ✓]. **Correction:** this is not only a miner attack. Any mempool user can feed such deploys at 2/byte. The binding cost is ~12k spendable outputs per stall block. |
| R7-2 no authorization primitive | CONFIRMED (capability) | Consensus none. |
| **R7-5** budgets up to 2^22 under a flat fee | **OVERSTATED as DoS; a valid tightening** | Verifier cost is polylogarithmic in height: the openings are queries × width, and the proof is capped at 4 MiB and paid for in PX bytes. What is real: `read_budget` admits `cycles` up to 2^22 [`px.rs:128-133`], but `MAX_CYCLES = 2^21` and the CPU limit is 2^21 (`prove.rs:36`). So **unprovable budgets are registrable**. Rejecting them at deploy is a trivial consensus tightening. |
| R7-8 / R7-9 output leak channel, auditability | CONFIRMED | Tooling items. |
| I1-F2 whole-block wallet sync | CONFIRMED | This also resolves I1's [assumed]: **no header commits to a PX root** [`consensus/src/header.rs:12-20`]. |
| I1 A1 grinding for queries | NEEDS MORE ANALYSIS | Its reference to "the M1 fix (`COMMIT_POW_BITS ≥ 1`)" is stale: M1 was closed by a witness == 0 rule in `4b277cd`. Recompute only after R4-01 is fixed. Not for v3. |
| I2-F1 issuer traceability | CONFIRMED | The contract nullifier = `Hk(NFC, contract ‖ rcm ‖ cm)` [`px-core/src/record.rs:101-111`]. **This constrains PX-F4 B:** `rcm` must stay prover-choosable, which supports deferring B. |
| I2-F2 owner tags derivable from FVK material | CONFIRMED | `owner = Hk(OWNER, ak ‖ nk ‖ d)` [`record.rs:33-36`]. The kernel derives `ak` and `nk` from `sk` [`kernel.rs:~267-270`]. |
| I2-F6 capacity | CONFIRMED | 3 × 720 = 2 160 per day, so 10 000 votes take ≈ 4.6 days [math ✓]. |
| I2-R1 hierarchical PX keys | CONFIRMED | Wallet-only. It must land before seeds are in users' hands, together with R11-W2/W3. |

**Reports that contradict each other:**
- R7 (PX-F4 B in v3) against R5 and I2-F1 (defer). I side with deferral.
- R6 "≤ 2 deploy outputs" against R12-2 "count the v1 part as weight". Option (a) makes the output cap unnecessary.
- R4-01 at "medium/P1" against its actual consensus reach, which is nil.
- R1 §4.4 "fold branch ids into v3" against the fact that they can be introduced at the upgrade itself.

---

## 2. Option C, (O, Cm) uniqueness: what it fixes and what it breaks

**What it fixes** [math, src]:
- A copy of a hidden output needs `y_v`, both for the balance equation (`px.rs:688-710`, and the transfer equivalent) and for the BP+ proof of knowledge. Griefing of hidden outputs is therefore impossible.
- Janus rejects any cross-tx copy, because `ctx` differs: `transfer_context` hashes the key images, `px_context` the nullifiers and key images [`crypto/src/stealth.rs:46-59`]. So wallets never credit a copy.

**Corrections that must be part of the design:**
1. **Keep intra-transaction uniqueness on O alone,** across outputs ∪ payouts.
   - Today `check_uniqueness_of` uses one set for the tx and the block [`tx/src/validate.rs:387-406`]. Pair-keying it would allow a PX tx to hold a hidden output and a payout with the same O and different Cm.
   - Both would be **Janus-valid**, because they share the ctx and the anchor. They also share one key image, so only one is spendable.
   - That is the Monero burning-bug exploit against exchanges. The per-tx sort order does not stop it, because outputs and payouts are sorted separately [`px.rs:648-652`].
2. **Clear-amount copies are still griefing,** at a price of `a`.
   - The attacker makes an output with `y = 1` and amount `a`, which is identical to a pending payout `(O, G + a·H)`. If the attacker's copy lands first, the victim's PX tx is invalid.
   - For small payouts, such as change, this is cheap. R6's "the copy is spendable by the real recipient" is only theoretical: the wallet rejects it through Janus, and it shares the key image with the real output.
3. **Every set keyed by O must be re-keyed:**
   - `MemoryChain.one_time_keys` and its undo [`tx/src/state.rs:45,196,227,257`];
   - `validate.rs:836` (the coinbase path);
   - the mempool `OutputKey` namespace from `16659ee` [`chain/src/mempool.rs:129`];
   - the extension-revalidation check.
   Undo by O alone would be wrong once duplicates exist.
4. **Wallets:**
   - Storage dedupes by global index and spends by key image [`wallet/src/wallet.rs:558-603`], so they tolerate duplicates.
   - Add an explicit "one credited output per key image" rule, and a test with two same-O outputs in the chain.
   - Decoy selection and ring checks work by index plus pair [`wallet.rs:1096-1131`], so they are unaffected.

**Option B (drop C4) deserves equal consideration:**
- C's only extra backstop is against *exact* duplicates made by the original sender.
- The sender can equally make a different-amount duplicate, which a wallet without Janus would accept. So C protects non-Janus wallets only marginally.
- B removes all griefing, including clear payouts, and removes the index.
- Either way, correction 1 is required.

---

## 3. The v3 plan, item by item

| v3 item | Verdict | Reason |
|---|---|---|
| 1. PX-F5 (owner = 0 for contract outputs) | **Include** | One check in the output loop [`px-core/src/kernel.rs:337-377`]. Add a native/guest differential and re-measure budgets. |
| 2. Platform-neutral kernel build | **Include, and do it last** | Every other kernel-changing item (F5, R2-C6) changes the ids, so compute and pin them once at the end. Pin the rustc toolchain as part of the identity record. |
| 3. Canonical proofs | **Done** (`4b277cd`) | Check that the tests cover both a non-zero witness and a present-but-empty opening. |
| 4. Genesis tool and procedure | **Include, and extend** | Add D0 set from the *measured* honest hash rate (err low: too high a D0 stalls block 1 with no downward adjustment until blocks arrive) and a timestamp at launch minus a few minutes (R1-C1 depth budget). |
| R4-02 schedule check | **Include (low value, low risk)** | Correct the rationale: it is not relayer malleability. Reuse `compute_log_arity_for_round`. Add a test that the derived schedule equals the honest one for every consensus shape. A mismatch would reject valid proofs, which is a liveness split. |
| R4-11 circuit id | **Include** | No marginal identity cost now. |
| R6 (O, Cm) uniqueness | **Include, with the §2 corrections; the owner picks C or B** | Corrections 1 and 3 are mandatory. Without correction 1 the change *introduces* a burning-bug vector. |
| R12-2 v1 inputs count | **Include** | Prefer option (a): charge the v1 part (inputs, outputs, BP+ clawback) of PX and deploy transactions against `MAX_BLOCK_WEIGHT`. The PX fixed fee (8.9 M) already exceeds the v1 minimum fee of 64 inputs (~0.87 M), so P-7 fee uniformity is untouched. Templates need a two-budget selection for the PX class. |
| R5-1 / R6 deploy cap and fee | **Include the per-block deploy sub-budget and an exact (not `≥`) deploy fee at ≥ the v1 rate** | **Drop "≤ 2 deploy outputs"** once R12-2 (a) prices the v1 part. The registry should also move off-RAM, but that is policy, not v3. |
| R5-7 duplicate program ids | **Include** | Trivial. |
| R2-C6 feed-forward | **Include, conditional on the budget re-measurement** | The cost is lower than R2 says: guest code, no AIR change. It removes a trap for any future tree whose leaves are not anchored (I2's gap tree, contract state trees), and `node` is kernel-id-bound, so a later change costs another identity. If the budgets break, fall back to the written argument plus corrected comments. |
| R1-C6 64-bit guard | **Remove from the v3 list** | It is not consensus, and it already landed in `8097f66`. |

**Deferred list:** I agree with all of it.
- The branch id can come at the upgrade itself.
- The function window matters only if the trial includes non-vault contracts.
- PX-F4 B′ needs a prover-choosable `rcm` (I2-F1).

**Missing items.** These must ride v3, or they decide whether a v4 is needed:
1. **An activation framework (R1-C10 and §4.4, R7's kernel-id schedule).**
   - Consensus parts: `ChainParams.upgrades` (height → header version, kernel id and verifier set), with `header.version == version_at(h)`. It is a no-op with one entry, so no identity cost.
   - Policy part: an unknown *future* version is non-permanent and non-banning, with a WARN.
   - v3 binaries must carry both. Otherwise the first post-launch rule change either bans upgraded peers or forces a new genesis.
2. **Deploy budget caps (R7-5 corrected).** Reject `cycles > MAX_CYCLES` and any table budget above its `limits()` height at deploy. Add a total cap from ZK-F4 measurements once they exist.
3. **The intra-tx O-uniqueness rule** (§2.1), if the R6 change goes in.
4. **Re-measure before freezing.** F5, R2-C6 and the neutral build all move cycle counts. The known "widest two-function proof size vs MAX_PROOF_BYTES" gap must be closed *before* the v3 ids are pinned.
5. **Non-consensus, but format-freezing, so they should ship with the v3 wallet:**
   - R2-C2 hedging;
   - R2-C9: the `px/delivery-key/v2` label with `V ‖ H(ek)` and identity-`V` rejection;
   - I2-R1 / R11-W2/W3 seed and key derivation;
   - pinned real-permutation Hk and node vectors plus a consensus-fingerprint CI pin, so that post-launch drift of the v3 identity is caught.
6. **Consider (needs analysis, not required):** a header or coinbase commitment to the PX root (I1-F2 light-wallet integrity). It is identity-level, so v3 is the cheap moment. It is not needed for the trial.

**Items added to the plan after R15, R16 and I4** (read after my first draft):
- **Upgrade mechanism: include.** It matches my missing item 1.
  - The **branch id** in the v1 signature message and in `h_tx` is acceptable at v3. It changes every v1 and PX signature and test vector, and nothing more. It is not *required*, since it could be introduced at the first upgrade.
  - **The plan contradicts itself:** "ZIP-200 branch ids" is still under Deferred. Remove one of the two.
  - "`h_tx` is a public input, so no kernel change": I did not re-verify this. It is consistent with R5 (`px.rs:387-396`).
- **Genesis id in the P2P session key and in the wallet network check: include.** It is free at a reset.
- **Kernel neutrality (no located panics): include.** The `assert!` at `px-core/src/hash.rs:81-82,102` embeds panic locations, and so source paths, into the ELF. Folding this into item 2 is correct.
- **Genesis nonce from a Bitcoin block-hash beacon: include (tool only).**
  - It makes the genesis id, and so the first RandomX seed, unpredictable before launch. That is the actual M1 defence.
  - The timestamp must be fixed *before* the beacon block, and the D0 note above still applies.
- **Hybrid ML-KEM P2P handshake: exclude from v3.** It is transport, not identity, and can ship at any time.
- **Shielded coinbase: exclude by default.** Activate it later by height through the upgrade mechanism.

**Not recommended for v3:**
- I1 A1 grinding: recompute only after R4-01.
- v1 fee tiers (R-FEE1): a later tightening through the activation framework.
- A RandomX salt variant: it does not restore K1 against a recompiled xmrig.
