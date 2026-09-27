# R5: the PX private-transaction protocol, full-project review 2026-09-27

Reviewer: R5 (internal review, not an audit). Read-only. No builds were run. Code was read at `f677e55` on `rebuild/core`.

Evidence tags: **[math]** mathematically established, **[test: name]** covered by a named test (not re-run by me), **[src]** source-read, **[assumed]**, **[unknown]**.

Scope read in full:
- `px-core/src/{kernel,call,record,hash,lib}.rs`
- `px/src/{prove,state,tree,delivery,share,vault,wallet}.rs`
- `zkvm/guests/{kernel,vault}/src/main.rs`
- `tx/src/{px,px_builder}.rs`
- the PX parts of `tx/src/{validate,state,params}.rs`
- the PX parts of `wallet/src/{px,wallet}.rs`
- `docs/px.md` and `docs/reviews/px-f4-f5-analysis.md`

---

## 0. Executive summary

**The PX core is carefully built and, as far as I can read, sound for what it claims.** One Rust source serves as both the native kernel and the proven guest. Balance is checked with integer arithmetic. Every witness element gets a canonical check. Nullifiers bind `cm`, and `rho` derives from `nf_0`. The proof is bound to `h_tx` and the network. Registration is mandatory in `verify`. Proof shapes are fixed, and the pool contains any damage. I found **no soundness break** (no inflation, theft or double spend) in the kernel, the call binding, the state or the consensus integration.

What I did find falls into four groups:
1. **Economic and DoS issues.** The PX block budget has no working fee market: the fee is uniform and deploys are cheap. The contract registry grows without bound, and a miner can grow it for free.
2. **A structural gap in the contract model.** Functions have no clock, so timeouts and refunds are impossible. The 2×2 shape and the canonical-anchor lag strongly limit contracts with shared state.
3. **Two privacy overstatements or leaks in wallet-side code.** Shares carry `cm` and `rho` in clear. The view tag is not post-quantum.
4. **Scalability.** About 0.025 PX tx/s, about 5.9 GB/day of PX bytes at capacity, and no pruning path while PX-F3 stands. None of this blocks a 7-device trial. All of it blocks any mainnet claim.

**PX-F4/F5 recommendation (§2).** The owner has already decided on a fresh v3 genesis (M1), so the identity cost of a kernel change before the trial is essentially zero.
- **In v3:** PX-F5 option B, the platform-neutral kernel build, and two cheap non-kernel consensus fixes (reject duplicate program ids in a deploy; cap deploy bytes per block).
- **PX-F4:** keep it as a documented trust assumption for the trial. Implement an improved variant (B′, below) together with the contract-model redesign (timelocks, larger shapes, user-owned contract records, constrained delivery). All of those change the call format anyway. Doing B now means two call-format changes and does not fix the underlying delivery problem.

---

## 1. Findings

Previously known items (PX-F1..F5, ZK-F3/F4, the build path, zeroization, P-1/P-2, and the raw-u32 function outputs) are not repeated here as new. Where I deepen them, I say so.

| ID | Title | Class | Sev | Where | Conf. |
|---|---|---|---|---|---|
| R5-1 | Deploys crowd out the PX budget and grow the registry in RAM without bound; free for a miner | Partially implemented | **medium** (testnet) / high (mainnet) | `tx/src/params.rs:19,22,24`; `tx/src/state.rs:177-191`; `tx/src/px.rs:714-735` | high |
| R5-2 | No PX fee market: the uniform fee makes PX capacity cheaply censorable, and censored transactions expire after 100 blocks | Accepted limitation (needs decision) | medium | `tx/src/params.rs:29`; `tx/src/px.rs:681`; `chain/src/mempool.rs` (class ordering) | high |
| R5-3 | Contract functions have no clock: timeouts and refunds are impossible by construction | Not implemented | medium (design) | `px-core/src/call.rs:41-80`; `px/src/prove.rs:118-140` | high |
| R5-4 | A share exposes `cm` and `rho` in clear; the doc claims it "reveals nothing to anyone but the addressee" | Partially implemented | medium (privacy) | `px/src/share.rs:9-18,53-57`; docs/px.md §13.3 | high |
| R5-5 | The 2-input limit with no consolidation: `InsufficientFunds` although the balance suffices; each chained step waits up to 16 blocks | Partially implemented | medium (usability/liveness) | `wallet/src/px.rs:521-547`; `wallet/src/wallet.rs:1205-1232` | high |
| R5-6 | The 1-byte view tag derives from ECDH only, so a harvest-now quantum adversary can partly link recipients | Accepted limitation (wallet policy) | low | `px/src/delivery.rs:113-115,207` | high |
| R5-7 | A duplicate program id with different budgets in one deploy: the first match silently wins | Complete but requires further testing | low | `tx/src/state.rs:273-283`; `tx/src/px.rs:584-593` | high |
| R5-8 | A contract's identity is a function *input*, not intrinsic to the program. Safe (the registry keys on `(contract, program)`), but undocumented for authors | Complete and verified (src) | info | `zkvm/guests/vault/src/main.rs:59`; `px/src/prove.rs:233-238` | high |
| R5-9 | Contract state records can transition at most about once per anchor interval (16 blocks) under the canonical-anchor policy, and they contend on one nullifier | Accepted limitation | medium (design) | `wallet/src/px.rs:49-58`; `px/src/state.rs:26` | high |
| R5-10 | PX-F5 is a symptom of a missing record kind, the *user-owned contract record* | Not implemented (design) | info | `px-core/src/kernel.rs:275,337-377` | high |
| R5-11 | Chain growth: about 5.9 GB/day of PX bytes at capacity, with no proof pruning while PX-F3 re-verifies | Deferred | medium (mainnet) | `tx/src/params.rs:22` | high |
| R5-12 | An expired-anchor retry republishes the same nullifiers, linking the attempts; the wallet releases inputs but never rebuilds | Accepted limitation | low | `wallet/src/wallet.rs:816-827` | medium |
| R5-13 | No delegated proving: `sk` must sit on the proving machine (about 45 s, 3.8 GB), which excludes hardware wallets and phones | Accepted limitation (design) | info | `px-core/src/kernel.rs:265-275` | high |
| R5-14 | Stale capacity and performance numbers in docs/px.md ("about four" PX tx per block; 2.04 MB/42 s/188 ms) against the measured 3 per block and 2.18 MB/45 s/0.21 s | Partially implemented (docs) | low | docs/px.md:362,371,385,546 | high |
| R5-15 | Option F4-B alone lets a function derive `rcm` from public data. Proposed variant B′ mixes `rho` into `rcm` to keep per-output freshness | Design note | info | `px-core/src/call.rs:33-39` | high |

### R5-1: deploy crowding and registry RAM (deepens "deploys act as cheap transfers" and PX-F1)

**Facts [src]:**
- A deploy is up to 1 MiB (`MAX_DEPLOY_TX_SIZE`). It pays 2 atomic units per byte (`PX_FEE_PER_BYTE`), about 0.021 BLK for 1 MiB, and needs no proof.
- It counts against the same 8 MiB `MAX_PX_BLOCK_BYTES` as PX transactions.
- Its programs are parsed and kept forever in `MemoryChain.registry` (`tx/src/state.rs:177-191`), next to the body, which is already in RAM (PX-F1).
- The mempool ranks the PX class by fee per byte. A PX transfer pays an effective 8,912,896 / ~2.18 MB ≈ 4.1 atomic/byte; a vault call pays ≈ 3.3 atomic/byte.

**Scenario:**
- A deploy paying about 4.2 atomic/byte (1 MiB → ~0.044 BLK) outranks every PX transaction. Eight of them fill a block's PX budget for ~0.35 BLK. That is about 1.7% of a ~20 BLK reward, and needs no CPU.
- Every node then holds another ~8 MiB of ELF, plus the parsed programs, in RAM **forever**. That is about 5.9 GB/day.
- **A miner does this at zero cost:** it includes its own deploys and collects the fees back.

**Why the concern holds:** registrations are permanent state, unlike mempool spam.

**Confidence:** high for the mechanism [src]. The RAM size of a parsed `Program` is [unknown]; it is at least the ELF size [assumed].

**Recommendation:**
- a consensus cap on deploy bytes per block (e.g. ≤ 1 MiB);
- a much higher per-byte deploy fee (e.g. 20–50×, since registrations are permanent state);
- optionally, a burn of part of the deploy fee, so a miner cannot recycle it.

| Aspect | Assessment |
|---|---|
| Why | Bounded state growth |
| Security | Removes a free RAM DoS |
| Privacy | None |
| Performance | Positive |
| Complexity | S |
| Consensus impact | **CONSENSUS** |
| New identity | Yes; fits v3 |
| Difficulty | S |
| Priority | **P1** (before a public testnet); P2 for the closed 7-device trial |

### R5-2: no PX fee market

**Facts [src]:**
- `fee == PX_STANDARD_FEE` exactly (`tx/src/px.rs:681`).
- Capacity is about 3 transfers per block.

**Scenario:**
- An attacker deposits once. It then submits 3 valid PX self-transfers per block, each paying 0.089 BLK from PX: about 0.27 BLK per block, plus about 1.1 CPU cores of proving.
- Honest users cannot outbid, because the fee is fixed. Their transactions age out of the 100-block root window, and the wallet then releases the inputs (R5-12).
- A miner can do the same for free: the fees return to it.

**Why the uniform fee exists:** it is a deliberate privacy choice (P-7), and it is correct that a free fee is a fingerprint.

**Recommendation:** replace the single fee with a **small ladder of standard fee levels** (e.g. 1×, 2×, 4×, 8× base; consensus rule: fee ∈ ladder).
- It leaks at most 2 bits, and only under congestion, when most users choose the same level.
- It gives honest users a way to get in.
- Alternative: an EIP-1559-style uniform base fee per block. It is more complex, and a transaction built at one height may be mined at another.

| Aspect | Assessment |
|---|---|
| Why | Liveness of PX under adversarial load |
| Security | Better anti-censorship |
| Privacy | −2 bits at most, under congestion |
| Performance | None |
| Complexity | S |
| Consensus impact | **CONSENSUS** |
| New identity | Yes |
| Difficulty | S |
| Priority | P2 (the trial can run with the current rule; state the limitation) |

### R5-3: contract functions have no clock

**The problem [src]:** a function sees only its private input. The statement `(io_hash ‖ contract ‖ outputs)` carries no chain height or time, and the kernel has no expiry field. So the vault's "no timeout, no refund" is **structural**: no PX contract can express a timelock. This is not specific to the demonstration vault. Zcash has `nExpiryHeight` (ZIP-225/ZIP-203); Aztec and Aleo expose block data to public or finalize logic.

**Proposal ("anchor height as a clock"):**
- **Consensus:** extend the function prefix to `io_hash ‖ contract ‖ anchor_height`. The verifier fills in `anchor_height` from its root→height map (the root window already knows it).
- **Functions** read it as a private input and must echo it.
- **Inclusion bound:** consensus already bounds inclusion to `anchor_height < h_incl ≤ anchor_height + ROOT_WINDOW`.
- **What contracts can then express:**
  - "after T" as `anchor_height ≥ T`;
  - "before T" as `anchor_height + ROOT_WINDOW < T`.
- **Granularity:** 16 blocks under the canonical-anchor policy. A consensus-enforced canonical anchor would make this uniform.
- **No new public data:** the anchor already reveals its height.
- **The kernel id is unchanged.** `prove::statement` and function programs change.

| Aspect | Assessment |
|---|---|
| Why | Timelocks, refunds and HTLCs are the minimum for any real contract |
| Security | Enables trustless swaps |
| Privacy | None new [src]; the anchor height is already public |
| Performance | Negligible |
| Complexity | M |
| Consensus impact | **CONSENSUS** |
| New identity | Yes |
| Difficulty | M |
| Priority | P3 for the trial; required before contracts beyond the demonstration |

### R5-4: shares expose `cm` and `rho` in clear

**Facts [src]:**
- `share = version ‖ cm ‖ rho ‖ ciphertext` (`px/src/share.rs:53-57`).
- `cm` is an on-chain commitment, so anyone who sees a share on its channel (chat, e-mail, paste) learns **which on-chain record** is being shared, and with whom if the channel identifies them.
- Observers cannot compute the nullifier without `rcm`, so they cannot see the record's consumption. They do learn the record's identity and its position in the tree.
- The module doc (`share.rs:16-18`) and docs/px.md §13.3 say a share "reveals nothing to anyone but the addressee". That is an overstatement.

**Fix (wallet-only):** seal `cm ‖ rho ‖ opening` under a delivery key that is not bound to `cm`, or bind it to a share-specific AAD, and let the recipient check `cm` after decryption. Also correct the docs.

| Aspect | Assessment |
|---|---|
| Security | None |
| Privacy | + |
| Performance | None |
| Complexity | S |
| Consensus impact | none (policy/format of an off-chain object) |
| New identity | No |
| Difficulty | S |
| Priority | **P2**, and fix the doc claim now |

### R5-5: two inputs and no consolidation

**Facts [src]:** `select` finds one record ≥ the amount needed, or a pair. Otherwise it returns `InsufficientFunds` even when the total balance suffices. There is no `px-merge` command.

**Consequences:**
- Each merge costs 0.089 BLK and about 45 s of proving.
- The merged record is spendable only once the canonical anchor passes it: up to 16 blocks (~32 min).
- A wallet with 8 small records needs 3 sequential rounds, roughly 1.5–2 h, to pay one amount.

**Recommendation:** add `px-merge` and automatic pre-consolidation, and report "spendable after N merges" instead of `InsufficientFunds`. The long-term fix is larger shapes (§4).

| Aspect | Assessment |
|---|---|
| Consensus impact | none |
| Difficulty | S |
| Priority | P2 (before trial users hit it) |

### R5-6: the view tag is not post-quantum

**Facts [src]:** `view_tag = H32(ss_ec ‖ R)[0]`. An adversary that later breaks discrete logarithms can take a published address, recover `v`, and compute the tag for every past output. That filters about 255/256 non-matching outputs per address: a probabilistic recipient link. Content stays protected by ML-KEM.

**Context:** at PX volume (≤ 6 outputs per block), a wallet can decapsulate every output. One ML-KEM decapsulation per output per address is cheap [assumed].

**Recommendation:** make the tag byte random, or derive it from `ss_ec ‖ ss_kem`. Consensus only fixes the length.

| Aspect | Assessment |
|---|---|
| Privacy | + (post-quantum) |
| Performance | Scanning cost ×(1 + decapsulation/scalar-multiplication ratio) |
| Consensus impact | none |
| Difficulty | S |
| Priority | P3 |

### R5-7: duplicate program ids in one deploy

**Facts [src]:**
- `px_function` returns the first entry for `(contract, program_id)`.
- Nothing rejects a deploy that registers the same ELF twice with different budgets.
- It is deterministic, so this is not a consensus split. The proof-cache soundness argument (`validate.rs:717-723`) also still holds.
- But the second budget is unusable and misleading to tooling.

**Recommendation:** reject duplicate program ids in `check_deploy_structure`.

| Aspect | Assessment |
|---|---|
| Consensus impact | **CONSENSUS** (tightening) |
| New identity | Fits v3 |
| Difficulty | S |
| Priority | P2 |

### R5-8: contract identity is an input

**Facts [src]:**
- The vault reads `contract` from its input and writes it. The id derives from key image, salt and payload, so a program cannot know it at compile time.
- The same ELF can be registered under many contracts.
- **This is safe:**
  - `verify` checks `registered(slot contract, program id)`;
  - the kernel requires `call.contract == input.contract` for approvals and for contract outputs;
  - I tried cross-instance approval and redirection and found no path.
- **Contract authors must know that "self" is a checked input,** not a constant.

**Recommendation:** document it in the §13.4.1 author guide.

| Aspect | Assessment |
|---|---|
| Consensus impact | none |
| Priority | P2 (docs) |

### R5-9: shared-state throughput

**Facts [src]:**
- A contract state record is consumed by one transaction; a concurrent update of the same record loses on the nullifier.
- With canonical anchors, the next state record is spendable up to 16 blocks later.
- So a shared-state contract is limited to about one update per ~16 blocks.

**Comparison:**
- Aleo pairs private records with public `finalize` mappings [assumed; developer.aleo.org].
- Aztec has public functions executed by the sequencer [assumed; docs.aztec.network].
- Penumbra batches swaps per block with sealed inputs ([protocol.penumbra.zone/main/dex/swap.html](https://protocol.penumbra.zone/main/dex/swap.html)).

**Recommendation (v1 redesign):** a hybrid model with private records plus deterministic public state updates, which the owner's transparent-contract track could supply. A contract-specific anchor policy is also possible, e.g. allowing the tip root for contract inputs; it leaks timing and needs analysis.

| Aspect | Assessment |
|---|---|
| Consensus impact | CONSENSUS |
| Difficulty | L/XL |
| Priority | P3 |

### R5-10: the missing user-owned contract record kind

**Facts [src]:** a record with `contract ≠ 0 ∧ owner ≠ 0` is exactly what a *contract-issued token held privately by a user* should be (Aleo's model: records carry an owner and belong to a program). Today it is unspendable (PX-F5), because the input path forces `owner = 0` for contract records.

**Design for the redesign:**
- **Contract inputs** may have `owner ∈ {0, user_owner}`, chosen by a private flag. The kernel already computes `user_owner` for constant work.
- **User-owned contract records** need both `sk` and a function approval.
- **Their nullifier** is the `nk`-based one, so holders of the opening, including the issuer, do not see the spend.

This subsumes PX-F5 (B is still right for v3; a later kernel relaxes it deliberately) and is the natural basis for multi-asset records (§4).

| Aspect | Assessment |
|---|---|
| Consensus impact | CONSENSUS (kernel) |
| Difficulty | M |
| Priority | P3 |

### R5-11: chain growth

**Facts [src] and measurement:**
- At capacity: 8 MiB × 720 blocks/day ≈ 5.9 GB/day, about 2.1 TB/year, of mostly proof bytes.
- Proofs are in the prunable part, but PX-F3 (restart re-verification) and replay make every node keep them.

**Needed before mainnet, not the testnet:**
- a verified-proof marker in the store, integrity-protected;
- pruning of proofs older than K blocks for non-archival nodes;
- then aggregation (docs/reviews/aggregation-study.md).

| Aspect | Assessment |
|---|---|
| Consensus impact | none (pruning is policy) |
| Difficulty | M |
| Priority | P3 |

### R5-12: retries after anchor expiry

**Facts [src]:**
- After the window passes, the node answers "Invalid…". The wallet releases the inputs but does not rebuild (`wallet.rs:816-827`).
- A user rebuild publishes the same nullifiers with new commitments, so observers learn it was a retry. That is a minor timing link.

**Recommendation:** automatic re-prove on `PxUnknownAnchor`, with a user notice.

| Aspect | Assessment |
|---|---|
| Consensus impact | none |
| Priority | P3 |

### R5-13: no delegated proving

**Facts:**
- Orchard separates proving (full viewing key plus note openings) from spend authorization (a RedPallas signature with a rerandomized `rk`), so a hardware wallet can authorize without proving [assumed; Orchard book, keys].
- In PX, the proof *is* the authorization and needs `sk`.

**Research direction (post-quantum preserving):** commit a fresh WOTS/XMSS one-time public-key hash into each record. The proof then shows that the published one-time key matches the record, and the signature over `h_tx` is checked outside the proof. The prover would need only `nk` and the openings.

| Aspect | Assessment |
|---|---|
| Priority | P3, research |
| Consensus impact | CONSENSUS (record format) |

### R5-14: stale docs

- docs/px.md:362 and :371 give 2.04 MB, ~42 s and 188 ms.
- docs/px.md:385 and :546 say "about four PX transactions".
- With the measured 2.18 MB, ⌊8,388,608 / 2.18e6⌋ = 3; vault calls (2.69 MB) also fit 3.

Pass these to A16b.

### R5-15: an improved PX-F4 fix (B′)

- `OutSpec` gains an optional `rcm_seed`. The kernel sets `rcm = Hk(RCM, rcm_seed ‖ rho'_j)`.
- `rho'_j` is unique and public, so the result is fresh per output even if a contract reuses its seed, and parties who know the seed can recompute `rcm` from the chain alone.
- A contract that uses a public seed still leaks (as in B): lint and document this.
- Without a seed, the caller chooses `rcm`, as today (needed for payouts to parties who share no secret with the contract).
- The flag and seed are inside the blinded `io_hash`, so they stay private.

### Also checked, no finding (correct as designed)

- **Kernel checks:**
  - canonical witness elements and a boolean check on flags [src];
  - integer balance [math], [test: `every_check_rejects_its_violation`];
  - approval requires a real, contract-kind input of the same contract (`kernel.rs:312`);
  - contract outputs must be specified by their own contract (`kernel.rs:374`);
  - a spec's contract must be 0 or its own (`kernel.rs:250`);
  - specs conflict only across functions;
  - `nf_0 ≠ nf_1` [test: `contract_rules_reject_their_violations`, `nullifiers_are_unique_and_key_dependent`].
- **Record-kind confusion:** a user record cannot be spent as a contract record, or the reverse, because `cm` binds both `owner` and `contract` [math under Hk collision resistance].
- **Faerie Gold:** `rho'_j = Hk(RHO, nf_0 ‖ j)`, `nf_0` is chain-unique (dummies included), and `nf` binds `cm` [math].
- **State:** atomic apply and undo; undo removes only the nullifiers it inserted (`state.rs:125-130`); the pool as `u128` with `checked_sub` [src], [test: `blocks_apply_and_undo_exactly`, `double_spends_are_rejected_and_leave_no_trace`].
- **Tree:** the frontier equals the full tree; depth 32 fixed; empty leaf 0 [test: `frontier_and_full_tree_agree_and_paths_verify`].
- **Binding:**
  - `h_tx` covers prefix and base, including ciphertexts, function outputs and the network (`px.rs:387-396`);
  - the CLSAGs sign over the proof and the range proof;
  - the proof encoding is canonical (re-encode check, `zk/src/lib.rs:203`), so there is no txid malleability through proof bytes [src].
- **Proof-verification cache:** keyed by txid, which commits to the proof; registrations are immutable and fixed by the contract id [src]. The argument at `validate.rs:717-723` holds.
- **Registry-mandatory `verify`:** `verify_transfer` passes `|_,_| None`, so a statement with functions cannot verify [src].
- **Empty output slots:** they get real ciphertexts to throwaway addresses, not random bytes (`px_builder.rs:170-178`), so there is no validity leak through `R`. The throwaway `sk` uses a biased `% P`; that is harmless.

---

## 2. PX-F4 / PX-F5: independent recommendation

**Context the analysis document predates or underweights:**
- The owner has already chosen a fresh **v3 genesis** before launch (M1). A kernel change bundled into v3 costs **no extra network identity**, only engineering and re-validation: kernel reproduction, P-5 re-run, reset rehearsal.
- **B does not solve the delivery problem.** It solves only the `rcm` part. With my R5-15 refinement it becomes useful in combination with *function-level constrained delivery*: a function fixes `rcm` and publishes `Enc_K(value ‖ data)` under a contract key shared by the participants, as extra public output words. That encryption is a few Poseidon2 permutations inside the function [assumed cost]. This matches Aztec's "in-band constrained delivery" ([docs.aztec.network, note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery)). Aleo goes further and checks record encryption inside the circuit ([ProvableHQ/snarkVM](https://github.com/provablehq/snarkvm/releases); [zksecurity Aleo synthesizer audit](https://blog.zksecurity.xyz/2023-aleo-synthesizer.pdf)). Payouts to arbitrary third parties still need either a shared secret or in-proof KEM verification (option D, research-level).
- **The contract model will change again before real contracts:** R5-3 (clock), R5-9 (shared state), R5-10 (user-owned contract records), and larger shapes (§4). Each changes `OutSpec`, `io_hash` or the function prefix.

**My recommendation:**
1. **PX-F5: option B in v3.** It is a single constant-work check (`contract ≠ 0 ⇒ owner = 0` in the output loop, `kernel.rs:337-377`). It prevents silent burns now. When the redesign introduces user-owned contract records (R5-10), the rule is relaxed deliberately in that kernel.
   - Tests: a mutation case in `contract_rules_reject_their_violations`, a native/guest differential, and budget headroom.
2. **Platform-neutral kernel build in v3.** It removes a Windows-only reproducibility dependency from consensus. It changes the id anyway, so v3 is the moment.
3. **PX-F4: document it for the trial; implement B′ (R5-15) with the contract-model redesign, not in v3.**
   - Doing B now yields a call format that the redesign changes again, and it does not make multi-party contracts safe on its own.
   - Today's only contract (the vault) is not exploitable through F4.
   - The docs must state plainly that any multi-party contract today trusts its caller to deliver the openings, and that this is **griefable** (lock or burn), not only an inconvenience.
4. **Also in v3 (not kernel, consensus, small):**
   - reject duplicate program ids in a deploy (R5-7);
   - cap deploy bytes per block and raise the deploy fee (R5-1).

I therefore disagree mildly with the analysis's lean towards "option 3 if the trial should test the v1 kernel". **The v1 kernel is not designed yet** (see §4). The trial should test node, P2P, mining and PX transfers on a kernel with F5 fixed, and the contract model should be redesigned deliberately afterwards.

**On the related footgun (§4a of the analysis, approval not tied to value):** I recommend **not** enforcing per-contract value conservation in the kernel. It would forbid legitimate patterns (contract-paid fees, partial releases to the caller). Instead:
- document it;
- provide an SDK helper and lint that sums approved values against specified outputs;
- test it in every host helper.

| Aspect | Assessment |
|---|---|
| Consensus impact | none |
| Priority | P2 |

---

## 3. Subsystem answers (the brief's 13 questions, condensed)

### 3.1 Kernel, records, hash (`px-core`)
1. **Implemented:**
   - the 2×2 kernel with up to 2 functions;
   - hash-based keys;
   - user and contract records and nullifiers;
   - the Poseidon2 sponge and truncated-permutation tree nodes;
   - one source compiled natively and to RISC-V.
2. **Correct and well designed:**
   - integer balance [math];
   - canonical checks;
   - constant-work masking;
   - `nf` binding `cm`;
   - `rho` from `nf_0`;
   - domain and length separation in `Hk` [test: `domain_and_length_separate_outputs`];
   - no allocation, `forbid(unsafe_code)`.
3. **Incomplete:** `asset` fixed to 0; no clock (R5-3); no user-owned contract records (R5-10).
4. **Fragile:**
   - Poseidon2 over 31-bit fields is young (already flagged);
   - the kernel id depends on the rustc version and the build path (known);
   - budgets carry only ~6% headroom: any kernel edit needs re-measurement.
5. **Exploitable:** nothing found for value or theft. The PX-F5 burn needs a buggy contract.
6. **Inefficient:**
   - both owner forms and both nullifier forms are computed for every input (deliberate);
   - the depth-32 path is hashed for dummies (deliberate).
7. **Does not scale:** 2 inputs and 2 outputs (R5-5, R5-9).
8. **Missing:** multi-asset; expiry and clock; a viewing-key split (known).
9. **Redesign:** shape classes (§4); the record kind of R5-10; B′.
10. **Innovate:** anchor height as a clock (R5-3); function-level constrained delivery (§2).
11. **Before the testnet:** F5-B and the neutral build (in v3).
12. **Defer:** F4-B′, multi-asset, shapes.
13. **Never change:** see §6.

### 3.2 Proving and verification (`px/src/prove.rs`)
- **Correct:**
  - a native pre-check;
  - function prefixes checked before proving;
  - the guest output checked against the native output;
  - registry-mandatory verify;
  - shaped budgets per `n_fn`.
- **Fragile:** kernel budgets hard-coded per `n_fn`, with small headroom.
- **Does not scale:** 45 s and 3.8 GB per transaction (known); no delegation (R5-13).
- **Before the testnet:** nothing beyond the known items (ZK-F3/F4, the widest-proof size).

### 3.3 Consensus state (`px/src/state.rs`, `tx/src/state.rs`)
- **Correct:** atomic apply, exact undo, containment pool, a root recorded every block (so the window counts blocks) [src].
- **Fragile:**
  - everything is in RAM (known PX-F1/F2);
  - the registry grows without bound (R5-1).
- **Missing:** TreeFull is unreachable, 2^32 leaves at ≤ 4,320 per day (known).
- **Never change:** the pool containment rule; nullifiers once ever; anchors only from block-end roots.

### 3.4 Anchors and the tree
- **Depth 32, window 100, wallet anchors at multiples of 16.**
- **Anchor lag:** effectively 85–100 blocks remain after the anchor is chosen, enough under normal load. Under R5-2 congestion, transactions expire.
- **The multiple-of-16 policy is wallet-only.** A different client choosing tip anchors is fingerprintable. Making it consensus (anchor height ≡ 0 mod 16) would enforce the anonymity set across implementations.
  - Cost: records need up to 16 blocks to become spendable, for everyone.
  - Recommendation: consider it together with R5-3.

  | Aspect | Assessment |
  |---|---|
  | Consensus impact | CONSENSUS |
  | Priority | P3 |

- **Comparison:** Zcash transactions name an anchor root from "some block height in the past" (ZIP-225); anchor-depth choice is also wallet policy there [src: ZIP-225 text; wallet depths assumed].

### 3.5 Nullifiers
- **User nullifier:** `Hk(NF, nk ‖ rho ‖ cm)`, a PRF-based design (Zerocash-style). Unlike Orchard, it has no discrete-log component, which is post-quantum friendly, and its privacy rests on Poseidon2 as a PRF [assumed].
- **Contract nullifier:** `Hk(NFC, C ‖ rcm ‖ cm)`, observable by every holder of the opening (intended).
- **Dummy nullifiers** enter the set forever: 64 B per transaction, negligible.
- **Correct:** uniqueness [math], unlinkability without `nk` [assumed PRF].

### 3.6 Contract binding (approve, specify, `io_hash`)
- **Correct:**
  - approvals identify exact `cm`s;
  - specs are exact;
  - `io_hash` is a hiding commitment with a CSPRNG blind;
  - registry checks.
- **Fragile:**
  - PX-F4;
  - approval not tied to value (§2);
  - contract identity as an input (R5-8).
- **Missing:** a clock (R5-3); access to output `cm`/`rho` (a function cannot know `nf_0`, so it cannot chain on output commitments).

### 3.7 Bridge and fee
- **Correct:**
  - the v1-side balance equation (`px.rs:688-710`);
  - no hidden outputs without v1 inputs;
  - payouts carry clear amounts, like coinbase outputs;
  - the output context is unique through nullifiers.
- **Privacy (known, documented):** bridge amounts are public (containment). The CLI warns.
- **Fee:** R5-2 (market) and R5-1 (deploys).
- **A vault claim with a v1-paid fee** links the claimer's v1 ring activity to a claim of contract C at the ring-anonymity level. Low; document it.

### 3.8 Delivery and sharing
- **Correct:**
  - a hybrid KEM with a combiner over both secrets and both ciphertexts plus `cm`;
  - the AEAD with AAD `cm`;
  - Janus-style acceptance by recomputing `cm`;
  - one plaintext length for both kinds [test: `the_record_kind_cannot_be_misrepresented`, `every_tampering_is_detected`].
- **Known:** the combiner is "X-Wing-like" (V and H(ek) omitted).
- **New:** R5-4 (share metadata) and R5-6 (view tag).
- **Scalability:**
  - addresses are 1.25 KB;
  - scanning costs one scalar multiplication per output per address (no Orchard-style shared incoming viewing key, because a shared ML-KEM key would link addresses). This is an accepted trade-off for post-quantum unlinkable addresses.

### 3.9 Demonstration vault
- **Correct for what it claims:**
  - CLAIM pays exactly the record value;
  - LOCK specifies `owner = 0`;
  - the lock domain lies outside PX's range;
  - wrong secrets halt [test: `a_wrong_secret_cannot_claim`].
- **Limits:** no timeout or refund. This is **structural** (R5-3), not just vault scope; the docs should say so.
- **Front-running:** an observer cannot claim, because the secret is private. Every holder of the secret and the opening can race (documented).

---

## 4. Protocol-level comparison and what to redesign for v1

**Proof per 2-in/2-out private transfer:**

| System | Proof | Setup | Post-quantum soundness |
|---|---|---|---|
| **BlackSilk PX** | ~2.18 MB, 45 s | Transparent | Yes (hash-based STARK) [measured] |
| **Zcash Orchard** | 2720 + 2272·n bytes, i.e. 7,264 B for 2 actions ([ZIP-225](https://zips.z.cash/zip-0225)) | Transparent (Halo 2) | No: discrete log on Pasta |
| **Zcash Sapling** | 192 B Groth16 per spend or output | Trusted setup | No |
| **Penumbra** | Groth16 on BLS12-377 per action ([protocol.penumbra.zone](https://protocol.penumbra.zone/main/index.html)) | Trusted setup | No |
| **Aleo** | Varuna (KZG) per transition, records encrypted in circuit | KZG setup | No [assumed] |
| **Aztec** | Client-side proofs, rolled up | KZG setup | No [assumed] |

- **PX's genuine differentiators:**
  - end-to-end post-quantum hash-based ownership, nullifiers and proofs;
  - hybrid post-quantum delivery;
  - no trusted setup;
  - one kernel source for every party.
- **Its genuine cost** is about 300× Orchard's proof size, hence about 3 transactions per block.
- **Where the others are ahead:**
  - arbitrary action counts;
  - multi-asset pools (Zcash ZSA ZIP-226/227; Penumbra's single multi-asset pool);
  - in-circuit delivery (Aleo);
  - public-state hybrids (Aleo finalize, Aztec public functions, Penumbra batch auctions);
  - expiry heights (Zcash).

**Redesign candidates for the v1 kernel.** Each is CONSENSUS, needs a new kernel id, and should come as **one** deliberate kernel generation after the trial:

| # | Change | Why | Privacy | Performance | Difficulty | Priority |
|---|---|---|---|---|---|---|
| 1 | **Shape classes** (e.g. 2×2 and 4×4; the class is public, unused slots are dummies) | Amortizes the ~2 MB fixed proof cost over more records. Kernel cycles grow about linearly per input (~32 Poseidon2 calls per path) while proof size grows only with log(height) [assumed; measure with `px/examples/kernel_cycles.rs` and `proof_lengths.rs`] | Class is 1 bit | Better bytes per record | M | P3 |
| 2 | **Multi-asset records** (the `asset` field already committed; per-asset integer balance; asset id = issuing contract id; mint and burn only through functions) | Tokens | Asset hidden in `cm` | Small | M | P3 |
| 3 | **User-owned contract records** (R5-10) | Private tokens and contract positions | + | Small | M | P3 |
| 4 | **Clock** (R5-3) | Timelocks | None | None | M | P3 (before real contracts) |
| 5 | **B′** (R5-15) plus the constrained-delivery SDK | Multi-party safety | Neutral | Small | M | P3 |
| 6 | **Public-state hybrid** (R5-9) | Shared state | Documented leakage | — | XL | P3 |
| 7 | **Fee ladder** (R5-2) | Liveness | −2 bits | — | S | P2 |
| 8 | **Proof parameters** (108 → ~60 queries at Johnson ≥ 120; docs/px.md §8) | −35 to −55% size, i.e. about 5–6 transactions per block | None | Big | S (parameters) plus re-analysis | Owner decision; P3 |
| 9 | **Aggregation and pruning** (R5-11) | Chain growth | None | Big | XL | P3 |

---

## 5. Before the testnet (the 7-device trial), and what can be deferred

**Before the testnet (P0/P1 for the PX scope):**
- no P0 PX blocker was found beyond the items already known and in progress (P-1/P-2, the ZK items);
- with v3, as described in §2: F5-B, the neutral kernel build, R5-7 (duplicate program ids), R5-1 (deploy cap and fee; P1 before any public testnet);
- correct the docs: R5-4's claim, R5-14's numbers, F4 stated as a griefable trust assumption, and "no timeouts are possible" (R5-3).

**Deferred safely:**
- R5-2 (monitor PX congestion in the trial);
- R5-3, R5-5 (P2 wallet work), R5-6, R5-9 to R5-13;
- §4 items 1–9.

---

## 6. What should never be changed (without very strong reason)

- **Hash-based ownership and `nk`-based user nullifiers.** This is the post-quantum property.
- **Integer (`u128`) balance** in the kernel, with no field sums [math].
- **`rho` from `nf_0`, and `nf` binding `cm`** (Faerie Gold resistance).
- **The `asset` field inside the commitment.** It keeps multi-asset forward-compatible.
- **One kernel source,** native and guest; consensus pins the kernel id, not the source.
- **Fixed proof shapes** per budget, and a fixed ciphertext length for all record kinds.
- **The pool containment rule** (`pool ≥ 0`, in order).
- **`h_tx` binding over prefix, base and network,** with the CLSAGs covering the proof.
- **A mandatory registry** in `verify`, and immutable registrations fixed by the contract id.
- **Canonical checks** on every field element, in the witness and in the codec.
- **Tree depth 32 and anchors only from block-end roots.**

---

## Sources
- ZIP-225, v5 transaction format (Orchard proof size, anchor, `nExpiryHeight`): https://zips.z.cash/zip-0225
- Orchard book, keys: https://zcash.github.io/orchard/design/keys.html
- Aztec note discovery and constrained delivery: https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery ; https://hackmd.io/@mike-connor/BkGu-i2mee
- Aleo / snarkVM (records, in-circuit encryption check): https://github.com/provablehq/snarkvm/releases ; https://blog.zksecurity.xyz/2023-aleo-synthesizer.pdf
- Penumbra (multi-asset shielded pool, batch swaps): https://protocol.penumbra.zone/main/index.html ; https://protocol.penumbra.zone/main/dex/swap.html
