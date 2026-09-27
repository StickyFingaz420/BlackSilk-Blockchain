# I1: Private computation (innovation research), full-project review 2026-09-27

**Reviewer:** I1, innovation researcher. This is internal review, not an audit.
**Method:** read-only. No builds were run. Code was read in the main checkout; the brief's HEAD for the code is `f677e55` on `rebuild/core`. Web research is cited in §9. No repository content was sent to any service.
**Inputs:**
- `review-brief.md`;
- R5 (PX protocol) and R7 (contract strategy). This report builds on their recommendations and does not repeat them: PX-only contracts, the function height window, approval records, message commitments, and aggregation as the throughput gate.

**Evidence tags:**
- **[math]:** mathematically established;
- **[test: name]:** covered by a named test;
- **[src]:** read in the source;
- **[web]:** an external source, cited in §9;
- **[estimate]:** my own arithmetic or estimate, still to be measured;
- **[assumed]**;
- **[unknown]**.

---

## 0. Executive summary

1. **Most of the "advanced" private-computation toolbox does not fit BlackSilk's priorities.** I recommend rejecting the following, with the reasons given in §6:
   - **Curve-based folding** (Nova, HyperNova, ProtoStar, ProtoGalaxy). Its soundness rests on discrete logarithms, which breaks requirement R4 (post-quantum soundness). It would also need non-native BabyBear arithmetic.
   - **FHE and threshold-encryption shared state** (the Zama and Penumbra styles). Both need a key-holding committee. A PoW chain has none, and Zama's committee also relies on TEEs.
   - **TEE-based confidentiality** (the Secret Network model).
   - **Third-party delegated proving.** The prover learns the witness.
   - **Proving RandomX inside a STARK**, to build a succinct light client.
   - **GPU proving in consensus code.** Driver FFI is unavoidable.
2. **What does fit** is a small, coherent set of techniques that are hash-based end to end:
   - STARK-in-STARK recursion over the same field and hash as today (BabyBear and Poseidon2);
   - hash-based cross-contract messages and contract-scoped tags;
   - a post-quantum confidential multi-asset extension of the existing `asset` field;
   - compact, proof-free wallet synchronization.
   All of them keep the post-quantum property and the pure-Rust rule.
3. **Four new repository-grounded findings:**
   - **I1-F1:** the prior-art section of zk.md (§17) omits **Neptune Cash**. It is a live PoW chain with STARKs, post-quantum privacy, hidden lock and type scripts, custom tokens and per-block transaction merging, so several BlackSilk novelty statements need correcting.
   - **I1-F2:** light wallets download **whole blocks as hex, proofs included**. At PX capacity that is about 16 MiB per block, which rules out privacy-preserving light wallets. A proof-free "compact PX feed" gives the same privacy at roughly 1/1000 of the bandwidth.
   - **I1-F3:** the prover is almost certainly built **without SIMD**. Plonky3's packed BabyBear arithmetic is compiled only when `target_feature = "avx2"` is set, and nothing in the repository sets it. This may be a cheap proving speedup with no consensus impact, but it has a consensus-split hazard if it is applied to the verifier.
   - **I1-F4:** proof size and proving time are dominated by the **generic zkVM table width**, not by the kernel's computation. A transfer (about 25k cycles) pays for 23 general-purpose tables. This is the structural reason for the 2.18 MB and 45 s figures, and the largest lever available.
4. **Differentiators (§7).** There are three honest ones. None is a "first", and Neptune Cash is prior art for parts of each.
   - **D1: post-quantum *programmable* private execution** with stateful contract records, where the proof system, ownership, nullifiers, delivery and a future recursion layer are all hash-based or lattice-based. None of the seven named chains has this.
   - **D2: function-hiding private calls with private cross-contract messages,** built on post-quantum recursion. Aztec hides functions, but not post-quantum. Aleo reveals the function.
   - **D3: aggregation that never sits on the mining critical path.** RandomX CPU mining stays prover-free. Aggregation is deferred and permissionless, and new nodes use proof-carrying synchronization. This contrasts with Neptune, whose block composers need tens of GB of RAM and many cores.
5. **Almost everything here is P3** (after the trial). Three items fit before or around the testnet:
   - **I1-F1 (docs):** P0 as part of the documentation work, because it concerns novelty claims;
   - **I1-F2, the compact PX feed:** P2, no consensus change;
   - **I1-F3, a SIMD build for the wallet prover only:** P2, no consensus change.
   One parameter item belongs in the v3 bundle **only with owner approval**: raising the grinding bits (A1), bundled with the known M1 fix (`COMMIT_POW_BITS ≥ 1`).

---

## 1. Baseline: the constraints that decide every idea

| Fact | Evidence | Why it matters here |
|---|---|---|
| Soundness must not rest on discrete logarithms; privacy must survive a quantum adversary (R4). Transparent setup (R3). No TEE. Client-side proving; witnesses are never sent to third parties (R8) | docs/zk.md §1 [src] | Rules out curve folding, KZG/Groth16 wrappers, TEEs and witness-revealing delegation |
| Pure Rust, no C/FFI, `forbid(unsafe_code)` in project crates | brief [src] | GPU drivers, C++ FHE and MPC libraries, and ICICLE are excluded from consensus and from default builds |
| Proof system: Plonky3 0.7 batch STARK over BabyBear, degree-8 extension, Poseidon2 Merkle and Fiat–Shamir, 108 queries, blow-up 8, query PoW 16 bits, commit PoW 0 | `zk/src/params.rs:32-73` [src] | The hash and field are recursion-friendly: a STARK can verify a STARK without emulating a foreign hash (aggregation-study §3.3) |
| Transfer: ~2.18 MB, ~45 s, 3.8 GB peak, 0.21 s to verify; about 3 PX transactions per 8 MiB block | brief (measured) | Throughput is about 0.025 PX tx/s. Every "shared state" design must survive this |
| The transfer kernel is **~25.0–25.2k cycles**; each function adds about 4k cycles to the kernel side, plus its own execution | docs/px.md:214-215,361 [src] | The computation is small. The cost is the fixed width of the zkVM tables (I1-F4) |
| Byte breakdown: 60.4% opened trace rows, 18.5% their authentication (10.1% hiding salts), 13.7% FRI | aggregation-study §1 (measured on the 2.04 MB proof) | Proof size scales with columns × queries. Recursion or width reduction are the only big levers |
| The widest statement commits 4,999 base columns in 23 tables | `zk/src/params.rs:85-89` [src] | Confirms that width dominates |
| Record: `cm = Hk(owner ‖ contract ‖ asset ‖ value ‖ data ‖ rho ‖ rcm)`, with `asset` fixed to `ZERO_DIGEST` in the kernel | `px-core/src/record.rs:8,49-55`; `kernel.rs:279,347` [src] | Multi-asset needs only a kernel generation, not a new record format |
| No recursion anywhere; §9.4 keeps it "available for later aggregation" | docs/zk.md §9.4 [src] | Every scaling and function-privacy idea waits on one recursion milestone |
| Consensus is PoW (RandomX); there is no validator set and no committee | brief [src] | Any design with a threshold key has no one to hold that key |
| Wallet synchronization downloads whole blocks and the complete commitment list; it never queries individual records | `wallet/src/px.rs:4-14`; `rpc/src/lib.rs:94-100,165-183` [src] | Scanning is already private ("download everything"), but it costs whole blocks (I1-F2) |

---

## 2. New findings

| ID | Title | Class | Sev | Where | Conf. |
|---|---|---|---|---|---|
| I1-F1 | Prior art omits Neptune Cash; the novelty statements need revision | Partially implemented (docs) | low (but P0 for claims) | docs/zk.md §17 (lines ~877-895) | high |
| I1-F2 | Wallet sync transfers whole blocks as hex, proofs included; light wallets do not scale | Partially implemented | medium (scalability; enables privacy-preserving light clients) | `rpc/src/lib.rs:94-100` (`BlockEntry.hex`), `:19` (`MAX_BLOCKS_PER_REQUEST = 100`); `wallet/src/node.rs:7` | high |
| I1-F3 | The prover is built without SIMD: Plonky3 packed BabyBear is compiled only under `target_feature="avx2"`, and nothing sets it | Not implemented (performance) | low (performance) / info | `~/.cargo/registry/.../p3-monty-31-0.7.0/src/lib.rs:26-49`; no `.cargo/config*`, no RUSTFLAGS or target-cpu anywhere in the repository | medium-high |
| I1-F4 | Transfers pay the generic zkVM's fixed table width; the kernel's own work is small | Accepted limitation (design) | info (design) | `zkvm/src/air/*.rs` (per-table `WIDTH`), `zk/src/params.rs:85-89`, docs/px.md:214 | medium |

### I1-F1: Neptune Cash is missing from prior art

**Facts [web]:**
- Neptune Cash has run a mainnet since February 2025.
- It uses Nakamoto-style PoW and STARKs (Triton VM).
- It claims post-quantum primitives throughout.
- Its lock and type scripts are hidden behind commitments.
- It supports custom tokens through type scripts.
- It merges all pending transactions into one per block, with recursive proofs.
- It gives newcomers fast synchronization, and uses mutator sets instead of a growing nullifier set.

**The problem [src]:**
- docs/zk.md §17 compares only with Zcash, Zexe/Aleo, Aztec, Penumbra, RISC Zero/SP1 and Monero, and states "what we believe is new".
- Any BlackSilk statement of the form "post-quantum private chain with STARKs" or "hidden scripts" would be wrong without the Neptune comparison.
- The same section, and §14, also assume v1 Wasm "facts" integration and "external audits". Both conflict with R7's PX-only recommendation and with the owner's no-external-auditor policy. Pass this to A16b.

**Recommendation:**
- Add Neptune (and Mina for recursive chain state) to §17.
- Rephrase the novelty list as differences, not firsts (see §7).

| Aspect | Assessment |
|---|---|
| Security | None |
| Privacy | None |
| Complexity | S |
| Consensus | none |
| Identity | no |
| Priority | **P0 (docs)**, because it guards against overclaiming |

### I1-F2: whole-block wallet synchronization

**Facts [src]:**
- `BlockEntry` carries `hex: String`, the full serialized block, so the wire size is 2× the block size.
- Up to 100 blocks go in one response.
- The PX wallet learns its records "only from data every wallet downloads alike: whole blocks".

**Arithmetic [estimate]:**
- At PX capacity, a block carries about 8 MiB of mostly proof bytes, so about 16 MiB of hex per block.
- That is about 11.8 GB of hex per day, and up to about 1.6 GB in one 100-block response (this deepens the known "unbounded responses" item).
- What a wallet actually needs per PX transaction:
  - 2 nullifiers;
  - 2 commitments;
  - 2 delivery ciphertexts (hybrid ML-KEM, on the order of 1–1.5 KB each [assumed]);
  - the anchor and the function outputs.
- That is about 3–4 KB per transaction against about 2.2 MB: a reduction of roughly 500–700×.

**Why it matters for this topic:** "download everything" is the strongest private-synchronization model available. It is information-theoretically private against the server, which is better than FMD, OMR or PIR. BlackSilk already has the model. It fails only because it drags the proofs along.

**Recommendation: a `/px/compact?from=` feed.**
- Per block: height, block id, PX root, and for each PX transaction its nullifiers, commitments, ciphertexts and anchor.
- Binary (postcard), bounded per response.
- The wallet checks the feed against the block's header chain and the root it already verifies (`wallet/src/px.rs:13-14`).
- To keep integrity without trusting the node, the wallet recomputes the tree root from the feed and compares it with the root that a trusted-work header commits to. **Today no header commits to the PX root [assumed; to verify].** If none does, the feed is trusted for completeness, as whole blocks are today unless the wallet checks PoW (W-F6).

| Aspect | Assessment |
|---|---|
| Security | Neutral (the same trust as today) |
| Privacy | Neutral to positive: it keeps download-all feasible as volume grows |
| Performance | ~500× less wallet bandwidth |
| Complexity | S–M |
| Consensus | none (RPC and wallet only) |
| Identity | no |
| Difficulty | S–M |
| Priority | **P2** |

### I1-F3: the prover is built without SIMD

**Facts [src]:**
- `p3-monty-31` 0.7.0 selects its AVX2 or AVX-512 packed field implementation only under `#[cfg(target_feature = "avx2")]` (lib.rs:26-49).
- The default `x86_64-pc-windows-msvc` target does not enable AVX2.
- A repository-wide search finds no `.cargo/config*`, no `target-cpu`, no RUSTFLAGS and no mention of AVX.
- **So the measured ~45 s proving time is very likely the scalar fallback [assumed].** The speedup from packing is [unknown]; it needs measurement.

**Recommendation:**
- Build the **wallet prover** with `-C target-cpu=x86-64-v3`, either as a second binary with runtime CPU detection or as a documented build profile.
- Leave the node's verifier on one pinned build, or add a CI differential job: verify a corpus of valid and mutated proofs with both builds and require identical accept/reject results.
- **The hazard:** a bug in a SIMD field path that only some nodes compile is a consensus split.
- Plonky3's SIMD code contains `unsafe` intrinsics. They live in a third-party crate that is already a dependency, so project crates stay `forbid(unsafe_code)`. Note it in the dependency review.

| Aspect | Assessment |
|---|---|
| Security | Neutral for the prover; a split risk for the verifier (mitigated as above) |
| Privacy | + (faster proving means less time between building and broadcast, and phones become more plausible) |
| Performance | Potentially large for the prover [unknown] |
| Complexity | S |
| Consensus | none, if the verifier build is pinned or differential-tested |
| Identity | no |
| Difficulty | S |
| Priority | **P2** (measure first) |

### I1-F4: width, not work, drives the cost

**Facts:**
- Per-table widths from source [src]:
  - CPU `SP2+1`;
  - ALU add 18, bit 15, less-than 25, multiply 44, shift 35;
  - byte 4;
  - Poseidon2 `P2_COLS + 16·PER_WORD` (aggregation-study: 224 of its columns are output byte decomposition);
  - plus memory, program, image and output tables.
- Every transfer opens all committed columns at every one of 108 queries.
- The kernel's real work: about two depth-32 Merkle paths (about 64 Poseidon2 permutations), a handful of commitment and nullifier hashes, and u128 arithmetic [src: px.md §6; my count, estimate].

**Implication:** a transfer pays a general RISC-V machine's fixed width for what is essentially a fixed hash circuit. This is the deeper reason why A3 (a dedicated transfer AIR) and recursion are the only large levers. Parameter changes give tens of percent; the architecture gives multiples. See §3, A2 and A3.

**Classification:** accepted limitation. It is a deliberate choice: one Rust source for the kernel, for assurance. Record the trade-off explicitly in docs/zk.md §10.

---

## 3. Ideas: proof size and proving acceleration

Each idea is given the brief's recommendation fields.

### A1. Trade queries for grinding (a parameter decision, not new cryptography)

**Proposal:** raise `QUERY_POW_BITS` from 16 to 20–24 and lower `NUM_QUERIES` so that both targets remain met: unique decoding ≥ 100 and Johnson ≥ 120 (`params.rs:64-67`).

**Arithmetic [estimate; must be recomputed with `p3-security` as `zk/examples/param_study.rs` does]:**
- At rate 1/8, a unique-decoding query gives about −log₂((1+ρ)/2) ≈ 0.83 bits.
- Today: 108 × 0.83 + 16 ≈ 105.6 ≥ 100. This is consistent with the binding constraint being unique decoding.
- With 24 grinding bits: (100 − 24) / 0.83 ≈ 92 queries.
- **Result:** about −15% queries, so about −13% proof size (about 92% of the proof scales with queries).
- **Prover cost:** about 2^24 Poseidon2 permutations, a few seconds spread over cores [estimate].
- **Verifier cost:** one hash.

**Bundle it with the known M1 fix** (`COMMIT_POW_BITS ≥ 1`, which also binds the FRI witnesses). Both change the parameter set, and so the transcript.

**Caveat:** grinding security is "work-based". An adversary with 2^k more compute gains k bits against it exactly as against queries. This is standard practice (ethSTARK, Plonky3 defaults). The owner's rule 5 applies: no reduction without analysis and an explicit decision.

| Aspect | Assessment |
|---|---|
| Why | ~13% more PX per block at no new cryptographic assumption |
| Security | Neutral at equal computed bits; needs the re-analysis |
| Privacy | none |
| Performance | −13% bytes; +few s proving |
| Complexity | S |
| Consensus | **CONSENSUS** (parameter set) |
| Identity | new; fits v3 only with owner approval, otherwise a verifier-registry entry later |
| Difficulty | S (plus analysis) |
| Priority | P2 (owner decision) |

### A2. Width reduction

Aggregation-study §3.2 already recommends width reduction: merge the ALU layouts, and replace the Poseidon2 output-byte decomposition with field-element memory for hash buffers. **I endorse it.** I1-F4 says why it is the right order: it acts on the dominant 60%.

**Add one idea:** a **"Poseidon2 absorb from field-element memory" syscall variant** for the kernel. The kernel hashes field elements, not bytes. The 224-column output decomposition exists only to hand bytes back to the RISC-V memory. This touches soundness-critical AIR code and needs the full mutation cycle.

| Aspect | Assessment |
|---|---|
| Why | The dominant cost is opened width (§1) |
| Security | Neutral; the change touches soundness-critical AIR code |
| Privacy | none |
| Performance | −10 to −25% bytes [estimate] |
| Complexity | M |
| Consensus | **CONSENSUS** (the kernel and zkVM ids change) |
| Identity | new, or an activation height through the verifier registry |
| Difficulty | M |
| Priority | P3 |

### A3. A dedicated transfer statement (a "kernel AIR") beside the zkVM

**Idea:** prove plain PX transfers (no functions) with a hand-written AIR: a Poseidon2 table plus a small arithmetic table for u128 balance and canonical checks. Keep the zkVM only for transactions that call functions.

**Estimate [estimate, unmeasured]:**
- The kernel needs about 70–80 permutations, so the Poseidon2 table would have about 2^7 rows.
- The widths would be a few hundred columns instead of about 4,000–5,000.
- Proof size should fall by a small multiple (3–8×) and proving time by more.
- It would be consistent with Orchard-class circuits being small. **Measure before believing.**

**Cost:**
- It gives up "one Rust source for native and guest" for the most common statement. It reintroduces hand-written constraints in the most error-prone place (zk.md §6.4).
- It needs:
  - an independent native model;
  - differential tests against the zkVM kernel on the same witnesses;
  - mutation testing of every constraint;
  - its own review.
- **Privacy cost:** transfers and function calls become distinguishable by proof type. They already are distinguishable through the program ids (P-8), so nothing new leaks.

| Aspect | Assessment |
|---|---|
| Why | The only non-recursive way to multiply PX capacity |
| Security | Risk: a new soundness-critical circuit |
| Privacy | none new |
| Performance | large [estimate] |
| Complexity | L |
| Consensus | **CONSENSUS** (new verifier-registry entry) |
| Identity | activation height through the registry (zk.md §9.5, which must be implemented first) |
| Difficulty | L |
| Priority | P3. Do a measurement spike first, with no consensus code |

### A4. WHIR or STIR instead of FRI

**Facts [web]:**
- WHIR (ePrint 2024/1586, EUROCRYPT 2025) needs fewer queries and verifies in hundreds of microseconds.
- Plonky3 ships `p3-whir`, releases v0.7.0 and v0.8.0, as a **multilinear** polynomial commitment scheme, with a hiding variant that was reworked in 2026 PRs.

**Why it is not a drop-in:**
- BlackSilk's stack is univariate `p3-uni-stark`/`batch-stark` with the hiding FRI of ePrint 2024/1037.
- Moving to WHIR means a sumcheck-based multilinear STARK: in effect a new proof system.
- Its zero-knowledge analysis would restart from zero; zk-coverage.md §3 would not carry over.

**Recommendation:** evaluate it only together with the Plonky3 0.8 upgrade, which is a hard fork anyway. Adopt it only when the hiding WHIR has a published ZK analysis you can check.

| Aspect | Assessment |
|---|---|
| Why | Fewer queries and faster verification |
| Security | New analysis needed, especially for zero knowledge |
| Privacy | The ZK argument must be redone |
| Performance | Plausibly smaller proofs and faster verification; the magnitude is unknown for this workload |
| Complexity | XL |
| Consensus | **CONSENSUS** |
| Identity | new, or a registry entry |
| Difficulty | XL |
| Priority | P3 (monitor) |

### A5. Recursion (STARK-in-STARK) as the one enabling milestone

**Status [web]:**
- `Plonky3/Plonky3-recursion` offers a fixed recursive verifier for `p3-uni-stark` and `p3-batch-stark`.
- As of August 2026 it is marked **WIP and unaudited**, and its extension field is not yet fully parametrizable. BlackSilk uses degree 8, which needs checking.
- Aggregation-study §3.3 estimates about 10^5 rows per verified proof with a dedicated circuit, and "not viable" through BVM-1 (about 25M cycles against `MAX_CYCLES` = 2^21).

**Recursion unlocks four distinct things.** They should be designed together but shipped separately.

| # | Use | What it gives | Consensus |
|---|---|---|---|
| A5a | **Proof-carrying sync (off-consensus).** Archival nodes publish a proof that "the PX proofs of blocks a..b verified". A syncing or restarting node verifies it instead of N proofs, then applies the public nullifiers and commitments itself | Fixes the cost of PX-F3 (restart re-verification) and enables proof pruning (R5-11) **without any consensus change**. Nodes trust the recursion circuit's soundness, and consensus still accepts blocks by full rules | **none** (policy; a node can fall back to full verification) |
| A5b | **Deferred block aggregation (consensus).** Blocks keep carrying individual proofs. Any party may later publish an aggregate for a finalized range, paid from a fee share, and after depth K nodes may drop the individual proofs | Chain-growth fix (5.9 GB/day at capacity), off the mining critical path (D3) | CONSENSUS (an aggregate object and its validity) |
| A5c | **Per-transaction wrapper (function privacy).** The user proves "I have a valid PX proof whose function program ids are in the registry Merkle root R", and publishes only the wrapper | Hides which contract or function ran (P-8); Zexe-level function privacy; enables D2 | CONSENSUS (new tx form); a registry commitment tree |
| A5d | **In-block aggregation by the miner** | Smaller blocks immediately | CONSENSUS. **Not recommended** (see below) |

**Why A5d is not recommended:**
- A 2-minute PoW block would have to be proven by the miner before it is mined, which puts a heavy prover on every miner.
- Neptune's composers are reported to need tens of GB of RAM and dozens of cores (one benchmark: about 83 s on 64 cores with 160 GB RAM for full blocks [web, secondary]).
- That centralizes block production and conflicts with "strong decentralization" and RandomX CPU mining.

**Recommendation:**
- Treat recursion as the **PX-4 milestone** from zk.md §14.
- Order the work: **A5a first** (no consensus, immediate operational value), then A5c (privacy), then A5b.
- Either pin Plonky3-recursion at a reviewed commit, or build a dedicated circuit. Either way it gets its own review, mutation testing and adversarial-proof cost measurement (as for ZK-F4).
- A5c must keep the inner proof's zero knowledge. The outer proof must itself be hiding; otherwise the wrapper leaks the inner openings.

| Aspect | Assessment |
|---|---|
| Why | The gate for throughput, pruning, fast sync and function privacy |
| Security | Adds a soundness layer (the recursion circuit) that all pruned nodes trust |
| Privacy | A5c: large +. A5a/A5b: neutral |
| Performance | Large + for chain and validation; the aggregator pays proving |
| Complexity | XL |
| Consensus | A5a none; A5b and A5c **CONSENSUS** |
| Identity | activation heights through the registry |
| Difficulty | XL |
| Priority | P3; A5a is the first step after the trial |

### A6. Folding schemes

**Nova, HyperNova, ProtoStar, ProtoGalaxy (curve-based): reject.**
- Their folding uses homomorphic commitments over elliptic curves (Pedersen and IPA, often KZG for the final SNARK), so **soundness rests on discrete logarithms** and breaks R4.
- They also need either non-native BabyBear arithmetic or a move of the whole stack to a curve field.
- Aztec's Chonk (HyperNova-style folding plus Goblin) shows what they buy: sub-3-second client proofs on laptops [web]. The price is a non-post-quantum stack, which is exactly BlackSilk's differentiator (D1).

**Lattice folding (LatticeFold, LatticeFold+, Neo/SuperNeo): monitor, research only.**
- Neo works over small fields such as Goldilocks and gives plausible post-quantum security [web: ePrint 2025/294, 2026/242].
- It is 2025–26 research, with no audited Rust implementation known to me [unknown].
- Lattice commitments add new assumptions (Module-SIS) beside the current hash-only soundness.
- Revisit it no earlier than a mainnet-scale redesign.

| Aspect | Assessment |
|---|---|
| Security | Curve: violates R4. Lattice: new assumption, young |
| Consensus | CONSENSUS if adopted |
| Priority | Curve: **rejected**. Lattice: P3 research watch |

### A7. GPU proving in Rust

**Facts [web]:**
- CubeCL writes GPU kernels in Rust for the wgpu, CUDA and ROCm runtimes.
- Every GPU path still ends in a vendor driver (Vulkan, DX12, CUDA): C-ABI FFI and `unsafe`.
- ICICLE and similar libraries are C++/CUDA and are excluded.

**Recommendation:**
- GPU is allowed only as an **optional, out-of-tree prover accelerator**. It is never in node, verifier or miner builds, never on by default, and never a consensus dependency (zk.md R5 already says so).
- **Do CPU first:** I1-F3 (SIMD) and A2 (width) are cheaper and pure Rust.

| Aspect | Assessment |
|---|---|
| Security | Isolated from consensus |
| Privacy | The witness stays on the device, so neutral |
| Performance | Potentially large for the DFT and Merkle hashing |
| Complexity | L |
| Consensus | none |
| Priority | P3 |

### A8. Client-side proving with delegation

| Variant | Verdict | Reason |
|---|---|---|
| Third-party prover sees the witness, with authorization kept separate (Aleo's delegated proving; Aleo's docs describe TEE-based services and state that outsourcing sacrifices privacy [web]) | **Reject** as a protocol feature | Violates R8. The prover learns amounts, recipients and records, even though it cannot steal |
| Prover in a TEE | **Reject** | No trusted hardware (zk.md non-goals; the Secret Network 2022 lesson in R7) |
| MPC or collaborative proving (zkSaaS-style secret-shared witness) | Reject for now | Research-grade, heavy communication, non-collusion assumptions, no pure-Rust audited stack [assumed] |
| **Same-owner split** (R5-13): records commit to a hash-based one-time public-key hash; the proof shows the published one-time key matches; the signature over `h_tx` is verified outside the proof (WOTS+ or XMSS over Poseidon2). A phone or hardware wallet authorizes; the owner's *own* desktop or home server proves with `nk` and the openings | **Recommended research** (P3) | Keeps R8 (no third party), makes hardware wallets possible, stays post-quantum. The prover learns everything except spend authority, so this is only for machines the user trusts with viewing |

For the last variant:

| Aspect | Assessment |
|---|---|
| Consensus | CONSENSUS (kernel generation plus record format) |
| Identity | new kernel generation |
| Difficulty | L |
| Priority | P3 |

---

## 4. Ideas: private computation features

### B1. Confidential multi-asset records (the `asset` field)

**Design sketch:**
- **Asset id:** `asset = Hk(ASSET, issuing_contract ‖ tag)`, so it is domain-separated from BLK (`ZERO_DIGEST`).
- **Balance:** the kernel checks balance **per asset** over the fixed slots.
  - With N inputs and N outputs, compare each output's asset against each input's and sum in u128 per matched class. Constant work, O(N²) comparisons; trivial at N = 2 to 4.
  - The bridge and the fee are BLK-only.
- **Issuance and burn** only through the issuing contract's function, as an explicit `mint(asset, amount)` or `burn` field that the function must specify. Consensus tracks **per-asset supply**, either public like ZSA issuance or hidden with a per-asset pool bound. Containment (R7) extends per asset.
- **Privacy:**
  - one pool; the asset is hidden inside `cm`;
  - **ordinary token transfers must not call the issuing contract,** or the program id reveals the asset (P-8). So transfers are kernel-only, and only mint and burn touch the contract;
  - Penumbra and Namada use the same "single multi-asset pool" idea; Zcash ZSA brings it to Orchard [web]. **None of those is post-quantum.**

**New constraint (not in R5 or R7) [src + estimate]:**
- A token transfer that pays its fee in BLK needs:
  - a token input and a BLK input;
  - three outputs: the token to the recipient, token change and BLK change.
- The 2×2 shape cannot do that without an exact-change BLK record.
- So B1 **requires** either shape classes (R5 §4 #1, e.g. 3×3 or 4×4) or a v1-side fee payment (bridge), which links to the ring layer.
- **Conclusion:** B1 and shape classes are one kernel generation. Do not ship B1 on 2×2.

| Aspect | Assessment |
|---|---|
| Why | Tokens and stable assets without splitting anonymity sets |
| Security | New per-asset conservation; mint and burn authority is contract logic |
| Privacy | +. Asset hidden; a single pool |
| Performance | Small kernel growth; the shape class dominates |
| Complexity | M–L |
| Consensus | **CONSENSUS** (kernel generation) |
| Identity | kernel-id-by-height schedule (R7) or a new identity |
| Difficulty | M–L |
| Priority | P3 |

### B2. Private shared state

| Option | Assessment | Verdict |
|---|---|---|
| UTXO state records (today) | Private, but about one update per 16 blocks; nullifier contention (R5-9, R7-4) | Keep, for bilateral contracts |
| Public finalize (Aleo-style; R7 option D) | Explicit, per-contract public state; value stays in PX | Keep as the door (R7) |
| **Threshold-encrypted batch** (Penumbra flow encryption: amounts encrypted to a validator threshold key; validators decrypt only batch totals) [web] | **There is no validator set in PoW.** Miners are anonymous and transient and cannot hold a threshold key. Adding a committee creates a permissioned trust root | **Reject** |
| **FHE** (the Zama protocol: TFHE-rs is Rust, but decryption is an MPC KMS, e.g. 9 of 13 parties, running inside AWS Nitro enclaves) [web] | Committee plus TEE trust; huge compute cost; FHE state has no post-quantum-private *decryption* governance story on a PoW chain | **Reject** |
| **Time-lock or VDF sealed inputs** | Hides inputs only until the lock opens, so it gives MEV protection, not privacy. RandomX offers no VDF; this needs new assumptions | Reject for privacy; P3 research, for sealed-bid ordering only |
| **Operator-sequenced private state** ("private app-chain inside PX"): a contract's state record is controlled by an operator key; users submit requests encrypted to the operator; the operator proves each transition with a PX function | Integrity is on chain; **privacy against the operator is lost**, but it is private against everyone else. An honest description of what dark pools and order books need without a committee | P3; an SDK pattern, **no consensus change** (it uses approval records, R7-2) |
| Two-party MPC with a collaborative proof (Renegade-style matching) | Research-grade; curve-based stacks today | Reject for now |

**Conclusion:**
- BlackSilk can honestly offer three things: **private bilateral state**, **explicit public state**, and **operator-private state**.
- It cannot offer committee-free, *everyone-private* shared state. As far as I know no deployed system does without a committee, TEE or trust in an operator.
- The docs should say this rather than promise "private DeFi" (the zk.md §14 PX-3 wording).

### B3. Private cross-contract interaction

R7-3's hiding message commitments are correct for `MAX_FN = 2`. **Extension with A5c:** once functions are wrapped recursively, the "which contracts exchanged a message" metadata also disappears.
- Message matching moves inside the wrapper, as in Aztec's private kernel call stack (Zexe's "local data").
- The public sees only a registry root.

This is the step that turns co-inclusion into composition **without** the P-8 leak. Priority P3, after A5c.

### B4. Contract-scoped tags

R7 proposed contract-scoped tags: `Hk(TAG, scope, secret)` with a per-contract used-tag set. They are the post-quantum, full-set-anonymous building block for:
- one-person-one-vote;
- one-time claims;
- anonymous credentials with rate limits: epoch-scoped tags give **rate-limiting nullifiers** (RLN-style, without the secret-sharing slash).

I endorse them as the cheapest high-value private-computation primitive. Consensus impact is CONSENSUS (a new set). Priority P3.

---

## 5. Ideas: privacy-preserving light clients

| Idea | Assessment | Verdict and priority |
|---|---|---|
| **Compact PX feed** (I1-F2) | Keeps "download everything" (the best privacy model) viable | **P2**, no consensus |
| **Local tree** (already done: the wallet builds its own authentication paths and never asks for a position) | Correct [src] | Keep. **Never add a "get path for cm" RPC**: it would reveal ownership |
| **Header verification for light wallets** | In the pure-Rust implementation, RandomX light-mode verification costs about 750 ms per hash with 256 MiB. At 720 blocks a day, about 9 CPU-minutes a day: fine on a desktop, marginal on a phone. FlyClient-style sampling needs an MMR commitment in headers (CONSENSUS) | P3. Pair it with the wallet PoW check (W-F6) first |
| **Proving RandomX in a STARK** (Mina-style succinct chain) | RandomX is designed to be hostile to this: a 2 GiB dataset, random programs, floating point | **Reject** |
| **Proof-carrying PX state** (A5a applied to wallets: a proof that the PX root sequence and nullifier set follow from valid transactions) | Lets a light wallet trust PX state given only the headers. PoW is still checked natively or by sampling | P3, after recursion |
| **OMR / FMD / PIR** (e.g. OMR by Liu and Tromer: post-quantum, lattice/FHE-based, servers detect obliviously [web]) | Unnecessary at 6 outputs per block. Download-all is strictly more private. They become relevant only if aggregation raises volume by orders of magnitude | P3 watch |
| **Tachyon-style oblivious sync plus out-of-band payments** (Zcash: removes on-chain ciphertexts; wallet state as PCD; untrusted sync services learn only nullifiers [web]) | Its idea of deriving nullifiers so that a sync service learns nothing is valuable. But its out-of-band model gives up BlackSilk's in-band, post-quantum delivery guarantee (a sender cannot lose the recipient's funds), and it is built on Pasta curves | P3 research. If adopted, keep in-band delivery as the default |

---

## 6. Rejected ideas, with reasons

| Idea | Reason for rejection | Evidence |
|---|---|---|
| Curve-based folding (Nova, HyperNova, ProtoStar, ProtoGalaxy); KZG or Groth16 wrap of STARKs | Soundness rests on discrete logarithms or pairings, breaking R4. A trusted setup for KZG or Groth16 breaks R3 | [web] Aztec Chonk; zk.md R3/R4 [src] |
| FHE smart contracts | A committee plus TEE for decryption; incompatible with PoW and with the no-TEE rule; heavy compute | [web] Zama KMS docs |
| Threshold-encrypted batch auctions | No validator set to hold the key | [web] Penumbra flow encryption; PoW [src] |
| TEE confidentiality or TEE provers | The no-trusted-hardware rule; SGX breaks | R7 §5; zk.md non-goals [src] |
| Witness-revealing proof outsourcing | Violates R8 | zk.md R8 [src]; Aleo docs [web] |
| Miner-produced in-block aggregate proofs | Puts heavy proving on the mining critical path, which centralizes it | [web] Neptune composer requirements (secondary); [estimate] |
| RandomX-in-circuit light clients | Infeasible by RandomX design | [assumed; RandomX design goals] |
| GPU in consensus builds | Driver FFI and `unsafe`; the pure-Rust rule | [web] CubeCL backends |
| Hiding the transaction *type* by padding transfers to the function shape | It would make every transfer about 0.5 MB and about 9 s more expensive per padded function, at 3 tx per block. Function privacy through recursion (A5c) is the proper fix | measured sizes in the brief |

---

## 7. Differentiators

These three could make BlackSilk meaningfully different from Monero, Zcash, Aztec, Aleo, Penumbra, Namada and Secret. They are stated honestly, with no claim of being first.

### D1: post-quantum *programmable* private execution with no trusted setup, committee or hardware

**How the named systems compare [web; R5 §4]:**
- Monero FCMP++: curve trees on Helios and Selene.
- Zcash Orchard and Tachyon: Pasta curves, Halo 2.
- Aztec: BN254 and KZG-based Honk/Chonk.
- Aleo: Varuna with KZG.
- Penumbra: Groth16 on BLS12-377.
- Namada: Groth16 MASP.
- Secret: SGX.

**Where BlackSilk differs:** none of these has soundness and privacy that are both plausibly post-quantum. BlackSilk PX has hash-based ownership and nullifiers, a transparent hash-based STARK, and hybrid ML-KEM delivery [src]. If recursion (A5) stays STARK-in-STARK, this holds for the scaling layer too.

**Honest caveat:** **Neptune Cash** already offers post-quantum privacy with STARKs on PoW, including hidden scripts and custom tokens [web]. BlackSilk's difference from Neptune is narrower:
- a general RISC-V zkVM with **Rust-source** contract functions;
- **contract-held records** with an approve-and-specify kernel model;
- a Monero-lineage ring layer with consensus-enforced containment.
Whether that is a *meaningful* difference depends on the SDK (R7 §7.2); today it is not.

**Why it matters:** "harvest now, decrypt later" is the one privacy threat that cannot be fixed retroactively. A curve-based chain's past transactions become linkable once discrete logarithms fall. Only D1-type designs protect history.

### D2: function-hiding private calls with private composition, post-quantum (A5c plus B3)

**Comparison [web]:**
- Aztec hides which private functions ran (recursive kernels), but not post-quantum.
- Aleo reveals the program and function id of each transition.
- Neptune hides lock and type scripts, but has no multi-contract call model with message passing that I could find [assumed].

**What BlackSilk would add:** a post-quantum wrapper proof that checks functions against a registry root, plus hiding message commitments between functions. That would give the Zexe/Aztec function-privacy property with hash-only assumptions and cross-contract messages.

**Honest caveat:** it depends entirely on the recursion milestone, the least mature part of the plan (Plonky3-recursion is WIP and unaudited [web]).

### D3: scaling that keeps mining CPU-only (A5a/A5b, I1-F2)

**The design:**
- Proving never sits on the PoW critical path.
- Blocks carry user proofs.
- Aggregation is deferred and permissionless (paid).
- New and restarting nodes use proof-carrying synchronization.
- Wallets use a compact, proof-free, download-everything feed.

**Contrast [web]:**
- Neptune splits "composers" (heavy provers, reported at tens of GB and dozens of cores) from "guessers".
- Aztec and Aleo rely on sequencers or provers with specialized hardware.

**What BlackSilk would keep:** "a laptop can mine, validate and transact privately", while the chain still gains an aggregation path.

**Honest caveat:** Monero and Zcash also keep mining prover-free. They simply have no aggregation. The differentiator is having *both*.

### Not a differentiator

**Confidential multi-asset (B1).** It is valuable, but Penumbra, Namada and Zcash ZSA have it (curve-based) and Neptune has custom tokens (post-quantum). Do it for utility, not for positioning.

---

## 8. The brief's 13 questions for "private computation"

| # | Answer |
|---|---|
| 1. Implemented | One-batch STARK per transaction; zkVM functions; the kernel; hash-based records; hybrid post-quantum delivery; download-all wallet sync; `asset` committed but fixed at 0 [src] |
| 2. Correct and well designed | Recursion-friendly field and hash choice; hash-only soundness; local authentication paths; bulk commitment downloads; `asset` inside `cm` for forward compatibility |
| 3. Incomplete | Multi-asset; recursion; function privacy; messages; light-wallet feed (I1-F2) |
| 4. Fragile | Novelty claims (I1-F1); the SIMD-verifier split hazard if builds diverge (I1-F3) |
| 5. Exploitable | Nothing new for value. Whole-block RPC responses are a bandwidth amplifier (deepens the known "unbounded responses") |
| 6. Inefficient | Generic zkVM width for fixed-shape transfers (I1-F4); scalar field arithmetic (I1-F3); hex block transport (I1-F2) |
| 7. Does not scale | About 0.025 PX tx/s; all proofs kept forever; whole-block wallet sync |
| 8. Missing | Recursion; a verifier registry (zk.md §9.5, design only), which is **the prerequisite for every activation-height upgrade here** |
| 9. Redesign | Aggregation off the mining critical path (A5b, not A5d); multi-asset only with shape classes (B1) |
| 10. Innovate | D1–D3; A5a proof-carrying sync; contract-scoped tags as rate-limiting nullifiers |
| 11. Before the testnet | I1-F1 docs (P0); optionally the owner's A1 decision in the v3 bundle; nothing else |
| 12. Defer safely | Everything in §3–§5 except I1-F2 and I1-F3 (P2, no consensus) |
| 13. Never change | See below |

**Never change (question 13):**
- hash-only soundness and ownership, with no curve or pairing in any consensus proof path;
- no committee, TEE or trusted setup;
- download-all or local-path synchronization: never add per-record RPCs;
- the `asset` field inside `cm`;
- proving kept off the mining critical path.

### Suggested order after the trial

1. Implement the verifier registry (zk.md §9.5), so later items activate at heights.
2. Measure I1-F3 (SIMD for the prover) and build I1-F2 (compact feed).
3. A2 width reductions, one at a time.
4. A3 measurement spike.
5. The recursion milestone: A5a, then A5c, then A5b.
6. The kernel generation with shape classes plus B1 plus R5/R7 items.
7. B3 and B4.

---

## 9. Sources

**Repository (source-read, main checkout):**
- `zk/src/params.rs`;
- `px-core/src/record.rs`, `kernel.rs`;
- `zkvm/src/air/*.rs`;
- `wallet/src/px.rs`, `node.rs`;
- `rpc/src/lib.rs`;
- `docs/zk.md` §§1, 9.4, 9.5, 14, 17;
- `docs/px.md`;
- `docs/reviews/aggregation-study.md`;
- the cargo registry: `p3-monty-31-0.7.0/src/lib.rs`.

**External (retrieved 2026-09-27):**
- Plonky3-recursion (WIP, unaudited): https://github.com/Plonky3/Plonky3-recursion ; https://hackmd.io/@aiv768/H16FHLn-fe
- p3-whir: https://docs.rs/p3-whir/latest/p3_whir/ ; https://github.com/Plonky3/Plonky3/releases/tag/p3-whir-v0.8.0
- WHIR, ePrint 2024/1586: https://eprint.iacr.org/2024/1586
- Neo, ePrint 2025/294: https://eprint.iacr.org/2025/294
- Neo and SuperNeo, ePrint 2026/242: https://eprint.iacr.org/2026/242
- Neptune Cash whitepaper and articles: https://neptune.cash/whitepaper ; https://neptune.cash/articles/mutator-sets ; https://docs.neptune.cash/consensus/mining.html ; https://neptune.cash/articles/memory-hard-proof-of-work (the composer hardware figures come from secondary search summaries; treat them as indicative)
- Zcash Tachyon: https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/ ; https://seanbowe.com/blog/tachyaction-at-a-distance/
- Penumbra batch swaps and flow encryption: https://protocol.penumbra.zone/main/dex/swap.html ; https://protocol.penumbra.zone/main/crypto/flow-encryption/threshold-encryption.html
- Zama protocol KMS (MPC threshold decryption, Nitro enclaves): https://docs.zama.org/protocol/protocol/overview/kms ; https://docs.zama.org/protocol/zama-protocol-litepaper
- Aztec client-side proving (Chonk, HyperNova-style folding, Goblin): https://aztec.network/blog/client-side-proof-generation ; https://aztec.network/blog/inside-an-aztec-transaction
- Aleo delegated proving: https://developer.aleo.org/sdk/delegate-proving/delegate_proving/
- Namada MASP: https://github.com/namada-net/masp ; https://specs.namada.net/masp.html
- Monero FCMP++ (curve trees, Helios/Selene; the activation status in secondary sources conflicts, so it is not relied on): https://github.com/monero-project/monero/pull/10724
- Oblivious Message Retrieval: https://eprint.iacr.org/2021/1256 ; PerfOMR: https://www.usenix.org/system/files/usenixsecurity24-liu-zeyu.pdf
- CubeCL: https://github.com/tracel-ai/cubecl

**Confidence notes:**
- All code facts are [src].
- Every performance multiple in A1, A2, A3, I1-F2 and I1-F3 is an [estimate] or [unknown] until measured.
- External project facts are as published at the cited pages. Neptune's internal design details beyond its whitepaper are [assumed].
