# Proof size, aggregation and verification cost: design study

Status: **study (2026-09-24). Nothing in §3 is implemented.** It records what was
measured, what was estimated (marked *estimate*), and what the options cost, so that
the owner can decide with evidence. Security parameters are unchanged: BS-ZK-2, 108
queries (AUDIT.md R8).

## 1. Where the bytes go (transfer proof, 2.04 MB)

**Measured:**
- about 2,400 committed elements opened per query;
- 108 queries;
- a degree-8 challenge extension.

**Decomposition** (*estimate*, from the proof structure):

| Part | Approx. size |
|---|---|
| Opened trace, lookup and quotient values: 108 × ~2,400 × 4 B | ~1.0 MB |
| Merkle paths for the trace trees (~4 trees × ~20 levels × 32 B per query) | ~0.3 MB |
| FRI commit-phase openings (~20 rounds of paths and extension siblings per query) | ~0.7 MB |
| Commitments, out-of-domain evaluations, final polynomial, grinding | < 0.1 MB |

Proof size therefore scales with:
- **queries** (linearly; a security-policy decision);
- **opened width** (linearly; engineering);
- **log(trace length)**, through the paths.

It does not scale with the amount of computation proven, beyond the logarithm.

## 2. Verification cost (done)

| Step | Before | After |
|---|---|---|
| Public tables (byte, program, image, output) recommitted on every verification | 76% of 1.3–1.5 s | periodic columns, evaluated by the verifier (zkvm.md §6.1) |
| One transfer proof | 1.3–1.5 s | **188 ms** |
| A block's PX proofs already verified in this node's mempool | verified again | **skipped** (`validate_block_transactions_cached`; soundness argument in its doc comment; test in `tx/tests/px_consensus.rs`) |

**Relay protections (done):**
- a per-peer PX bucket and a global PX bucket;
- a separate 64 MiB PX mempool class;
- invalid proofs are penalised as stateless misbehaviour;
- the proof runs last in validation.

A flooding peer can make a node verify at most 2 proofs per second on average, about
0.4 s of CPU per second, whatever the number of peers.

## 3. Options for smaller proofs

### 3.1 Parameters (security policy; owner decision, unchanged)

The parameter study (`zk/examples/param_study.rs`) measured:
- **Johnson ≥ 120 bits** without the extra unique-decoding target needs **49–71
  queries**, −35% to −55% of the proof.
- **Blow-up 16** instead of 8 needs fewer queries for the same bits, at about 2× the
  prover time and memory.

Neither is applied. Rule 5 of the owner's instructions: no security parameter is
reduced without full analysis and an explicit decision.

### 3.2 Opened width (engineering, no security change)

Every committed column is opened at every query, so fewer columns means proportionally
smaller proofs. **Candidates** (*estimates*):
- merging the three ALU tables' shared operand layout;
- the Poseidon2 table's output decomposition. It spends 14 columns on each of 16
  words (224 of its columns) to hand bytes to memory; memory interfaces that carry
  field elements for hash buffers would remove most of them. Round constants are
  already AIR constants, not columns;
- dropping main-trace copies of periodic columns once `p3-lookup` supports periodic
  values in messages (upstream).

**Expected gain:** 10–25% (*estimate*). Each change touches soundness-critical AIR
code and needs the full mutation and forgery-analysis cycle
(docs/reviews/zk-security-review.md §3).

### 3.3 Aggregation by recursion (the architectural fix)

**Idea:** a block producer proves "I verified these N PX proofs", so the chain carries
one proof per block instead of N.

**Prerequisites that hold today:**
- the proof system's hash (Merkle and Fiat–Shamir) is Poseidon2 over BabyBear, the
  same field as the circuit, so it can be verified inside a proof without emulating a
  foreign hash;
- the zkVM already has a Poseidon2 table.

**Through BVM-1 (the general zkVM): not viable** (*estimate*).
- **Work:**
  - The verifier's DEEP-quotient step alone evaluates ~2,400 opened values per query
    in the degree-8 extension, which is ~100 RV32 cycles per extension operation with
    emulated modular arithmetic.
  - That is roughly 25 million cycles for 108 queries, before Merkle and FRI work.
- **Limit:** `MAX_CYCLES` is 2^21, about 2.1 million.
- **Proving time:** at today's proving rate (about 25k cycles in 42 s, dominated by
  fixed per-table costs), the time would be hours per aggregated proof.

**Through a dedicated recursion circuit: the realistic path.**
- An AIR whose rows are:
  - extension-field operations;
  - Poseidon2 permutations (reusing `air/poseidon.rs`);
  - FRI fold steps.
- Such a circuit verifies one proof in on the order of 10^5 rows, not 10^7.
- Plonky3's own recursion work is not released as a stable, pinned crate; building it
  here is a milestone comparable to ZK-3, including its own security review.

**Privacy consequences (important):**
- Aggregation hides nothing more and nothing less: each aggregated transaction still
  publishes its nullifiers, commitments and ciphertexts.
- The aggregator needs only the proofs, never witnesses, so no private data moves.
- The individual proofs must still be relayed to the aggregator and to other nodes
  before inclusion (mempool validity). Recursion saves chain space and block-validation
  time, not relay bandwidth.

**Consensus consequences:**
- A block would carry either individual proofs or one aggregate covering all its PX
  transactions.
- Pruning individual proofs after inclusion would require every node to trust the
  aggregate's soundness to the same margin (the recursion circuit's own parameters).

### 3.4 Proof pruning after confirmation (storage only)

- The proof is in the transaction's prunable section, and the transaction id commits
  to its hash.
- Archival nodes keep proofs; pruned nodes could drop them after a depth and keep the
  prunable hash, as Monero does for signatures.
- This saves disk, not bandwidth or block size. It is **not implemented**; the storage
  layer currently keeps full blocks.

## 4. Recommendation

1. **Testnet:** keep BS-ZK-2 and 108 queries. Accept ~2 MB proofs and about 4 PX
   transactions per block. That is enough to test every PX flow; it is not a
   throughput target.
2. Pursue the width reductions of §3.2 one at a time, each with the full mutation and
   review cycle.
3. Plan recursion (§3.3) as its own milestone, with a dedicated circuit and an
   independent review, before any mainnet capacity target is set.
4. The owner decides separately on the query policy (§3.1), with the study's numbers.
