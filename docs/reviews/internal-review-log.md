# Internal review log

Status: **internal work only. No external audit or independent review has taken place**
(review-status.md).

**How each round was done.** Each review pass was run by a fresh-context review agent
that was given only:
- the code;
- the specifications;
- the pass's objectives.

It was not given the author's reasoning. The author then **verified** each finding
against the source, or by a test or measurement, before accepting it. The
"Verified" column says how.

**Limitation (review-status.md §3):**
- The review agents and the implementing agent are the same underlying model, so
  their blind spots may be correlated.
- These passes are internal review, not an external audit.

## Round 1 (2026-09-25/26)

| Component | Passes | Reviewer | Report |
|---|---|---|---|
| ZK configuration: Plonky3 0.7.0 hiding mode, BS-ZK-2, the three patches | implementation, adversarial, privacy (ZK), patch diff, failure | fresh-context agent | summarized below |
| PX kernel, function binding, PX consensus, reorganization | implementation, adversarial, consensus, reorganization, failure, privacy | fresh-context agent | summarized below |
| BVM-1 circuits (all AIR tables, buses, memory, control, Poseidon2) | adversarial soundness (under-constraint search) | fresh-context agent | summarized below |
| Wallet (v1 and PX), including recovery | failure and recovery, privacy, adversarial node, reorganization, implementation | fresh-context agent | summarized below |

### Critical and high findings

| # | Finding | Verified by the author | Status |
|---|---|---|---|
| **ZK-F29** | **Proofs are not zero-knowledge as configured: the per-table LogUp terminals are published unblinded.** In `p3-batch-stark` 0.7.0 each table's terminal is computed from the real trace rows and public challenges (`prover.rs:249-259`), published in `BatchProof::lookup_terminals` and absorbed into the transcript. The hiding PCS masks commitments and openings, but not these values; `p3-lookup` has no zero-knowledge handling. The Program table's terminal depends only on the per-instruction execution counts. | **Yes.** Source: read `prover.rs` and searched `p3-lookup` for ZK handling (none). **Measured:** `px/examples/execution_profile.rs` ran the kernel on 100 witnesses. It produced **33 distinct execution-count vectors**. `pay2` (two real inputs) never shares a profile with `pay1` (one real input and a dummy), and the profiles vary within classes with amounts and keys. So a proof reveals at least whether a private payment spends one or two real records, and some amount-dependent information. | **OPEN. Critical for privacy.** A fix needs a proof-system change (owner decision; §4) |
| **ZK-F30** | **Small tables may be opened at more points than their hiding randomness covers.** A table of h rows gets h random rows; the verifier sees each column at up to 108 query points plus two out-of-domain points. With h = 64 (`MIN_LOG_HEIGHT = 6`), about 104–110 openings exceed the 64 random degrees of freedom, so linear relations on witness values leak. **Correction (2026-09-26):** the Poseidon2 table is shared by all executions of a proof, so the vault's budget does not create a 64-row table. In the measured transfer layout the smallest witness table was Poseidon2 at 128 rows (about 110 openings: a margin of 18, below the counting argument's comfort), and Output (64 rows) holds public data. Budgets below 128 (for example small registered functions) could still produce 64-row witness tables. | **Partly.** The vault budget and the minimum height were confirmed in the source (`px/src/vault.rs:54`, `zk/src/params.rs:66`). The counting argument (C) is the standard one, but it has not been checked against a written Plonky3 zero-knowledge theorem, and no test demonstrates extraction. | **OPEN. High.** Fix: raise the minimum height of witness tables to at least 2^8, which changes shapes and is a consensus change (owner decision) |
| W-F1 | "Stored before sending" existed only in memory: a crash during the up-to-120 s submission lost the reservation, the stored transaction, the rings and a vault opening | Yes (source) | **Fixed.** `Wallet::set_autosave`: the wallet file is saved before the transaction is handed to the node. Test `the_wallet_is_saved_before_a_transaction_leaves_it` reads the file at submission time |
| W-F2 | **Ring-member queries excluded the real input**, so the node could identify it as the one ring member never requested. This predates this week's work. Retries would also have singled it out by intersection | Yes (source) | **Fixed.** One `/outputs` request per input, containing the real output, the stored members and a pool of about 60 candidates, shuffled; decoys are chosen locally. Test `ring_queries_never_single_out_the_real_input` |
| W-F3 | A node behind the wallet (or one lying about its height) made it drop stored transactions and rings | Yes (source) | **Fixed.** Inputs that are not currently visible do not count as buried; rings are kept until the spend is buried beyond the reorganization window; a node still synchronizing is refused. Test `a_node_behind_the_wallet_does_not_make_it_forget_its_transactions` |

### Medium findings

| # | Finding | Verified | Status |
|---|---|---|---|
| W-F4 | A reorganization deeper than the 720 kept block ids was taken for a fresh wallet: no rescan, stale outputs | Yes (source); the new test fails on the old logic | **Fixed.** Test `a_reorganization_deeper_than_the_kept_window_rescans` |
| W-F5 | A refused submission dropped its rings; a lying node could force fresh rings | Yes | **Fixed.** Rings are always kept. Test `a_refused_transaction_still_pins_its_rings` |
| W-F6 | Blocks from the node were not checked to extend the previous block | Yes | **Fixed** (prev-id linkage). **Open:** the wallet does not check proof of work; it trusts its node for that (documented) |
| W-F7 | A restore from the seed scans only account 0 (and 50 addresses ahead), and 20 PX addresses ahead | Yes (source) | **Open.** Documented; a restore option for more accounts is planned |
| W-F8 | Two processes on one wallet file could overwrite each other or corrupt the file | Yes | **Fixed.** Exclusive `<wallet>.lock` for the whole command; a per-process temporary file |
| PX-F1 | All block bodies stay in memory forever; cheap PX deploys (about 8 MiB per block) can grow a node's memory by gigabytes per day | Yes (source: `chain/src/manager.rs` `bodies`) | **Open.** A node change (not consensus): keep bodies on disk only |
| PX-F4 | A function fixes an output's owner, contract, value and data, but the caller picks its `rcm` and writes its ciphertext. A third-party payout or shared contract state can be made unopenable | Yes (source: `px-core/src/kernel.rs`) | **Open (design).** Letting functions fix `rcm` changes the kernel (consensus; owner decision). Otherwise it is documented as a trust assumption of contracts |
| ZK-F3 | Reusing a `VerifierConfig` rejects valid proofs, because verification draws salts from the config's RNG, contrary to its documentation | Not yet reproduced | **Open** (latent; today every verification uses a fresh config) |
| ZK-F4 | Every verification recomputes the preprocessed commitments (the 2^16-row byte table and more) before it can reject: a denial-of-service cost | Not measured | **Open** |

### Low and informational (selection)

- **zkVM (the circuit review found no critical, high or medium soundness issue):**
  - F1: `MAX_OUTPUT_WORDS` is not enforced by the verifier. Harmless today, because PX pins the output length.
  - F3: the verifier relies on `Program::validate` invariants it does not re-check.
  - F4: the periodic-repetition argument (sound, but not written down or tested).
- **PX:**
  - F5: contract outputs are not forced to have `owner = 0` (a kernel change);
  - F6: reorganizations drop dependent PX transactions;
  - F2, F3: undo records and proof re-verification on restart and reorganization;
  - F7–F11: verifier cost, a full tree, duplicate program ids, precheck, panic containment.
- **ZK:**
  - F5: the prover chooses how many random codewords to use (malleability);
  - F6: the calculator does not cover the real PX multi-execution shapes (the unique-decoding bits do not depend on shape);
  - F7–F10: panic containment, decoder amplification, documentation mismatches (BabyBear^5 vs ^8, 128 vs 123 bits, 130–230 KB vs 2 MB), the zero-statement API.
- **Wallet:**
  - F10: spoofed acceptance; wording is now "submitted";
  - F11: a malformed distribution panicked the decoy selector. **Fixed:** it is now an error; tests added;
  - F12: an `Invalid` verdict can be transient;
  - F13: `first_output` is trusted;
  - F14: `clear-pending` deleted contract-record openings. **Fixed;**
  - F15: the restore height is taken from the node;
  - F16: wrong error message. **Fixed.**

## What this round did not cover

- `isa.rs` (the decoder);
- the formal zero-knowledge of the hiding PCS;
- Poseidon2 cryptanalysis;
- the delivery KEM;
- P2P and Dandelion++;
- RandomX and difficulty;
- v1 transaction cryptography (CLSAG, BP+);
- the vault program's own execution profile.
