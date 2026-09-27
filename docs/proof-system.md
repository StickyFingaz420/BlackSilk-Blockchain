# BlackSilk proof system: format and verifier rules

This document is **normative** for the zero-knowledge proof layer (`zk/`): the parameter
set, the Fiat–Shamir transcript, the proof encoding and every rule a verifier applies to
a proof before and around the Plonky3 verifier. It is written **by reference**: every
value lives in code, and this document names the constant or function that holds it.
Where the two disagree, the code is what nodes run and this document is wrong; fix it.

- Design and rationale: [`zk.md`](zk.md) §9 (proof system), §12 (security analysis).
- The circuit (the AIRs the proofs are about): [`zkvm.md`](zkvm.md) §6–§7, §10.
- Consensus use (PX transactions, exact shapes, fees): [`px.md`](px.md) §11.
- Changes to anything here are consensus changes, recorded in
  [`reviews/v3-consensus-changes.md`](reviews/v3-consensus-changes.md).

This is internal engineering documentation, not an audit. Zero knowledge is claimed only
as statistical and conditional (reviews/zk-coverage.md §3).

---

## 1. Sources of truth

| What | Where |
|---|---|
| Parameter set, its identifier and relations | `zk/src/params.rs` (`PARAMS_ID` and the constants next to it) |
| Plonky3 configuration (field, hash, Merkle tree, PCS, challenger) | `zk/src/config.rs` |
| Proving, verification, encoding, canonical form, FRI schedule | `zk/src/lib.rs` |
| Circuit tag and statement digest | `zkvm/src/prove.rs` (`CIRCUIT_ID`, `statement_digest`) |
| Plonky3 | exact pins `=0.7.0` in `zk/Cargo.toml`, `zkvm/Cargo.toml`; three prover-side patched crates in `third_party/` (verifier code byte-identical to upstream; third_party/README.md) |
| Consensus fingerprint entries for all of the above | `px/src/fingerprint.rs` (`px_entries`) |

---

## 2. Parameter set

The active set is the one named by `params::PARAMS_ID` (currently BS-ZK-3). A parameter
set is never edited in place: any change to a constant in `zk/src/params.rs` that affects
proofs is a new set with a new `PARAMS_ID`.

| Parameter | Constant |
|---|---|
| FRI blow-up (log2) | `LOG_BLOWUP` |
| FRI queries | `NUM_QUERIES` |
| Maximum folding arity (log2) | `MAX_LOG_ARITY` |
| Final polynomial length (log2) | `LOG_FINAL_POLY_LEN` |
| Query proof-of-work bits | `QUERY_POW_BITS` |
| Commit-phase proof-of-work bits | `COMMIT_POW_BITS` (0) |
| Random codewords per committed matrix (hiding PCS) | `NUM_RANDOM_CODEWORDS` (= `EXTENSION_DEGREE` since BS-ZK-3) |
| Salt elements per Merkle leaf | `MERKLE_SALT_ELEMS` |
| Challenge field | degree-`EXTENSION_DEGREE` binomial extension of BabyBear |
| Table heights | powers of two in `[2^MIN_LOG_HEIGHT, 2^MAX_LOG_HEIGHT]` |
| Encoded proof size | at most `MAX_PROOF_BYTES` |

**Relations checked at compile time** (`const` assertions in `zk/src/params.rs`):

- R1 (ePrint 2024/1037 §4.2 eq. 17, both opening points counted):
  `2·(NUM_QUERIES + EXTENSION_DEGREE·OPENING_POINTS) ≤ 2^MIN_LOG_HEIGHT`.
- R2 (eq. 16): `OPENING_POINTS + NUM_QUERIES ≤ 2^MIN_LOG_HEIGHT`.
- R3: `NUM_RANDOM_CODEWORDS ≥ EXTENSION_DEGREE` (Plonky3 0.8's hiding-PCS rule, PR #2100).
- R4: `MIN_LOG_HEIGHT + 1 > LOG_FINAL_POLY_LEN` (every committed polynomial folds at
  least once).
- R5: `MAX_LOG_HEIGHT + 1 + LOG_BLOWUP ≤ 27`: the largest evaluation domain stays at or
  below 2^27, so query positions (low bits of a canonical BabyBear element,
  p − 1 = 15·2^27) are uniform up to a 1/p bias.
- R6: `TARGET_JOHNSON_BITS ≤ COLLISION_BITS`.

**Security figures** are computed, not assumed: `params::security` (p3-security 0.7.0 on
the committed, post-zero-knowledge domain `degree_bits = log_height + 1`) and the
independent calculator `zk/tests/soundness_calc.rs`. Both must reach `MIN_PROVEN_BITS`
in the unique-decoding regime and `TARGET_JOHNSON_BITS` in the Johnson regime over the
whole envelope; the binding terms are pinned (query phase; commitment term
`COLLISION_BITS`, ePrint 2026/089 Theorem 3). Figures and their caveats: zk.md §9.3.

---

## 3. Configuration and transcript

- **Configuration:** `config::ZkConfig`, a Plonky3 `StarkConfig` of the hiding FRI PCS
  (`HidingFriPcs`) over the salted Merkle tree (`MerkleTreeHidingMmcs`, cap height 0),
  Poseidon2 (BabyBear, width 16, Plonky3's default constants; pinned by
  `zk/tests/pins.rs`) for leaves, nodes and Fiat–Shamir, and the `DuplexChallenger`.
- **Transcript start** (`config::challenger`): the challenger absorbs the length of
  `PARAMS_ID`, its bytes, then the 32 bytes of the **statement digest**, before any
  commitment. For zkVM proofs the statement digest is `zkvm::prove::statement_digest`,
  whose first input is `CIRCUIT_ID` (zk.md §9.3, zkvm.md §7). After that, the transcript
  is Plonky3 0.7.0's `p3-batch-stark` transcript unchanged.
- **Circuit identity.** `CIRCUIT_ID` names the BVM-1 constraint system. The circuit
  digest (`zkvm::air::check::fingerprint` over the table lists of 1 to `MAX_EXECUTIONS`
  executions, with the height limits and the blinding width) is pinned next to it in
  `zkvm/tests/circuit_fingerprint.rs` (`REVISIONS`). **Procedure:** any change to an AIR,
  a bus, a width, the table order or a limit changes the digest; the same commit must
  bump `CIRCUIT_ID` and append the new (id, digest) pair. An existing pair is never
  edited. The v3 changes to the parameter set and canonical form (BS-ZK-3, §5) do not
  touch the AIRs, so `CIRCUIT_ID` is unchanged by them.
- **Prover randomness** (not checkable by a verifier): hedged seeds, OS randomness mixed
  with a witness digest, fresh per proof (`ProverConfig::for_statement`).
- **Prover policy, grinding** (not a verifier rule): the prover's challenger
  (`config::ProverChallenger`, configuration `ProverZkConfig`) delegates every
  transcript operation to the verifier's `DuplexChallenger`, except that its query
  proof-of-work witness is the **smallest** valid nonce (`config::smallest_pow_witness`,
  confirmed by `check_witness`). Plonky3 0.7.0's parallel search returns a
  thread-dependent nonce that reveals a class of the prover's thread count (27 W6,
  F27-3). Verifiers accept any valid nonce, so proofs from other provers still verify.
  Both configurations produce the same proof type and bytes format.

---

## 4. Encoding

A proof on the wire is `PROOF_VERSION ‖ postcard(BatchProof)` (`encode_proof`).
`decode_proof` accepts a byte string only if **all** of the following hold, in this
order; any failure is `ZkError::Encoding`:

| # | Rule |
|---|---|
| D1 | length ≤ `MAX_PROOF_BYTES` |
| D2 | first byte = `PROOF_VERSION` |
| D3 | the body decodes as a Plonky3 0.7.0 `BatchProof` for `ZkConfig` (a panicking decoder counts as failure) |
| D4 | no trailing bytes |
| D5 | re-encoding the decoded proof gives exactly the input bytes |
| D6 | the canonical-form rules of §5 |

---

## 5. Canonical form

These rules make one honest proof have exactly one valid encoding, and close fields the
Plonky3 0.7.0 verifier leaves unbound (`check_canonical_form`, applied by
`decode_proof`). Honest proofs satisfy all of them by construction.

| # | Rule | Why |
|---|---|---|
| C1 | While `COMMIT_POW_BITS = 0`, every commit-phase grinding witness is zero | 0.7.0 accepts any unabsorbed witness at 0 bits (upstream fix #2106): a relayer could rewrite it and change the transaction id |
| C2 | No optional opening (`trace_next`, `preprocessed_local`, `preprocessed_next`, `random`) is present but empty | 0.7.0 compares lengths only, so `Some([])` passes where `None` is expected (upstream fix #2256) |
| C3 | Every Merkle cap has exactly one root: the `main`, `permutation`, `quotient_chunks` and `random` commitments and every FRI commit-phase commitment | `MerkleCap` deserializes any root count and 0.7.0 compares only root 0 while the transcript absorbs all (upstream fix #2277; F24-2) |
| C4 | The hidden random-codeword openings (`opening_proof.0`) have exactly one round per opening round of the proof (the mask `R`, main, quotient, preprocessed if any instance opens `preprocessed_local`, permutation if the `permutation` commitment is present), and every point of every matrix carries exactly `NUM_RANDOM_CODEWORDS` values, except the preprocessed round (at Plonky3's `Pcs::PREPROCESSED_TRACE_IDX`), which carries none | 0.7.0 checks only the nesting and appends whatever is there: without the rule the hidden width is prover-chosen (padding up to `MAX_PROOF_BYTES`, a proof-length channel, silent loss of hiding); preprocessed tables are committed with zero columns, not random codewords (22 W2 = 26 ZP-7 = 24 I2) |

C3 and C4 are part of the v3 rule set (reviews/v3-consensus-changes.md, "Canonical
proof shape"). Plonky3 0.8 enforces both itself.

---

## 6. Verification

`verify(cfg, airs, proof, public, max_log_heights)` accepts a proof only if, in order:

| # | Rule | Failure |
|---|---|---|
| V1 | one table, one public-value vector and one height limit per AIR, and the proof covers exactly that many tables | `Shape` |
| V2 | every table's `degree_bits` (log2 height + 1 under zero knowledge) is in `[MIN_LOG_HEIGHT + 1, min(limit, MAX_LOG_HEIGHT) + 1]` | `Height` |
| V3 | the FRI folding schedule equals `honest_fri_schedule(degree_bits)` (R4-02) | `Invalid` |
| V4 | Plonky3 0.7.0 `verify_batch` accepts it, with the preprocessed commitment recomputed from a fresh `VerifierConfig::setup()` | `Invalid` |
| V5 | a panic inside Plonky3 is caught (`catch_unwind`; builds must use `panic = "unwind"`, enforced by `compile_error!`) | `VerifierPanicked` |

Consensus paths decode with `decode_proof` first, so §4–§5 always apply before §6.
`verify` does **not** re-check §5: called on a proof object that did not come from
`decode_proof`, it accepts what Plonky3 0.7.0 accepts, including rewrites C1 and C2
exist to refuse (the advisory suite asserts this, so an upstream change is noticed).
Every caller that takes proof bytes from outside must decode them with `decode_proof`.
zkVM statements with a fixed shape (every PX statement) additionally require each table's
`degree_bits` to equal the shape's (`zkvm::prove::verify`, zkvm.md §6.6).

---

## 7. Rule table

| Rule | Code | Tests |
|---|---|---|
| R1–R6 | `zk/src/params.rs` (`const` assertions) | compile time |
| Security figures | `zk/src/params.rs` `security`, `security_report` | `params::tests::every_shape_within_limits_meets_both_security_targets`; `zk/tests/soundness_calc.rs` (independent calculator, headline figures, `COLLISION_BITS` derivation) |
| D1–D5 | `zk/src/lib.rs` `decode_proof` | `zk/tests/proofs.rs` `encoding_is_strict`, `byte_mutations_never_verify_and_never_panic_the_caller`; `zk/tests/field_mutations.rs`; fuzz target `proof_decode` |
| C1–C2 | `zk/src/lib.rs` `check_canonical_form` | `zk/tests/proofs.rs` `unbound_proof_fields_cannot_be_rewritten` |
| C3 | `zk/src/lib.rs` `check_canonical_form` | `zk/tests/proofs.rs` `honest_proofs_have_the_canonical_hidden_openings_and_caps`, `every_merkle_cap_root_count_mutation_is_refused` |
| C4 | `zk/src/lib.rs` `check_hidden_openings` | `zk/tests/proofs.rs` `honest_proofs_have_the_canonical_hidden_openings_and_caps`, `every_hidden_opening_count_mutation_is_refused` (every position, +1 and −1, with and without a preprocessed round) |
| V1–V2 | `zk/src/lib.rs` `verify` | `claimed_heights_and_table_counts_are_checked_first` |
| V3 | `zk/src/lib.rs` `check_fri_schedule` | `honest_proofs_use_the_canonical_fri_schedule`, `a_non_canonical_fri_schedule_is_refused`, `schedule_tests::*`, `px/tests/fri_schedule.rs` |
| V4–V5 | `zk/src/lib.rs` `verify` | `zk/tests/proofs.rs` (all), `zkvm/tests/*`, PX consensus tests |
| Upstream fixes after 0.7.0 | C1 (#2106), C2 (#2256), V3 (#2033), C3 (#2277) | `zk/tests/upstream_advisories.rs`: every commit-phase witness rewritten (0.7.0 alone accepts; decode refuses) and the query witness (verify refuses); the #2256 panic case (`preprocessed_next = Some([])` on a preprocessed table) refused at decode and contained by a direct `verify` (`VerifierPanicked`); an empty `preprocessed_local` (0.7.0 alone accepts; decode refuses); swapped fold arities; 2- and 3-root caps |
| Patched crates | `third_party/p3-{dft,fri,merkle-tree}` | `zk/tests/upstream_advisories.rs::third_party_patched_crates_are_pinned` (digest of every tracked file, line ends normalized) |
| Circuit identity | `zkvm/src/prove.rs` `CIRCUIT_ID`; `zkvm/src/air/check.rs` `fingerprint` | `zkvm/tests/circuit_fingerprint.rs` (pinned digest; every single mutation of any table, a table swap and an execution-id change alter it; independent of programs); `zkvm/tests/circuit_id.rs` |
| Grinding policy (prover) | `zk/src/config.rs` `ProverChallenger`, `smallest_pow_witness` | `zk/tests/grinding.rs`: `the_prover_grinds_the_smallest_valid_nonce`, `proofs_do_not_depend_on_the_thread_count`, `upstream_grinding_witness_depends_on_the_thread_count` (the leak), `proofs_from_the_upstream_grinding_prover_still_verify` |
