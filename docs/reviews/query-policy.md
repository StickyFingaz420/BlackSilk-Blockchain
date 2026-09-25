# FRI query-count policy: rationale, costs and when to revisit

Status: **decision record (2026-09-25).** The owner keeps the current policy: BS-ZK-2
with **108 queries**. This file records why, what it costs, and what would justify a
change. Nothing here changes a parameter.

## 1. The current parameters (`zk/src/params.rs`)

| Parameter | Value |
|---|---|
| Field | BabyBear (p = 2^31 − 2^27 + 1), challenges in its degree-8 extension (247 bits) |
| FRI blow-up | 8 (rate 2^-3) |
| Queries | **108** |
| Query proof-of-work | 16 bits |
| Folding arity | up to 16; final polynomial of length 2^6 |
| Envelope | tables up to 2^22 rows, up to 4,000 committed columns |
| Digest collision resistance | 123 bits (8-element Poseidon2 digests) |

## 2. Security rationale

Soundness is computed by the project's own tested calculator over the **whole shape
envelope** (`zk/src/params.rs`, `every_shape_within_limits_meets_both_security_targets`),
in two regimes:

| Regime | What it relies on | Target | BS-ZK-2 at 108 queries |
|---|---|---|---|
| Johnson bound (list decoding) | The FRI proximity-gap results up to the Johnson bound (2020/2025 literature) | ≥ 120 bits (approved floor 100) | **≥ 123 bits** |
| Unique decoding | No list-decoding theorem at all: the conservative, fully proven regime | ≥ 100 bits | **≥ 105 bits** |

**Why the unique-decoding target matters.**
- Proximity-gap results beyond unique decoding are recent. Parameters beyond the
  Johnson bound rest on conjectures that this project does not rely on.
- Requiring ≥ 100 bits in the unique-decoding regime means soundness does **not**
  depend on the list-decoding results; they only add margin.

**Why 108 and not the minimum.** The parameter study (`zk/examples/param_study.rs`,
blow-up 8, 16 grinding bits) finds that:
- **102 queries** are the minimum reaching both targets (Johnson 123, unique decoding
  exactly 100);
- **108** keeps about 5 bits of margin in the unique-decoding regime against small
  errors in the calculator's model and future shape growth.

## 3. Costs of the policy (measured)

| Item | Effect of the query count |
|---|---|
| **Proof size** | About 92% of a 2.04 MB transfer proof scales linearly with the queries (aggregation-study.md §1): opened rows 60.4%, authentication 18.5%, FRI folding 13.7%. Each query costs about 17 KB |
| **Verification** | Linear in the queries for the FRI part; 183–188 ms per transfer proof today |
| **Proving** | Barely affected: proving time is dominated by commitments and DFTs, not by opening queries |
| **Chain capacity** | About 4 PX transactions per block under the 8 MiB PX budget |

**Alternatives measured** (same blow-up; sizes *estimated* from the 92% linear part):

| Policy | Queries | Johnson / unique-decoding bits | Proof size (*estimate*) |
|---|---|---|---|
| **Current** | **108** | **≥ 123 / ≥ 105** | **2.04 MB (measured)** |
| Both targets, no margin | 102 | 123 / 100 | ~1.93 MB (−5%) |
| Johnson ≥ 120 only | 71 | 120 / 74 | ~1.40 MB (−31%) |
| Blow-up 16, Johnson only | 53 | 120 / 64 | *not measured* (about 2× prover time and memory) |

Dropping the unique-decoding target (71 queries) would make soundness rest on the
list-decoding results: a policy change, not an optimization.

## 4. When to revisit

- **An independent review** finds an error in the security calculator, or recommends
  a different regime or target.
- **New cryptanalysis** of FRI proximity gaps (in either direction).
- **The envelope grows** (taller tables, more columns): the calculator must be re-run,
  and the margin may shrink.
- **Proof size becomes the binding constraint** for the network. Then aggregation
  (aggregation-study.md §3.3) is the preferred fix, because it keeps the per-proof
  security.

Any change is a new parameter set with a new identifier (`PARAMS_ID`): a consensus
change, never an in-place edit.
