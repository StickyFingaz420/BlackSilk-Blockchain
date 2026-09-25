# Review status and internal review process

Status: **authoritative, 2026-09-25.** Where another document suggests otherwise, this
one is correct and the other has a bug.

## 1. External review status

- **No external auditors have been engaged.**
- **No independent external review of BlackSilk has been completed.** No part of the
  project's own code has been examined by anyone outside the project.
- **Every security and privacy conclusion in this repository comes from internal
  work:** design, source analysis, testing, fuzzing and internal review passes.
- **Finding no vulnerability does not prove that the system is secure.** Tests and
  fuzzing show that the cases we thought of, and those the fuzzer reached, behave as
  expected. Nothing more.
- **Remaining uncertainty is documented, not hidden:** docs/reviews/assumptions.md,
  and the "open" and "limitations" sections of each review.

**Decision (owner, 2026-09-25):**
- The project proceeds self-reliantly: the owner's oversight, with internal review, is
  the primary development and review resource.
- External review is **not** a current requirement or testnet gate. It may be
  revisited later, depending on resources, the project's stage and risk.
- The reviewer shortlist (reviewer-candidates.md) and the review scope
  (external-review-scope.md) are kept **for future reference only**. No firm has been
  contacted and no commitment made.

## 2. How claims are classified

Every security or privacy claim in the reviews states which kind of evidence it rests
on:

| Class | Meaning | Example |
|---|---|---|
| **T: tested** | A test or fuzz target would fail if the claim were false in the cases it exercises | Double spends across a partition resolve to one spend (p2p test) |
| **S: source analysis** | Established by reading the code; no test could fail | The Merkle verifier fixes leaf lengths (`check_widths`) |
| **C: cryptographic assumption** | Holds if a standard assumption holds; we did not and cannot prove it | Poseidon2 collision resistance; DL hardness in Ristretto255 |
| **U: upstream behaviour** | Depends on a library behaving as documented | Plonky3's hiding mode making proofs zero knowledge |
| **O: open** | Unproven, or beyond our verification capability | Zero knowledge of the hiding configuration's parameters; Poseidon2 over BabyBear-16 cryptanalysis |

**Never** described as secure or production-ready on the basis of T alone.

## 3. The internal review process

Every critical component gets seven passes, each with its own objective:

| # | Pass | Question |
|---|---|---|
| 1 | Implementation | Does the code implement the written design? |
| 2 | Adversarial | What can a malicious user, peer, miner or prover do? |
| 3 | Privacy | What leaks: metadata, linkability, timing, reuse, recovery, errors, network behaviour? |
| 4 | Consensus | Can two honest nodes reach different results, or accept an invalid state transition? |
| 5 | Reorganization | Forks, deep reorganizations, conflicting spends, replay |
| 6 | Failure and recovery | Crashes, interrupted submissions, corrupted state, restarts, backups, incomplete operations |
| 7 | Integration | Is the behaviour tested in the integrated system, not only in isolation? |

**Critical components:**
1. Plonky3 configuration, hiding mode and the local patches;
2. Poseidon2 and `Hk`;
3. BVM-1 circuits;
4. the PX kernel and function binding;
5. PX consensus and state;
6. v1 transactions (CLSAG, BP+, stealth outputs);
7. chain management and reorganizations;
8. P2P and Dandelion++;
9. wallet (v1 and PX), including recovery;
10. record delivery;
11. RandomX and difficulty.

**Independence between passes.** A pass is done where possible by a reviewer that did
not write the code and is **not given the author's reasoning**. In practice this is a
fresh-context review agent that receives only the code, the specification and the
pass's objective, and reports findings with reproduction steps. The author then
verifies and fixes each finding.

**Limits of this independence, stated plainly:**
- The review agents and the implementing agent are the same underlying model. Their
  blind spots may be correlated in ways a human expert's would not be.
- Separating contexts reduces shared assumptions; it does not remove them.
- These passes are internal review and are recorded as such. They are **not** an
  independent external audit.

Results are recorded per component and pass in docs/reviews/internal-review-log.md.
