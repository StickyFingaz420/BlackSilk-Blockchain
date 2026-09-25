# Independent review: reviewer candidates and selection

Status: **2026-09-25. No reviewer has been contacted.**
- The owner engages reviewers; this document only prepares the choice.
- The candidates below are listed by public reputation as known to the project. Their
  current services, availability, prior relevant work and any conflicts of interest
  **must be verified directly** before engagement.

## 1. What the review needs (review-package.md §1.1)

| Area | Expertise |
|---|---|
| 1. Poseidon2 and `Hk` | Symmetric cryptanalysis, arithmetization-oriented hashes |
| 2. Plonky3 configuration and patches | STARK/FRI soundness and zero knowledge; Rust concurrency |
| 3. BVM-1 circuits | AIR/LogUp circuit auditing (under-constrained columns, bus soundness) |
| 4. PX kernel and function binding | ZK application protocols |
| 5. PX consensus rules | Blockchain consensus and state management, in Rust |
| 6. Delivery (hybrid KEM) | Applied cryptography: KEM combiners, ML-KEM |
| 7. Privacy and metadata | Transaction-graph and network-level privacy (ring signatures, Dandelion++) |
| 8. Wallet | Rust application security |

No single team is likely to be strongest in all eight. A realistic plan is one lead
auditor for areas 2–5 and 8, plus a cryptography specialist for areas 1 and 6, plus a
privacy review for area 7.

## 2. Candidates by area

| Candidate (type) | Relevant to areas | Why considered |
|---|---|---|
| Trail of Bits (audit firm) | 2, 3, 4, 5, 8 | Established ZK and Rust audit practice |
| NCC Group Cryptography Services (audit firm) | 1, 2, 6 | Long record of cryptographic protocol and library reviews, including privacy coins |
| Least Authority (audit firm) | 4, 5, 7 | Privacy-focused; has reviewed privacy-coin protocols |
| zkSecurity (ZK specialist firm) | 2, 3, 4 | Specialised in ZK proof systems and circuits |
| Veridise (ZK specialist firm) | 3, 4 | Circuit auditing with tooling for under-constrained circuits |
| Zellic (audit firm) | 3, 4, 5, 8 | ZK and Rust audits |
| Kudelski Security or Quarkslab (audit firms) | 1, 6, 7 | Have published reviews of Monero-style cryptography (verify which) |
| Academic researchers in arithmetization-oriented hash cryptanalysis | 1 | Poseidon2 is young; published cryptanalysts are the most credible reviewers |
| Academic researchers in network-level anonymity (Dandelion++) | 7 | P-6 and N4 (assumptions.md) need network-privacy judgement |

## 3. Selection criteria

1. **Independence:**
   - no financial or contributor relationship with the project;
   - for area 2, the Plonky3 authors are valuable consultants but are not independent
     of the library under review.
2. **Named reviewers** with published work in the area, not only the firm's name.
3. **Public report** allowed: findings, severities, what was not covered.
4. **Scope agreed in writing** from review-package.md, including the pinned commit.
5. **Re-review** of fixes included.

## 4. What the project provides

- review-package.md, assumptions.md, the pinned commit and the evidence folders;
- a contact who answers questions within one working day;
- no pressure on conclusions: findings are recorded in AUDIT.md as reported.
