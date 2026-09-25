# Independent review: reviewer shortlist and recommendation

Status: **2026-09-25, for the owner's approval.**
- **No reviewer has been contacted and no commitment made.** Nothing in the project is
  independently reviewed.

**Method:**
- Public web pages only.
- Every claim below cites its source, as found by a research pass on 2026-09-25.
- Two items were re-verified directly by the project, because they bear on the scope:
  the Plonky3 audit's scope (Least Authority's page) and the Plonky3 security
  advisories (the GitHub advisory API; dependency-review.md §5a).
- Other claims come from the research pass's reading of the cited pages. They must be
  **confirmed with each firm** before engagement.
- Pricing and availability are not public for any firm.

## 1. What must be reviewed

See review-package.md §1.1 and external-review-scope.md §2 (areas 1–9). The two
hardest areas for finding reviewers:
- **Area 2 (Plonky3 in hiding mode).** The only published Plonky3 audit (Least
  Authority, 2024) covered "a non-hiding STARK protocol". The zero-knowledge mode
  everything private here depends on has **no published audit**.
- **Area 1 (Poseidon2 over BabyBear, width 16).** No published cryptanalysis specific
  to this instance was found. Firms rarely offer hash cryptanalysis; academics do.

## 2. Candidates (public evidence)

**Legend:** S = strong public evidence · P = some evidence · — = none found. "None found"
is not proof of no experience: many audits are private.

| Candidate | ZK / proof systems | Consensus / P2P | Rust | Monero-style privacy | Public reports | Reviews code |
|---|---|---|---|---|---|---|
| **zkSecurity** | S: OpenVM 2.0 (built on Plonky3, LogUp; 2026-06), Stwo-Cairo verifier (2025), Zcash Orchard (2026-07), Penumbra circuits, RISC Zero Helios. Sources: reports.zksecurity.xyz, github.com/risc0/rz-security | P: Era consensus (2024), Aleo consensus (2023) | P: Rust p256 (2025) | P: Generalized Bulletproofs (2026) | reports.zksecurity.xyz | Yes |
| **Veridise** | S: RISC Zero zkVM and circuits (96 person-weeks, 2024), ZKM Ziren (Plonky3, 2025), a Plonky3-based "ZK #17" (2024), ZKsync Airbender (2026); tools for under-constrained circuits (Picus). Source: veridise.com/audits-archive | — | P: the zkVM audits are Rust | P: Monero FCMP++ circuit (2025) | veridise.com/audits-archive | Yes |
| **Zellic** | S: found the Plonky3 FRI size-check bug (GHSA-m23j-cj9m-ppg9, 2025); SP1 review | P: Solana, Cosmos, Aptos, Sui | P: Zcash Rust audits | P: Zcash | github.com/Zellic/publications | Yes |
| **Least Authority** | S: Plonky3 (2024, non-hiding only), Plonky2 (2022). Source: leastauthority.com/blog/audit-of-plonky3 | S: Zebra and zcashd NU6 (2024), Eth2 specifications, Lotus | P | P: Zcash, BEAM | leastauthority.com/security-consulting/published-audits | Yes |
| **NCC Group** | P: Zcash Sapling/Overwinter (2019), NU5/Orchard (2021) | S: Zcash Zebra (consensus, networking, RPC; 60 person-days; 2023) | S: Zebra; RustCrypto AES-GCM and ChaCha20-Poly1305 (2019–20) | P: Zcash | nccgroup.com research pages | Yes |
| **Quarkslab** | — | S: Bitcoin Core (2025), RandomX (2019) | S: dalek-cryptography, the Ristretto implementation we use (2019) | S: Monero Bulletproofs (2018), Bulletproofs and MLSAG (2019), Tari Bulletproofs+ in Rust (2023) | github.com/quarkslab/public-reports | Yes |
| **Trail of Bits** | P: Miden zkVM (2025), Halo2, Scroll, Aleo | P: snarkOS, Arbitrum; RandomX (2019) | P (advertised) | S: Monero FCMP++ cryptography (2026) | github.com/trailofbits/publications | Yes |
| **Kudelski Security** | P: Zcash Sapling (2019), Halo2 research (2024) | S: RandomX (2019) | P: Solana | P: Monero Bulletproofs (2018) | kudelskisecurity.com/blockchain | Yes |
| Cypher Stack (additional) | — | — | — | S: Generalized Bulletproofs proofs; CARROT (FCMP++ addressing) | none central | Not verified (proof work) |

**Poseidon2 cryptanalysis (area 1).** The relevant public work is academic:
- Ashur, Buschman, Mahzoun, ePrint 2023/537 (ACISP 2024): algebraic attacks; no
  practical instance affected;
- Merz and Rodríguez García, ePrint 2026/306: better collision attacks on one 128-bit
  set, not below the claimed security;
- the Ethereum Foundation's Poseidon Cryptanalysis Initiative, which targets 31-bit
  width-16 instances. It is co-run by a Poseidon2 designer, so it is not independent.

**Conflicts of interest to confirm:**
- Least Authority audited Plonky3 for Polygon (the author of Plonky3): valuable
  knowledge, but less independent on area 2.
- zkSecurity and Cypher Stack also do development work: check for product overlap.
- Nothing else was found.

## 3. Recommendation (for approval)

Two engagements, plus one specialist:

| Engagement | Areas | First choice | Alternative | Why |
|---|---|---|---|---|
| **A: proof system and circuits** | 2, 3, 4 (and 1 as far as they cover it) | **zkSecurity** | Veridise | Recent public work on a Plonky3-based zkVM with LogUp (OpenVM 2.0) and on shielded-transaction circuits (Orchard, Penumbra). Veridise is equally strong on zkVM circuits (RISC Zero) and has Plonky3-based audits |
| **B: consensus, privacy, Rust** | 5, 6, 7, 8, 9 | **Quarkslab** | NCC Group | Reviewed exactly the v1 building blocks we use (the dalek/Ristretto library, Monero-style ring and range proofs, RandomX) and Bitcoin Core consensus. NCC is strongest on a Rust node's consensus and networking (Zebra) and on RustCrypto AEADs |
| **C: Poseidon2 instance** | 1 | An academic cryptanalyst with published Poseidon/Poseidon2 work | — | No firm shows direct evidence here |

**Before any contact, the owner decides:**
1. Budget and timing. No pricing is public; each firm quotes on scope. Past effort for
   scale: NCC's Zebra review took 60 person-days; Veridise's RISC Zero review took 96
   person-weeks.
2. Whether reports may be published. Public reports are strongly preferred
   (external-review-scope.md §4).
3. Which commit to freeze for review (review-package.md §2).

**Requests to every firm:**
- a review of the **implementation**, not only the documents;
- named reviewers;
- a fix review;
- a public report listing what was not covered.

## 4. Limitations of this research

- Automated reading of public pages. Some pages were unreachable (reports.zellic.io
  returned 403; the Quarkslab services page returned 502). Most PDFs were not opened
  individually.
- Pre-2025 sources may not reflect current staff or capacity.
- No firm showed public work on Dandelion++, an X-Wing-style KEM combiner, or finality
  policy (area 9); for those areas the judgements rest on adjacent work.
