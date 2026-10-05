# RES-FREEZE: research dossier on the open pre-freeze questions

> Historical record (2026-10-03). Superseded where it conflicts with the code: the wallet derives the decoy distribution from its own output index and makes no spend-time `/distribution` request (1902761). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

Agent RES-FREEZE, phase 2, 2026-10-03/04. Read-only on the repository (`rebuild/core` at
8682274). Internal engineering research, not an audit. It claims nothing about BlackSilk
being secure, production-ready or proven.

## 0. Method, evidence classes and an honesty note on sources

> **Read §8 first.** It holds the verification of every external citation against its
> primary source (2026-10-04), the corrections, and the post-verification
> recommendations. Wherever §§1–5 conflict with §8, §8 wins.

- **Read in full:** brief.md, decisions.md (all 1,521 lines), tm2-consensus.md,
  tm2-privacy.md, the relevant parts of tm2-crosscheck.md and tm2-network-ops.md;
  docs/evidence/daa-sim-2026-09-27/{results,redteam}.md; docs/px.md §6 and §11.1;
  docs/zk.md §9.3; docs/p2p.md §1, §8, §11, §12; consensus/src/difficulty.rs;
  px/src/delivery.rs; tx/src/decoy.rs; zk/src/params.rs (constants).
- **Two measurements of my own** (scripts in my session scratchpad, not in the repo):
  - **M-A** `rt4_stall.py`: an independent Python port of `next_difficulty` at 8682274,
    used to size the RT-4 stall (§1.2).
  - **M-B** `ristretto_frac.py`: the RFC 9496 §4.3.1 decoder in pure Python, used to
    measure what share of random 32-byte strings are valid ristretto255 encodings
    (§2.2). It checks itself against the RFC's generator vector.
- **Evidence tags:** [src] code read; [ev] committed evidence; [M-A]/[M-B] my
  measurements; [lit] a published source; [eng] my engineering conclusion.
- **Source verification status.** Five parallel web-research sub-agents were launched to
  fetch and verify primary sources, one per topic. **None had reported when this dossier
  had to be delivered.** Every external citation below therefore comes from my own
  knowledge of the literature and was **not re-fetched in this run**. Each is marked
  **[lit, not re-fetched]**. Before any of them goes into a normative doc, the Lead should
  have it verified (the sub-agents' reports can be collected for that). No web content
  was read, so no injected instructions were met. No repository content was sent anywhere.
- Where my memory of a detail is uncertain, the text says so.

---

## 1. DAA raising race, hash-and-leave, selfish mining

### 1.1 Question

The frozen DAA is LWMA-75 with a counted-clock step T/2, an 11-block warm-up and a 6T
solve cap. It leaves two residuals:
- **Race:** a difficulty-raising race succeeds more often than baseline, +3.5 percentage
  points at q = 0.4 and +27.4 points at q = 0.45, at z = 100.
- **RT-4:** after a won race, honest miners inherit up to 18× the equilibrium difficulty.

The question is whether to accept these and document them, change the DAA, or add a
mitigation before the freeze.

### 1.2 What BlackSilk does now (facts)

- **The rule** [src] `consensus/src/difficulty.rs`:
  - `this = max(ts, prev + max(1, T/2))`, with the clock warmed over the 11 blocks before
    the window;
  - solve time capped at 6T; LWMA weights, N = 75;
  - floor n²T/20; fingerprint id `lwma1-n75-step-t/2-warm11-cap6t-floor20`.
- **The counted clock bounds the per-block rise** at about 2× the window average [ev
  redteam.md RT-1]. This is the mechanism that bounds the race.
- **The race figures are absolute percentage points of P(attacker wins)** at z = 100.
  - The compressed-stamp attacker is compared with an honest-stamp private miner on the
    same draws [ev results.md "Difficulty-raising race"; redteam.md RT-3].
  - Without a raising attack (honest-stamp baseline), a q = 0.4 private miner wins a
    100-deep race about 0.2–0.5% of the time; with raising, about 4%. At q = 0.45:
    about 13.5% → about 41%.
  - So at q = 0.4 the DAA residual multiplies the 100-confirmation reversal probability by
    roughly an order of magnitude. That is small in absolute terms, but not negligible.
- **The search was broad** [ev redteam.md]: 24 adaptive policies screened, then confirmed
  on fresh seeds. Its limits: no network latency, no orphans, no clock skew. It is finite
  evidence, not a proof.
- **RT-4 measured stall [M-A], my port.** History: 87 compressed blocks at m × DEQ,
  stamps 60 s apart; then honest hash only. Time until D ≤ 1.1 × DEQ:

  | m | Deterministic | Stochastic median (101 seeds) | 90th percentile |
  |---|---|---|---|
  | 2.5× | 89 blocks, 4.8 h | 88 blocks, 5.3 h | 6.8 h |
  | 10× | 135 blocks, 11.6 h | 137 blocks, 13.5 h | 16.3 h |
  | 18× | 144 blocks, 17.5 h | 156 blocks, 20.5 h | 24.3 h |

  - At 18× the first honest blocks take about 36 min each.
  - This is an independent port, not the committed harness. The redteam's "about 130
    blocks, 9.6 h" for a typical (2.4–2.7×) inherited difficulty is consistent in order of
    magnitude.
  - **This closes the crosscheck's "measure the RT-4 stall" item as an estimate.** A
    committed daa-sim run should confirm it.
- **Park-on-deep-reorg does not cover either residual** [ev redteam.md correction
  2026-10-02; tm2-crosscheck §1.7]: the decided park depth is 720, the race is measured at
  100, and RT-4 happens after acceptance. Park is not implemented anyway.
- **The majority assumption is nominal (K1)** [tm2-consensus §2]. Rented or redirected
  rx/0 hash power (Monero-scale) outruns a small chain's whole hash rate.

### 1.3 Established facts and literature [lit, not re-fetched]

- **Bahack**, "Theoretical Bitcoin Attacks with less than Half of the Computational
  Power (draft)", arXiv:1312.7013, 2013.
  - Introduces the difficulty-raising attack. Under most-work fork choice, an attacker
    mining a private branch of fewer, harder blocks has a higher-variance work total, so it
    overtakes the honest chain with non-negligible probability even below 50%.
  - The attack depends on how fast the DAA lets a branch raise its difficulty. Bitcoin's
    per-2016-block retarget with a ×4 clamp limits it.
- **Garay, Kiayias, Leonardos**, "The Bitcoin Backbone Protocol with Chains of Variable
  Difficulty", CRYPTO 2017 (ePrint 2016/1048).
  - Proves the backbone properties under variable difficulty only with a threshold
    (dampening) τ on how much the target may change per epoch.
  - They argue such a bound is necessary, citing Bahack.
  - My recollection of the exact τ condition is not reliable enough to quote. **Verify
    before citing a formula.**
  - **Relevance:** a bounded per-block rise (BlackSilk's step) is exactly the kind of
    dampening the theory requires. A per-block DAA has no published backbone proof with
    concrete constants: **unsettled** for LWMA-type rules.
- **Selfish mining:**
  - **Eyal and Sirer**, "Majority is not Enough: Bitcoin Mining is Vulnerable", FC 2014.
    The threshold is (1−γ)/(3−2γ); 1/3 at γ = 0, and 1/4 with uniform tie-breaking.
  - **Sapirshtein, Sompolinsky and Zohar**, "Optimal Selfish Mining Strategies in
    Bitcoin", FC 2016. MDP-optimal strategies lower the threshold further.
  - **Grunspan and Pérez-Marco**, "On profitability of selfish mining", arXiv:1805.08281.
    Selfish mining is unprofitable until the difficulty adjusts down after the orphaning
    it causes, so a faster DAA makes it profitable sooner. **A per-block DAA (LWMA, ASERT)
    removes Bitcoin's 2-week "profit lag".**
  - **Negy, Rizun and Sirer**, "Selfish Mining Re-Examined", FC 2020. Intermittent
    selfish mining exploits the difficulty adjustment itself.
  - BlackSilk's RT-5 (SM1 with work-based fork choice) reproduces Eyal–Sirer within about
    2 points and finds that FTL-edge stamps add +0.6 to +1.8 share points [ev].
- **Coin hopping and DAA stability:**
  - **Meshkov, Chepurnoy and Jansen**, "Short Paper: Revisiting Difficulty Control for
    Blockchain Systems", DPM/CBT 2017. Coin-hopping attacks on difficulty control.
  - **Kwon, Kim, Son and Vasserman**, "Bitcoin vs. Bitcoin Cash: Coexistence or
    Downfall of Bitcoin Cash?", IEEE S&P 2019. Hash migration between chains sharing an
    algorithm.
  - **The BCH EDA episode (2017):** an asymmetric emergency rule oscillated and was gamed.
    It was replaced by cw-144 (Nov 2017), then by ASERT (aserti3-2d, Nov 2020).
  - **Lesson:** emergency or asymmetric difficulty rules are exploitable. **Do not answer
    RT-4 with an emergency-drop rule.**
- **ASERT:**
  - Lundeberg, "Static difficulty adjustments, with absolutely scheduled exponentially
    rising targets (DA-ASERT) v2", 2020.
  - Toomim, aserti3-2d specification (BCH, 2020-11-15 upgrade; half-life 2 days).
  - The target depends only on the height and timestamp relative to an anchor, which makes
    it path-independent and free of oscillation. Its per-block rise under compression is
    2^(T/H).
  - BlackSilk's own harness confirms the trade-off: a 6 h half-life meets the race
    criterion (+0.3%) but needs 19 h to follow a 10× rise [ev results.md].
- **Zawy12, github.com/zawy12/difficulty-algorithms** (issue #3 LWMA; timestamp-attack
  and hopper issues; the comparisons of LWMA, EMA and ASERT). This is the primary design
  record for LWMA. It is not peer-reviewed.
  - LWMA was deployed on many small CryptoNote coins, which saw recurring timestamp
    manipulation and hash-hopping episodes.
  - Zawy later recommended ASERT/EMA-type rules for their simplicity and
    path-independence.
- **Monero** (`src/cryptonote_basic/difficulty.cpp`): window 720, cut 60 (outliers by
  sorted timestamps), lag 15. It is slow and therefore race-resistant, but it reacts
  poorly to hash swings.
  - **The 2025 Qubic episode:** a pool claimed majority-like control and produced
    multi-block reorgs on Monero, which revived MRL discussions of finality layers and
    "publish or perish"-style ideas. **Exact reorg depths and dates must be verified
    before citing.**
- **Publish or perish:** Zhang and Preneel, "Publish or Perish: A Backward-Compatible
  Defense Against Selfish Mining in Bitcoin", CT-RSA 2017 (I believe CT-RSA, not USENIX;
  verify). Tie-breaking by fork-free "uncles".

### 1.4 Alternatives

| Option | Security | Liveness / fairness | Maintenance | Verdict [eng] |
|---|---|---|---|---|
| A. Accept, document, runbook (no rule change) | race +3.5 pts at q = 0.4; RT-4 stall about 17–24 h | unchanged (passes all 8 criteria) | none; the evidence is already pinned | **recommended for the testnet** |
| B. Slower rise (smaller step factor, or a larger N) | lowers the race (LWMA-90: still +18.8% without the step) | fails 10× up or down and the genesis ramp; raises the hopper gain (structural trade-off, redteam RT-2) | a new selection, red-team pass, vectors and fingerprint | no |
| C. ASERT, half-life ≥ 6 h | best race resistance in the literature and the harness | fails liveness by an order of magnitude on a small, volatile network | simple, path-independent | no for the testnet; reconsider for mainnet once the hash rate is stable |
| D. Emergency drop rule for RT-4 | — | the EDA precedent: exploitable oscillation | — | **reject** |
| E. A "difficulty-anomaly park" policy: park a deep reorg whose branch has markedly fewer, harder blocks than the branch it replaces | targets Bahack's signature directly | node-local divergence risk, like any park; the threshold needs calibration against honest variance; the attacker can adapt by compressing less (which also cuts its gain) | new policy code plus tests | research item (P2); never consensus before analysis |
| F. Finality or checkpoint layer | addresses q ≥ 0.5, which dominates the real risk | social trust and centralisation | large | mainnet owner decision (K1/K4) |

### 1.5 Recommendation [eng], confidence medium-high

**Accept and document for the testnet; do not change the DAA before the freeze.**

- The residual is real but small at q ≤ 0.4. At q ≥ 0.45 the attacker is effectively a
  majority on a small RandomX chain (K1), where no DAA helps.
- Every alternative tested trades the race against liveness or hopper fairness, as the
  literature predicts (GKL dampening against responsiveness; BCH's experience).
- Required with the acceptance:
  1. The freeze record says "accepted under K1", not "covered by park" (crosscheck F5).
  2. An RT-4 runbook entry with the measured stall (about 17.5 h deterministic, about 20 h
     median, 24 h at the 90th percentile from 18×). The testnet response is "wait, or reset
     by owner decision".
  3. Wallet and exchange guidance: confirmations do not bound a ≥ 40% attacker.
  4. Reopen the DAA and finality before any mainnet (option C or F), with selfish-mining
     profitability under the per-block DAA modelled explicitly (Grunspan/Pérez-Marco
     timing).
- **Evidence that would confirm it:** a committed daa-sim run of RT-4 at 18× (it should
  reproduce M-A within noise); a labnet selfish-mining and withholding scenario (tm2 M2);
  an optimal-strategy (MDP) search for the race beyond the 24 policies.

---

## 2. PX ciphertext R: the canonical-point rule (decided IN for v3)

### 2.1 Question

Is "R must be a valid, canonical, prime-order point" the correct and complete rule? What
goes wrong without it? What else in the encrypted output should be checked at consensus?

### 2.2 What BlackSilk does now (facts)

- **Format** [src] `px/src/delivery.rs`; docs/px.md §6:
  `R (32) ‖ view tag (1) ‖ ML-KEM-768 ct (1088) ‖ ChaCha20-Poly1305 body (104 + 16)`.
- **The curve is Ristretto255** (`CompressedRistretto::decompress` in `seal`/`open`).
- **Consensus fixes only the length:** "This is wallet-side code: consensus only fixes the
  ciphertext length."
- **The ciphertexts are in the PX prefix**, so tx id and `h_tx` cover them (docs/px.md
  §11.1). No relay malleability exists today: the bytes are bound, even if they are junk.
- **v1 already enforces the analogous rule:** canonical point decoding at the codec, plus
  T6 (`EphemeralIdentity`, `OutputKeyIdentity`, stateless; `tx/src/validate.rs`).
- **[M-B]:** 12,467 of 200,000 random 32-byte strings (6.23%, about 1/16) are valid
  canonical ristretto255 encodings.
  - The four independent conditions are: s < p (top bit), s non-negative (even), the
    square-root ratio exists, and t non-negative with y ≠ 0.
  - The all-zero string decodes (it is the identity).
  - So **a non-reference wallet that fills R with random bytes (for example in a dummy or
    padding output) is identified with probability 15/16 per ciphertext** by anyone
    running a decoder.

### 2.3 Established facts [lit, not re-fetched]

- **RFC 9496 (2023), "The ristretto255 and decaf448 Groups":**
  - decoding MUST reject non-canonical encodings, so each element has exactly one
    encoding;
  - the group has prime order ℓ, so there are no small-subgroup elements to reject beyond
    decoding;
  - the identity is a valid element (all-zero encoding);
  - **Hamburg, "Decaf: Eliminating cofactors through point compression", CRYPTO 2015**,
    is the underlying construction;
  - curve25519-dalek's `CompressedRistretto::decompress` implements the canonical decode
    and returns `None` otherwise.
- **Incidents from missing point validation:**
  - **CryptoNote/Monero key-image torsion bug (disclosed May 2017).** Key images were not
    checked to lie in the prime-order subgroup: KI + torsion gave up to 8 distinct "key
    images" per output, so one output could be spent several times. It was exploited on
    Bytecoin. The fix checks ℓ·KI = identity.
    - Lesson: on a cofactor curve, validation means the prime-order subgroup.
    - **Ristretto removes this class by construction**, which is why "canonical decode" is
      a complete group-membership check here.
  - **Monero "burning bug" (2018):** duplicate one-time keys, through repeated tx public
    keys in unvalidated tx_extra, let a sender burn a recipient's funds. This is about
    free, unvalidated key fields. BlackSilk handled the v1 analogue with D8-B and the
    wallet dedupe.
  - **Zcash ZIP 216, "Require Canonical Jubjub Point Encodings"** (activated with NU5).
    Non-canonical encodings of Jubjub points (x = 0 with the sign bit) were accepted by
    some implementations: a consensus-divergence and malleability hazard. Zcash's lesson
    is "consensus accepts exactly one encoding".
  - **Zcash Sapling** output descriptions carry `epk`. My recollection is that the spec
    requires `epk` and `cv` not to be of small order. Orchard's `ephemeralKey` must be a
    valid Pallas encoding. **Verify the exact rule text and section before citing.**
  - **"Taming the many EdDSAs"** (Chalkias, Garillot, Nikolaenko, SSR 2020) and **Cremers
    et al., "The Provable Security of Ed25519: Theory and Practice"** (IEEE S&P 2021):
    divergent acceptance of non-canonical or small-order points across libraries causes
    consensus splits. Canonical-only decoding at consensus is the standard remedy.
  - **Bitcoin BIP 66** (strict DER) and **BIP 62** (malleability) are the precedent for
    "consensus accepts exactly one encoding".
- **Small-subgroup and invalid-curve attacks:** Lim–Lee (CRYPTO 1997); Biehl–Meyer–Müller
  (CRYPTO 2000); Jager–Schwenk–Somorovsky, "Practical Invalid Curve Attacks on
  TLS-ECDH" (ESORICS 2015).
  - These attacks target a recipient's **static** secret through attacker-chosen points.
  - The PX recipient multiplies its static view scalar v by an on-chain R, so a scanner
    is the potential victim.
  - With Ristretto decoding they cannot apply: every decodable R is in the prime-order
    group, and an undecodable R is skipped by `open`.
  - **So the consensus rule is not needed to protect the scanner.** The wallet already
    rejects such R. The rule's value lies elsewhere (§2.4).
  - RFC 7748 §6.1 (an all-zero X25519 output check) is the cofactor-curve counterpart.
- **ML-KEM (FIPS 203, Aug 2024):**
  - Decapsulation input checking covers the ciphertext's type (its length) and the key's
    consistency (the decapsulation-key hash check). The encapsulation-key modulus check
    applies to `ek`, not to `ct`.
  - For ML-KEM-768 (d_u = 10, d_v = 4), ByteDecode_d with d < 12 maps every bit string
    to valid coefficients, so **every 1,088-byte string is a well-formed ciphertext**.
  - Implicit rejection makes decapsulation of junk return a pseudorandom key.
  - **There is nothing to canonical-check in ct_kem beyond length.** Section numbers
    should be verified before citing.
- **Combiner binding:**
  - X-Wing (Barbosa et al., ePrint 2024/039) hashes the classical ciphertext and public
    key;
  - Cremers, Dax and Medinger, "Keeping Up with the KEMs" (CCS 2024), defines binding
    notions (X-BIND-K-PK, …);
  - Giacon, Heuer and Poettering, "KEM Combiners" (PKC 2018).
  - BlackSilk's combiner omits V and H(ek) (documented in px.md §6).

### 2.4 Analysis [eng]

What the rule buys:

1. **Uniformity and fingerprint removal (privacy, the main benefit).** Without it, R is
   32 free bytes: a covert channel and a wallet fingerprint. Random-byte R is detectable
   with probability 15/16 [M-B]. The rule forces every wallet, dummy outputs included,
   to publish a real group element.
   - It does not force R to be uniform (a wallet could still use structured valid points,
     such as small multiples of G). No consensus rule can check that.
   - This matches tm2-privacy C-6.
2. **Recipient safety (burn prevention).** An undecodable R makes a record undeliverable
   on chain: the funds are lost unless the record is re-sent off-chain. The rule turns a
   silent loss into a refused transaction.
3. **Consistency with v1 T6** and with the Zcash and Bitcoin canonical-encoding lessons.
   One less "free field" to reason about after the freeze.
4. **Malleability:** none added or removed, since the bytes are already bound by `h_tx`.

**Should R = identity be refused?**
- With R = identity, ss_ec is the identity encoding for every recipient. The classical
  half of the hybrid then gives nothing, and confidentiality rests on ML-KEM alone.
- The sender can always leak its own record anyway, so this is a **misuse guard, not an
  attack defence**.
- The cost is zero and it mirrors v1's `EphemeralIdentity`. **Refuse it.**

**Completeness.** The checkable structure in the 1,241 bytes is R only:
- the view tag is a hash byte, uncheckable without the secret;
- every ct_kem string is valid;
- the AEAD body is pseudorandom.

So "R decodes canonically as ristretto255 and R ≠ identity" is the complete consensus
rule for the format. "Prime order" adds nothing on Ristretto.

**Not recommended:**
- distinct R across the two ciphertexts: no security gain (Monero shares one R across all
  outputs), and it would only catch broken RNGs, which the hedged derivation already
  covers;
- any rule on the view tag.

**Same-reset wallet item (not consensus).** The KEM combiner hardening (add V and H(ek)
to the key hash, X-Wing style) changes only wallet-side key derivation. Consensus fixes
only the length. Like the R rule, it is free only now, before any records exist.
Recommend doing it in the same window (tm2-privacy item 17).

### 2.5 Recommendation [eng], confidence high

- **Keep the decision:** a stateless, decode-level, penalizable rule that every PX
  ciphertext's first 32 bytes decode as canonical ristretto255 and are not the identity.
- Use the same decoder as v1 (`crypto/src/point.rs`). Place it with T6 in the
  stateless-error table, and give it its own error variant.
- **Tests:**
  - random 32-byte strings are refused at about 15/16;
  - a non-canonical encoding of a valid point (s ≥ p, or a negative s) is refused;
  - the all-zero string is refused;
  - an honest `seal` output is accepted;
  - a golden vector;
  - a mutation pass over the check (including the inclusive-bound pass).
- Process: the consensus-change record, a red-team pass, a fingerprint revision.
- Bundle the combiner hardening in the same reset window, as a wallet-format change with
  vectors.
- **Evidence that would confirm it:** the tests above, plus the RFC 9496 Appendix A
  vectors (valid and invalid encodings) run through the consensus decoder.

---

## 3. Decoy selection for v1 CLSAG rings; rings versus PX long term

### 3.1 Question

What v1 decoy design should the testnet use, and should v1 rings remain long term or
should privacy route through PX?

### 3.2 What BlackSilk does now (facts)

- **The picker** [src] `tx/src/decoy.rs`, Monero's gamma picker:
  - shape 19.28, scale 1/1.61 over log-seconds;
  - the 10-block lock shift, and a uniform draw over the last 15 blocks;
  - eligibility applied inside the draw, with a bounded neighbourhood (R3-1);
  - ring 16, spendable age 10, coinbase maturity 60.
- **`average_output_time` is computed over the whole chain** (`Picker::new`); Monero uses
  at most about a year (F38-9).
- **The wallet takes the node's `/distribution`**, checked only for monotonicity and its
  total, and fetches it at spend time (`wallet/src/wallet/px_flows.rs:224-235`; F38-1,
  F38-6).
  - Ring members themselves are resolved locally.
  - A malicious remote node can skew where decoys land: High for remote-node users
    [tm2-privacy TM2-P3].
- **The decoy RNG is not hedged** (F38-5).
- **Guess-newest** is about 84–89% for spends 12 blocks after receipt on a mature chain;
  about 52% only on a young chain (dossier 38; docs correction W9 decided).

### 3.3 Literature [lit, not re-fetched]

- **Möser, Soska, Heilman, Lee, Heffan, Srivastava, Hogan, Hennessey, Miller, Narayanan
  and Christin**, "An Empirical Analysis of Traceability in the Monero Blockchain",
  PoPETs 2018 (arXiv:1704.04299).
  - Guess-newest identified most real inputs in early Monero.
  - They proposed sampling decoys from a gamma fit to spend ages (the source of the
    19.28/1.61 parameters), which Monero adopted.
- **Kumar, Fischer, Tople and Saxena**, "A Traceability Analysis of Monero's Blockchain",
  ESORICS 2017. Zero-mixin chain reactions.
- **Ronge, Egger, Lai, Schröder and Yin**, "Foundations of Ring Sampling", PoPETs 2021.
  Formal definitions: ring samplers can only be as good as their match to the real-spend
  distribution, and there are impossibility results for natural notions.
- **Egger, Lai, Ronge, Woo and Yin**, "On Defeating Graph Analysis of Anonymous
  Transactions", PoPETs 2022; **Vijayakumaran**, Dulmage–Mendelsohn analysis of CryptoNote
  graphs (ePrint 2021/760); **Yu et al.**, "New Empirical Traceability Analysis of
  CryptoNote-Style Blockchains", FC 2019; **Deuber, Ronge and Rückert**, "SoK: Assumptions
  Underlying Cryptocurrency Deanonymizations", PoPETs 2022.
- **Monero's 2021 decoy-selection bug.** A wallet2 bug in the selection of recent outputs
  made real spends of very young outputs identifiable. It was found in 2021 (Rucknium,
  j-berman) and fixed in the v0.17.3.x line. **Verify the exact PR, issue and release
  numbers.**
  - Rucknium's MRL work (OSPEAD, an estimate of the real-spend distribution) found
    Monero's gamma parameters out of date. Re-fitting is still open in MRL.
- **Black marbles:**
  - MRL-0001 (Noether, Noether and Mackenzie, 2014), chain reactions;
  - Chervinski et al., "FloodXMR" (2019/2021);
  - the suspected black-marble flooding of Monero in early 2024 (Rucknium's MRL analysis
    estimated a sizeable drop in effective ring size during the flood). **Verify the
    figures.**
- **Remote nodes:** Monero's wallet2 also takes `get_output_distribution` from the daemon.
  This is the same trust BlackSilk has today (tm2-privacy §11).
- **FCMP++** (Full-Chain Membership Proofs; Luke Parker / kayabaNerve; built on Curve
  Trees, Campanelli, Hall-Andersen and Kamp, USENIX Security 2023, ePrint 2022/756) is
  Monero's planned replacement of rings with full-chain anonymity, together with the Carrot
  addressing scheme. Monero's motivation is explicitly the statistical weakness of rings.
  **Status and hard-fork timing as of 2026: verify.**
- **The Zcash lesson for optional pools:**
  - Kappos, Yousaf, Maller and Meiklejohn, "An Empirical Analysis of Anonymity in Zcash",
    USENIX Security 2018: most shielded activity was linkable by deposit/withdraw amount
    and timing ("round-trip" transactions) while the shielded pool was small and optional.
  - Biryukov, Feher and Vitto, "Privacy aspects and subliminal channels in Zcash", CCS
    2019: similar.

### 3.4 Analysis [eng]

**Testnet v1 design:**
- local distribution from the wallet's verified index (already decided P0 before a public
  testnet);
- no spend-time `/distribution`;
- a hedged decoy RNG keyed from the hedge key;
- `average_output_time` over a bounded recent window (about 1 year, as Monero), with the
  formula documented.

**The gamma parameters:**
- Keep Monero's 19.28/1.61 for now, since there are no BlackSilk spend data to fit.
- Mark them "inherited, unfitted".
- Plan an OSPEAD-style re-fit only after the network has real usage. Trial data are
  coinbase-dominated (tm2-crosscheck X10) and unusable for fitting.

**Long term:**
- Rings give statistical, sampler-dependent anonymity (Ronge et al.). On a young or small
  chain they are weak: guess-newest above 80% for quick spends, and cheap black marbles.
- PX already gives a full-pool anonymity set.
- The Zcash lesson cuts the other way: an optional pool reached by public bridge-in and
  bridge-out amounts leaks through amount and timing matching.

So:
- (1) make PX-to-PX the wallet's default private payment path, with bridge denominations
  and delays as a wallet helper (C-5 is currently a reminder only);
- (2) keep v1 for the testnet and the coinbase. There is no shielded coinbase in v3 (21-G),
  so v1 cannot be retired yet;
- (3) research a shielded coinbase plus a v1 sunset (v1 for coinbase and bridge only) as a
  later scheduled upgrade, mirroring Monero's own FCMP++ direction.

### 3.5 Recommendation [eng], confidence medium

- **For the testnet:** the local distribution, the hedged RNG and the window-parity items
  are P0 before a public testnet; the guess-newest docs correction is P0.
- **v1 rings stay for v3** but are documented as the weaker layer.
- **Long term:** route privacy through PX (default PX payments, a bridge-hygiene helper),
  and plan a v1 sunset after a shielded coinbase exists. Owner decision (P3).
- **Confirming evidence:**
  - the tm2 M4 synthetic mature-chain guess-newest test;
  - a test that a skewed but monotone node distribution cannot change rings;
  - a ring-intersection test after a deep reorg (X7);
  - later, measured PX anonymity-set sizes against bridge-flow matching on labnet data.

---

## 4. Transaction relay privacy

### 4.1 Question

What must the relay have before a public testnet?

### 4.2 What BlackSilk does now (facts)

- **Dandelion++** [src] `p2p/src/dandelion.rs`; docs/p2p.md §8:
  - epochs of 9–11 min, q = 0.2, 2 stem peers, per-source routes;
  - embargo 10 s + Exp(39 s);
  - the origin always stems and holds when it has no stem peer.
- **Per-peer Poisson trickle** with no shared inbound timer and unshuffled batches
  (R8-16).
- **Unpadded frames:** a link observer sees origination of v1 and PX (p2p.md §1).
- **SOCKS without stream isolation; no onion-only outbound;** a dual-homed `--proxy`
  (p2p.md §11).
- **Open issues:**
  - the request tracker shares state across clearnet and onion identities (RT3 F6; fix
    decided: per-network-class tracker);
  - TM2-P4 (black-holing PX stems);
  - TM2-P6 (the stempool timing oracle).
- **Fixed:** the re-announce origin oracle, re-origination, and the GetTx limits (TM2-P2P
  rounds).

### 4.3 Literature [lit, not re-fetched]

- **Bojja Venkatakrishnan, Fanti and Viswanath**, "Dandelion: Redesigning the Bitcoin
  Network for Anonymity", SIGMETRICS 2017.
- **Fanti, Bojja Venkatakrishnan, Bakshi, Denby, Bhargava, Miller and Viswanath**,
  "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees",
  SIGMETRICS 2018 (arXiv:1805.11060).
  - The guarantees are against honest-but-curious spy nodes (a fraction p), measured as
    precision and recall.
  - They rely on 4-regular anonymity graphs, per-epoch one-to-one routing and embargo
    timers.
  - **They give no protection against link observers (ISPs) or against active
    black-holing beyond the fail-safe.**
- **BIP 156** (Dandelion) was never merged into Bitcoin Core, chiefly over DoS and
  complexity concerns around the stempool.
- **Sharma, Gosain and Diaz**, "On the Anonymity of Peer-To-Peer Network Anonymity
  Schemes Used by Cryptocurrencies", NDSS 2023. With realistic adversaries and network
  sizes, Dandelion/Dandelion++ deanonymize a large share of transactions: their
  guarantees are weaker in practice than the asymptotic analysis suggests. **Verify the
  numbers.**
- **Deanonymization of P2P relay and Tor clients:**
  - Biryukov, Khovratovich and Pustogarov, "Deanonymisation of Clients in Bitcoin P2P
    Network", CCS 2014;
  - Biryukov and Pustogarov, "Bitcoin over Tor isn't a Good Idea", IEEE S&P 2015 (Tor
    exit and ban manipulation; it isolates Tor-only clients onto attacker exits);
  - Fanti and Viswanath, "Anonymity Properties of the Bitcoin P2P Network", NeurIPS
    2017: diffusion, like trickle, gives weak anonymity;
  - Koshy, Koshy and McDaniel, FC 2014.
- **Monero:**
  - Dandelion++ in monerod (PR #6314, v0.16, 2020);
  - q and embargo tuned by PR #7025 (cited in the code);
  - anonymity-network relay (`--tx-proxy`, `--anonymous-inbound`) with fixed-size
    "noise" padding for Tor/I2P links;
  - Cao, Yu, Decouchant, Luo and Veríssimo, "Exploring the Monero Peer-to-Peer Network",
    FC 2020.
- **Bitcoin Core:**
  - `txrequest` (PR #19988, Wuille, 0.21/22): preferred outbound announcers, one in-flight
    request per txid, deadlines, per-peer caps;
  - a shared inbound inv timer and shuffled inv batches (PR #13298 lineage, "Random delays
    per network group");
  - per-network cached addr answers (PR #18991);
  - `-proxyrandomize` (random SOCKS credentials for Tor stream isolation, default on) and
    `-onlynet`;
  - BIP 324 v2 transport (pseudorandom bytestream, garbage, decoy messages);
  - private broadcast of local transactions over short-lived Tor/I2P connections (PR
    #29415, Vasil Dimov). **Verify the merge and release status;** tm2-privacy cites
    "30.x".
  - The 2023 "LinkingLion" spy-node findings (b10c): large spy deployments exist in
    practice.
- **Tor:** the `IsolateSOCKSAuth` SocksPort flag (default on) isolates streams by SOCKS
  credentials, which is why per-connection random credentials matter.
- **Alternatives:**
  - Clover (Franzoni and Daza, 2022);
  - mixnet relay (Loopix, Piotrowska et al., USENIX Security 2017; Nym);
  - Zcash relies on Tor rather than Dandelion.
  - Bogatyy (2019) showed Grin's Dandelion did not protect Mimblewimble aggregation
    against a sniffing node.

### 4.4 Analysis [eng]

- Dandelion++ is necessary but weak. It only addresses spy nodes, and the practical
  results (Sharma et al.) are weaker than the paper's asymptotics.
- **The strongest available protection for origin against both spies and ISPs is sending
  one's own transactions over Tor** (private broadcast, or a Monero-style `--tx-proxy`),
  together with stream isolation and onion-only operation for Tor nodes.
- **Padding:** PX transactions are about 2.2 MB, so padding can at best hide which kind,
  not that something was sent. Padding v1 to a fixed size class and adding cover traffic
  is a mainnet item.
- **Linkability across identities (F6, GetAddr mixing, dual-homing)** is a design
  property: separate per-network-class state, as Bitcoin Core does for addr caches.

### 4.5 Recommendation [eng], confidence medium-high

Before a public testnet (P0-public):
1. the per-network-class tracker and the RT3/RT4 fixes;
2. a shared inbound trickle timer per network class, with shuffled inv batches (R8-16);
3. `--onion-only` (default under `--proxy-only`) and random SOCKS credentials per
   connection;
4. local re-stem on the first embargo expiry and a kind-aware PX embargo (TM2-P4);
5. a per-network GetAddr cache and no dual-homed fluff fallback (F33-7);
6. the privacy regression suite gating every relay change;
7. docs stating plainly that Dandelion++ does not hide origin from the node's ISP, and
   that Tor is the recommended path.

P1 (before mainnet): private broadcast of originated transactions over Tor (Bitcoin Core
style), then transport v2 with size classes.

**Confirming evidence:** the Rust first-spy simulator (33 W9) at realistic spy
fractions, compared with the Sharma et al. methodology; labnet PX stem-latency and
black-hole measurements (tm2 M2, M3); NS-8 chutney Tor tests.

---

## 5. ZK proof-system parameters: is "≈100+ bits" honest?

### 5.1 Question

Is the FRI configuration's soundness claim honest under current results, and what would
make it provable rather than conjectured?

### 5.2 What BlackSilk does now (facts)

- **BS-ZK-3** [src] `zk/src/params.rs`:
  - BabyBear⁸ (247-bit challenges);
  - LOG_BLOWUP 3 (ρ = 1/8), 108 queries;
  - arity ≤ 16, final poly 2^6;
  - query grinding 16 bits, commit grinding 0;
  - 8 random codewords, salted leaves;
  - COLLISION_BITS 122.
- **Claim** (docs/zk.md §9.3): about 105 bits **computed from proven bounds** in the
  unique-decoding regime. The Johnson regime's algebraic bound is ≥ 150 bits, so it is
  hash-bound at about 122.
- **The docs explicitly reject sizing by conjectured up-to-capacity bounds.**
  `ConjecturedSecurity` is never used for sizing (decision 25, W6 test).
- **My arithmetic check:**
  - unique decoding: δ = (1−ρ)/2 = 7/16 per query, so −log2(9/16) = 0.830 bits × 108 =
    89.7, plus 16 grinding = 105.7 ✓;
  - Johnson: 1 − √ρ ≈ 0.646, so ≈ 1.5 bits × 108 ≈ 162 (capped by 122);
  - the capacity conjecture would give 3 bits × 108 = 324. **This shows how far BlackSilk
    is from relying on the conjecture.**
- **Unanalysed:** mixed-height FRI (no published bound); the Merkle extractability
  adaptation of ePrint 2026/089 Theorem 3 (argued, not proven); LogUp and the DEEP union
  (bounded by the in-repo calculator at ≥ 200).

### 5.3 Literature [lit, not re-fetched]

- **Ben-Sasson, Carmon, Ishai, Kopparty and Saraf**, "Proximity Gaps for Reed–Solomon
  Codes", FOCS 2020 (ePrint 2020/654). Proven correlated agreement up to the
  unique-decoding radius and up to the Johnson bound (with polynomial losses). These are
  the proven FRI soundness bounds.
- **StarkWare, "ethSTARK Documentation"** (ePrint 2021/582). It sets parameters by a
  stated conjecture (soundness about queries × log(1/ρ) plus grinding) and also gives
  proven bounds.
- **Block, Garreta, Katz, Thaler, Tiwari and Zając**, "Fiat–Shamir Security of FRI and
  Related SNARKs", ASIACRYPT 2023 (ePrint 2023/1071).
  - Round-by-round soundness of FRI and its non-interactive security in the ROM.
  - They show that some deployed parameterizations had lower concrete security than
    claimed once FS attacks across rounds are counted.
  - This is what makes the per-round commit-phase terms necessary in a non-interactive
    claim.
- **Haböck**, "A summary on the FRI low degree test" (ePrint 2022/1216).
- **The 2025 status of the "up to capacity" proximity-gap conjecture:**
  - Several 2025 papers gave counterexamples or limits to the strongest (up to list
    decoding capacity) forms. The Ethereum Foundation started a prize on the question.
  - Ben-Sasson, Carmon, Haböck, Kopparty and Saraf (ePrint 2025/2055) improve the proven
    bounds (BlackSilk's calculator uses its Thm 1.5 form).
  - The Johnson and unique-decoding regimes, which BlackSilk uses, are proven and
    unaffected.
  - **Exact paper identities and what each disproves: verify.** I recall a Crites–Stewart
    ePrint on RS proximity-gap conjectures, but I am not certain of the number.
- **STIR** (Arnon, Chiesa, Fenzi and Yogev, CRYPTO 2024) and **WHIR** (same authors,
  2024/2025): RS proximity tests with proven soundness at far fewer queries. This is the
  route to proven security with smaller proofs, but a new proof system.
- **Hash assumptions:**
  - BCS-compiled soundness requires a random-oracle-like hash;
  - Chiesa, Manohar and Spooner, TCC 2019 (QROM);
  - Poseidon2 (Grassi, Khovratovich and Schofnegger, AFRICACRYPT 2023) is the subject of
    continuing algebraic cryptanalysis, including over small fields (the Ethereum
    Foundation's Poseidon initiative);
  - Khovratovich, Rothblum and Soukhanov, "How to Prove False Statements: Practical
    Attacks on Fiat–Shamir" (2025): FS soundness depends on the instantiation, not only
    on the ROM proof. It does not directly break FRI-based STARKs, but it removes "the ROM
    proof is enough" as a comfort.
- **Implementation-level incidents** (the class that dominates in practice):
  - Frozen Heart (Trail of Bits, 2022), FS transcript omissions;
  - the SP1 and RISC Zero 2025 advisories;
  - the Plonky3 upstream fixes BlackSilk already tracks (PR 2106/2256/2033/2277, PR
    2100). **Verify the identifiers before citing.**

### 5.4 Analysis [eng]

**Is the claim honest?** Largely yes, with one correction of framing.

- The headline is **not** conjectured in the ethSTARK sense: it uses the proven
  unique-decoding regime, about 66 bits below what the capacity conjecture would claim.
  The task's phrase "~100+ bits, conjectured" understates the method.
- It is also **not a proof of the system**. It is a sum of proven component bounds
  (FRI in unique decoding, BCIKS20/BCHKS25 in Johnson, Block et al.'s FS framework), under
  four conditions:
  1. Poseidon2 modelled as a random oracle (heuristic);
  2. mixed-height batched FRI with no published analysis (assumed covered by per-round
     terms);
  3. an argued, not proven, adaptation of the Merkle extractability theorem;
  4. no end-to-end round-by-round soundness proof of Plonky3's batch-STARK as configured
     (DEEP-ALI, LogUp, multi-table, ZK masking).

**Honest headline wording:**

> "≈105 bits in the unique-decoding regime, computed from proven FRI bounds under the
> random-oracle model for Poseidon2. System-level soundness additionally assumes that
> mixed-height batching and the batch-STARK composition lose nothing beyond the computed
> terms (no published proof), and our Merkle extractability adaptation (argued). Not
> reviewed externally."

docs/zk.md §9.3 is close to this already. It should drop "proven" wherever it modifies the
system rather than the FRI component.

**To make it provable:**
- (a) Write an end-to-end RBR soundness argument for the exact protocol: a written proof,
  then external academic review. The owner policy rules out auditors, so this would rest on
  publication and peer review.
- (b) Bound mixed heights conservatively: a union over ≤ 23 distinct heights costs about
  5 bits, which the 105-bit margin absorbs. Or fold all heights into a single
  known-analysis schedule.
- (c) Prove the Merkle adaptation, or use a construction the theorem covers verbatim.
- (d) Long term, a proof system whose concrete soundness is fully proven and published
  (STIR/WHIR-based), and machine-checked FRI bounds (Lean formalizations exist in research
  projects; verify).

### 5.5 Recommendation [eng], confidence medium-high

- **Keep BS-ZK-3 for the freeze.** No parameter change is warranted: the margins sit in
  the proven regime.
- **Before the freeze (docs only):** adopt the wording above; add a mixed-height union
  bound term to the independent calculator (W2) so the "unanalysed" item becomes a
  conservative computed term.
- **P2/P3:** a written soundness argument and a hash-agility plan (already required by
  R2-C6).
- **Confirming evidence:** a calculator test with the union term at the largest shape
  (expected ≥ 100 bits unique decoding); verified citations for the 2025 conjecture
  refutations; the golden-proof tamper sweep (TM2-2) for transcript completeness.

---

## 6. Summary of recommendations

| Topic | Recommendation | Confidence | Consensus change? |
|---|---|---|---|
| 1 DAA | Accept the residual under K1 for the testnet; correct the record; RT-4 runbook (about 17–24 h stall from 18×); reopen DAA and finality before mainnet | medium-high | no |
| 2 PX R | Keep IN: canonical ristretto255 decode **and** R ≠ identity; nothing else in the format is checkable; do the KEM-combiner hardening in the same reset (wallet format) | high | yes (decided) |
| 3 Decoys | Local distribution, hedged RNG, a 1-year window, no spend-time query (P0 public); keep rings in v3; long-term PX-default payments and a v1 sunset after a shielded coinbase | medium | no |
| 4 Relay | Per-class tracker, shared shuffled trickle, onion-only and stream isolation, local re-stem, privacy suite, honest docs (P0 public); private broadcast over Tor before mainnet | medium-high | no |
| 5 FRI | The claim is honest in method (proven unique-decoding regime, not conjectured); reword "proven" as component-level; add a mixed-height union term; a written RBR proof long term | medium-high | no |

## 7. Open items for the Lead

- Collect the five research sub-agents' reports, which were still running at delivery,
  and verify every [lit, not re-fetched] citation before it enters a normative doc. The
  ones needing the most care:
  - the exact GKL-2017 τ condition;
  - the Zcash epk rule text;
  - the Monero 2021 bug's PR and release numbers;
  - the Sharma et al. figures;
  - the 2025 proximity-gap refutation papers;
  - Bitcoin Core private-broadcast release status;
  - the Qubic reorg facts.
- Confirm M-A with the committed daa-sim harness (an RT-4 18× run).


---

## 8. Verification addendum (2026-10-04). This supersedes every "[lit, not re-fetched]" marker above.

**How the sources were checked.**
- All five source sub-agents (DAA, canonical point, decoys, relay, FRI) delivered. They
  fetched primary texts, extracting full PDFs with pdftotext where needed.
- I independently re-fetched GKL 2016/1048 (Definition 2 and Remark 2), RFC 9496, ZIP 216,
  and arXiv 2512.01437.
- **The decoy sub-agent (topic 3) delivered last; §8.3 is verified.**
- One integrity incident: a WebFetch summary misattributed a different NDSS paper's
  claims to Sharma et al. The relay agent caught it and re-extracted the real arXiv text.
  No page carried instructions.
- **Statuses:**
  - **V** = verified in the primary text;
  - **V-meta** = bibliographic details only;
  - **C** = corrected;
  - **U** = unverified.

### 8.1 Topic 1 (DAA)

| Citation | Status | Source and finding |
|---|---|---|
| GKL 2017 | **V, C** | https://eprint.iacr.org/2016/1048, Definition 2: the target is clamped per **epoch of m blocks** to [T/τ, τT]; Table 1 calls τ "the dampening filter". Remark 2: "in the absence of such dampening, an efficient attack is known [2] … this dampening is sufficient for us to prove security against all attackers, including those considered in [2] (… the attack still holds but it will take exponential time to mount)". Remark 3: Bitcoin's τ=4, m=2016 is justified only for hash-rate fluctuation "up to 28% every approximately 2 months". **Correction:** the theorem is per epoch; per-block LWMA is outside the model |
| Bahack, arXiv:1312.7013 | **V** | §2.2, Claim 4: with a ×4 limit, "no matter how small her hash-power is, on some point her chain will surpass the honest chain"; "any mechanism enabling exponentially rise of the difficulty is vulnerable … no matter how small is the exponential base". It is a draft and calls itself "of theoretical importance only" |
| Eyal–Sirer, FC 2014 | V | arXiv:1311.0243 |
| Sapirshtein et al., FC 2016 | V | arXiv:1507.06183 |
| Grunspan–Pérez-Marco | **V** | arXiv:1805.08281: "no strategy is more profitable than the honest strategy before a difficulty adjustment … it is an attack on the difficulty adjustment algorithm" |
| Negy–Rizun–Sirer, FC 2020 | **V, C** | https://fc20.ifca.ai/preproceedings/4.pdf: intermittent selfish mining is profitable above 37% at γ=0; "with the DAAs under analysis, DAA choice is irrelevant when it comes to selfish mining" (this includes sliding-window BCH and XMR). **Correction:** the dossier implied per-block DAAs worsen selfish mining. The verified finding is that for sliding-window DAAs the choice barely matters, because orphaning keeps the difficulty near-constant |
| Bar-Zur, Eyal, Tamar, AFT 2020 | V | arXiv:2007.05614 |
| Ren Zhang thesis, KU Leuven 2019 | **V (added)** | "It is an open question that whether there is a per-block difficulty adjustment mechanism where selfish mining is not profitable" |
| Meshkov–Chepurnoy–Jansen 2017 | V-meta | Springer; abstract snippet only |
| Kwon et al., IEEE S&P 2019 | **V, C** | arXiv:1902.11064. Authors: **Kwon, H. Kim, Shin, Y. Kim** ("fickle mining") |
| BCH Nov-2017 cw-144 spec | V | bitcoincash.org spec: replaces the EDA |
| Noda et al.; Fullmer–Morse; Kraft | V-meta | abstracts or search results only |
| Lundeberg, DA-ASERT v2 | **V (added caveat)** | https://www.bitcoinunlimited.info/nexa/da-asert.pdf: path-independent. It warns that "it is actually quite dangerous to artificially restrict … upward movement of difficulty" in relative algorithms unless timestamps are monotonic. **BlackSilk's counted clock is monotonic, which meets that precondition. The tension with GKL's clamp is unresolved in the literature** |
| aserti3-2d spec | V | https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/, halflife 172800 s |
| Zawy12 issues #3, #30, #58, #76 | V (GitHub, not peer-reviewed) | #3 recommends N=90 at T=120 (BlackSilk uses 75) and FTL ≈ N·T/20 (450 s; BlackSilk 360 s); #30 covers the timespan-limit attack (the fix is monotonic stamps); #58 says sum-of-difficulty work overestimates hashes on short or variable tips (relevant to Bahack); #76 now recommends WTEMA with N = 1–2 days |
| Monero difficulty.cpp | **V, C** | 720/60/15, FTL 2 h. **Monero's MTP window is 60 (`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`), not 11** |
| Qubic 2025 | **V, C** | Lee & Kim, arXiv:2512.01437 (AFT 2026): no "sustained majority control", strategies "varied", "gained no reward advantage over honest mining". The **18-block** reorg (heights 3,499,659–3,499,676, 14–15 Sep 2025; 115 transactions invalidated; "the 10-block lock was overwhelmed") comes from Rucknium's blog (https://rucknium.me/posts/monero-18-block-reorg/), a primary analyst source. The 6- and 9-block reorgs come from the press only (U) |
| Monero responses | V | research-lab #144 (Publish-or-Perish soft fork; "does not (and cannot) address 51% attacks"), #135 (finality layer), monero #10064 (rolling DNS checkpoints: "a determined attacker with 30% hashpower share could cause a 10-block re-org about three times per day"). Mainnet deployment of these is U |
| Zhang–Preneel, Publish or Perish | **V, C** | **CT-RSA 2017** (LNCS 10159), as I suspected; not USENIX |
| BIP 54 | V (added) | Consensus Cleanup timewarp rules |
| Law, Erol, Tseng, arXiv:2308.15312 | V (added) | "POW blockchains with frequent difficulty adjustments relative to time reporting flexibility will be substantially more vulnerable to longest-chain attacks" |
| Zhang–Preneel, S&P 2019 | V-meta | content U |

### 8.2 Topic 2 (PX R)

All key items verified by the sub-agent and by my own re-fetch:

- **RFC 9496:** §4.3.1 "non-canonical values are rejected"; §4 "every element except the
  identity is a generator"; Appendix A.1, the identity is all zeros and decodes; §8
  "invalid states are unrepresentable".
- **Decaf:** ePrint 2015/673.
- **dalek docs:** decompress returns `None` for a non-canonical encoding and accepts the
  identity.
- **Zcash protocol spec v2026.7.0:**
  - **§4.5** "cv and epk MUST NOT be of small order", which "has the effect of also
    preventing non-canonical encodings";
  - **§4.6** Orchard: "Elements of an Action description MUST be canonical encodings";
  - §5.4.5.5: KA^Orchard.Public = P* (non-identity);
  - §4.20: "epk cannot be O_P", and the KDF must use the wire bytes.
  - **This is exactly the proposed rule, already in production.**
- **ZIP 216.**
- **FIPS 203:**
  - §7.2 (ek type and modulus checks);
  - §7.3 (ciphertext type check, length only; "does not guarantee … c is a properly
    produced output");
  - §4.2.1 "For d satisfying 1 ≤ d ≤ 11, the conversion is one-to-one", so all 1,088-byte
    strings are valid.
- **Combiners and binding:** X-Wing (ePrint 2024/039; draft-11 claims MAL-BIND-K-PK/CT);
  Cremers–Dax–Medinger (ePrint 2023/1933); Schmieg (2024/523); Giacon et al. (2018/024).
- **Other verified:** RFC 7748 §6.1; Cremers–Jackson CSF 2019 (2019/526); "Taming the many
  EdDSAs" (2020/1244); ZIP 215; Tramèr–Boneh–Paterson (2020/220: wallets must treat any
  failure as "not mine").
- **Metadata only (V-meta):** Lim–Lee, Biehl et al., Jager et al.

**Corrections:**
- **(C1)** The 2018 "burning bug" was about outputs sharing a one-time key (PR #4438,
  v0.12.3.0). The **tx_extra** duplicate-pubkey mechanism was the separate "multiple
  counting bug" (getmonero.org, 2018-09-05). Both are verified.
- **(C2)** "Exploited on Bytecoin" is **U**; the 2017 post says only that Bytecoin was
  vulnerable and unpatched. The claim is withdrawn.
- **(C3)** The Ed25519 provable-security paper is by **Brendel, Cremers, Jackson and
  Zhao** (S&P 2021, ePrint 2020/823).
- **(C4)** "Consensus accepts exactly one encoding" is our paraphrase of BIP 66/62 and ZIP
  216, not a quote.
- **The 1/16 figure:** valid strings number exactly l ≈ 2^252, so the share is l/2^256 ≈
  1/16. This confirms M-B analytically.

### 8.3 Topic 3 (decoys). VERIFIED (the decoy sub-agent delivered after the first draft of this addendum)

| Citation | Status | Finding |
|---|---|---|
| Möser et al., PoPETs 2018 (arXiv:1704.04299) | **V** | "about 62% of transaction inputs with one or more mixins are vulnerable to 'chain-reaction' analysis"; guess-newest has "80% accuracy"; the gamma fit is shape 19.28, rate 1.61 in log seconds, **fitted on deducible pre-RingCT inputs only**. Monero's wallet2 still hard-codes these values (wallet2.cpp, master 2026-10-02) |
| Kumar et al., ESORICS 2017 (ePrint 2017/338) | V | "87% of cases"; "over 98%" of traced inputs spend the newest output |
| Ronge et al., "Foundations of Ring Sampling", PoPETs 2021 | **V** | A mimicking sampler reaches at least half the optimal anonymity only if the estimate is right; the real-spend distribution is "arguably unknowable and inapproximable". They recommend a **partitioning sampler** (≤ lg α below optimal) |
| Egger et al., PoPETs 2022 | V | With partitioning samplers and ring size ≥ log(#users), graph analysis gains at most a factor of 2 |
| Vijayakumaran, AFT 2023 (ePrint 2021/760) | V | Main chain: "None of the 4,330,234 RingCT rings could be traced"; 0.15% traceable using key images across forks. Graph attacks are largely dead; **the residual risk is statistical (age)** |
| Yu et al., FC 2019 | **V, C** | Authors corrected to **Yu, Au, Yu, Yang, Xu, Lau** |
| Deuber, Ronge, Rückert, PoPETs 2022 | V | "assumptions based on user behaviour are in general the most unreliable" |
| **Monero 2021 decoy bugs** | **V, C** | Issue **#7807** (j-berman, 2021-07-27): the gamma was applied from the unlock point, not the tip. Fix: **PR #7821** (merged 2021-08-20). A second bug truncated `average_output_time` to an integer; fixes **PR #7798** and #7845. Release **v0.17.2.3** (2021-08-31); post-mortem 2021-09-20; affected v0.14.1.0–v0.17.2.2. Lesson: "all wallets would conform to the same spec". Which PR shipped in which point release: U |
| **Monero 2023 off-by-one** (issue #8872; fixed by PR #8794 in v0.18.2.2) | **V (added)** | Decoys were never exactly 10 blocks old: "the only time a 10-block old ring member will show up in a transaction is if it is the true spend". **Directly relevant to BlackSilk's 10-block spendable age** |
| Wownero 2022 | U (summary only) | A lock-anchor error made about 80% of rings deducible |
| **OSPEAD** (Rucknium) | **V, C** | The name is "Optimal Static Parametric Estimation of Arbitrary Distributions". **The status-quo gamma gives MAP attack success of 23.5%, an effective ring size of 4.2 out of 16, since Aug 2022.** The recommended GB2 fit gives 7.6% success, effective ring size 13.2. Not deployed |
| wallet2 trusts the daemon distribution | **V** | `get_rct_distribution` and `get_outs` check only size, ordering and the max index. Open PR #11451 (2026-10-02) hardens them. Feather incident (2024-04-28): "a malicious remote node manipulates the output distribution in a way that reveals the true spend"; its hard-coded cap later caused a DoS. **This confirms TM2-P3 and the local-distribution fix** |
| MRL-0001 (2014) | V | Black-marble chain reactions |
| Rucknium, March-2024 flood (draft v0.1) | **V** | "mean effective ring size has decreased from 16 to 5.5 if the black marble flooding hypothesis is correct"; estimated cost about 42.5 XMR |
| FloodXMR (ePrint 2019/455) | V | Trace "up to 47.63%" of inputs for about 1,746 USD over 12 months |
| FCMP++ (getmonero.org 2024-04-27) | **V** | Rings are "vulnerable to attacks such as the EAE attack, have difficulties upon chain reorganizations, and in general enable statistical analysis"; the anonymity set goes from 16 to about 100,000,000 |
| Curve Trees, USENIX Security 2023 (ePrint 2022/756) | V | — |
| **FCMP++ status** | **V, C** | **Not on mainnet:** mainnet is v0.18.5.1, ring-based. The beta stressnet v0.19.0.0-beta.3.0 forks on 2026-10-05; no mainnet date. Trail of Bits crypto audit (2026-08): 0 high/medium/low findings. Secondary claims of a "May 2026 activation" are **false** |
| Kappos et al., USENIX Security 2018 | **V** | 14.96% of transactions touched the shielded pool; heuristics "reduce the size of the overall anonymity set by 69.1%"; round-trip matching linked 28.5% of deposited coins; "the only way … is to require all transactions to take place within the shielded pool" |
| Biryukov, Feher, Vitto, CCS 2019 | V | Value matching; on average 1.42 shielded hops |
| Monero research-lab #109 | **V (added)** | P2Pool coinbases were 14% of outputs, giving an effective ring size of about 13. This argues for coinbase handling in decoy selection on coinbase-dominated chains |
### 8.4 Topic 4 (relay)

| Citation | Status | Finding |
|---|---|---|
| Dandelion++ (arXiv:1805.11060, POMACS 2(2) 2018) | **V** | ISP/AS adversaries are "outside the scope of this paper"; they can eclipse nodes, and then "routing-based defenses (like Dandelion++) cannot provide any guarantees". q ≤ 0.2 limits the precision increase to 0.1. Same-source transactions share a path within an epoch, a linkability trade-off the paper states. Fail-safe embargo, Proposition 3 |
| Dandelion (arXiv:1701.04439) | V (abstract) | — |
| BIP 156 | **V** | Closed; Bitcoin Core PR #13947 closed over stempool DoS concerns (sipa, sdaftuar; Optech #9) |
| **Sharma, Gosain, Diaz, NDSS 2023** | **V** | arXiv:2201.11860 full text: "none of them offers acceptable anonymity"; at 15% adversarial nodes Dandelion leaves "uncertainty among only 8 possible originators"; at 20% the median entropy is **3 bits (Dandelion) and 5 bits (Dandelion++)**; "increasing the network size does not correspond to an increase in the anonymity set"; more than 98.5% of the D++ privacy subgraph was learned with 100 transactions per node. Caveat: they did not model one-to-one routing in the entropy |
| Biryukov–Khovratovich–Pustogarov, CCS 2014 | V | 11%, and up to 60% with DoS; under 1500 EUR per month |
| Biryukov–Pustogarov, S&P 2015 | V (abstract) | "full control of information flows" for Bitcoin-over-Tor users; fingerprinting links Tor and clearnet identities |
| ProxyMark (Shi et al., arXiv:2607.07062) | **V** | Monero's originated transactions go to 2 fixed proxy nodes over Tor, a fingerprint. Height inflation biases proxy selection; a Tor-relay watermark achieves 100% precision and 91–94% recall given guard placement. **Lesson for BlackSilk: originated and relayed transactions must be indistinguishable on the anonymity network** |
| Monero PR #6314, config, levin_notify | **V** | Stems 2, fluff 20%, epoch 10 min + 30 s, embargo 39 s from k=5, ε=0.10, 175 ms per hop. Noise mode gives ISP protection with fixed 3 KiB packets; `--pad-transactions` pads to 1 KiB; local transactions go only to anonymity peers (held, never leaked to clearnet) |
| Monero spy-node ban list (meta #1124) | V | Opt-in; overlaps with LinkingLion |
| LinkingLion (b10c 2023) | V | — |
| Kopyciok et al., arXiv:2509.10214 | V (added) | About 14.7% of reachable Monero peers are anomalous |
| Bitcoin Core txrequest, PR #19988 (merged 2020-10-14) | **V** | Preferred (outbound) first; one outstanding request per txhash; random choice among candidates; a DoS and censorship design, not a privacy one |
| Inv trickle, PR #13298 (v0.17) and **PR #33464 (2025-10)** | **V** | One shared timer per network key, because "a spy node could make multiple inbound connections"; PR #33464 adds network-dependent timers because a shared pattern makes it "trivial to confirm" that a clearnet node and an onion node are the same. Invs are sorted, not sent in arrival order |
| **Private broadcast, PR #29415** | **V, C** | **Merged 2026-01-12, shipped in Bitcoin Core v31.0** (`-privatebroadcast`). It sends one transaction per short-lived Tor/I2P connection. Advisory 2026-06-06: a v2→v1 handshake fallback **leaked the sender IP**; fixed in 31.1. **Lesson: fallbacks must fail closed.** (tm2-privacy's "30.x" is corrected to 31.0) |
| PR #18991 | V | Per-network cached GETADDR answers |
| -proxyrandomize, -onlynet, doc/tor.md | **V** | Default true: "This enables Tor stream isolation"; tor.md advises against exposing a node on multiple networks "if you require unlinkability" |
| BIP 324 | **V** | Uses ElligatorSwift because plain point encodings are distinguishable; concedes that "traffic analysis … can still reveal that the Bitcoin v2 P2P protocol is in use" |
| Tor IsolateSOCKSAuth | V | Default on; isolates by credentials |
| Loopix, USENIX Security 2017 | V | — |
| Fanti–Viswanath; Koshy et al.; Cao et al.; TxProbe; Clover; Bogatyy (403); Zcash/Grin/Firo | U / V-meta | not used for decisions |

### 8.5 Topic 5 (FRI)

| Citation | Status | Finding |
|---|---|---|
| BCIKS20 (ePrint 2020/654) | **V** | Theorem 1.2: UD error n/q; Johnson error O(n²/q); Conjecture 8.4 is the capacity conjecture |
| ethSTARK (ePrint 2021/582, rev. 2025-06) | **V** | Conjecture 1 and eq. (19) λ = min{ϑ + R·s, log2 abs(K)} − 1; a proven alternative is in §5.10.2. Plonky3's `conjectured_soundness_bits()` would give 3·108 + 16 = 340 "bits" for BlackSilk, meaningless as a proof |
| Block et al., ASIACRYPT 2023 (ePrint 2023/1071) | **V, C** | RBR soundness, Theorems 4.1/4.2; FS in the ROM: ε_fs = Q·ε_rbr + 3(Q²+1)/2^λ. **Correction:** they did not break deployed systems. They show Plonky2-style parameters have "large provable soundness errors", meeting their targets only under the aggressive conjecture, plus an FS loss in parallel-repetition variants. Their App. A.4 recommends fixing the adversary's hash budget Q |
| Haböck (ePrint 2022/1216) | V | Theorem 2 batched FRI |
| **2025 refutations** | **V** | **Diamond & Gruen, ePrint 2025/2010:** "proves that the capacity conjecture of [BCIKS] is false". **Crites & Stewart, ePrint 2025/2046:** disprove BCIKS CA up to capacity, WHIR's Conjecture 4.12, and DEEP-FRI list-decodability up to capacity. **Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, ePrint 2025/2055:** *improve* the proven UD and Johnson bounds (Theorems 1.3, 1.5) and refute n^c-bounded forms beyond Johnson. **The Johnson and unique-decoding regimes are unaffected, and improved.** Follow-ups: Haböck 2025/2110 (MCA to Johnson); Dao–Kominers–Thaler 2026/2056 |
| EF Proximity Prize; Goyal–Guruswami | U | — |
| DEEP-FRI (2019/336); LogUp (2022/1530); STIR (2024/390); WHIR (2024/1586) | V | **LogUp needs the field characteristic p > total multiplicities. This is a new check item for BabyBear (p ≈ 2^31)** |
| **Mixed-height FRI** | **V (absence)** | No published soundness theorem for roll-in batching. **Plonky3 GHSA-f69f-5fx9-w9r9 (2025-06):** roll-in without randomness was unsound. The dossier's "no published analysis" is correct and worth stressing. *Narrowed 2026-10-04 (decisions "BS-ZK-4"): a close peer-reviewed analogue exists, Zhang et al., USENIX Security 2024, Protocol 1 / Theorem 3.1 (rolling batch FRI, arity 2, unique decoding; the query term has no factor in the number of rolled-in polynomials). No theorem covers Plonky3's exact construction.* |
| Plonky3 advisories | **V, C** | GHSA-vrmm-4mm5-38vm (FS omission, PR #627); GHSA-m23j-cj9m-ppg9 (FRI size checks); GHSA-f69f-5fx9-w9r9 (roll-in); GHSA-3g92-f9ch-qjcm (PaddingFreeSponge, by Wagner, Khovratovich, Mennink); GHSA-vj64-rjf3-w3v7 / CVE-2026-46654 (MultiField32Challenger, p3-challenger < 0.4.3 / < 0.5.3). The earlier PR numbers #2100/#2106 and the SP1/RISC Zero/Frozen Heart identifiers are **U** |
| Plonky3 0.8.0 `p3-security` | V | Released 2026-09-23. Regimes: UniqueDecoding ("No conjectures", with ρ⁺ = (k + max_combo)/n, slightly worse than ρ), JohnsonBound, CapacityBound (unsupported for FRI). Its citation "[2024/1553]" is actually Atapoor et al. (a title mismatch) |
| Poseidon2 (ePrint 2023/323) | V | 2025–26 cryptanalysis papers are U (snippets only). No full-round Poseidon2 break was found |
| Khovratovich–Rothblum–Soukhanov (ePrint 2025/118) | V | A practical FS attack on GKR; ROM bits are heuristic |
| Chiesa–Manohar–Spooner (ePrint 2019/834) | V | — |
| **CKMW, ePrint 2026/089** (CCS 2026, "The Billion Dollar Merkle Tree") | **V, C** | Theorem 3: (4q² + 2q)/(abs(H) − 1) for the overwrite sponge **using the same permutation P** as the compression. Remark 2: if the leaf hash uses a different permutation (Plonky3's common width-24 leaf / width-16 compression), **Theorem 2 applies instead, at about 122.7 bits**. Remark 1 requires injective padding (cf. GHSA-3g92). **New check item:** confirm which theorem BlackSilk's leaf/compression configuration falls under. Either way the figure stays at about 122 bits |

### 8.6 Post-verification recommendations, and whether verification changed them

1. **DAA. Unchanged: accept under K1 for the testnet; reopen before mainnet.**
   Confidence medium-high.
   - Verification strengthens the reasoning: GKL show that dampening defeats Bahack only in
     the sense of exponential time, and Bahack himself says no exponential-rise mechanism
     is immune. A residual is therefore inherent, not a bug.
   - **Changed framing:**
     - (a) GKL is per epoch, so per-block LWMA has no proof (Ren Zhang: an open problem).
     - (b) Negy et al. find that DAA choice is nearly irrelevant to selfish mining for
       sliding-window DAAs. The selfish-mining risk is a fork-choice matter, consistent
       with RT-5.
     - (c) The Qubic evidence (18-block reorg; no sustained majority, yet bursts overwhelmed
       a 10-block lock) confirms that the dominant risk for a RandomX chain is
       burst-majority hash, which no DAA addresses. The mainnet item should evaluate
       Publish-or-Perish, rolling checkpoints or a finality layer (Monero #144/#135/#10064).
     - (d) New P2 check: Zawy #58's work-overestimation on variable-difficulty tips, and
       N=75 versus Zawy's N=90 recommendation (already evaluated by the harness).
2. **PX R rule. Unchanged and strengthened: IN, with canonical ristretto255 decoding and
   R ≠ identity.** Confidence high.
   - Zcash Orchard's consensus rule is the direct precedent (§4.6, P*). FIPS 203 confirms
     nothing else can be checked. RFC 9496 confirms the identity check must be separate.
   - Additions:
     - wallets treat every failure as "not mine" (Tramèr et al.);
     - the KDF keeps hashing the wire bytes (Zcash §4.20);
     - the combiner hardening (bind V and H(ek)) is supported by X-Wing and
       Cremers–Dax–Medinger, plus Schmieg showing ML-KEM alone is not MAL-BIND.
   - Factual corrections C1–C4 above.
3. **Decoys. Unchanged and strengthened. Confidence medium-high (raised from medium).**
   - Verified: Monero's wallet2 and the Feather incident show that remote-node distribution
     manipulation is real, so the local distribution is the right fix.
   - OSPEAD measures Monero's own gamma at an effective ring size of 4.2 out of 16.
   - FCMP++ exists because rings "enable statistical analysis", and it is not yet on
     mainnet.
   - Zcash shows that an optional pool leaks through round-trips (69.1% set reduction).
   - **New items:**
     - (a) A boundary test at exactly the 10-block spendable age and at the coinbase
       maturity, because off-by-one decoy bugs recurred three times (Monero 2021 and 2023,
       Wownero).
     - (b) Label 19.28/1.61 as "a pre-RingCT Monero fit, known to be mis-fit". Evaluate a
       partitioning sampler (Ronge et al.) as a lower-risk default for a chain with no
       spend data.
     - (c) Handle coinbase outputs in decoy selection (research-lab #109).
   - Long term: PX-default payments plus a v1 sunset after a shielded coinbase. The Zcash
     evidence says mandatory or default shielding is what makes a full-set pool effective.

4. **Relay. Unchanged direction, sharpened. Confidence medium-high.**
   - Verified: Sharma et al. (3 to 5 bits median entropy at 20% spies; graph learnable);
     D++ explicitly excludes ISP adversaries.
   - Bitcoin Core now has: network-key timers (PR #33464, 2025) against exactly the
     dual-homed linkage RT3-F6 found; per-network addr caches; stream isolation by
     default; and private broadcast (v31.0).
   - **New items:**
     - (a) the trickle timer must be per network class, not just shared (PR #33464);
     - (b) originated and relayed transactions must look identical on Tor (ProxyMark);
     - (c) any private-broadcast or Tor fallback must fail closed (the 31.0 advisory).
   - Docs must not quote Dandelion++ as strong protection.
5. **FRI. Unchanged: keep BS-ZK-3; the claim is honest in method (proven regimes, not
   conjectured).** Confidence medium-high.
   - Verified: the capacity conjecture is now **false** (2025/2010, 2025/2046), while the
     UD and Johnson regimes are proven and were improved (2025/2055). BlackSilk's refusal
     to size by conjecture was the right call.
   - **New check items:**
     - (a) Plonky3's UD regime uses ρ⁺ (the OOD degree), which lowers 89.7 slightly. Recompute
       with ρ⁺ before quoting 105.
     - (b) Mixed-height roll-in has no theorem, and an upstream bug (GHSA-f69f) occurred
       exactly there. Make it the top "unproven" item and confirm BS-ZK-3's 0.7 + patches
       include its fix.
     - (c) LogUp needs p > total multiplicities; add a bound check.
     - (d) Confirm whether CKMW Theorem 3 or Theorem 2 applies (same versus different leaf
       permutation); about 122 bits either way.
     - (e) Confirm the 0.7 challenger is not affected by CVE-2026-46654 (p3-challenger
       < 0.4.3 / < 0.5.3; 0.7 should be outside that range, but verify).
     - (f) Quote bits as log2(work/success) against a stated hash budget Q (Block et al.).

**Overall: verification changed no recommendation's direction.**
- Confidence for topic 3 rose from medium to medium-high.
- About fifteen factual attributions were corrected.
- New check items were added for each topic.
