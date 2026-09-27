# I2: Identity, credentials, disclosure and governance (innovation research)

**Reviewer:** I2, innovation researcher. Internal review, not an audit.
**Date:** 2026-09-27.
**Code read:** `rebuild/core` working tree (HEAD `9578517`, a descendant of `f677e55`). The files I relied on do not differ from `f677e55` in any way that matters here.
**Rules followed:** read-only, no builds, web research cited in §9.
**Inputs:** review-brief.md, R7-contracts.md (PX-only contracts), R11-wallet.md (PX key hierarchy, versioned seeds, authorization split).

**Evidence tags:**
- **[math]:** mathematically established.
- **[test: name]:** covered by the named test.
- **[src]:** read in the source.
- **[assumed]:** an estimate or assumption, not measured.
- **[unknown]:** not established either way.
- **[web]:** an external source, cited in §9.

---

## 0. Executive summary

1. **Build no identity system. Build privacy-preserving *statements* about PX state that users choose to make.**
   - Everything in this topic group reduces to two primitives that PX already almost has:
     - **(a) contract-held credential records**, used and advanced by functions;
     - **(b) an off-chain "snapshot statement"**: a stand-alone BVM-1 proof about one's own records at a public height.
   - With these two, and **no consensus change**, you get:
     - anonymous one-credential-one-vote governance;
     - coin-weighted polls without moving funds;
     - reserve (solvency) proofs;
     - anonymous credential shows with revocation.
   - Real systems validate the pattern:
     - Zcash's 2026 coinholder vote uses a "voting authority note" that each vote consumes and re-creates;
     - it also uses a sorted nullifier tree to prove a note was unspent at a snapshot [web].
2. **Most "classic" credential cryptography does not fit.** BBS+, CL, Coconut, homomorphic-ElGamal tallies and the scoped ring signatures in `crypto/src/membership.rs` all fail at least one of these:
   - they are not post-quantum (their anonymity or unlinkability rests on DL, DDH or pairings);
   - they add a pairing curve or RSA code base to the consensus or wallet supply chain;
   - they duplicate what the zkVM already expresses.
   I recommend none of them for core (§6).
3. **The one timing-critical item is a refinement of R11-W2 (I2-R1).** Make the PX delivery and diversifier roots **hierarchical, by index range**, before the public testnet. This gives:
   - **range-scoped (time-scoped) viewing keys**;
   - an **incoming-only viewing package without `nk`**.
   The package corrects R11's "IVK = FVK in this design" (see I2-F3). Like R11-W2, it changes seed→address derivation, so it must be decided now. It needs no consensus change and no new testnet identity.
4. **Security requirement for every future disclosure or voting program (I2-F2).** Ownership is visible from `(ak, nk, d)` alone, which is FVK material. Any program that proves "these records are mine" by recomputing owner tags, without proving knowledge of `sk`, therefore:
   - lets every auditor or watch-only server vote with, or claim reserves over, the user's funds;
   - must be rejected at design review.
5. **Capacity is the binding constraint on on-chain governance.** At about 3 PX transactions per block, on-chain voting tops out at about 2,000 votes per day at full PX capacity, and it displaces payments [math, from the brief's measurement]. Coin-weighted polls, credential shows and reserve proofs should therefore be **off-chain proofs against public snapshot roots**. Only actions with on-chain effects should be PX transactions.
6. **Protocol governance: do not add on-chain governance of the protocol** (coin votes or miner votes that change rules). Keep:
   - activation heights shipped in reviewed releases (R7's kernel-id schedule);
   - optional, non-binding private coinholder polls built on item 1.
7. **Coercion resistance and receipt-freeness (MACI-style voting) are not achievable** under the project's constraints (no trusted coordinator, post-quantum, pure Rust, zkVM cycle limits) without XL research. State plainly that BlackSilk voting would be **anonymous but not receipt-free**.

**Before the testnet:**
- the I2-R1 decision (P0 decision, P1 implementation);
- documentation items (P1).

Nothing in this report needs a consensus change before the testnet. R7-1 (validity windows, already in R7's v3 bundle) is the only consensus item that credential expiry and on-chain deadlines depend on.

---

## 1. What exists today

| Item | Status | Evidence |
|---|---|---|
| Scoped linkable ring signature (bLSAG with a per-scope tag base), ring 1–16, Ristretto | Complete and verified as a primitive; **no consumer** (R7-10) | [src] crypto/src/membership.rs:1-220; [test: `signs_and_verifies_for_every_size_and_index`, `tags_link_within_a_scope_only`, `framing_with_another_members_tag_fails`, `outsiders_cannot_sign`] |
| Confidential claims (range, equality, reveal) over Pedersen commitments | Complete; no consumer; Ristretto only | [src] crypto/src/claims.rs:1-45 |
| Contract records (`owner = 0`) whose nullifier depends only on the opening | Complete and verified | [src] px-core/src/record.rs:102-112; kernel.rs:323-325 |
| Functions approve records of their own contract and specify outputs; `io_hash` binding | Complete and verified | [src] call.rs:53-80; kernel.rs:308-377 |
| Function public outputs: up to 256 words, uninterpreted by consensus | Complete (R7-8 leak channel) | [src] tx/src/params.rs:33 |
| Sharing a record opening sealed to a PX address | Complete, for **contract records** only | [src] px/src/share.rs; wallet.rs:1640-1673 (`px_import` refuses user records) |
| v1 view key (`k_v`), incoming only | Crypto layer only (R11-W15) | [src] crypto/src/keys.rs; docs/transactions.md §11.5 |
| PX viewing keys, auditor keys, payment proofs, reserve proofs | **Not implemented** | docs/zk.md:869-873 lists them as open design questions |
| Private voting, credentials, governance | **Not implemented** (contracts.md examples were Wasm-only and are out of scope under R7) | [src] docs/contracts.md:1037 |
| Protocol governance or signalling | None. One valid header version | [src] consensus/src/header.rs:8-13 |

---

## 2. New findings

### I2-F1: contract-record credentials are traceable by their creator until the holder re-keys them

- **Severity:** medium (privacy design; it governs every credential and voting design).
- **Classification:** accepted limitation of the record model; an SDK pattern is needed.
- **Where:**
  - `px-core/src/record.rs:102-112`: the contract nullifier is `Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`;
  - `kernel.rs:338-353`: the caller supplies output `rcm`;
  - PX-F4.
- **Scenario:**
  1. An issuer runs the issuance function and creates the credential record, so it knows `(cm, rcm)`.
  2. It can compute the record's nullifier.
  3. It therefore sees exactly when the credential is first used, and links that use (for example a vote) to the person it issued the credential to.
  - The record.rs comment already says that "every holder of the opening sees when the record is consumed". The consequence for credentials is new: **an issued credential gives zero anonymity on first use.**
- **Mitigation (SDK, no consensus change):**
  1. The holder gives the issuer only `C_h = Hk(HOLDER, holder_secret)`. The credential's `data` holds `C_h` and the attributes.
  2. The holder then runs a **refresh** function: it consumes the issued record and specifies an identical record, with a holder-chosen `rcm` and knowledge of `holder_secret` proven inside the function.
  3. After the refresh, only the holder knows the opening.
  4. The refresh itself is linkable to the issuance by timing. So issuers should issue in batches, and holders should refresh after a random delay. The anonymity set is then the set of credentials refreshed in the same window.
- **PX-F4 interaction:** if PX-F4 option B moves `rcm` into the function, the function must take `rcm` from the prover's private input, not derive it from public data. Otherwise the re-key is impossible. This is a design constraint for the PX-F4 decision.
- **Confidence:** high [src].

### I2-F2: owner tags are FVK-derivable, so an ownership check without `sk` hands spend-equivalent powers to viewing-key holders

- **Severity:** medium (a latent design hazard for future programs; nothing today is affected).
- **Classification:** not implemented (a design requirement).
- **Where:**
  - `record.rs:33-36`: `owner = Hk(OWNER, ak ‖ nk ‖ d)`;
  - R11-W2: FVK = `(ak, nk, dk, ivk_root)`.
- **Scenario:** a future snapshot or voting program proves "record `r` is mine" by recomputing `owner` from `(ak, nk, d)`, and derives a vote or reserve tag from `nk`. Then anyone holding the FVK can:
  - an auditor or a self-hosted light-wallet server can cast the user's coin-weighted vote first, and the user's own vote is refused as a duplicate tag;
  - a custodian can claim the user's records in its own reserve proof.
- **The kernel is safe:** it derives `nk` and `ak` from `sk` (kernel.rs:273-274).
- **Requirement:** every statement program that confers authority (votes, reserve claims, credential shows) must, like the kernel:
  - take `sk` as a witness;
  - derive `ak` and `nk` from it.
  Purely informational programs (a payment disclosure) may use FVK material.
- **Consequence for R11-W4 (authorization split):** a future authorization key must be the one these programs check.
- **Confidence:** high [math: owner and tags are functions of FVK material only].

### I2-F3: correction to R11-W2: an incoming-only PX viewing capability without `nk` is possible wallet-side

- **Severity:** info (it improves a P0 decision).
- **Classification:** not implemented.
- **Where:** delivery.rs:189-246. `open` needs only the delivery keys and the address's **owner tag**; it recomputes `cm` with that tag.
- **Argument:**
  - R11 says IVK = FVK because deriving `owner` needs `nk`.
  - But detection never needs `nk`: it needs the owner tags, which can be **exported as a list** for a finite range of indices (32 bytes per address).
  - An incoming-only package `(delivery range root, [owner_i for i in range])` therefore detects and decrypts every incoming record of the range.
  - It cannot compute nullifiers, so spends stay invisible.
  - It is enumerated, not derivable: new addresses need a new export. That is acceptable for audits.
- **Confidence:** high [src + math, under the PRF assumption of `Hk`].

### I2-F4: scoped-membership anonymity is classical only (harvest-now, deanonymize-later)

- **Severity:** low today (no consumer); medium if it is ever used for voting.
- **Classification:** accepted limitation, undocumented.
- **Where:** membership.rs:16-23 claims anonymity under DDH.
- **Scenario:**
  1. A DL-capable adversary computes every ring member's `x_i` from `P_i = x_i·G`.
  2. It checks `x_i·B == I` and names the voter.
  - The chain is permanent, so every past vote becomes attributable.
  - The ring is capped at 16, so large electorates get 1-of-16 anonymity.
  - PX nullifier-style tags are hash-based and survive this [math; conditional on statistical ZK, zk-coverage.md].
- **Recommendation:** document it in membership.rs and contracts.md, and never build voting on it. At most, use it off-chain for committees of 16 or fewer members, where the ring is the whole set and classical anonymity is accepted.
- **Consensus:** none. **Priority:** P2 (docs).
- **Confidence:** high [math].

### I2-F5: a contract id is derived from the deployer's first key image

- **Severity:** low.
- **Classification:** accepted limitation.
- **Where:** tx/src/px.rs:565-572.
- **Scenario:**
  - A DAO, credential issuer or voting contract is permanently tied to its deploy transaction's v1 ring (1-of-16) and to the funds that paid for it.
  - Deployers who want to stay anonymous must deploy from funds with no history.
  - This matters for "issuer-anonymous" communities and for organizers under pressure.
- **Recommendation:** add a wallet warning and a documentation note.
- **Consensus:** none. **Priority:** P3.
- **Confidence:** high [src].

### I2-F6: capacity bounds on-chain governance and credential use

- **Severity:** medium (scalability).
- **Classification:** accepted limitation.
- **Arithmetic** [math from the brief's measurements]:
  - About 3 PX transactions per 8 MiB block × 720 blocks per day gives about 2,160 PX transactions per day chain-wide.
  - Each vote carries a function, so it costs about 2.7 MB, about 53 s of proving and 0.089 BLK.
  - An election of 10,000 voters therefore occupies all PX capacity for about 4.6 days.
- **Recommendation:**
  - Use on-chain votes only where the vote must move value or state.
  - Use off-chain snapshot proofs (§4.2) for polls and shows.

### I2-F7: there is no committed nullifier accumulator, and naive reserve proofs leak future spend times

- **Severity:** info (it shapes the design).
- **Classification:** not implemented.
- **Where:** px/src/state.rs:43 holds nullifiers in a `HashSet`; nothing commits to them in a header.
- **Consequence:**
  - A Monero-style reserve proof would reveal each record's real nullifier, so the verifier later sees exactly when each record is spent.
  - The private alternative proves non-membership against a **sorted gap tree** of the nullifier set at height H.
  - Anyone can rebuild that tree deterministically from the chain, so it needs **no consensus change**, only a precise specification.
  - Zcash's 2026 coinholder vote uses exactly this ("a sorted Merkle tree of all used nullifiers at the snapshot height") [web].

### I2-F8: functions cannot see user records, so coin-weighted on-chain voting requires locking value into contract records

- **Severity:** info.
- **Classification:** accepted limitation.
- **Where:** kernel.rs:308-321: functions approve only their own contract's records.
- **Consequence:** an on-chain coin vote needs a "voting escrow". The published vote weight is then a leak of the locked amount, which should be bucketed. Off-chain snapshot polls (§4.2) avoid both problems.

### I2-F9: payment proofs cannot reuse the share format for user records (deepens R11-W11)

- **Severity:** low.
- **Classification:** not implemented.
- **Where:** delivery.rs:229-245. For a user record, `open` substitutes the **opener's own** owner tag, so an opening shared with a verifier fails the commitment check.
- **Consequence:** a payment proof needs its own format that carries the recipient address's owner tag (§4.3).
- **Nature of the proof:** such a proof is **transferable and non-deniable**. The opening verifies against a public `cm` forever. Users must be told that a payment proof is permanent evidence.

---

## 3. Answers to the 13 questions, per area

### 3.1 Viewing keys and compliance by choice (PX)

| # | Answer |
|---|---|
| 1 Implemented | v1 incoming view key (crypto layer only); PX contract-record share. |
| 2 Correct | Janus-style acceptance in `open`; shares bound to `cm` through the AEAD's associated data; per-address independent delivery keys (unlinkable addresses, even post-quantum apart from R11-W5). |
| 3 Incomplete | No PX viewing key (R11-W2), no disclosure formats. |
| 4 Fragile | Ad hoc disclosure (sharing `sk`) is the only option today, and it hands over spend authority. |
| 5 Exploitable | I2-F2 for future programs. |
| 6 Inefficient | — |
| 7 Does not scale | Per-address scanning (inherent, R11 §5.1). |
| 8 Missing | Range-scoped keys, incoming-only package, payment proofs, reserve proofs. |
| 9 Redesign | Hierarchical delivery and diversifier derivation (I2-R1). |
| 10 Innovate | Range-scoped viewing, a reserve-tag scheme resistant to double counting (§4.4). |
| 11 Before the testnet | The I2-R1 decision. |
| 12 Defer | Reserve proofs; the snapshot program. |
| 13 Never change | No mandatory or escrowed viewing (no protocol auditor ciphertext); disclosure stays the user's choice. |

### 3.2 Credentials and identity

| # | Answer |
|---|---|
| 1 Implemented | Nothing specific; contract records plus functions suffice as a substrate. |
| 2 Correct | Hash-based records; the fixed shape; `h_tx` binding (prove.rs:11). |
| 3 Incomplete | SDK and manifest (R7 §7.2); validity windows (R7-1) for expiry. |
| 4 Fragile | I2-F1 (issuer traceability); R7-8 (a function can leak attributes through public outputs). |
| 5 Exploitable | A credential verifier that checks only the program id, not the **contract id**, accepts credentials from an attacker's re-deployment of the same ELF. The contract id cannot be embedded in the program, because it is derived from the deploy payload (px.rs:566). So verifiers must pin the contract id. [src] |
| 6 Inefficient | About 50 s and 2.7 MB per on-chain show. |
| 7 Does not scale | I2-F6. |
| 8 Missing | Revocation; off-chain shows; issuer signatures for off-chain issuance. |
| 9 Redesign | — |
| 10 Innovate | §4.1 and §4.2. |
| 11 Before the testnet | Nothing. |
| 12 Defer | Everything (P3). |
| 13 Never change | Do not import real-world identity into the protocol. |

### 3.3 Governance and voting

| # | Answer |
|---|---|
| 1 Implemented | Only the unused scoped ring signature. |
| 2 Correct | Its tests cover linkability, framing and scope binding. |
| 3 Incomplete | No voting program or tally tool. |
| 4 Fragile | I2-F4; MEM-1 (the prover chooses the scope) carries over to any tag scheme. |
| 5 Exploitable | Vote buying (not receipt-free); I2-F2 (an FVK holder votes). |
| 6 Inefficient | The per-vote cost on chain. |
| 7 Does not scale | I2-F6. |
| 8 Missing | Snapshot tooling; the gap-tree specification. |
| 9 Redesign | — |
| 10 Innovate | Credential-state voting with no consensus change (§4.1); snapshot polls (§4.2). |
| 11 Before the testnet | Only the governance statement in the documentation (P1). |
| 12 Defer | All voting implementations. |
| 13 Never change | No on-chain protocol governance; no trusted coordinator or TEE in consensus. |

---

## 4. Recommended designs

### 4.1 Credential records and one-credential-one-vote, with no consensus change (P3)

**Credential.** A contract record of credential contract `C`:
`data = [C_h (as a digest) | attrs_hash | state]`, where
- `C_h = Hk(HOLDER, holder_secret)`;
- `state` is a small bitmap or counter packed into 8 words, with 248 usable bits (record.rs:57).

**Functions:**
- **issue:** the issuer proves knowledge of the issuer secret committed in the ELF, and specifies the credential. Batch issuance is recommended (I2-F1).
- **refresh:** the holder proves `holder_secret` and re-creates the credential with its own `rcm`.
- **vote(p, choice):**
  1. The holder proves `holder_secret`.
  2. The function checks that `state` has not voted on proposal `p`: bit `p mod 248` within a proposal window, or `last_p < p` for sequential proposals.
  3. It specifies the credential with the updated state.
  4. It publishes `(p, choice)` as public output words.
- The **fee record** is the second kernel input, and change is the second output. Everything fits the 2×2 shape: inputs = credential and fee record; outputs = new credential and change; `bridge_out` = fee (tx/src/px.rs:16-20, 690).

**Double-vote prevention:** the consumed credential's nullifier (a consensus rule that already exists) plus the state update. No per-contract tag set is needed [math: a vote requires consuming the unique live credential, whose successor records the vote].

**Tally:**
- Anyone recomputes it from the chain: sum the public outputs of the transactions that called `(C, vote program)` between two heights.
- The proof, bound to `h_tx`, makes those outputs authentic.
- The deadline is a height range applied by the tally, so R7-1 is not needed for this.

**Properties:**
- Voter anonymity among all live credentials of `C` after refresh.
- Post-quantum under `Hk`, given the statistical-ZK conditions.
- Choices are public: anonymous, not secret-ballot, not receipt-free.

**Revocation:** the holder gives the issuer `rh = Hk(REVOKE, holder_secret)` at issuance. Revocation is then a published list of `rh`, and the vote or show proves `rh ∉` the list. This needs the gap-tree machinery of §4.2, or a contract-held revocation root.

**Cost:** one function (about +0.5 MB and +9 s, R7 table) on top of a transfer [measured baseline; per-function cost from R7].

**Compared with R7's "contract-scoped tags":**
- Tags avoid consuming a credential and allow many concurrent scopes.
- They need a consensus-kept per-contract tag set (CONSENSUS, state growth).
- The credential-state pattern needs nothing new.
- Recommendation: prefer credential state; keep tags as a P3 option only if a measured use case needs concurrent scopes beyond 248.

**Recommendation details:**
- **Security:** sound under existing kernel rules [src]. MEM-1 carries over: the program must fix which proposals are valid; typically proposal ids are committed in a contract config record.
- **Privacy:** positive.
- **Consensus:** none.
- **Identity:** none.
- **Difficulty:** M, after the SDK.
- **Priority:** P3.

### 4.2 Off-chain snapshot statements: one program family for polls, shows and reserves (P3; the highest-value innovation here)

**The statement.** A stand-alone BVM-1 program, proven with the existing prover (no transaction, no fee, no block space):

> At height `H`, with commitment root `A_H` and nullifier gap-tree root `N_H` (both recomputable by anyone from the chain), I know `sk` and records `r_1..r_k`, with `k` padded to a fixed `K`, such that:
> - each record is mine (owner derived from `sk`, I2-F2);
> - each record is in `A_H`;
> - each record's real nullifier lies in a gap of `N_H` (unspent at `H`);
>
> and I output public tags `t_j = Hk(TAG_domain, nk ‖ rho_j ‖ scope)` together with a statement-specific public value.

**Instances:**
- **Coin-weighted poll:**
  - public value = `(scope, choice, weight bucket)`;
  - one tag per record prevents double counting;
  - the tags are unlinkable to real nullifiers (a different domain, PRF);
  - bucketed weights, or Zcash's 16-way splitting [web], limit amount fingerprinting.
- **Reserve proof:**
  - public value = `Σ value ≥ X`, plus a verifier challenge;
  - **reserve tags**, with scope = the audit epoch, stop two custodians from counting the same records in one epoch (the "borrowed reserves" attack);
  - no real nullifier is revealed (fixes I2-F7);
  - limitation: it proves control at `H` only.
- **Credential show:** it proves a live credential record of contract `C` whose attributes satisfy a predicate (for example age ≥ 18), with a per-verifier pseudonym `Hk(PSEUDO, holder_secret ‖ verifier_scope)`. This is the PX analogue of BBS per-verifier linkability [web].

**Missing pieces:**
- **(a)** A specification of the gap tree: sorted nullifiers with sentinels, depth 32, the `Hk` node hash, and an exact snapshot height rule.
- **(b)** A statement program and a verifier tool. Every verifier must pin the program id.
- **(c)** Fixed `K` and padding for shape privacy.
- **(d)** An owner-authority check using `sk` (I2-F2).

**Cost** [assumed]:
- proving similar to a transfer (about 45 s; about 2 MB proof; about 0.2 s verification);
- the gap tree is 32 bytes × 2 per PX transaction of history, which is small today.

**Why this over on-chain voting:**
- no capacity cost (I2-F6);
- no need to move funds (I2-F8);
- anyone verifies with public data.
- Validated in production by Zcash's 2026 vote, which also needed PIR only because Orchard's nullifier set is about 2 GB [web]. BlackSilk wallets already download everything (R11).

**Recommendation details:**
- **Security:** it needs its own review of tag domains and the gap-tree soundness (sentinels, duplicates).
- **Consensus:** none.
- **Identity:** none.
- **Difficulty:** L.
- **Priority:** P3. Specify the gap tree early (P2) so that tools agree.

### 4.3 PX payment disclosure (P2, wallet-only)

**Format:**

```text
version ‖ tx_id ‖ output index j ‖ recipient owner tag ‖ contract ‖ value ‖ data ‖ rcm
```

**Verifier steps:**
1. Recompute `rho = Hk(RHO, nf_0 ‖ j)` from the transaction.
2. Recompute `cm` and check that it equals the transaction's output `j`.
3. Check that the owner tag equals the tag inside the claimed recipient's PX address.

**Who can produce it:** the sender, if it stored the opening (R11-W11), or the recipient.

**Delivery:** optionally sealed to the verifier's PX address (delivery.rs) for confidentiality in transit.

**Disclose:**
- the proof is **permanent and transferable** (I2-F9);
- it reveals neither spends nor other records (no `nk`) [math].

**Recommendation details:**
- **Security:** neutral.
- **Privacy:** user-chosen.
- **Consensus:** none.
- **Identity:** none.
- **Difficulty:** S–M.
- **Priority:** P2.

### 4.4 I2-R1: hierarchical, range-scoped PX key derivation (P0 decision, P1 implementation)

This extends R11-W2. The kernel is unchanged, because `d` is a free witness (kernel.rs:266) [src].

```text
sk                               spend authority (unchanged)
ak = Hk(AK, sk), nk = Hk(NK, sk) unchanged
dk      = H("px/div-key", sk)
ivk     = H("px/ivk", sk)
range k = index >> 16  (or an explicit account/epoch number; internal change branch per R11-W14)
dk_k    = H("px/div-range",  dk  ‖ k)       d_i  = Hk(DIVERSIFIER', dk_k ‖ i)
ivk_k   = H("px/ivk-range",  ivk ‖ k)       (v_i, kem_seed_i) = H(ivk_k ‖ i)
```

**Disclosure levels:**

| Level | Contents | Reveals |
|---|---|---|
| Incoming-only, range `k` (I2-F3) | `(ivk_k, [owner_i]_{i in k})` | Receipts in range `k`. No spends, no other ranges |
| Full, range `k` | `(ak, nk, dk_k, ivk_k)` | Receipts **and spends** in range `k`. `nk` yields nullifiers only for records the holder can open [math] |
| Full, wallet | `(ak, nk, dk, ivk)` | Everything (R11's FVK) |

**Policy:** wallets allocate one range per period (for example a quarter), so **a range is a time scope**. A full range view must include the internal change branch of that range; otherwise spends look like losses.

**Recommendation details:**
- **Why now:** it changes seed→address derivation (as R11-W2 does), so it must be decided with R11-W2 and R11-W3 before the public testnet.
- **Security:** neutral for spending (preimage assumption on `Hk`).
- **Privacy:** strongly positive (least-privilege disclosure).
- **Performance:** none. Scanning is unchanged.
- **Complexity:** low beyond R11-W2.
- **Consensus:** none. **Identity:** none (addresses change; the v3 reset makes that free).
- **Difficulty:** S on top of R11-W2.
- **Priority:** **P0 decision**; P1 implementation.

### 4.5 Dapps without identity leakage (P2–P3, wallet or SDK)

- **Per-dapp login keys:**
  - derive a domain-scoped key `H("blacksilk/login", seed-key ‖ domain)`;
  - use it for sign-in with a Schnorr signature (classical, which is acceptable for authentication), or with ML-DSA if post-quantum authentication is wanted (RustCrypto `ml-dsa`, pure Rust, to be reviewed);
  - never use a PX address as a login identity;
  - PX addresses have no signing key, and proving `sk` off-chain costs a 45 s proof.
  - None. P3.
- **Per-counterparty PX addresses** (existing guidance, px.md §12), plus a wallet feature: "new address per dapp", labelled.
- **Contract manifests** with a declared public-output schema, and wallet refusal of undeclared outputs (R7-8). This is the main dapp leak control. P2.
- **No public events;** encrypted "events" through delivery (R7 §7.1).
- **Minimum anonymity set warning:** the wallet shows the number of live credentials or records of a contract before a show or vote (I2-F1, P-8). P3.

### 4.6 Sybil resistance without identity

| Option | Fit | Verdict |
|---|---|---|
| Coin weight (snapshot polls, §4.2) | Sybil-proof by construction; plutocratic | **Use for coinholder polls**, labelled as such |
| Locked value or burn to mint a credential (a contract record holding value; needs R7-1 for time locks) | Cost-based, private | Acceptable per application; P3 |
| RandomX hashcash per credential | Botnets and cloud defeat it; its only use is rate limiting | Anti-spam only; not personhood |
| Issuer-agnostic credentials (a community, meet-up or "pseudonym party" issuer through §4.1) | Moves trust to issuers explicitly | **The platform stays issuer-agnostic**; ship a template, not an identity provider |
| Existing ID (passport or e-ID signature inside the zkVM, zk-creds style [web]) | ECDSA P-256 or RSA verification without bigint precompiles in BVM-1 is likely beyond `MAX_CYCLES = 2^21` for ECDSA [assumed] | Research only; never in core |
| Social graph (BrightID-like) or biometrics (World ID) | Publishes graphs or collects biometrics | **Reject** |

Network-layer Sybil resistance (eclipse attacks, N-7/N-8) belongs to R8 and is not addressed here.

---

## 5. Protocol governance

**Recommendation.**
- **No on-chain protocol governance:** no coin vote or miner vote that changes consensus.
- **Reasons:**
  - it hands rule changes to capital or to hashpower pools;
  - vote weights leak amounts;
  - it adds a consensus mechanism with no privacy benefit.
- **What to use instead:**
  - activation heights in reviewed releases, through R7's `kernel_id(height)` schedule;
  - the owner's approval process;
  - optional non-binding private coinholder polls (§4.2) as a signal.
- **Miner signalling (BIP9-style version bits):**
  - it reveals nothing about users, but gives pools agenda power;
  - not recommended for v1;
  - the single header version (header.rs:8) is fine.
- **Recommendation details:**
  - **Consensus:** none.
  - **Priority:** P1 documentation ("how BlackSilk upgrades").

**Coercion resistance and MACI.**
- **MACI's properties:**
  - its receipt-freeness and collusion resistance rest on a **trusted coordinator** who can decrypt every vote [web];
  - it needs in-circuit ECDH and encryption.
- **Threshold-committee variants** (Zcash 2026: DKG, homomorphic shares, 2/3 of validators) replace the coordinator with a committee and classical homomorphic encryption [web]. This is not post-quantum, and it needs a committee that a PoW chain does not have.
- **JCJ and VoteAgain-style designs** need registrars and anonymous channels.
- **Verdict:**
  - reject for core;
  - P3 research only;
  - document "anonymous, publicly tallied, not receipt-free: vote buying is possible".

---

## 6. Rejected ideas

| Idea | Reason |
|---|---|
| **BBS/BBS+** in consensus or the wallet core | Pairings on BLS12-381, a new curve dependency; anonymity is DL-based (not post-quantum); duplicates §4.2. The IRTF draft is still a draft (-10) [web]. An application may use it off-chain; the project should not ship it |
| **CL signatures** | RSA and strong-RSA assumptions; large, slow and not post-quantum. The main Rust implementation lineage (Hyperledger Ursa) is archived [assumed] |
| **Coconut / threshold issuance** | Pairings, not post-quantum; needs an authority committee |
| **Lattice anonymous credentials** | Promising and post-quantum, and active research (2025–2026 papers) [web]. But there is no mature, reviewed pure-Rust implementation. Revisit after mainnet; §4.2 already gives post-quantum credentials under `Hk` |
| **Scoped ring signatures for voting** (membership.rs) | I2-F4: classical, capped at 1-of-16, and Wasm-only. Keep behind a feature (R7-10) |
| **Homomorphic-ElGamal tallies with DKG** | Classical and committee-based; see §5 |
| **Mandatory auditor or escrow viewing ciphertexts** | A backdoor by design; it violates privacy-first. An *optional* per-output auditor ciphertext changes the fixed ciphertext length (CONSENSUS), and its presence would fingerprint unless every transaction carried one |
| **Privacy Pools / association-set proofs at kernel level** | PX does not track record lineage, so this needs a kernel redesign. It also creates "clean/dirty" tiers that damage fungibility and anonymity sets [web, Privacy Pools paper]. Not recommended |
| **TEE-based coordinators or provers** | "No trusted hardware" (R7 §9; the SGX.fail history) |
| **Biometric or social-graph personhood** | Collects or publishes identity data |
| **On-chain protocol governance** | §5 |

---

## 7. Priorities

| ID | Item | Consensus | Identity | Diff. | Priority |
|---|---|---|---|---|---|
| I2-R1 | Hierarchical range-scoped delivery and diversifier roots; incoming-only package | none | none (derivation change, pre-v3) | S (on top of R11-W2) | **P0 decision / P1 impl.** |
| — | Docs: governance statement; "voting is not receipt-free"; I2-F4 caveat; I2-F9 permanence; "verifiers pin the contract id" | none | none | S | P1 |
| — | PX-F4 option B must keep a private-input `rcm` possible (I2-F1) | (part of the v3 kernel bundle) | v3 | — | P1 (a design constraint) |
| §4.3 | PX payment-disclosure format and tool | none | none | S–M | P2 |
| §4.2a | Nullifier gap-tree specification | none | none | S | P2 |
| I2-F2 | Rule: authority-conferring programs must derive keys from `sk` | none | none | S (design rule) | P2 |
| §4.1 | Credential and voting contract templates (after the SDK) | none | none | M | P3 |
| §4.2 | Snapshot statement program (polls, reserves, shows) | none | none | L | P3 |
| §4.5 | Per-dapp login keys; anonymity-set warnings | none | none | S–M | P3 |
| — | Contract-scoped tags (R7) | CONSENSUS | activation height | M | P3, only with evidence |
| — | Coercion-resistant voting; lattice credentials | — | — | XL | Research |

**Before the testnet:** I2-R1 decided, and the P1 documentation.
**Safely deferred:** all programs and templates.
**Never change:**
- the atomic, per-record nullifier model;
- hash-based ownership;
- per-address independent delivery keys;
- no mandatory viewing;
- no trusted hardware or coordinator in consensus.

---

## 8. Evidence summary and confidence

- **Code facts:** [src], high confidence.
- **Soundness of the credential-state voting (§4.1) and of the tag unlinkability:** [math] under the PRF and collision assumptions of `Hk` and the kernel's existing rules.
- **Not implemented, not tested:**
  - none of the designs in §4 is implemented or tested;
  - the proving costs of the stand-alone programs are [assumed];
  - the BVM-1 cycle cost of ECDSA and RSA is [unknown or assumed].
- **External facts:** as of the pages retrieved on 2026-09-27. The Zcash voting details come from its public design description [web] and were not verified in code.

---

## 9. Sources

**Repository** (source-read):
- crypto/src/membership.rs, claims.rs, schnorr.rs;
- px-core/src/kernel.rs, record.rs, call.rs;
- px/src/delivery.rs, share.rs, state.rs, prove.rs;
- tx/src/px.rs, params.rs;
- consensus/src/header.rs;
- chain/src/address.rs;
- wallet/src/wallet.rs:1640-1673;
- docs/px.md §12, zk.md §4 and :869-873, contracts.md, reviews/contracts-crypto-review.md §3, privacy-review.md (P-8).

**External:**
- Zcash NU7 coinholder vote (snapshot, voting window): https://zcashlabs.org/voting ; https://forum.zcashcommunity.com/t/nu7-coinholder-vote/56912
- Zcash coinholder voting chain design (VAN, sorted nullifier tree, PIR, DKG threshold tally, limitations): https://forum.zcashcommunity.com/t/the-coinholder-voting-chain/56925
- hhanh00 coin voting: https://hhanh00.github.io/coin-voting-book/proposal/details.html ; https://github.com/hhanh00/zcash-vote-app/releases
- Penumbra governance (per-proposal nullifier sets; roll-over of delegation notes): https://protocol.penumbra.zone/main/governance.html
- MACI (trusted coordinator, receipt-freeness): https://maci.pse.dev/docs/introduction ; https://github.com/privacy-scaling-explorations/maci
- BBS signatures IRTF draft (-10) and per-verifier linkability: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ ; https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/ ; blind BBS: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html
- zk-creds (Rosenberg, White, Garman, Miers, IEEE S&P 2023): https://eprint.iacr.org/2022/878
- Lattice anonymous credentials: https://eprint.iacr.org/2022/509 ; https://eprint.iacr.org/2026/1920 ; revocation accumulator https://eprint.iacr.org/2025/1099 ; post-quantum Privacy Pass https://eprint.iacr.org/2023/414.pdf

**From my own knowledge, not re-fetched in this session** (verify before external quotation):
- Coconut (Sonnino et al., NDSS 2019, arXiv:1802.07344);
- Camenisch–Lysyanskaya signatures (2001/2004);
- Hyperledger Ursa archival;
- Juels–Catalano–Jakobsson coercion-resistant voting (ePrint 2002/165);
- VoteAgain (Lueks, Querejeta-Azurmendi, Troncoso, USENIX Security 2020);
- Privacy Pools (Buterin, Illum, Nadler, Schär, Soleimani, 2023, SSRN 4563364);
- Semaphore (PSE);
- Monero reserve proofs revealing key images.
