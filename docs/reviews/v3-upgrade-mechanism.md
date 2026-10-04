# v3 candidate: upgrade mechanism and deploy rules

> Historical record (2026-09-27). Superseded where it conflicts with the code: the v3 candidate was merged into `rebuild/core` in 9e422d8, so the status below ("Not merged") no longer holds. Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

Status: **candidate for the testnet v3 identity (branch `v3a-candidate`). Not merged
into `rebuild/core` and not active on any network until the owner reviews it.**
This is internal engineering work, not an audit. The v2 genesis constants are
unchanged, and no v3 genesis is created here.

Sources: R16-1 and R16-15 (architecture), I4 §7.1 (F1, F2), R1-C10, R5-1, R5-7,
R6 TX-4 and §3.3, R7-5, and the SX1 cross-review. Process: analysis (§1), proposal
(§2), tests (§3), implementation (§4). Items 2 to 4 are in §5 to §7.

Every item is a separate commit so that the owner can drop any of them.

---

## 1. Analysis: why an upgrade mechanism, and why now

**Today (v2):**
- Rules are compiled in with no notion of height. `HeaderChain::check_rules`
  requires `header.version == HEADER_VERSION`.
- A header with any other version is `BadVersion`: permanent, scored as an invalid
  header (100 points) by P2P, so the peer is banned at once.
- Consequently, every consensus change needs a new genesis (R16-1). After the first
  change, un-upgraded nodes would ban every upgraded peer, which speeds up the split
  and gives operators no "upgrade required" signal (R1-C10).

**What it costs to add now.** The signature messages and the PX binding `h_tx`
already hash `network_id` (`tx/src/types.rs`, `tx/src/px.rs`). A branch id is 4 more
fixed-width bytes in the same place. `h_tx` is a **public input** of the PX proof, so
no kernel or function program changes.

**Checked in the source, not assumed (px, px-core, zkvm):**
- `zkvm/src/air/trace.rs::public_values` puts `st.binding` into each execution's CPU
  public values as 16 little-endian 16-bit limbs.
- `zkvm/src/air/cpu.rs` (`pv::BINDING`) documents these limbs as "absorbed in the
  transcript, not otherwise constrained". So the binding reaches Fiat–Shamir and does
  not enter any guest's input.
- `px/src/prove.rs::statement` passes `h_tx` to `Statement::single` and to nothing
  else.
- `px-core` never sees `h_tx`; `grep binding|h_tx px-core/src` finds nothing.

So changing how `h_tx` is computed changes every PX proof, as intended (a proof
made for one branch fails on another), and leaves `KERNEL_PROGRAM_ID`, the vault id
and the circuit unchanged.

**SX1 note.** SX1 points out that the branch id is not *required* at v3: it can be
introduced at the first upgrade, as Zcash Overwinter did. Adding it now costs only a
change to every v1 and PX signature and test vector. It saves a two-format
transition later, since every v3 transaction is then bound to a branch from the
start. The coordinator's plan includes it, so this candidate implements it.

## 2. Proposal (implemented)

### 2.1 The schedule

`consensus::schedule` holds an activation table:

```rust
pub struct Epoch {
    pub name: &'static str,
    pub activation_height: u64,
    pub header_version: u32,
    pub branch_id: u32,
    pub verifier_id: u32,
}
pub struct Schedule { /* &'static [Epoch] */ }
impl Schedule {
    pub const fn new(epochs: &'static [Epoch]) -> Schedule; // validated
    pub fn epoch_at(&self, height: u64) -> &Epoch;         // last with activation ≤ height
    pub fn max_header_version(&self) -> u32;
    pub fn activation_in(&self, from: u64, to: u64) -> Option<&Epoch>;
}
```

`ChainParams.schedule` holds the table. Every built-in network uses the one-epoch
table `V3`:

| Epoch | Activation | Header version | Branch id | Verifier id |
|---|---|---|---|---|
| `v3` | 0 | 1 | `0x42537633` (`"BSv3"`, big-endian ASCII) | 1 (`VERIFIER_PX_1`) |

`Schedule::new` is a `const fn`. It panics during compilation for a static table
that breaks any of these rules:
- the table is non-empty;
- the first activation is at 0;
- activations strictly increase;
- header versions never decrease;
- branch ids are nonzero and pairwise distinct (so no transaction replays across
  epochs).

**Header version 1 is kept.** The genesis header uses the version of the epoch at
height 0, which is `HEADER_VERSION` = 1. So no genesis id changes (the pinned-id test
passes unchanged).

**The verifier id** names the PX verifier: the kernel id, the parameter set and
`kernel_budget`. Only `1` exists. A test in `tx` checks that every epoch of every
built-in schedule names a verifier that `tx` implements
(`tx::params::SUPPORTED_VERIFIERS`). Dispatching on it is future work (see §2.6).

### 2.2 Header rule (consensus.md §6 rule 1)

With `E = epoch_at(P.height + 1)`:
- `B.version == E.header_version`: continue.
- `B.version > schedule.max_header_version()`: `HeaderError::UnknownUpgrade { version }`.
  It is **not permanent** (`is_permanent() == false`): the peer probably runs a
  newer release, and it may be right.
- Otherwise: `HeaderError::BadVersion { expected, got }`, permanent. This includes an
  old version after an activation, and a known future version before its activation.

The epoch is taken at the height the header must have (`P.height + 1`), not at the
height it claims, so a bogus height cannot select another epoch.

`BlockTemplate.version` carries the version for the template's height.

**P2P: must be done by its owner (not in this candidate).** `p2p/src/net.rs`
matches `HeaderError` explicitly and scores every unlisted variant as
`INVALID_HEADER`. So until p2p changes, `UnknownUpgrade` is still banned. Required
changes:
- `on_header_error` (net.rs ~1102): add `HeaderError::UnknownUpgrade { .. }` to the
  no-score arm, and log WARN once per peer: "peer is on a newer consensus version
  (header version N); this node may need an upgrade".
- The block handler (net.rs ~1188): the same.
- Optional: disconnect (without a ban) after K such headers, and count distinct
  peers reporting it for an operator alert.

**Residual DoS.** A version-N header costs the sender nothing (the version check
comes before PoW), and it is not scored. It is as cheap as a `Duplicate` today, and
the verdict is reached before any RandomX work. The P2P rate limits bound it.

### 2.3 Branch id in the signature messages and `h_tx`

`TxRules` gains `branch_id`. `TxRules::domain()` returns
`SigDomain { network_id, branch_id }`, whose 8 bytes are
`LE32(network_id) ‖ LE32(branch_id)`. These bytes replace `LE32(network_id)` in:

| Hash | Definition |
|---|---|
| transfer `sig_message` | `H32("tx/sig-message", domain ‖ prefix ‖ base ‖ bp)` |
| deploy `sig_message` | the same tag, with the deploy prefix |
| PX `sig_message` | `H32("px/sig-message", domain ‖ prefix ‖ base ‖ bp ‖ H32(proof))` |
| PX `h_tx` | `H32("px/tx-binding", domain ‖ prefix ‖ base)` |

The block id is unchanged: it hashes `network_id` and the header, and the header
version identifies the epoch.

**Consensus-visible effect:** every v1, deploy and PX signature and every PX proof
changes, including on the one-epoch schedule. This is why it belongs to the v3
identity.

**Construction.**
- `TxRules::at_height(params, h)` builds the rules of the epoch active at `h`.
- `TxRules::for_chain(params)` keeps its meaning ("the rules of this chain") and
  **panics if the schedule has more than one epoch**. This is a tripwire: before a
  second epoch can ship, every caller must choose a height. Today every network has
  one epoch, so it never fires.

### 2.4 What callers must do across an activation (other owners)

Validation code receives a `TxRules`. It is correct across an activation only if the
caller builds it for the right height. With one epoch nothing changes. Before a
second epoch is scheduled:

| Owner | Change |
|---|---|
| `chain/src/manager.rs` | Validate a block at height `h` with `TxRules::at_height(params, h)`, not the stored `rules` |
| `chain/src/mempool.rs` | Admit with `at_height(params, tip + 1)`. When an extension crosses an activation (`schedule.activation_in(old_next, new_next)` is `Some`), **flush the pool**, or re-run full validation; `revalidate_after_extension` is not enough (below) |
| `tx/src/validate.rs` | `revalidate_after_extension` assumes C3 signatures and PX5 are unchanged by an extension. That is false across an activation. Document it, or have it take the two heights |
| `tx/src/validate.rs` | `TxError::PxProof` is classified stateless (misbehaviour). Across an activation, a proof bound to the previous branch fails honestly. The classification should be contextual for a transaction checked within a grace window after an activation |
| `wallet/` | Build with `at_height(params, synced_height + 1)`. Do not broadcast when the target height crosses an activation until the wallet has re-signed (and re-proved PX). **Done (V3-C, §10)** |
| `node/`, `miner/` | Use `BlockTemplate.version` instead of `HEADER_VERSION` |

`InvalidSignature` (C3) is already contextual, so v1 transactions signed for an old
branch do not get peers banned.

### 2.5 Mempool flush at activation (design)

At activation height `A`, every pooled transaction signed for the old branch is
invalid in block `A`:
- v1 and deploy signatures and PX proofs fail;
- PX transactions cannot be re-signed: they must be **re-proved** (about 45 s each).

**Chosen design: flush.** When the tip moves from below `A − 1` to `A − 1` or above,
the mempool drops the transactions admitted under the previous epoch and returns their
key images and nullifiers. Wallets rebuild. Also:
- templates for height `A` never include old-branch transactions (block validation at
  `A` would reject them anyway);
- after a reorganization back below `A`, dropped transactions are not restored. Their
  owners rebroadcast. This is rare and only costs liveness.

**Alternatives considered:**

| Alternative | Why not now |
|---|---|
| Accept both branch ids for K blocks after activation (a grace window) | Two valid signatures for one intent near the boundary. For PX, proof verification would be tried under two bindings (twice the cost of an invalid proof). Future work, possibly only for v1 |
| Explicit branch-id field in each transaction (ZIP 225 style) | Redundant: every transaction in an epoch has the same value, and the implicit binding already fails cheaply. It could be added in a later epoch (I4 §7.1) |
| Branch id derived from a hash of the rule set | Nice for auditability, but the rules are code, not data. A named constant with a uniqueness check is simpler to review |
| Keep BadVersion permanent and let P2P special-case it | P2P would have to know the schedule. The typed error keeps that knowledge in consensus |

### 2.6 Future work (not in this candidate)

- **Grace windows** (above).
- **Verifier dispatch.** `validate.rs` selects the PX verifier by `epoch.verifier_id`
  (kernel id, parameters, budgets). Old verifiers must be kept while blocks under them
  can still be validated (R16-14). The proof cache must be keyed by the verifier id
  (R16-8) before a second verifier exists.
- **End-of-service halt** for releases past their expected lifetime (zcashd
  precedent; I4 §7.1).
- **A testnet no-op activation** (I4 F2): a second testnet epoch that changes only
  the branch id and bumps the header version, at a height such as 20,000. It needs the
  §2.4 integration first. The regtest test (§3) exercises the rules; the scheduled
  activation exercises the operational path.
- **Production upgrades should bump the header version** so that old nodes stop with
  `UnknownUpgrade` rather than following a minority chain and failing only on bodies.
  The schedule allows equal versions (the no-op test uses them), so this is a review
  rule, not a type rule.

**Privacy note (I4 §7.1, R1 §4.4).** In a contentious split with shared history,
key images can be spent on both chains with different rings. The branch id prevents
replay; it does not prevent ring intersection. The wallet must reuse stored rings
(wallet-review W-5).

## 3. Tests (item 1)

- `consensus::schedule` unit tests: boundaries (`A − 1`, `A`, `A + 1`, `u64::MAX`),
  table validation (every invalid form rejected), `activation_in`.
- `consensus::chain` tests:
  - an old version after an activation is `BadVersion` (permanent);
  - a version above every known one is `UnknownUpgrade` (not permanent);
  - a known future version before its activation is `BadVersion`;
  - templates carry the epoch's version.
- `tx/tests/upgrade.rs` (regtest, a test-only 2-epoch table identical except for the
  branch id, activation at height `A`):
  - the transfer and deploy signature messages and the PX `h_tx` change with the
    branch id and with the network id;
  - a transfer signed under the old branch is valid below `A` and fails with
    `InvalidSignature` at `A`;
  - a transfer re-signed under the new branch is valid at `A` and fails below `A`;
  - `for_chain` refuses a multi-epoch schedule;
  - every built-in schedule names a supported verifier.

## 4. Implementation (item 1)

| File | Change |
|---|---|
| `consensus/src/schedule.rs` | new: `Epoch`, `Schedule`, `V3`, `BRANCH_ID_V3`, `VERIFIER_PX_1` |
| `consensus/src/params.rs` | `ChainParams.schedule`, `epoch_at`; the genesis version comes from epoch 0 |
| `consensus/src/chain.rs` | the §2.2 version rule; `BadVersion { expected, got }`; `UnknownUpgrade`; `BlockTemplate.version` |
| `tx/src/params.rs` | `SigDomain`, `TxRules.branch_id`, `at_height`, `domain`, `SUPPORTED_VERIFIERS`, the `for_chain` tripwire |
| `tx/src/types.rs`, `tx/src/px.rs` | the three signature messages and `h_tx` take a `SigDomain` |
| call sites (mechanical, required to build) | `rules.network_id` → `rules.domain()` in `tx/src/validate.rs`, `tx/src/builder.rs`, `tx/src/px_builder.rs`, `chain/tests/{mempool_conflicts,revalidation}.rs`, `fuzz/fuzz_targets/tx_decode.rs`, `tx/tests/{adversarial,validation_order}.rs` |

---

## 5. Item 2 (R5-7): duplicate program ids in one deploy

**Analysis.** `MemoryChain::px_function` returns the first registration of
`(contract, program_id)`. A deploy may register the same program twice with
different budgets, and the second is unreachable. It is deterministic, so not a
split, but it is misleading dead state.

**Rule (stateless).** In `check_deploy_structure`, after the programs load: the
program ids (`Program::id()`, computed from the loaded code and data, not from ELF
bytes) must be pairwise distinct. Otherwise `TxError::PxDuplicateProgram { program }`,
where `program` is the index of the second occurrence.

It compares loaded ids because two different ELF files (for example, differing only
in sections the loader ignores) can load to the same program.

## 6. Item 3 (R7-5): budgets above the proving limits

**Analysis.** `read_budget` admits every budget field up to `2^MAX_LOG_HEIGHT` =
2^22 rows. But:
- the CPU table of every execution is limited to `MAX_CYCLES` = 2^21 rows
  (`zkvm::prove::limits`, `Table::Cpu`);
- the ALU (`add`, `bit`, `lt`, `shift`, `mul`) and Poseidon2 tables are **shared**:
  their height is `pow2(Σ budgets)` over the kernel and every function, and must be at
  most 2^22;
- the memory-init table (`keys`) is per execution and limited to 2^22, which decoding
  already enforces.

So a function with `cycles > 2^21` is registrable but can never be proven. It is
useless state paid at the deploy price (SX1: "overstated as DoS; a valid
tightening").

**Rule (stateless).** For each registered budget `b`, with `K = kernel_budget(1)` (the
kernel's budget when it calls one function):
- `b.cycles ≤ MAX_CYCLES` (2^21);
- `b.keys ≤ 2^MAX_LOG_HEIGHT`;
- for each shared table `x ∈ {add, bit, lt, shift, mul, poseidon}`:
  `K.x + b.x ≤ 2^MAX_LOG_HEIGHT`.

Otherwise: `TxError::PxBudgetTooLarge { program }`.

This is exactly the condition for the one-function proof's table heights to be
within the limits. A two-function call can still exceed the shared limit with two
large functions. That combination fails when proved, and the verifier refuses the
heights. It is not a soundness issue, and it cannot be checked at deploy.

**Not done:** a total cap from ZK-F4 measurements (the proof size at large heights
may exceed `MAX_PROOF_BYTES` well before 2^22 rows). It needs measurements, which
need proving runs that this candidate does not do.

## 7. Item 4 (R5-1, R6 TX-4): deploy byte cap and exact fee

### 7.1 Facts (verified in source)

| Constant | Value | Where |
|---|---|---|
| `FEE_PER_WEIGHT` (v1) | 20 atomic per weight unit (≈ per byte) | `tx/src/params.rs` |
| `PX_FEE_PER_BYTE` | 2 | same |
| `PX_STANDARD_FEE` | 2 × (4 MiB + 256 KiB) = 8,912,896 | same |
| `MAX_DEPLOY_TX_SIZE` | 1 MiB | same |
| `MAX_PX_BLOCK_BYTES` | 8 MiB (PX transactions and deploys together) | same |
| Measured PX transfer | ~2.18 MB, so ~4.1 atomic/byte effective | R5, R6 |
| Deploy fee today | `≥ 2 × encoded size`, any amount above | `px.rs::check_deploy_structure` |
| 1 BLK | 10^8 atomic units; first reward ≈ 20.03 BLK | `docs/blocks.md` |

Deploys are 10 times cheaper per byte than v1 transfers. Their registrations are
permanent RAM state. A deploy paying about 4.2/byte outranks every PX transaction.
And the `≥` rule lets the fee fingerprint the wallet (R6 §3.3).

### 7.2 Proposal

**Exact deploy fee (stateless, T8 for deploys):**

```
deploy_fee(n, k, payload) = FEE_PER_WEIGHT × max_weight(n, k)
                          + DEPLOY_FEE_PER_BYTE × payload_len
```

- `n`, `k`: the v1 input and output counts.
- `max_weight(n, k)`: the shape bound that the v1 standard fee already uses
  (`builder::max_weight`). The v1 part pays exactly what a standard transfer of the
  same shape pays, including the Bulletproofs+ clawback. This closes the
  "deploy as cheap batch payment" gap (R6 scenario 1).
- `payload_len`: the length of the encoded payload (salt, program count, and each
  program's length, ELF bytes and budget). It is a function of the programs alone,
  not of the fee, so the rule has no fixed-point problem.
- `DEPLOY_FEE_PER_BYTE = 50`: 25 times the current PX rate and 2.5 times the v1 rate.
  This is within R5's suggested 20–50 times, and above the v1 rate, as R6 and SX1
  require.
- `fee` must equal `deploy_fee` exactly (`TxError::DeployFeeNotExact { fee, required }`).
  The fee is then a function of public shape data, so it reveals nothing about the
  wallet (R6 §3.3, P-7).

**What it costs:**

| Deploy | Payload | v1 part (1 in, 2 out) | Total |
|---|---|---|---|
| The vault (13.4 KB ELF) | ~13.5 KB → ~0.0068 BLK | `20 × max_weight(1,2)` | ~0.007 BLK |
| Maximum (1 MiB) | ~1 MiB → ~0.52 BLK | same | ~0.52 BLK |
| Filling a 1 MiB block sub-budget every block for a day (720 blocks) | | | ~377 BLK/day for ~720 MiB of registry |

**Per-block deploy sub-budget (block rule, not implemented here).**
`MAX_DEPLOY_BLOCK_BYTES` = 1 MiB is defined in `tx/src/params.rs`: the encoded
deploy bytes of a block must not exceed it. With it:
- a block still has 7 MiB of PX lane, enough for 3 PX transfers (~6.5 MB);
- so deploys can no longer crowd PX transactions out, even though they outrank them
  per byte.

A const assertion keeps `MAX_DEPLOY_TX_SIZE ≤ MAX_DEPLOY_BLOCK_BYTES`, so every valid
deploy fits in a block. **The check belongs in `validate_block_transactions`
(`tx/src/validate.rs`), next to the `MAX_PX_BLOCK_BYTES` check. Its owner must add
it**, with the error `BlockError::DeployBytes`, and the template builder
(`chain/src/mempool.rs`) must respect it.

**Dropped:** "≤ 2 deploy outputs" (SX1: unnecessary once the v1 part pays the v1
rate, which the exact fee now does).

**Not proposed (owner decision):** burning part of the deploy fee, so that a miner
cannot recycle it (R5-1 option). A miner who fills the sub-budget with its own
deploys forgoes about 0.27 BLK of PX fees per block and adds at most 1 MiB of registry
per block. The byte cap bounds the rate; a burn would add an emission rule.

**Wallet and builder change (owner of `tx/src/px_builder.rs`).**
`px_builder::deploy_fee` must return `px::deploy_fee` exactly. Its current value (an
upper bound of `2 × size`) is refused by the new rule. This candidate makes that
one-line delegation so that the branch builds and tests run; see the report.

---

## 8. Integration of §2.4 (V3-B)

The §2.4 items, done on the candidate branch by V3-B. Every one is a no-op with a
single epoch (every built-in network).

| Owner | Done |
|---|---|
| `p2p/src/net.rs` | `HeaderError::UnknownUpgrade` is not penalized, in header batches (`penalized`, `on_header_error`) and in blocks (`on_block`). The first one per peer is logged at WARN ("peer … is on a newer consensus version (header version N); this node may need an upgrade"). Not done: disconnecting after K such headers, and an operator alert counting distinct peers. |
| `chain/src/manager.rs` | Blocks are validated with `rules_at(h)` (`TxRules::at_height` for the block's height, with the fee and weight limits given to `open`). Pool admission and templates use the next block's rules. **The PX proof cache is gated by the rule set:** `validate_block_transactions_cached` skips PX5 for a pooled transaction only when the pool was validated under the block's own signature domain. Without the gate, a PX transaction without v1 inputs (no CLSAG, so C3 cannot catch it) proven for the old branch and still pooled would pass block `A` on nodes that pooled it and fail on the others: a consensus split. |
| `chain/src/mempool.rs` | The pool records the signature domain it was validated under (`validated_under`). `enter_rules` flushes it when the domain changes, in either direction (an activation, or a reorganization back across one); `add` and `revalidate` call it first, and the manager logs the flush. Templates offer transactions only when the pool's domain is the template height's, and respect the deploy sub-budget `MAX_DEPLOY_BLOCK_BYTES` inside the PX lane. |
| `tx/src/validate.rs` | Block rule: `BlockError::DeployBytesExceeded` when a block's deploy bytes exceed `MAX_DEPLOY_BLOCK_BYTES` (**consensus**). `revalidate_between(tx, chain, height, from, rules)`: the extension-only check within an epoch, full validation (PX proof included) when the domains differ. `revalidate_after_extension` documents that it is not valid across an activation. |
| `PxProof` classification | `TxError::is_stateless_at(params, height)`: `PxProof` is contextual when `height` is within `ACTIVATION_GRACE_BLOCKS` = **N = 60** blocks of an activation, on either side (`near_activation`). P2P also stops treating `InvalidSignature` over buried rings as proof of misbehaviour in that window. Why 60: about 2 h at 120 s; covers peers behind or ahead of the activation block and transactions proven shortly before it; the same depth p2p already treats as final (`SIGNATURE_BURIAL`). P2P scoring only. |
| `node/`, `miner/` | `chain::Template.version` and `rpc::Template.version` (serde default 1 for older nodes) carry the epoch's header version; the miner builds headers with it. |
| Tests | `chain/tests/activation.rs` (regtest two-epoch no-op activation at the manager level: flush at `A − 1`, old-branch transactions refused in the pool and in block `A`, new-branch ones refused before and mined at `A`, blocks below `A` still valid under the old rules, a reorganization across `A` re-admits returned transactions only under the new rules); `chain/src/mempool.rs` unit tests (flush, deploy sub-budget in templates); `tx/tests/upgrade.rs` (`revalidate_between`, the grace window); `tx/tests/deploy_rules.rs` (the block deploy budget); `p2p/src/net.rs` (`unknown_upgrades_are_not_penalized`). |

**Wallet (V3-C):** done; see §10.

## 9. R2-C6 Hk node feed-forward: decision data (V3-B, measured, not implemented)

**The owner decides.** Nothing here changes the kernel. The kernel pinned by this
candidate (`0577e667…`) has no feed-forward.

**What was measured (native, no proving; 2026-09-27).** The zkVM interpreter runs
the kernel ELF and `zkvm::air::trace::usage` gives each table's rows. Two kernels
ran the same witness (a plain bridge-in, both inputs dummy, `n_fn = 0`):
- the candidate kernel;
- the same source with `node()` changed to `P(l ‖ r)[0..8] + l` (feed-forward on
  the first 8 words), built with the same flags in a scratch copy.

Dummy inputs skip only the membership verdict, not the 2 × 32 `node()` calls, so
the difference is the full cost of the change. It is the same for every shape (the
number of `node()` calls does not depend on `n_fn`).

| Table | Candidate | Feed-forward | Δ |
|---|---|---|---|
| cycles (CPU) | 24,550 | 27,181 | **+2,631** |
| keys | 4,272 | 4,321 | +49 |
| add | 16,902 | 18,509 | +1,607 |
| bit | 1,378 | 1,890 | +512 |
| lt | 14,199 | 14,786 | +587 |
| shift, mul, poseidon | — | — | 0 |

SX1 estimated +2–3k cycles; measured +2,631.

**Headroom per fixed shape** (use from `budgets_leave_headroom` with the candidate
kernel, plus Δ, against the current budget and the table height the budget gives):

| Shape | Cycles now / budget | + Δ | Height now | Height needed (use + Δ, +6%) |
|---|---|---|---|---|
| `n_fn = 0` | 24,586 / 26,500 | 27,217 | 2^15 | 2^15 (28,850) |
| `n_fn = 1` | 28,388 / 31,200 | 31,019 | 2^15 | **2^16** (32,880 > 32,768) |
| `n_fn = 2` | 32,020 / 35,600 | 34,651 | 2^16 | 2^16 |

- Shared ALU tables: `add` and `lt` keep their heights in every shape; `bit` for
  `n_fn = 1` goes from 2^11 to 2^12 once the vault's budget (250) is added. Small.
- **The decision point is `n_fn = 1` (one vault call).** With the usual +6% rounding
  its CPU table doubles to 2^16 rows, which increases that shape's proof size and
  proving time (not re-measured here; proving was not run for this). With a budget
  of exactly 32,768 cycles the use is 94.7%, inside the 95% headroom rule, and the
  height stays 2^15, at a thinner margin than the other shapes.
- Every budget change and the node change itself change the kernel id, so the
  choice must be made before the v3 ids are pinned for launch.

**Options for the owner:**
1. **Adopt** feed-forward in v3: `node()` becomes collision resistant on its own
   (a future tree with free leaves stays safe); re-measure, set `n_fn = 1` to 32,768
   cycles or accept 2^16; re-measure the widest two-function proof against
   `MAX_PROOF_BYTES`; rebuild (new ids).
2. **Keep** the current `node()`: the tree is argued to be ≈2^124-binding from leaf
   anchoring and fixed depth (the corrected comment in `px-core/src/hash.rs`); any
   future tree must not reuse `node()` with free leaves.

## 10. Wallet integration (V3-C)

The §2.4 wallet item, done on the candidate branch by V3-C (`wallet/` only). No-op
with a single epoch (every built-in network).

| Item | Done |
|---|---|
| Rules per height | Every build (transfer, deposit, PX send and withdraw, deploy, vault lock and claim) syncs, then uses `TxRules::at_height(params, synced + 1)` (`Wallet::next_block_rules`). The `rules` argument of the public build methods is kept for source compatibility (`tools/labnet`, `tools/supply-audit`); only its network is checked (`WrongNetwork` otherwise), and its epoch is ignored. The CLI no longer calls `TxRules::for_chain`. `Wallet::set_chain_params` replaces the built-in parameters (same network and genesis only), for regtest schedules in tests; it is not persisted. |
| Stored transactions | Each `PendingTx` records the branch id it was built for (`branch_id`; files written before have none, and the epoch of `relayed_height + 1` stands in, which is exact on single-epoch chains). |
| No broadcast across an activation | `submit` asks the node for its height first. If the node's next block needs another branch than the transaction's (the tip crossed an activation while the transaction was built or proven), nothing is sent or reserved: `WalletError::EpochChanged` (a vault lock's new record is dropped as on a refusal). |
| No rebroadcast across an activation | `refresh_pending` (every sync; the stored and Uncertain paths alike) does not rebroadcast an unconfirmed transaction whose branch differs from that of `synced + 1`. Its unspent inputs (v1 outputs, PX and contract records) are released, the stored copy is dropped, a warning says to send the payment again, and it is listed in `Wallet::stale_transactions` (persisted as `stale_txs`; `sync` prints "needs rebuilding"; kept `RING_RETENTION_BLOCKS` = 720 blocks or until `clear-pending`). Rings stay stored, so a rebuild reuses them (W-5). |
| Warning before an activation | When an activation lies within `ACTIVATION_GRACE_BLOCKS` = 60 blocks after the next block, building a transaction and syncing with unconfirmed stored transactions warn that they are valid only if mined before it. |
| Tests | `wallet/tests/e2e.rs` with the regtest two-epoch schedule of `chain/tests/activation.rs` (activation at 110): `a_transfer_built_before_an_activation_is_not_rebroadcast_after_it` (a recorded and an Uncertain transfer built for 91 are kept and reserved at 108 with a warning; at 116, when a rebroadcast is due, nothing is sent, both inputs are released and the balance is whole again, two notices survive a save and load; the node refuses the old transaction; the payment sent again is accepted and mined under the new branch although the caller passed first-epoch rules); `a_transaction_is_not_sent_across_an_activation_it_was_not_built_for` (`EpochChanged`, nothing sent or reserved, then a rebuild after a full sync is accepted). `wallet/src/wallet.rs`: `stored_transactions_keep_their_branch_id_and_older_files_load` (older wallet JSON without the new fields loads; the fields round trip; rules and parameters of another network are refused). |

**What remains (not done here):**
- **PX flows across an activation are not tested end to end.** The code path is the
  same (`submit`, `refresh_pending`, nullifiers released through `for_each_input`),
  but the PX e2e tests prove and were not run for this change.
- **A reorganization back below an activation** makes transactions built for the new
  branch stale in turn: they are released and dropped, not kept for a later
  re-activation. Only liveness is lost (the node's pool flushes them too, §2.5). If
  the chain then crosses the activation again, the user sends again.
- **Linkability of a rebuild.** A payment sent again spends the same key images and
  nullifiers as the dropped transaction, so anyone who saw the dropped one relayed
  can link the two. Stored rings prevent ring intersection. This cannot be avoided
  without spending other funds.
- **Uncertain and dropped vault locks.** A vault record created by a lock that is
  later dropped stays listed as "unconfirmed" in `px-records` (with its secret); it
  holds no value on chain.
- **The pre-submission check trusts the node's height** and is skipped when `info`
  fails (the submission then fails as Uncertain and the next sync applies the
  rebroadcast rule).
- **Other `for_chain` callers remain** outside the wallet: `node/src/main.rs`
  (`ChainManager::open` with `for_chain`; must become `at_height(params, 0)` like
  `chain/tests/activation.rs` before a second epoch is scheduled), `tools/labnet`
  (its argument to the wallet is now only a network check), fuzz targets and tests.
