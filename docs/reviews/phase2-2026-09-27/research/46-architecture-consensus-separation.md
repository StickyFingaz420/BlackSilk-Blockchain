# 46 architecture-consensus-separation: research dossier (phase 2, phase 1)

**Internal engineering research, not an audit.** Nothing here claims that BlackSilk, or any
part of it, is secure, audited or production-ready. Read-only on the repository; no builds,
no tests run.

Deliverables (coordinator's mandate, decisions.md "Agent 31"):
1. the exact `p2p/src/net.rs` split plan (target modules, which item goes where, owner
   after the split, and the moved-code-only review procedure) — §5.1;
2. a file-ownership map for all phase-2 implementation work, built from every dossier
   filed so far — §5.3;
3. a staged ADR for consensus separation (R16-4, R16-5, R16-6, R16-9, R16-11) — §3.6 and
   §5.2.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD` on `rebuild/core`), working tree clean.

**Brief, roster, decisions:** `C:/bszkeval/p2/brief.md` (all), `roster.md` (all 50 entries;
mine is 46, neighbours 30–36, 45, 47–50), `decisions.md` (all, as of 12:37), `status.md`.

**Research dossiers read for ownership and conflicts (all filed at the time of writing):**
01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
25, 26, 27, 28, 29, 30, 31, 34, 35, 36, 37 — sections 5 (implementation plan) and 6
(dependencies) of every one, plus the findings sections of 30, 31, 34 and 13 in full.
**Not yet filed** when I wrote this: 24, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 47, 48, 49,
50. For those the ownership map uses the roster scope plus the claims other dossiers make
on their behalf, and is marked *provisional*.

**Required reading:**
- `docs/reviews/full-review-2026-09-27.md` (all 1,422 lines: register, P0–P3, v3 bundle,
  never-change list, risks);
- `docs/reviews/autonomous-session-2026-09-27.md` (all);
- `docs/reviews/full-review-2026-09-27/R16-architecture.md` (all 770 lines);
- `docs/reviews/v3-upgrade-mechanism.md` §1, §2 (schedule, §2.4 caller duties, §2.5 flush,
  §2.6 future work), §8 (integration);
- the crate graph: every workspace `Cargo.toml` (path dependencies extracted by script) and
  the root `Cargo.toml`.

**Code read in full:** `p2p/src/net.rs` (2,934 lines, every line), `p2p/src/lib.rs`,
`p2p/Cargo.toml`, `consensus/src/schedule.rs` (the schedule part), `tx/src/lib.rs`,
`px/src/lib.rs`, `tx/src/state.rs:150-260` (apply/undo), `tx/src/validate.rs:575-760` and
`:940-965` (the per-kind dispatch sites), `chain/src/mempool.rs:75-140` (`conflict_keys`),
`tx/src/types.rs:470-524` (`key_images`, `output_keys`), the `pub fn` index of
`chain/src/manager.rs`. Grepped: every consumer of `blacksilk_p2p::*`, every
`Transaction::PxDeploy` match site, every `into_inner()` poison recovery, every reference to
`net.rs` in docs, `CIPHERTEXT_BYTES`, uses of `crypto::{schnorr,membership,claims}`, and
`env_logger` 0.8.4's filter (`filter/mod.rs:366`).

**Tests read:** the `net.rs` unit tests (5); the public-API users `p2p/tests/network.rs`,
`p2p/tests/withheld_body.rs`, `p2p/tests/fuzz_message.rs`, `node/tests/deploy_configs.rs`,
`fuzz/src/seeds.rs` (imports only).

**Internet research (primary sources, §8):** Bitcoin Core libbitcoinkernel (tracking issue,
the kernel author's write-up, the first kernel PR), the Bitcoin Core net / net_processing
split (PR #9260 history, meta issue #33958) and CONTRIBUTING's move-only rule, Bitcoin Core
`undo.h`; Zebra RFC 0005 (state updates) and `zebra-state`'s `SemanticallyVerifiedBlock`;
reth's `Consensus`/`HeaderValidator`/`FullConsensus` traits and `ExecutionOutcome`; Sui
transaction effects; quinn-proto (sans-IO); git `diff --color-moved`, `blame -C`,
`--ignore-revs-file`, GitHub's `.git-blame-ignore-revs`; the Rust Reference on module files;
cargo-semver-checks.

---

## 2. Current state

### 2.1 The crate graph at `9e422d8` [source-read: every `Cargo.toml`]

```
randomx ──► consensus ─────────────────────────────────────────────┐
crypto ─────────────────────────────────┐                          │
px-core (no deps, no_std, also the guest)                          │
zk ◄─ crypto ; zkvm ◄─ zk, crypto                                   │
px ◄─ px-core, crypto, zk, zkvm        (state, tree, prove  +  wallet, delivery, share, vault)
tx ◄─ crypto, consensus, px, px-core, zkvm, zk   (params, codec, types, px, validate, state
                                                   +  builder, px_builder, scan, decoy)
chain ◄─ consensus, crypto, tx, px, px-core, randomx
p2p ◄─ consensus, crypto, tx, chain          (dev: px)
rpc (no project deps)
node ◄─ chain, consensus, tx, rpc, p2p, px, randomx, crypto
miner ◄─ randomx, consensus, crypto, tx, chain, rpc
wallet ◄─ consensus, crypto, tx, chain, rpc, px, px-core, zkvm   (dev: node, miner)
contracts ◄─ crypto            (default workspace member; used by nothing)
tools/labnet, tools/supply-audit, tools/genesis
```

Compared with R16 §1.1: unchanged in shape. `node` now also depends on `px`, `randomx` and
`crypto` (fingerprint and identity code, `f440c4b`), and `tools/genesis` is new. The graph
is still acyclic [source-read]. The two R16 layering observations still hold:
- `tx` (the rules) depends on `px`, which also holds the wallet, the delivery encryption,
  the share format and the demo vault [source-read `px/src/lib.rs:20-30`];
- every binary that depends on `chain` (miner included) links the whole STARK stack.

### 2.2 Where consensus lives today (R16 §2.1, re-checked)

The R16 table is still accurate, with three changes since `9578517`:
- `consensus/src/schedule.rs` exists (merged from `v3/candidate`): one epoch `v3` from
  height 0 with `header_version`, `branch_id` and `verifier_id` [source-read]. R16-1 is
  therefore **partially implemented** on `rebuild/core`: the table and the branch id exist;
  verifier dispatch does not (`verifier_id` is read nowhere in validation; 22 and 10 F10-7
  report the same) [source-read].
- The consensus fingerprint (`f440c4b`) pins `px.delivery.CIPHERTEXT_BYTES`
  (`px/src/fingerprint.rs:270-271`), so the R16-4 scenario (a wallet edit silently changes
  a consensus length) now **fails a pinned test** instead of passing silently [source-read;
  tested through the fingerprint pin tests]. The layering defect remains.
- `tx/src/state.rs::apply_block` still re-parses deploy ELFs with `expect` (`:193`) and
  `expect`s the PX apply (`:220`); `chain/src/manager.rs:917` still `assert!`s the undo
  [source-read]. R16-6 is unchanged, but its consequence changed: a poisoned chain lock is
  now fail-stop (`lock_or_exit`, exit 70), so a validate/apply disagreement is a
  deterministic **crash loop on replay** rather than silent divergence (§4, F46-5).

### 2.3 What is right and must be kept [source-read unless tagged]

- One header-rule definition (`check_rules`), used by sequential validation and the batch
  pre-check [tested: `precheck_agrees_with_sequential_validation_and_computes_no_pow`].
- A partial effects vocabulary already exists on `Transaction`: `key_images()` and
  `output_keys()` (`tx/src/types.rs:480-520`), and `conflict_keys` is derived from them
  (`chain/src/mempool.rs:112-133`). The F1 fix (`16659ee`) was exactly "derive, don't
  restate". This is the seed of the effects model; it does not need a redesign.
- Typed rule errors with `is_stateless` / `is_stateless_at` drive peer scoring.
- The body-storage-order determinism of fork choice (`manager.rs:17-24`), which makes
  scheduler changes (actor, module split) consensus-neutral [tested:
  `replay_reproduces_live_fork_choice_exactly`].
- `forbid(unsafe_code)` in every project crate (including `p2p/src/lib.rs:14`).

### 2.4 `p2p/src/net.rs` today [source-read, all 2,934 lines]

| Lines | Content |
|---|---|
| 1-67 | module doc and concurrency rules; imports; `SharedChain`; `POISONED_EXIT_CODE`; `lock_or_exit`; `fatal` |
| 69-105 | 17 constants (timeouts, windows, outboxes, queue caps, caches, save/seed intervals) |
| 107-197 | `NetConfig` (+ `new`), `PeerInfo`, `NetStats` (public) |
| 199-345 | `Peer`, `StemEntry`, `State`, `BlockJob`, `HeaderBatch`, `queue_key`, `remember` |
| 347-379 | `Inner`, `Network`, `unix_now`, `short` |
| 381-544 | `impl Network` (public API: `start`, `submit_tx`, `connect`, `peers`, `stats`, `stempool_contains`, `header_queue_len`, `save`) |
| 546-800 | `impl Inner`: lock access (`state`, `chain`, `with_chain`), `save`, `send`, `send_now`, scoring (`misbehave`, `penalize`, `ban_addr`, `misbehave_departed`), `header_queue_room`, `warn_unknown_upgrade`, `request_headers(_after)`, `reject_cache`, `announce_tx` |
| 802-1244 | connections: `accept_loop`, `inbound_count`, `same_ip_count`, `HandshakeSlot`, `connect_outbound`, `advertised_listen`, `recv_msg`, `run_connection` (handshake + registration + read loop + cleanup, 270 lines), `write_loop` |
| 1246-1391 | `requested_by_us`, `handle` (dispatcher), `on_get_addr`, `on_addr`, `in_grace` |
| 1393-1827 | header sync: `on_headers`, `HeaderOutcome`, `penalized`, `header_worker`, `sender_live`, `ANTI_DOS_BLOCKS`, `anti_dos_threshold`, `worth_verifying`, `verify_headers`, `on_header_error` |
| 1829-2039 | blocks: `on_get_blocks`, `release_block_slot`, `on_block`, `block_worker`, `schedule_downloads`, `window_has_room` |
| 2041-2498 | tx relay and admission: `on_inv_tx`, `on_get_tx`, `retry_tx`, `decode_tx`, `stem_keys`, `is_px`, `input_rings`, `ctx_rejected`, `ctx_reject`, `admit_tx`, `SIGNATURE_BURIAL`, `provably_invalid_signature`, `proven_invalid`, `on_invalid_tx`, `on_tx`, `unstem_key_images`, `on_stem_tx` |
| 2500-2590 | Dandelion glue: `stem_or_fluff`, `send_held_local_txs`, `fluff` |
| 2592-2852 | `maintenance_loop` (Dandelion epoch + embargo, tip announce, trickle flush + pings + timeouts, re-requests, downloads, outbound, saving), `maintain_outbound` |
| 2854-2934 | 5 unit tests |

**Public surface** (must not change): `blacksilk_p2p::net::{NetConfig, NetStats, Network,
PeerInfo, SharedChain, lock_or_exit, POISONED_EXIT_CODE, BLOCK_WINDOW_BYTES}` and the
`Network` methods. Consumers: `node/src/{lib,main,config}.rs`, `node/tests/deploy_configs.rs`,
`p2p/tests/{network,withheld_body}.rs` (which import `blacksilk_p2p::net::BLOCK_WINDOW_BYTES`
by that path), `fuzz/src/seeds.rs` [source-read, grep]. Everything else in `net.rs` is
private.

**Growth.** R16 measured `net.rs` at 1,781 lines at `9578517`; it is now 2,934 (+65 %)
after P2P rounds 2 and 3. Every R16/R8/R10 line reference into `net.rs` is stale
(e.g. the R10-2 residual sites 323, 442, 446 — §4 F46-6).

---

## 3. Problems in scope

### 3.1 P1: `net.rs` is the single most contended file of phase 2 (F46-1)

**Problem and cause.** One module holds nine concerns (§2.4). Phase-2 dossiers plan edits
in it from 30 (W1, W2, W8), 31 (S1, S2, S5–S8, S10), 34 (Stage 1a/1b, Stage 2 facade), 04
(W2 clock, W3 hooks, W9), 07 (W3/W6, owned by 31), 02 (W-3, owned by 31), 11 (I5), 12
(W3), 13 (stempool accessor; MP-9 fallback), 14 (item 4), 10 (item 5 constant), and the
not-yet-filed 32 (connection manager, addrman, eviction) and 33 (trickle, Dandelion, GetAddr
caches) [dossier §5 tables]. That is at least 12 workstreams. Several edits land in the
same functions: `run_connection` (30, 34, 32), `maintenance_loop` (31, 32, 33, 34, 04),
`admit_tx` (11, 12, 14, 34), `handle` (34, 31 via the `NotFound` arm).

**Consequences.** Not consensus-critical, not privacy-critical by itself. It is a
correctness-of-integration and review risk: large rebases in a file that implements
ban/penalty policy, Dandelion privacy rules (never-change items 22–25) and the lock-ordering
rule. A mis-resolved merge conflict in `stem_or_fluff` or `penalized` is a privacy or
liveness regression that no single reviewer owns.

**Prior art.**
- Bitcoin Core split networking out of `main.cpp` in PR #9260 (2016, move-only, by
  theuni): "net processing and validation were split into separate files" (net_processing).
  Its CONTRIBUTING rule is the method: refactoring PRs must not mix code moves, style fixes
  and real refactoring, and "must not change the behaviour of code within the pull request
  (bugs must be preserved as is)". The current meta issue #33958 continues the separation
  (CConnman vs PeerManager, then interfaces), in steps.
- quinn-proto is the Rust precedent for isolating protocol state machines from I/O
  ("contains no networking code and does not get any relevant timestamps from the operating
  system"), which 31 already proposes for `header_queue.rs` and `presync.rs`.

**Solution.** A mechanical, move-only split into a `net/` module tree **before wave 1**,
then per-module owners (§5.1). A second, separately reviewed extract-only commit turns
the two multi-owner functions (`maintenance_loop`, the inline arms of `handle`) into
calls to per-concern functions so that each lands in its owner's module.

**Trade-offs and what could go wrong.**
- Moving code changes `module_path!()`, which is the default `log` target:
  `blacksilk_p2p::net` becomes `blacksilk_p2p::net::headers` and so on. `env_logger` 0.8.4
  filters by prefix (`!target.starts_with(name)`, `filter/mod.rs:366`) [source-read], so
  every existing `--log`/`RUST_LOG` directive still matches. The printed target in log
  lines changes (the committed labnet evidence logs show `blacksilk_p2p::net`). Nothing in
  `tools/` or `deploy/` parses it [grep]. This is the **only** externally visible effect
  and must be stated in the commit message (F46-9).
- Panic messages carry file:line; they change. They are fail-stop diagnostics only.
- Visibility: private items used across sibling modules must become `pub(super)`. This is a
  non-move token and the one kind of edit the review must allow. It cannot widen the crate's
  public API (`pub(super)` from `net::x` reaches `net` and its children only).
- Glob imports can change name resolution silently. The split uses explicit `use` lists,
  never `use super::*` in production code (tests keep `use super::*`, as today).
- History: `git blame -C -C` follows lines "from other files in the commit that creates
  the file"; the split commits go into `.git-blame-ignore-revs` (GitHub honours it).

**Tests that prove it.** The unchanged test suites of p2p, node and fuzz; the
public-API check; the line-multiset check (§5.1.4). No new test is needed for a move.

**Invariant.** No behaviour change: identical verdicts, penalties, timings, lock scopes
and await points.

### 3.2 P2: rules restated per transaction kind (R16-5), re-checked at HEAD

Per-kind dispatch over `Transaction` occurs in `tx/src/types.rs` (8 sites), `tx/src/validate.rs`
(7), `chain/src/mempool.rs` (8), `p2p/src/net.rs` (3), `tx/src/state.rs` (1),
`tx/src/scan.rs` (1), `wallet/src/wallet.rs` (1) [grep `Transaction::PxDeploy`]. Three
kinds of restatement matter:

1. **Effects restated.** `stem_keys` (`net.rs:2147-2153`) = key images + nullifiers;
   `conflict_keys` (`mempool.rs:112-133`) = key images + nullifiers + contract id + output
   keys; `apply_block` (`state.rs:159-231`) inserts key images, one-time keys, records,
   nullifiers, registry entries; `input_rings` (`net.rs:2160-2168`) re-matches the input
   list that `key_images` already matches; `is_px` (`net.rs:2155`) duplicates mempool
   `class_of` (`mempool.rs:96-101`). The stem pool therefore lacks the contract-id key
   (F46-3). After D8 option B the output-key namespace disappears from the mempool
   (decisions "D8/C4"), so the remaining drift is contract ids.
2. **The cheap stateless dispatch restated in P2P.** `admit_tx` (`net.rs:2273-2283`)
   re-implements "structure then balance, per kind", which `validate_transfer`,
   `validate_px_without_proof`, `validate_deploy` (`validate.rs:592-672`) and block phase 1
   (`validate.rs:940-962`) each state again (F46-2).
3. **Contextual rules restated for extensions.** `revalidate_after_extension`
   (`validate.rs:712-755`) repeats C2/C4, PX1–PX4 and the contract check. This is intended
   (a subset), and documented; 12 W1 extends it. It is fine as long as the subset is derived
   from the same effects.

**Security consequence.** Not consensus-critical today: the full `validate_mempool_tx` and
block validation are single-sourced. The drift class is **policy**: conflict keys, peer
scoring and stem acceptance. F1 was this class and could stall templates.

**Prior art.**
- Zebra computes a block's effects once, at semantic verification, and passes them on:
  `SemanticallyVerifiedBlock` carries `new_outputs` ("New transparent outputs created in
  this block, indexed by OutPoint") and precomputed `transaction_hashes`; the `Chain` caches
  "created and spent UTXOs, nullifiers (Sprout, Sapling, Orchard), note commitment trees
  and anchors" (RFC 0005).
- reth separates validation phases by trait: `validate_block_pre_execution` ("disregarding
  world state") and `validate_block_post_execution` ("considering world state"), and
  represents the outcome as data: `ExecutionOutcome` ("post-execution changes and
  reverts", with `revert_to`, `split_at`).
- Sui makes the effects the unit of agreement: `TransactionEffects` lists created,
  mutated and deleted objects plus gas and status, and the effects digest is what the
  network compares.
- Bitcoin Core applies per-block effects through a `CCoinsViewCache` layered view and
  writes `CBlockUndo`/`CTxUndo` records (`undo.h`) for disconnection.

**Solution (staged, §3.6).** Now: one `TxEffects` accessor and one cheap-stateless entry
point, both behaviour-neutral; later: `check -> BlockEffects`, `commit(BlockEffects)`.

### 3.3 P3: validate-then-apply-with-`expect` (R16-6), re-checked at HEAD (F46-5)

`apply_block` calls `load_programs().expect(...)` (`state.rs:193`), a **second ELF parse of
consensus data**, and `px.apply_block(..).expect(...)` (`:220`). Since `35b7cb9`/`7d72b37`
a panic under the chain lock is fail-stop. If validation and apply ever disagree on some
block (a future parser or tree bug), every restart replays to the same block and panics
again: a deterministic crash loop on every node that stored it, recoverable only by an
operator tool (35 S5 `--invalidate-block`). 11 I3 proposes `apply_block -> Result` (an
interim that turns the panic into an error); the structural fix is an infallible commit of
precomputed effects (parsed programs and PX tree appends computed during checking, R16 §3).
Consensus-adjacent, liveness-critical under a latent bug, not exploitable today (no known
disagreement) [source-read].

### 3.4 P4: no separable consensus core (R16-4), re-checked at HEAD

Still true: `tx` holds `builder`, `px_builder`, `scan`, `decoy` next to `validate`/`state`;
`px` holds `wallet`, `delivery`, `share`, `vault` next to `state`, `tree`, `prove`;
`tx/src/px.rs:36` imports `CIPHERTEXT_BYTES` from the wallet delivery module; emission is
in `chain/src/emission.rs` [source-read]. Mitigated by the fingerprint pin (a change is
now caught), not solved (§2.2).

**Prior art on how to separate.** libbitcoinkernel's two stated principles are the right
ones for BlackSilk: "Reusing existing code … allows us to be continually integrated … and
benefit from our extensive test suite" and "Incremental decoupling instead of building from
scratch … allows us to avoid having to prematurely optimize for a 'perfect' boundary". The
kernel "purposely does not include any P2P networking, JSON RPC … a wallet". Its
predecessor, libbitcoinconsensus, shows the failure mode of a boundary with no in-tree
user: "It took nearly two years after the activation of taproot for support to land" in
its API (the kernel author's write-up), and it was deprecated. Lesson: a consensus crate
must be used by the node itself (dogfooded), and extracted by moves verified by the
existing tests, not rewritten.

### 3.5 P5: state commitment and divergence detection (R16-9)

Unchanged: no state digest exists. My position differs from R16 in one respect. R16
recommended not adding a digest before the effects model, because "a state digest computed
by today's ad hoc apply code would pin today's accidental orderings into consensus". That
reasoning applies to a **committed** digest only. A **node-local** digest is not consensus,
can be redefined freely, and gives the seven-device trial the one piece of evidence it
lacks: immediate, attributable detection of state divergence between devices (today it
surfaces only when a later transaction is valid on one node and not another). 35 S7 already
plans a `state-delta` digest in `tx/src/state.rs` for its checkpoint binding. One digest
should serve both. Recommendation: node-local digest P1 before the trial (owner 35,
definition reviewed by 46), logged per block and exposed in `/info`, compared by labnet and
by the trial sampler. The committed digest stays P3 (activation through the schedule, after
the effects model).

### 3.6 Staged ADR: consensus separation (ADR-46-1)

**Status:** proposed. **Context:** R16-4/5/6/9/11, §3.2–§3.5, the v3 freeze plan, and
decisions.md (net.rs split before the waves; ADR-28-1 PX-only contracts; 29's Wasm freeze).

**Decision.** Separate consensus from wallet, prover and I/O code **incrementally, by moves
and derivations that the golden corpus proves neutral**, in five stages. No stage changes
consensus except E, which is an activation.

| Stage | When | What | Consensus | Evidence gate |
|---|---|---|---|---|
| **A0** | Now, before wave 1 | `net.rs` move-only split (§5.1); `.git-blame-ignore-revs`; the ADR recorded; a **consensus-surface file list** (the files whose edits change consensus bytes or verdicts) for 47's CONTRIBUTING and 43's CI trailer check (P1-16) | none | p2p/node/fuzz suites green; public API unchanged; line-multiset check |
| **A1** | Waves 1–2 (pre-freeze), small, verdict-neutral | (a) `Transaction::effects() -> TxEffects` (key images, output keys, nullifiers, contract id, record commitments, bridge in/out) in `tx/src/types.rs`; `conflict_keys`, `stem_keys`, `input_rings`, `is_px`/`class_of` derived from it (after D8 lands); (b) `validate::check_stateless_cheap(&Transaction, &TxRules)` as the single cheap dispatch, used by the three `validate_*` functions, block phase 1 and `admit_tx`; (c) move `CIPHERTEXT_BYTES` (and the other record-format constants) to a consensus-side module `px/src/format.rs`, with `delivery.rs` const-asserting its layout equals it; (d) node-local state digest (§3.5, 35 S7); (e) endorse 29 W29-2/W29-5 (contracts out of the workspace, `schnorr`/`membership`/`claims` behind a feature) — R16-11 closes | none | property tests: old == new for conflict keys, stem keys and cheap verdicts over the tx corpus (11 I1) and random mutations; fingerprint pin unchanged; `px/tests/delivery.rs` |
| **B** | The v3 freeze | Freeze the consensus corpus (01 vectors, 11 tx golden, 19 Hk vectors, 22 golden proofs) and the fingerprint. **Declare the consensus core frozen**: every later diff that changes the corpus is a consensus change | (the v3 rules themselves, owned by their workstreams) | the corpus |
| **C** | After the trial; refactor behind the frozen corpus | (1) crate move: wallet-side modules out of the consensus graph — `tx::{builder, px_builder, scan, decoy}` → `blacksilk-wallet-core`; `px::{wallet, delivery (non-const), share, vault}` → `blacksilk-px-wallet`; emission → `consensus`. (2) the effects model proper: `check_block(block, view, epoch) -> Result<BlockEffects, BlockError>` and `commit(BlockEffects)` **infallible by construction** (parsed programs and PX tree appends precomputed at check; closes R16-6 and replaces 11 I3's interim `Result`); mempool revalidation, conflict keys and stem keys derived from the same effects. (3) verifier dispatch by `epoch.verifier_id` and the `VerifiedCache` key including it (10 item 6 / F10-7; 28 W28-9; R16-8) — **before** any second verifier. (4) the chain actor (34) is a sibling item, not part of this ADR | none (corpus-verified) | the frozen corpus replayed byte-identically; 34's E1–E4 for the actor; differential old/new apply over random apply/undo sequences |
| **D** | Pre-mainnet | Frozen per-verifier crate `bs-verifier-v1` with a project-owned proof codec (R16-3, R16-14); optionally a single `blacksilk-rules` facade crate re-exporting consensus, tx rules, state transition and schedule, used by the node itself (the libbitcoinkernel dogfooding lesson) | none | byte-identical codec over the corpus and golden proofs |
| **E** | By activation height, through the schedule | Committed state digest (coinbase or header, R16-9 option 1 then 2); a new tx kind added through the effects model; v1 turnstile steps (R16-10) | **CONS** | full consensus discipline (brief §3) |

**Alternatives considered.**

| Alternative | Why not (now) |
|---|---|
| Build a `consensus-core` crate now, before the freeze | Moves hundreds of lines across crates while 30+ workstreams edit them, before the corpus that would prove neutrality is frozen. Violates "no rewrites" and the kernel lesson (incremental, test-backed). Stage C does it after B |
| A `TxKind` trait object per kind (R16 §3 sketch) | Four kinds, one closed enum, exhaustive `match` is already the compiler-checked form; a trait adds dynamic dispatch and a second place to forget an effect. An `effects()` method on the enum returning one struct gives the same "cannot forget a key" property. Revisit if kinds grow past about six |
| Keep restatements, add tests | That is today's state after F1; it catches drift only where someone wrote the test |
| Committed state digest in v3 | R16's objection holds for a committed digest (it would freeze today's apply order); node-local first (§3.5) |
| Split `consensus` by moving `chain/src/manager.rs` fork choice into `consensus` | Fork choice there is node policy tied to storage order (H1 body-complete rule); it stays in `chain` |

**Consequences.** Good: wallet and prover edits cannot change consensus by dependency
direction (after C1); rules and effects are stated once; emergency upgrades are table
entries plus a frozen verifier crate. Costs: crate churn after the trial (C1 is L); the
effects model must be proven neutral on the corpus; ownership of `tx/src/types.rs` gains a
46 item in A1.

**Invariants (never change, carried into every stage):** full-review §8 items 1–31,
especially: one header-rule definition; replay = live; fsync before apply; the mempool
never changes a block verdict; canonical encodings; no admin keys; the kernel single-source
principle; the lock-ordering rule (item 25) in any module layout.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F46-1** | Medium (integration/review risk; architectural) | Not implemented (split decided) | `p2p/src/net.rs` (2,934 lines; +65 % since R16) | ≥ 12 workstreams edit one file, several in the same functions (`run_connection`, `maintenance_loop`, `admit_tx`, `handle`); a mis-resolved conflict in `stem_or_fluff` or `penalized` regresses a privacy or ban rule without an accountable owner | High [source-read + dossier plans] |
| **F46-2** | Low | Not implemented | `p2p/src/net.rs:2267-2286` vs `tx/src/validate.rs:592-672, 940-962` | The cheap stateless dispatch (structure, balance, per kind) is restated in P2P. A new cheap stateless rule added to a `validate_*` function but not to `check_structure`/`check_px_structure` would be skipped by `admit_tx`: the relayer is then classified by the later full check instead, and a contextual reject may be cached where a stateless penalty was due. Policy drift (scoring), not validity | High [source-read] |
| **F46-3** | Low (confirms and narrows R6 MP-9) | Partially implemented | `p2p/src/net.rs:2147-2168, 2155`; `chain/src/mempool.rs:96-133` | `stem_keys` lacks the contract-id key that `conflict_keys` has: two deploys of the same contract can both enter the stem; the second is dropped only at fluff (one wasted verification per variant, rate-limited). `is_px` and `input_rings` re-derive what `class_of` and `key_images` already give. After D8 (option B) the output-key gap disappears, the contract-id gap remains | High [source-read] |
| **F46-4** | Low (R16-4 re-rated from Medium) | Partially implemented | `tx/src/px.rs:36`; `px/src/delivery.rs:90`; `px/src/fingerprint.rs:270` | The consensus record-ciphertext length still lives in the wallet delivery module. A delivery-format change now fails the fingerprint pin, so it is caught; the layering still makes a wallet PR a consensus PR | High [source-read] |
| **F46-5** | Low–Medium (liveness under a latent bug; R16-6 consequence changed) | Partially implemented | `tx/src/state.rs:193, 220`; `chain/src/manager.rs:917` | Any future validate/apply disagreement becomes a deterministic crash loop at replay on every node that stored the block (fail-stop re-panics at the same height); recovery needs an operator tool (35 S5) | Medium [source-read; no known trigger] |
| **F46-6** | Informational (register correction) | — | full-review register row R10-2/R16-6; P0-8 | The "three remaining poison-recovery sites in `p2p/src/net.rs` (323, 442, 446)" no longer exist: every lock in `net.rs` goes through `lock_or_exit`, and `with_chain`/worker task panics call `fatal`. The only `into_inner()` recoveries left in chain/p2p/node are `chain/src/manager.rs:76,83` (the `CachedPow` cache map), which is a cache and not consensus state. P0-8 can be closed by 47 after the coordinator confirms | High [grep + source-read] |
| **F46-7** | Informational | Partially implemented | `consensus/src/schedule.rs` (`verifier_id`) | R16-1 is now partially implemented on `rebuild/core` (schedule, branch id, header version per epoch, `UnknownUpgrade` not penalized). Verifier dispatch is absent (same as 10 F10-7, 22); no new work beyond theirs | High |
| **F46-8** | Medium (process/integration risk) | Not implemented | `chain/src/manager.rs` (1,459 lines), `tx/src/validate.rs` (1,132), `wallet/src/wallet.rs` (**3,333**) | The same hotspot pattern as F46-1: `manager.rs` is edited by 01, 02, 07, 09, 10, 11, 12, 31, 34, 35; `validate.rs` by 10, 11, 13, 14, 15, 28, 34, 35; `wallet.rs` by 13, 17, 18, 21, 28, 37, 38, 39. The decisions log already splits `validate.rs` and `node/src/lib.rs` ownership by function; the files themselves are not split | High [wc + dossier plans] |
| **F46-9** | Informational (planned effect) | — | every `log::` call moved by the split | The default `log` target follows `module_path!()`; after the split, targets gain a suffix (`blacksilk_p2p::net::headers`). Filters still match (prefix rule, env_logger 0.8.4 `filter/mod.rs:366`); printed targets and any external grep on the exact target change | High [source-read] |

**Challenges to existing reports.**
- **R16-4 severity:** Medium → Low while the fingerprint pins every consensus constant
  (F46-4). The structural recommendation stands (Stage C1).
- **R16-9 ordering:** a node-local digest does not pin anything into consensus, so it does
  not need to wait for the effects model (§3.5).
- **R16 §12 C4 ("split `net.rs`", P3):** now P0-process, as the coordinator decided; the
  file grew 65 % and phase 2 multiplies its editors.

---

## 5. Implementation plan for phase 2

### 5.1 The `net.rs` split (deliverable 1)

#### 5.1.1 Layout

Rust Reference: a module's children live in `net/<child>.rs` next to `net.rs` (the
non-`mod.rs` form "is encouraged"). **`p2p/src/net.rs` stays the module root** and shrinks;
children go in `p2p/src/net/`. No `#[path]` attributes.

| New file | Items moved (verbatim, with their doc comments) | Approx. lines | Owner after the split |
|---|---|---|---|
| `p2p/src/net.rs` (root) | module doc + concurrency rules (1-12); `mod` declarations; `pub use` re-exports (`config::{NetConfig, PeerInfo, NetStats}`, `blocks::BLOCK_WINDOW_BYTES`); `SharedChain`, `POISONED_EXIT_CODE`, `lock_or_exit`, `fatal` (42-67); `Network` struct (364-368) and `impl Network` (381-544) | ~270 | **34** (public facade; replaced by `ChainHandle` in Stage 2). 13's `#[doc(hidden)]` stempool accessor and 31's presync status getter are append-only hunks here |
| `net/config.rs` | `NetConfig` + `impl NetConfig` (107-165), `PeerInfo` (167-177), `NetStats` (179-197) | ~95 | **Append-only shared**; owner of record **32** (connection limits). New fields from 04 (clock), 30 (`PeerInfo.sid`), 31 (`min_chain_work`/`SyncParams`), 33 (trickle), 34 land as separate additive hunks |
| `net/state.rs` | `Peer` (199-242), `StemEntry` (244-251), `State` (253-302), `BlockJob` (304-315), `HeaderBatch` (317-326), `Inner` (347-362), `unix_now` (370-375), `short` (377-379); `impl Inner { state, chain, with_chain, save, send, send_now }` (546-607) | ~240 | **34** (lock access; becomes `chain_access.rs`). Struct fields are **append-only** for every other owner; each field block keeps its owner comment |
| `net/peers.rs` | `CONNECT_TIMEOUT`, `SEED_RETRY`; `impl Inner { misbehave, penalize, ban_addr, misbehave_departed }` (609-671); `accept_loop` (804-846), `inbound_count`, `same_ip_count` (848-858), `HandshakeSlot` + impls (860-892), `connect_outbound` (894-924), `advertised_listen` (926-940), `maintain_outbound` (2761-2852) | ~330 | **32** (eclipse, inbound eviction, /64-/16 caps, bans). 30 W2 (transport failure never bans) edits `run_connection`, not this file |
| `net/addr_relay.rs` | `on_get_addr` (1328-1351), `on_addr` (1353-1387) | ~65 | **32** (addr rate limit, per-source limits); **33** adds the per-network GetAddr cache as a scheduled hunk |
| `net/conn.rs` | `HANDSHAKE_TIMEOUT`, `IDLE_TIMEOUT`, `OUTBOX`, `BULK_OUTBOX`, `HANDSHAKE_UNKNOWN_FRAMES`; `recv_msg` (942-951), `run_connection` (953-1223), `write_loop` (1225-1244); test `control_messages_overtake_queued_block_frames` | ~320 | **30** (handshake, pre-Verack cap W1, transport arm W2), with **34** holding an exclusive window for Stage 1a (fast/slow lanes in the read loop) and 1b (handshake height from the snapshot) |
| `net/dispatch.rs` | `requested_by_us` (1248-1274), `handle` (1276-1326) | ~85 | **34** (lanes) |
| `net/headers.rs` | `HEADERS_TIMEOUT`; `queue_key` (328-335); `impl Inner { header_queue_room, warn_unknown_upgrade, request_headers, request_headers_after }` (673-762); `in_grace` (1389-1391); `on_headers` … `on_header_error` (1393-1827: `HeaderOutcome`, `penalized`, `header_worker`, `sender_live`, `ANTI_DOS_BLOCKS`, `anti_dos_threshold`, `worth_verifying`, `verify_headers`); tests `header_queue_origins_ignore_the_port`, `unknown_upgrades_are_not_penalized` | ~560 | **31** (S1 moves `anti_dos_threshold`/`worth_verifying` to `chain/src/sync_policy.rs`; S2, S5, S7, S8; 04 W3/W9 hooks through 31) |
| `net/blocks.rs` | `BLOCK_TIMEOUT`, `BLOCKS_IN_FLIGHT`, `pub const BLOCK_WINDOW_BYTES`, `SERVE_BLOCKS_PER_REQUEST`, `UNREQUESTED_QUEUE`; `on_get_blocks` (1829-1851), `release_block_slot`, `on_block`, `block_worker`, `schedule_downloads`, `window_has_room` (1853-2039); test `the_byte_window_is_the_binding_limit` | ~240 | **31** (S6; 02 W-3 through 31; 10 item 5 constant) |
| `net/relay.rs` | `TX_TIMEOUT`, `ANNOUNCED_CAP`; `remember` (337-345); `impl Inner { announce_tx }` (775-799); `on_inv_tx` (2041-2084), `on_get_tx` (2086-2118), `retry_tx` (2120-2137); test `remembered_ids_are_capped` | ~150 | **33** (trickle, shuffled invs, inbound trickle timer R8-16) |
| `net/admission.rs` | `RECENT_REJECTS`; `impl Inner { reject_cache }` (764-773); `decode_tx`, `is_px`, `input_rings`, `ctx_rejected`, `ctx_reject`, `admit_tx` (2139-2316 minus `stem_keys`), `SIGNATURE_BURIAL`, `provably_invalid_signature`, `proven_invalid`, `on_invalid_tx`, `on_tx` (2318-2438), `on_stem_tx` (2446-2498) | ~330 | **34** (Stage 4 "check, verify outside, re-check"); earlier hunks scheduled for **11** (I5 `is_stateless_at`; A1b cheap dispatch), **12** (W3 fee pre-check), **14** (item 4 deploy token), **46** (A1a derived keys) |
| `net/stem.rs` | `stem_keys` (2146-2153), `unstem_key_images` (2440-2444), `stem_or_fluff`, `send_held_local_txs`, `fluff` (2500-2590) | ~110 | **33** (Dandelion++, never-change item 23) |
| `net/maintenance.rs` | `PING_INTERVAL`, `PONG_TIMEOUT`, `SAVE_INTERVAL`; `maintenance_loop` (2594-2759) | ~175 | **34** (scheduler; F34-2 snapshot reads). After commit S2 (below) the loop body is calls into owner modules |

`p2p/src/lib.rs` keeps `pub mod net;` and its re-export line unchanged; only its module
table comment gains the children (doc-only, commit S3). Name collision check: `net::peers`
does not clash with the crate-level `addrman`/`dandelion` modules; the Dandelion glue is
named `stem.rs` to avoid confusion with `crate::dandelion`.

**Why these boundaries.** They follow owners, not line counts: each file has one owner
from the roster (30 transport/handshake, 31 sync, 32 peers/addr, 33 relay privacy, 34
scheduling/lock access). The two residual shared files (`config.rs`, `state.rs`) are
append-only by rule, because `State` is one struct and splitting it into per-owner
sub-structs is a refactor, not a move (it is proposed as a follow-up by each owner, e.g.
31's `SyncState`, 33's `RelayState`).

#### 5.1.2 Commits (each separately reviewed; no behaviour change in any)

- **S0 — baseline (no code).** Coordinator announces a `net.rs` freeze (no open branch
  touches it; status.md shows all agent worktrees were removed). Record on `9e422d8`:
  `cargo test -p blacksilk-p2p -- --list`, the node and fuzz build, and the public API
  (`cargo semver-checks check-release -p blacksilk-p2p --baseline-rev 9e422d8` if the tool
  is available on the machine; otherwise the compile of every dependent without edits is
  the check).
- **S1 — move-only.** Create the files of §5.1.1; move items **verbatim** (bodies, doc
  comments, attribute lines, blank lines within items); add only `mod`/`use` lines, `pub(super)`
  on items and fields used across siblings, and each new file's one-paragraph `//!` header.
  Unit tests move into a `#[cfg(test)] mod tests { use super::*; … }` in the module of the
  item they test. `rustfmt` runs.
- **S2 — extract-only (optional, recommended).** Three extractions, each a contiguous block
  cut into a function in its owner's module and called at the same place, with the same
  locks, the same `.await` points and the same order:
  - `maintenance_loop`: `tick_dandelion` (→ `stem.rs`: lines 2603-2624), `announce_tip`
    (→ `headers.rs`: 2626-2644), `tick_peers` (trickle, pings, timeouts: 2646-2712; →
    `maintenance.rs` stays, or split between `relay.rs`/`blocks.rs` if 33/31 ask),
    `resync_behind_peers` (→ `headers.rs`: 2714-2732), `save_if_changed` (→ `peers.rs`:
    2740-2757);
  - `handle`: the `NotFound` arm → `blocks::on_not_found` (31 needs it for 02 W-3), the
    `GetHeaders` arm → `headers::on_get_headers`, the `Pong` arm → `conn::on_pong`;
  - nothing in `run_connection` (30 and 34 restructure it in their own reviewed work; a
    mechanical cut there crosses early `return`s and the reader/writer borrows).
- **S3 — docs.** `p2p/src/lib.rs` module table; `docs/p2p.md` "where" references;
  `.git-blame-ignore-revs` with the S1 and S2 hashes; a note in `docs/reviews/` that R8/R10/
  R16 `net.rs:NNN` references predate the split (47 updates the register pointers).

#### 5.1.3 Owner of the split

46 performs S0–S3 in one worktree in an exclusive window before wave 1 (decisions.md "Agent
31"). The diff review is done by a different agent (the coordinator, or 50), per §5.1.4.

#### 5.1.4 The moved-code-only diff review (acceptance procedure)

A reviewer accepts S1 only if all of these hold:
1. **Colour-moved diff.** `git diff -M --color-moved=dimmed-zebra
   --color-moved-ws=allow-indentation-change 9e422d8 S1 -- p2p/src` shows every removed line
   of `net.rs` as moved. The only non-moved added lines are: `mod`/`use` lines, the
   `pub(super)` tokens, `#[cfg(test)] mod tests {` / `use super::*;` / closing braces, and
   the new `//!` headers. The reviewer lists any other non-moved line; there must be none.
2. **Line multiset.** Mechanical: take the old `net.rs` lines and the new
   `net.rs` + `net/*.rs` lines; delete `use`/`mod`/`//!` lines and the test-module wrapper
   lines; strip the `pub(super) ` token; compare the two sorted lists (`sort | comm -3`).
   The output must be empty except for rustfmt re-wrapping of `use` groups (listed).
3. **Public API.** `cargo semver-checks … --baseline-rev 9e422d8` reports no change, or (if
   the tool is not approved by 44) `node`, `fuzz`, `p2p/tests/*` compile with **zero** edits.
4. **Tests.** `cargo test --locked -p blacksilk-p2p` (lib, `network`, `withheld_body`,
   `fuzz_message`), `-p blacksilk-node`, the fuzz workspace build; the p2p PX network tests
   in the proving tier. Same pass counts as S0. The only difference in `--list` is the 5
   moved unit-test paths (`net::tests::x` → `net::<child>::tests::x`).
5. **Lints.** `cargo clippy --locked --workspace --all-targets -D warnings` and
   `cargo fmt --check` clean. No new `#[allow]`.
6. **Blame.** `git blame -C -C` on two sample functions attributes their lines to their
   original commits.
7. **Commit message** states: "move-only; no behaviour change; log targets gain a
   submodule suffix (filters unaffected)".

S2 uses the same procedure except item 2, which is replaced by: each extracted function's
body equals the removed block (colour-moved), the call sits exactly where the block was,
and no lock guard or `.await` moved across the cut (reviewer checks each of the ≤ 9 cuts).

#### 5.1.5 Tests, docs, size, priority

No new tests (a move needs none); all existing suites are the oracle. Docs: S3. Difficulty
S (S1 ≈ half a day including review), S (S2). **Priority: P0 (process), before wave 1.**
Consensus: none. Identity: none. Externally visible: log target strings only (F46-9).

### 5.2 My other work items (ADR-46-1 stages A0/A1)

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Diff. | Pri |
|---|---|---|---|---|---|---|---|---|
| 46-1 | `net.rs` split S0–S3 (§5.1) | `p2p/src/net.rs`, new `p2p/src/net/*.rs`, `p2p/src/lib.rs` (doc table), `.git-blame-ignore-revs` (new) (46) | none | none | existing suites; §5.1.4 | `docs/p2p.md` pointers | S | **P0** |
| 46-2 | ADR-46-1 recorded, plus the consensus-surface file list | new `docs/reviews/adr-46-consensus-separation.md` (46); the file list feeds 47's CONTRIBUTING and 43's CI trailer check | none | none | — | the ADR | S | **P0** |
| 46-3 | `Transaction::effects() -> TxEffects` and derivations (A1a) | `tx/src/types.rs` (46 writes the accessor; 11 reviews), `chain/src/mempool.rs::conflict_keys` (12 applies), `p2p/src/net/stem.rs::stem_keys` (33 applies, adds the contract id), `net/admission.rs::{input_rings,is_px}` | none (policy: stem pool gains the contract-id key) | none | property: new `conflict_keys` == old over the 11 I1 corpus and random txs; stem keys ⊇ old; p2p: two same-contract deploys stemmed → second dropped before verification | blocks.md §7, p2p.md §8 | S | P1 (after D8 lands) |
| 46-4 | Single cheap-stateless entry (A1b) | `tx/src/validate.rs` new `check_stateless_cheap` (**11** writes), callers in `validate.rs` (11) and `net/admission.rs::admit_tx` (admission owner) | none | none | differential: old admit verdict == new over the tx corpus with every stateless-rule mutation; `validation_order` unchanged | transactions.md §8 order note | S | P1 |
| 46-5 | Consensus-side record-format module (A1c) | new `px/src/format.rs` (46; `CIPHERTEXT_BYTES` and the record-length constants), `px/src/delivery.rs` (const-assert only; 37 reviews), `tx/src/px.rs:36` import (11), `px/src/fingerprint.rs` path (40) | none | fingerprint **value unchanged** (same constant) | fingerprint pin unchanged; `px/tests/delivery.rs` | px.md §11 | S | P2 |
| 46-6 | Node-local state digest definition (A1d) | spec in the ADR (46); implementation in `tx/src/state.rs` (**35**, S7), `/info` field (36), labnet compare (09/45) | none (node-local) | none | digest equal across labnet nodes; changes when one output is flipped in a test chain; replay == live | blocks.md §8 | S | P1 (trial evidence) |
| 46-7 | Split proposals for the other hotspots (F46-8), same procedure as §5.1 | `chain/src/manager.rs` → `manager.rs` + `manager/{pow_cache (07 W4 already), sync, headers_api, template, replay}.rs`; `tx/src/validate.rs` → `validate.rs` + `validate/{errors, tx, block, revalidate}.rs`; `wallet/src/wallet.rs` → by concern (v1 scan/apply, send, PX, vault) | none | none | as §5.1.4 | — | S each | P1 (coordinator decision Q1) |
| 46-8 | Stage C design note: crate moves and `BlockEffects`/infallible commit | ADR appendix (46), with 11, 21, 35 | none | none | test plan only | ADR | M | P3 (design P2) |

### 5.3 File-ownership map for all phase-2 implementation work (deliverable 2)

**Rules of the map.**
- One **owner** per file (or per function group where decisions.md already split a file).
  Others land **scheduled hunks** in the owner's merge window, listed in "also edited by".
- **Append-only shared** files: owners add items; nobody reorders or rewrites others'
  items.
- **Order** gives the merge sequence where two workstreams edit the same code.
- Items from not-yet-filed dossiers are **provisional** (roster scope).
- "New" files are owned by their creator.

#### A. Consensus crates

| File | Owner | Also edited by (scheduled hunks) | Order / notes |
|---|---|---|---|
| `consensus/src/chain.rs` | 01 | 07 (`next_seed_for`, `BlockTemplate.next_seed`; 07 owns the next-seed plumbing, 09 I3 consumes it), 31 (S6 `is_ancestor`, S7 `BranchContext` — 01 reviews), 02 (W-9 `mark_invalid`), 04 (W10 `saturating_add`), 01 (F-05 reorder) | F-05 and 03 W2 before 01 freezes vectors; 31 S7 after freeze is policy-only (no rule change) |
| `consensus/src/params.rs` | 40 (v3 genesis constants, decision) | 01 (F-06 `check()`, review), 03 (W2 DAA field) | 03 W2 before freeze |
| `consensus/src/difficulty.rs` | 03 | — | W1 harness first, W2 before freeze |
| `consensus/src/pow.rs` | 07 | 06 (W7 `pow_hash_batch` default method, after 07 W1), 09 (I3 `next_seed_height` → implemented by 07) | 07 W1 first |
| `consensus/src/schedule.rs` | 01 | 10 (F10-7, read), 46 (ADR) | — |
| `consensus/src/lib.rs` | 01 | 08 (W6 big-endian `compile_error!`, decided) | — |
| `consensus/tests/golden.rs`, `consensus/tests/vectors/` | 01 | 03 (new DAA vectors), 04 (time vectors in its own `time_edges.rs`) | freeze last |
| `consensus/tests/properties.rs` (new) | 01 | 03 W3 (same file, agreed) | — |
| `randomx/src/lib.rs` (`mod` lines) | 05 | 06, 08 (serialized `mod` edits) | 05 C1 first |
| `randomx/src/{vm,superscalar,fpu,argon2d}.rs` | 06 | 05 (visibility/cfg(test) only, first), 08 (W5 folded into 06's `vm.rs` work) | 05 C1–C3 green before 06 W3–W7 |
| `randomx/src/dataset.rs` | 06 | 07 (`try_new`, additive; 05 reviews) | 07 before 06 W3 |
| `randomx/src/{conformance_kats,fpu_oracle,generator_conformance}.rs`, `randomx/tests/*`, `randomx/tests/data/` | 05 | 06 (`reference.rs`, `tests/equivalence.rs` — agree names) | — |
| `randomx/src/{selftest,determinism_tests}.rs` | 08 | — | — |
| `crypto/src/hash.rs` (tag registry) | 19 | 12 (ring-digest tag), 16 (2 batch tags), 30 (P2P tags), 35 (`state-delta`), 37 (seed/hedge tags), 15 (W4 vectors in tests) | append-only tags; 19 item 7 `Tag` typing last |
| `crypto/src/clsag.rs` | 15 | — | W3, W2 before W1 |
| `crypto/src/bulletproofs_plus.rs`, `crypto/src/generators.rs` | 16 | 18 W10 (via 16) | — |
| `crypto/src/nonce.rs` | 18 | — | 37 K2 before 18 pins |
| `crypto/src/keys.rs` | 37 (`hedge_secret`) | 17 (tests, `insert` assertion) | — |
| `crypto/src/stealth.rs`, `crypto/src/janus.rs` | 17 | 19 item 8 (`px_context` signature) | — |
| `crypto/src/{membership,schnorr,claims}.rs`, `crypto/src/lib.rs`, `crypto/Cargo.toml` | 18 (W1, W6) | 29 (W29-5 feature gate, after 18) | R16-11 closes with W29-5 |
| `crypto/tests/*` | per file creator (15 `clsag_*`, 16 `bpp_*`, 17 `stealth_vectors`, `janus_properties`) | `malleability.rs`: 15 and 16 (serialize) | — |
| `tx/src/validate.rs` | split per decisions.md: **11** single-tx functions, `TxError`, classification, capacity rule; **10** block phases, parallelism, cache parameter; **13** `check_uniqueness_of` and C4 removal | 15 (W1 T11 structural check, via 11), 14 (item 6 T8, via 11), 28 (PX6 window rule), 34 (Stage 4 split API, via 11), 35 (`VerifyMode`, via 10), 46 (A1b entry, via 11) | 13 D8 + 11 I3 trait edits in **one** commit; 10 item 1 before 11 I3; 46-7 split (if decided) before all |
| `tx/src/types.rs` | 11 | 14 (R12-2 weight, consensus), 10 (item 2, same rule as 14 — one implementation, owner 14), 46 (A1a `effects()`) | 14 R12-2 before freeze; 46-3 after D8 |
| `tx/src/px.rs` | 11 | 15 (W1), 28 (W28-1 ABI, W28-2 window), 22 (W7 conditional), 19 (item 8), 46-5 (import) | — |
| `tx/src/params.rs` | 14 | 11 (I8 asserts), 16 (one line), 10 (verifier id, F10-7) | — |
| `tx/src/state.rs` | 21 | 13 (D8: remove `one_time_keys`), 11 (I3 `apply_block -> Result`), 35 (S4 undo slimming, S7 digest, S11 trait later), 28 (registry `abi`/`out_words`), 36 (W6 range accessor) | D8 first, then 11 I3, then 35 S4 |
| `tx/src/builder.rs`, `tx/src/px_builder.rs` | 18 (hedging) | 14 (`max_weight` → `weight.rs`, I6 via 11), 18 W5 (coinbase context) | Stage C moves them out |
| `tx/src/decoy.rs`, `tx/src/scan.rs` | 38 (provisional) / 17 (`scan.rs` `ScanOutcome`) | 13 (F13-7: no filtering) | — |
| `tx/tests/*` new files | creators: 11 (`golden_tx`, `rule_vectors`, `roundtrip`, `classification_property`), 21 (`px_nullifier_rules`), 28 (`px_window`), 18 (`rng_failure`) | shared `tx/tests/common/mod.rs`: additive helpers, 11 owns | — |
| `px-core/src/kernel.rs`, `px-core/src/record.rs` | 20 | 19 (comments only), 21 (tests, doc) | **one** kernel rebuild (43) after 20 W1 + W5, 28 W28-1 |
| `px-core/src/call.rs` | 28 (`function_prefix`) | 20 | same rebuild window |
| `px-core/src/hash.rs` | 19 (comments) | — | ELF id verified unchanged |
| `px/src/prove.rs` | 22 | 10 (`verify_decoded`), 20 (W5 budgets, W6), 28 (`statement`), 27 (W7 after 10) | 10 item 1 before 27 W7 |
| `px/src/state.rs`, `px/src/tree.rs` | 21 | 11 (size accessor), 35 (S4 PX undo delta; 21 reviews) | 21-D before 11 I3; 21-F / 35 S4 one owner: **35 writes, 21 reviews** |
| `px/src/wallet.rs` | 37 | 18 (W2 `HedgedStream`, W4 samplers) | 37 K2 before 18 |
| `px/src/delivery.rs` | 37 | 46-5 (const-assert) | — |
| `px/src/vault.rs`, `zkvm/guests/vault/*` | 28 | 20 (W7 call builder: 28 owns, 20 reviews) | vault rebuilt once with the kernel |
| `px/src/fingerprint.rs` | 40 | 19 (Poseidon2 instance), 22 (W4/W5), 46-5 | pins re-cut once before freeze |
| `px/src/share.rs` | 28 (doc) | — | — |
| `px/tests/*`, `px/examples/*` | creators: 20 (`kernel_spec`), 19 (`hk_vectors`, `domains`, `tree_binding`), 22 (`proof_limits`, `golden_proof`), 26 (`blinding`, `proof_length_campaign`), 27 (`proof_bench`, `span_profile`, `proof_corpus`), 37 (`key_vectors`) | `px/tests/unified.rs`: 20 owner, 28 adds W28-3 | — |
| `zk/src/lib.rs` | 22 | 26 (ZP-7, one coordinated change), 27 (W2 const, W4 guard) | — |
| `zk/src/params.rs` | 25 | 26 (ZP-8, review of eq. 17), 22 (doc wording) | decided |
| `zk/src/config.rs` | 26 (ZP-9) | 27 (W6 alt.) | — |
| `zkvm/src/**`, `zkvm/tests/**` | 23 | 26 (ZP-4, ZP-5 in `air/util.rs`, `air/trace.rs`, `prove.rs`), 22 (W3/W4 tests), 25 (W4 asserts), 27 (W7 memoization) | 23 W8 and 26 ZP-5 are the same type-state: **23 writes** |
| `third_party/**`, root `[patch]` | 24 (provisional) | 27 (W6 `p3-challenger`) | — |

#### B. Node-side crates

| File | Owner | Also edited by | Order / notes |
|---|---|---|---|
| `chain/src/manager.rs` | **34** (lock/actor surface) **with function-level owners**: 02 (`missing_bodies`, `keeps_body`, `sync_state` W-4, `template` W-5, W-7 park), 07 (hot-seed call sites; `CachedPow` → `pow_cache.rs`), 09 (`template_ready`, `Template.next_seed` via 07), 10 (step budget, thread count, cache wiring), 12 (`SyncOutcome`, disconnect loop, `finish_sync`, W4, expire call), 01 (replay sampling, template self-check, `rules_at`), 11 (I3 `Result` at the apply call), 31 (S6 passthrough), 35 (`open`, `replay_one`, `invalidate`, body accessors, S7) | decisions: 02 W-4 → 10 items 1/5 → 12 W1/W2 → 34 Stage 2. Strongly recommend the 46-7 split first (F46-8) |
| `chain/src/mempool.rs` | 12 | 14 (items 2, 3: two-budget `select`, sub-pools — 12 applies), 13 (D8: remove `OutputKey`), 10 (cache population), 46-3 (derived keys), 09 (I6 asserts) | D8 first |
| `chain/src/store.rs` | 35 | 10 (item 8 tombstones = 35 S5; 35 owns) | S1, S2 before freeze |
| `chain/src/{pow_cache,sync_policy,verify_cache,snapshot,actor,verify_pool}.rs` (new) | 07, 31, 10, 34, 34, 34 respectively | 35 (S10 snapshot is a *state* snapshot: name it `state_snapshot.rs` to avoid clashing with 34's `snapshot.rs`) | name clash flagged |
| `chain/src/emission.rs` | 01 | — | Stage C moves it to `consensus` |
| `chain/tests/*` new | creators: 01 (`block_rules`), 02 (`fork_choice_model`, `fork_choice_props`, `deep_reorg_px`), 12 (`mempool_stateful`), 13 (`c4_frontrunning`), 21 (`px_anchor_reorg`), 09 (`template`), 34 (`actor_equivalence`, `support/slow_store.rs`) | `activation.rs`: 02 adds cases; `manager.rs`: 10 (item 7), 04 (W7), 12 (W9) append-only; `mempool_conflicts.rs`, `revalidation.rs`: rewritten by 13 | — |
| `p2p/src/net.rs` + `p2p/src/net/*.rs` | per §5.1.1 | per §5.1.1 | split first |
| `p2p/src/transport.rs`, `p2p/src/message.rs` | 30 | 19 (tags live in `hash.rs`, not here) | — |
| `p2p/src/limits.rs` | 30 | 14 (item 4 deploy bucket; via admission owner) | — |
| `p2p/src/addrman.rs`, `p2p/src/addr.rs`, `p2p/src/socks5.rs` | 32 (provisional) | 30 (T-9 addr kinds) | — |
| `p2p/src/dandelion.rs` | 33 (provisional) | — | — |
| `p2p/src/{clock,presync,header_queue,chain_access}.rs` (new) | 04, 31, 31, 34 | — | `chain_access.rs` lands with 34 Stage 2 |
| `p2p/tests/network.rs` | append-only: every p2p owner adds tests in its own section | — | — |
| `p2p/tests/*` new | 31 (`sync_adversarial`), 30 (`transport_adversarial`), 34 (`liveness`), 04 (`time`), 13 (`frontrun`, optional) | — | — |
| `node/src/lib.rs` | split per decisions.md: **36** router, guard, serve, `/block` wiring; **09** `/template`, `/tip`; **34** `with_chain` | 27 (W4 `FIELD_BACKEND` in `/info`), 12 (W7 metrics), 02 (W-7 `/info` field), 04 (W3/W5 fields), 36 W6 | — |
| `node/src/main.rs` | 36 | 01 (flag), 04 (W4 sanity), 08 (W4 self-test), 34 (spawn actor), 35 (flags) | 34 last |
| `node/src/config.rs` | 36 | 01, 02, 04, 10 (`--verify-threads`), 31 (`--min-chain-work`), 35 | append-only flags |
| `node/src/fingerprint.rs`, `node/tests/deploy_configs.rs` | 40 | 03 (W4), 13 (rule revisions), 14 (weight samples), 16 (BP+ entries), 27 | re-pinned once before freeze |
| `rpc/src/lib.rs` | 36 | 04 (`Info`, `Template.curtime`), 07 (`next_seed_id`), 09 (`/tip`), 30 (`sid`), 36 (cookie) | additive `serde(default)` fields |
| `miner/src/main.rs` | 09 (decided) | 06 (W9 `--selftest`), 07 (planner wiring via 09), 08 (W4), 18 (W5 `--hedge-file`), 36 (`--rpc-cookie`), 04 (W5) | — |
| `miner/src/lib.rs` | 07 (`SeedPlanner`) and 09 (`run_loop`) — two disjoint sections | 04 (W5), 18 (W5) | — |
| `wallet/src/wallet.rs` | 37 (constructors, persistence) with section owners: 38 (`plans_for`, decoys), 39 (scanning/apply), 17 and 13 (one output per key image — **one** change), 18 (W3 `plans_for`, W4 vault), 21 (anchor call sites), 28 (vault flows) | — | serialize; strongly recommend the 46-7 split (3,333 lines) |
| `wallet/src/{seed,file,px,main,lib}.rs` | 37 (`seed.rs` new, `file.rs`, `main.rs`), 21 (`px.rs::anchor_height`), 39 (`px.rs` scanning) | 18, 27 (W5 hint, W8 flag), 36 (cookie flag) | — |
| `contracts/**`, root `Cargo.toml` members | 29 (W29-2), 46 reviews | 43 (CI) | — |

#### C. Tools, fuzz, CI, docs

| File | Owner | Also edited by |
|---|---|---|
| `tools/daa-sim/**` (new, workspace member) | 03 | 04 (strategies) |
| `tools/consensus-vectors/`, `tools/vectors/poseidon2_hk.py` | 01, 19 | 11 (tx vector script) |
| `tools/randomx-reference/` / `tools/randomx-refgen/` | 05 | — |
| `tools/monero-rx-fixtures/`, `tools/clsag-conformance/` (excluded) | 05, 15 | — |
| `tools/labnet/src/*` | 09 (I4) | 04 (clock offset), 36 (cookies), 45 (metrics), 46-6 (digest compare) |
| `tools/genesis/**` | 40 | 03 (gap test), 04 (W11) |
| `tools/px-verify-contract/`, `px-sdk/` (new) | 28 | — |
| `fuzz/**` | 41 | targets supplied by 15, 16, 17, 22, 23, 30, 31, 35; 29 (remove Wasm targets); 20 (`seeds.rs` kernel seeds) |
| `.github/workflows/ci.yml` | 43 | 05, 06, 27, 29, 42 (job specs) |
| `.github/workflows/randomx-determinism.yml` | 08 | — |
| root `Cargo.toml` (members, patch), `Cargo.lock` | 43 / 44 | 03 (daa-sim member), 29 (contracts out), 27 (patch entry via 24) |
| `clippy.toml` (new) | 43 | 19 (disallowed `node()`) |
| `.git-blame-ignore-revs` (new) | 46 | — |
| `docs/consensus.md` | 01 | 03 §4, 04 §5, 05/08 §9, 07 §3.1, 09 §3, 02 §8 |
| `docs/blocks.md` | 47 coordinates; sections: 02 §6, 12 §7, 35 §8, 36 §9, 37 §10 | 01, 10, 14 |
| `docs/transactions.md` | 47 coordinates; sections: 15 §6, 16 §7, 18 §10, 17 §3/§12, 11 §8/§16, 13 C4 rows | — |
| `docs/px.md` | 20 (§4), 28 (§7, §13), 21 (§3, §9), 19 (§2, §9.1), 11 (§11 rule ids), 37 (§3.1) | 47 |
| `docs/zk.md`, `docs/zkvm.md` | 25 (§9.3), 22, 23, 26 | 47 |
| `docs/p2p.md` | 31 (§6, §12), 30 (§3, §4), 34 (§6, §10 concurrency), 33 (§8), 32 (§9) | 47 |
| `docs/contracts.md` → rewrite; `docs/research/wasm-contracts.md` | 28 (move and rewrite) | 29 (banner) |
| `docs/hash-domains.md`, `docs/hash-agility.md` | 19 | — |
| `docs/reviews/adr-*.md` | 28, 29, 34, 46 | — |
| `docs/evidence/**` | the workstream that produced the run (09, 06, 27, 26, 45) | — |
| `docs/testnet.md`, `docs/testnet-v3-genesis.md` | 40 | 04, 08, 09, 36, 37 |

#### D. Conflicts found while building the map (for the coordinator)

1. **Next-seed plumbing** is proposed twice: 07 W5 and 09 I3 (`consensus/src/chain.rs`,
   `chain/src/manager.rs::Template`, `rpc`, `node /template`). Resolved above as 07 owns the
   plumbing, 09 consumes it in `main.rs` (consistent with decisions.md "Agent 07").
2. **R12-2 weight rule** is 10 item 2 and 14 item 1 (the same rule, decisions "Agent 10").
   One implementation: owner 14 in `tx/src/types.rs`; 10 owns the tests/benchmarks.
3. **Tombstones:** 10 item 8 and 35 S5 are the same item; owner 35.
4. **PX undo delta:** 21-F and 35 S4 are the same code; owner 35 writes, 21 reviews.
5. **Blinding type-state:** 23 W8 and 26 ZP-5(b) are the same change; owner 23.
6. **`snapshot.rs` name clash** in `chain/src/`: 34 (chain snapshot cell) vs 35 S10 (state
   snapshot for restart). Rename 35's to `state_snapshot.rs`.
7. **`p2p/src/limits.rs`** is named "owner 30" by 14; admission policy now lives in
   `net/admission.rs` (34). 14 item 4 lands via the admission owner; `limits.rs` itself stays 30.
8. **`/info` field sprawl:** 02, 04, 12, 27, 31, 46-6 all add fields. 36 owns the struct and
   merges them in one additive order.
9. **Fingerprint re-pins** (03, 13, 14, 16, 19, 22, 27): one owner (40), one re-pin before
   the freeze, not seven.
10. **`wallet/src/wallet.rs`** has 8 editors and is the largest file of the project; the
    coordinator should either split it (46-7) or run its edits strictly serially.

---

## 6. Dependencies and conflicts

- **30, 31, 32, 33, 34:** receive the split modules. 34 needs an exclusive window in
  `conn.rs`/`dispatch.rs` for Stage 1a right after the split; 31 needs S2 (the
  `on_not_found` extraction) for 02 W-3.
- **34:** the actor (Stage 2) replaces `state.rs` lock access with `chain_access.rs`;
  ADR-46-1 treats the actor as a sibling of the consensus separation, not part of it.
- **11, 12, 13, 33:** 46-3/46-4 derive conflict keys, stem keys and the cheap dispatch; they
  apply the call-site hunks in their own files.
- **35:** owns the node-local digest implementation (46-6); I specify the canonical input.
- **10, 22, 28:** verifier dispatch and the verified-cache key (Stage C3).
- **29:** R16-11 / W29-2 / W29-5 are endorsed; `contracts` → `exclude` (option c) is fine;
  no preference for `research/contracts-wasm`.
- **40:** fingerprint path change for 46-5 (value unchanged).
- **41/43/44:** `cargo semver-checks` or `cargo public-api` as a dev tool for the split review
  (44 to approve; not a project dependency); `.git-blame-ignore-revs`; the consensus-surface
  trailer check (43).
- **47:** stale `net.rs:NNN` pointers in R8/R10/R16 and the register; F46-6 register
  correction; CONTRIBUTING consensus-surface list.
- **50:** reviews the S1/S2 diffs (a different agent from the author).

## 7. Open questions for the coordinator

1. **Q1 — more mechanical splits before wave 1?** `chain/src/manager.rs` (10 editors),
   `tx/src/validate.rs` (8) and `wallet/src/wallet.rs` (8 editors, 3,333 lines) have the
   same problem as `net.rs` (F46-8). Same move-only procedure, same owner (46), same
   exclusive window. Recommended at least for `manager.rs` and `wallet.rs`.
2. **Q2 — S2 extract-only commit:** approve the `maintenance_loop` and `handle`-arm
   extractions, or keep S1 only and let owners extract in their own work?
3. **Q3 — review tool:** may the reviewer use `cargo semver-checks` (dev tool, not a
   dependency) on this machine, or is "all dependents compile unchanged" enough?
4. **Q4 — node-local state digest before the trial** (46-6 with 35 S7): P1 for the trial
   evidence, as proposed?
5. **Q5 — ADR-46-1 Stage C timing:** after the seven-device trial, and before a public
   testnet? The crate moves are large but mechanical; the effects model is where the
   R16-6 crash-loop class goes away.
6. **Q6 — who reviews S1:** coordinator or 50?

## 8. Sources

- Bitcoin Core, *Bitcoin Kernel Library Project Tracking*, issue #27587:
  https://github.com/bitcoin/bitcoin/issues/27587
- Bitcoin Core, *The libbitcoinkernel Project*, issue #24303:
  https://github.com/bitcoin/bitcoin/issues/24303
- Bitcoin Core PR #24322, *[kernel 1/n] Introduce initial libbitcoinkernel*:
  https://github.com/bitcoin/bitcoin/pull/24322
- sedited (TheCharlatan), *The Bitcoin Core Kernel*: https://thecharlatan.ch/Kernel/
- Bitcoin Core IRC meeting 2016-11-10 (net_processing split, PR #9260):
  https://bitcoincore.org/en/meetings/2016/11/10/
- Bitcoin Core, *Net split meta issue*, #33958: https://github.com/bitcoin/bitcoin/issues/33958
- Bitcoin Core `CONTRIBUTING.md` (refactoring and move-only rules):
  https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md
- Bitcoin Core `src/undo.h`: https://github.com/bitcoin/bitcoin/blob/master/src/undo.h
- Zebra RFC 0005, *State Updates*: https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html
- `zebra-state` 13.0.0, `SemanticallyVerifiedBlock`:
  https://docs.rs/zebra-state/13.0.0/zebra_state/struct.SemanticallyVerifiedBlock.html
- reth, `crates/consensus/consensus/src/lib.rs` (`HeaderValidator`, `Consensus`,
  `FullConsensus`): https://github.com/paradigmxyz/reth/blob/main/crates/consensus/consensus/src/lib.rs
- reth, `crates/evm/execution-types/src/execution_outcome.rs`:
  https://github.com/paradigmxyz/reth/blob/main/crates/evm/execution-types/src/execution_outcome.rs
- Sui documentation, *Life of a Transaction* (transaction effects):
  https://docs.sui.io/develop/transactions/transaction-lifecycle
- quinn-proto (sans-IO QUIC state machine): https://lib.rs/crates/quinn-proto
- Git, `git-diff` (`--color-moved`, `--color-moved-ws`, `-M`, `-C`):
  https://git-scm.com/docs/git-diff
- Git, `git-blame` (`-C` levels, `--ignore-revs-file`): https://git-scm.com/docs/git-blame
- GitHub Docs, ignoring commits in the blame view (`.git-blame-ignore-revs`):
  https://docs.github.com/en/repositories/working-with-files/using-files/viewing-and-understanding-files
- The Rust Reference, *Modules* (module source filenames, `mod.rs`, `path`):
  https://doc.rust-lang.org/reference/items/modules.html
- cargo-semver-checks (`--baseline-rev`): https://github.com/obi1kenobi/cargo-semver-checks
- env_logger 0.8.4 source, `src/filter/mod.rs:366` (prefix match), local cargo registry
  (read, not fetched).
