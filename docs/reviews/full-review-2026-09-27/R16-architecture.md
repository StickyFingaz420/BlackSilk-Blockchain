# R16: Whole-system architecture, technical debt and future protocol architecture

- **Reviewer:** R16 (chief architect view).
- **Date:** 2026-09-27.
- **Nature:** internal review, **not an audit**. Read-only. No builds were run.
- **Tree reviewed:** `rebuild/core` at **`9578517`**. That commit is newer than the brief's `f677e55`; it includes `16659ee` (mempool F1) and `9578517` (storage fail-safe load, seed-keyed PoW cache).
- **Evidence tags:**
  - **[math]**: mathematically established;
  - **[test: name]**: tested by the named test;
  - **[src]**: source-read;
  - **[assumed]**;
  - **[unknown]**;
  - **[web]**: external source.
- **Cross-references:** R1, R7, R10 and R12 were available in `C:/bszkeval/review/`. Where they already report something, this review cites them and adds only the architectural consequence.

---

## 0. Executive summary

**Verdict.** For a project of its age, BlackSilk's architecture is unusually disciplined:
- a strict crate split with `forbid(unsafe_code)` everywhere;
- one RandomX implementation;
- one definition of the header rules (`check_rules`, used by both `validate` and `precheck_batch`);
- typed consensus errors with a stateless/contextual split;
- a single-source kernel (`px-core`, compiled both natively and as the guest).

It is **not yet a mainnet-grade architecture**, for three structural reasons:

1. **No consensus-rule schedule.** Every consensus change needs a new genesis:
   - `HEADER_VERSION`, `TX_VERSION` and `PROOF_VERSION` are hard equalities;
   - the PX kernel is a process-wide singleton;
   - there is no `rules_at(height)`.

   This is acceptable for a testnet. It is fatal for a mainnet, and the **v3 genesis is the cheapest moment to install the mechanism** (R16-1).
2. **No consensus golden corpus.** Almost every consensus test is self-consistent: code builds a transaction and the same code validates it. Only genesis ids, the kernel and vault program ids and the Poseidon2 permutation are pinned. A refactor, a dependency bump (postcard, serde, Plonky3) or a "harmless" cleanup can change tx ids, signature messages, proof encodings or state transitions **without any test failing**. Every later refactor in this report depends on fixing this first (R16-2, R16-3).
3. **The consensus core is not a unit.** Consensus rules are spread over about 8 crates and mixed with wallet, prover and I/O code. Rules are restated in 4–6 places (block validation, mempool validation, revalidation, apply, conflict keys), and drift between those restatements has already produced real bugs (F1). Everything runs under one global `std::sync::Mutex<ChainManager>` shared by async RPC and P2P tasks (R16-4 to R16-8).

**On the dual transaction model.**
- **Keep v1 (CLSAG/BP+) and PX both for testnet and v1.** PX capacity (~3 tx per 8 MiB block, ~45 s proving) cannot carry payment traffic.
- **Freeze v1 as a stable, feature-closed "payments layer" now.** All new capability goes to PX.
- **Plan a turnstile-style convergence** (the PX-5 idea) that becomes possible only once proof size falls by an order of magnitude.

**On contracts.** I **concur with R7's option D**: PX is the only contract platform, and the Wasm system leaves the workspace. I add one point: `crypto::{schnorr, membership, claims}` (1,037 lines) is referenced by nothing outside its own tests and should leave the consensus crypto crate with it (R16-11).

**Top findings**

| ID | Severity | Class | Title |
|---|---|---|---|
| R16-1 | **High** | Not implemented | No height-scheduled rule set, kernel or verifier; every consensus change is a new genesis |
| R16-2 | **High** | Not implemented | No consensus golden corpus or known-answer vectors; refactors and dependency bumps can change consensus silently |
| R16-3 | Medium-High | Partially implemented | The consensus proof wire format is Plonky3's serde layout through postcard (caret-pinned) |
| R16-7 | Medium-High | Partially implemented | One global std mutex over header tree, state, bodies, mempool and store; about 10 P2P and 8 RPC sites lock it on async workers while writers verify PX proofs under it |
| R16-4 | Medium | Partially implemented | No separable consensus core; wallet-side modules define consensus constants |
| R16-5 | Medium | Partially implemented | Rules are restated in 4–6 places per transaction kind; F1 is an instance of the drift |
| R16-6 | Medium | Partially implemented | "Validate then apply-with-`expect`" plus poison recovery (extends R10-2): the architectural fix is effects-based apply |
| R16-8 | Low-Medium | Complete but requires further testing | Block validation consults the mempool as a proof cache; sound today, broken by planned features |
| R16-9 | Medium | Accepted limitation / Deferred | Everything in RAM, no state commitment, silent divergence; decide the state digest before the v3 freeze |
| R16-10 | Info | Accepted limitation | Dual transaction model: sustainable only if v1 is frozen and PX is the growth path |
| R16-11 | Low | Partially implemented | Wasm contracts and 1,037 lines of unreferenced consensus crypto |
| R16-12 | Medium (repo hygiene) | Not implemented | 118.6 MB of tracked `legacy/` and `research/`, including `target/` build artifacts |
| R16-13 | Medium | Partially implemented | Consensus artifacts (kernel ELF) are platform-dependent binaries (known); fold the fix into v3 |
| R16-14 | Info / planning | Deferred | A verifier registry means old verifiers (and the patched Plonky3 0.7) live forever |
| R16-15 | Low | Partially implemented | Header version is not tied to rule epochs; old nodes must fail loudly, not diverge |

The staged plan in §12 is ordered to minimize consensus risk:
- **Stage A** (now): tests and hygiene, no consensus change.
- **Stage B**: put the mechanisms (not new features) into the already-planned v3 genesis.
- **Stage C**: refactor the node behind the golden corpus, with no consensus change.
- **Stage D**: storage and scalability.
- **Stage E**: height-activated protocol evolution.

---

## 1. System map

### 1.1 Crate dependency graph (path dependencies only) [src: each `*/Cargo.toml`]

```
randomx ─────────────► consensus ───────────────────────────────┐
crypto  ─────────────────────────────────────┐                  │
px-core (no deps, no_std)                    │                  │
zk (Plonky3 0.7 + 3 patched crates) ◄─ crypto│                  │
zkvm ◄─ zk, crypto                           │                  │
px   ◄─ px-core, crypto, zk, zkvm, ml-kem, chacha20poly1305     │
tx   ◄─ crypto, consensus, px, px-core, zkvm, zk  ◄─────────────┘
chain ◄─ consensus, crypto, tx, px, px-core
p2p  ◄─ consensus, crypto, tx, chain (+ tokio, aes-gcm)
rpc  (serde, reqwest-blocking; no project deps)
node ◄─ chain, consensus, tx, rpc, p2p (+ axum, tokio)
miner ◄─ randomx, consensus, crypto, tx, chain, rpc
wallet ◄─ consensus, crypto, tx, chain, rpc, px, px-core, zkvm
contracts ◄─ crypto, wasmi =0.38.0            (used by nothing)
tools/labnet ◄─ consensus, chain, rpc, tx, wallet
```

**Observations:**
- **Good:** acyclic, and bottom-up from primitives [src].
- **Layering inversion.** `tx`, the transaction *rules*, depends on `px`, which also contains the wallet (`px/src/wallet.rs`), hybrid delivery encryption (`delivery.rs`), off-chain sharing (`share.rs`) and a demo contract (`vault.rs`). So wallet-side code is part of the consensus crate graph. It becomes *consensus-defining* where a consensus constant lives there:
  - `tx/src/px.rs:36` imports `blacksilk_px::delivery::CIPHERTEXT_BYTES`, which fixes the record ciphertext length (a consensus rule: testnet-reset-plan §2 item 4) [src].
- **The miner links the whole STARK stack** through `chain → tx → px/zk/zkvm`, although it only needs the block format and a coinbase builder. The same holds for anything that depends on `chain`. There is no security issue, but it:
  - enlarges the supply chain of every binary;
  - lengthens builds.

### 1.2 Size profile (tracked `.rs`, lines) [src: `git ls-files | wc -l`]

| Area | Lines | Largest files |
|---|---|---|
| zkvm | 8,325 | `air/trace.rs` 737, `isa.rs` 565, `air/cpu.rs` 471 |
| tx | 7,151 | `validate.rs` 936, `px.rs` 735, `types.rs` 524 |
| chain | 6,325 | `mempool.rs` 1,091, `manager.rs` 849, `store.rs` 610 |
| p2p | 4,991 | **`net.rs` 1,781** |
| crypto | 4,964 | `clsag.rs` 1,003, `bulletproofs_plus.rs` 847 |
| wallet | 4,351 | **`wallet.rs` 1,686**, `px.rs` 728 |
| px | 4,094 | `state.rs`, `tree.rs`, `prove.rs` (≤ 260 each) |
| contracts | 3,151 | `exec.rs` 946 |
| randomx | 2,851 | `vm.rs` 882, `superscalar.rs` 763 |
| consensus | 1,692 | `chain.rs` 902 |
| zk | 1,340 | |
| px-core | 989 | `kernel.rs` 503 |
| third_party (patched Plonky3) | 16,146 | `p3-fri/src/verifier.rs` 2,251 |
| legacy | 19,873 (plus ~118 MB of non-source) | |

**File sizes are healthy.** No project file exceeds about 1,800 lines. The hotspots are `p2p/src/net.rs` (connections, handshake, sync, relay, Dandelion glue, bans and maintenance in one module) and `wallet/src/wallet.rs` (v1 wallet, PX wallet and **vault-specific commands** `px_vault_lock` and `px_vault_claim` in the generic wallet type) [src: `wallet/src/wallet.rs:1419,1522`].

---

## 2. The consensus core: where it is, and can it be specified and reimplemented?

### 2.1 Where consensus actually lives [src]

| Rule family | Location |
|---|---|
| Header format, id, PoW, LWMA, MTP/FTL, seed schedule, most-work selection | `consensus/src/*` (clean, pure, documented) |
| Genesis, network ids | `consensus/src/params.rs` |
| Emission, supply | `chain/src/emission.rs` |
| Block encoding, `MAX_BLOCK_BYTES`, `MAX_BLOCK_TXS` | `chain/src/block.rs` |
| Tx encoding, kinds, limits, fees | `tx/src/types.rs`, `tx/src/px.rs`, `tx/src/params.rs` |
| Tx and block validity | `tx/src/validate.rs` |
| State transition (outputs, key images, one-time keys, registry, PX) | `tx/src/state.rs` + `px/src/state.rs` + `px/src/tree.rs` |
| Record ciphertext length | `px/src/delivery.rs` (wallet encryption module) |
| PX statement, kernel program, kernel budgets | `px/src/prove.rs` (+ `px/kernel.elf`, a binary) |
| Proof system parameters, proof encoding | `zk/src/params.rs`, `zk/src/lib.rs` + Plonky3 serde + postcard |
| zkVM semantics and AIR | `zkvm/src/*` |
| Kernel semantics | `px-core/src/*` |
| Connect/disconnect ordering, "body-complete most-work" selection | `chain/src/manager.rs` |

**Answer.** There is an identifiable consensus core, and most of it is pure and deterministic. But:
1. **It is not a unit.** It spans 9 crates plus two checked-in binaries (`kernel.elf`, and `vault.elf` for tests), with consensus constants defined in wallet and prover modules.
2. **It is not independently specifiable in one place.** docs/consensus.md, blocks.md, transactions.md, px.md, zk.md and zkvm.md each hold part of it. `validate.rs` tags rules (T1–T11, C1–C4, B1–B7, PX1–PX5), which is a very good start.
3. **Its PX part is not independently reimplementable at all today.** The verifier *is* Plonky3 0.7 with 3 patched crates, and the proof wire format is Plonky3's `serde` derive layout encoded by `postcard` (R16-3). A second implementation would have to reproduce a third-party library's internal struct layout byte for byte.

**What is right and must be preserved:**
- `check_rules` as the single definition of the header rules (`consensus/src/chain.rs:289-330`) [src];
- the single-source kernel (`px-core` compiled natively and as the guest; `prove.rs:192` checks guest and host agreement on every proof) [src];
- typed, rule-tagged errors with `is_stateless()` (`tx/src/validate.rs:158-184`) [src];
- the explicit invariant doc on `ChainManager` (`chain/src/manager.rs:4-12`) [src].

### R16-4 — No separable consensus core (Medium, Partially implemented)

- **Where:**
  - `tx/src/lib.rs:20-29`: the modules `builder`, `decoy`, `scan` and `px_builder` are wallet-side, next to `validate` and `state`;
  - `px/src/lib.rs:20-27`: `wallet`, `delivery`, `share` and `vault` sit next to `state`, `tree` and `prove`;
  - `tx/src/px.rs:36`: a consensus constant comes from `px::delivery`;
  - `chain/src/emission.rs`: emission is in the chain crate, not in consensus.
- **Scenario.** A wallet engineer changes the delivery format, for example to make the ML-KEM combiner a true X-Wing (a known item: V and H(ek) are omitted). If the ciphertext length changes, **the change is a consensus change**, because `CIPHERTEXT_BYTES` is imported into the PX tx decoder. Nothing in the crate structure signals that. The same holds for any edit to `px/src/prove.rs::kernel_budget`, which reads like prover tuning but is consensus (it fixes statement shapes).
- **Confidence:** high [src].
- **Recommendation:** define a **consensus facade** (see §11): one crate, or a clearly marked module tree, that owns every consensus constant, rule and state transition, and depends only on primitives. Wallet and prover code moves out. Mechanically, this is moving code and re-exporting it. The golden corpus (R16-2) proves that nothing changed.

---

## 3. Duplicated rule statements, and the apply path

### R16-5 — Rules restated per transaction kind in 4–6 places (Medium, Partially implemented)

- **Where [src]:**
  - `validate_block_transactions_cached` (`tx/src/validate.rs:724-936`), whose per-kind `match` arms appear at lines 762, 847, 855, 878 and 926;
  - `validate_transfer`, `validate_px`, `validate_px_without_proof` and `validate_deploy` (477-566);
  - `revalidate_after_extension` (603-637);
  - `MemoryChain::apply_block` (`tx/src/state.rs:146-219`), which re-enforces the PX rules by `expect`;
  - `px::state::State::apply_block`;
  - `mempool::conflict_keys` (`chain/src/mempool.rs:112`);
  - `p2p::net::stem_keys` (`p2p/src/net.rs:1342`).
- **Evidence that this drifts:**
  - **F1:** mempool conflict keys missed output one-time keys although C4 enforced them; fixed in `16659ee`;
  - "stateless checks run after contextual ones in mempool paths" and "some intra-tx errors are classed contextual" (brief, being fixed).

  Both are symptoms of the same shape: the *effects* of a transaction (what it consumes and creates in state) are re-derived ad hoc by each consumer.
- **Scenario.** Adding kind 4 (for example a PX variant with 4 outputs, or a Wasm call) means editing at least 7 sites. Missing one produces a mempool/consensus disagreement or a template that stalls (F1 class), or an `apply_block` panic (R16-6 class).
- **Confidence:** high [src].
- **Recommendation: an effects model.** Each kind implements one trait:

  ```text
  trait TxKind {
      fn check_stateless(&self, rules) -> Result<(), TxError>;          // T-rules, cheap first
      fn effects(&self) -> Effects;   // key_images, one_time_keys, outputs, nullifiers,
                                      // commitments, contract_ids, pool_delta, px_bytes, weight, fee
      fn check_contextual(&self, view, height) -> Result<(), TxError>;  // C1 and PX3 (reads)
      fn expensive(&self) -> Vec<Check>;       // CLSAG, BP+ batch items, PX proof
  }
  ```

  Every consumer is then derived from `effects()`:
  - block uniqueness (C2, C4, PX2, contracts);
  - pool accounting;
  - mempool conflict keys;
  - Dandelion stem keys;
  - extension revalidation;
  - `apply`.

  A new kind then cannot forget a conflict key, because the key is not written separately.
  - Consensus impact: **none**, if proven equivalent against the golden corpus (R16-2).
  - Difficulty: L. Priority: P2 (Stage C).

### R16-6 — Validate-then-apply-with-`expect`, and poison recovery (Medium, Partially implemented; extends R10-2)

- **What R10-2 already establishes:**
  - `MemoryChain::apply_block` mutates in a loop, then calls `expect(...)` on the PX apply (`tx/src/state.rs:181, 205-208`);
  - `ChainManager::sync_state` calls `assert!(self.state.undo_block())` (`chain/src/manager.rs:538`);
  - both locks recover from poison with `unwrap_or_else(|e| e.into_inner())` (`node/src/lib.rs:53-58`, `p2p/src/net.rs:355-361`; 9 sites in total [src: grep]);
  - the justifying comment at `node/src/lib.rs:54-56` ("sync_state runs to completion or panics before mutating") is **false**.
- **Architectural addition.** The root cause is not the poison recovery. It is that the system has **two definitions of the state rules**: validation says yes, and apply independently re-checks and panics if it disagrees. With the effects model (R16-5):
  - `connect` = `check(block) -> Result<Effects>` followed by `commit(Effects)`, where `commit` is **infallible by construction**: it only inserts what `effects()` listed, and the PX tree append is precomputed during checking.
  - A disagreement then becomes impossible, not merely "excluded by validation".
  - Until then, the chain lock should be **fail-stop** (R10-2 option 1). A deterministic replay is the correct recovery for a deterministic state machine.
- **Security:** it prevents silent divergence.
- **Privacy:** none.
- **Consensus:** none.
- **Priority:** P1 for fail-stop (Stage A), P2 for effects-based apply (Stage C).

---

## 4. Concurrency model

### 4.1 What exists [src]

- **Runtime.** A tokio multi-threaded runtime. `SharedChain = Arc<std::sync::Mutex<ChainManager>>` (`p2p/src/net.rs:32`, `node/src/lib.rs:27`).
- **What the lock guards:** `ChainManager` holds the header tree, `MemoryChain` state, **all block bodies**, the invalid-block map, the **mempool**, the **block store handle**, and the batch-verification RNG (`chain/src/manager.rs:164-185`).
- **The stated rule** (`p2p/src/net.rs:4-6`): the chain lock and the network-state lock are never held together, never across `.await`, and CPU-heavy work runs on blocking threads.
- **What the code does:**
  - **Writers** (`submit_block`, `submit_tx`, `accept_headers`) do run in `spawn_blocking` (`net.rs:1175, 1409, 1537`; `node/src/lib.rs:193, 235`). But they hold the lock for the **whole** operation, including:
    - PX proof verification for PX transactions not already in the mempool (0.21–0.26 s each, measured in the brief);
    - full mempool revalidation after any reorg (6.8 ms per v1 transfer);
    - `sync_state` over many blocks during sync;
    - at startup, replay of every block including every PX proof (PX-F3).
  - **Readers on async worker threads.** About 10 P2P sites call `inner.chain()` directly from async tasks or synchronous handlers invoked by them:
    - `net.rs:444` locator;
    - 602 `run_connection`;
    - 845 `handle`;
    - 1108 `on_header_error`;
    - **1126 `on_get_blocks`, which clones up to 16 bodies of up to ~9.4 MB each under the lock;**
    - 1206 `schedule_downloads`;
    - 1238 `on_inv_tx`;
    - 1298 `on_get_tx`;
    - 1583 and 1668 maintenance.

    At least 7 RPC handlers do the same (`node/src/lib.rs:140, 159, 267, 301, 323, 367, 383`). Examples:
    - `/template` runs `mempool.select` under the lock;
    - `/px/commitments` clones every PX record with its ciphertext (R10, R12-3).

### R16-7 — Global lock plus async-thread readers (Medium-High, Partially implemented; deepens the known "chain lock taken on async threads")

- **Scenario.** An attacker with modest hash power, or any peer relaying such blocks, sends a block with 3 PX transactions that our node never saw (so the mempool cache misses), on a side branch that triggers a 2-block reorg.
  - The writer holds the lock for about 3 × 0.25 s of proof verification, plus reorg revalidation of the whole mempool, plus the re-add of returned transactions.
  - Meanwhile every tokio worker that enters one of the ~17 read sites **blocks its OS thread** on the std mutex. There are as many workers as cores by default.
  - Once all workers are parked, no async task runs: ping/pong, handshake and headers timeouts fire across **all** peers (`PONG_TIMEOUT` 30 s is safe; `HANDSHAKE_TIMEOUT` 10 s and the RPC may not be).
  - Repeating this is cheap for anyone who can produce valid-PoW side blocks, and on a small testnet that is anyone with a CPU.
- **Evidence:** [src] for the mechanism; [unknown] for the magnitude. It was not measured; the labnet has never been run under this pattern.
- **Confidence:** medium-high that stalls occur, medium on severity.
- **Recommendation: target concurrency architecture.**
  1. **Chain actor (single writer).** A dedicated OS thread owns `ChainManager` (or its successor) and receives commands over a bounded channel: `SubmitBlock`, `AcceptHeaders`, `SubmitTx`, `Template`. Back-pressure is explicit, and nothing async ever blocks on a mutex.
  2. **Snapshot reads.** After each state change, the actor publishes an immutable `Arc<ChainSnapshot>`: tip, height, locator, header index, mempool summary, and paginated PX indexes. It goes through a `std::sync::RwLock<Arc<..>>` swap, with no new dependency. Readers clone the `Arc` and never touch the writer. Body serving reads the store, not RAM (ties in with PX-F1).
  3. **Verification outside the writer.** Stateless and state-independent checks run on a bounded worker pool **before** the command reaches the actor:
     - T-rules;
     - BP+;
     - **the PX proof**, whose statement is fixed by the transaction plus immutable registry entries; the soundness argument is already written at `validate.rs:716-723`;
     - CLSAG only after ring resolution, which needs state; resolve rings on a snapshot, then re-check existence cheaply in the actor.

     The actor then does only the contextual checks and the commit.
  4. **Mempool out of the consensus object.** A policy component that talks to the actor, not a field inside it.
- **Security:** removes a whole-node stall vector.
- **Privacy:** positive. Timing of the RPC and P2P responses no longer correlates with the lock holder's work. This is a weak side channel today [assumed].
- **Performance:** large improvement in tail latency; enables parallel PX verification.
- **Complexity:** L. **Consensus:** none. **Identity:** none. **Priority:** P1 in two steps:
  - Stage A: stop cloning bodies and PX records under the lock on async threads, and wrap remaining async-side reads in `spawn_blocking` (S);
  - Stage C: the actor (L).

### R16-8 — Consensus validation consults the mempool (Low-Medium, Complete but requires further testing)

- **Where:** `chain/src/manager.rs:561-569` passes `&|id| mempool.contains(id)` as `proof_verified` to `validate_block_transactions_cached`.
- **Why it is sound today [src, argued at `tx/src/validate.rs:716-723`]:**
  - the tx id commits to the proof bytes;
  - the statement depends only on the transaction, the network and registry entries that are immutable and content-addressed;
  - PX3 is still checked.
  - A proof malleated through M1 (unbound FRI witnesses) changes the id, so it misses the cache and is verified.
- **Why it is fragile.** Three planned features break the argument silently:
  - (a) a **kernel or verifier schedule by height** (R16-1): a transaction admitted under verifier A before activation must not skip verification in a block after A's sunset;
  - (b) **upgradable contracts** (R7 §7.1, "Aleo-style editions"): registry entries become mutable;
  - (c) any rule where PX5 depends on the block height.

  Also, the mempool can evict a transaction between admission and block arrival, which costs performance but not soundness.
- **Recommendation.** Replace the predicate with an explicit, bounded `VerifiedProofCache`:
  - keyed by `(tx id, verifier id, registry-entry digest of every called function)`;
  - owned by the node, not the mempool;
  - persisted optionally, which answers PX-F3 at restart with the same trust model as the already-accepted stored PoW hashes.

  Record the invariant "cache key covers every input of the PX5 statement" as a doc-tested rule next to `check_px_proof`.
- **Consensus:** none. **Priority:** P2 (Stage C); mandatory before R16-1 is used for a real verifier change.

---

## 5. Error handling

**What is good [src]:**
- **Consensus errors are closed enums with rule tags:** `TxError`, `BlockError`, `HeaderError`.
- **`is_stateless()` drives peer scoring** (P2P §10).
- **`SubmitError` separates `BodyMismatch`,** which means the header is not touched: a good anti-poisoning choice.
- **The store now fails stop:** `STORE_FAILURE_LIMIT`, `store_failed()`, and the node exits (`chain/src/manager.rs:187-191, 449-472`).
- **Plonky3 panics are contained** with `catch_unwind` (`zk/src/lib.rs` hardening; `decode_proof` also wraps postcard in it). `panic = "unwind"` is fixed in the release profile with a comment explaining why (`Cargo.toml` `[profile.release]`).

**What is fragile:**
- `expect`, `assert` and `unreachable!` sit on consensus paths that should be infallible by construction:
  - `manager.rs:538` `assert!(undo_block())`;
  - `state.rs:181` `expect("validated deploys load")`, which **re-parses ELFs at apply time** and so is a second parser invocation on consensus data;
  - `state.rs:208`.

  They are acceptable only with fail-stop locks (R16-6).
- **`catch_unwind` depends on the build profile.** A packager who builds with `panic = "abort"`, as some distributions and hardening guides recommend, turns every malformed proof into a node crash, **a network-wide kill switch**. **Recommendation:** add a `compile_error!` or a startup self-test in `node` that fails if `cfg!(panic = "abort")`. Policy only, S, P1.
- **`ZkError::Encoding(String)` and `Invalid(String)` carry free text.** That is harmless for consensus, since only the variant matters, but log lines built from peer-controlled data should stay bounded. It already looks bounded [src], so this is informational.

---

## 6. State model

### 6.1 What exists [src: `tx/src/state.rs:40-61`, `chain/src/manager.rs:164-185`]

**`MemoryChain` holds, in RAM:**
- every output record;
- every key image and one-time key;
- per-block undo **forever**;
- the PX state (frontier and root window);
- the contract registry with parsed programs;
- a contract log;
- **every PX record with its 1,241-byte ciphertext**;
- every nullifier.

`ChainManager` also keeps **every block body** in RAM, so PX ciphertexts exist twice (R10-7). Headers are in a `HashMap` that nothing prunes.

**There is no state commitment.** Headers commit only to `tx_root`. The PX tree root is state, but it is not committed in headers: it is used only as the anchor window.

### R16-9 — State model: scalability and divergence detection (Medium; Accepted limitation for testnet; Deferred)

- **Scalability.** Known as PX-F1 and PX-F2, and R10's storage items. This review endorses them.
- **The architectural consequence is "divergence is silent".** Without a per-block state commitment, two nodes whose `MemoryChain` diverged, for example through R16-6 poison recovery or a future nondeterminism, agree on every header and tx root. They discover the divergence only when some later transaction is valid on one and invalid on the other, which is a chain split at an unpredictable height. A committed state digest turns this into an immediate, attributable failure at the first divergent block. It also enables snapshot sync (assumeutxo-style) and light verification later.
- **Options, cheapest first:**
  1. **A rolling effects digest,** `D_h = H(D_{h-1} ‖ canonical(Effects of block h))`. It costs one hash per block, detects divergence exactly and needs no new data structure. It does not support membership proofs.
  2. **An MMR over outputs + the PX tree root + a key-image and nullifier accumulator.** This enables proofs and snapshots. It is L to XL and a large new consensus surface.
- **Where it would live:** a header field (changes `HEADER_SIZE` and ids) or the coinbase (the contracts.md coinbase v2 pattern).
- **Recommendation:**
  - **Decide before the v3 freeze** whether option 1 goes into v3. It is the only moment when it costs no extra reset.
  - **My recommendation:** do **not** add it to v3 unless the effects model (R16-5) exists first. A state digest computed by today's ad hoc apply code would pin today's accidental orderings into consensus.
  - Instead, build it **node-local first** (Stage C): compute and log `D_h`, and compare across the labnet machines. Then activate it at a height (Stage E) once R16-1 exists.
- **Consensus:** CONSENSUS when activated. **Priority:** P3 (node-local digest P2).

---

## 7. The dual transaction model (v1 CLSAG/BP+ and PX STARK)

### R16-10 — Is it sustainable long term? (Info, Accepted limitation)

**Facts [src; brief measurements]:**
- **v1:** 1-of-16 CLSAG rings, BP+ range proofs, stealth outputs with the Janus anchor, and a 600k weight limit per 2-minute block.
- **PX:** full-set anonymity, hash-based ownership that is post-quantum for ownership, and ML-KEM delivery. But:
  - about 2.2 MB per transfer, 45 s proving and 0.21 s verification;
  - an 8 MiB PX byte budget per block, so **about 3 PX tx per block, about 0.025 TPS**.
- **The two are already coupled:** PX transactions carry a v1 part (ring inputs to bridge in, hidden change, clear payouts), and `px_pool` is a turnstile (`validate.rs:508, 858-863`). Deploys are v1 transfers with programs attached.

**Assessment:**
1. **PX cannot replace v1 now.** It is two orders of magnitude short of payment throughput, and the proving cost excludes ordinary hardware and phones. Dropping v1 would make BlackSilk unusable for payments. **Keep both.**
2. **Two anonymity sets is a real privacy cost.**
   - Every bridge-in and bridge-out is a linkage point between the ring world and the PX world.
   - The bridged amounts are public (`bridge_in` and `bridge_out` are clear u64 values), so amount correlation across the boundary is the dominant deanonymization vector. This is well known from the Zcash transparent/shielded boundary [web: e.g. Kappos et al., "An Empirical Analysis of Anonymity in Zcash", USENIX Security 2018].
   - This is a privacy-architecture issue to own explicitly. Wallet policy mitigations (R3 domain): round-denomination bridging, delayed and split bridge-outs, and never bridging-in and -out in one session.
3. **Sustainability requires asymmetry.**
   - **Freeze v1 as feature-closed:** payments only; no new kinds built on ring inputs; no v1 contracts (hence also R7 D).
   - **All new capability goes to PX:** tokens, contracts, time, messages.
   - This bounds the long-term cost of maintaining CLSAG/BP+/decoys to "keep it correct", and it avoids a third privacy tier.
4. **The long-term convergence path** (zk.md PX-5) is **turnstile and sunset, not deletion**:
   - (a) proof aggregation or recursion brings the PX cost per transaction down by about 10×;
   - (b) at an activation height, *new v1 outputs* stop being creatable, so bridge-in is the only v1 spend;
   - (c) old v1 outputs remain spendable into PX forever.

   Sprout to Sapling is the precedent [web: ZIP 209, the Sprout value pool turnstile]. `px_pool` is already the right accounting primitive. Every step is height-activated, which again requires R16-1.
5. **The v1 output format** (`O`, `Cm`, the Janus anchor, key images) must stay stable, because future proof systems (for example FCMP-style membership) could then spend old outputs without migration (transactions.md §11.7). This goes on the "never change" list (§13).

- **Consensus:** none now. **Priority:** freeze v1 now (policy, P1); convergence P3.

---

## 8. Contracts: Wasm system versus PX (assessment of R7's recommendation)

**R7 recommends option D:** PX as the single contract platform, and the Wasm system removed from v1 scope and frozen as research. A public "finalize" phase attached to PX calls may come later if there is demand.

**My assessment: concur, for architectural reasons in addition to R7's privacy ones:**
- **Two state machines, two value layers.** Wasm contracts would add a second state root (coinbase v2), a second value-conservation proof (notes, the kernel, BP+ claims), fuel calibration as a consensus constant, and a second VM with `unsafe` inside (wasmi 0.38, an unsupported line; C-1 to C-5 open). Each of these multiplies the R16-5 problem, because every consumer must learn a new kind of effect.
- **The kind conflict** (Wasm kinds 2 and 3 are taken by PX) is a symptom of there being no registry of kinds, version ids or activation heights (R16-1).
- **Consensus determinism.** Wasm execution by every node is a new nondeterminism surface: floats are disabled by the profile [src: `contracts/src/profile.rs`], but memory growth, fuel metering and wasmi upgrades are all consensus (contracts.md §16.3). PX moves execution off chain and verifies a proof: validators never run contract code.
- **R7's "finalize later" door is sound**, provided it is specified as a *new effect type* (a public mapping update) in the effects model, not as a separate engine with its own value layer.

**R16-11 additions (Low, Partially implemented):**
- `crypto/src/{schnorr, membership, claims}.rs` (249 + 457 + 331 = 1,037 lines) are **referenced by nothing** outside their own unit tests [src: grep across all project crates; `contracts/src` only uses `crypto::hash`, `Point`, `commitment`]. They sit in the consensus crypto crate, which the brief's "no KAT vectors" item already covers. Move them into `contracts/` or behind a non-default `contracts` feature.
- `contracts` is a default workspace member, so CI builds and tests it, and the lint job requires its `forbid(unsafe_code)`. Move it to `exclude`, or keep it as a member but outside every binary's dependency graph (already true). Its fuzz targets can stay.
- **Consensus:** none. **Identity:** none. **Difficulty:** S. **Priority:** P2 (Stage A).

---

## 9. Upgrade and versioning strategy

### 9.1 What exists [src]

| Item | Value | Check |
|---|---|---|
| Header version | `HEADER_VERSION = 1` | `header.version != HEADER_VERSION → BadVersion` (`consensus/src/chain.rs:301`) |
| Tx version | `TX_VERSION = 1`, kinds 0–3 | `version != TX_VERSION → UnsupportedVersion` (`tx/src/types.rs:390-393`) |
| Proof version | `PROOF_VERSION = 1` | exact (`zk/src/lib.rs:193`) |
| Kernel | `KERNEL_ELF` via `include_bytes!`, a `OnceLock` singleton (`px/src/prove.rs:30-41`) | id pinned by a test [test: `the_kernel_program_id_is_pinned`] |
| Kernel budgets | `kernel_budget(n_fn)` constants (`px/src/prove.rs:54-71`) | none |
| P2P protocol | `PROTOCOL_VERSION = MIN_PROTOCOL_VERSION = 1` | handshake |
| Wallet file | `version: 1` | exact |
| Block store | `BSB1` record magic, **no file header or version** | (R10-3) |
| Activation heights | **none anywhere** | testnet-reset-plan §1: "no activation height" |
| Verifier registry | zk.md §9.5: **design, not implemented** | |

### R16-1 — No rule schedule; every consensus change is a new genesis (High, Not implemented)

- **Scenario.** On mainnet, a soundness bug is found in the kernel or zkVM (zk.md §13 lists this as a risk: "emergency upgrade: activate a fixed verifier and sunset the old one"). That response **cannot be executed** with the current code:
  - the kernel is a global singleton with no height input;
  - `check_px_proof` has no height or verifier selector;
  - old blocks must still verify under the old kernel during replay;
  - the only available action is a new genesis, which is impossible on mainnet.

  An ad hoc `if height >= X` patched in under emergency pressure is exactly how consensus bugs are born.

  The same applies to known planned consensus items:
  - M1 (the FRI witness rule or `COMMIT_POW_BITS`);
  - the Plonky3 0.8 upgrade (a "hard fork" per the brief);
  - PX-F4 and PX-F5 kernel changes;
  - R7-1 time windows;
  - a platform-neutral kernel rebuild (R16-13).
- **Confidence:** high [src].
- **Recommendation (Stage B, in the v3 genesis):**
  1. Add `consensus::schedule`: a static, ordered table of **rule epochs**:

     ```text
     struct Epoch {
         from_height: u64,
         header_version: u32,                 // must equal the header's version
         tx_kinds: &'static [KindSpec],       // allowed kinds and per-kind limits
         verifiers: &'static [VerifierSpec],  // allowed PX verifiers (id, kernel id,
                                              //   kernel budgets, proof params id, sunset)
         limits: Limits,                      // weights, PX byte budget, fees
     }
     fn epoch_at(params: &ChainParams, height: u64) -> &'static Epoch
     ```

     Per network: mainnet, testnet and regtest each have their own table. **v3 ships with exactly one epoch from height 0.** Behavior is therefore identical to today's rules, but every consumer already asks `epoch_at(h)` instead of reading a global constant.
  2. **Put an explicit verifier id in the PX transaction's non-prunable part,** covered by `h_tx`. Validation requires it to be in `epoch_at(h).verifiers` and not sunset at `h`. The proof's version byte stays as a codec version.
  3. **Select the kernel by verifier id**, not from a global: `kernel_program(verifier_id)`, which holds the ELF bytes and pinned id per verifier.
  4. **Grace windows.** An old verifier stays valid for a defined number of blocks after a new one activates, so pooled transactions and slow wallets are not stranded. Mempool admission checks `epoch_at(next_height)`, and the verified-proof cache is keyed by verifier id (R16-8).
  5. **A pinned test** enumerates the schedule and its fingerprint (R16-2).
- **Why v3.** The mechanism itself changes the PX tx format (the verifier id field) and the header check semantics. Folded into the already-approved v3 reset, it costs **no extra identity change**. Added later, it costs a hard fork of its own.
- **Security:** high positive. It enables emergency response without a reset.
- **Privacy:** neutral if every transaction carries the same verifier id within an epoch. During a grace window, the verifier id partitions the anonymity set: old-wallet transactions are distinguishable. Keep windows short and document this.
- **Performance:** none.
- **Complexity:** M.
- **Consensus:** CONSENSUS (a format and mechanism change; behavior is otherwise identical).
- **Identity:** it rides the v3 reset.
- **Difficulty:** M.
- **Priority:** **P0 for inclusion in v3** (if v3 happens before the trial), otherwise P1.

### R16-15 — Header version is not tied to rule epochs (Low, Partially implemented)

- **Problem.** Today an old node receiving a post-fork block fails with whatever rule it trips first, or accepts a block that new nodes reject (for soft-fork-shaped changes). Either way it forks quietly.
- **Recommendation:** Monero-style scheduled upgrades [web: Monero hard-fork table, `hardforks.cpp`]:
  - each epoch sets a header version;
  - `header.version` must equal `epoch_at(height).header_version`;
  - old nodes then **reject every block from the activation height with `BadVersion`** and stall visibly, instead of following a minority chain;
  - the node logs "unknown future version: upgrade required" once it sees N such headers with valid PoW.

  **No miner signaling** (BIP9-style): with a small and young miner set, signaling adds a coordination surface without a safety benefit.
- **Consensus:** CONSENSUS (semantic only; v1 behavior is identical). **Priority:** P1, in the v3 bundle.

### R16-14 — The verifier registry implies permanent old verifiers (Info / planning, Deferred)

- **The problem.** Once R16-1 exists, the Plonky3 0.8 upgrade becomes "verifier 2 at height H" instead of a new genesis. But **every node that validates from genesis must still verify verifier-1 proofs** (Plonky3 0.7 plus 3 patched crates), forever, unless history is checkpointed.
- **Recommendation:**
  - (a) Freeze each verifier as its own crate: `bs-verifier-v1` pins its whole dependency closure with `=` versions, vendors the patched crates, and exposes only `verify(statement, proof_bytes)` with a **project-owned proof codec** (R16-3). Cargo can link 0.7 and 0.8 side by side, since they are semver-incompatible.
  - (b) Do not adopt an assume-valid mechanism for PX proofs without an explicit owner decision. It changes the trust model: a new node would trust that historic proofs were valid.
- **Consensus:** none by itself. **Priority:** P3 (a Stage E design item), but (a) should shape the Stage C crate split.

### R16-13 — Consensus artifacts are platform-dependent binaries (Medium, Partially implemented; known)

- **Known:** `px/kernel.elf` embeds a Windows developer path. It reproduces only on Windows, and a neutral rebuild changes the kernel id.
- **Architectural point.** A consensus artifact must be reproducible from source on any platform by anyone. Otherwise verification of the chain rests on trusting the developer's machine.
- **Recommendation:** fold the platform-neutral rebuild (`--remap-path-prefix`, a pinned toolchain in `zkvm/guests/rust-toolchain.toml`, and a pinned linker script) into v3, and CI-reproduce it on Linux *and* Windows.
- **Consensus:** CONSENSUS (kernel id). **Identity:** it rides v3. **Priority:** P0 in the v3 bundle.

---

## 10. Test architecture for consensus

### R16-2 — No golden corpus, no known-answer vectors (High, Not implemented)

**Pinned today** [src: grep for `*_is_pinned`, `*_are_pinned`]:
- genesis ids (`consensus/src/params.rs:124`);
- kernel and vault program ids (`px/tests/proof.rs:24`, `px/tests/unified.rs:59`);
- the Poseidon2 permutation (`zk/tests/pins.rs:14`);
- Wasm fuel (`contracts/tests/exec.rs:83`);
- the RandomX official vectors (`randomx/src/lib.rs` tests).

**Not pinned** [src]:
- a transaction id;
- a signature message (`signature_message(network_id)`);
- a prunable hash;
- a block id beyond genesis;
- `h_tx` or the binding;
- a PX public-statement word vector;
- a proof encoding;
- a contract id;
- a coinbase commitment;
- a Janus anchor;
- a state after N blocks;
- any consensus constant.

(The brief already lists missing Ristretto CLSAG and BP+ external vectors and missing schnorr/membership/claims KATs; this finding is broader.)

- **Scenario 1.** Someone "cleans up" `Transfer::encode` field order, or changes `Writer::varint` handling for an edge case. Every test still passes, because builder and validator share the code, and testnet v2 nodes built from the new code reject the existing chain.
- **Scenario 2.** `cargo update` moves `postcard` 1.x or `serde` (caret-pinned per A14), changing the proof encoding. `decode_proof`'s re-encode check then **rejects every historical PX proof** on replay, or accepts a second encoding. No test notices, because tests generate fresh proofs.
- **Recommendation (Stage A, no consensus change):**
  1. **Consensus corpus.** A deterministic regtest chain generated once by a seeded generator (the labnet or test harness) and committed under `tests/corpus/`:
     - a few hundred blocks;
     - v1 transfers, a deploy, PX deposit, send and withdraw, a vault call, a reorg with a side branch, an invalid block, and a RandomX seed switch with a short test epoch.

     Commit it as raw `blocks.dat` plus a manifest of expected block ids, tx ids and, per height, the node-local effects digest (R16-9, option 1). A test replays it through `ChainManager` and checks every expected value.
     - **Every refactor in Stage C must keep this test green without regenerating the corpus.**
     - Regenerating it is a consensus change by definition and requires the owner-approval process.
  2. **Consensus fingerprint.** One test hashes a canonical dump of every consensus constant and pins the digest. The constants include `ChainParams`, `TxRules`, `tx::params::*`, `MAX_BLOCK_BYTES`, emission constants, `zk::params::*`, `MAX_CYCLES` and the other zkVM limits, `kernel_budget(0..=2)`, `CIPHERTEXT_BYTES`, the PX tree depth, the root window, and the epoch schedule (R16-1). This is the "consensus fingerprint pin" the brief lists as missing in CI; this is its content.
  3. **Golden PX proof.** One stored transfer proof and one vault proof (about 5 MB total, acceptable; or store them compressed). Test that each decodes, re-encodes identically and verifies. This catches Plonky3, postcard and serde drift.
- **Security:** high. It is the enabling control for every other change.
- **Privacy:** none; regtest keys only.
- **Performance:** CI time grows by the length of a replay (minutes, including proof verification).
- **Complexity:** M. **Consensus:** none. **Identity:** none. **Difficulty:** M. **Priority:** **P0**.

### R16-3 — The proof wire format is a third-party serde layout (Medium-High, Partially implemented)

- **Where:** `zk/src/lib.rs:177-181` defines `encode_proof = PROOF_VERSION ‖ postcard::to_allocvec(BatchProof<ZkConfig>)`. The consensus byte format is therefore whatever Plonky3 0.7's `#[derive(Serialize)]` produces through postcard 1.x.
- **What is good:** the canonical re-encode check (`decode_proof`, lines 209-211) gives one valid encoding per proof, and the length variation is analysed (privacy §3a).
- **Risk:**
  - the format is caret-pinned (`postcard = "1"`, `serde = "1"`, per A14), with no `--locked` in CI;
  - the canonicality check makes the node *reject* old proofs if the encoding drifts, which is fail-closed but splits the chain;
  - an independent verifier implementation is impractical.
- **Recommendation:**
  - (Stage A) pin `postcard` and `serde` with `=`, use `--locked` everywhere, and add the golden proof (R16-2 item 3);
  - (Stage D) write a **project-owned proof codec**: an explicit field-by-field layout mirroring today's bytes exactly, proven identical on the corpus, inside the frozen verifier crate (R16-14). It is then specified in zk.md as bytes, not as "postcard of a struct".
- **Consensus:** none, if byte-identical as verified by the corpus. **Priority:** P1 (pins), P2 (codec).

---

## 11. Target architecture (mainnet-grade)

```
                 ┌─────────────────────────── primitives (frozen APIs) ───────────────────────────┐
                 │ randomx │ crypto-core (Ristretto, CLSAG, BP+, stealth, Janus, hash tags)       │
                 │ px-core (no_std kernel) │ zkvm-verify │ bs-verifier-v1 (Plonky3 0.7, own codec)│
                 └───────────────────────────────────────────────────────────────────────────────┘
                                                   ▲
 ┌──────────────────────────── CONSENSUS CORE (pure: no I/O, no clock, no logging decisions) ──────┐
 │ params + schedule (epochs, verifiers, limits, genesis)  │ emission │ codecs (header, block, tx)  │
 │ header rules (today's consensus::chain)                 │ TxKind trait: stateless / effects /  │
 │ state transition: check(block, view, epoch) -> Effects ; commit(Effects) (infallible)           │
 │ StateView trait (reads) ; effects digest                                                        │
 └─────────────────────────────────────────────────────────────────────────────────────────────────┘
          ▲                          ▲                                   ▲
 ┌────────┴──────── node services ───┴──────────────┐         ┌──────────┴───── wallet side ─────────┐
 │ chain actor (single writer; header tree; state DB│         │ wallet-core: builder, decoy, scan,   │
 │   with undo deltas; body store) ; snapshots      │         │   px wallet, delivery (X-Wing), share│
 │ verifier pool + VerifiedProofCache               │         │ px-prover (zkvm prove, Plonky3 prove)│
 │ mempool (policy only; conflict keys = effects)   │         │ contract SDK + vault (example)       │
 └──────────────────────────────────────────────────┘         └──────────────────────────────────────┘
          ▲                                                              ▲
 ┌────────┴──────── I/O ─────────────────────────────┐          ┌───────┴──────────┐
 │ p2p (split: conn, sync, relay, dandelion, peers)  │          │ wallet CLI, miner│
 │ rpc server (reads snapshots; bounded pages)       │          └──────────────────┘
 │ node binary (config, signals, fail-stop)          │
 └───────────────────────────────────────────────────┘
```

**Properties this buys:**
- **One place defines consensus:** a reviewer, a spec writer or a second implementation reads one crate plus its frozen primitives.
- **Wallet and prover changes cannot change consensus** by dependency direction: the consensus core does not depend on them.
- **Rules are stated once** (effects), so the mempool, relay and apply are derived from them.
- **Emergency upgrades are table entries** plus a new frozen verifier crate.
- **Validation is parallel outside the writer;** the writer does only contextual checks and the commit.
- **Divergence is detectable** (the effects digest).

---

## 12. Staged migration plan (minimizing consensus risk)

The order is chosen so that **every consensus-touching step comes after the control that detects accidental consensus change** (the golden corpus), and **all intentional consensus changes are batched into the single already-approved reset (v3)**.

### Stage A: before the seven-machine trial. No consensus change, no identity change.

| # | Action | Finding | Diff. | Prio |
|---|---|---|---|---|
| A1 | Golden corpus, consensus fingerprint, golden PX proofs | R16-2, R16-3 | M | P0 |
| A2 | `=` pins for postcard and serde (and the other caret-pinned consensus crates per A14); `--locked` in CI and in documented builds | R16-3 | S | P0 |
| A3 | Chain lock fail-stop on poison; fix the false comment at `node/src/lib.rs:54-56` | R16-6 / R10-2 | S | P1 |
| A4 | Startup self-test refusing `panic = "abort"` | §5 | S | P1 |
| A5 | Remove body and PX-record cloning under the lock on async threads; move the remaining async-side reads into `spawn_blocking` | R16-7 | S–M | P1 |
| A6 | `git rm -r legacy/smart-contracts/target` and every other build artifact. Move `legacy/` and `research/` out of the main tree, into an archive branch or tag, or a separate repository. **A history rewrite, which is what actually shrinks clones, is destructive and needs explicit owner approval** | R16-12 | S | P2 |
| A7 | `contracts` out of the default members; move `crypto::{schnorr, membership, claims}` into it or behind a feature; mark contracts.md superseded (R7 D, owner decision) | R16-11 | S | P2 |
| A8 | Freeze v1 as feature-closed (a policy statement in transactions.md) | R16-10 | S | P1 |
| A9 | Stale module docs: `zkvm/src/lib.rs:9-10` ("ZK-3, in progress"), the node lock comment, and `tx/src/state.rs:6-7` ("the node's persistent store must behave identically": the node *uses* `MemoryChain`) | R16-12 | S | P2 |

### Stage B: the v3 genesis bundle (CONSENSUS; the one identity change already approved)

Intentional consensus changes go in together, each through the owner's process (analysis → evidence → proposal → security review → tests → implementation → integration review). Proposed mechanism content:

| # | Action | Finding |
|---|---|---|
| B1 | `consensus::schedule` with one epoch from height 0; `epoch_at(h)` used by every consumer | R16-1 |
| B2 | Explicit verifier id in the PX tx; kernel selected by verifier id; grace-window semantics specified (initially unused) | R16-1 |
| B3 | Header version bound to the epoch | R16-15 |
| B4 | Platform-neutral kernel rebuild (new kernel id), reproduced in CI on Linux and Windows | R16-13 |
| B5 | Already-identified consensus fixes, decided by the owner: M1 FRI witness rule or `COMMIT_POW_BITS ≥ 1`; M2 and M3 as analysed; PX-F4 (B) and PX-F5 (B); the R7-1 time window; a fresh genesis (M1 pre-mining) | known |
| B6 | Regenerate the golden corpus **once**, under review, as the v3 reference | R16-2 |

**Out of v3:** state digest activation, a new tx kind, v1 sunset. None of them is ready, and each can be scheduled later through B1.

After B6, **declare the consensus core frozen.** Any diff that changes the corpus is a consensus change.

### Stage C: after the trial. Internal refactor, no consensus change (corpus must stay green).

| # | Action | Finding | Diff. | Prio |
|---|---|---|---|---|
| C1 | Extract the consensus facade; move wallet and prover modules out of `tx` and `px`; move emission into consensus | R16-4 | L | P2 |
| C2 | `TxKind` effects model; derive conflict keys, stem keys, revalidation and apply from it; infallible `commit` | R16-5, R16-6 | L | P2 |
| C3 | Chain actor, snapshots, verifier pool, `VerifiedProofCache` keyed by verifier id | R16-7, R16-8 | L | P1–P2 |
| C4 | Split `p2p/src/net.rs` into modules; move vault commands out of `wallet.rs` into a contract module or plugin | R16-12 | M | P3 |
| C5 | Node-local effects digest, logged and compared across labnet nodes | R16-9 | S | P2 |

### Stage D: pre-mainnet scalability (no consensus change)

- A persistent state DB with undo **deltas** and bounded undo depth (tied to K4 policy), bodies on disk (PX-F1 and F2, R10);
- a streaming replay with persisted `VerifiedProofCache` (PX-F3);
- a project-owned proof codec in `bs-verifier-v1` (R16-3, R16-14);
- a consensus spec document generated from, or checked against, the consensus crate's rule tags.

### Stage E: protocol evolution (height-activated through B1; each item CONSENSUS)

- Plonky3 upgrade as verifier 2 with a sunset of verifier 1 for *new* transactions (old proofs stay verifiable);
- state digest activation;
- aggregation or recursion (PX-4);
- evaluation of a v1 turnstile or sunset;
- the optional public finalize (R7 D).

---

## 13. What should NEVER be changed

Changing any of these adds consensus or security risk far beyond any foreseeable benefit. Each belongs in the golden corpus or fingerprint so that a change cannot happen by accident.

1. **RandomX as specified by the reference (v1, Monero parameters), bit-exact with the official vectors.**
   - No "BlackSilk variant" parameters: a custom variant loses the only external correctness oracle (the official vectors) and the reference implementations.
   - The seed schedule `E = 2048`, `L = 64` can change only through an epoch entry, never in place.
2. **Header encoding and the id derivation with the network id,** plus the rule "signatures commit to `network_id`" (no cross-network replay).
3. **Strict canonical encodings with a single valid encoding per object:**
   - sorted key images and outputs;
   - canonical points and field elements;
   - the proof re-encode check.

   Malleability defences must never be relaxed for convenience.
4. **Key-image definition, CLSAG and BP+ domain tags and generators, and the stealth-output and Janus-anchor derivations** for existing outputs. Old outputs must stay spendable and scannable forever.
5. **The v1 output format** (`O`, `Cm`, the anchor fields). Future spend proofs (FCMP-style) must be able to reference existing outputs unchanged.
6. **The PX record layer:** `Hk` = the standard Poseidon2 instance, the record, commitment, nullifier and `rho` derivations, the domain constants (`px-core/src/hash.rs`), and tree depth 32. The verifier registry's promise ("records stay spendable across verifier upgrades", zk.md §9.5) depends on this layer being immutable.
7. **Fixed-shape privacy invariants:**
   - 2-in/2-out PX statements;
   - `PX_STANDARD_FEE` exactly;
   - per-program budgets fixing table heights;
   - no variable-shape proofs.

   Making shapes "flexible for efficiency" would leak through table heights and fees.
8. **The emission schedule, the supply cap and tail, and `px_pool` turnstile accounting.** The pool's non-negativity is the bound on loss from a PX soundness bug (zk.md R7).
9. **No admin, pause or upgrade keys** anywhere in consensus. Responses are consensus upgrades adopted by operators (zk.md §13).
10. **Most-work selection with no depth limit** (K4) unless the owner deliberately revisits it. Checkpoints and finality gadgets add trust assumptions and have caused real-world splits.
11. **Immutability of registered contract programs** (the contract id hashes the deploy). The mempool proof cache's soundness and PX3 rely on it (R16-8).
12. **Build and safety invariants:**
    - `forbid(unsafe_code)` in project crates;
    - no C or FFI in the node's dependency closure;
    - `panic = "unwind"` in any node build (R16 §5);
    - the kernel and guest single-source principle (px-core compiled natively and as the guest).
13. **Plonky3 must not be upgraded in place.** Any proof-system change is a new verifier id at an activation height (R16-1, R16-14).

---

## 14. The 13 questions (architecture scope)

| # | Answer |
|---|---|
| 1. Implemented | A full pure-Rust stack: RandomX, header chain, v1 CLSAG/BP+ transactions, PX kinds 2 and 3 with a zkVM kernel and registry, a chain manager with reorgs, mempool, store, encrypted P2P with Dandelion++, RPC, miner and wallet. The Wasm contract engine exists but is not integrated [src] |
| 2. Correct and well designed | Acyclic crate graph; single header-rule definition; single-source kernel; typed rule-tagged errors with a stateless/contextual split; `catch_unwind` containment with the profile documented; body-before-header `tx_root` check; fail-stop store; exact dependency pins for Plonky3 (`=0.7.0`) [src] |
| 3. Incomplete | Rule schedule and verifier registry (R16-1); golden corpus (R16-2); consensus facade (R16-4); persistent state (PX-F1, F2) |
| 4. Fragile | Rule restatement (R16-5); validate-then-`expect` apply (R16-6); the mempool-as-proof-cache invariant (R16-8); a proof codec that belongs to a dependency (R16-3); `panic = "abort"` sensitivity |
| 5. Exploitable | Global-lock stall through PX-heavy side blocks and reorgs (R16-7, magnitude unmeasured); the rest is in other reviewers' scope |
| 6. Inefficient | Every read path contends with every write; PX proofs verified under the writer lock; replay re-verifies all proofs; the miner and every binary link the prover stack |
| 7. Does not scale | All state, bodies and undo in RAM; one lock; `HashMap` header tree never pruned; about 3 PX tx per block |
| 8. Missing | State commitment or divergence detection (R16-9); consensus fingerprint; old-node "upgrade required" behaviour (R16-15) |
| 9. Redesign | The concurrency model (actor plus snapshots); effects-based validation and apply; the consensus facade |
| 10. Innovate | A consensus corpus as the specification of record; an effects digest; verifier epochs with grace windows designed for a privacy chain (partition-aware); PX-first growth with a v1 turnstile |
| 11. Before testnet (trial) | Stage A (A1–A5 at least); decide whether v3 happens before the trial, and if so Stage B |
| 12. Safely deferred | Stages C–E, except that A5 and A3 cover the worst of R16-6 and R16-7 in the interim |
| 13. Never change | §13 |

---

## 15. Recommendation register

| ID | Why | Security | Privacy | Performance | Complexity | Consensus | New identity | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| R16-1 schedule + verifier id | Emergency fixes and upgrades without a reset | High + | Neutral; grace windows partition, keep them short | none | M | **CONSENSUS** | rides v3 | M | P0 if v3 precedes the trial, else P1 |
| R16-2 corpus + fingerprint + golden proofs | Detect accidental consensus change | High + | none | CI minutes | M | none | no | M | **P0** |
| R16-3 pins now, own codec later | Dependency drift must not change consensus | + | none | none | S / M | none if byte-identical | no | S / M | P1 / P2 |
| R16-4 consensus facade | Specifiability; wallet changes cannot touch consensus | + | none | build times ↓ | L | none (corpus-verified) | no | L | P2 |
| R16-5 effects model | Removes the rule-drift bug class (F1) | + | + (stem keys consistent) | small + | L | none (corpus-verified) | no | L | P2 |
| R16-6 fail-stop now, infallible commit later | No silent divergence | + | none | none | S / L | none | no | S / L | P1 / P2 |
| R16-7 actor + snapshots + off-lock verify | Removes the node-stall vector; enables parallelism | + | + (timing) | large + | L | none | no | S (A5), L (C3) | P1 |
| R16-8 `VerifiedProofCache` | Keeps the cache sound under upgrades | + | none | + (restart) | M | none | no | M | P2 |
| R16-9 effects digest (node-local, then activated) | Detect divergence; later snapshot sync | + | none | negligible | S / M | none, then CONSENSUS | no / activation height | S / M | P2 / P3 |
| R16-10 freeze v1; PX growth; turnstile later | Sustainability; no third privacy tier | + | + (boundary awareness) | none | S (policy) | none now | no | S | P1 (policy), P3 |
| R16-11 contracts out; unused crypto out | Smaller consensus surface; no wasmi `unsafe` in the build | + | + (no public-state tier) | build ↓ | S | none | no | S | P2 |
| R16-12 legacy/research out; stale docs | Supply-chain and review hygiene; 118.6 MB tracked | + (no stale binaries, JS or TSX apps in the tree) | none | clone size (only with a history rewrite) | S | none | no | S | P2 |
| R16-13 neutral kernel build | Reproducible consensus artifact | + | none | none | S | **CONSENSUS** (kernel id) | rides v3 | S | P0 in v3 |
| R16-14 frozen verifier crates | Long-term replay of old proofs | + | none | build ↑ | M | none | no | M | P3 |
| R16-15 header version = epoch | Old nodes stall loudly instead of forking | + | none | none | S | **CONSENSUS** (semantic) | rides v3 | S | P1 |
| §5 `panic = "abort"` guard | Stops a packaging choice becoming a network kill switch | High + | none | none | S | none | no | S | P1 |

---

## 16. Evidence and limits of this review

**What I did:**
- read `Cargo.toml` for every member;
- read `lib.rs` for 12 crates;
- read `chain/src/manager.rs` and `tx/src/validate.rs` in full;
- read `tx/src/state.rs` (apply and undo), `px/src/prove.rs`, `consensus/src/chain.rs:120-538`, `consensus/src/params.rs` and `tx/src/params.rs`;
- read the proof codec in `zk/src/lib.rs`;
- read the locking sites in `p2p/src/net.rs` and `node/src/lib.rs`;
- checked the specs' upgrade sections (zk.md §9.5 and §14, contracts.md §18, transactions.md §11.7, testnet-reset-plan §1–2);
- read the CI workflow;
- measured the tracked sizes of `legacy/` and `research/` with `git ls-files` and `stat` (118,590,400 bytes);
- used R7, R10 and R12 for cross-reference.

**What I did not do:**
- no builds, tests or benchmarks;
- the lock-stall magnitude (R16-7) is **[unknown]**: it is a source-read mechanism, not a measured effect;
- no line-by-line review of the zkvm AIR, p2p internals, wallet or mempool (other reviewers' scope);
- I did not verify whether `reqwest` in `rpc` pulls any non-Rust code (A14 states that "no C/C++" is verified for the root lock).

**Confidence overall:** high on structural findings (R16-1, -2, -3, -4, -5, -11, -12, all [src]); medium-high on R16-7 (mechanism [src], impact [assumed]).
