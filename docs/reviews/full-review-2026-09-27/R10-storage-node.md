# R10: storage, recovery, node and RPC (internal review, 2026-09-27)

**Reviewer:** R10 (internal review, not an audit).
**Tree:** `rebuild/core` @ `f677e55`, main working tree. This was a read-only review: no builds, and no files in the repository were changed.

**Scope:**
- `chain/src/store.rs`, `chain/src/manager.rs`;
- `tx/src/state.rs` (MemoryChain), `px/src/state.rs`;
- `node/src/{main,lib,config}.rs`, `rpc/src/lib.rs`;
- `deploy/`.

I also read the parts of `p2p/src/net.rs`, `consensus/src/{chain,difficulty,params}.rs` and `chain/src/block.rs` that these files depend on.

**Evidence tags:**
- **[src]**: source-read;
- **[test: name]**: a named existing test;
- **[math]**: arithmetic from constants in the source;
- **[ext]**: an external source, cited;
- **[assumed]**;
- **[unknown]**.

No test was run for this review. Tests named here are cited as evidence that already exists.

---

## 0. Executive summary

The storage layer is small and honest about its limits. It has four parts:
- an append-only, CRC-framed log with fsync before apply;
- undo of failed writes;
- conservative torn-tail handling;
- repair only on request.

`docs/blocks.md` §8 describes the limits accurately. The node does not decide consensus: it binds to loopback, bounds request sizes, and has systemd hardening. That is a reasonable base for a *controlled* testnet.

**New or sharpened findings** (not in the brief's "already known" list, or with a new, concrete exploit or quantification):

| ID | Sev. | Class | One-line |
|---|---|---|---|
| R10-1 | **High** | Partially implemented | An attacker can cheaply mine siblings of block 1 (testnet: 100 hashes each at `D0 = 100`), each with up to ~9.4 MB of decodable but never-validated body. Every one is fsynced to `blocks.dat`, kept in RAM forever, and re-read at every start. This makes the known K4/PX-F1 gaps a concrete memory/disk DoS |
| R10-2 | Medium | Partially implemented | Recovering a poisoned mutex (`lock()` → `into_inner`) resumes after a panic that *can* have left `MemoryChain` half-applied. The comment that justifies it (`node/src/lib.rs:54-56`) is incorrect. The result is silent state divergence instead of crash-and-replay |
| R10-3 | Medium | Not implemented | `blocks.dat` has no file header (format version, network id, genesis id). After the planned v3 reset, an old store is not refused: every old block silently becomes an "orphan", and the file is re-read at every start forever |
| R10-4 | Medium (privacy) | Not implemented | No Host-header check, auth token or CORS policy on the loopback RPC. DNS rebinding lets any web page read `/info` (it fingerprints that the user runs a node) and POST `/tx` and `/block` |
| R10-5 | Medium | Partially implemented | `/px/commitments` clones **every** PX record, each with its 1,241-byte ciphertext, on every call, under the chain lock, on a tokio worker. `/distribution` is O(height) and unpaginated. All RPC handlers take the std chain mutex on async workers |
| R10-6 | Medium (scaling) | Accepted limitation → fix later | PX undo keeps a full copy of the 100-root window plus the frontier, about 4.2 KB **per block, including empty blocks**, forever. That is about 1.1 GB/year of RAM at 120 s blocks with zero PX use (quantifies PX-F2) |
| R10-7 | Low–Med | Accepted limitation | PX record ciphertexts are duplicated in RAM (`px_records`, and again inside `bodies`). The node itself only uses them through the RPC, which throws them away |
| R10-8 | Low | Complete, needs testing | The torn-tail heuristic has a quadratic worst case on attacker-shaped block bytes. It also confirms the known silent-drop regression (mid-file damage plus a torn last record ⇒ everything is truncated) |
| R10-9 | Low | Partially implemented | Shutdown handles only SIGINT/Ctrl-C. `docker stop` (SIGTERM) kills the node without saving peers or bans. The Dockerfile sets no `STOPSIGNAL` and no `HEALTHCHECK` |
| R10-10 | Low (privacy) | Partially implemented | Debug logs write `stem tx <id> -> peer <p>` and `fluff tx <id>`, and info logs write peer IPs. A debug log is an origin-deanonymization record. The CLI help suggests `blacksilk_p2p=debug` |
| R10-11 | Low | Partially implemented | RPC: no timeouts (slowloris), no concurrency limit, no per-endpoint cost budget |
| R10-12 | Low | Accepted limitation | `CachedPow` is an unbounded map that also caches the hashes of *rejected* headers |
| R10-13 | Low | — | Docker docs put the wallet file inside the node's data volume (`/data/me.wallet`) |
| R10-14 | Info | — | Stale dependencies: `fs2 0.4.3` (std `File::try_lock` exists since Rust 1.89) and `env_logger 0.8.4`. No `rust-toolchain` pin. Two log strings embed source indentation (`manager.rs:415`, `main.rs:80`) |
| R10-15 | Low | Partially implemented | `peers.json`/`bans.json` are written without fsync before rename, and the file I/O runs while the p2p state lock is held |

**Before a public testnet I recommend:**
- **P0:** R10-1 (a node-policy fix, not consensus) and R10-3 (the file header, before the v3 reset).
- **P1:** R10-2, R10-4, R10-5.

The persistent-state redesign (§5) is P2/P3, but it should begin during the trial because PX-F1, PX-F2, PX-F3 and R10-6 all grow with the chain.

---

## 1. Detailed findings

### R10-1: Cheap low-work side-branch bodies are stored and kept in RAM forever (High)

**Class:** Partially implemented. **Confidence:**
- high for the code path;
- medium that the whole ~9.4 MB can be filled with decodable content, because PX blob decode limits are not re-checked here.

**Code path** [src]:
- **Height-1 difficulty:** `consensus/src/difficulty.rs:18-21` returns `initial` when there is no history, so every child of genesis (height 1) has difficulty `D0`. `ChainParams::testnet()` sets `D0 = 100` (`consensus/src/params.rs:53-63`).
- **No fork limit:** `HeaderChain::accept` (`consensus/src/chain.rs:464-486`) has no fork-depth, minimum-work or sibling-count limit. This is the known K4 gap.
- **Stored before validation:** `ChainManager::submit_inner` (`chain/src/manager.rs:325-372`) checks only `tx_root`. It then **appends to `blocks.dat` before any body validation** and inserts the body into `bodies`.
  - `sync_state` validates bodies only on the best chain.
  - A side-branch body is therefore never validated, never evicted, and never removed from the file.
- **Decode-only check:** `Block::decode` (`chain/src/block.rs:54-79`) checks framing and `MAX_BLOCK_BYTES ≈ 1 MB + MAX_PX_BLOCK_BYTES + 64 KiB`. That is the only content check.
- **Unrequested blocks are still processed:** in `p2p/src/net.rs:1170-1175` an unrequested block costs the sender 10 misbehaviour points (ban at 100, for 24 h, exact IP), but `submit_block` still runs.
  - So one IP delivers about 9 blocks per ban period.
  - With exact-IP bans (known N-5) and IPv6, IPs are effectively free.

**Scenario:**
1. The attacker mines many different height-1 blocks on top of the v2 genesis. Each needs ~100 RandomX hashes: about 0.1 s with reference RandomX [assumed ~1 ms/hash, from the brief].
2. Each block carries a ~9 MB decodable garbage body.
3. The attacker pushes them unsolicited from rotating addresses, or through any node that relays them.
4. **Victim effects:**
   - each block is an fsync'd append plus ~9 MB of heap, permanently;
   - 1,000 such blocks cost the attacker about 2 CPU-minutes and the victim about 9 GB of RAM and disk;
   - at the next start the victim must read the whole file into memory (R10-8/PX-F3) and re-insert every body;
   - the victim ends up OOM, cannot restart, and fills its disk.
5. **After a v3 reset** (`D0` unchanged), the same attack works from the new genesis.

**Comparison** [ext]:
- Bitcoin Core's `AcceptBlock` ignores unrequested blocks unless they have at least as much work as the tip, are not too far ahead, and are above minimum chain work: `fRequested` / `fHasMoreOrSameWork` / `fTooFarAhead` in `src/validation.cpp`, https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp.
- Bitcoin Core also keeps no body of a low-work fork.

**Recommendation.** Node policy only; consensus is not touched:
- **(a) Rule for unrequested blocks:** process one only if its cumulative work is at least the connected tip's work. Otherwise drop it without storing it (misbehaviour score unchanged).
- **(b) Rule for storing any body:** store it only if it is on the best header chain, or on a branch whose cumulative work is at least `tip_work − W`, where `W` is a small policy margin (e.g. 6 × tip difficulty). Otherwise keep the header only.
- **(c) Cap on side-branch bodies:** bound the total number of bytes of side-branch bodies held in memory (LRU, re-fetchable). Once bodies move to disk (§5), apply the same bound to disk.
- **(d) Replay:** apply the same rule, so an already-poisoned `blocks.dat` is not kept in memory. Log the bytes skipped.

**Assessment:**
- **Why:** it turns two known gaps into a practical, cheap remote DoS on every public node.
- **Security:** high benefit.
- **Privacy:** none.
- **Performance:** positive.
- **Complexity:** low for (a) and (b); moderate for (c).
- **Consensus:** policy only. Chain selection is unchanged, because a branch with more work is still requested and stored.
- **Testnet identity:** none.
- **Difficulty:** S–M.
- **Priority:** **P0** for any testnet that accepts inbound peers from strangers.
- **Tests to add:**
  - many low-work siblings of block 1 are not stored, and memory stays flat;
  - a heavier branch arriving later is still fetched and wins.

### R10-2: Poisoned-mutex recovery can continue from a half-applied state (Medium)

**Class:** Partially implemented. **Confidence:**
- high on the mechanism [src];
- the trigger needs a validator/apply mismatch, whose reachability is [unknown].

**Code path** [src]:
- **Lock recovery:** `node/src/lib.rs:53-58` and `p2p/src/net.rs:356-361` recover poisoned locks with `unwrap_or_else(|e| e.into_inner())`. The comment says "sync_state runs to completion or panics before mutating". That is not true.
- **Where a panic lands:** `MemoryChain::apply_block` (`tx/src/state.rs:147-219`) mutates `key_images`, `px_records`, `px_nullifiers`, `registry`, `one_time_keys` and `outputs` inside the loop. It then panics:
  - on `load_programs().expect(...)` (line 182);
  - or on `self.px.apply_block(...).expect(...)` (lines 205-208, e.g. `TreeFull`, which validation does not check — known, and unreachable today).
- **What stays behind:** no `BlockUndo` is pushed and `connected` is not extended. `sync_state` also contains `assert!(self.state.undo_block())`.
- **Why a panic is caught at all:** `panic = "unwind"` is required by the ZK `catch_unwind` (`Cargo.toml:29-31`). So a panic in `spawn_blocking` is caught as a `JoinError` (`node/src/lib.rs:166`, `p2p/src/net.rs:1197`), and the node keeps running.

**Scenario.** A future validation/apply mismatch (a new tx kind, or a rule drift) panics in `apply_block` after inserting key images and outputs. The node continues with:
- extra outputs, so every later global output index is shifted: ring members resolve to the wrong keys and valid transactions are rejected;
- extra key images, so valid spends are refused.

The node forks off silently instead of crashing and replaying `blocks.dat` into a consistent state.

**Recommendation:**
1. Treat a poisoned *chain* lock as fatal: log at error level with context, then `std::process::exit(1)`. systemd `Restart=on-failure` restarts the node, and the replay rebuilds the state.
2. Separately, make `MemoryChain::apply_block` transactional: compute all changes, check the PX state, then commit. Or wrap it in an undo-on-unwind guard.
3. Correct the comment.

**Assessment:**
- **Security:** it prevents a silent consensus divergence.
- **Privacy:** none.
- **Performance:** none.
- **Consensus:** none (node behaviour).
- **Testnet identity:** none.
- **Difficulty:** S.
- **Priority:** **P1**.
- **Test:** inject a panic into `apply_block` (test hook) and assert that the process refuses to continue, or that the state is unchanged.

### R10-3: `blocks.dat` has no header, so a store from another network or format is silently accepted (Medium)

**Class:** Not implemented. **Confidence:** high [src].

**Code path:**
- The record format is `"BSB1" ‖ len ‖ crc ‖ payload` (`chain/src/store.rs:1-6`). There is no file header that names the format version, network id or genesis id.
- The default data directory is `<data>/BlackSilk/testnet` for every testnet generation (`node/src/config.rs:184-189`).
- **Replay of an old store:** an old v1 or v2 `blocks.dat` replayed under new params decodes. But no block's `prev_id` is ever known, so every block goes into `waiting` and is reported as an orphan: "they will be downloaded again" (`chain/src/manager.rs:228-237`). The message is wrong: they never will be.
- **Growth:** the node then syncs the new chain and **appends new records after the old ones**. Every start re-reads and re-decodes the dead prefix (memory and time).
- **Silent reset:** a node started with the wrong network flag silently shows height 0 instead of refusing to start.

**Scenario.** The v3 reset (M1) is planned "near launch". Every operator who does not delete `blocks.dat` gets a permanently bloated store and a misleading log line. With R10-1 this is worse, because an old store can be large.

**Recommendation:**
- Add a versioned file header: `"BSBF" ‖ format_version ‖ network_id ‖ genesis_id ‖ reserved`, written when the file is created and checked at open.
- On a mismatch, refuse to start with a clear message ("blocks.dat belongs to network X / genesis Y; move it aside").
- Migration: a header-less file whose first record's `prev_id` is the current genesis is accepted and the header is prepended (a one-time rewrite through tmp + fsync + rename). Anything else is refused.
- Include the same fields in any future DB (§5).

**Assessment:**
- **Security:** low–medium (operator error, DoS on self).
- **Privacy:** none.
- **Performance:** positive.
- **Consensus:** none.
- **Testnet identity:** none. Land it *before* v3, so v3 stores carry the header from the start.
- **Difficulty:** S.
- **Priority:** **P0** (it is cheap, and the reset is imminent).

### R10-4: The RPC is open to DNS rebinding and cross-origin requests (Medium, privacy)

**Class:** Not implemented. **Confidence:**
- high that no mitigation exists [src: `node/src/lib.rs:90-103`: the router has only `DefaultBodyLimit`, no Host check, no auth, no CORS layer];
- the attack class is well established [ext]: DNS rebinding against localhost JSON-RPC, as in the Geth and Transmission disclosures. Details [assumed].

**Scenario.** A user who runs the node visits a malicious site, which rebinds its own hostname to 127.0.0.1. The page is then same-origin with `http://attacker.example:29333`. It can:
- read `/info`, which confirms that the user runs a BlackSilk node, reveals the network, height and peer count, and links the web identity to node operation;
- POST `/tx` and `/block`, feeding CPU-heavy validation (up to `MAX_REQUEST_BYTES ≈ 18.9 MB` per request);
- poll `/template`.

Without rebinding, simple cross-origin GETs (for example from `<img>`) can still trigger `/template` and `/blocks` work under the chain lock (R10-5), although the page cannot read the responses.

**Recommendation:**
- **Host check:** reject any `Host` header that is not a loopback literal or an operator-listed name.
- **Cookie auth:** use a random 32-byte token written to `<data_dir>/.rpc-cookie` with mode 0600 at start (Bitcoin Core's cookie model, https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md). Require it as a Bearer token on every method; the local miner and wallet read it from the data directory. Compare tokens in constant time.
- **No CORS:** send no CORS headers (the current default), and reject requests whose `Origin` header is present and not allowed.
- **Non-loopback binds:** make a non-loopback `rpc_bind` refuse to start unless auth is configured, instead of the current warning (`node/src/main.rs:93-98`).

**Assessment:**
- **Security:** medium.
- **Privacy:** positive (it removes a node-fingerprinting vector).
- **Performance:** none.
- **Consensus:** none.
- **Testnet identity:** none.
- **Difficulty:** S–M. The miner and wallet clients need a token option.
- **Priority:** **P1**.

### R10-5: RPC handlers cost O(chain) under the chain lock, on async workers (Medium)

**Class:** Partially implemented. **Confidence:** high [src].

**Per-endpoint cost:**
- **`/px/commitments`** (`node/src/lib.rs:264-284`) calls `px_records(0, u64::MAX)`. That clones every `PxRecordEntry`, including its `ciphertext: Vec<u8>` of `CIPHERTEXT_BYTES = 32+1+1088+104+16 = 1241` bytes [math, `px/src/delivery.rs:47-54`], and then keeps at most 65,536 entries.
  - With 1 M PX outputs, each call allocates about 1.3 GB while holding the chain mutex.
  - It runs on a tokio worker, not in `spawn_blocking`.
- **`/distribution`** (`lib.rs:330-338`) builds an O(height) vector and serializes it all; there is no pagination.
- **Lock waits:** `/info`, `/template`, `/blocks`, `/outputs` and `/px/contracts` all call `lock()` from async context. While `submit_block` or a reorg holds the lock (PX proofs at ~0.2 s each, plus a full mempool revalidation after a reorg — known), these handlers block runtime worker threads. Those threads are shared with the P2P tasks: `P2p::start` runs on the same runtime (`main.rs:100-121`).
- This is the RPC side of the known item "chain lock taken on async threads".

**Recommendation:**
- **`px_records`:** make it index-based (`&self.px_records[from..to]`, since records are position-ordered) and drop the ciphertext from the clone.
- **Pagination:** paginate `/distribution` (`from`, `to`, a maximum span).
- **Blocking work:** move every lock-taking handler to `spawn_blocking`, or put the chain behind a dedicated actor thread.
- **Admission:** add a `tokio::sync::Semaphore` per endpoint class.

**Assessment:**
- **Security:** DoS hardening.
- **Privacy:** none.
- **Performance:** large improvement.
- **Consensus:** none.
- **Testnet identity:** none.
- **Difficulty:** S (slicing, pagination) to M (actor).
- **Priority:** **P1** for the slicing and `spawn_blocking`; P2 for the actor.

### R10-6: PX undo keeps a full ~4.2 KB snapshot per block, including empty blocks (Medium, scaling)

**Class:** Accepted limitation today (PX-F2); this finding quantifies it. **Confidence:** high [src, math].

**Code path:**
- `px::state::State::apply_block` (`px/src/state.rs:100-114`) stores in `Undo` a clone of the whole root window, `VecDeque<Digest>` with 100 × 32 B = 3,200 B, plus the `Frontier` (`size` + 32 × 32 B = 1,032 B).
- `MemoryChain` keeps a `BlockUndo` for every block forever (`tx/src/state.rs:46, 209-217`), and `apply_block` always records a PX undo, even for an empty block (`tx/src/state.rs:204-208`).

**Cost:** about 4.3 KB per block with heap overhead. At 120 s blocks that is 262,800 blocks/year, about **1.1 GB/year of RAM with no PX activity at all**, before bodies (PX-F1).

**Recommendation.** Undo as a delta:
- the root popped from the window (if any) and the root pushed;
- the frontier's changed branch slots (usually 1–2, at most 32);
- the old pool value and the list of nullifiers.

That is about 100–200 B per block. Later, keep undo on disk (§5) instead of trimming it by depth: K4 means there is no reorg depth limit.

**Assessment:**
- **Security:** memory DoS resistance.
- **Privacy:** none.
- **Performance:** large memory saving.
- **Consensus:** none, provided `undo` restores exactly what it did before.
- **Required test:** keep the property test "apply then undo equals the identity" for random blocks, and compare with the current snapshot undo.
- **Testnet identity:** none.
- **Difficulty:** S–M.
- **Priority:** **P2** (P1 if the trial runs longer than a few months).

### R10-7: PX ciphertexts are duplicated in RAM (Low–Medium)

**Class:** Accepted limitation. **Confidence:** high [src].

**Code path:**
- `MemoryChain.px_records` stores `ciphertext.clone()` (`tx/src/state.rs:163-170`). The same bytes are also in `ChainManager.bodies` (PX-F1).
- Inside the node, only `/px/commitments` reads `px_records`, and it discards the ciphertext. Wallets get ciphertexts from `/blocks`.

**Recommendation:**
- Store `(height, position, commitment, nf0, slot, tx locator)` only, and read the ciphertext from the body on demand.
- Better still, put the index on disk (§5).

**Assessment:**
- **Why:** it halves PX-related RAM.
- **Security:** none.
- **Privacy:** none.
- **Performance:** memory saving.
- **Consensus:** none.
- **Testnet identity:** none.
- **Difficulty:** S.
- **Priority:** **P2**.

### R10-8: Torn-tail heuristic: cost and the confirmed silent-drop case (Low)

**Class:** Complete, needs testing.

**(a) Silent drop (known; A6 is reverting it). Confirmed by reading the code.**
- `load` (`store.rs:193-236`) treats a damaged record as the tail unless a valid run of records follows it **to the end of the file**.
- If the file has mid-file bit rot **and** a torn last record (for example a crash after silent media damage), no run reaches the end. Everything from the damaged record on is truncated, and only a `warn!` is logged.
- The test `a_record_embedded_in_a_torn_tail_does_not_block_restart` covers the benign case only.
- Suggested replacement for A6:
  - treat damage as the tail only if the damaged record starts within `MAX_PAYLOAD + RECORD_HEADER` bytes of the end;
  - that is, a torn record can only be the last one;
  - otherwise refuse to start and point to `--repair-store`.
  - This is O(1) and cannot drop more than one record's worth of bytes.

**(b) Cost.**
- `later_valid` scans every offset of `rest` and runs `valid_to_end` at every `MAGIC`. A torn record of attacker-chosen block bytes can contain about 700 k fake `BSB1` headers, each with a length that fits, so each CRC runs over up to MBs. That is a quadratic startup cost.
- It needs a crash exactly during that block's write, so the risk is low. The rule in (a) removes it too.

**(c) Memory at startup.**
- `load` reads the whole file (`read_to_end`), then copies every payload (`payload[32..].to_vec()`). Peak memory is about twice the file size, plus the decoded blocks. `repair` also reads the whole file.
- Recommendation: stream records with a `BufReader` (P2).

**Assessment:**
- **Security:** integrity and DoS.
- **Privacy:** none.
- **Performance:** positive.
- **Consensus:** none.
- **Testnet identity:** none.
- **Difficulty:** S.
- **Priority:** (a) **P0** (already in progress with A6); (b) and (c) P2.

### R10-9: Shutdown signals and Docker lifecycle (Low)

**Class:** Partially implemented. **Confidence:** high [src], [assumed default tokio/Docker behaviour].

**Code path:**
- `with_graceful_shutdown` waits only for `tokio::signal::ctrl_c()` (`node/src/main.rs:144-147`).
- The systemd unit sets `KillSignal=SIGINT`, which is correct.
- The Dockerfile sets no `STOPSIGNAL SIGINT`. `docker stop` sends SIGTERM, which ends the process immediately (default disposition), with no `n.save()`.
- Block data is safe, because each append is fsynced. `peers.json` and `bans.json` since the last periodic save are lost.

**Recommendation:**
- Handle SIGTERM too (`tokio::signal::unix::signal(SignalKind::terminate())`, and `ctrl_close`/`ctrl_shutdown` on Windows).
- Add `STOPSIGNAL SIGINT` and a `HEALTHCHECK` to the Dockerfile.
- Log a "clean shutdown" marker, so an unclean start can be detected and counted.

**Assessment:**
- **Difficulty:** S.
- **Priority:** P2.
- **Impact:** no consensus, privacy or identity impact.

### R10-10: Logs as a privacy liability (Low, privacy)

**Class:** Partially implemented. **Confidence:** high [src].

**What is logged:**
- **Debug:** `p2p/src/net.rs:1519` logs `stem tx {id} -> peer {p}`, and `:1540` logs `fluff tx {id}`.
- **Info:** peer IPs on disconnect (`:408`, `:768`); the local miner's accepted blocks (`node/src/lib.rs:169`).
- The CLI help (`config.rs:78`) suggests `blacksilk_p2p=debug`.

**Why it matters.** A debug log kept on disk, then seized or leaked, records which transactions entered this node's stem, and from whom. That is exactly what Dandelion++ hides from network observers. The block log also marks which blocks this node mined.

**Recommendation:**
- Never log transaction ids together with routing decisions or peer identities, at any level. Log counters instead.
- Add a `log_peer_addresses = false` option, on by default for Tor configs.
- Document log retention in `docs/testnet.md` §11.

**Assessment:**
- **Privacy:** positive.
- **Difficulty:** S.
- **Priority:** P2 (P1 for the Tor configuration).
- **Consensus:** none.

### R10-11: RPC resource controls (Low)

**Class:** Partially implemented. **Confidence:** medium [src + assumed axum 0.7 defaults].

**Code path:**
- `axum::serve` is used with no header-read timeout, no request timeout and no connection limit (`main.rs:143`).
- The body limit is 18.9 MB (`rpc/src/lib.rs:14`), so a local client can hold many slow 18 MB uploads.
- Loopback-only by default, so the impact is local.

**Recommendation:**
- `tower_http::timeout`, or `tokio::time::timeout` around handlers;
- a concurrency limit;
- a smaller body limit for `/tx` (the maximum transaction size) than for `/block`.

**Assessment:**
- **Priority:** P2.
- **Difficulty:** S.

### R10-12: `CachedPow` grows without bound (Low)

**Class:** Accepted limitation. **Confidence:** high [src].

**Code path:**
- `chain/src/manager.rs:35-65`: every computed PoW hash is cached forever, including the hashes of headers that are then rejected, because `compute_parallel` caches before `accept`.
- The growth rate is bounded by RandomX speed (about 100 B per entry), so it is slow.

**Recommendation:**
- Evict entries for headers that are not in the header tree once a batch is processed.
- Or keep only the hashes of accepted headers, which are needed for the store.

**Assessment:**
- **Priority:** P3.
- **Difficulty:** S.

### R10-13: Wallet in the node's volume (Low)

**Issue:**
- `docs/testnet.md` §4.4 creates `/data/me.wallet` in the node container's data volume.
- A compromise of the internet-facing node process, or a backup of node data, then includes the wallet file. The file is Argon2id-encrypted, but it is in the wrong trust domain.

**Recommendation:**
- A separate volume or container for the wallet.
- Document that node data backups must not include wallets.

**Assessment:**
- **Priority:** P3.
- **Difficulty:** S (docs).

### R10-14: Dependencies and cosmetics (Info)

- **fs2:** `fs2 0.4.3` (`Cargo.lock:937`) has had no release for years. It uses platform FFI for locking, which is unavoidable, but through an unmaintained crate. `std::fs::File::try_lock` has been stable since Rust 1.89 [ext: Rust 1.89 release notes]. Switch to it when the toolchain is pinned; there is no `rust-toolchain` file today.
- **env_logger:** `0.8.4` is several major versions behind.
- **Log strings:** `chain/src/manager.rs:415` and `node/src/main.rs:80` are string literals that contain the source indentation (a missing `\` continuation). The logs show runs of spaces.
- **Priority:** P3.

### R10-15: Peer and ban files (Low)

**Issue:**
- `AddrMan::save` and `BanList::save` (`p2p/src/addrman.rs:212-219, 261-268`) do write-then-rename with no fsync of the tmp file or the directory. After a power loss the file can be empty.
- Loading then falls back to an empty table: for a Tor node that means re-seeding, which is an eclipse opportunity.
- `Inner::save` holds the p2p state mutex during the file I/O (`net.rs:363-373`).

**Recommendation:**
- fsync the tmp file before the rename.
- Serialize under the lock, and write after releasing it.

**Assessment:**
- **Priority:** P2.
- **Relation to known items:** it sits next to the known "bans.json save" item.

---

## 2. Per-subsystem answers (the brief's 13 questions)

### 2.1 Block store (`chain/src/store.rs`)

1. **Implemented:**
   - an append-only CRC32-framed log with the stored PoW hash;
   - fsync (`sync_data`) per append;
   - undo of a failed append by truncation;
   - a "poisoned" flag if the undo fails;
   - torn-tail truncation at load;
   - refusal of mid-file damage;
   - operator repair that sets bytes aside.
   - Tests: `round_trip_and_reopen`, `torn_tail_is_truncated`, `corruption_in_the_middle_is_an_error`, `a_failed_append_is_undone`, `a_failed_append_that_cannot_be_undone_stops_writes_until_restart`, `a_record_embedded_in_a_torn_tail_does_not_block_restart`, `corruption_in_the_middle_is_repaired_only_on_request`; in `chain/tests/manager.rs`, `restart_after_torn_write_recovers_previous_block` and `a_failed_block_write_during_sync_is_recoverable`.
2. **Correct and well designed:**
   - fsync before apply;
   - never writing after damaged bytes;
   - refusing to auto-drop mid-file data;
   - repair keeps the data aside;
   - the `MAX_PAYLOAD` bound;
   - read/write open, so truncation works on Windows.
   - An append-only file can be backed up safely while the node runs, because a copy is a valid prefix plus at most a torn tail (§4).
3. **Incomplete:** no file header (R10-3); no index; no read-by-id; no streaming load.
4. **Fragile:**
   - the tail heuristic (R10-8a, known);
   - whole-file reads;
   - CRC32 is fine for crash detection but not tamper-evident (acceptable, since the file is local).
   - No fsync of the directory after the file is created. That is minor, because a lost empty file only costs a resync.
5. **Exploitable:** only via what gets written (R10-1). The file format itself is not remotely reachable.
6. **Inefficient:** peak memory at load is about twice the file size; one fsync per block (fine at 120 s blocks).
7. **Does not scale:** a single file that is fully read and fully replayed at every start.
8. **Missing:**
   - an offset index;
   - segmentation (e.g. 128–512 MiB segment files, which make pruning and backups easier);
   - a format version.
9. **Redesign:** keep it as the body archive; add an index and a state DB (§5).
10. **Innovation:** a per-segment BLAKE2/BLAKE3 digest in a small manifest, which gives tamper-evident backups and cheap `verify-store`.
11. **Before testnet:** R10-3, R10-8a (A6), R10-1(b).
12. **Deferrable:** streaming, segments, index.
13. **Never change:**
    - the fsync-before-apply ordering;
    - never appending after damage;
    - never silently dropping mid-file data.

### 2.2 Chain manager (`chain/src/manager.rs`)

1. **Implemented:**
   - the invariant "state = apply(bodies of `connected[1..]`)";
   - the most-work body-complete switch;
   - replay with a parent-wait queue;
   - the PoW-hash preload;
   - templates;
   - the locator;
   - header batches with pre-computed PoW.
2. **Correct:**
   - bodies are checked against `tx_root` before a header can enter;
   - an invalid body marks its descendants invalid and re-selects;
   - replay tolerates only deterministic errors (`Body`, `Duplicate`, `InvalidParent`).
   - `restart_replays_the_store_without_recomputing_pow`, `restart_rebuilds_the_px_state_exactly` and `restart_after_out_of_order_body_arrival_replays_the_store` exist.
3. **Incomplete:** replay tie-breaks (known); H1 (known).
4. **Fragile:**
   - R10-2 (panic mid-apply);
   - `on_best_chain` compares `connected[height]`, which is fine;
   - the orphan log message (R10-3).
5. **Exploitable:** R10-1; the known reorg revalidation DoS.
6. **Inefficient:**
   - every replayed block runs `sync_state`, including `fork_height` and a mempool revalidation of an empty pool. That is cheap per block but O(n) calls;
   - bodies are cloned for `/blocks` and `block()`.
7. **Does not scale:** `bodies` (PX-F1), `invalid` (unbounded), `CachedPow` (R10-12), and every start re-validates everything (PX-F3).
8. **Missing:**
   - a trait boundary for body storage (read by id);
   - a persisted connected tip;
   - persisted `invalid` flags, so invalid blocks are not re-validated at every start;
   - metrics (validation time, lock hold time).
9. **Redesign:**
   - separate `ChainManager` into three parts: a header index, a body store (disk) and a state DB, each behind its own trait;
   - keep `sync_state` as the single mutation point, with one DB transaction per connected block (§5).
10. **Innovation:** a "verified-state digest" per height (§5.3), so a restart can check its own state cheaply.
11. **Before testnet:** R10-1, R10-2.
12. **Deferrable:** everything in §5.
13. **Never change:**
    - body-before-header acceptance (the `tx_root` check);
    - the invariant and its single mutation path;
    - the replay-through-the-same-code-path principle (keep it as `--reindex`).

### 2.3 `MemoryChain` (`tx/src/state.rs`) and PX state (`px/src/state.rs`)

1. **Implemented:**
   - the output set;
   - the key-image and one-time-key sets;
   - PX (frontier, a root window of 100, nullifiers, pool);
   - the registry;
   - record and nullifier logs;
   - per-block undo.
2. **Correct:**
   - the PX `apply_block` is atomic on error (`apply_inner` plus undo);
   - containment of the pool (`checked_sub`);
   - anchors refer to roots from before the block;
   - duplicate contracts are rejected in validation (`tx/src/validate.rs:539, 631, 867`), so `registry.remove` on undo is safe.
3. **Incomplete:** `TreeFull` is not checked in validation (known); `MemoryChain::apply_block` is not atomic (R10-2).
4. **Fragile:** `px_contract_log.truncate(len - contracts.len())` relies on registrations being appended last. That is true today; document it and assert it.
5. **Exploitable:** only through memory growth (R10-6, R10-7, PX-F1).
6. **Inefficient:**
   - `px_records(from, to)` and `px_nullifiers` are linear filters, even though the data is ordered (R10-5);
   - `cumulative_outputs()` is O(height) on every call.
7. **Does not scale:**
   - the undo snapshots (R10-6);
   - all sets are in RAM. A privacy chain can never prune outputs (any output can be a ring member), key images or nullifiers, so the state grows monotonically and must live on disk.
8. **Missing:** persistence (a "persistent store that behaves identically" is promised in the module docs, `tx/src/state.rs:6-7`).
9. **Redesign:** a DB-backed `ChainView`, with differential tests against `MemoryChain` (§5.4).
10. **Innovation:** a commitment over the state (§5.3).
11. **Before testnet:** nothing beyond R10-2. R10-6 can wait until the trial is measured.
12. **Deferrable:** R10-6, R10-7, persistence.
13. **Never change:**
    - the `ChainView` semantics;
    - the order in which outputs get global indices;
    - PX atomicity and containment.

### 2.4 Node binary (`node/src`)

1. **Implemented:**
   - CLI, TOML and defaults, with precedence and `deny_unknown_fields`;
   - per-network data directories;
   - an exclusive `LOCK`;
   - `--repair-store`;
   - the RNG seed from the OS;
   - load timing in the log;
   - an RPC warning for non-loopback binds;
   - no DNS in proxy-only mode;
   - listening disabled by default in proxy-only mode.
2. **Correct:**
   - the lock is taken before repair;
   - mainnet is refused;
   - typos are errors;
   - the Tor configuration binds only to loopback.
3. **Incomplete:**
   - shutdown handles only SIGINT (R10-9);
   - no store/network identity check (R10-3).
4. **Fragile:** poison recovery (R10-2); the RPC warning only warns (R10-4).
5. **Exploitable:** R10-4.
6. **Inefficient:** —
7. **Does not scale:** the start time (PX-F3).
8. **Missing:**
   - `/health` and `/metrics` (§4);
   - version, build and kernel id in `/info`;
   - a JSON log option;
   - `--reindex`, `--verify-store`;
   - a data directory permission check (0700) on Unix.
9. **Redesign:** a chain actor thread that owns `ChainManager` (removes the lock-on-async-thread class).
10. **Innovation:** a `blacksilk-node doctor` subcommand that checks the store header, permissions, disk space, clock skew and port reachability.
11. **Before testnet:** R10-2, R10-4, and the node-side part of R10-3.
12. **Deferrable:** the actor, `doctor`, JSON logs.
13. **Never change:**
    - loopback RPC by default;
    - no DNS in proxy-only mode;
    - `deny_unknown_fields`.

### 2.5 RPC (`rpc/`, `node/src/lib.rs`)

1. **Implemented:**
   - 9 endpoints;
   - count limits (`/blocks` 100 blocks and 64 MiB of hex; `/outputs` 1,024; `/px/*` paginated by count);
   - a body limit;
   - CPU-bound submits on `spawn_blocking`;
   - bulk-only PX lists (good for privacy).
2. **Correct:**
   - with P2P, `/tx` enters the Dandelion stem;
   - wallets download whole lists (contract and commitment privacy).
3. **Incomplete:** auth, Host check, timeouts, pagination of `/distribution` (R10-4, R10-5, R10-11).
4. **Fragile:**
   - `m.block_at(h).expect("connected height")` is safe only because `end ≤ height` and the lock is held;
   - `SubmitResult.already_pooled` parses `Debug` names. That is a stringly-typed API; move to an error code enum.
5. **Exploitable:** R10-4, R10-5.
6. **Inefficient:** R10-5.
7. **Does not scale:** `/distribution`; `/px/commitments` over all records.
8. **Missing:**
   - a restricted/public mode;
   - an API version;
   - structured error codes;
   - `/health`, `/metrics`.
9. **Redesign:** two listeners, a wallet API and an admin/miner API (§3).
10. **Innovation:**
    - PIR-style or bucketed decoy fetches: fetch fixed, randomised output ranges instead of exact ring indices (docs/blocks.md §9 already lists this as future work);
    - serve compact per-block PX filters (commitments plus ciphertexts only) so that wallets do not download full blocks.
11. **Before testnet:** R10-4; R10-5 slicing and `spawn_blocking`.
12. **Deferrable:** the split API, restricted mode, PIR.
13. **Never change:**
    - bulk-only PX endpoints (never add "get contract X" or "get record for position P" lookups, which leak interest);
    - no wallet or key operations in the node.

### 2.6 Deployment (`deploy/`)

1. **Implemented:**
   - configurations for node, seed, Tor, lab and regtest;
   - a hardened systemd unit (`ProtectSystem=strict`, empty capabilities, `SystemCallFilter`, `UMask=0077`, `KillSignal=SIGINT`);
   - a miner unit;
   - a Dockerfile (non-root, `--locked`, RPC not exposed);
   - an install script;
   - a health script.
2. **Correct:** loopback RPC everywhere; the Tor configuration is loopback-only; `MemoryDenyWriteExecute` works for the interpreter-only RandomX.
3. **Incomplete:**
   - Docker: no `STOPSIGNAL`, no `HEALTHCHECK` (R10-9);
   - `check-node.sh` parses JSON with `sed` (fragile); it does not check a stale tip.
4. **Fragile:**
   - `miner.env` has mode 0644 (the address is readable by local users; low);
   - the install script builds as `$SUDO_USER` in the repository, which is fine.
5. **Exploitable:** —
6. **Inefficient:** —
7. **Does not scale:** —
8. **Missing:**
   - log rotation guidance;
   - backup and restore procedure;
   - an upgrade and rollback procedure;
   - alert rules;
   - `LimitNOFILE` is set but not checked against `max_inbound`;
   - `MemoryMax`/`MemoryHigh` (useful against R10-1-type growth, so systemd restarts instead of the host OOM-killing other processes).
9. **Redesign:** —
10. **Innovation:** reproducible-build attestation printed in `/info` (a hash of the binary).
11. **Before testnet:** `STOPSIGNAL`; `MemoryHigh`/`MemoryMax` guidance; a stale-tip check in `check-node.sh`.
12. **Deferrable:** the rest.
13. **Never change:** the RPC is not published in the container; the systemd sandbox.

---

## 3. RPC: target model

**Two surfaces:**
- **Wallet API** (read, plus `/tx`):
  - `/blocks`, `/distribution` (paginated), `/outputs`, `/px/*`, `/tx`, `/info` (reduced).
  - It may be offered to others only in a "restricted" mode, as Monero's `--restricted-rpc` [ext: https://docs.getmonero.org/interacting/monerod-reference/] does.
- **Admin/miner API** (loopback plus cookie, always):
  - `/template`, `/block`, peer and ban administration, metrics.

**Authentication:**
- a random cookie in `<data_dir>/.rpc-cookie` (0600), regenerated at every start;
- optionally a static token from the configuration for remote wallets over TLS or Tor;
- constant-time comparison;
- a Host-header allowlist;
- no CORS;
- refuse to bind non-loopback without auth.

**Rate and cost limits:**
- a semaphore per class;
- per-connection timeouts;
- a `/tx` body limit equal to the maximum transaction size;
- `/blocks` bounded in bytes (as now);
- pagination on every list endpoint;
- no O(chain) work per request.

**Never expose** (on any public or restricted surface):
- `/block` and `/template`. They show mempool contents and fees, and they cost CPU.
- peer lists, addresses, ban lists, connection directions and per-peer stats. These give network topology, which is eclipse and deanonymization input.
- mempool listings with first-seen times or source peers. Together with Dandelion stem state they point to the transaction origin.
- anything that tells whether a given transaction is in the *stempool*.
  - [unknown]: whether `/tx` returns a distinguishable error for a transaction this node holds in its stem. This should be checked, because a public `/tx` could otherwise be a stem-probing oracle.
- per-output or per-contract lookup endpoints that reveal a wallet's interest (keep bulk-only).
- debug and log endpoints.
- any wallet or key operation (there are none today; keep it so).

---

## 4. Operator experience

**Health and metrics** (loopback, admin surface):
- **`/health`:**
  - liveness: the process is up and the store is writable;
  - readiness: `header_height − height ≤ k`, the tip is younger than 30 min on testnet, `peers ≥ 1`, and the store is not poisoned.
- **`/metrics`** (Prometheus text format; implemented by hand or with the pure-Rust `prometheus-client` crate):
  - height, header height, peers in/out, and bans;
  - mempool transactions and bytes;
  - store bytes;
  - replay seconds at start;
  - block validation seconds (histogram), and PX verification seconds;
  - chain-lock wait and hold (histogram);
  - reorg depth (counter plus maximum);
  - misbehaviour disconnects by reason;
  - RandomX cache or dataset rebuilds;
  - the RSS of the process.
- **Structured logs:** a `--log-format json` option with a stable `event` field. Privacy redaction as in R10-10.
- **Alerts** (to ship as an example rules file):
  - no new tip for more than 30 minutes;
  - a header/body gap for more than 15 minutes;
  - a reorg of depth 10 or more;
  - no peers;
  - store write errors;
  - disk below 10 % free;
  - RSS above the configured limit;
  - repeated start without a "clean shutdown" marker.

**Backups:**
- `blocks.dat` is append-only, so a hot copy is a valid prefix plus at most a torn tail. The loader repairs such a tail, so it is a safe backup ([src] reasoning; add a test that copies while appending).
- Document this, and that `peers.json` and `bans.json` are optional.
- With a DB (§5), use the DB's savepoint or snapshot API, or back up only `blocks.dat` and run `--reindex`.
- **Never back up wallets with node data** (R10-13).

**Upgrades:**
- Versioned file headers (R10-3) and a DB schema version with explicit forward migrations.
- A downgrade is refused with a clear message.
- `--reindex` is the universal fallback.
- `/info` reports the node version, the consensus fingerprint and the PX kernel id, so operators can see split-version networks.
- A consensus change needs the reset procedure that already exists (docs/testnet-reset-plan.md).

---

## 5. Architecture: a production-grade storage layer for BlackSilk (pure Rust)

### 5.1 Requirements specific to this chain

**Monotonic, unprunable state:**
- the output set: any output can be a ring decoy, so it can never be pruned;
- the key-image set and the one-time-key set (C4 rule);
- PX nullifiers;
- the PX commitment leaves (wallets need positions and commitments);
- the contract registry.

**Bounded state:**
- the PX root window (100 roots);
- the frontier (33 × 32 B);
- the pool.

**Prunable:**
- block bodies older than N, but only on non-archival nodes. Wallet scanning needs bodies, both the v1 outputs' encrypted data and the PX ciphertexts, so the default stays archival. A pruned mode must refuse `/blocks` below its prune height.

**Undo:** kept for every block, on disk. K4 sets no depth limit, and deltas are small (R10-6).

**Startup:** open the DB, check the schema, the network and genesis, and the persisted tip, then load the header index (about 150 B per header; 1 M headers ≈ 150 MB, which can stay in RAM or be memory-cached). Re-verify **nothing**.

**Crash consistency:**
- The unit of atomicity is "connect or disconnect one block": state changes, undo record, tip pointer and the `invalid` flag, all in **one DB write transaction**.
- The body is appended and fsynced to the body archive *before* that transaction commits. That is the current order.
- On start, a body archive that is ahead of the DB tip is normal, and the DB is the truth.
- A DB tip that points past the archive is a fatal inconsistency: refuse to start and suggest `--reindex`.

### 5.2 Pure-Rust KV options

| Engine | Model | Status (as of 2026-09) | Crash-safety claims | `unsafe` | Verdict |
|---|---|---|---|---|---|
| **redb** | Copy-on-write B+tree; ACID; one writer and MVCC readers | Actively maintained. 3.0 (2025-08-09), 4.1.0 is on docs.rs. The README says "Stable and maintained… file format is stable" [ext: https://github.com/cberner/redb, https://docs.rs/crate/redb/latest] | Crash-safe by default. **1PC+C:** a single fsync with an XXH3-128 Merkle checksum and a "god byte" primary flip. **2PC:** two fsyncs. Repair on open. The design doc says 1PC+C relies on non-cryptographic checksums and "users who need to accept malicious input are encouraged to use 2PC" [ext: https://github.com/cberner/redb/blob/master/docs/design.md] | The mmap backend was removed because its soundness could not be proven, so the public API is safe [ext: redb CHANGELOG; author on HN https://news.ycombinator.com/item?id=39323183]. Internal `unsafe` count is [unknown]; run `cargo geiger` before adoption | **Recommended.** Use **2PC** (block data is attacker-influenced) |
| **fjall** | LSM tree; keyspaces with cross-keyspace atomic batches; single-writer or optimistic transactions | 3.0 released 2026-01-02 with a new on-disk format "designed for longevity" [ext: https://fjall-rs.github.io/post/fjall-3/] | By default, writes go only to OS buffers. `persist(PersistMode::SyncAll)` is needed per commit. The journal is fsynced when the database is dropped [ext: https://github.com/fjall-rs/fjall] | Claims "100% safe & stable Rust" [ext: README]. Its dependencies (compression, hashing) need review | A viable alternative when write volume dominates. Its durability is opt-in, so there is more room for mistakes. Background compaction threads add operational complexity |
| **sled** | Lock-free B-link tree (log-structured) | Beta. The README says it is out of sync with a large rewrite, and "the on-disk format is going to change … manual migrations before 1.0". It says "if reliability is your primary constraint, use SQLite" [ext: https://github.com/spacejam/sled] | Periodic flush (500 ms by default) | Extensive internal `unsafe` [assumed, from its lock-free design] | **Reject** |
| LMDB, RocksDB (Monero, Zebra) | — | Mature | Strong | C and C++ | Excluded by the no-C/FFI policy |

**Recommendation: redb 4.x with two-phase commit.** Why:
- a B+tree matches the access pattern (point lookups on key images, nullifiers and outputs by index; range scans by height);
- MVCC readers let the RPC read without the chain write lock, which removes R10-5 structurally;
- one fsync-backed transaction per block fits the atomicity unit;
- the format is stable, with an upgrade-path promise;
- the API is safe.

**Keep the storage behind a small trait:**
- `StateStore`: `begin_block` / `commit`, `get_output`, `key_image_spent`, …;
- a `BodyArchive` trait.

Then the engine can be replaced, and `MemoryChain` stays as the reference implementation for tests.

### 5.3 Snapshots and verified-state checkpoints

**State digest.** Maintain incrementally a *state digest* per height, H = BLAKE2b over:
- a running hash of outputs in index order;
- a multiset hash (for example, additive in the Ristretto group, or a sorted-Merkle rebuilt at intervals) of key images, one-time keys and nullifiers;
- the PX frontier root and the pool;
- a hash of the registry log.

**Uses:**
- (a) a cheap self-check at start: recompute from the DB lazily or in the background, and compare with the digest stored per height;
- (b) cross-node comparison in labnet ("do all nodes have the same state at height h?"), which gives strong evidence for determinism;
- (c) later, AssumeUTXO-style bootstrap from a published snapshot with background full validation [ext: https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md].

**Rules:**
- (c) is a trust and policy decision. It needs a careful privacy review: a snapshot carries every output, which is public anyway.
- **Never** put the digest into consensus or headers without the full change process.
- For the testnet it is P3.

### 5.4 Migration path from today's log

Each step is non-consensus and keeps the old replay path as the oracle.

| Step | Content | Removes | Priority |
|---|---|---|---|
| 0 | R10-1 storage policy; R10-3 file header; R10-8a tail rule; R10-2 fatal poison | DoS, silent loss, divergence | P0/P1 (before public testnet) |
| 1 | Bodies out of RAM: an in-memory `id → (offset, len)` index built during load; `BodyArchive::read(id)`; LRU cache; side-branch bodies bounded | PX-F1 | P1 (early in the trial) |
| 2 | Undo as deltas (R10-6); `px_records` without ciphertexts (R10-7); streaming load | PX-F2, R10-6/7 | P2 |
| 3 | Interim fast start without a DB: every N blocks, write an atomic *state snapshot* (serialized `MemoryChain` + `generated` + `connected` + the blocks.dat offset + the state digest; tmp + fsync + rename + dir fsync). At start, load the snapshot and replay only the tail. Keep `--reindex` for full replay | PX-F3 (mostly) | P2 |
| 4 | A redb `StateStore` implementing `ChainView`, with a differential property test: the same random block and reorg sequences are applied to `MemoryChain` and `DbChain`, and all `ChainView` answers and state digests are compared after every step. `--reindex` builds the DB from `blocks.dat` | RAM-bound state | P2–P3 |
| 5 | Segmented body archive, optional pruning (non-archival only), persisted `invalid` set and header index; state digests per height | Startup/disk scaling | P3 |
| 6 | Snapshot bootstrap (AssumeUTXO-like), only after an owner decision | Initial sync time | P3 / future |

**Testing to require at each step:**
- crash injection at every write boundary (kill between the archive fsync and the DB commit, and in the middle of a snapshot write);
- a real disk-full run (the docs say it is untested);
- a restart-equivalence test: a node that restarts after each block has the same digest as one that never restarts;
- a long-chain benchmark of start time and RSS.

---

## 6. What must never be changed (storage, node, RPC)

- The body is fsynced before its state is applied, and state changes are atomic per block.
- The node never silently discards data in the middle of the store (refuse, and repair only on request).
- Replay and reindex run through the *same* validation code as live blocks.
- Stored PoW hashes are trusted only for the node's own store, and never for peer data.
- The RPC binds to loopback by default; there is no wallet or key material in the node; PX endpoints are bulk-only.
- Data directories are per network, and there is no DNS in proxy-only mode.
- The `ChainView` semantics and the global output index order. Changing either is consensus.

## 7. Before testnet vs deferred

**Before a public testnet:**
- **P0:**
  - R10-1 (a/b);
  - R10-3;
  - R10-8a (in progress with A6).
- **P1:**
  - R10-2;
  - R10-4;
  - R10-5 (slice plus `spawn_blocking`);
  - migration step 1 (bodies out of RAM) early in the trial.

**Deferred (P2/P3):**
- R10-6, R10-7, R10-9, R10-10, R10-11, R10-12, R10-13, R10-14, R10-15;
- §4 metrics, health, JSON logs and alerts. The alerts are P2, but a minimal `/health` and a stale-tip check are cheap and worth doing early;
- §5 steps 2–6.

## 8. Limits of this review

- **Nothing was executed.**
  - The DoS figures in R10-1 are derived from constants and the brief's hash rates.
  - Whether ~9 MB of decodable garbage fits past `Transaction::decode` (the PX blob limits) is [unknown] until a test builds such a block.
- **Axum and hyper timeout defaults (R10-11)** are [assumed].
- **redb's internal `unsafe`** was not counted.
- **The DNS-rebinding exposure** is inferred from the missing Host check [src] and the known attack class. It has not been demonstrated against this node.

**Sources:**
- https://github.com/cberner/redb
- https://github.com/cberner/redb/blob/master/docs/design.md
- https://github.com/cberner/redb/blob/master/CHANGELOG.md
- https://docs.rs/crate/redb/latest
- https://news.ycombinator.com/item?id=39323183
- https://github.com/fjall-rs/fjall
- https://fjall-rs.github.io/post/fjall-3/
- https://github.com/spacejam/sled
- https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp (AcceptBlock unrequested-block rules)
- https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md
- https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md (cookie auth)
- https://docs.getmonero.org/interacting/monerod-reference/ (restricted RPC)
