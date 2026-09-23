# BlackSilk Testnet Readiness Audit

Status: **ready for a controlled multi-machine testnet trial; NOT yet ready for a
public testnet launch.**
- All Phase 2 findings are closed (see *Finding status after R1–R6*).
- The P2P network is implemented (R5).
- The testnet configuration is final (R6): genesis, seed system and deployment files.
- Two 3-hour lab-network runs passed every check (R6).

Remaining before a public testnet:
- the multi-machine procedure in `docs/testnet.md` §7, including a 72-hour run: only
  one machine was available here;
- deployed seed nodes, added to the built-in list;
- the Linux deployment files, run and verified on Linux;
- an external cryptographic review of the transaction layer and the Janus anchor
  (required before mainnet).

Smart contracts (`docs/contracts.md`, approved model) are being implemented (R7). The
cryptography (M1) and the engine and state (M2) are done, but they are **not yet part of
consensus**. Private execution with zero-knowledge proofs is the current priority (R8): the proof
layer, the VM's execution layer and its core constraint system are done; a compiled Rust
program has been proven. The Poseidon2 syscall circuit, the kernel and integration remain.
Contracts will activate later, at a fork height or with a testnet reset.

This file tracks the audit defined in `Claude.md`.
Each finding lists where it is, what goes wrong, and its severity. Findings stay
open until a fix lands **and** a test demonstrates it.

Severity: **C** = critical (breaks consensus, lets funds be stolen or created, or
removes privacy); **H** = high; **M** = medium.

---

## Phase 1: Build baseline

**Update (R4): resolved.** The audit machine now uses
`stable-x86_64-pc-windows-msvc` (VS 2022 Build Tools), and the rebuilt workspace
builds and passes all tests. The original baseline is kept below for the record.

Toolchain at the time: rustc 1.98.1, `stable-x86_64-pc-windows-gnu` (no MSVC/gcc on the
audit machine).

**Blocked by the environment, not yet a verdict on the code.** rustup's GNU
toolchain ships `dlltool` without the assembler it needs, so `getrandom`
(`raw-dylib`) fails and every crate that depends on it is blocked. A real
C/linker toolchain (MSVC Build Tools or MinGW-w64) is required, and
`ml-dsa-44` needs a C compiler anyway.

Errors found so far that do not depend on the toolchain:

| # | Crate | Error |
|---|-------|-------|
| E1 | `smart-contracts/randomx` | Does not compile (13 errors). Missing modules `vm` (it is `vm/state.rs` with no `vm/mod.rs`) and `jit`. It uses the non-existent `blake2::Blake2b256` and a wrong `SaltString` API. Its const-assert fails because instruction frequencies don't sum to 256, and it has borrow-check errors. |
| E2 | `gui-wallet` | The git-pinned `iced` master fails: "No futures executor has been enabled". The moving branch pin (D2) has drifted. |

---

## Phase 2: Consensus-critical audit

### 2.1 Proof-of-Work: the project does not implement RandomX

| # | Sev | Location | Finding |
|---|-----|----------|---------|
| P1 | C | `node/src/randomx/vm.rs` | The "RandomX VM" is a custom hash, not RandomX. It never reads the dataset (`read_memory_u64` only touches the scratchpad), so it is **not memory-hard**. The scratchpad fill, program generation, instruction semantics (e.g. `IMUL_RCP` is division, `FSCAL_R` multiplies by 2^-64) and finalization (Blake2b over 8 sampled 64-byte chunks) all diverge from the spec. |
| P2 | C | `node/src/randomx/cache.rs:74` | The Argon2d "cache" writes 32 bytes per 256 KiB chunk and leaves the rest zero (≈99.99% zeros). The spec requires the full 256 MiB Argon2d memory (3 iterations, `RandomX\x03` salt). |
| P3 | C | `node/src/randomx/mod.rs:62` | `randomx_hash()` builds a new cache **and a 2 GiB dataset on every call**, then never uses the dataset. Each block verification allocates 2 GiB: a trivial memory-exhaustion DoS. |
| P4 | C | `miner/src/randomx/*`, `miner/src/randomx_pro.rs`, `miner/src/pure_randomx.rs`, `smart-contracts/randomx/*` | There are three more independent "RandomX" implementations. None has been checked against the official test vectors. `smart-contracts/randomx` declares `mod jit;` with no `jit.rs`, and its Argon2 call outputs a hash tag instead of the Argon2 memory blocks. |
| P5 | C | miner `main.rs:922` vs node `randomx_verifier.rs:279` | Miner and node disagree on every PoW input. The **key** is the constant `"BlackSilk-RandomX-Key-v1"` on the miner and `prev_hash‖height` on the node. The **input** is the ASCII template `"h:prev:ts:addr"`+nonce on the miner and a binary header on the node. The **target** check is `hash_BE ≤ 2^256/difficulty` on the miner and `u64_LE(hash[0..8]) ≤ difficulty` on the node. They also use **different VM code**. No block the miner produces can verify. |
| P6 | C | `node/src/randomx_verifier.rs:173-276` | Validity depends on **wall-clock time**. The node rejects a block if *its own* recomputation ran "too fast" relative to a calibration run, which is non-deterministic across machines and causes consensus splits. The time measured is the verifier's, not the miner's, so it cannot detect GPUs/ASICs anyway. |
| P7 | C | `node/src/randomx_verifier.rs:649-727` | Heuristic "integrity" checks reject valid hashes. `calculate_access_correlation` compares values mod 1000, so its expected value is about 0.001 against a required 0.7: **every block is rejected** while `secure` is on (the default). It also rejects hashes with more than 8 zero bytes, which are exactly the hashes that meet high difficulty. |
| P8 | C | `node/src/lib.rs:58`, `http_server.rs:637` | Difficulty semantics are inverted. Testnet "minimal difficulty" `1` means `hash ≤ 1`, a 2^-64 chance per hash, **the hardest possible target**. Mainnet adjustment (`lib.rs:153`, `:745`) raises the number when blocks are slow, which makes mining *easier* under node semantics. |
| P9 | H | `node/src/lib.rs:113` vs `:719` | There are two different difficulty algorithms (±25% vs ×4), and `validate_block_with_chain` only warns on a mismatch (`lib.rs:854`). Difficulty is not enforced. |
| P10 | H | `node/src/randomx_verifier.rs:291` | The RandomX key changes **every block** (`prev_hash‖height`). Even a correct RandomX would then need a 2 GiB dataset rebuilt every block. Monero rotates the key every 2048 blocks with a 64-block lag. |

### 2.2 Block validation and chain handling

| # | Sev | Location | Finding |
|---|-----|----------|---------|
| B1 | C | `node/src/lib.rs:765-797`, `:799` | `Chain::add_block` calls `validate_block(block)` with **no chain context** and **no PoW check**. Blocks from P2P (`lib.rs:303`) are checked only for prev-hash linkage and coinbase reward, so anyone can append blocks with zero work. |
| B2 | C | `node/src/lib.rs:806` + `http_server.rs:661-669` | `validate_block` rejects blocks with no transactions, but `handle_submit_block` builds blocks with `transactions: vec![]`. **Mined blocks can never be added**: the chain cannot grow through mining. |
| B3 | C | `node/src/http_server.rs:601-612` | The node rebuilds the header from **its own clock** at submission time, with `merkle_root` computed from an empty tx list. It ignores the header the miner actually hashed, so any PoW check is meaningless. |
| B4 | C | `node/src/lib.rs:860` | Merkle root, block hash, block-contained transactions (signatures, key images, range proofs) and timestamps are never validated (`TODO`). |
| B5 | C | `node/src/lib.rs:1183-1275` | Reorg compares the work of *all* incoming blocks with the work of the local blocks *after the fork point*, uses no PoW, and truncates the chain **before** validating replacements. A failed replacement leaves the chain truncated. |
| B6 | H | `node/src/lib.rs:329-333` | `GetBlocks` returns the entire chain in one JSON message with no limit (bandwidth/memory DoS). |
| B7 | C | `node/src/main.rs:829`, `lib.rs:1322` | The production node uses `start_p2p_server_with_privacy`, whose handler `handle_client_with_privacy` is an **empty stub**. The deployed node performs no P2P message handling: no block relay and no sync. |
| B8 | H | `node/src/lib.rs:246` | `read_message` builds a new `BufReader` per call, so buffered bytes of subsequent messages are lost. `read_line` is unbounded (memory DoS). |
| B9 | M | `node/src/main.rs:1070-1100`, `:1210` | CLI commands `sync`, `validate`, `export`, `import`, `privacy mix-test` print "✅ completed successfully" but do nothing. |

### 2.3 Transaction signatures, double-spend and balance

| # | Sev | Location | Finding |
|---|-----|----------|---------|
| S1 | C | `node/src/lib.rs:388-503` | The node's ring-signature verifier is **forgeable without any secret key**. `L_0 = r_0·G` has no public-key term, and `c_vec[0]` is only compared at the end against a value the forger computes. It is also a different algorithm from the wallet's signer (`primitives/src/ring_sig.rs`), so honest multi-member signatures fail. |
| S2 | C | `primitives/src/ring_sig.rs`, `lib.rs:537-545` | Ring signatures are **not linkable**. `key_image` is a free field that the signature never binds, so double-spend protection is bypassed by choosing a fresh random key image. |
| S3 | C | `node/src/lib.rs:537`, `wallet/src/main.rs:637` | Signatures cover `tx.extra` (empty) or the constant `"blacksilk_tx"`, not the transaction. Anyone can replace a transaction's outputs and keep the signatures. |
| S4 | C | `node/src/lib.rs:529-601` | There is **no balance check** (Σinputs = Σoutputs + fee via commitments), and inputs carry no amount or pseudo-output commitments. Unlimited coins can be created. |
| S5 | C | `primitives/src/quantum_ring.rs` | The "post-quantum ring signature" is not a ring signature. `verify` ignores the message and requires every member's response to verify under that member's key, so no honest signer with decoys can pass. Key images are `Keccak(pk)`, which exposes each member's public key. `build()` panics (`responses[i] = …` on an empty `Vec`). No practical, audited lattice-based linkable ring signature is available off the shelf. |
| S6 | H | `pqcrypto_native` | Wraps PQClean **C code via FFI** (`pqcrypto-dilithium`, `pqcrypto-falcon`), which conflicts with the pure-Rust requirement. `keypair_from_seed` ignores the seed, so deterministic wallet recovery is impossible. `verify()` is `unimplemented!()`. |
| S7 | M | `pqsignatures` | Pure Rust, but uses `crystals-dilithium` (round-3 Dilithium, **not** FIPS 204 ML-DSA) and `falcon-rust` 0.1.x (young, unaudited). The only practical use today is the optional `quantum_signature`, which again signs `tx.extra`. |
| S8 | H | `ml-dsa-44/build.rs` | Compiles C sources with `cc` (not pure Rust; needs a C toolchain). |

### 2.4 Keys and privacy (details in Phase 3)

| # | Sev | Location | Finding |
|---|-----|----------|---------|
| K1 | C | `primitives/src/lib.rs:84-96` | `StealthAddress::generate(None)` derives view **and** spend keys from the hard-coded seed `[42u8; 32]`, so every classical wallet made this way has the **same private keys**. |
| K2 | C | `wallet/src/main.rs:630-673` | Ring size is 1, and outputs are paid to the recipient's **public address in the clear** (no one-time keys). The key image depends only on the spend key, so a wallet can spend at most once before being flagged as a double-spend. On-chain privacy is effectively absent. |
| K3 | C | `node/src/lib.rs:870-877`, `:970` | `tor_only: true` rejects every inbound TCP peer, because a Tor-proxied connection arrives from 127.0.0.1 and never looks like `.onion`. Outbound Tor is unimplemented ("In a real implementation, use Tor SOCKS5"). |

### 2.5 Build and supply chain

| # | Sev | Location | Finding |
|---|-----|----------|---------|
| D1 | H | `build.rs` (root) | Every build of the root crate `git clone`s `pq-crystals/dilithium` at an **unpinned HEAD**, runs `make`, and **executes** the result. That is arbitrary remote code execution at build time. |
| D2 | M | root `Cargo.toml` | `[patch.crates-io]` pins `iced`/`winit` to moving git branches (`master`/`main`), so builds are not reproducible. |
| D3 | M | repo root | Stray files (`hello.c`, `parser.rs`, `testmsg.txt`, `REMOVE_ME_CLEANUP_LOG.txt`, empty `*.rs` under `pqcrypto_native/algorithms`, empty `miner/src/main_new.rs`). |

---

## Remediation log

### R1: Pure-Rust, spec-conformant RandomX (`randomx/`, crate `blacksilk-randomx`)

The node and miner now have a single RandomX implementation available (not yet wired
in; see "Next"). It is a port of the reference implementation (tevador/RandomX,
BSD-3-Clause, license retained in `randomx/LICENSE`), RandomX **v1** as used by Monero.

- `#![forbid(unsafe_code)]`, no FFI, no C. Dependencies: `blake2` and `aes` (RustCrypto,
  using `hazmat` single-round AESENC/AESDEC equivalents).
- Floating-point rounding modes are **emulated exactly in software** (`randomx/src/fpu.rs`)
  instead of switching MXCSR, which Rust/LLVM cannot do soundly. The error-free transforms
  run on power-of-two-rescaled operands, and IEEE overflow is handled per mode.
  *Finding:* contrary to a naive reading of spec 4.3, the e registers **do overflow** past
  f64::MAX in real programs (official test vector 1b hits it thousands of times), so the
  overflow semantics (±MAX vs ±inf per mode) are consensus-critical.
- Light mode (cache only, 256 MiB) for verification; full mode (~2 GiB dataset) for mining.

**Evidence:** `cargo test -p blacksilk-randomx` passes every applicable official vector from
the reference `tests.cpp`:
- cache words
- all 10 SuperscalarHash program hashes
- 7 reciprocals
- 4 dataset items
- AesGenerator1R
- hash vectors 1a to 1e

It also passes six unit tests for directed rounding, overflow and infinity propagation. The
opt-in `--ignored` test builds the full 2 GiB dataset and gets the same official hash
(133 s on 8 threads).

**Performance (release, this machine):** cache init 0.63 s; light-mode hash about 0.45 s.
That is fine for verification at a 120 s block time, but slow for syncing long chains and
for mining. Follow-ups: faster superscalar execution for dataset generation and light
mode; mining throughput with full mode.

**Next:** wire the crate into node and miner behind one PoW definition, then delete the four
old implementations (`node/src/randomx*`, `miner/src/randomx*`, `miner/src/pure_randomx.rs`,
`miner/src/randomx_pro.rs`, `smart-contracts/randomx`). Findings P1–P4 close then.

### R2: Header-chain consensus (`consensus/`, crate `blacksilk-consensus`)

Specification: [`docs/consensus.md`](docs/consensus.md). The crate is pure Rust with no I/O.
It is the single definition of block validity for node and miner.

| Rule | Design | Replaces finding |
|---|---|---|
| Header | fixed 100-byte encoding; id = H(domain ‖ network_id ‖ header) | B3 (node rebuilt the header), network separation |
| PoW | RandomX(seed, full header) recomputed by every verifier; `h × d < 2^256` | P5 (miner/node mismatch), P6/P7 (timing/heuristic "checks" gone), P8 (inverted targets) |
| RandomX key | Monero schedule: epoch 2048, lag 64, seed taken from the header's own branch | P10 (per-block key) |
| Difficulty | LWMA-1 (N = 60, T = 120 s), enforced exactly | P9 (two algorithms, not enforced) |
| Timestamps | > median of last 11; ≤ now + 360 s (non-permanent) | none (previously no timestamp rules) |
| Merkle root | domain-separated leaves/nodes, no odd-node duplication | B4 (merkle never checked) |
| Chain selection | most cumulative work, first-seen on ties; validation independent of best chain | B1/B5 (unchecked P2P blocks, broken reorg) |
| Reorg | ordered disconnect/connect lists; the branch is fully validated before switching; `mark_invalid` re-selects | B5 |

**Evidence:** `cargo test -p blacksilk-consensus` runs 25 unit tests:
- header encoding, strictness and id separation
- `check_hash` boundaries
- the Monero seed schedule
- LWMA stability and response, with manipulation and timestamp-attack bounds
- median-time-past and FTL
- the Merkle shape and no-duplication property
- rejection of every invalid field
- heavier versus equal-work forks, with exact reorg lists
- arrival-order independence
- invalidation fallback
- a branch-aware seed across an epoch boundary

It also runs 2 end-to-end tests with **real RandomX**. A block mined through the miner-side
flow (template → header → `check_hash`) is accepted by `HeaderChain` + `RandomXPow`, and an
insufficient-work header is rejected.

**Not yet done:** wiring into the node and miner binaries and deleting the old
implementations. Neither binary builds on the audit machine yet (toolchain, Phase 1). The
node's P2P/HTTP layers are also slated for rebuild, so integration happens with that work.
Genesis headers are provisional until the transaction format exists.

### R3: Privacy transaction system (`crypto/`, `tx/`; spec `docs/transactions.md`)

The spec was written first, reviewed, and then implemented. The implementation is pure
Rust with `#![forbid(unsafe_code)]` in both crates, and has no FFI or C. Dependencies:
- `curve25519-dalek` 4.1.3 (Ristretto255; audited by Quarkslab, 2019)
- `blake2`
- `subtle`
- `zeroize`
- `rand_core` (traits only; the caller supplies the RNG)

**`blacksilk-crypto`:**

| Module | Content |
|---|---|
| `hash` | length-prefixed domain tags, `Hs` (wide reduction), `Hp` (RFC 9496) |
| `point` | canonical-only points and scalars |
| `generators` | `G`, `H`, 2×1024 BP+ generators (hash-to-group) |
| `keys` | seed → `k_s`, `k_v`; uniform `(D, k_v·D)` subaddresses; view-only keys |
| `stealth` | output creation and scanning, view tags, encrypted amounts |
| `janus` | Janus anchor |
| `clsag` | CLSAG, ring 16, key images |
| `bulletproofs_plus` | aggregated BP+ prover, single-MSM verifier, batch verifier |
| `nonce` | hedged randomness |

**`blacksilk-tx`:**

| Module | Content |
|---|---|
| `codec` | strict minimal varints; bounded counts before allocation |
| `types` | format, three-part hashing, `sig_message`, weight |
| `validate` | T1–T11, C1–C4, B1–B7, each with its own error variant; block-wide BP+ batch |
| `state` | reference chain state with undo |
| `builder` | transfer and coinbase construction with a self-check; standard fee |
| `scan` | wallet scanning |
| `decoy` | Monero gamma picker |

It also adds `HeaderChain::template_on(parent)` to consensus, so a node or miner can
extend a side branch.

**Evidence:** `cargo test -p blacksilk-crypto -p blacksilk-tx -p blacksilk-consensus` gives
**132 passing tests**. Clippy reports no warnings, and `cargo fmt --check` is clean.

62 crypto tests:
- canonical-encoding rejection, including ℓ, p, "negative" and high-bit encodings
- tag distinctness
- CLSAG at all 16 positions, with rejection of every modified input
- linkability (same output, different rings, same key image)
- the signer refusing wrong secrets
- key-less forgery
- nonce separation under a completely broken RNG
- BP+ for k = 1..16 and boundary amounts
- the optimized verifier cross-checked against a direct round-by-round verifier written
  from the paper's equations
- every single-element proof mutation rejected
- statement binding
- malicious-prover forgeries rejected: 2^64 via a non-binary bit, −1, and a negative bit
- batch detection of any bad proof, and batch weights defeating cancelling errors
- 12 Janus anchor attack scenarios (spec §12.6)

43 tx tests:
- one negative test per rule, asserting the exact error
- **every single-bit flip of a valid transaction's bytes rejected** (2 × ~1.6 k cases)
- double spends within one block and across blocks, and replay
- cross-network replay
- an **inflation attack with valid signatures and balance** (negative output commitment),
  rejected only by BP+, individually and in the block batch
- overspend
- a **Janus probe inside a valid on-chain transaction**, accepted by consensus and refused
  by the victim's wallet
- decoder fuzzing: truncations, random corruption, random buffers, oversize, huge counts
- privacy: uniform output encoding, a uniformly positioned change output, a varying real
  ring position, outsiders and view-only wallets, unlinkable repeat payments
- decoy distribution
- header-chain integration: `tx_root` binding, and a real reorg through `HeaderChain` that
  undoes a payment, which is then re-mined

**Findings closed by this work (for the new code path):**
- S1: CLSAG is unforgeable.
- S2: key images are bound and unique.
- S3: signatures cover everything.
- S4: balance plus range proofs.
- K1: seeds come from a CSPRNG.
- K2: ring 16 and stealth outputs.

They stay open in the old `node/`, `wallet/` and `primitives/` code until those use the
new crates.

**Known limits:**
- There is no external cryptographic review yet, and none of Monero's test vectors apply
  (Ristretto).
- The Janus anchor analysis is our own (spec §12.8).
- Property tests are seeded loops, because `proptest` needs `getrandom` (toolchain,
  Phase 1).
- Economics constants are provisional.
- Performance has not been profiled. The tests prove and verify hundreds of proofs in a
  few seconds with opt-level 3.

**Next:** block validation integration in the node (the emission schedule and
`block_reward`), wallet rebuild on `scan`/`builder`/`decoy`, then removal of
`primitives/src/ring_sig.rs`, `quantum_ring.rs` and the node's old verifier.

### R4: Node, block validation, miner and wallet rebuilt on the new core

**Decisions (user, 2026-09-23):**
- Rebuild the node core rather than patch it.
- Park contracts, escrow and the marketplace apps in `legacy/`; redesign them later.
- Remove all non-Rust or unverified post-quantum code.
- Smooth emission with a tail; 8 decimals.

**Repository:**

| Action | What |
|---|---|
| Deleted | the broken ring and "quantum ring" code (`ring_sig.rs`, `ring_signature.rs`, `quantum_ring.rs`) |
| Deleted | C/FFI PQ crates (`pqcrypto_native`, `ml-dsa-44`, `ml-dsa-44-c`, `ml-dsa44-standalone`) and the NIST KAT test harness around them |
| Deleted | the root `build.rs` that cloned and ran remote code |
| Deleted | the old miner with its three private RandomX copies |
| Deleted | stray files |
| Parked in `legacy/` (outside the workspace; see `legacy/README.md`) | the old node, wallet, `primitives`, smart contracts, marketplace, GUI and web wallets, faucet, explorer, deploy files, and the old README and testnet docs, which advertised unverified features |
| Moved to `research/` | `pqsignatures` (pure Rust) |
| Workspace | now only the pure-Rust rebuilt crates; the moving `iced` git pins are gone |
| Toolchain | switched to `stable-x86_64-pc-windows-msvc` |

**New specification:** [`docs/blocks.md`](docs/blocks.md):
- units (10^8);
- emission: `M = 21 M BLK`, `S = 20`, tail 0.6 BLK, a function of height only;
- genesis with an empty body and no premine;
- block format and limits;
- block validity with header-first processing;
- the reorg and state model;
- mempool policy;
- storage format and recovery;
- RPC, and its privacy caveats;
- address, seed-word and wallet-file formats.

**New crates:**

| Crate | Content |
|---|---|
| `chain` | block codec (strict, bounded); emission; `ChainManager`; mempool (key-image conflicts, fee-rate eviction and selection); `FileStore` (append-only, CRC, fsync before apply; a torn tail is truncated, damage in the middle is an error); address strings |
| `rpc` | wire types, blocking client |
| `node` | axum RPC on loopback with body-size and count limits; CPU-bound validation off the async workers; data-directory lock; mainnet refused |
| `miner` | templates from the node, coinbase built locally with a hedged secret, a multithreaded nonce search on a shared RandomX cache (light) or dataset (full), periodic template refresh |
| `wallet` | Argon2id + AES-256-GCM file with the header authenticated and atomic replace; 24-word seed; sync that verifies block ids and `tx_root`s from the node and detects reorgs; the Janus/amount checks from `crypto`; coin selection; decoys via the gamma picker, excluding too-young coinbase outputs; pending-spend tracking |

`ChainManager` keeps the header chain, transaction state and emission consistent:
- it validates bodies on connect;
- it marks invalid blocks and re-selects the best chain;
- after reorgs it returns transactions to the mempool;
- it replays its store at startup, reusing stored PoW hashes.

**Evidence:**
- `cargo test --workspace` (MSVC): **174 passed**, 1 ignored (the optional 2 GiB
  full-dataset RandomX test).
- `cargo clippy --workspace --all-targets`: no warnings.
- `cargo fmt --check`: clean.

New tests in this phase:
- chain, 16:
  - emission curve values (spec table), monotonicity;
  - coinbase over- and under-claims rejected, with the block marked invalid and its
    children rejected (`InvalidParent`);
  - body/header mismatch rejected without touching the header;
  - reorg with a transaction: it returns to the mempool and re-confirms, with correct
    emission;
  - an invalid side-branch body is rejected when it would win;
  - restart replay makes **zero** PoW calls and reproduces tip, state, supply and spent
    key images;
  - torn-write recovery;
  - store corruption detection;
  - mempool conflicts and duplicates.
- miner, 2: a nonce found by the miner verifies with consensus RandomX; stop and
  limits.
- wallet, 7:
  - file encryption: wrong password, every-byte tamper detection, atomic write;
  - **end to end over the real HTTP RPC**:
    - the miner mines 90 blocks, then pays Alice's subaddress, then Alice pays Bob,
      with exact balances and a 10-block lock;
    - insufficient funds;
    - file round trip;
    - restore from mnemonic;
    - a reorg rolls back and re-confirms Bob's payment;
    - wrong network refused;
    - malformed and oversized RPC requests rejected.

**Manual smoke test** with the release binaries and **real RandomX** (light mode),
regtest:
- node, then wallet `create`, then miner;
- 16 blocks were mined and accepted;
- LWMA raised difficulty from 1 to 615 as blocks came ~60× too fast (expected
  behaviour);
- the wallet CLI balance equals the node's generated supply (320.43227831 BLK);
- a wrong password was refused;
- a transfer of immature coinbase funds was refused;
- a node restart replayed 16 blocks in 28 ms to the same tip;
- a second node on the same data directory was refused.

**Open items from this phase:**
- **No P2P yet** (next phase). Until then a node trusts its local miner's submissions
  only in the sense that it validates them fully; there is no block or transaction
  relay.
- The node keeps all block bodies and the transaction state in memory, rebuilt from
  `blocks.dat` at startup. This is fine for testnet scale. Persistent indexes are
  needed before the chain grows large.
- Regtest uses the real LWMA, so local testing slows down as difficulty adapts. Fixed
  difficulty for regtest would help development; it would be a regtest-only consensus
  parameter and needs a spec change.
- RandomX performance is unchanged (light hash ~0.45 s; dataset build slow). Mining
  throughput work is still open (R1).
- Wallet: a remote node learns which ring members the wallet fetches (documented).
  There is no multi-output sweep or consolidation command yet. Pending spends are
  cleared manually (`clear-pending`) if a transaction is dropped.
- The testnet genesis timestamp is still provisional.
- Deployment files (Docker, configs, CI) are to be recreated for the new binaries. CI
  is already rewritten (`.github/workflows/ci.yml`: fmt, clippy `-D warnings`, tests,
  `forbid(unsafe_code)` check).

### R5: Peer-to-peer network (`p2p/`, spec `docs/p2p.md`)

The P2P layer was built from scratch, spec first.
- Pure Rust, `#![forbid(unsafe_code)]`, no FFI.
- Dependencies: `tokio`; `aes-gcm` (RustCrypto, already used by the wallet); the
  project's own Ristretto255 and hashing from `crypto`.

**Design (with its reasons in the spec):**

| Requirement | Implementation |
|---|---|
| Privacy-aware transport | Ephemeral Ristretto255 DH, then AES-256-GCM frames with encrypted lengths. The network id is bound into the keys, so there is no plaintext magic. Forward secrecy. |
| Handshake and version negotiation | `Version`/`Verack` with no user agent, clock or service bits; minimum protocol check; network check; self-connection detection by nonce; 10 s deadline |
| Peer discovery | seeds, `--peer`, `GetAddr`/`Addr` once per connection, small-batch address relay; own address advertised only with `--public-address` |
| Eclipse resistance | *new* and *tried* tables, bucketed by `H(secret ‖ group(addr) ‖ group(source))`; outbound diversity of one per /16 (IPv4), /32 (IPv6) or onion; inbound limit 64, at most 2 per IP |
| Header-first sync | locator; `GetHeaders`/`Headers` (2000 per batch); PoW of a batch computed **in parallel** from seeds taken from the batch; bodies downloaded with 16 in flight per peer and reassigned after a 60 s timeout |
| Chain sync and reorgs | `ChainManager` now keeps the connected chain on the most-work branch whose **bodies are all available**. A heavier branch known only by headers never rolls the state back early (blocks.md §6). |
| Block propagation | new tips announced as one-header `Headers`; bodies fetched on demand |
| Transaction propagation | `InvTx` with per-peer randomized trickle delays; `GetTx` from one announcer at a time with fallback; `GetTx` served **only for transactions announced to that peer** (no mempool probing) |
| Transaction origin privacy | **Dandelion++**: 10-minute epochs, 2 stem peers, per-source fixed routes, 10 % diffusers, a stempool that is never announced, served or mined, and an embargo timer (10 s + Exp(39 s)). RPC transactions enter the stem. |
| Scoring and bans | violation scores; disconnect and 24 h IP ban at 100. Tor/proxied peers and loopback peers on regtest are disconnected, not IP-banned. |
| Spam and flood protection | every list bounded before allocation; 2 MiB frame cap checked after the encrypted length; per-peer token buckets (50 messages/s burst 500, 4 MB/s, 20 txs/s); a bounded outbox (a slow reader is disconnected); cache of recently rejected transactions |
| Tor | SOCKS5 client (onion names resolved by the proxy); `--proxy-only`, which also does not listen on clearnet by default |

**Evidence:** `cargo test --workspace` gives **213 passed**, 0 failed, 1 ignored.
Clippy with `-D warnings` and `fmt --check` are clean.

- p2p unit tests (26):
  - transport:
    - round trip including a maximum-size frame;
    - different networks cannot talk;
    - the ciphertext hides plaintext;
    - a MITM bit flip is detected;
    - identity and non-canonical keys rejected;
    - handshake timeout;
    - an oversized length rejected before the payload is read;
  - message codec: round trip, truncation and trailing bytes, limits before
    allocation, random input;
  - addresses: parsing, groups, routability, bad encodings;
  - address manager:
    - **10 000 attacker addresses from one /16 fill at most one bucket (64 slots)**;
    - secret-dependent buckets;
    - persistence, including garbage files;
  - bans;
  - token buckets;
  - Dandelion++: stable routes per epoch; a diffuser fraction of ≈10 % over 2000
    epochs; stem replacement; embargo mean;
  - SOCKS5 against a mock proxy (onion sent as a domain name; refusal).
- p2p multi-node tests over real localhost TCP (9):
  - propagation along A–B–C;
  - a fresh node syncs 150 blocks header-first;
  - **a transaction stems** (it is in B's stempool, not in A's mempool), **then
    fluffs** to D and is mined everywhere;
  - partitions join and the heavier chain wins;
  - **automatic discovery** of a third node through `Addr`;
  - an invalid header disconnects the peer;
  - malformed messages and a **700-ping flood** disconnect the peer;
  - wrong-network and self connections are refused;
  - **`GetTx` probing of the mempool gets no answer**.
- chain header-first tests (4):
  - headers without bodies leave the state untouched;
  - out-of-order bodies connect once the gap closes;
  - a heavier branch known only by headers, or with partial bodies, does not
    reorganize;
  - locator shape and `headers_after`;
  - PoW jobs take their seeds from the batch across the first RandomX key change
    (2200 blocks).

**Smoke test with the release binaries and real RandomX (regtest):**
- Node A with the miner; B peered to A; C started late, connected only to B.
- B followed A block by block.
- C synced 13 blocks header-first in **7 s**, then **discovered A through B's address
  table and connected to it**.
- All three had the same tip.
- After a forced kill, B restarted with the same chain.
- The address table (`peers.json`) was initially only written on a graceful shutdown.
  **Found and fixed:** it is now saved within a minute of any change, and the fix was
  verified with a forced kill.

**Open items:**
- **No peer authentication.** An active MITM can read or drop a connection
  (spec §1, §12). A future version could add optional authentication of long-term
  node keys.
- Traffic sizes and timing are not padded.
- The encrypted handshake starts with 32-byte Ristretto points. Unlike BIP 324's
  ElligatorSwift, these are not uniformly random bytes, so a DPI system can guess that
  a connection is BlackSilk.
- **Initial sync speed** is bounded by RandomX light-mode verification (~0.45 s per
  header, divided by the core count).
- No compact blocks.
- I2P is not supported.
- Built-in seed nodes are empty until testnet launch.
- Dandelion++ parameters are Monero's, not re-tuned for BlackSilk.
- There is no peer-count metric or RPC beyond `/info.peers`.

### R6: Testnet launch configuration and long-duration testing

**Configuration and deployment:**
- **Testnet genesis finalized.**
  - Timestamp 1790121600 (2026-09-23 00:00 UTC).
  - Id `bbeb1a9f…12909`.
  - Empty body, no premine.
  - Pinned by a test, together with regtest's.
  - The mainnet timestamp remains provisional.
- **Regtest now uses 10-second blocks**, so a single machine can test hours of chain
  activity. Every other rule is shared.
- **Seed and configuration system** (`node/src/config.rs`):
  - a TOML configuration file, with the command line overriding it and unknown keys
    rejected;
  - a built-in seed list per network, deliberately **empty** until real seed hosts
    exist;
  - seeds may be host names, resolved with system DNS but refused in `--proxy-only`
    mode (no DNS leak);
  - `--connect-only` for fixed topologies;
  - `--allow-private` for LAN/lab networks.
- **Deployment** (`deploy/`):
  - configuration templates: normal, seed, Tor-only, lab/LAN, regtest;
  - hardened systemd units for the node and miner (unprivileged user, read-only
    system, `MemoryDenyWriteExecute`, restricted address families);
  - a multi-stage Docker image that runs as non-root, with the RPC not exposed;
  - `install-linux.sh` and `check-node.sh`;
  - `.gitattributes` forces LF line endings.
- **Documentation:** `docs/testnet.md` covers parameters, running a node, Tor, Docker,
  mining, seed operation, the **multi-machine test procedure (§7)**, the lab tool,
  troubleshooting and operator security. The consensus and P2P specs are updated. The
  old deployment files stay in `legacy/`.

**Lab network tool** (`tools/labnet`, pure Rust):
- It starts real node and miner processes, and routes every node-to-node link through
  a proxy that adds latency (80 ms) and jitter (0–60 ms), and can cut links for
  partitions.
- Wallets, in process, send transactions through random nodes.
- It samples heights, tips, mempools, peers and memory every 15 s.
- At the end it checks:
  - convergence;
  - drained mempools;
  - a late node that joins through one peer, discovers others and syncs;
  - every wallet restored from its seed against that fresh node matches;
  - **Σ wallet balances = coins generated**;
  - no crashes;
  - no misbehavior disconnects;
  - no node stuck behind for more than 90 s.

**Findings from the long runs.** Fixed, each with a regression test:

| # | Finding | Fix |
|---|---|---|
| L1 | **Honest peers banned each other over hours.** Relaying a transaction that a block had just spent scored as an invalid transaction (+20). This also applied to anything checked against chain state: ring members on another branch, and the signature over them. | `TxError::is_stateless()`: only stateless failures (T1–T11) are penalized or cached. Tests: `relaying_an_already_confirmed_transaction_is_not_penalized`, `stateless_and_contextual_errors_are_distinguished`. |
| L2 | **Transaction request timeouts banned honest peers.** A node silently ignored `GetTx` for a transaction mined since it was announced; the requester scored +5 per timeout (10 of 14 false bans). | `GetTx` is answered with `NotFound` for every unserved id (uniform, so it reveals nothing about pool contents). `NotFound` moves the request to the next announcer. Transaction timeouts are no longer penalized. Test: `mempool_cannot_be_probed_with_gettx` (extended). |
| L3 | **Wallet funds stuck as "pending" forever** when a submitted transaction was dropped (its ring members were reorganized away). | Pending spends expire after 20 blocks without confirmation. Safe: a late confirmation is still detected, and reuse is rejected by consensus. Test: `stale_pending_spends_expire_but_late_confirmation_still_counts`. |
| L4 | Peer table lost on a forced kill (only saved on clean shutdown). | Saved within a minute of any change (R5 smoke test; verified). |
| L5 | Flaky test: a ping flood can be cut by the rate limit **or** by the slow-reader protection. | Both are counted (`NetStats::slow_disconnects`); the test accepts either defense. |

Two harness bugs were also found and fixed before the final runs:
- the partitions leaked through discovered addresses (hence `--connect-only`);
- the stuck detector counted normal propagation with 120 s blocks as "stuck"; it now
  measures time *continuously behind*.

**Final runs on the fixed code** (Windows, 8 threads, 3 hours each, both concurrent).
Evidence is in `docs/evidence/labnet-2026-09-23/`: summaries, per-15 s metrics and
journals. The first runs' summaries, which found L1–L3, are kept in `first-runs/`.

| | Regtest rules (10 s) | **Testnet rules (120 s, D0 = 100)** |
|---|---|---|
| Result | **all checks passed** | **all checks passed** |
| Blocks / partitions | 1121 / 6 (4 min each) | 116 / 3 (8 min each) |
| Reorganizations (max depth) | 179 (20) | 4 (3) |
| Transactions submitted | 445 of 448 attempts | 41 of 50 attempts |
| Transaction failures | 3 × `NotEnoughOutputs` (young chain, before 16 mature coinbases) | 9 × same |
| Misbehavior disconnects / stuck nodes / crashes | 0 / 0 / 0 | 0 / 0 / 0 |
| Late joiner | synced, discovered 4 peers | synced, discovered 3 peers |
| Fresh-node wallet restore | 5 of 5 wallets identical | 5 of 5 identical |
| Supply | 22438.46150858 BLK generated = held by wallets | 2323.02324589 = held by wallets |
| Node memory (RSS) | 267 → 275 MB over 1121 blocks | 264 → 266 MB |

Memory grows about 7 KB per block, which is the documented in-memory design (all
bodies and state in RAM). There is no leak beyond that. Persistent indexes are still
needed for a long-lived chain (R4 open items).

**Testnet readiness checklist (this phase's acceptance criteria):**

| Criterion | Status |
|---|---|
| Multiple nodes join automatically | ✅ Lab: late joiners with one peer discovered 3–4 peers and synced. Release binaries (R5): a node discovered a third node through a peer. **Not yet across machines.** |
| Mining works across different machines | ⚠️ Mining on two nodes across latency-emulated links: verified. **Different physical machines: not verified.** Only one machine was available. |
| Transactions propagate correctly | ✅ Lab: 486 transactions through random nodes, Dandelion++ stem then fluff, all confirmed, mempools drained, supply conserved. |
| Reorganizations under real network conditions | ⚠️ Verified under **emulated** latency, jitter and partitions: 183 reorgs, depth up to 20, all converged, transactions returned and confirmed. Real internet conditions: not verified. |
| Wallet sync from a fresh node | ✅ Every wallet restored from 24 words against a node synced from scratch matched exactly (both runs). |
| Long-duration stability | ✅ 2 × 3 hours, concurrent, no crashes, flat memory. A **72-hour** multi-machine run is still required (testnet.md §7 step 7). |

**Verdict:**
- The software is ready for a **controlled multi-machine testnet trial**, run by the
  operators following `docs/testnet.md` §7.
- It is **not declared ready for a public testnet launch** until that trial passes.
  That means at least 3 machines in 2 networks, including a 72-hour run.
- Seed nodes must also be deployed and added to the built-in list.
- The Linux deployment files (systemd, install script, Docker) must be verified on
  Linux. They were written here but **not executed**, because no Linux environment or
  Docker was available.

An external cryptographic review remains a mainnet prerequisite.

### R7: Confidential contracts: M1 (cryptography) and M2 (engine and state). In progress.

**Specifications:**
- `docs/contracts.md`, v0.2. The model was approved on 2026-09-23:
  - anonymous callers;
  - declared value movements approved by contracts;
  - private and public notes;
  - range, equality and reveal claims;
  - scoped membership;
  - failed calls are invalid and pay no fee;
  - BLK only in v1.
- `docs/zk.md`, v0.1, for review: the zero-knowledge successor (private execution).
  Nothing in it is implemented.

**Not consensus yet.** No transaction kind, block rule or activation height exists.
Chain integration is M3.

**M1: cryptography** (`crypto/`). Internal review:
`docs/reviews/contracts-crypto-review.md`.
- Tagged Schnorr signatures (`schnorr.rs`) for the balance kernel, auth keys, and
  equality/reveal claims.
- Scoped linkable ring signatures (`membership.rs`) for anonymous voting.
- Range, equality and reveal claims on Pedersen commitments (`claims.rs`); range
  claims use the existing BP+.
- 24 new tests. The crypto crate total is 86.
- **Findings fixed in the design during M1:**
  - SCH-1: identity key forgeable; rejected.
  - KER-1/KER-2: kernel re-signable when `e` is public; rule K2 plus a wallet rule.
  - MEM-1: prover-chosen scope; contracts must fix the scope.
  - CLM-1: degenerate equality or reveal claims; refused.
- **Open questions for the external review:** KER-Q1/Q2, MEM-Q1/Q2 and CLM-Q1 (see
  the review document).

**M2: engine and state** (`contracts/`, crate `blacksilk-contracts`,
`#![forbid(unsafe_code)]`):
- **Module profile** (`profile.rs`). It validates with a restricted feature set:
  - no floats, SIMD, threads, tail calls, memory64, multi-memory, exceptions,
    extended-const or saturating float conversions;
  - imports only from `"bs"`, with exact host signatures;
  - one bounded memory (≤ 2 MiB), and at most one bounded funcref table;
  - no start function and no passive segments;
  - required exports;
  - size and local limits.
- **Executor** (`exec.rs`):
  - wasmi with fuel and eager compilation;
  - 31 host functions;
  - reads through an overlay, and all effects returned as a diff;
  - cross-contract calls within the access list, with depth ≤ 4 and reentrancy
    trapping;
  - note approval and acceptance checks;
  - storage accounting and per-contract caps.
- **State** (`state.rs`, `smt.rs`):
  - key–value entries, notes, key sets and deduplicated code;
  - atomic diffs with per-block undo;
  - sparse-Merkle state root. It is cached, and tested against a from-scratch
    reference.
- **Tests:** 29, all passing:
  - the profile accepts valid modules and rejects 26 kinds of forbidden module;
  - persistence, and undo restoring the exact root;
  - determinism across two independent engines, with a **pinned golden fuel count**
    of 1 807;
  - out of fuel, abort, storage limit, key and pointer bounds;
  - note approval and acceptance, the access list, unknown and duplicate notes;
  - cross-contract calls, depth and reentrancy (including indirect reentrancy);
  - auth keys, key sets, deploy with init and code-storage accounting;
  - recursion trapping inside the interpreter, and memory growth capped at the
    declared maximum;
  - callee failure propagating, and contracts seeing only their own notes.

**Dependency decision: wasmi `=0.38.0`, not the newest 2.0.0.**

| | 0.38.0 (chosen) | 2.0.0 |
|---|---|---|
| External audit | Runtime Verification 2024-11 (0.36–0.38); SRLabs 2023 (0.31) | none |
| Published advisories | not affected (CVE-2024-28123: ≤ 0.31.0; CVE-2025-66627: 0.41.0–1.0.0) | not affected |
| `unsafe` occurrences in its own `src/` | 120 | 302 |
| Custom per-instruction fuel table | no (wasmi's internal schedule, pinned by a golden test) | yes |

We rely on the external audit for wasmi's internal `unsafe`; **we have not reviewed it
line by line** (open item). The parser is `wasmparser-nostd =0.100.2`, the one wasmi
0.38 uses, and it also runs the profile check.

**Spec corrections made while implementing:**
- §9.4 record layouts: the note record said 200 bytes but its fields summed to 186; it
  is now padded to 200. The claim record now carries a second commitment for Equal
  claims.
- §10.2: the sparse Merkle tree is defined in its shortcut form, with O(log n)
  updates. The original full-depth definition cost 256 hashes per update and O(256)
  nodes per leaf.
- §9.5: the fuel schedule is stated as it actually is in wasmi 0.38, plus the
  instantiation cost.

**Remaining for contracts** (M3–M6, docs/contracts.md §19):
- chain integration: transaction kinds 2 and 3; the kernel; K/X/KB rules; coinbase v2
  with `state_root`; activation; mempool and templates; reorg tests;
- the SDK and 5 example contracts;
- wallet and RPC;
- benchmarks, fee calibration, fuzzing, labnet with contract traffic;
- the external review.

### R8: Zero-knowledge layer (private execution). In progress.

The project owner moved this ahead of contracts M3 (2026-09-23).

**Specifications:**
- `docs/zk.md` v0.2: architecture and decisions;
- `docs/zkvm.md` v0.1: the BVM-1 virtual machine;
- `docs/evidence/px0-2026-09-23/`: measurements.

**Not consensus.** No transaction kind or activation exists yet.

**PX-0 (evaluation, done).** Candidate stacks were measured on this machine, not
assumed. Decision B was approved by the owner:

| Choice | Result |
|---|---|
| Proof system | Plonky3 0.7 (batch STARK, LogUp lookups, hiding FRI and Merkle), pinned exactly |
| Fields | BabyBear base field with a degree-5 challenge extension |
| Soundness | ≥ 100 **proven** bits in the Johnson-bound regime; unique-decoding bits also reported |
| Measured proof sizes | 130–230 KB |

**Findings that changed the design:**
- BabyBear with a degree-4 extension, a common industry choice, **never reaches 100
  provable bits** (≤ 97).
- Proof size is dominated by Merkle paths, not circuit width: conservative
  unique-decoding parameters would give 260–550 KB.
- **Rejected stacks:**

  | Stack | Reason |
  |---|---|
  | Winterfell | cannot be unpacked on Windows (reserved file name `aux.rs`) |
  | Stwo | no zero-knowledge mode |
  | SP1 | core proofs are not zero-knowledge |
  | RISC Zero | C++ kernels |

- Goldilocks uses inline assembly in its x86-64 reduction; BabyBear's scalar path does
  not.

**ZK-1: proof layer** (`zk/`, crate `blacksilk-zk`, `forbid(unsafe_code)`, 12 tests):
- **Parameter set BS-ZK-1:**
  - blow-up 32, 50 queries, 16 grinding bits, arity 16, final polynomial 2^6;
  - hiding: 4 random codewords, 4 salt elements per Merkle leaf;
  - Fiat–Shamir challenger pre-seeded with the parameter id (domain separation).
- **A test recomputes proven security over the whole shape envelope.** It found
  that at 2^22 rows the batching term drops below 100 bits above ~2 000 committed
  columns, and that queries and grinding cannot fix that term. The envelope is
  therefore limited to 2 000 columns, and a further test proves the limit is binding.
- **Hiding randomness:**
  - `ProverConfig` hedges the OS CSPRNG with a witness digest, for every proof;
  - Plonky3's own tests use fixed seeds, which would silently remove zero knowledge;
  - `VerifierConfig` cannot prove.
- **Hardened `verify`:**
  - table counts and claimed heights are checked before Plonky3 runs (`CommonData`
    computes `ext_db − is_zk` without a check, and would panic on a crafted 0);
  - Plonky3 verification runs behind `catch_unwind`. Its README says the verifier may
    panic on malformed proofs, so the workspace release profile moved from
    `panic = "abort"` to `panic = "unwind"`.
- **Strict encoding:** version byte, size cap, no trailing bytes, and canonical
  re-encoding, so one proof has exactly one encoding.
- **Tests:**
  - honest proofs verify (a toy proof is ~111 KB);
  - wrong public values and wrong transaction binding are rejected;
  - false statements (a lookup violation, a wrong constraint) are rejected;
  - forged heights and table counts are rejected;
  - **402 single-byte mutations are all rejected, with no verifier panic**;
  - the encoding is strict;
  - proofs are randomized, even with a broken OS RNG.
- **Found by testing:** FRI needs every table ≥ 2^6 rows (`MIN_LOG_HEIGHT`). It is now
  a compile-time relation.

**ZK-2: BVM-1 execution** (`zkvm/`, crate `blacksilk-zkvm`, `forbid(unsafe_code)`,
25 tests):
- A strict RV32I + Zmmul decoder and encoder: it rejects EBREAK, CSRs, FENCE.I,
  compressed encodings, RV64 forms and illegal reserved bits.
- Our own strict ELF loader: one code segment, up to 4 data segments, layout checks,
  and every code word decoded at load.
- The reference interpreter, as the executable specification. It records the witness:
  - per-cycle steps;
  - every register and memory access, with previous value and timestamp, for the
    offline memory argument.
- Guest SDK (`zkvm/sdk`, `no_std`). Its single `unsafe` block is the `ecall`, which
  runs inside the VM.
- **A real Rust guest compiled by rustc/lld runs correctly:** static data, the
  Poseidon2 syscall, software division. It is a committed fixture, rebuilt by
  `zkvm/guests/build.sh`.

**Design decisions taken during ZK-2:**
- **ZK-3a: no hardware division.** DIV and REM are the most intricate circuit; guests
  divide in software, and the loader rejects division opcodes. rustc lists `zmmul` as
  an unknown/unstable target feature (LLVM implements it); documented, and consensus
  is unaffected.
- **Cycle limit 2^21**, so every timestamp stays below 2^24. The "timestamps strictly
  increase" check is then three byte-range lookups, with no wrap-around case.
- `ECALL` reads `a7` and `a0` in the two register slots, so every cycle reads exactly
  two registers.

**ZK-3: the BVM-1 constraint system** (`zkvm/src/air/`). Core done; the Poseidon2
syscall circuit is pending.

Eleven tables in one batch STARK:

| Group | Tables |
|---|---|
| Byte operations | `BYTE` (2^16-row preprocessed byte pairs: range, AND, OR, XOR) |
| ALU | `ALU_ADD`, `ALU_BIT`, `ALU_LT` (SLT/SLTU/EQ), `ALU_SHIFT` (5-stage barrel shifter), `ALU_MUL` (8×8-byte convolution) |
| Program | `PROGRAM` (preprocessed decoded program) |
| Memory argument | `IMAGE` (preprocessed initial memory and registers), `MEM_INIT` (sorted keys; the endpoints of the offline memory argument) |
| Execution | `CPU` |
| Public output | `OUTPUT` (preprocessed from the claimed outputs) |

**Assurance tools built:**
- **Constraint oracle** (`check.rs`): evaluates the same constraint code the STARK
  proves, over concrete values, and checks exact bus balance. It records exclusive
  interactions explicitly, because Plonky3's default for them is a silent no-op.
- **Incremental mutation checker:** re-evaluates only the rows a mutated cell affects.

**Results:**
- Every instruction class satisfies the constraints: all ALU operations; loads and
  stores of every width and signedness; writes to `x0`; branches of every kind;
  JAL/JALR; LUI/AUIPC; loads from the code segment; READ/WRITE/HALT.
- **Mutation testing: 419 364 ALU mutations and 37 292 CPU and memory-table
  mutations. Every single-cell change of every real row is caught.**
  - The only free cell is the inverse witness of the ALU zero test when the
    difference is zero, which does not affect the result.
  - The CPU forces unused columns to zero, so its witness is unique.
- False ALU results unbalance the bus; a prover lying about a register value is
  rejected.
- A real proof verifies, and is rejected for a wrong exit code, output, program or
  binding.
- **A Rust program compiled by rustc/lld (insertion sort, multiplication, software
  division; 11 156 cycles) was proven in zero knowledge and verified.** A forged output
  was rejected.
- **Shape check:** 414 constraints, ~1 210 committed columns (the limit is 2 000),
  **exactly 100 proven bits at the maximum height 2^22** (63 by unique decoding). The
  margin is **zero** at the maximum height; real traces are far smaller.

**Findings during ZK-3:**

| # | Finding | Resolution |
|---|---|---|
| ZK-F1 | **Integration bug:** `blacksilk-zk` committed preprocessed tables with the prover's hiding (salted) configuration, so the verifier's commitment differed and honest proofs failed (`InvalidPowWitness`). | Preprocessed tables are public: both sides commit them with the deterministic setup configuration. Regression test in `zk/tests/proofs.rs`. |
| ZK-F2 | **Soundness trap:** a 32-bit address or jump target used as a field element could wrap modulo p onto a valid address. | Every computed address and target is range-checked below 2^28 first (zkvm.md §2). |
| ZK-F3 | The semantics of reading code as data were undefined (the interpreter returned 0). | Code is part of the image, so loads return instruction words; stores must be ≥ `CODE_END` (decision ZK-3b). |

**Open items:**
- The POSEIDON2 syscall circuit (ZK-3c). Programs using it execute, but cannot be
  proven yet.
- **Performance:** proofs are 0.5–0.7 MB and take ~60–90 s even for small programs,
  dominated by the 2^16-row byte table at blow-up 32.
- **Security margin:** zero at 2^22 rows. Cap VM table heights below 2^22, or reduce
  columns.
- Multi-cell (coordinated) forgery is covered by the soundness arguments, not by the
  single-cell tests. It is an external-review item.

**Remaining** (none of it is done until tested; nothing here is production-ready
before external review):
- **ZK-3c:** the Poseidon2 syscall circuit.
- **ZK-4:** records, nullifiers and the kernel (private transfers).
- **ZK-5:** composition of functions and kernel in one batch proof.
- **ZK-6:** integration with contracts and transactions.
- Security review document, fuzzing, benchmarks, external audits.

### Finding status after R1–R6

| Findings | Status | Evidence |
|---|---|---|
| E1, E2 | **Closed** (crates removed from the workspace) | `legacy/README.md` |
| Phase 1 toolchain | **Resolved:** MSVC toolchain; the whole workspace builds and tests | R4 |
| P1–P4 (fake or duplicated RandomX) | **Closed:** one spec-exact implementation; the copies are deleted | R1 vectors, R4 miner test |
| P5–P10 (miner/node PoW mismatch, timing checks, inverted targets, difficulty, key schedule) | **Closed:** the miner and node share `consensus` | R2 tests, R4 miner/e2e tests, smoke test |
| B1–B5 (no PoW/context checks, unminable chain, rebuilt header, unchecked Merkle, broken reorg) | **Closed** | R2, R4 chain tests |
| B7, B8 (stub P2P handler, broken framing) | **Closed:** replaced by the new P2P layer | R5 (35 p2p tests, smoke test) |
| B6, B9 (unbounded `GetBlocks`, no-op CLI commands) | **Closed by removal**; the RPC bounds every request | R4 e2e `rpc_rejects_malformed_and_oversized_requests` |
| S1–S4 (forgeable, unlinkable ring signatures; signatures over constants; no balance) | **Closed** | R3 (43 tx tests), R4 e2e |
| S5 (fake PQ ring) | **Closed:** deleted, not advertised | spec §11.6, README |
| S6, S8 (C/FFI PQ) | **Closed:** deleted | — |
| S7 (unaudited PQ crates) | **Parked** in `research/`; not used by any shipped crate | — |
| K1, K2 (shared seed, no stealth/ring) | **Closed** | R3 key/stealth tests, R4 wallet |
| K3 (Tor inbound rejection) | **Closed:** SOCKS5/Tor outbound, proxy-only mode, onion addresses; inbound through the operator's hidden service. I2P is not yet supported. | R5 |
| D1–D3 (remote-exec `build.rs`, moving git pins, stray files) | **Closed** | R4 repository changes |
| L1–L5 (false bans from contextual tx errors and `GetTx` timeouts, stuck pending spends, peer table persistence, flaky flood test) | **Closed** | R6 regression tests; labnet reruns with 0 misbehavior disconnects |
| Multi-machine testnet trial | **Open:** procedure ready, not yet run | `docs/testnet.md` §7 |
| Linux deployment files | **Open:** written but not executed | `deploy/` |
| Seed nodes | **Open:** the built-in list is empty | `node/src/config.rs` |

## Decisions needed before remediation

1. **RandomX implementation:** *decided on a pure-Rust implementation, now done (R1).*
2. **Transaction privacy model:** *decided on the Monero-based model (CLSAG-16, key images,
   stealth outputs with view tags, BP+, pseudo-outputs), now specified and implemented (R3).*
   Original note:
   Correct CryptoNote-style privacy needs
   linkable ring signatures (CLSAG) with key images, one-time stealth outputs,
   pseudo-output commitments with a balance check, and range proofs, all over a
   single curve. The "quantum ring signature" should be removed and not
   advertised until a real, reviewed scheme exists.
