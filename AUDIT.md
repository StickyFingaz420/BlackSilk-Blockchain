# BlackSilk Testnet Readiness Audit

Status (2026-09-25): **not ready for the experimental testnet; the reset and the launch
are on hold** pending the readiness report (docs/testnet-launch-checklist.md).
**No external audit or independent review has taken place:** every finding and
conclusion below is internal work (docs/reviews/review-status.md). The status lines
further down are historical records of each round.
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
layer, the VM with its complete constraint system (including the Poseidon2 circuit), and
the private-transfer kernel (records, nullifiers, commitment tree, record delivery) are
implemented and tested; a private transfer has been proven and verified end to end. The
unified proof of contract functions and the kernel is implemented and tested, and the
internal ZK security review is written (`docs/reviews/zk-security-review.md`). Consensus
integration remains. **Nothing in the ZK layer is production-ready before independent
review** (R8).
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

An external cryptographic review was then seen as a mainnet prerequisite. Current policy (2026-09-25): self-reliant internal review; external review may be revisited later (docs/reviews/review-status.md).

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

### R8: Zero-knowledge layer (private execution). Integrated into consensus; not production-ready.

The project owner moved this ahead of contracts M3 (2026-09-23).

**Specifications:**
- `docs/zk.md` v0.3: architecture and decisions;
- `docs/zkvm.md` v0.3: the BVM-1 virtual machine, multi-execution proofs and fixed
  shapes;
- `docs/px.md` v0.4: records, nullifiers, the transfer kernel, state, delivery,
  consensus integration (§11), privacy guidance (§12), contract tooling and record
  distribution (§13);
- internal reviews in `docs/reviews/`:
  - `zk-security-review.md`;
  - `privacy-review.md`;
  - `dependency-review.md`;
  - `aggregation-study.md`;
- `docs/evidence/px0-2026-09-23/`: measurements;
- `zk/examples/param_study.rs`: the FRI parameter study.

**Consensus (ZK-6, 2026-09-24).**
- Transaction kinds 2 (PX transaction) and 3 (private-contract deploy) are validated
  by nodes, relayed, mined and applied.
- No activation height exists: the rules apply from genesis on every network. The
  owner has approved a testnet reset for the final trial (see "Open items").

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
- **Parameter set BS-ZK-2** (replaced BS-ZK-1, finding ZK-F4):
  - degree-8 challenge extension (247 bits), blow-up 8, 108 queries, 16 grinding
    bits, arity 16, final polynomial 2^6;
  - every shape of the envelope (up to 2^22 rows, 4 000 committed columns) reaches
    **≥ 123 bits in the Johnson regime and ≥ 105 in the unique-decoding regime**
    (tested); the approved minimum is 100;
  - hiding: 4 random codewords, 4 salt elements per Merkle leaf;
  - Fiat–Shamir challenger pre-seeded with the parameter id (domain separation).
- **A test recomputes proven security over the whole shape envelope.** It found
  that at 2^22 rows the batching term drops below 100 bits above ~2 000 committed
  columns, and that queries and grinding cannot fix that term. The envelope was
  therefore limited to 2 000 columns under BS-ZK-1, and a further test proves the
  limit is binding. *(Superseded: BS-ZK-2 raised it to 4 000 columns, above.)*
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

**ZK-3: the BVM-1 constraint system** (`zkvm/src/air/`). Complete, including the
Poseidon2 syscall circuit (ZK-3c).

Twelve tables in one batch STARK:

| Group | Tables |
|---|---|
| Byte operations | `BYTE` (2^16-row preprocessed byte pairs: range, AND, OR, XOR) |
| ALU | `ALU_ADD`, `ALU_BIT`, `ALU_LT` (SLT/SLTU/EQ), `ALU_SHIFT` (reduced to one multiplier lookup; 35 columns instead of 213), `ALU_MUL` (8×8-byte convolution) |
| Program | `PROGRAM` (preprocessed decoded program) |
| Memory argument | `IMAGE` (preprocessed initial memory and registers), `MEM_INIT` (sorted keys; the endpoints of the offline memory argument) |
| Execution | `CPU` |
| Public output | `OUTPUT` (preprocessed from the claimed outputs) |
| Syscall | `POSEIDON2`: Plonky3's `Poseidon2Air` (standard BabyBear constants) embedded unchanged, plus memory access, canonical-encoding and pointer checks |

**Assurance tools built:**
- **Constraint oracle** (`check.rs`): evaluates the same constraint code the STARK
  proves, over concrete values, and checks exact bus balance. It records exclusive
  interactions explicitly, because Plonky3's default for them is a silent no-op.
- **Incremental mutation checker:** re-evaluates only the rows a mutated cell affects.

**Results:**
- Every instruction class satisfies the constraints: all ALU operations; loads and
  stores of every width and signedness; writes to `x0`; branches of every kind;
  JAL/JALR; LUI/AUIPC; loads from the code segment; READ/WRITE/HALT.
- **Mutation testing: every single-cell change of every real row is caught.** With
  the tables at the time: 419 364 ALU and 37 292 CPU and memory-table mutations.
  Re-measured on the current tables (2026-09-25): 231 120 ALU and 37 616 CPU and
  memory mutations, plus 2 500 Poseidon2 and 180 public-copy mutations, all caught.
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
- **Shape check (BS-ZK-1, at the time):** 414 constraints, ~1 210 committed columns
  (the limit was 2 000), exactly 100 proven bits at the maximum height 2^22 (63 by
  unique decoding). *(Superseded by BS-ZK-2, ZK-F4: ≥ 123 / ≥ 105 bits over the whole
  envelope.)*

**ZK-3c: the Poseidon2 syscall circuit.**
- One row per call: the 16 input words are consumed from memory with their previous
  timestamps, the permutation is proven by the embedded `Poseidon2Air`, and the output
  words are produced at the call's write slot.
- Input and output words must be canonical field elements (one encoding per value);
  the CPU checks that the 64-byte buffer lies in writable memory.
- **Mutation testing: 2 500 single-cell mutations of the Poseidon2 rows and their CPU
  rows, all caught.** A consistent forgery of an output (permutation column and memory
  bytes together) is rejected by the permutation constraints.
- The AIR's output equals the interpreter's permutation on every call (asserted during
  trace generation); a compiled Rust guest using the syscall proves and verifies.

**ZK-4: private records and transfers** (`px-core/`, `px/`; spec `docs/px.md`).
- `Hk` (Poseidon2 sponge, 8-element digests, domain constants), keys from the wallet
  seed, per-address owner tags, records, nullifiers `Hk(nk ‖ rho ‖ cm)`, and `rho`
  derived from the transaction's first nullifier (no Faerie Gold).
- **The transfer kernel is one Rust source** (`px-core`, `no_std`, no dependencies),
  compiled natively and as the zkVM guest. The proven program is pinned by program id
  (`px/kernel.id`); the rebuild was byte-identical.
- 2-in/2-out with dummies; balance in `u128` integers, so no field wrap-around is
  possible.
- Consensus state: tree frontier, 100-block root window, nullifier set, containment
  pool, atomic blocks with exact undo.
- Record delivery: Ristretto ECDH and ML-KEM-768 (RustCrypto `ml-kem` 0.3.2, pure Rust)
  combined into a ChaCha20-Poly1305 key bound to the commitment. Recipients accept only
  records that recompute the commitment.
- **Tests:**
  - 20 rejection cases, each failing identically natively and in the zkVM;
  - constant trace heights across witness shapes;
  - a deposit and a private payment proven and verified, then rejected under 10
    statement alterations;
  - state, tree, delivery and hash tests (docs/px.md §9.3).
- **Measured** (this machine, idle, sequential, BS-ZK-2, after ZK-F11):
  - kernel v2: 25.0–25.2k cycles without functions, 29.3–29.4k with one;
  - transfer proof: **2.08 MB**, proving 43.0 s, verifying 1.3 s. After ZK-F13 and
    ZK-F14: **2.04 MB**, proving ~42 s, **verifying 188 ms**;
  - kernel + one function (vault CLAIM): **2.54 MB**, proving 50.8 s;
  - a 40-proof stress run: 48.4–51.4 s per kernel + function proof.

**ZK-5: unified proof of contract functions and the kernel** (zkvm.md §6.5,
docs/px.md §7).
- **Multi-execution proofs:**
  - one batch STARK proves up to 5 executions;
  - each execution has its own program, image, memory, CPU and output tables, and every
    memory, program, image, output and syscall message carries its execution id;
  - byte, ALU and Poseidon2 tables are shared.
- **Tests:**
  - isolation;
  - statement binding: swapped outputs or programs, altered parts, a dropped or
    reordered execution;
  - **11 458 mutations, all caught**, including the Poseidon2 execution column;
  - a 3-execution proof.
- **Kernel v2:**
  - contract-owned records, spent only with the approval of a function of their
    contract;
  - outputs specified by functions must match exactly, which stops redirected payouts;
  - contract state can be created only by its own contract's functions;
  - function and kernel commit to one transcript `io_hash` (hiding, with a random
    blind).
- **Constant work:** both nullifier forms are computed for every input, so user and
  contract inputs give identical trace heights (tested).
- **Registry (critical):** the verifier takes a mandatory `registered(contract,
  program)` check. Without it, anyone could write a "function" that spends another
  contract's records. Consensus must implement it.
- **Example contract:** a private hash-locked vault (`zkvm/guests/vault`).
  - LOCK and CLAIM are proven and verified.
  - A wrong secret gives no proof.
  - **12 contract-rule violations**, each rejected identically natively and in the
    guest.
  - A transcript mismatch, unregistered programs and altered outputs are refused.

**Internal security review** (`docs/reviews/zk-security-review.md`):
- the complete assumption list;
- a coordinated multi-cell forgery analysis: bus by bus from consumer to provider, down
  to preprocessed and public data; memory consistency; per-row determinism;
  field-wrap hazards;
- protocol attacks and privacy;
- the Pure-Rust and determinism audit: no C/C++ build dependencies, `unsafe` forbidden
  in every workspace crate except the guest SDK's `ecall`;
- the required independent reviews.

It is explicitly **not** an independent review.

**Findings during ZK-3:**

| # | Finding | Resolution |
|---|---|---|
| ZK-F1 | **Integration bug:** `blacksilk-zk` committed preprocessed tables with the prover's hiding (salted) configuration, so the verifier's commitment differed and honest proofs failed (`InvalidPowWitness`). | Preprocessed tables are public: both sides commit them with the deterministic setup configuration. Regression test in `zk/tests/proofs.rs`. |
| ZK-F2 | **Soundness trap:** a 32-bit address or jump target used as a field element could wrap modulo p onto a valid address. | Every computed address and target is range-checked below 2^28 first (zkvm.md §2). |
| ZK-F3 | The semantics of reading code as data were undefined (the interpreter returned 0). | Code is part of the image, so loads return instruction words; stores must be ≥ `CODE_END` (decision ZK-3b). |
| ZK-F4 | **Security margin:** BS-ZK-1 had exactly 100 Johnson bits and 63 unique-decoding bits at 2^22 rows. The batching term bound it, so queries and grinding could not help. | BS-ZK-2: degree-8 challenge extension; ≥ 123 / ≥ 105 bits over the envelope (tested). |
| ZK-F5 | **Found by the oracle:** the redesigned shift table's padding rows violated three constraints, and its `s = 0` flag was a degree-5 product (larger quotient). | Inverse-witness zero test and a committed partial product: every constraint has degree ≤ 3 and holds on padding. The free inverse cell is listed in the mutation test, like `ALU_LT`'s. |
| ZK-F6 | **Found by the first end-to-end proof:** the Poseidon2 table's padding rows permute a zero state, but their output-byte columns are zero, so honest proofs failed (`OodEvaluationMismatch`). | Word equalities gated by `is_real`; oracle test added. |
| ZK-F7 | Transfer proofs (~2 MB) exceeded the decoder's 1 MiB cap, so valid proofs would have been rejected from the network. | Cap raised to 4 MiB; the transfer test round-trips the strict encoding under the cap. |
| ZK-F8 | **Performance:** the size-optimized guest profile made the kernel 141k cycles, and a two-permutation tree node doubled hashing. | Kernel built at opt-level 2, one-permutation tree nodes, lean sponge: 18.7k cycles (7.5×). The Poseidon2 table's interaction columns were cut from 67 to 39 without weakening any check. |
| ZK-F9 | **Found by the security review:** the CPU table height was bounded by the global 2^22 limit rather than `MAX_CYCLES` (2^21), so the circuit accepted executions twice as long as the interpreter allows (not a forgery: timestamps stay far below p). | CPU tables capped at `MAX_CYCLES`; the LogUp multiplicity bound at the largest accepted statement fell from 84% to 63% of p (tested). |
| ZK-F10 | **Design gap found while building ZK-5:** a proof shows only that *some* program produced a function's transcript. | Mandatory registry check in the verifier (tested); consensus must implement it. |
| ZK-F11 | **Prover hang (Plonky3 bug, found by sequential test runs).** Multi-table proofs could hang forever, depending on thread scheduling. `HidingFriPcs::get_quotient_ldes` (p3-fri 0.7.0) holds a `spin::Mutex` on the PCS randomness across parallel DFTs, and is called for several tables inside a rayon parallel loop. A thread waiting in the DFT can steal another table's task, which then spins on the lock held further up its own stack. `MerkleTreeHidingMmcs::commit` held its lock across the parallel tree build in the same way. **Evidence:** 3 of 3 sequential runs hung (one for 4 hours at full CPU); the span log located the stall in table 4's quotient step. This is a liveness defect (a wallet could hang); soundness and zero knowledge are unaffected. | Patched copies in `third_party/` (`[patch.crates-io]`; documented in `third_party/README.md`): random values are drawn under the lock, which is released before any parallel work; no other change. **Verified:** 40 of 40 consecutive proofs of the unfixed-hang case completed (48.4–51.4 s each), where the unpatched build hung at the second; the sequential test runs pass. Upstream fix not yet available; not reported from here. |
| ZK-F12 | `px::prove` proved first and checked the function transcripts afterwards, so a mismatched call cost a full proof before being refused. | Function runs are executed and checked in the interpreter before proving; the post-proof checks remain as a second line. |
| ZK-F13 | **Verification cost:** 76% of the 1.3–1.5 s verification recommitted the public tables (byte, program, image, output) on every proof. | They are periodic columns the verifier evaluates itself, with constrained main-trace copies (`p3-lookup` cannot carry periodic values in messages). A digest of all verifier-supplied public data (`zkvm/statement`) is absorbed into the Fiat–Shamir challenger before any commitment, which rules out Frozen-Heart-style statement changes. **Verified:** 188 ms per transfer proof; 180 mutations of the copies are all caught; wrong statements are rejected. |
| ZK-F14 | **Privacy: trace heights leaked execution length** (privacy review P-1). Tables were sized to each execution, so a function's secret-dependent loop changed the proof's shape. | Public budgets for the kernel and every registered function. The prover pads to the budget and the verifier accepts only exactly that shape (`BudgetExceeded` otherwise). Registered budgets are part of the deploy. **Tested:** identical shapes for 1 and 90 secret rounds, with different shapes unbudgeted; budget enforcement; ≤ 95% budget use for every tested witness. |
| ZK-F15 | **Relay DoS:** invalid PX proofs were classed as stateful rejections, so a peer could make nodes verify garbage proofs for free. Per-peer limits alone scaled with the number of peers. | `PxProof` is stateless misbehaviour: once the anchor (PX1) and registry (PX3) checks pass, the statement does not depend on the receiver's pool. A global PX bucket (2/s, burst 10) sits on top of the per-peer bucket. |
| ZK-F16 | **Wallet correctness (privacy review P-3):** spent key images were tracked only for transfers. A v1 output spent by a PX deposit or a deploy looked unspent and could be selected again (a rejected transaction, and the same ring member exposed twice). | Key images come from every transaction kind (`Transaction::key_images`) in the wallet and the test harnesses. |
| ZK-F17 | **Privacy (P-2):** wallets anchored spends at their own sync height, so the anchor fingerprinted when a wallet last synced. | Canonical anchor: the last multiple-of-16 height. Records become spendable once that height reaches them; tested end to end over RPC. |
| ZK-F18 | **Efficiency:** block validation re-verified every PX proof, although the mempool had already verified it. | `validate_block_transactions_cached` skips PX5 for transactions in the node's mempool. **Sound:** the id commits to the proof bytes, and the statement is fixed by the transaction, the network and immutable registry entries (PX3 is still checked). **Tested:** a block with a corrupted proof is refused, and its id differs from the original's. |
| ZK-F19 | **Hardening:** the ephemeral secrets of record delivery (ECDH scalar, KEM message, shared secrets, AEAD key) were not wiped after use. | Wrapped in `Zeroizing` in `seal` and `open`. |
| ZK-F20 | **Network (own review of ZK-F15):** exhausting the *global* PX bucket penalized whichever honest peer relayed next, and a PX transaction we had *requested* (`Tx`) could be penalized as a rate violation. An attacker could use this to get honest peers disconnected. | `px_rate` distinguishes the peer's own bucket from the global one. Only a StemTx over the peer's own share is penalized. Global exhaustion, and every requested `Tx`, is dropped silently. **Tested** over TCP with six peers (see below). Also fixed: the `px-deposit` and `px-withdraw` CLI help wrongly called v1 "transparent-amount". |
| ZK-F21 | **Prover hang, second round (Plonky3; found by the full test suite).** Concurrent proofs in one process hung forever: five threads spun at 100% for two hours in the unified-proof tests, while each test alone passed in 69 s. Two more places held a `spin` lock across rayon work, as in ZK-F11: `HidingFriPcs::commit` passed its lock guard into `with_random_cols`, whose row copy is parallel, and `p3-dft`'s `Radix2DitParallel` computed its twiddle tables (a parallel computation above 1,024 elements) under a `spin::RwLock` write lock. A thread holding one of these locks could pick up a task that needed the same lock. **Impact:** liveness only. Any process running proofs concurrently could hang: a wallet proving several transactions, or a node verifying while proving. Soundness and zero knowledge are unaffected. | Both patched in `third_party/` (`p3-dft` is a third patched crate): random values are drawn under the lock, and tables are computed before the write lock is taken. The patched Plonky3 code was checked for every other `spin` lock (that check missed one site; see ZK-F28): the FRI prover's small-batch DFT already computes outside its lock, and the other DFTs are not used. `diff -r` against the registry shows exactly the three patched files. **Evidence, stated plainly:** the hang was observed once, and the two lock sites are established from the source code. It could not be reproduced on demand: the build without these patches also passed 2 full concurrent unified runs and 80 concurrent proofs (`zkvm/tests/stress.rs`). So the fix rests on the code analysis, not on a before/after reproduction. **Checked after the fix:** 3 of 3 full concurrent unified runs (300–310 s each), 96 concurrent proofs in `stress.rs`, and the full suite; no hang. The stress test is kept, ignored by default, for every Plonky3 upgrade. |
| ZK-F22 | **Functional defect: contract records could not be delivered at all.** The delivery plaintext held only `value ‖ data ‖ rcm`, and `delivery::open` always rebuilt a *user* record with the recipient's owner tag. A contract record (owner 0, `contract ≠ 0`) therefore never passed the commitment check. Nobody could learn a contract record from the chain; only its creator, in memory, knew the opening (privacy review P-4). | Delivery v2 (docs/px.md §6, §13): the plaintext carries the contract, and `open` rebuilds user or contract records accordingly. The plaintext has one length for both kinds (104 bytes), so the ciphertext grows from 1,209 to 1,241 bytes; this is a consensus format change, covered by the planned testnet reset. **Tested:** contract records open only for their addressee; the record kind cannot be misrepresented; the end-to-end vault flow. |
| ZK-F23 | **Privacy P-7: the uniform PX fee was only a wallet convention.** Consensus required only a per-byte minimum, so a wallet paying any other fee identified itself. | Consensus rule: a PX transaction's fee is exactly `PX_STANDARD_FEE` (`TxError::PxFeeNotStandard`, stateless, checked before the proof). **Tested:** fees of ±1 are refused (`tx/tests/px_consensus.rs`). Side effect, documented: fee-per-byte ordering ranks contract calls (~2.5 MB) below transfers (~2 MB) under congestion. |
| ZK-F24 | **Documentation error in P-5 (proof length).** The privacy review blamed a varint encoding of field elements. Plonky3 in fact writes field elements as fixed 4-byte arrays in binary formats. | Corrected with measurements. A fixed-width codec was built and measured: it did not make lengths constant and made proofs 4% larger, so it was reverted. **Measured:** 6 transfer proofs of different witnesses were 2,029,768–2,046,856 bytes; the part outside the Merkle opening proof was 129,898 bytes in all six. The variation comes only from pruned query paths, which depend on the public query positions. No leak; exact constancy would need padding each proof to a per-shape worst case (docs/px.md §4.4). |
| ZK-F25 | **Documentation errors.** The dependency review said the PX proofs do not use Plonky3's Merkle path pruning; they do (FRI's `open_multi_batch`). `px/src/lib.rs` still said "not consensus yet". | Both corrected. |
| ZK-F26 | **Wallet: `clear-pending` did not clear PX spends.** Only v1 outputs were unmarked, so PX records of a dropped transaction stayed unspendable until the 20-block expiry. | `clear_pending` also clears PX and contract records, and drops unconfirmed contract records this wallet created (unit-tested). |
| ZK-F27 | **Wallet: a claimer whose wallet was newer than a contract's deploy could not use the contract.** The wallet learned contracts only from the deploys it scanned, and a new wallet scans from the current height. Found in the contract-wallet review. | The node serves the complete, ordered registration list (`/px/contracts`, backed by a registration log in the chain state with exact reorganization undo). Wallets download it whole, like the commitment list, so the node learns nothing about which contracts a wallet uses. **Tested:** a wallet created after the deploy knows the contract (`wallet/tests/e2e.rs`); the log gains the registration and loses it on undo (`tx/tests/px_consensus.rs`). |
| ZK-F28 | **Our own ZK-F11 patch was incomplete** (found while preparing the upstream report, by auditing every lock in the patched crates). In `get_quotient_ldes` the patch released the lock before the DFTs, but inside the locked block it still called `with_random_cols`, whose row copy is parallel: the ZK-F21 pattern, still present at one site. So the earlier statement that no `spin` lock is held across rayon work was wrong for this site. | The random columns are drawn sequentially under the lock (`RowMajorMatrix::rand`, in the order `with_random_cols` draws them), and the matrices are widened by a shared helper (`widen`) after the lock is released, with the originals dropped to keep peak memory as upstream. `commit` uses the same helper. **Every** `lock()` in the three patched crates was re-audited: each now does only sequential work. **Tested:** a new unit test shows the result equals `with_random_cols`'s exactly for the same RNG state (proofs unchanged for a seed); upstream's `p3-fri` suite passes with the fix (65 tests, with and without parallelism). Downstream, with the final patch: the full suite (396 passed, 0 failed) and 80 concurrent proofs on 8 threads without a hang (909 s). |

**ZK-6: consensus integration** (spec `docs/px.md` §11). All of the following is
implemented, wired into the node and tested:
- **Transaction formats:** kind 2 (PX) and kind 3 (deploy), with strict canonical
  codecs and size caps.
- **Balance:** the v1-side balance, and the PX-side balance proven by the kernel; the
  uniform standard fee; a separate 8 MiB PX byte budget per block.
- **State:** the anchor window, nullifier set, containment pool, contract registry
  (immutable entries fixed by the contract id), and exact per-block undo.
- **Validation:** the PX rules PX1–PX5 in the mempool and in blocks, including
  in-order pool simulation and contract-id uniqueness.
- **Mempool:** a separate PX class; conflicts on key images, nullifiers and contract
  ids; revalidation after each block without re-proving.
- **Network:** relay of every kind; Dandelion++ stem conflicts on nullifiers;
  per-peer and global PX limits.
- **RPC:** `/px/commitments` and (ZK-7) `/px/contracts` for bulk wallet sync.
- **Wallet:** `px-address`, `px-balance`, `px-deposit`, `px-send` and `px-withdraw`,
  with persistence, rewind and the canonical anchor.

**Tests:**
- `tx/tests/px_consensus.rs`:
  - private payments;
  - anchors and value creation;
  - a contract deployed, then used through consensus (LOCK/CLAIM);
  - tampering, other networks and double spends refused;
  - a block with a corrupted proof refused.
- `p2p/tests/network.rs::px_transactions_travel_the_stem_and_confirm_everywhere`: a
  proven deposit is stemmed, diffused and verified by three nodes over TCP, then mined;
  all nodes end with one PX state. The same test then floods one node with StemTx PX
  transactions from six raw peers: exactly the one peer over its own share is
  penalized (ZK-F20).
- `wallet/tests/e2e.rs`:
  - `private_funds_move_over_rpc`: deposit, private payment and withdrawal through the
    real node and RPC;
  - `px_records_follow_a_reorganization`: a deposit is reorganized away (balance and
    records drop to zero, the transaction returns to the pool), then re-mined and
    spendable again.
- `wallet/src/px.rs` unit tests: the canonical anchor, spendability under the anchor,
  input selection, and rewind of records, spends and commitments.
- `zkvm/tests/stress.rs` (ignored by default): 8 threads proving concurrently
  (ZK-F21).
- **Tests corrected after the PX changes** (the product code was right in each case):
  - `p2p` `transport::frames_round_trip_both_ways` deadlocked once `MAX_FRAME` grew
    past the test pipe's 4 MiB buffer, because it sent before receiving on one task.
    It now sends and receives concurrently, as peers do; each connection has its own
    writer task.
  - `p2p/tests/network.rs::transactions_travel_the_stem_then_fluff_everywhere`
    checked node C's height at the instant A confirmed. Blocks spread headers-first
    over whatever links address exchange made, so it now waits for C.
  - `tx/tests/adversarial.rs::decoder_never_panics_on_garbage` expected every input
    over 100 kB to be `TooLarge`. It now checks the absolute cap and each kind's cap.

**Privacy and dependency reviews** (`docs/reviews/privacy-review.md`,
`dependency-review.md`):
- Every channel is graded: transaction structure, proof shape and length, timing,
  contract execution, propagation, scanning, errors.
- Findings P-1 to P-8 (updated 2026-09-25): P-1, P-2, P-3, P-4 and P-7 fixed; P-5
  supported by measurement and reasoning, with independent review pending (privacy
  review §3a); P-6 and P-8 inherent and documented.
- `zk/tests/pins.rs` pins Poseidon2 to a known-answer vector, so a dependency upgrade
  cannot silently change every PX hash.

**Fuzzing** (pure Rust, seeded and repeatable; `BLACKSILK_FUZZ_ITERS`; not
coverage-guided):

Campaign of 2026-09-24, release build, `BLACKSILK_FUZZ_ITERS=20000` unless stated.
Everything passed: no panic, no invariant violation.

| Target | Test | Result |
|---|---|---|
| Transaction codec | `tx/tests/fuzz_decode.rs` | 20,000 mutants per seed; 30,588 still decoded, all canonical (decode∘encode is the identity); 25 PX mutants validated in full, all rejected. 123 s |
| BVM-1 constraints | `zkvm/tests/fuzz.rs::random_programs_satisfy_every_constraint` | 20,000 random programs (every ALU operation, loads and stores of every width, branches, `WRITE`, `POSEIDON2`, `READ`): all halted and satisfied every constraint of every table, with every bus balanced; 2 proven and verified end to end. The generator is built to halt, so traps are not exercised here (the ELF target covers them). 4,284 s |
| BVM-1 loader | `zkvm/tests/fuzz.rs::mutated_elfs_never_panic_the_loader_or_the_interpreter` | 40,000 mutated ELFs: 21,002 loaded, 1,437 halted. 2 s |
| PX kernel | `px/tests/fuzz.rs::mutated_witnesses_get_the_same_verdict_natively_and_in_the_guest` | 20,000 mutated witnesses: 7,181 accepted with identical output natively and in the guest, 8,756 rejected identically, 4,063 trapped (short input) |
| PX delivery | `px/tests/fuzz.rs::mutated_ciphertexts_never_open_and_never_panic` | 20,000 mutated ciphertexts: none opened |
| P2P messages | `p2p/tests/fuzz_message.rs` | 20,000 mutants and 20,000 random frames; 7,295 mutants still decoded, all canonical |
| Contract engine | `contracts/tests/fuzz.rs` | 20,000 mutated modules: 1,941 passed the check and deployed, 1,714 called |
| Block codec | `chain/tests/fuzz_block.rs` | 20,000 mutants; 5,400 still decoded, all canonical |

These are seeded mutation campaigns: repeatable, but not coverage-guided. The
coverage-guided campaign is under ZK-7.

**ZK-7: contract tooling, record distribution and hardening (2026-09-25).**
- **Record distribution** (docs/px.md §13; privacy review P-4 resolved):
  - on-chain delivery of each contract record to a designated party;
  - the creator's own copy;
  - off-chain sealed shares (`px/src/share.rs`);
  - spends seen by every holder through the contract nullifier
    (`px_core::record::contract_nullifier`, checked against the kernel's).
- **Reference contract** (`px/src/vault.rs`): the vault's program is pinned
  (`px/vault.elf`, `px/vault.id`, tested) and shared by the wallet and the tests.
- **Wallet:**
  - the contract index (every deploy);
  - contract records kept apart from funds, with their lifecycle under
    reorganizations;
  - `px-deploy`, `px-contracts`, `px-records`, `px-vault-lock`, `px-vault-claim` (fee
    from PX or v1), `px-share`, `px-import`.
- **Consensus:** the exact PX fee (ZK-F23).
- **Tests:**
  - 3 new delivery tests;
  - the vault-id pin and the contract-nullifier check;
  - 3 new wallet unit tests;
  - `wallet/tests/e2e.rs::a_vault_is_deployed_locked_delivered_shared_and_claimed_over_rpc`,
    which passed through a real node: deploy, lock delivered to Bob, share to Carol,
    wrong secret refused before proving, claim paid from v1 funds, spend seen by all
    three, second claim refused, then a second lock and a claim paid from a PX record
    (v1 balance untouched, the exact PX balance checked).
- **Supply chain:** `cargo audit` found 0 vulnerabilities in 319 crates and one
  unmaintained compile-time proc macro (`paste`, via Plonky3); see
  docs/reviews/dependency-review.md §5.
- **Plonky3 patches:**
  - upstream's own test suites pass with our three files applied to the v0.7.0 release
    commit: `p3-dft` 44 tests, `p3-merkle-tree` 99, `p3-fri` 64 (65 after ZK-F28), each with and without rayon parallelism (all pass; the release sources equal the crates.io copies patched here);
  - upstream fixed the `p3-dft` site independently in 0.8.0, with the same fix and the
    same diagnosis in its comments;
  - the two hiding-commitment crates are still unfixed in 0.8.0;
  - a ready-to-file report is drafted in `third_party/UPSTREAM-REPORT.md` (not filed:
    owner decision).

**Coverage-guided fuzzing** (`fuzz/`, cargo-fuzz and libFuzzer with AddressSanitizer;
nightly MSVC toolchain; seeds from `fuzz/src/seeds.rs`; `fuzz/run_campaign.sh`):

Campaign of 2026-09-25: 15 minutes per target, one core, AddressSanitizer on,
seeded from real encodings (`fuzz/src/seeds.rs`).

| Target | What it checks | Executions | Rate/s | New corpus units | Crashes |
|---|---|---|---|---|---|
| `tx_decode` | Transaction decoding never panics; decode then encode is the identity; stateless rules never panic | 4,928,551 | 5,470 | 623 | 0 |
| `block_decode` | Block decoding never panics; canonical | 24,966,181 | 27,709 | 1,281 | 0 |
| `p2p_message` | Message decoding never panics; canonical | 108,829,741 | 120,787 | 1,012 | 0 |
| `zkvm_elf` | The ELF loader never panics; loaded programs never panic the interpreter | 880,471 | 977 | 2,409 | 0 |
| `kernel_diff` | The native and in-VM kernels agree on any input | 88,488 | 98 | 953 | 0 |
| `delivery_open` | Record delivery and shares never panic, and nothing opens without the keys | 1,629,515 | 1,808 | 38 | 0 |
| `wasm_module` | The contract engine never panics on any module; calls are fuel-bounded | 3,090,446 | 3,430 | 13,319 | 0 |
| `proof_decode` | The strict proof decoder never panics; decoding is canonical | 19,412 | 21 | 837 | 0 |

**Total:** 144 million executions, no crash, no artifact.

**Limits:**
- 15 minutes per target is short for the slow targets: the kernel differential and the
  2 MB proof decoder reached only 88,488 and 19,412 executions.
- The delivery target's low number of new units is expected: without the recipient's
  keys, almost every input stops at the view tag or the AEAD.
- The proof decoder only decodes; it does not run the verifier. Proof verification is
  covered by the mutation tests in `zk/tests/proofs.rs`.

**Final verification (2026-09-25, all ZK-7 changes in place):**
- `cargo test --release --workspace --no-fail-fast`: **394 passed, 0 failed, 2
  ignored**, over 63 test binaries (30 min). The two ignored tests are opt-in by
  design (RandomX full mode needs ~2.3 GiB; the concurrency stress test is slow).
  Both were run explicitly afterwards (RandomX full mode equals light mode, 129 s; 32 concurrent proofs on 8 threads, no hang, 316 s).
- `cargo clippy --workspace --all-targets --release`: 0 warnings; `cargo fmt
  --check`: clean. The same for `fuzz/`.
- **Proof-length evidence** (privacy review §3a):
  - the regression test in `px/tests/proof.rs`;
  - 10 deposit and 10 payment proofs: permutation p = 0.70.

**ZK-8: pre-trial assurance round (2026-09-25, after the owner's review).**
- **Plonky3 patch:** ZK-F28 fixed our own incomplete ZK-F11 patch.
  - Every lock in the patched crates was re-audited.
  - An equivalence test; upstream suites 208/208.
  - Downstream: the full suite (396 passed) and 80 concurrent proofs without a hang.
- **Upstream report:** two versions (naming BlackSilk, and anonymous), with patches
  that apply to v0.7.0, in `third_party/upstream/`. **Not filed:** owner decision.
- **P-5** (privacy review §3a): a 260-proof campaign over 6 classes and 2 shapes.
  - Every non-authentication part is byte-identical within each shape.
  - No class dependence: all pairwise p ≥ 0.49.
  - Padding options analysed; deferred with the reason recorded.
  - **Status: supported, independent review pending.**
- **Query policy:** the rationale and costs are recorded (docs/reviews/query-policy.md);
  108 queries are kept.
- **External review:** the scope is defined (docs/reviews/external-review-scope.md).
  **No part of BlackSilk's own code has been independently reviewed.**
- **Adversarial tests:**
  - peers relaying a corrupted-proof or non-standard-fee PX transaction are
    penalized, and a deposit with a corrupted proof is refused on its signatures,
    without penalty (`p2p/tests/network.rs::invalid_px_transactions_get_the_relaying_peer_penalized`);
  - a node restarted from its block file rebuilds the PX state exactly
    (`chain/tests/manager.rs::restart_rebuilds_the_px_state_exactly`).
- **Labnet with PX traffic** (5 processes, partitions, 62 min): `checks_passed`;
  restored wallets match, private balances included; supply conserved
  (docs/evidence/labnet-2026-09-25/).
- **Reset rehearsal:** a new identity; a 30-minute testnet-rules run passed; an
  old-identity node is refused (docs/testnet-reset-plan.md §7).
- **CI:**
  - the workflow now runs the tests in release mode, lint over all crates,
    `cargo audit` and a fuzz smoke job;
  - the campaign script fails on crash artifacts;
  - **not yet run:** CI runs on GitHub after a push.
- **Long coverage-guided fuzzing:** campaign of 2026-09-25, AddressSanitizer on, continuing from the first campaign's
  corpus. **All 8 targets: 386,839,603 executions in 10.5 hours, 0 crashes, 0
  artifacts.**

  | Target | Time | Executions | New units |
  |---|---|---|---|
  | `kernel_diff` | 2 h | 429,700 | 564 |
  | `proof_decode` | 2 h | 280,957 | 3,049 |
  | `tx_decode` | 1.5 h | 35,567,646 | 765 |
  | `zkvm_elf` | 1.5 h | 5,012,866 | 1,023 |
  | `delivery_open` | 1 h | 11,837,636 | 0 (saturated: without the keys, inputs stop at the view tag or the AEAD) |
  | `wasm_module` | 1 h | 16,789,244 | 10,048 |
  | `block_decode` | 45 min | 130,060,974 | 313 |
  | `p2p_message` | 45 min | 186,860,580 | 74 |

  **Limits:**
  - still modest for the slowest targets (the kernel differential, and 2 MB proofs);
  - the contract engine was still finding new coverage at the end, so it merits
    longer runs;
  - not a proof of absence of bugs.
- **Final full suite** (all ZK-8 changes): **396 passed, 0 failed, 2 ignored (opt-in).**

**Open items:**
- **Proof size (main open problem):** ~2 MB per transfer, so about 4 PX transactions
  per block. Options and measured costs are in `docs/reviews/aggregation-study.md`:
  - the query policy (owner decision; unchanged);
  - opened-width reductions;
  - recursion (a separate milestone; not viable through BVM-1).
- **Testnet reset:** approved by the owner for the final trial (PX rules apply from
  genesis).
- **Contracts beyond the vault** need their own host-side call helpers before the
  wallet can call them. The vault is a demonstration contract, not a complete swap
  contract (no timelock or refund).
- **Upstream report** of the Plonky3 hangs: drafted; owner decision.
- **Independent reviews:** security review §9; privacy review §4; dependency review
  §6.
- Multi-machine testnet trial of the PX flows (labnet), as the final stage.

### R9: Pre-testnet hardening round (2026-09-25). Internal; not independently reviewed.

**CI**
- **GitHub Actions has never run for this repository.** The workflow is registered and
  active, but GitHub reports 0 runs on any branch, and the repository's Actions page
  returns 404. Actions appears to be disabled in the repository settings; enabling it
  is the owner's action (a repository security setting).
- **Workflow hardened** (commit `3b6a0b2`):
  - actions pinned to full commit SHAs, verified against the upstream tags and
    branches;
  - `persist-credentials: false`;
  - a read-only token;
  - toolchains pinned to the evidence's versions (1.98.1, nightly-2026-09-24);
  - `cargo-audit` and `cargo-fuzz` versions pinned.
- **Two latent bugs fixed** that would have failed the first run:
  - `fuzz/run_campaign.sh` was not executable in git;
  - the fuzz job called `cargo +nightly` with a dated toolchain.
- **Checked locally only** (Windows):
  - `cargo fmt --check`, workspace and fuzz: clean;
  - `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings;
  - the no-`unsafe` check: every listed crate forbids `unsafe`;
  - `cargo audit --ignore RUSTSEC-2024-0436`: exit 0 (323 dependencies).

  **Not yet passed in GitHub Actions** at that point.
- **First GitHub Actions run** (after the owner enabled Actions):
  - run 36177083290, commit `d6534c3`, `ubuntu-latest`, 2026-09-25 19:01–20:00 UTC;
  - **all four jobs passed:**

    | Job | Time |
    |---|---|
    | lint (fmt, clippy `-D warnings`, no-`unsafe` check) | 53 s |
    | audit (`cargo-audit` 0.22.2) | 2.5 min |
    | fuzz-smoke (nightly-2026-09-24, 2 min per target, ASan) | 24 min |
    | test (release, full workspace) | 59 min |

  - **Limitation:** the results were read from the run's status API; the job logs
    need authentication and were not inspected. So test counts on Linux are not
    recorded.
  - This is the first evidence from a second platform (Linux x86_64) for
    assumptions K5 and I3. It is not a review.

**Wallet error-handling review** (docs/reviews/wallet-review.md). Findings:
- **W-1 (high, privacy):** after a transport failure the inputs were not reserved, so
  a retry re-spent a v1 output with a new ring, and the two rings could be intersected
  to find the real input.
- **W-2 (high, privacy):** reserved inputs were released after 20 blocks while the
  transaction was still pooled.
- **W-3 (medium):** a reorganization released the inputs of a confirmed spend.
- **W-4 (medium, funds):** an uncertain vault lock lost the record's opening.

**The fix, in the wallet only, with no consensus change:**
- submitted transactions are stored and their inputs reserved before sending;
- stored transactions are rebroadcast unchanged, never rebuilt;
- inputs are released only on an `Invalid` verdict or an explicit `clear-pending`;
- a transport failure returns the new `WalletError::Uncertain`;
- the RPC gains `SubmitResult::already_pooled`.

**Open:** W-5, spending again with a new ring after an `Invalid` verdict (ring reuse
not implemented). Privacy review §3c (P-9).

**Tests** (Windows, release, run locally):
- `-p blacksilk-wallet -p blacksilk-rpc`: 10 unit and 10 e2e tests passed (740 s),
  including the new and changed tests;
- the new `an_uncertain_vault_lock_keeps_the_record_opening`: passed (120 s);
- `-p blacksilk-chain`: 23 passed (202 s), including the new `deepest_reorg`
  assertion.
- **Full workspace suite** (`cargo test --release --workspace --no-fail-fast`, commit
  `f18cab6`): **399 passed, 0 failed, 2 ignored** (the opt-in RandomX full mode and
  stress tests), in 2,482 s; 3 more tests than before (the new wallet tests).

**Privacy review §3b** (P-6, P-8, query positions, proof size), the assumptions
register (docs/reviews/assumptions.md), the review package with the expertise per area,
reviewer candidates, and a launch checklist (docs/testnet-launch-checklist.md).

**K4, reorganization depth:**
- Policy for the testnet: no limit and no checkpoints. The most-work chain wins at any
  depth (docs/consensus.md §8).
- Reorganizations of 10 blocks or more are logged as warnings;
  `ChainManager::deepest_reorg` tracks the deepest.
- This adds monitoring only; chain selection is unchanged.
- Limits and checkpoints were rejected for now (a permanent-split risk, and central
  trust); they remain open for mainnet.

### R10: Hardening round 2 (2026-09-25). Internal; not independently reviewed.

- **W-5, ring reuse** (docs/reviews/wallet-review.md §1a):
  - the wallet stores the decoys of every submitted ring under the key image, and a
    later spend of the same output reuses them;
  - each member is re-verified by index and keys, and for age and coinbase maturity;
    only lost members are redrawn (`tx::decoy::select_ring_keeping`);
  - a definite refusal does not pin the ring.

  Residuals: two spends of one output stay linkable through the key image; a restore
  from the seed loses the stored rings. Tests: `an_output_spent_again_reuses_its_ring`
  (after `clear-pending`, after an `Invalid` verdict, and after a restart),
  `a_refused_transaction_does_not_pin_its_rings`, and the decoy unit test.
- **K4** is documented as a **provisional testnet policy**, accepted by the owner:
  - analysis in docs/reviews/k4-reorg-policy.md;
  - review area 9 added;
  - `/info` now reports `deepest_reorg` and `misbehaving_disconnects`.
- **Rollback and incident response:** docs/testnet-incident-response.md and
  SECURITY.md. Not rehearsed; roles not named. Also corrected docs/testnet.md, which
  still told users to run `clear-pending` for a transfer that never confirms.
- **Adversarial multi-node test** `a_double_spend_across_a_partition_resolves_to_one_spend`
  (p2p). Two nodes confirm conflicting spends of one output while partitioned. After
  healing, all three nodes hold only the heavier branch's spend, the loser is gone
  from every pool, and no honest peer is penalized.
- **Plonky3 dependency check** (dependency-review.md §5a):
  - Of the five published advisories, none applies to the 0.7.0 configuration. Three
    were fixed long before v0.7.0 (checked with GitHub's compare API).
    `MultiField32Challenger` is not used. `PaddingFreeSponge` is used, but only with
    inputs whose length the verifier fixes (`check_widths`).
  - **The only published Plonky3 audit (Least Authority, 2024) covered the non-hiding
    protocol:** the hiding mode used here has no published audit.
- **Plonky3 report, Version B:**
  - Every claim is classified as observed, inferred or unverified.
  - The attached patch was re-tested on a clean v0.7.0 checkout: it applies cleanly;
    `p3-fri` 65 and `p3-merkle-tree` 99 tests pass, with and without parallelism.
  - An overstated comment ("proofs are unchanged for a given seed") was corrected in
    the patch and in our vendored copy. What is shown is that the drawn values are
    unchanged.
  - Not submitted.
- **Reviewer shortlist:** docs/reviews/reviewer-candidates.md. Nobody has been
  contacted.
- **Extended contract-engine fuzzing** (Windows 10, 8 logical CPUs, one core per
  target, nightly-2026-09-24 MSVC, AddressSanitizer, libFuzzer via cargo-fuzz 0.13.2).
  **The engine under test (`contracts/`, wasmi 0.38) is not integrated into the chain
  (milestone M3): these results do not cover any consensus path.**

  | Target | Command | Duration | Executions | Coverage at the end | New corpus units | Crashes, panics, timeouts, OOM |
  |---|---|---|---|---|---|---|
  | `contract_sequence` (new) | `cargo fuzz run contract_sequence corpus/contract_sequence -- -max_total_time=14400 -timeout=60 -rss_limit_mb=4096 -max_len=4096` | 14,401 s (4 h) | 322,055 (22/s) | 5,475 edges, 16,605 features (corpus replay: 1,396 inputs, 781 after reduction) | 1,306 | **0** (0 artifacts); peak RSS 538 MB |
  | `wasm_module` (continued) | `-max_total_time=21600 -timeout=60 -rss_limit_mb=4096 -max_len=65536` | 6 h | *recorded when finished* | | | |

  **What `contract_sequence` checks** on every input: identical results from two
  independent executors (consistency across execution paths); fuel and storage within
  their limits (resource exhaustion); exact state-root restoration on undoing a block
  (rollback); replaying the committed diffs into a fresh state gives the same root
  (recovery); no panic. Sequences mix calls with fuzzed inputs and limits, block ends
  and undos, against a key-value module and a counter module.

  **Limits:**
  - 22 executions per second is slow: each input deploys two modules on two executors,
    so Wasm compilation dominates. Exploration depth is limited. Caching the deployed
    state per run is a possible improvement.
  - The corpus was still growing at the end.
  - Only two fixed modules are exercised as contracts. Arbitrary modules are covered
    by `wasm_module`, but not in sequences.
  - A fuzzing campaign is not a proof of absence of bugs.

### R11: Internal review round 1 (2026-09-25/26). Internal; not an external audit.

**Method** (docs/reviews/review-status.md):
- Four fresh-context review agents examined the ZK configuration, the PX kernel and
  consensus, the BVM-1 circuits, and the wallet. They were given the code,
  specifications and objectives, not the author's reasoning.
- The author verified every accepted finding against the source or by measurement.
- Full log: docs/reviews/internal-review-log.md.

**Result:**
- **ZK-F29 (critical, OPEN):** PX proofs are **not zero-knowledge as configured**.
  Plonky3 0.7.0's batch prover publishes each table's LogUp terminal unblinded. The
  Program table's terminal depends only on the per-instruction execution counts, and
  measurement (`px/examples/execution_profile.rs`) shows 33 distinct count vectors
  over 100 kernel witnesses. A proof reveals at least whether a private payment spends
  one or two real records, and some amount-dependent information.
- **ZK-F30 (high, OPEN):** 64-row tables are opened at more points than their hiding
  randomness covers. The vault's Poseidon2 table is at that minimum.
- **Both need proof-system changes, which are consensus changes:** owner decision
  (the options are in the report).
- **The circuit review found no critical, high or medium soundness issue.**
- **The PX review found no critical or high issue.** Open medium issues: memory
  retention of block bodies (PX-F1), and the caller-chosen `rcm` of
  function-specified outputs (PX-F4, a design question).
- **Wallet:** W-F1 to W-F6, W-F8 and several low findings were **fixed**, with new
  tests:
  - save before sending;
  - one ring query per input, always containing the real output (an older leak to
    the node);
  - no dropping of stored transactions or rings when a node is behind;
  - a rescan after a reorganization deeper than the kept window;
  - rings kept even after a refusal;
  - previous-block linkage checks;
  - a wallet-file lock;
  - no panics on a malformed distribution;
  - contract openings never deleted.

  Open: W-F7 (restore scans account 0 only), W-F13, W-F15, and proof-of-work checks
  in the wallet.

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
