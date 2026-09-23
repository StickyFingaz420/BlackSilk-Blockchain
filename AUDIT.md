# BlackSilk Testnet Readiness Audit

Status: **NOT testnet-ready.** This file tracks the audit defined in `Claude.md`.
Each finding lists where it is, what goes wrong, and its severity. Findings stay
open until a fix lands **and** a test demonstrates it.

Severity: **C** = critical (breaks consensus, lets funds be stolen or created, or
removes privacy); **H** = high; **M** = medium.

---

## Phase 1: Build baseline

Toolchain: rustc 1.98.1, `stable-x86_64-pc-windows-gnu` (no MSVC/gcc on the
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
