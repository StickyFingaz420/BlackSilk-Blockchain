# BlackSilk

BlackSilk is a privacy-first proof-of-work cryptocurrency written in Rust. It has two private value layers in one chain: a CryptoNote-style **v1 payment layer** (CLSAG ring signatures, stealth outputs, Pedersen commitments and Bulletproofs+ on Ristretto255) and **private execution (PX)**, a shielded pool of private records whose transfers and private contract functions are proven with one STARK proof in the BVM-1 zkVM. Blocks are mined with RandomX v1 under BlackSilk's own Argon2 salt. The node, miner and wallet are pure Rust, and every root-workspace crate root carries `#![forbid(unsafe_code)]`.

> **Status: pre-freeze, not launched, no external audit.**
> - No network running the current (v3) rule set has launched. `blacksilk-node --network testnet` refuses to start until the v3 genesis is final, and `--network mainnet` is refused. Only local regtest runs today.
> - The protocol is **not yet frozen**: the freeze gates in [docs/STATUS.md](docs/STATUS.md) §5 are open, and rules may still change. Before the freeze, the highest status any v3 item has is "Complete but requires further testing".
> - BlackSilk has had **no external audit and no independent review**, and none is engaged or planned (owner decision 2026-09-25, [review-status.md](docs/reviews/review-status.md)). All security work is internal engineering review. [AUDIT.md](AUDIT.md) is a historical internal findings log, not an audit.
> - Zero knowledge is claimed only as **statistical and conditional (computational in practice)** ([zk-coverage.md](docs/reviews/zk-coverage.md)).
> - [docs/STATUS.md](docs/STATUS.md) is the single status source. Do not use this software for anything of value.

## Contents

- [Overview](#overview)
- [Design principles](#design-principles)
- [At a glance](#at-a-glance)
- [Architecture](#architecture)
- [Consensus and blockchain](#consensus-and-blockchain)
- [Proof of work and mining](#proof-of-work-and-mining)
- [Transactions and cryptography](#transactions-and-cryptography)
- [Privacy model](#privacy-model)
- [Networking](#networking)
- [Wallets](#wallets)
- [Private execution (PX), ZK proofs and contracts](#private-execution-px-zk-proofs-and-contracts)
- [Security model and verification](#security-model-and-verification)
- [Networks](#networks)
- [Getting started (build, run, regtest)](#getting-started-build-run-regtest)
- [Configuration and RPC](#configuration-and-rpc)
- [Testing](#testing)
- [Repository structure](#repository-structure)
- [Current status](#current-status)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Reporting security issues](#reporting-security-issues)
- [Licence](#licence)
- [Further reading](#further-reading)

## Overview

BlackSilk keeps two private value layers inside one block chain:

- **The v1 payment layer.** CryptoNote-style transfers on Ristretto255. CLSAG ring signatures with key images hide the sender; one-time stealth outputs with view tags, subaddresses and the Janus anchor hide the receiver; Pedersen commitments with aggregated Bulletproofs+ hide the amount ([transactions.md](docs/transactions.md); [Transactions and cryptography](#transactions-and-cryptography)).
- **Private execution (PX).** A shielded pool of private records and nullifiers. Each PX transaction carries one STARK proof that a fixed transfer kernel, plus up to two registered contract functions, ran correctly on a private witness. The proof is made in the BVM-1 zkVM, a RISC-V virtual machine proven with Plonky3 ([px.md](docs/px.md), [zkvm.md](docs/zkvm.md), [zk.md](docs/zk.md); [PX section](#private-execution-px-zk-proofs-and-contracts)).

Blocks are mined with RandomX v1 proof of work with BlackSilk's own Argon2 salt ([consensus.md §3](docs/consensus.md); [Proof of work and mining](#proof-of-work-and-mining)).

### How the pieces fit

```
                     one block (172-byte header, RandomX v1 PoW over a 47-byte mining blob)
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ header: prev_id, timestamp, difficulty (LWMA-75), tx_root,                       │
 │         output_count + output_root (v1 outputs), px_root (PX commitment tree)    │
 ├──────────────────────────────────────────────────────────────────────────────────┤
 │ coinbase (reward(h) + fees)                                                      │
 │ v1 transfers ── CLSAG rings of 16, stealth outputs, Bulletproofs+                │
 │ PX transactions (kind 2) ── nullifiers, commitments, anchor, one STARK proof     │
 │        ▲  public bridge amounts move BLK between v1 outputs and PX records       │
 │ private-contract deploys (kind 3) ── register BVM-1 programs for PX calls        │
 └──────────────────────────────────────────────────────────────────────────────────┘
          validated by blacksilk-node, which shares one consensus crate with
          blacksilk-miner and the wallet; relayed by blacksilk-p2p (Dandelion++)
```

The header commits to both value layers: `output_root` covers the v1 outputs and `px_root` covers the PX commitment tree. A mismatch makes the block invalid ([consensus.md §2, §7.1](docs/consensus.md)).

### Goals and their documented limits

| Goal | What the code does | Limit (documented) |
|---|---|---|
| **Privacy first** | Sender, receiver and amount are hidden by default in v1 ([transactions.md §11.1](docs/transactions.md)). PX also hides which record is spent within the whole pool, and the logic of private contract functions ([zk.md §1](docs/zk.md)). | Ring privacy is statistical (1 of 16). A link observer sees which transactions a node originates. Small trial networks give small anonymity sets ([STATUS.md §6](docs/STATUS.md)). |
| **Pure Rust** | No C, no C++ and no FFI in the project's own code. RandomX is a safe-Rust interpreter with no JIT ([randomx/README.md](randomx/README.md)). | Dependencies and the patched Plonky3 crates keep their own `unsafe` ([Pure Rust and `unsafe` code](#pure-rust-and-unsafe-code)). |
| **CPU-oriented proof of work** | RandomX v1 with a project-specific salt, so stock `rx/0` hash power cannot be pointed at BlackSilk unmodified. | The salt is not a security boundary; the honest-majority assumption is nominal for a small chain (K1, [assumptions.md](docs/reviews/assumptions.md)). |
| **Fair launch** | Empty genesis body, no premine and no founder reward. The first coins are created by block 1 ([blocks.md §3](docs/blocks.md)). | The genesis is not final on any network: no beacon is committed ([Networks](#networks)). |
| **Verifiable engineering** | One status file. Every consensus change has a 15-step record. Evidence is kept under [docs/evidence/](docs/evidence/). | All review is internal. Passing tests show only the cases tested ([review-status.md §1](docs/reviews/review-status.md)). |

## Design principles

Each principle names the decision or specification section that records its reason.

1. **Remove fingerprints in the format, not in wallet policy.** The ring size is fixed at 16, outputs are sorted by consensus, and no format has `extra`, `unlock_time` or payment-ID fields. Every fee is a function of public data: a v1 transfer pays exactly the standard fee for its shape (rule T8), a PX transaction exactly `PX_STANDARD_FEE`. The PX kernel has a fixed shape, so transactions of the same shape produce traces of the same shape. **Why:** consensus can enforce a format rule for every user, but not a recommendation ([transactions.md §11.3](docs/transactions.md), [px.md §4.4](docs/px.md), record `exact-v1-fee` in [v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md)).
2. **Use a prime-order group.** All keys, key images and commitments are Ristretto255 elements with one canonical encoding each. **Why:** a whole class of cofactor bugs, including Monero's 2017 key-image double-spend, cannot occur; the cost is incompatibility with Monero wallets and vectors ([details](#cryptographic-primitives); [transactions.md §1.1](docs/transactions.md)).
3. **One implementation of each rule, shared by every role.** The node and the miner share one consensus crate; `blacksilk-randomx` is the only PoW implementation; the PX kernel is ordinary Rust (`px-core/src/kernel.rs`) compiled once for the zkVM and once natively ([px.md §1](docs/px.md)). **Why:** a separately written circuit or a second implementation could disagree with the specification and split consensus.
4. **Protocol invariants never live in user code.** One fixed kernel enforces balance, nullifiers, record existence and user-record authorization; contract functions only approve or produce records of their own contract and never move value ([contracts.md §1](docs/contracts.md)). **Why:** under-constrained circuits are a common catastrophic bug class in deployed ZK systems; this confines that risk to one component that can be reviewed in depth ([zk.md §3](docs/zk.md)).
5. **A transparent, hash-based proof system.** PX uses a Plonky3 STARK with hiding FRI over BabyBear and Poseidon2 (parameter set BS-ZK-4). **Why:** no trusted setup and pure Rust (requirements R3 and R5 in [zk.md §1](docs/zk.md)); soundness and zero knowledge rest on hash functions, not discrete logarithms ([zk.md §9.2](docs/zk.md), DR-2). **Cost:** proofs are megabytes, not kilobytes ([proof sizes](#proof-sizes-proving-cost-and-the-block-budget)).
6. **Smooth emission with a permanent tail, and no premine.** **Why:** miner revenue should not depend on fees alone, a hard cap adds no verifiable guarantee when amounts are hidden, and the tail offsets lost coins ([emission](#emission); [blocks.md §2](docs/blocks.md)).
7. **Keep the PoW algorithm and give it its own identity.** RandomX was kept with its own salt; the proposed BlackSilk-native CPU PoW (SKC-1) was rejected by internal research. **Why:** rented RandomX hash power is the real threat to a small chain, and no algorithm choice removes it ([SKC-1](#skc-1-research-only); decisions log, "Proof of work: SKC-1 research, the RandomX salt, the mining blob, xmrig" in [decisions.md](docs/reviews/phase2-2026-09-27/decisions.md)). Merge mining, checkpoints and multi-algorithm schemes were rejected in the same decision.
8. **Evidence over claims.** Every consensus change carries a record with prior art, alternatives, vectors and regression tests ([v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md)); status lives in one file with evidence per row; measured and modelled figures are labelled separately. **Why:** "finding no vulnerability does not prove that the system is secure" ([review-status.md §1](docs/reviews/review-status.md)).

## At a glance

"Not yet activated" means the item is a rule of the v3 genesis rule set, but no network running that rule set has launched.

| Area | Design | Status | Section |
|---|---|---|---|
| Proof of work | RandomX v1, Argon2 salt `"BlackSilk/RandomX/v1"`, every other parameter as in Monero's `rx/0`; input is a 47-byte mining blob; solo mining through the node's `/template` | Not yet activated. No pool or stratum server exists (a pure-Rust stratum server is **planned**) | [PoW](#proof-of-work-and-mining) |
| Block time | 120 s on testnet and mainnet; 10 s on regtest (local testing only) | Not yet activated | [Networks](#networks) |
| Difficulty | LWMA-1, window 75, counted clock with step T/2, warmed over 11 blocks; FTL 360 s | Not yet activated; the DAA residuals are accepted for the testnet only | [Difficulty](#difficulty-adjustment-lwma-1-n--75-with-a-warmed-counted-clock) |
| Emission | `reward(h) = max(0.6 BLK, (M − G(h)) >> 20)`, `M` = 21 M BLK, then a 0.6 BLK tail per block forever; no premine | Not yet activated; curve figures are computed from the formula, not observed | [Emission](#emission) |
| v1 privacy | CLSAG (ring 16), key images, stealth outputs, view tags, subaddresses, Janus anchor, Pedersen commitments, Bulletproofs+ on Ristretto255 | Not yet activated | [Transactions](#transactions-and-cryptography) |
| PX | Private records and nullifiers; a fixed transfer kernel plus up to two contract functions in one Plonky3 STARK (BS-ZK-4); transaction kinds 2 (PX) and 3 (deploy) | Not yet activated; part of the rule set from genesis. **Experimental**: zero knowledge is statistical and conditional (computational in practice) | [PX](#private-execution-px-zk-proofs-and-contracts) |
| PX proof size | About 2.40 MB (transfer), 3.0 MB (one function), 3.63 MB (two functions), **measured** under BS-ZK-3 on one machine; about 3.70 MB for the widest shape **by model** | Not re-measured under BS-ZK-4 (expected unchanged) | [Proof sizes](#proof-sizes-proving-cost-and-the-block-budget) |
| Contracts | PX is the only consensus contract platform; one **demonstration** contract (the vault, not an HTLC); the Wasm design is frozen **research**, outside the build | Not yet activated (PX); research (Wasm) | [Contracts](#contracts-deploy-and-call-flow) |
| Network | Encrypted but unauthenticated transport (optional pre-shared key), header-first sync, Dandelion++, bucketed address manager, outbound SOCKS5/Tor | **Experimental**, not consensus. Transport v2 is **planned** (design notes only). No I2P, no built-in seed nodes | [Networking](#networking) |
| Network ids | Testnet v3 `0x0001D673`; regtest `0x00DEB06E`; mainnet parameters provisional | Testnet disabled; mainnet refused | [Networks](#networks) |

## Architecture

### Crate map (root workspace)

The root [Cargo.toml](Cargo.toml) has nineteen members. "Depends on" lists only dependencies on other BlackSilk crates, as declared in each crate's `Cargo.toml`.

| Crate (directory) | Responsibility | Depends on (BlackSilk crates) |
|---|---|---|
| `blacksilk-randomx` (`randomx/`) | The single RandomX v1 implementation: light mode (256 MiB cache) and full mode (dataset of about 2 GiB), software emulation of the FPU rounding modes, start-up self-test vectors | none |
| `blacksilk-consensus` (`consensus/`) | Header-chain rules: header format, mining blob and PoW check, LWMA difficulty, timestamps, transaction Merkle root, chain parameters, genesis, the `HeaderChain` tree | randomx |
| `blacksilk-crypto` (`crypto/`) | Ristretto255 primitives, domain-separated hashing, Pedersen commitments, keys and subaddresses, stealth outputs and view tags, the Janus anchor, CLSAG, aggregated Bulletproofs+, hedged nonces | none |
| `blacksilk-zk` (`zk/`) | Plonky3 configuration (hiding FRI STARK over BabyBear, degree-8 extension), parameter set BS-ZK-4, strict proof decoding, verification behind `catch_unwind` | crypto |
| `blacksilk-zkvm` (`zkvm/`) | BVM-1 (RV32I plus Zmmul): decoding, ELF loading and program ids, the reference interpreter, the AIR constraint tables | crypto, zk |
| `blacksilk-px-core` (`px-core/`) | `no_std`, no allocation, no dependencies: the `Hk` hash, records, nullifiers and the transfer kernel, compiled for host and guest | none |
| `blacksilk-px` (`px/`) | PX host side: commitment tree, consensus PX state with undo, wallet-side records, record delivery, kernel and function proofs (embeds `kernel.elf` and `vault.elf`), the reference vault | px-core, crypto, zk, zkvm |
| `blacksilk-tx` (`tx/`) | Transaction format and canonical codec; stateless, contextual and block-level validation for v1, PX and deploy; the reference state `MemoryChain` with per-block undo; the output MMR; builders, scanning and decoy selection | crypto, consensus, px, px-core, zkvm, zk |
| `blacksilk-chain` (`chain/`) | Blocks, emission, the `ChainManager` (fork choice, reorganizations, replay), the chain actor, the mempool, the block store, sync policy, address strings | consensus, crypto, tx, px, px-core |
| `blacksilk-p2p` (`p2p/`) | Encrypted transport, message codec, header-first sync, block and transaction relay, Dandelion++, address manager, limits and bans, SOCKS5 | consensus, crypto, tx, chain |
| `blacksilk-rpc` (`rpc/`) | RPC wire types shared by the node, miner and wallet, plus a blocking client (an interface, not consensus) | none |
| `blacksilk-node` (`node/`) | The node binary: configuration, data directory, store replay, chain actor, P2P, the authenticated loopback RPC (axum), the consensus fingerprint | chain, consensus, tx, rpc, p2p, crypto, px, randomx |
| `blacksilk-miner` (`miner/`) | The solo miner: builds a block from `/template` and searches nonces with RandomX | randomx, consensus, crypto, tx, chain, rpc |
| `blacksilk-wallet` (`wallet/`) | The CLI wallet: encrypted wallet file, scanning, local output index, header-chain check, v1 transfers, PX flows and contracts | consensus, crypto, tx, chain, rpc, px, px-core, zkvm |
| `blacksilk-labnet` (`tools/labnet/`) | Lab network: real node and miner processes behind latency and partition proxies, with invariant checks | consensus, randomx, chain, rpc, tx, wallet |
| `blacksilk-supply-audit` (`tools/supply-audit/`) | Closed-set supply check for a trial: wallet holdings against emission and the PX pool | consensus, chain, rpc, tx, wallet |
| `blacksilk-genesis` (`tools/genesis/`) | Builds and verifies a genesis block derived from a Bitcoin block-hash beacon | consensus |
| `blacksilk-daa-sim` (`tools/daa-sim/`) | Monte Carlo harness for the difficulty rule (evidence, not consensus) | consensus |
| `blacksilk-stratum-bridge` (`tools/stratum-bridge/`) | Loopback, regtest-only stratum bridge that let real xmrig mine for the xmrig compatibility gate; verifies every share with the node's own PoW code. An evidence and test tool, not a pool, and not in the release package | randomx, consensus, crypto, chain, rpc, miner |

The dependency graph has no cycles, and the PX crates sit below `tx`. `px-core` is the one source shared by nodes, wallets and the kernel guest, so no separate circuit description can drift from what a proof establishes ([px-core/src/lib.rs](px-core/src/lib.rs)). `consensus` is shared by the node and the miner, so the two cannot disagree on what a valid header is ([consensus/src/lib.rs](consensus/src/lib.rs)). Workspaces outside the root build are listed under [Repository structure](#repository-structure).

### Node composition

`node/src/main.rs` starts the node in this order:

1. Load the configuration; check the chain parameters (`ChainParams::check`) and refuse parameters the code was not written for.
2. Create the data directory owner-only, take an exclusive `LOCK` file, and tighten permissions left too open.
3. Run the **RandomX self-test** against known answers before anything is verified.
4. Open `blocks.dat` and build the `ChainManager` with `open_checked`, which replays the store and re-verifies a sample of the stored PoW hashes (all of them with `--verify-store-pow`).
5. Check the local clock (the only clock consensus reads).
6. **Start the chain actor.** From here only the actor thread touches the manager.
7. Inside a tokio runtime, start P2P with a handle to the actor, bind the RPC listener and serve it (cookie authentication, connection limits, the guard). Watchers stop the node if the store fails or the manager halts.
8. On shutdown, stop the actor between drain steps. A drain in progress is replayed at the next start, because every kept body was fsynced before it was applied.

### The chain manager and the chain actor

**`ChainManager`** (`chain/src/manager.rs`) keeps the header tree, the block bodies, the transaction state (`tx::state::MemoryChain`: outputs and their MMR, key images, PX state, contract registry), the mempool and the store consistent behind one API. Its invariant: the state equals the result of applying the connected chain's bodies in order. Replay releases stored blocks in the same order as live processing, so every restart passes through the same sequence of states. Fork choice is described under [Fork choice and reorganizations](#fork-choice-and-reorganizations).

**The chain actor** (`chain/src/actor.rs`; [chain-actor-stage2.md](docs/reviews/chain-actor-stage2.md)) is one OS thread that runs every manager operation, one at a time:

- **Lanes.** Commands come from four bounded priority lanes, Headers > Blocks > Query > Tx, with a starvation bound. Producers never block: a full lane returns `SendError::Full`, and relayed transactions are dropped instead, without penalty.
- **Bounded drains.** Bodies that release waiting descendants are connected in bounded steps, with at most one waiting command served between two steps.
- **Snapshots.** After every command or step the actor publishes a `ChainSummary`. The P2P handshake, locators, tip announcements and `/info` read this snapshot, so they never wait for chain work.
- **Fail-stop.** A panic exits the process with status 70; a restart replays the store.

**Why:** before this stage every access went through one unfair mutex, so a heavy block or a reorganization stalled header sync, relay and RPC. The actor runs exactly the closures the mutex allowed, so consensus results are unchanged (`chain/tests/actor_equivalence.rs`, `chain/tests/actor_order.rs`). It uses std primitives only (decisions "Agent 34"). Stages 3 and 4, which move the header index, mempool and verification outside the writer, are **not implemented** ([STATUS.md §3](docs/STATUS.md)). The chain crate has no async runtime: replies go through callbacks that P2P wraps in tokio oneshots, so consensus code does not depend on a network runtime.

### Data flow

```text
 wallet (blacksilk-wallet)                              miner (blacksilk-miner)
  build_transfer / build_px  ──POST /tx──┐       ┌── GET /template ─┐   POST /block
  (PX: prove locally via px::prove)      │       │                  │   (RandomX nonce search)
                                         v       │                  v        │
 ┌────────────────────────── blacksilk-node ─────┴──────────────────────────┴───┐
 │  RPC (axum, cookie, loopback)                                                 │
 │     │ /tx with P2P                                   /block: PoW precomputed  │
 │     v                                                off-actor, Blocks lane   │
 │  P2P (tokio) ── Dandelion++ stem ── StemTx ──> peer ... ──> fluff: InvTx/Tx   │
 │     │ header-first sync: PoW jobs computed by the header worker, then         │
 │     │ accept_headers on the Headers lane; bodies fetched by missing_bodies    │
 │     v                                                                         │
 │  chain actor (one thread; lanes Headers > Blocks > Query > Tx) ── snapshot ──>│ readers
 │     v                                                                         │
 │  ChainManager                                                                 │
 │   ├─ mempool  (validate_mempool_tx: v1 / PX incl. proof / deploy)             │
 │   ├─ headers  (consensus::HeaderChain: PoW, LWMA, MTP/FTL)                    │
 │   ├─ store    (blocks.dat append + fsync  ──before──>  apply)                 │
 │   └─ state    (tx::MemoryChain: outputs+MMR, key images, PX state; undo)      │
 │         reorg: undo_block → validate_block_transactions_cached → apply_block  │
 └───────────────────────────────────────────────────────────────────────────────┘
```

1. **Transaction creation (wallet).** For v1, the wallet picks decoys from its *own* output index, so the node is never asked about ring members, and builds the transfer. For PX, `tx::px_builder::build_px` runs the kernel natively and contract functions in the interpreter, encrypts output records, builds the v1 part, computes `h_tx`, proves, and then signs the v1 inputs over a message that includes the proof ([px.md §11.1](docs/px.md); `tx/src/px_builder.rs`).
2. **Mempool admission and relay.** With P2P running, a locally submitted transaction enters the Dandelion++ stem rather than being broadcast ([Networking](#transaction-relay-dandelion-and-the-trickle)). Relayed transactions are admitted on the Tx lane through `validate_mempool_tx`, which fully validates v1, PX (including the proof) and deploy transactions. Conflicts on key images, nullifiers and contract ids are first-seen-wins. The mempool is policy, not consensus ([blocks.md §7](docs/blocks.md)).
3. **Block template and mining.** `/template` is served only once the node is caught up and not mid-drain. The miner builds the coinbase and header, hashes the mining blob, and posts the block. Its PoW check is `consensus::pow::check_hash`, the same function nodes use ([Mining](#mining-and-the-mining-rpc)).
4. **Block validation.** An RPC block has its PoW computed outside the actor and is submitted on the Blocks lane. From peers, headers arrive first; the header worker computes their PoW in parallel, then bodies are requested. The body is checked against `tx_root`, the block is appended to the store (fsync) and then connected ([Validation pipeline](#validation-pipeline)).
5. **PX proving and verification.** A PX proof is one BVM-1 batch proof: execution 0 is the fixed kernel, executions 1 and later are registered contract functions, all bound to `h_tx`. Verification decodes the proof under fixed caps and calls into `zk::verify` behind `catch_unwind`, which is why the release profile sets `panic = "unwind"`. Proofs verified at mempool admission under the same rule set are not verified again when a block connects.

**Planned:** moving the wallet-side code out of `tx` and `px` (Stage C) is scheduled after the trial (decisions "Agent 46").

## Consensus and blockchain

> **Status: not yet activated.** The v3 rule set as implemented on `rebuild/core`. [STATUS.md §2](docs/STATUS.md) lists each rule as "Complete but requires further testing".

The normative specifications are [consensus.md](docs/consensus.md) (header chain) and [blocks.md](docs/blocks.md) (blocks, emission, node behaviour); transaction and block-body rules are in [transactions.md §8](docs/transactions.md). Per-network parameters are under [Networks](#networks).

- **The network id is bound into everything.** It enters the block id (`H("BlackSilk/block-id" ‖ LE32(network_id) ‖ header)`) and the PoW mining hash; every transaction signature domain commits to `network_id ‖ branch_id ‖ genesis_id` ([consensus.md §11](docs/consensus.md)); the block store's file header names the network id and genesis id. Headers, work, signatures and stored data therefore cannot be carried from one network to another.
- **Startup checks.** `ChainParams::check` rejects inconsistent parameters at start-up, for example requiring `T·N·(N+1) < 2^64` for the difficulty arithmetic and `1 ≤ FTL ≤ 7200 s`.

### Block header (172 bytes)

The serialized header is exactly 172 bytes, little-endian, with no padding (`HEADER_SIZE`, `consensus/src/header.rs`). Any other length is refused.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `version` | Header version of the rule-set epoch at this height (`1` in every built-in schedule) |
| 4 | 8 | `height` | Distance from genesis |
| 12 | 32 | `prev_id` | Parent block id |
| 44 | 8 | `timestamp` | Unix seconds, chosen by the miner |
| 52 | 8 | `difficulty` | Must equal the DAA's output for this position |
| 60 | 32 | `tx_root` | Merkle root of the block's transaction ids, coinbase first |
| 92 | 8 | `output_count` | v1 outputs of the chain through this block, coinbase outputs included |
| 100 | 32 | `output_root` | Root of the Merkle mountain range (MMR) over those outputs |
| 132 | 32 | `px_root` | Root of the PX commitment tree after this block |
| 164 | 8 | `nonce` | Controlled by the miner |

- **Why height and difficulty are in the header.** A header can be checked in context without its body, and a block's work is explicit ([consensus.md §2](docs/consensus.md)).
- **Why this `tx_root` shape.** Leaf and node prefixes (`0x00`, `0x01`) and carrying an odd node up unchanged remove the CVE-2012-2459 class of duplicate-transaction malleability ([consensus.md §7](docs/consensus.md)).
- **Proof-of-work input.** RandomX hashes a 47-byte mining blob derived from the header, not the header itself ([The mining blob](#the-mining-blob)).

#### Output commitments: rules B-OMR and B-PXR

- **B-OMR.** `output_count` must equal the parent's count plus the block's outputs, and `output_root` must be the MMR root of the parent's output range with the block's outputs appended in block order (coinbase first). Each leaf binds the output's one-time key, commitment, block height and a coinbase flag; the root binds the count ([consensus.md §7.1](docs/consensus.md)).
- **B-PXR.** `px_root` must be the PX commitment tree's root after the block's PX output commitments are appended ([px.md §5](docs/px.md)).
- **Checked with the body, not the header.** A header with false values enters the header tree; when its body is checked against the parent's state, the block and its descendants are marked invalid. No block is connected before its body is validated, so a header-only bound would reject nothing extra (record `output-root`).
- **Why.** Before this rule, the global index of every ring member, and the PX commitments below a restored wallet's height, rested on the node's word; a dishonest node could shift that list and make a wallet's rings name different outputs. Now a wallet checks its output index against a single header (record [`output-root`](docs/reviews/v3-consensus-changes.md); prior art: Grin's header MMRs).
- **Test vectors.** The independent script `tools/vectors/output_mmr.py` generates vectors checked by `tx/tests/output_mmr_vectors.rs`; chain-level tests are in `chain/tests/output_root.rs`. These rules are not yet covered by any mutation-testing run ([STATUS.md §2](docs/STATUS.md)).

### Block format and limits

```
block = header (172 bytes) ‖ varint tx_count (1..=10 000) ‖ { varint len ‖ tx bytes } × tx_count
```

| Limit | Value | Source |
|---|---|---|
| Encoded block size | `1 000 000 + 8 MiB + 64 KiB` (`MAX_BLOCK_BYTES`) | `chain/src/block.rs` |
| v1 block weight (B6) | 600 000 (`MAX_BLOCK_WEIGHT`); fee 20 atomic units per weight unit | `tx/src/params.rs` |
| PX and deploy bytes per block | 8 MiB (`MAX_PX_BLOCK_BYTES`), of which deploys at most 1 MiB | `tx/src/params.rs` |
| Transactions per block | 10 000 (`MAX_BLOCK_TXS`) | `chain/src/block.rs` |

Each length prefix must match its transaction's strict decoding, with no trailing bytes. The v1 part of a PX or deploy transaction counts against the weight limit (record `r12-2`), so a valid block holds at most 914 v1 inputs of all kinds ([transactions.md](docs/transactions.md) B6). The limits are fixed; a dynamic block size is **planned** ([blocks.md §5](docs/blocks.md)).

### Validation pipeline

Checks run cheap-first. The order decides only which error is reported and how much work comes before it, never the verdict ([consensus.md §6](docs/consensus.md), [transactions.md §8.3](docs/transactions.md)).

```
block arrives (P2P or /block)
  │
  ├─ body vs tx_root ── mismatch → body discarded, header neither stored nor marked invalid (anyone can pair a header with garbage)
  │
  ├─ header rules (parent known and not invalid), in this order:
  │     1 version == epoch_at(height).header_version   (unknown higher version: non-permanent,
  │                                                      only with real PoW, RT-1)
  │     2 height == parent.height + 1
  │     3 difficulty == next_difficulty(parent's branch)
  │     4 timestamp > median of the last 11 timestamps  (median-time-past)
  │     5 timestamp ≤ local clock + 360 s               (non-permanent: depends on the local clock)
  │     6 RandomX(seed_id, mining blob) meets difficulty (most expensive, last)
  │
  ├─ low-work body policy (node policy) → record appended to blocks.dat and fsynced
  │
  └─ when the block would connect: body against the parent's state, cheap-first
        coinbase (B1, B2, B7) → transaction structure → B5, B-OMR, B6, B8, B-PXR, B3
        → balances → PX proof decode → key images / nullifiers / PX6 → ring resolution
        → Bulletproofs+ batch → CLSAGs → PX proofs
        valid → atomic apply;  invalid → block and its descendants marked invalid
```

- **Permanent rules before the future limit (F-05).** Every permanent header rule except PoW runs before the future time limit, so a header with a wrong difficulty and a future timestamp is reported as the permanent `BadDifficulty` (vectors `header_check_order_vectors`; record `f05-header-check-order`).
- **A valid block always applies.** Validation is a superset of every condition under which applying fails (B8). A block that passes validation and still fails to apply is a node bug: the manager halts without marking the block invalid, and the node exits with status 65.
- **Coinbase.** The coinbase must pay **exactly** `reward(h) + fees` (B3). Unlike Monero, under-claiming is invalid, so the supply is exactly computable.
- **Spendable age.** Ring members must be at least 10 blocks old, coinbase outputs at least 60 (`COINBASE_MATURITY`, [transactions.md §5.3](docs/transactions.md)). **Why:** a reorganization shallower than 10 blocks cannot invalidate a ring; coinbase outputs vanish in any reorganization that replaces their block.

### Timestamps

- **Median-time-past.** A timestamp must be strictly greater than the median of the last 11 timestamps (the lower middle value for an even count).
- **Future limit.** At most `local time + 360 s`. A header rejected only by this rule is not marked invalid and may be accepted later. The node never adjusts its clock from peers.
- **Why 360 s rather than 2 hours.** LWMA reacts to timestamps within a few blocks; the LWMA recommendation is `FTL ≤ N·T/20` (450 s at `N = 75`, `T = 120`). Operators must keep their clocks synchronized with NTP ([testnet.md §12.2](docs/testnet.md)).

### Difficulty adjustment: LWMA-1, N = 75, with a warmed counted clock

The rule id is `lwma1-n75-step-t/2-warm11-cap6t-floor20` (`consensus/src/difficulty.rs`); it is part of the consensus fingerprint. For each block it reads the last 87 ancestors on the block's own branch: a window of 76 timestamps plus a warm-up of 11.

- **Counted clock.** Each solve time is measured on a clock that advances at least `step = max(1, ⌊T/2⌋)` per block: `this = max(t[i], prev + step)`. A single counted solve time is capped at `6·T`.
- **Warm-up.** The clock is warmed over the 11 blocks before the window, so a single low timestamp at the window's start cannot restart it low (red-team finding RT-DAA RT-1).
- **Formula.** `next = S·T·(n+1) / (2·L)`, where `S` is the sum of the window's difficulties and `L` the linearly weighted sum of solve times, floored at `n²·T/20`, clamped to `[1, u64::MAX]`, all in `u128` integers. Near genesis the window shortens.
- **Why.** The earlier rule (LWMA-60 with a 1-second clock step) allowed a difficulty-raising attack (finding 03-F1): a private branch could concentrate its work in a few very hard blocks. With the counted clock a block can raise the difficulty to at most twice the window average. N = 75 with step `T/2` was the only one of 29 candidates that met all 8 acceptance criteria in the `tools/daa-sim` harness (decisions "DAA DECIDED" and "DAA FINAL" in [decisions.md](docs/reviews/phase2-2026-09-27/decisions.md); record `daa-lwma75-warm`).
- **Simulated figures** (from the harness, not a live network; [daa-sim red-team evidence](docs/evidence/daa-sim-2026-09-27/redteam.md)): an attacker with 40 % of the hash rate gains about +3.5 % over the honest baseline in a 100-confirmation race; honest block times are about 1 % slower than `T`; recovery from a 10× hash-rate change takes about 113 blocks upward and 130 downward.
- **Accepted limits for the testnet.** A hash-rate hopper gains a few points of block share (criterion relaxed to ±5 points for the testnet, to be reopened before mainnet); settling after a 100× or 1000× hash-rate increase takes a few hundred blocks; the remaining raising-race excess is accepted under K1 ([assumptions.md](docs/reviews/assumptions.md)).
- **Differences from the reference LWMA-1** are deliberate and listed in [consensus.md §4](docs/consensus.md). Vectors: `consensus/tests/data/lwma_vectors.txt`, from the independent script `tools/vectors/lwma_warm.py`.

### Fork choice and reorganizations

- **Most work wins.** A block's work is its difficulty; a chain's work is the `u128` sum. On a tie the chain whose tip arrived first is kept. Header validity depends only on a header's own ancestors, so every node reaches the same verdict in any arrival order.
- **Connected chain versus best header chain.** The transaction state follows the most-work chain whose bodies are all present; the best header chain only guides downloads. The node leaves its current chain only for a body-complete branch with **strictly** more work ([blocks.md §6](docs/blocks.md)). **Why:** fix A10-H1 (2026-09-27): an attacker who announced a header and withheld its body could otherwise stall block production for good (tests `chain/tests/fork_choice.rs`, `p2p/tests/withheld_body.rs`).
- **How a reorganization runs.** The node undoes the old blocks in reverse order with exact per-block undo, after capturing their transactions for the mempool, then validates and applies the new branch block by block in bounded steps. It never leaves a lighter tip than it started with. An independent brute-force reference model (`chain/tests/reference_model.rs`) is compared with the real manager after every step; it tests only the cases it runs.
- **Deep reorganizations (provisional testnet policy K4).** There is **no depth limit and no checkpoint**: the most-work chain wins at any depth, so honest nodes always converge. Reorganizations of 10 blocks or more are logged as warnings, and the deepest seen is reported in `/info` as `deepest_reorg`. The cost: an attacker with a majority of the hash power can rewrite any amount of history (K1, K4). **Why:** a hard limit could split nodes that saw different branches, and release checkpoints would add central trust ([k4-reorg-policy.md](docs/reviews/k4-reorg-policy.md)). "Park on deep reorg" is **planned** for a public testnet; it is not implemented and is off for the trial. The mainnet policy is open.
- **Operator override (node policy, not consensus).** `--invalidate-block` and `--reconsider-block` work like Bitcoin Core's `invalidateblock` ([blocks.md §8](docs/blocks.md)).

### Emission

`1 BLK = 10^8` atomic units; all amounts are `u64` (`chain/src/emission.rs`):

```
M = 21 000 000 BLK,  S = 20,  TAIL = 0.6 BLK
reward(0) = 0
reward(h) = max(TAIL, (M − G(h)) >> S)      G(h) = rewards of blocks 1..h−1 (fees excluded)
```

The reward depends on the height alone, so it is the same on every branch. The first reward is 20.02716064 BLK. The base term `(M − G(h)) >> 20` decays towards `M` = 21 M BLK, which it never reaches; once it falls below 0.6 BLK (block 3 678 315, about 20.37 M BLK emitted) the permanent tail of 0.6 BLK per block (157 680 BLK per year at 120 s blocks) takes over. The figures below are **computed from the formula**, not measured, at 262 800 blocks per year; the 1-year value, the 4-year value and the tail-start height are pinned by `curve_matches_spec`.

| Point | Value (computed) |
|---|---|
| After 1 year | about 4.66 M BLK (22.2 % of M) |
| After 4 years | about 13.29 M BLK (63.3 %) |
| Tail starts | block 3 678 315 (about 14.0 years), about 20.37 M BLK emitted |

**Why a tail** ([blocks.md §2](docs/blocks.md)): a fee-only security budget is volatile and invites fee sniping; with hidden amounts, supply integrity rests on balance and range proofs, not an auditable sum, so a hard cap adds no verifiable guarantee; the tail also offsets lost coins. **Why no premine:** the genesis body is empty by rule ([blocks.md §3](docs/blocks.md)).

### Block storage (node, not consensus)

Blocks are kept in `blocks.dat`, an append-only log of typed, CRC-checked records, format 3 (`chain/src/store.rs`, [blocks.md §8](docs/blocks.md)).

- **Network binding.** The file header binds the store to one network id and one genesis id. A store from another network or an older format is refused with advice to resync, never migrated. **Why:** an old testnet's store would otherwise be replayed into the new genesis and silently orphaned.
- **Durability.** A block record is written and flushed (`sync_data`) **before** the block is applied, so a crash cannot lose an applied block.
- **Damage.** A torn tail is truncated with a warning; damage followed by a valid record is treated as corruption and the node refuses to start. `--repair-store` moves the damaged region aside, keeps the operator's verdict records, and the node downloads the dropped blocks again.
- **Replay.** At start-up the node replays the store through the live code path, validates every body again, and recomputes a sample of the stored RandomX hashes (the 16 highest blocks plus 48 random heights, or all with `--verify-store-pow`); a mismatch refuses the store (exit status 66).
- **Known limitations** (accepted for a controlled testnet): every body and its undo data stays in memory; start-up re-validates every block and PX proof; there are no indexes and no pruning. A disk-backed store with checkpoints is **planned** (decisions "Agent 35"; [STATUS.md §6](docs/STATUS.md)).

## Proof of work and mining

> **Status: not yet activated.** Everything in this section is part of the v3 rule set.

BlackSilk uses **RandomX v1**. The only change from Monero's `rx/0` configuration is the Argon2 salt. RandomX is computed by one crate, `blacksilk-randomx` ([randomx/README.md](randomx/README.md)): the node uses it to verify blocks, the miner to search for them, and the wallet to check headers. The normative specification is [consensus.md §3](docs/consensus.md).

```
                     header (172 bytes, nonce at 164..172)
                                  │
       H32("mining-hash", LE32(network_id) ‖ header[0..164])
                                  │
   pow_blob (47 B) = "BSilk/1" ‖ mining_hash ‖ LE64(nonce)
                                  │
   key = id of block at seed_height(h)  ──►  RandomX v1, salt "BlackSilk/RandomX/v1"
                                  │
                       pow_hash  ──►  check_hash(pow_hash, difficulty)
```

| Component | What it does | Where |
|---|---|---|
| `blacksilk-randomx` | RandomX v1 in Rust: Argon2d cache fill, SuperscalarHash, dataset, VM interpreter, AES generators, software rounding modes | `randomx/` |
| `blacksilk-consensus` | Builds the mining blob, runs the key schedule (`seed_height`), checks the target (`check_hash`), header validation | `consensus/src/header.rs`, `consensus/src/pow.rs`, `consensus/src/chain.rs` |
| `blacksilk-chain` | Pooled PoW hashing for header and block validation, a PoW cache, the stored-PoW check at start-up | `chain/src/manager/` |
| `blacksilk-node` | Serves mining templates over the local RPC; RandomX self-test at start-up | `node/src/lib.rs`, [blocks.md §9](docs/blocks.md) |
| `blacksilk-miner` | Solo miner: builds blocks from templates, searches nonces, submits blocks | `miner/src/` |

### Algorithm and the BlackSilk salt (RX-SALT)

**What.** The RandomX cache for a key `K` is the Argon2d memory for password `K` and salt `"BlackSilk/RandomX/v1"` (20 ASCII bytes, no terminator). Every other RandomX v1 parameter is the reference default. Because the salt enters Argon2's `H0`, every cache, dataset and hash differs from `rx/0`. The reference salt is kept only so the official test vectors can run (`Variant::MoneroRx0`). Compile-time assertions in `randomx/src/config.rs` check that the salt is at least 8 bytes, contains no NUL byte and differs from the reference salt.

**Why.**
- **To separate BlackSilk from existing `rx/0` hash power.** Before this change, BlackSilk's PoW was byte for byte Monero's `rx/0`: stock xmrig, rented RandomX hash rate, `rx/0` aggregators and RandomX ASICs on stock firmware could all mine it unmodified. The RandomX designers recommend a unique salt per project and advise against changing other parameters.
- **Why only the salt.** Changing program, memory or Argon2 parameters moves away from the analysed parameter set and costs an attacker no more to port than a salt change.
- **Why not merge mining.** Merge mining with Monero needs an auxiliary-PoW header, makes validators build caches for keys Monero chooses, and links BlackSilk blocks to Monero pool identities, which has a privacy cost.
- Record: [v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md) `rx-salt`.

**Limits.** The salt is public and is not a security boundary; it only stops *zero-effort* redirection of hash power. Adding the salt to a JIT miner such as xmrig is a small patch (about five files in xmrig), and such a miner is estimated (not measured on BlackSilk hardware) to be roughly 50 to 100 times faster per core than the project's safe-Rust miner. Anyone who builds one, or rents generic CPUs, can out-mine the testnet and reorganize the chain, so K1 is nominal for a small chain ([STATUS.md §6](docs/STATUS.md); [testnet.md §12.6](docs/testnet.md)). The salt adds no ASIC resistance beyond what RandomX already provides.

### The mining blob

RandomX does not hash the 172-byte header. It hashes a fixed 47-byte blob:

| Bytes | Content |
|---|---|
| 0..7 | `"BSilk/1"` (ASCII tag, `POW_BLOB_TAG`) |
| 7..39 | `mining_hash = H32("mining-hash", LE32(network_id) ‖ header[0..164])`: every header field except the nonce |
| 39..47 | `LE64(nonce)` (`POW_NONCE_OFFSET = 39`) |

The block id is still the hash of the full header, nonce included. `PowFunction::pow_hash` takes a typed `PowBlob` (`[u8; 47]`), so code that passes raw header bytes fails to compile.

**Why.**
- **Compatibility with existing miners.** Stock xmrig writes its 4-byte RandomX nonce at byte 39 of the job blob, and the offset is compiled into xmrig per algorithm. With the nonce at byte 39, xmrig needs only a small patch adding an `rx/blacksilk` algorithm entry (the salt), not a change to its nonce handling ([xmrig-compatibility.md](docs/pow/xmrig-compatibility.md), historical research note). The xmrig compatibility gate tested this on regtest: real xmrig with only the salt patch mined blocks the node accepted (see [Third-party miners](#third-party-miners-xmrig)).
- **Room for a pool extranonce.** xmrig iterates bytes 39..43; a pool server could own bytes 43..47. `blacksilk-miner` iterates the whole `u64`.
- **Constant size.** The blob is fixed-length and derived by every node from the header, never transmitted, so it has no field a miner could vary to produce equal-work duplicates.
- **Commitment and network separation.** `mining_hash` commits to every field except the nonce and binds the network id, so work never carries across networks. Future header changes do not affect the blob layout miners see.

**Target check.** `pow_hash` is read as a 256-bit little-endian integer `h`; a block meets difficulty `d` iff `h × d < 2^256` (Monero's `check_hash`). Difficulty 0 is never satisfied.

### RandomX key (seed) schedule

The key is the id of an earlier block on the **same branch**. It changes once per epoch of `E = 2048` blocks with a lag of `L = 64` (Monero's `rx_seedheight`):

```
seed_height(h) = 0                              if h <= E + L
               = (h - L - 1) & !(E - 1)         otherwise
```

The first switch is at height 2113, then 4161, and so on, on every network.

**Why.** A cache costs about 256 MiB to build and a mining dataset about 2 GiB plus minutes, so a key per block would charge that on every block. An epoch of 2048 blocks (about 2.8 days at 120 s) still changes the key often. The lag announces the next key about two hours in advance, so a shallow reorganization cannot change the key under active miners.

**As implemented (policy, not consensus).** During the lag window `/template` carries `next_seed_id` so miners can prepare the next dataset; the template's `seed_id` is the only key a block is hashed with. The node keeps at most two "hot" keys' caches built (`HOT_SEEDS = 2`).

**Test coverage.** The schedule is pinned against Monero's formula (`seed_schedule_matches_monero`). Key switches are exercised with real RandomX only in short-epoch tests; a full-mode miner crossed the real first switch at height 2113 once, on one machine, on regtest ([rx-fullmode evidence](docs/evidence/rx-fullmode-seedswitch-2026-09-29/README.md)).

### Light mode and full mode

| | Node and wallet (verification) | Miner (search) |
|---|---|---|
| Mode | Light only | Full by default; `--light` selects light |
| Memory | 256 MiB cache per key | 2 GiB dataset plus about 0.3 GB; about 4.4 GiB peak with `--prebuild auto` |
| Per-hash time | 0.45 to 0.75 s per header (**measured**) | Full mode about 100 ms per hash per thread (**measured**, with the full test suite running at the same time) |
| Key-switch cost | A new cache | A new dataset: about 180 s with 8 threads, about 20 minutes with 1 thread (**measured**) |

Both modes produce identical hashes. The figures come from [testnet.md §12.1](docs/testnet.md), one development machine, and were measured before the interpreter rewrite; a benchmark of the rewritten interpreter is pending ([STATUS.md §3](docs/STATUS.md)).

### The `randomx/` crate: implementation and evidence

- A Rust port of tevador/RandomX that follows its specification; `#![forbid(unsafe_code)]`, no FFI, no C and **no JIT** (interpreter only, with SuperscalarHash programs decoded once per cache).
- RandomX switches the FPU rounding mode, which Rust cannot do soundly, so the crate emulates every rounding mode in software, intended to give bit-identical results on every platform.
- Dependencies: the RustCrypto `blake2` and `aes` crates; `argon2` only in tests, as an independent check of the cache fill. RandomX v2 is not implemented.

| Evidence | Scope | Source |
|---|---|---|
| Official vectors 1a–1f, with the reference salt | Light mode; full mode in CI job `randomx-full` | `randomx/src/self_test.rs`, [randomx/README.md](randomx/README.md) |
| Every word of the Argon2d cache compared with the RustCrypto `argon2` crate, under both salts | The salt-dependent stage only | `argon2_crate_fills_the_same_cache` |
| BlackSilk vectors bs-1a to bs-1f and the mining-blob known answer, reproduced by unmodified tevador/RandomX v1.2.3 with only the salt changed (freeze gate B4) | **Light mode only**; full mode not run against the reference | [randomx-reference evidence](docs/evidence/randomx-reference-2026-10-04/README.md) |
| Full mode reproduces light-mode results and agrees on random inputs | Ignored tests, CI on Linux | [randomx/README.md](randomx/README.md) |
| Differential tests of the rewritten interpreter (RT-RXINTERP) | 1a–1f and bs-1a to bs-1f | [STATUS.md §3](docs/STATUS.md) |

**Not covered:** the reference's instruction-level tests (including rounding-mode cases) are not ported; platforms other than x86_64 are untested; no mutation-testing run covers `randomx/`, RX-SALT or the mining blob yet ([STATUS.md §5](docs/STATUS.md)).

**Start-up self-test.** The node and the miner hash the reference vectors 1a–1f and BlackSilk's bs-1a to bs-1c in light mode at every start and exit with status 71 on a mismatch, because a build that computes RandomX differently would fork from the network. The miner also spot-checks every dataset against its cache (sampled items and one hash computed in both modes) before mining with it. `--randomx-self-test` runs the vectors on request (the miner's version adds full mode); `--skip-randomx-self-test` is for diagnosis only.

### Mining and the mining RPC

`blacksilk-miner` mines **solo** against a local node. BlackSilk has no pool or stratum server.

1. **Fetch a template.** `GET /template` returns the height, parent id, header version, difficulty, `seed_id`, minimum timestamp, reward, fees, transactions, the parent's output range, the block's `px_root`, and `next_seed_id` during the key-switch window. It answers `503` until the node has caught up, during a drain, and during an operator fork ([blocks.md §9.4](docs/blocks.md)).
2. **Build the block.** The miner builds the coinbase (a one-time stealth output to `--address`), appends its outputs to the output range, and fills in the header.
3. **Search.** The blob is computed once and each nonce is written at bytes 39..47 across `--threads` threads. Every template starts from a fresh random nonce, because a counter carried across templates would let observers group blocks, and so coinbase outputs, by miner. The search stops when the node's tip moves (a `GET /tip` long poll) or after `--refresh` seconds (default 15).
4. **Submit.** `POST /block`; the node re-validates the block from scratch.

**Key switches** (`--prebuild`; [testnet.md §5](docs/testnet.md)):

| `--prebuild` | Behaviour |
|---|---|
| `auto` (default) | Prebuilds the next dataset during the 64-block window; if the memory is not there, falls back to the light-mode bridge |
| `on` | Prebuilds without the fallback, and also in light mode |
| `off` | Frees the old dataset at the switch and mines in light mode until the new dataset is built |

Blocks are announced without delay, so the IP address of the mining node is not protected ([Networking](#header-first-synchronization-and-block-relay)).

### Third-party miners (xmrig)

| Item | Status |
|---|---|
| Blob layout compatible with xmrig's nonce offset | Implemented in consensus (above) |
| xmrig compatibility gate: a local xmrig build with an `rx/blacksilk` entry that changes **only the Argon2 salt**, driven by a minimal pure-Rust stratum bridge on regtest, mining blocks the node accepts | **Complete but requires further testing**: real xmrig v6.26.0 mined 2,133 regtest blocks the node accepted, in fast and light mode and across the first RandomX key switch; every xmrig result byte-equal to BlackSilk's own hash (offline recompute of every submission); invalid shares, a bad block and a negative control (Monero's salt) rejected; no consensus finding. One machine and CPU ([gate evidence](docs/evidence/xmrig-gate-2026-10-09/README.md); [xmrig-mining.md](docs/pow/xmrig-mining.md); [STATUS.md §5](docs/STATUS.md)) |
| Pure-Rust stratum server for external miners (decided as optional) | **Planned**, after the freeze (decisions "xmrig compatibility gate: before the freeze") |
| Pinned `rx/blacksilk` xmrig build for the testnet | **Planned**, after the freeze (decisions "xmrig compatibility gate: before the freeze") |
| Upstream xmrig pull request for `rx/blacksilk` | **Planned**; after the stratum server and a tested patch exist |

The compatibility gate is a test, not a mining product. xmrig is C++, so neither xmrig nor the test bridge becomes part of the node, the miner or the wallet. An earlier desk assessment (reading xmrig's source, no build) found that a BlackSilk salt configuration is a change to about five xmrig files, that xmrig would search only the low 32 bits of the nonce unless extended, and that xmrig's daemon mode cannot read a BlackSilk template; the gate then built and ran it (above). How to mine regtest with xmrig through the bridge, and xmrig's nonce fingerprint (its low 32 nonce bits count up from 0, so its blocks are distinguishable), are in [xmrig-mining.md](docs/pow/xmrig-mining.md).

### SKC-1: research only

SKC-1 was an owner proposal for a BlackSilk-native CPU proof of work. Two internal research reports and a fresh-context cross-check concluded "redesign required": its 32 MiB of memory per nonce fits in on-die ASIC SRAM, it repeats CryptoNight's pattern, its mixer and graph are unanalysed, and its nonce binding is unspecified; a redesign has insufficient evidence. RandomX stays. SKC-1 is **research** only, not implemented and not activated ([skc1-research.md](docs/pow/skc1-research.md); reports [A](docs/pow/skc1-research-a-crypto.md) and [B](docs/pow/skc1-research-b-hardware.md)).

## Transactions and cryptography

> **Status: not yet activated.** The v1 transaction layer (kinds 0 and 1) and the PX kinds (2 and 3) are implemented and have internal tests. The normative specification is [transactions.md](docs/transactions.md); where it and the code disagree, that is a bug.

The design starts from Monero's RingCT stack as Monero has run it since 2022 (CLSAG, Bulletproofs+, view tags). BlackSilk changes a small number of things on purpose; each change is marked **[Δ Monero]** in the specification with its reason, and all are listed in [transactions.md §14](docs/transactions.md).

### Transaction kinds

Every transaction starts with `version = 1` (varint) and a one-byte `kind`. Decoding is strict: per-kind size caps, bounded counts, canonical points and scalars, minimal varints, no trailing bytes. Every transaction therefore has exactly one valid encoding (`Transaction::decode`, `tx/src/types.rs`).

| Kind | Name | Contents | Size cap | Spec |
|---|---|---|---|---|
| 0 | Coinbase | block height, 1 to 16 stealth outputs with **clear** amounts | 100 000 bytes | [transactions.md §4.3](docs/transactions.md) |
| 1 | Transfer | 1 to 64 inputs (key image plus a ring of 16), 2 to 16 hidden outputs, fee, pseudo-outputs, one aggregated Bulletproofs+ proof, one CLSAG per input | 100 000 bytes | [transactions.md §4.2](docs/transactions.md) |
| 2 | PX transaction | optional v1 inputs and hidden outputs, clear payouts, bridge amounts, validity window, anchor, exactly 2 nullifiers, 2 commitments and 2 record ciphertexts, 0 to 2 function entries, one STARK proof | proof cap plus 256 KiB | [px.md §11.1](docs/px.md) |
| 3 | Private-contract deploy | a v1 transfer plus a salt and 1 to 16 program binaries with their budgets | 1 MiB | [px.md §11.2](docs/px.md) |

PX is covered in [its own section](#private-execution-px-zk-proofs-and-contracts). For any v1 inputs, kinds 2 and 3 apply the same rules as transfers (T4 to T11, C1 to C3).

**No `extra` field [Δ Monero].** No kind has `extra`, `unlock_time`, payment IDs or any optional field, Monero's largest wallet-fingerprinting sources. Some fields are still checked only for length (the encrypted per-output fields) or for length and a canonical, non-identity `R` (the 1,241-byte PX record ciphertexts); the rest of their bytes cannot be checked, and the spec requires every wallet to fill them with the specified encryption under fresh randomness ([transactions.md §4.1](docs/transactions.md)).

### Cryptographic primitives

| Primitive | Choice | Where |
|---|---|---|
| Group | **Ristretto255** (RFC 9496), a prime-order group over Curve25519 [Δ Monero] | `crypto/src/point.rs`; [transactions.md §1.1](docs/transactions.md) |
| Hash | **Blake2b** (256 and 512), always with a domain tag | `crypto/src/hash.rs`; [transactions.md §1.2](docs/transactions.md) |
| Hash to scalar `Hs` | Blake2b-512 reduced mod ℓ | `hash::hash_to_scalar` |
| Hash to group `Hp` | Ristretto element from 64 uniform bytes | `hash::hash_to_point` |
| Generators | `G` is the base point; `H` and the 2 × 1024 Bulletproofs+ generators come from `Hp`, so no one knows a discrete-log relation between them | `crypto/src/generators.rs`; [transactions.md §1.3](docs/transactions.md) |
| Commitments | Pedersen `Com(a, y) = y·G + a·H`, `a < 2^64` | `crypto/src/commitment.rs`; [transactions.md §1.4](docs/transactions.md) |
| PX hash `Hk` | Poseidon2 over BabyBear, width 16 (PX records and the PX tree only) | `px-core/src/hash.rs`; [px.md §2](docs/px.md) |

**Why Ristretto255 and not Ed25519.** Ed25519 has cofactor 8, and Monero has had to defend against small-order components; one result was the 2017 key-image bug, where adding a torsion point gave a new key image for the same output. Ristretto255 has prime order and one canonical encoding per element, so this class of bug cannot occur. Non-canonical points and scalars are rejected, never reduced. The cost is incompatibility with Monero wallets and test vectors ([transactions.md §1.1, §14](docs/transactions.md)).

**Domain separation.** Every hash input begins with `u8(len(tag)) ‖ tag`, where `tag` is `"BlackSilk/v1/" ‖ name`. All names are in `crypto::hash::tags`, and `tags_are_distinct_and_short` checks they are distinct. The module also keeps the tags of the frozen Wasm contract research (`contract/*`), which no consensus crate uses.

### Keys, addresses and one-time (stealth) outputs

A wallet holds two independent secret scalars derived from the seed's 32-byte `master`: the **spend key** `k_s = Hs("wallet/spend-key", master)` and the **view key** `k_v = Hs("wallet/view-key", master)`.

**Addresses [Δ Monero].** Every address, the primary one included, is a pair `(D, C) = (K_s + m·G, k_v·D)`, with `m = Hs("subaddress", k_v ‖ account ‖ index)` and `m = 0` for the primary address. One output format serves every recipient, so paying a subaddress is not publicly flagged as it is in Monero. Without `k_v`, two subaddresses cannot be linked (DDH). There are no payment IDs ([transactions.md §2.2](docs/transactions.md)).

**Output construction** ([transactions.md §3.2](docs/transactions.md), `crypto/src/stealth.rs`). Each output gets its own ephemeral key [Δ Monero]:

```text
ctx      = H32("input-context", key images of the tx)   (coinbase: H32(.../coinbase, height))
anchor   ← 16 hedged random bytes
r        = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)
R        = r·D                     published (per output)
S        = r·C  (= k_v·R)          shared secret
O        = Hs("output-key", S)·G + D            one-time key, published
view_tag = H32("view-tag", S)[0]                1 byte, published
Cm       = Hs("mask", S)·G + a·H                amount commitment, published
enc_amount = LE64(a) ⊕ H64("amount", S)[0..8]
enc_anchor = anchor  ⊕ H64("anchor", S)[0..16]
```

The recipient computes `S = k_v·R`; the view tag rejects about 255 of every 256 foreign outputs, and the subaddress table finds `D' = O − x·G`. The recipient then re-derives `r` from the decrypted anchor and accepts the output only if `r·D' = R`. This is the **Janus anchor** [Δ Monero]: it stops an adversary from linking two of a victim's subaddresses with a crafted output, and a wallet treats a failing output exactly like a foreign one ([transactions.md §12](docs/transactions.md)). Scanning needs only `k_v`. The anchor construction and its analysis are BlackSilk's own and have not been peer-reviewed ([transactions.md §12.8](docs/transactions.md)).

Two outputs in different transactions never share derivation inputs, because key images and coinbase heights are unique; with the anchor check this prevents Monero's 2018 "burning bug" at the recipient. The former chain-wide uniqueness rule on one-time keys (C4) was removed so a third party cannot invalidate a pending transaction by mining a copy of its output key first (decision D8, option B; [v3-consensus-changes.md §1](docs/reviews/v3-consensus-changes.md)).

### CLSAG ring signatures and key images

Each transfer input names exactly **16** ring members by global output index, in strictly increasing order; the ring size is fixed by consensus (`RING_SIZE`, `crypto/src/clsag.rs`) so every input looks the same. The signature is a CLSAG (Goodell, Noether and Blue, IACR ePrint 2019/654), built as in Monero without cofactor handling ([transactions.md §6.1](docs/transactions.md)).

- **Key image.** `I = p·Hp("key-image", O)`. The group has prime order, so each output has exactly one key image, and only the holder of `k_s` can compute it.
- **Double-spend prevention.** Consensus rejects a key image already spent on chain or earlier in the block (C2); the mempool rejects a conflicting one (first seen wins, no replace-by-fee).
- **Identity checks (v3 rule).** Verification rejects `I = identity` and an auxiliary image `D = identity`; a signer refuses `z = 0`, which would reveal the real input ([v3-consensus-changes.md §2](docs/reviews/v3-consensus-changes.md)).
- **What the signature covers.** Every byte except the CLSAGs themselves, plus a 40-byte domain `network_id ‖ branch_id ‖ genesis_id`, so a signature is valid on one network, in one epoch and on one chain (RT-14, [v3-consensus-changes.md §3](docs/reviews/v3-consensus-changes.md)).
- **Hedged nonces.** CLSAG nonces come from a stream keyed with the secrets and bound to the whole signed statement, so a broken OS RNG does not cause nonce reuse ([transactions.md §10](docs/transactions.md)).

### Pedersen commitments and Bulletproofs+

A transfer balances through pseudo-outputs:

```text
Σ C'_k  =  Σ Cm_j + fee·H          (rule T9; C'_k = pseudo-output of input k)
```

Each input's CLSAG proves that `Cm_π − C'_k` commits to zero, so each pseudo-output commits to the real input's amount without revealing which ring member is real. One aggregated **Bulletproofs+** proof (Chung et al., IACR ePrint 2020/735) shows every output amount is in `[0, 2^64)`, for up to 16 outputs. Every Fiat–Shamir challenge hashes the complete statement and all earlier prover messages, which avoids the "weak Fiat–Shamir" (Frozen Heart) class of forgeries. Nodes batch-verify a block's proofs with independent random 128-bit weights ([transactions.md §7](docs/transactions.md)). A coinbase output's commitment is defined as `1·G + a·H` from the clear amount, so coinbase outputs can serve as ring members.

The in-module naive BP+ verifier shares the challenge code, so it is not an independent check. An independent verifier is decided but not implemented ([STATUS.md §3.1](docs/STATUS.md)).

### Fees

Fees are public and depend only on public data. This is a consensus rule, so no wallet can fingerprint itself through its fee:

| Kind | Fee rule | Source |
|---|---|---|
| Transfer | **exactly** `standard_fee(n, k) = FEE_PER_WEIGHT × max_weight(n, k)`, `FEE_PER_WEIGHT = 20` atomic units; `max_weight` is the weight of the transaction's shape with every varint at its maximum | T8; record `exact-v1-fee` |
| PX transaction | **exactly** `PX_STANDARD_FEE`, the per-byte fee of the largest possible PX transaction | [px.md §11.3](docs/px.md) |
| Deploy | exactly the standard fee of its transfer part, plus 50 atomic units per payload byte | [px.md §11.3](docs/px.md) |

There is no priority fee; congestion is handled by mempool policy. All `max_weight` values are pinned in `tx/tests/data/max_weight.txt`, generated by the independent script `tools/vectors/max_weight.py`. Example from the spec: a 1-input, 2-output transfer has `max_weight` 1 723 and pays 34 460 atomic units ([transactions.md §8.4](docs/transactions.md)). Outputs are sorted by one-time key, so their order reveals nothing, including which one is the change.

### Decoy selection (wallet policy, not consensus)

The wallet (`tx/src/decoy.rs`) uses Monero's gamma age distribution, `exp(Gamma(19.28, 1/1.61))` seconds shifted by the 10-block lock, and picks a uniform eligible output inside the drawn block or a bounded neighbourhood. Rings are built **from the wallet's own output index**: no spend path asks the node for `/distribution` or for outputs per ring, so the node cannot learn the real input from the request or skew the decoy ages (D1; [transactions.md §11.3.1](docs/transactions.md); test `rings_do_not_depend_on_the_nodes_distribution`). The gamma parameters are Monero's, fitted to Monero's spend data, because no BlackSilk spend data exist. The decoy draws use the OS RNG, not the hedged stream (F38-5, not implemented).

### Cryptographic dependencies

All are pure-Rust crates pinned in `Cargo.lock`; they contain `unsafe` internally. Their review status, internal only, is in [dependency-review.md](docs/reviews/dependency-review.md) §2.

| Crate | Version | Used for |
|---|---|---|
| `curve25519-dalek` | 4.1.3 | Ristretto255: stealth outputs, CLSAG, Bulletproofs+, PX delivery |
| `blake2` | 0.10.6 | every tagged hash |
| `subtle`, `zeroize` | 2.6.1, 1.8.1 | constant-time selection; wiping secrets (best effort) |
| `ml-kem` | 0.3.2 | ML-KEM-768 half of the hybrid PX record delivery (pre-1.0; no external review known) |
| `chacha20poly1305` | 0.10.1 | PX record encryption, fresh key per ciphertext |
| `aes-gcm`, `argon2` | 0.10.3, 0.5.3 | P2P transport and wallet-file encryption |

The crypto crate takes its RNG as an explicit parameter. Secret-dependent arithmetic uses dalek's constant-time operations; variable-time multi-scalar multiplication runs only on public data (`crypto/src/lib.rs`). BlackSilk-specific vectors are pinned in [crypto/tests/vectors/](crypto/tests/vectors/). Monero's vectors do not apply because of the group change, and a Monero CLSAG conformance harness is decided but not implemented ([STATUS.md §3.1](docs/STATUS.md)).

## Privacy model

This section gathers what is hidden, what is public, and the known limits. The full PX analysis is [privacy-review.md](docs/reviews/privacy-review.md) (an internal review).

| Hidden | Mechanism | Against whom |
|---|---|---|
| Which ring member is spent (v1) | CLSAG, 1 of 16 | any observer (DDH); statistical limits below |
| Recipient and links between their outputs | one-time keys, a separate `R` per output | anyone without the recipient's view key (DDH) |
| Links between subaddresses | `C = k_v·D`, Janus anchor | anyone without `k_v` |
| Amounts (v1) | Pedersen commitments (hiding without any assumption), encrypted amounts | commitments: everyone; encrypted amounts: anyone without `S` |
| Change position | consensus-sorted outputs | everyone |
| Which PX record is spent; record contents; contract-function inputs and control flow | nullifiers, commitments, hybrid-encrypted records, the STARK proof | anyone without the record's keys; function inputs and control flow are hidden within the public, registered budgets ([zkvm.md §8](docs/zkvm.md)); zero knowledge is **statistical and conditional (computational in practice)** |

| Public | Notes |
|---|---|
| Ring members, key images, input and output counts, transaction size, fee | Ring members also reveal output-age statistics |
| When a transaction appears, and transaction-graph timing | On chain in the clear |
| Coinbase amounts | The miner's address is not public (one-time keys) |
| PX: the kind of operation, `bridge_in`, `bridge_out`, payouts, fee, nullifiers, anchor, validity window, and for each called function its contract id, program id and public output words | [privacy-review.md §1, §2.1](docs/reviews/privacy-review.md); [px.md §11](docs/px.md). Deposit and withdrawal amounts are public |
| The node's network origin | Hidden only as far as the P2P layer hides it ([Networking](#networking)) |

**Known limits.**

- **Ring signatures give statistical anonymity, and it degrades under analysis.** On a mature chain a real input spent 12 blocks after it was received is the newest ring member in about 84–89 % of rings (a simulation estimate, `guess_newest_success_on_a_mature_chain` in `tx/tests/decoy_statistics.rs`). Other weaknesses: Eve–Alice–Eve, rings rebuilt after a reorganization (which narrows the real input to the intersection), and visible consolidations ([transactions.md §11.3](docs/transactions.md)). Only waiting before spending helps.
- **Network-layer privacy is limited.** Dandelion++ protects against spy nodes only. Frames are not padded, so an observer of a node's own link (ISP or Tor guard) can tell when the node originates a transaction, v1 or PX; a PX transaction (about 2.4 MB or more) is unmistakable even over Tor. Block origin is not protected, and a node is recognizable by its handshake. Tor is optional: outbound through SOCKS5, and inbound through an operator-run hidden service that forwards to the onion listener (`--onion-inbound`); there is no I2P ([Networking](#networking); [testnet.md §12.7](docs/testnet.md)).
- **The wallet trusts its node with metadata.** The wallet has no Tor or SOCKS support and talks plaintext HTTP to its node; a node the user does not control learns the wallet's IP address, sync times and submissions ([Wallets](#the-node-rpc-from-the-wallet)). Use your own node.
- **Small anonymity sets on a trial network.** A trial can show function and liveness, not privacy ([STATUS.md §6](docs/STATUS.md)).
- **Not post-quantum.** No part of the v1 layer resists a quantum adversary, who could forge spends and link key images to outputs after the fact ("harvest now, deanonymize later"); amounts to unknown addresses stay hidden ([transactions.md §11.6](docs/transactions.md)). PX ownership and proofs are hash-based, but their quantum security is not quantified, and the v1 side of the PX bridge is exposed like the rest of v1 ([zk.md §9.3](docs/zk.md)). The PX record delivery is hybrid with ML-KEM-768, which covers record confidentiality only. No post-quantum security is claimed; post-quantum privacy is a **research** track with no design or code in the tree (the earlier signature research crate was removed on 2026-10-05 and stays in the git history).

## Networking

> **Status: experimental.** The P2P layer (`blacksilk-p2p`, `p2p/`) is implemented and wired into the node. It is not consensus: nodes agree on validity only through the consensus rules, and the network only moves data. None of the mechanisms below has run against a live adversary. The full specification is [p2p.md](docs/p2p.md).

Every protocol rule does one of three things: move data reliably, keep a node available under attack, or leak as little as possible about who sends what ([p2p.md §1](docs/p2p.md)).

```
           TCP (direct, or SOCKS5 proxy such as Tor)
                          │
              ┌───────────▼────────────┐
              │ transport.rs           │  Ristretto255 key exchange, AES-256-GCM frames
              └───────────┬────────────┘
              ┌───────────▼────────────┐
              │ message.rs             │  strict, bounded codec (15 message types)
              └───────────┬────────────┘
        read loop (never waits for the chain) ── per-peer slow lane (chain queries, tx relay)
              │                │                 │
   header worker        block worker      admission / Dandelion++ / trickle
   (PoW-checked sync)   (one at a time)   (stem.rs, trickle.rs, tx_requests.rs)
              └───────────┬────┴─────────────────┘
              ┌───────────▼────────────┐
              │ chain actor (chain/)   │  sole writer of chain state; decides validity
              └────────────────────────┘
   addrman.rs + addrman_gate.rs + connman.rs: which peers to dial, keep or evict
   limits.rs: token buckets and misbehaviour scores applied throughout
```

The network layer never decides validity; it hands headers, bodies and transactions to the [chain actor](#the-chain-manager-and-the-chain-actor). A read loop never waits for chain work, so pings keep being answered during a long block connection or reorganization ([p2p.md §10](docs/p2p.md)).

### Encrypted transport (unauthenticated)

Right after the TCP connect, each side sends a 32-byte ephemeral Ristretto255 public key; there are no magic bytes and no version in the clear. The session key is derived with BLAKE2b over the network id, the genesis id, the transport version, an optional pre-shared key, both public keys and the shared point, and split into one AES-256-GCM key per direction with a counter nonce ([p2p/src/transport.rs](p2p/src/transport.rs); [p2p.md §3](docs/p2p.md)).

- **Network separation without a marker.** A node of another network, genesis or transport version derives different keys, so the first frame fails to decrypt (decision "Agent 30").
- **Decryption failures close the connection but are never scored.** Anyone on the path can flip a bit, and a ban would let that party separate two honest nodes.
- **What it protects:** message contents from passive observers; ephemeral keys protect a finished session against later compromise.
- **What it does not protect:** peers are not authenticated, so an active man in the middle can read, drop and eclipse a link; a closed network can close this gap with an optional pre-shared key (`--network-psk-file`), never required on a public network (`p2p/tests/transport_adversarial.rs`). Frames are not padded ([Privacy model](#privacy-model)). There is no rekeying and no post-quantum step; the handshake is recognizable, and censorship resistance is not a goal of this version.
- **Transport v2** (uniform key encoding, hybrid ML-KEM-768, padding, rekeying) is **planned**; only design notes exist ([p2p.md §3.1](docs/p2p.md)).

### Handshake and messages

Both sides send `Version` and answer with `Verack`. `Version` carries the protocol version (3), the network id, a nonce for detecting self-connections, best-header hints (not trusted), an optional own address and `relay_txs`. It deliberately has **no user agent, no timestamp and no service bits**, because each would fingerprint the software or the clock ([p2p.md §4](docs/p2p.md)). Before `Verack` the peer has no budget: frames are at most 4096 bytes, at most 8 unknown frames are allowed, and the key exchange must finish within 5 s (10 s over Tor) and the handshake within 20 s. Nothing is scored before registration, because the peer's address may be a proxy's.

| Type | Message | Limit |
|---|---|---|
| 0, 1 | `Version`, `Verack` | handshake frames ≤ 4096 bytes |
| 2, 3 | `Ping`, `Pong` | a `Pong` must answer our ping |
| 4, 5 | `GetAddr`, `Addr` | ≤ 1000 entries; each address ≤ 512 bytes |
| 6, 7 | `GetHeaders`, `Headers` | locator ≤ 64; ≤ 2000 headers |
| 8, 9, 10 | `GetBlocks`, `Block`, `NotFound` | ≤ 128 ids; block ≤ `MAX_BLOCK_BYTES` |
| 11, 12 | `InvTx`, `GetTx` | ≤ 500 ids |
| 13, 14 | `Tx`, `StemTx` | the size cap of the transaction's kind |

Every list is bounded before allocation, and the frame length is checked as soon as it decrypts. Unknown message types are ignored without penalty (but rate-counted), so a later version can add messages; a malformed message of a known type is a violation ([p2p.md §5](docs/p2p.md)).

### Header-first synchronization and block relay

1. **Request.** A node asks a peer for headers if the peer claims a greater height **or** names a tip the node cannot place on its own best chain, because fork choice is by work, not height.
2. **Cheap checks first.** A single header worker checks every rule except PoW for the whole batch, then computes RandomX hashes in parallel chunks.
3. **Work gate.** A batch is hashed only if its claimed work reaches the best chain's work 144 blocks below the tip, or if it is a full batch of comparable work density. **Why:** once difficulty is driven down, valid low-work headers cost an attacker nothing but about 0.5 s of light-mode RandomX each to verify.
4. **Header PoW budget.** Untrusted inbound batches draw on a per-network-class token bucket, refunded when the PoW is valid ([p2p/src/net/header_budget.rs](p2p/src/net/header_budget.rs)). **Why:** onion peers cannot be banned. The queueing figures in [p2p.md §6](docs/p2p.md) are **measured** in scaled-down tests; the wait an untrusted peer has under a flood is **modelled**.
5. **Bodies.** At most 16 blocks and 32 MiB in flight per peer; a request unanswered within 60 s is reassigned without penalty.
6. **Announcement.** A new tip is announced to every peer not known to have it as soon as the chain publishes it. Blocks get no random delay, so **block origin is not protected**: jitter large enough to hide it would raise the stale rate, which favours large miners. There is no compact-block relay.

### Transaction relay: Dandelion++ and the trickle

```
 origin ──StemTx──► relayer ──StemTx──► relayer ──► diffuser ──InvTx (trickled)──► all peers
          (fixed per-epoch route; each hop fluffs with probability 0.2)
 embargo timer at every stem hop: 10 s + Exp(mean 39 s); if it fires first, that node fluffs
```

- **Stem phase** ([p2p/src/dandelion.rs](p2p/src/dandelion.rs); [p2p.md §8](docs/p2p.md)). Epochs last 9 to 11 minutes; a node picks 2 outbound stem peers and maps itself and each inbound peer to one of them, so routes stay fixed per epoch, which defeats the intersection attacks on the original Dandelion. The parameters follow Fanti et al. (SIGMETRICS 2018) and Monero PR #7025, have not been re-tuned for this network, and are **experimental**.
- **Stempool.** Stem transactions are never announced, served or mined, and an `InvTx` for one is answered exactly like one for an unknown transaction.
- **Embargo.** If a stem transaction has not come back fluffed when its timer fires, the node fluffs it itself, guaranteeing delivery past a malicious stem peer. The node's own transaction is **held** until an outbound stem peer exists.
- **Originated set** ([p2p.md §8.1](docs/p2p.md)). Ids of locally originated transactions are persisted to an owner-only (0600 on Unix) `originated.json` before they leave the node, so a wallet resubmission is held instead of originated again. **Why:** a re-origination would name the origin to a spy with near certainty (decision "Agent 33"). Known limitation: `originated.json` is a plaintext list of the node's own transaction ids ([STATUS.md §3](docs/STATUS.md), TM2-P2).
- **Fluff phase: the trickle** ([p2p.md §7](docs/p2p.md)). Announcements are batched in random order. Each outbound peer has its own exponential timer (mean 2 s); inbound peers share **one Poisson timer per network identity** (mean 5 s), so a spy opening many inbound connections does not get many independent delays.
- **Serving.** A node serves `GetTx` only for transactions it has already announced to that peer and answers everything else with the same `NotFound`.
- **Limits** ([p2p.md §8](docs/p2p.md)): Dandelion++ gives statistical origin privacy against spy nodes, not against an observer of the node's own link; a spy can make stems fail; a local re-stem and a separate PX embargo are **planned**. The privacy regression suite `p2p/tests/privacy.rs` gates relay changes; two properties remain open as ignored, failing tests (the slow-lane timing oracle TM2-P6 and the stem black hole X1). The suite tests properties; it does not show that origins are protected.

### Peer discovery and the address manager

- **Address tables** ([p2p/src/addrman.rs](p2p/src/addrman.rs), after Bitcoin Core's). A *new* table (256 × 64) and a *tried* table (64 × 64) with keyed-hash placement, per-source-group caps, test-before-evict, and a *tried* bias set from the eclipse simulator (decision "W3-32c").
- **Admission.** An unsolicited `Addr` of more than 10 entries is dropped and scored (after Heilman et al., USENIX Security 2015); small ones are rate limited; relay of an address does not depend on whether it was new, so a spy cannot probe the table.
- **`GetAddr` is answered only to inbound peers**, once per connection, with at most 23 % of the table (but at least 8 addresses, or all of a smaller table) and time 0. **Why:** answering outbound requests would let a peer plant unique addresses and link the node's sessions across IPs or Tor circuits (Biryukov and Pustogarov, IEEE S&P 2015).
- **Own address.** Advertised only with `--public-address`; an onion address only over Tor, a clearnet address only over clearnet.
- **Outbound.** 8 full-relay and 2 block-relay-only connections, at most one per network group; block-relay-only links are saved as anchors at shutdown; feelers about every 2 minutes; stale-tip rotation by delivered tips, never by claimed height. Seeds are one-shot address fetches. The built-in seed lists are empty until a launch.
- **Inbound.** At most 64 connections, at most 2 per IPv4 address or IPv6 /64; eviction protects peers by keyed group, ping and recent useful delivery.
- **Eclipse resistance is limited.** The eclipse simulator (`p2p/tests/eclipse_sim.rs`) is a **modelled** regression metric: in its small-network scenario a fresh node with an empty *tried* table still gives an attacker about 61 % of its outbound slots. **None of these mitigations has been tested against a real Sybil attack**; the lab network runs on one machine with grouping, per-IP limits and bans turned off ([p2p.md §12](docs/p2p.md)). Chain-sync eviction, staller disconnection, asmap and a minimum-chain-work headers presync are **planned**. For the testnet, the practical defences are manual `--peer` links to known operators, anchors, independent seeds and monitoring.

### Misbehaviour scoring, bans and DoS bounds

At a score of **100** a peer is disconnected and its IP (an IPv6 /64) banned for 24 h; proxied and onion peers are only disconnected ([p2p/src/limits.rs](p2p/src/limits.rs), [p2p/src/net/peers.rs](p2p/src/net/peers.rs)).

| Violation | Score |
|---|---|
| Oversized frame, malformed message, invalid header PoW or rules, invalid block body | 100 |
| Headers that do not connect; transaction invalid by a stateless rule | 20 |
| Unrequested block, transaction or multi-header batch; unsolicited large `Addr` | 10 |
| Each message over the rate limit | 1 |

Events honest peers can trigger are **not** penalized: decryption failures, anything before `Verack`, future-time rejections, headers descending from an invalid body, transactions invalid only against this node's state, relay over a budget, timeouts and `NotFound`. **Why:** honest peers can trigger each of these. In the lab network, penalties for contextual transaction errors and `GetTx` timeouts banned honest nodes ([AUDIT.md](AUDIT.md) R6, a historical internal findings log); the others were found in review.

| Bucket (`PeerLimits::default`; node-wide PX bucket in `p2p/src/net.rs`) | Rate | Burst |
|---|---|---|
| Messages | 50 per second | 500 |
| Bytes | 4 MB per second (answers to our own requests exempt) | 16 MB |
| Stem transactions (each `InvTx` id costs 0.1) | 20 per second | 100 |
| v1 inputs (ring signatures) | 50 per second | 500 |
| PX and deploy transactions, per peer | 0.2 per second | 4 |
| PX and deploy transactions, node-wide | 2 per second | 10 |

A relayed transaction is admitted cheapest check first; a malformed PX proof never takes the node-wide PX token. Each peer has three bounded outboxes (control, transaction answers, blocks), so a pong never waits behind bulk data.

### Tor and proxies

- **`--proxy`** sends outbound connections through SOCKS5 (no authentication); onion names are resolved by the proxy, never by local DNS ([p2p/src/socks5.rs](p2p/src/socks5.rs)).
- **`--proxy-only`** routes every connection through the proxy, with no local DNS and no clearnet listener unless one is bound. It still dials clearnet addresses through Tor exits, which can read and alter the unauthenticated link.
- **Inbound over Tor** uses a hidden service forwarded to a dedicated `--onion-inbound` loopback listener, not the P2P port; otherwise all onion peers share one loopback address's limits and bans. Onion peers there are never IP-banned and are capped as a class ([p2p.md §11](docs/p2p.md); `deploy/config/testnet-tor.toml`).
- **Open limits:** `--proxy` without `--proxy-only` is dual-homed, so one address table and mempool serve both identities and a spy can link them; there is no SOCKS stream isolation; onion-only outbound is **planned**, not implemented; I2P is not implemented.

### Privacy of logs

At `info` level the P2P layer names peers by a local numeric id; IP addresses and onion names are logged only at `debug`. A transaction this node originated never appears by id in any log line ("a local tx"), though that placeholder still shows *that* and *when* the node originated one. `debug` logs, `originated.json`, `peers.json`, `anchors.json` and `bans.json` are private and must not be shared ([testnet.md §7](docs/testnet.md)).

## Wallets

> **Status: not yet activated.** The wallet implements the v3 rule set. Because the testnet and mainnet genesis blocks are not final, **only regtest wallets can be created or restored today** (`wallet/src/wallet/keys.rs`).

`blacksilk-wallet` is a command-line wallet and library (`wallet/`). It holds one seed and derives two key families: **v1** keys for CLSAG transfers and a **PX** account for private records. It does not run a node: it talks to a `blacksilk-node` over the node's local RPC, downloads whole blocks, checks them itself, and builds and proves every transaction locally. The normative formats are in [blocks.md §10](docs/blocks.md); key derivations in [transactions.md §2](docs/transactions.md) and [px.md §3.1](docs/px.md).

```
 27 seed words ──► master = H32("seed/master/v1", version ‖ network ‖ features ‖ entropy)
                      │
          ┌───────────┴─────────────────────────┐
     v1 keys (transactions.md §2.1)       PX root (px.md §3.1)
     k_s, k_v ──► subaddresses (D, C)     hardened account 0 ──► ranges ──► PX addresses
          │                                     │
   scan v1 outputs, build CLSAG rings     trial-decrypt PX outputs, build own PX tree
          └──────────────┬──────────────────────┘
                 wallet file (Argon2id + AES-256-GCM)
                         │  plain HTTP + cookie
                    blacksilk-node RPC (/blocks, /headers, /tx, ...)
```

### Seed and key derivation

A seed is 27 words from the BIP-39 English list; only the list is shared with BIP-39, not the format, checksum or derivation. The words encode 256 bits of OS-CSPRNG entropy, a version (1), a network code, a 10-bit birthday and two feature bits. Two Reed–Solomon check words over GF(2^11) detect any one or two wrong words, including a swap ([blocks.md §10](docs/blocks.md); `wallet/src/seed.rs`).

- **v1 keys** are hashes of `master` under separate domains ([Keys and addresses](#keys-addresses-and-one-time-stealth-outputs)).
- **PX keys (Derivation V2).** A PX root derived from `master`; account 0 is a hardened child; addresses are grouped in ranges of 2^16, each with its own diversifier key and incoming viewing key, from which delivery keys derive ([px.md §3.1](docs/px.md)). The former 24-word seed and wallet files of versions 1 and 2 were removed at the v3 reset; the wallet no longer uses the former flat derivation (it remains in the px library; its removal is open).

**Why.** The network enters `master`, so one seed gives unrelated keys on each network, and a seed is refused on another network. Any version other than 1 is refused, so a wallet never guesses a derivation. The birthday only sets where scanning starts. The wallet names the position of a single wrong word but never applies a correction itself, because two wrong words can look like a different single one (decision "W2-37"). 27 words is not a BIP-39 length, so neither kind of wallet accepts the other's phrases. Hardened accounts and per-range keys let a range be disclosed for viewing without the spend secret. Vectors: [wallet/tests/data/seed_v1_vectors.txt](wallet/tests/data/seed_v1_vectors.txt), generated by the independent script [tools/vectors/seed_v1.py](tools/vectors/seed_v1.py).

**Limits.** No passphrase (feature bit 0 is reserved). The wallet uses PX account 0 and range 0 only. Open seed-format items are in [STATUS.md §3](docs/STATUS.md).

### Wallet file: encryption at rest

```
"BSW1" ‖ LE32 m_kib ‖ LE32 t ‖ LE32 p ‖ salt (16) ‖ nonce (12) ‖ AES-256-GCM ciphertext
key = Argon2id(password, salt; default m_kib = 65536, t = 3, p = 1)
```

- The header is authenticated as associated data; salt and nonce are fresh on every save. The plaintext (JSON, format version 3) holds the seed entropy, scan state, the wallet's own PX tree, stored transactions and their rings, and contract records.
- Files are replaced atomically. On Unix the file and its `.lock` are owner-only (0600) and a too-open file is tightened; on Windows the file inherits its directory's ACL. An exclusive lock is held for the whole command.
- An empty password is refused; one shorter than 12 characters is accepted with a warning. Absurd KDF parameters in a tampered header are refused before key derivation.

**Why.** A copy of the file (in a synced folder or a backup) must not give the funds away without the password; storing the KDF parameters in the header lets them be raised later.

**Limits.** Encryption at rest protects a copied file, not a running wallet, and a weak password still falls to an offline search. `BLACKSILK_WALLET_PASSWORD` (for automation) can be read by other processes of the same user. **The 27 words do not recover everything:** stored rings of pending spends and contract records created for others live only in the wallet file, so back up the file as well. The **old experimental wallet files in git history** (plaintext files with BIP-39 mnemonics and private keys, committed early in the project) are permanently compromised; history is not rewritten, and none of those keys or phrases may be reused on any network (owner decision 2026-10-04, "Old wallet files in published history" in [decisions.md](docs/reviews/phase2-2026-09-27/decisions.md)).

### Scanning and what the wallet checks of its node

The wallet scans whole blocks: one scalar multiplication per v1 output, a view-tag filter, the Janus-anchor check and the commitment opening; for PX outputs it trial-decrypts and accepts a record only if it recomputes the on-chain commitment ([px.md §6](docs/px.md)). Each block is decoded strictly, its id and `tx_root` recomputed, and its link checked. The wallet builds the PX commitment tree itself and anchors its PX transactions at a root it computed. The header chain is checked from genesis on the first sync of a restored wallet, and at every sync with `--verify-headers`: version, height, link, LWMA difficulty and timestamp of each header, and light-mode RandomX for the node's last 720 headers, the first scanned header and a random sample (`wallet/src/headers.rs`). The wallet warns when the synced tip is old by the local clock and refuses to build transactions after 60 target block times plus the future time limit, unless run with `--allow-stale-tip`.

**Why.** A node that hides a spend from a restored wallet could make it spend the same output again with a different ring, and the two rings would reveal the real input; these checks bound what such a node can do (F39-10).

**Limits.** F39-10 is bounded, not closed: a node that mines its own chain from genesis under the difficulty rule passes every check, and routine syncs without `--verify-headers` do not check PoW ([blocks.md §10](docs/blocks.md)).

### Building transactions

- **Rings come from the wallet's own output index** (`wallet/src/index.rs`); outputs below the restore height are fetched once, as the whole range, and checked against the synced header's `output_count` and `output_root`. Decoy selection is described under [Decoy selection](#decoy-selection-wallet-policy-not-consensus).
- **Merge avoidance.** Input selection first takes at most one output per source transaction and warns if it must fall back.
- **Hedged randomness.** Transfer anchors and pseudo-output masks come from a stream hedged with a key derived from the spend key.
- **Pending transactions** are stored and never rebuilt. The wallet asks `/tx/status` about them every 20 blocks, never re-posts to probe, and re-sends at most once, after the network expiry window ([px.md §12](docs/px.md)).

**Why.** Per-ring `/outputs` requests let a node intersect them with rings on chain; a spend-time `/distribution` request told the node a spend was being built; a re-post marks the wallet's node as the origin. **Planned** (decided, not implemented): a young-spend warning, an opt-in spend delay and a decoy RNG keyed with the hedge key ([STATUS.md §3.1](docs/STATUS.md)).

### The node RPC from the wallet

The wallet uses `/info`, `/blocks`, `/headers`, `/outputs` (backfill only), `/px/commitments` and `/px/contracts` (below the restore height, once), `/tx` and `/tx/status` (`wallet/src/node.rs`). The client speaks **plain HTTP only** (it refuses `https://`), ignores proxy environment variables, follows no redirects, caps every response, and sends the node's RPC cookie. A node the user does not control learns the wallet's IP address, sync times, scan start (approximating the birthday), pending transaction ids and submissions; it does not learn from scanning which outputs or records are the wallet's ([blocks.md §9.3](docs/blocks.md)). The wallet has **no Tor or SOCKS support** (wallet SOCKS5 is decided, not implemented). **Use your own node**, or reach one over an SSH tunnel, a VPN or a local Tor forwarder.

### PX wallet functions

The PX commands are `px-address`, `px-balance`, `px-deposit`, `px-send` and `px-withdraw`, plus `px-deploy`, `px-contracts`, `px-records`, `px-share`, `px-import` and the demonstration vault (`px-vault-lock`, `-claim`, `-refund`, `-recover`, `-secret`) ([px.md §11.4, §13.4](docs/px.md); [contracts.md §8](docs/contracts.md)).

**Record delivery.** Every PX output carries its record encrypted to the recipient: a Ristretto255 ephemeral key, a one-byte view tag, an ML-KEM-768 ciphertext and a ChaCha20-Poly1305 body. The key combiner hashes both shared secrets, both ciphertexts, both recipient public keys and the record commitment, so reading a record requires breaking both the discrete logarithm in Ristretto255 and ML-KEM-768 (`px/src/delivery.rs`; [px.md §6](docs/px.md)). The combiner follows the binding pattern of hybrid KEM combiners but is **not X-Wing**, and X-Wing's security argument does not carry over as is.

### View keys and disclosure

The crypto library supports view-only scanning from `(k_v, K_s)`, and PX has `RangeViewKey` and `IncomingViewKey` as a **library API** ([transactions.md §11.5](docs/transactions.md), [px.md §3.1](docs/px.md)). **There is no view-only mode in the CLI**: no view-key export and no watch-only wallet, for either key family. An address-scoped incoming viewing package is **planned**.

### Network and build guards

A wallet file records its network and genesis id, and the wallet refuses a node whose genesis differs. A wallet binary built with test-only code works only on regtest, and `--require-clean-build` refuses such a binary everywhere.

## Private execution (PX), ZK proofs and contracts

> **Status: not yet activated; experimental.** PX transactions (kind 2) and private-contract deploys (kind 3) are consensus rules **from genesis** in the v3 rule set. Nothing in this section has had external review. Zero knowledge is claimed only as **statistical and conditional (computational in practice)**.

PX is BlackSilk's second value layer. Value in PX lives in **private records**. A PX transaction spends two records and creates two; it publishes two nullifiers, two new commitments, a recent tree root (the anchor), the public bridge amounts to and from v1, and **one STARK proof** that a fixed RISC-V program, the **transfer kernel**, accepted a private witness. Private contract functions run in the same proof. Normative specifications: [px.md](docs/px.md) (records, kernel, consensus rules), [zkvm.md](docs/zkvm.md) (the VM), [proof-system.md](docs/proof-system.md) (proof format and verifier rules), [zk.md](docs/zk.md) (architecture and parameters) and [contracts.md](docs/contracts.md).

```
 user device                                             node (consensus)
 ───────────                                             ────────────────
 witness: keys, records, paths, secrets                  PX1  anchor in the last 100 roots
      │                                                  PX2  nullifiers never seen before
      ▼                                                  PX3  every function registered
 kernel  (execution 0, pinned px/kernel.elf)             PX4  pool stays ≥ 0
 function 1, function 2  (registered programs)  ──►      PX5  proof verifies (decode, shape, verify)
      │      BVM-1 zkVM, one p3-batch-stark proof        PX6  block height inside the window
      ▼                                                       │
 PX transaction (kind 2): nullifiers, commitments,            ▼
 ciphertexts, bridge amounts, window, proof, h_tx        append commitments, record nullifiers,
                                                         update the pool; root becomes px_root
```

### Records, nullifiers and the commitment tree

`Hk` is a sponge over Poseidon2 (BabyBear, width 16, standard constants), the same permutation the proof system uses for its Merkle trees and transcript. With a spend secret `sk`:

```
nk = Hk(NK, sk)    ak = Hk(AK, sk)    owner_i = Hk(OWNER, ak ‖ nk ‖ d_i)        address i
cm = Hk(RECORD, owner ‖ contract ‖ asset ‖ value ‖ data ‖ rho ‖ rcm)            commitment
nf = Hk(NULLIFIER, nk ‖ rho ‖ cm)                                              nullifier
rho'_j = Hk(RHO, nf_0 ‖ j)                                                     output j
```

Commitments go into an append-only depth-32 tree whose root after each block is the header's `px_root`; an anchor must be one of the last 100 roots. A nullifier can appear once, ever, and the pool of value bridged in from v1 must stay at or above zero. **Why:** ownership is hash-based (no discrete logarithm); each output's `rho` derives from the transaction's first nullifier, so two records never share a nullifier (no "Faerie Gold"); and even a complete break of the proof system cannot withdraw more than the pool holds ([zk.md §4.7](docs/zk.md)). **Limits:** the tree's extractability rests on an adaptation of ePrint 2026/089, argued, not proven ([px.md §2](docs/px.md)); Poseidon2 over 31-bit fields is young and under active cryptanalysis.

### The transfer kernel

The kernel is ordinary Rust (`px-core/src/kernel.rs`), compiled once for the zkVM and once natively. For each of two inputs it checks ownership (or a function's approval, for a contract record), tree membership (dummy inputs have value 0) and the nullifier; it checks that the nullifiers differ, derives the outputs' `rho`, and checks the balance over the integers (`u128`):

```
Σ value_in + bridge_in = Σ value_out + bridge_out
```

Every rejection has an append-only exit code, and only exit code 0 has a valid proof. The guest ELF is pinned (`px/kernel.elf`, id in `px/kernel.id`): consensus pins the id, not "whatever the source compiles to", because the ELF depends on the compiler version. The prover runs the kernel natively first and refuses to prove a rejected witness. **Why** this split: see [design principle 4](#design-principles). Integer balance instructions rule out the field wrap-around inflation bug, and a test tries exactly that wrap.

### Private contract functions and the unified proof

A transaction may call up to `MAX_FN = 2` functions, each an ordinary BVM-1 program registered under a contract, run in the **same batch proof** as the kernel (execution 0 is the kernel, function `k` is execution `k + 1`). A function never moves value: it **approves** kernel inputs that are records of its own contract, and **specifies** kernel outputs (new records of its contract, owner 0, or payouts). Function and kernel both compute `io_hash`, a hiding commitment to the approvals and specifications; each function writes a 21-word prefix and exactly its registered number of output words, and the verifier rebuilds the prefix from public values, so a proof exists only if function and kernel agree. The verifier takes the registry as a **mandatory** argument, so only a program registered to a contract can approve that contract's records ([px.md §7.3](docs/px.md)). **Why one proof:** the byte, ALU and Poseidon2 tables are shared, so a function adds only its own tables; recursion is not needed ([zk.md §9.4](docs/zk.md); [px.md §7.1](docs/px.md); [zkvm.md](docs/zkvm.md)).

### BVM-1: the zero-knowledge virtual machine

| Item | Definition ([zkvm.md](docs/zkvm.md)) |
|---|---|
| ISA | **RV32I** plus the multiplication-only **Zmmul** extension; `DIV`, `DIVU`, `REM`, `REMU` are rejected at load (decision ZK-3a) |
| Guest target | `riscv32i-unknown-none-elf` with `+zmmul`, pinned rustc in `zkvm/guests/rust-toolchain.toml` |
| Memory | 2^28 bytes, little-endian; stores only above the code segment; addresses below `0x1000` trap |
| Syscalls (`ECALL`) | `HALT`, `READ` (private input word), `WRITE` (public output word), `POSEIDON2` |
| Limits | `MAX_CYCLES = 2^21` per execution; up to 5 executions per proof (PX uses at most 3) |
| Program id | The first 32 bytes of `H64("zkvm/program", entry, code base, code words, data segments)`, independent of ELF metadata |

**Constraint system.** One `p3-batch-stark` batch of tables connected by LogUp buses (CPU, memory, five ALU tables, Poseidon2, public byte, program, image and output tables, and a blinding table). A circuit tag `CIRCUIT_ID` and a pinned circuit digest (`zkvm/tests/circuit_fingerprint.rs`) bind every AIR change to the transcript and the consensus fingerprint. **Why no division:** division and remainder are the most intricate circuit of a RISC-V zkVM; leaving them out removes the riskiest table from the review surface. **Fixed shapes:** the prover pads every table to the height the public row budgets imply, and the verifier accepts only that shape, so table heights and proof size depend only on which programs ran, never on what they did ([zkvm.md §6.6, §8](docs/zkvm.md)).

### The proof system: Plonky3 0.7.0

| Component | Choice ([zk.md §9.2](docs/zk.md)) |
|---|---|
| STARK | `p3-batch-stark`, lookups by LogUp |
| Commitments | Hiding FRI over a salted Merkle tree |
| Fields | BabyBear base field, degree-8 challenge extension |
| Hashing | Poseidon2 for Merkle trees and Fiat–Shamir |
| Pins | every Plonky3 crate pinned exactly at `=0.7.0` |

**Why.** Decided 2026-09-23 after benchmarks: only a hash-based STARK meets both requirements, no trusted setup and soundness and zero knowledge that do not rest on discrete logarithms. Halo2 was rejected as not post-quantum sound, Groth16 and KZG-PLONK for their trusted setup, SP1 and Stwo for lacking zero-knowledge proofs, and RISC Zero for its C++ kernels.

**Verifier hardening** ([proof-system.md §4–§6](docs/proof-system.md)). Proof bytes are size-capped and strictly decoded (version byte, no trailing bytes, exact re-encoding); canonical-form rules close fields the Plonky3 0.7.0 verifier leaves unbound; the FRI folding schedule must be the honest one. The verifier runs behind `catch_unwind` with `panic = "unwind"`, so a malformed proof becomes a rejection, not a crash. Parameters are compiled in, never read from the proof.

**The four locally patched crates** (prover side only; the verifier logic is unchanged from upstream, [third_party/README.md](third_party/README.md)):

| Crate | Problem in 0.7.0 | Patch |
|---|---|---|
| `p3-fri`, `p3-merkle-tree`, `p3-dft` | **Lock scope.** Spin locks held across rayon parallel work could livelock (found here: ZK-F11, ZK-F21, ZK-F28) | Draw the random values under the lock, release it, then do the parallel work. Same values, same order |
| `p3-batch-stark` | **Determinism.** Quotient randomness drawn from a shared RNG inside a parallel loop made proofs differ between runs (PXDET-1) | Draw in table order; proofs are identical across runs and thread counts |

The supply-chain gate (`.github/scripts/third-party-gate.sh`, CI job `gates`) checks that each crate equals its pinned published `.crate` plus an allow-listed diff, and `tools/tpgate` checks dependency identity; the gate makes a change exact and visible but does not replace human review. `p3-dft` is fixed upstream in 0.8.0; `p3-fri` and `p3-merkle-tree` were not, as of the last check.

### Parameter set BS-ZK-4 and computed soundness

`PARAMS_ID = "BlackSilk/zk/BS-ZK-4"` (`zk/src/params.rs`): blow-up 8, 108 FRI queries, **20 query grinding bits**, degree-8 extension, 8 random codewords per committed matrix, 4 salt elements per Merkle leaf, minimum table height 2^8. A changed constant makes a new parameter set, never an in-place edit.

| Figure (**computed estimates, not proven**) | Value | Source |
|---|---|---|
| Unique decoding, headline | about 109.6 bits (about 89.6 statistical + 20 grinding) | `zk/tests/soundness_calc.rs` |
| Unique decoding with the mixed-height union term (the conservative figure; freeze gate B6) | about 104.5 bits, about 4.5 bits above the 100-bit floor, all of it grinding | `zk/tests/soundness_calc.rs` |
| Johnson (list-decoding) regime | capped by the commitment term, `COLLISION_BITS = 122` | `zk/src/params.rs` |

**Why BS-ZK-4.** Under BS-ZK-3 (16 grinding bits) the conservative figure sat only about 0.5 bits above the floor; raising grinding to the 20-bit cap gives the margin without changing the proof format, expected size or verifier code. The cap is now used up for the chain's life (record `bs-zk-4`). **Limits:** the mixed-height term is a heuristic stand-in for a missing theorem; `COLLISION_BITS` rests on the argued adaptation of ePrint 2026/089; grinding bits are computational and worth less against cheap Poseidon2 hardware; no parameter is sized by a quantum bound ([zk.md §9.3](docs/zk.md)).

### Zero knowledge: statistical and conditional (computational in practice)

**What a proof reveals:** the program ids, exit codes, public outputs, registered budgets and the binding `h_tx`. **Hidden:** inputs, registers, memory, control flow and cycle counts ([zkvm.md §8](docs/zkvm.md)). **Mechanisms:** hiding FRI commitments (random codewords, salted leaves, a mask polynomial per table), terminal blinding of every table's LogUp sum, a minimum table height, and fresh hedged randomness per proof. **Why only "statistical and conditional":** each table meets the per-table conditions of the published construction (ePrint 2024/1037), but that the multi-table, mixed-height, LogUp-based system as a whole is zero knowledge is **not proven**; LogUp leaks a little in every proof, and the masks are PRG outputs, which makes the property computational in practice. Open items: [zk-coverage.md §3](docs/reviews/zk-coverage.md).

### Proof sizes, proving cost and the block budget

**Measured** at freeze gate B3, on the frozen kernel, under **BS-ZK-3**, on one machine (i7-6700, 16 GB, Windows, release build, one proof at a time). BS-ZK-4 changes only the grinding, so the expected sizes are unchanged, but the proofs were **not re-measured** under BS-ZK-4 ([freeze B2/B3 evidence](docs/evidence/freeze-b2-b3-2026-10-04/README.md); [px.md §8](docs/px.md)).

| Statement | Proof size | Proving | Verifying | Peak prover memory |
|---|---|---|---|---|
| Transfer (kernel only) | about 2.40 MB | about 50–60 s | about 0.20–0.33 s | about 3.6 GB |
| Kernel + one function (vault LOCK or CLAIM) | about 3.0 MB | about 60–67 s | about 0.26–0.36 s | about 4.3 GB |
| Kernel + two functions (the vault pair) | about 3.63 MB | about 95–115 s | about 0.31–0.39 s | about 6.4 GB |

**Size by model, memory measured** (deploy-time row caps V12, freeze gate B2): the widest PX proof a deploy can lead to is about **3.70 MB** (3.78 MB worst over the query positions) by model, below the 3.8 MB bound; that size-widest shape is not measured. Prover memory for the memory-widest pair is **measured** at 10,585 MiB peak, no swap, within the 10.4 to 13.1 GB model (one 16 GB GitHub runner, one run; its proof, 3.67 MB, verified; [evidence](docs/evidence/b2-v12mem-2026-10-10/README.md)), so proving arbitrary two-function calls needs a 16 GB device; 8 GB devices prove transfers, single calls and the vault pair. **Why the caps:** under the earlier deploy rule the widest registrable proof was about 4.09 to 4.13 MB by model and gate B2 **failed**; V12 caps every function's budget so that any two fit with the kernel (decisions "px-deploy-row-caps (V12)").

**Block budget.** PX and deploy bytes share a separate **8 MiB** budget per block: at the measured sizes, **3 transfers or 2 calls** per 2-minute block. Proof size is the main open problem; aggregation (recursion) is a design study only ([aggregation-study.md](docs/reviews/aggregation-study.md)).

### Contracts: deploy and call flow

1. **Deploy (kind 3).** A v1 transfer pays the fee, so the deployer is hidden behind ring signatures. It carries a salt and 1 to 16 programs, each an ELF of at most 256 KiB with its row budget, call ABI and exact output-word count. The binaries go on chain because verifiers need them to build the statement.
2. **Contract id.** `H64("px/contract-id", first key image ‖ salt ‖ H32(payload))`. Registrations are immutable and usable from the next block. Deploy checks: budgets within the V12 caps, programs that load and are pairwise distinct, the supported ABI, a new contract id.
3. **Call (kind 2).** Up to two registered functions next to the kernel, in one proof bound to `h_tx`. The validity window `[not_before, not_after]` is public, covered by `h_tx`, `(0, 0)` unless a contract needs one, and the only clock a function can read.
4. **Validation.** PX3 checks the registration and output-word count; PX5 decodes, checks the shape and verifies last; PX6 checks the window against the block height.

**Always public for a call:** the contract id, each called function's program id, its public output words, the validity window and the bridge amounts. **A contract is its whole program set:** any registered program can approve any record of the contract, so the wallet uses a vault only if the contract registers exactly the reference vault with its reference budget ([px.md §13.4](docs/px.md)).

### The reference vault: a demonstration contract

`zkvm/guests/vault` (host side `px/src/vault.rs`, pinned as `px/vault.elf`) is a hash-locked vault (vault-v3) with entries LOCK, CLAIM (with the claim secret) and, **only if the lock has an optional timeout**, REFUND (with a refund secret, from the timeout on). A claim and a refund of one record are never both valid at one height. Locks bind the contract id; a wrong secret gives no proof. The wallet locks with a derived or given claim secret, derives the refund secret from its keys, and dry-runs every way out before every lock ([contracts.md §8](docs/contracts.md)).

It is a **demonstration, not a finished contract**:
- A lock **without a timeout has no refund**: it stays claimable forever by whoever holds the claim secret.
- **It is not an HTLC.** A claim proves the secret without publishing it, so two vaults do not make an atomic swap.
- A miner can delay a claim until the timeout passes and the refund becomes valid.
- The caller of a claim or refund chooses the new record's `rcm` and writes its ciphertext (PX-F4).
- Contracts other than the vault need their own host-side helper code before the wallet can call them ([px.md §10](docs/px.md)).

### The contract model: PX only; Wasm is frozen research

**PX is the only consensus contract platform** (ADR-28-1, owner decision D22): no second value layer, no public contract state, no committee. Contracts are bilateral and UTXO-style, with no shared state between users ([contracts.md §1, §2](docs/contracts.md)). The earlier Wasm confidential-contract engine (`contracts/`) is **frozen research, not consensus**: excluded from the root workspace, with its own lockfile; CI fails if `wasmi` reappears in the root lockfile, and no transaction kind is reserved for it ([contracts/README.md](contracts/README.md); [research/wasm-contracts.md](docs/research/wasm-contracts.md)). **Why:** the Wasm design had public code, state and inputs, 1-of-16 ring callers, a second value layer, and an engine with many `unsafe` blocks. Keeping both would have created two privacy tiers (a user's privacy degrading to the weakest counterparty's) and doubled the consensus attack surface (dossier [28](docs/reviews/phase2-2026-09-27/research/28-private-contracts-px.md) §3.1; dossier [29](docs/reviews/phase2-2026-09-27/research/29-wasm-contracts-review.md)).

### Not covered yet

- No external review of Poseidon2 and the `Hk` constructions, the kernel statement, the zkVM circuits, the hybrid delivery combiner or the PX consensus rules ([px.md §10](docs/px.md)).
- The BVM-1 AIR has internal mutation evidence only, which is not a proof of soundness; no mutation run covers the consensus code added after run E ([STATUS.md §5](docs/STATUS.md)).
- Prover memory for the memory-widest V12 pair is measured once, on one 16 GB runner; the size-widest V12 proof is modelled, not measured; the other proof sizes were not re-measured under BS-ZK-4.
- Verifier selection by (epoch, ABI) for a second kernel generation is designed, not implemented ([contracts.md §4.2](docs/contracts.md)).
- Proof identity across operating systems and CPU architectures is not tested ([third_party/README.md](third_party/README.md)).

## Security model and verification

> BlackSilk has had **no external audit and no independent review**; none is engaged or planned (owner decision 2026-09-25). Everything below is internal engineering work. Finding no bug in that work does not show that there is none.

### Threat model

The adversaries considered are a malicious user, peer, miner and prover, plus a network observer. Every critical component is reviewed against these passes ([review-status.md §3](docs/reviews/review-status.md)):

| Pass | Question |
|---|---|
| Implementation | Does the code implement the written design? |
| Adversarial | What can a malicious user, peer, miner or prover do? |
| Privacy | What leaks: metadata, linkability, timing, reuse, recovery, errors, network behaviour? |
| Consensus | Can two honest nodes reach different results, or accept an invalid state transition? |
| Reorganization | Forks, deep reorganizations, conflicting spends, replay |
| Failure and recovery | Crashes, interrupted submissions, corrupted state, restarts, backups |
| Integration | Is the behaviour tested in the integrated system, not only in isolation? |

The threat model is written down in [assumptions.md](docs/reviews/assumptions.md) (every assumption, with its status), round 1 ([48-threat-model-adversarial.md](docs/reviews/phase2-2026-09-27/research/48-threat-model-adversarial.md)), round 2 ([consensus](docs/reviews/phase2-2026-09-27/research/tm2-consensus.md), [network and operations](docs/reviews/phase2-2026-09-27/research/tm2-network-ops.md), [privacy](docs/reviews/phase2-2026-09-27/research/tm2-privacy.md), [cross-check](docs/reviews/phase2-2026-09-27/research/tm2-crosscheck.md); partially implemented, its open P0 items are rows of [STATUS.md](docs/STATUS.md)) and [privacy-review.md](docs/reviews/privacy-review.md).

### Trust assumptions

| # | Assumption | Status |
|---|---|---|
| K1 | An honest majority of RandomX hash power | **Nominal** for a small chain ([STATUS.md §6](docs/STATUS.md)) |
| K4 | No reorganization-depth limit and no checkpoint | Provisional testnet policy ([k4-reorg-policy.md](docs/reviews/k4-reorg-policy.md)) |
| C1–C3 | Discrete log and DDH hard in Ristretto255; Blake2b-based hashes behave as random oracles | Standard cryptographic assumptions |
| C6 | Quantum resistance | **Not assumed** |
| Z1–Z3 | Knowledge soundness of the Plonky3 STARK at BS-ZK-4; the Poseidon2 challenger as a random oracle; Poseidon2 collision resistance | Figures **computed, not proven**; Poseidon2 is young |
| Z7 | Zero knowledge of the proofs as configured | **Statistical and conditional (computational in practice)**, open ([zk-coverage.md](docs/reviews/zk-coverage.md)) |
| N1 | A node has at least one honest outbound peer | Argued; not tested against a real Sybil attack |
| N2 | No global passive adversary | **Explicit non-goal**: even one link observer sees which transactions a node originates |
| N3 | Transport encryption stops only passive reading | Peers are not authenticated |
| I4 | The wallet host is not compromised | **Explicit non-goal** |
| I5 | Rust's memory safety holds; dependencies' `unsafe` is trusted | Not reviewed line by line ([unsafe-inventory.md](docs/reviews/unsafe-inventory.md)) |

Every security or privacy claim in the reviews names the evidence it rests on ([review-status.md §2](docs/reviews/review-status.md)): **T** tested, **S** source analysis, **C** cryptographic assumption, **U** upstream behaviour, **O** open. Nothing is described as ready for value on the basis of tests alone.

### Internal review

Review is done by fresh-context review agents that receive only the code, the specification and the pass's objective, and report findings with reproduction steps; the author verifies each finding against the source or with a test before accepting it ([internal-review-log.md](docs/reviews/internal-review-log.md)). **Limit:** the review agents and the implementing agent are the same underlying model, so their blind spots may be correlated. These passes are internal review, not an audit.

| Kind of review | Record |
|---|---|
| Review rounds 1 to 4 (2026-09-25/26) | [internal-review-log.md](docs/reviews/internal-review-log.md) |
| Full review of 2026-09-27 | [full-review-2026-09-27.md](docs/reviews/full-review-2026-09-27.md) |
| Red-team rounds (RT-*) and threat-model rounds (TM2) | [decisions.md](docs/reviews/phase2-2026-09-27/decisions.md) |
| Per-change review of every v3 consensus rule (the 15-step record) | [v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md) |
| Historical findings log up to 2026-09-27 (not an audit, despite its file name) | [AUDIT.md](AUDIT.md) |

### Verification methods

| Method | What it shows | Limits | Where |
|---|---|---|---|
| **Mutation testing** (cargo-mutants runs A–E; run F partial) | Every surviving mutant in the code runs A–E and the finished part of run F covered is killed by a test or exempted with a written argument | The rest of run F was never done (`replay.rs`, the zk verify, config and params path, `randomx/`, both fingerprint modules, the supply audit), and 124 chain mutants invalidated by an overload were never re-run ([STATUS.md §5](docs/STATUS.md)); no run covers the consensus code added after run E (PX-R, RX-SALT, the output root and mining blob, the RandomX interpreter rewrite) | [mutation-exemptions.md](docs/reviews/mutation-exemptions.md); [docs/evidence/](docs/evidence/) |
| **Boundary mutants** | `>=`/`<=` off-by-one mutants that cargo-mutants does not generate | Only the files it is run on | [tools/boundary-mutants.sh](tools/boundary-mutants.sh) |
| **AIR mutation census** (BVM-1) | No false execution was accepted | Internal evidence, not a proof of AIR soundness | [mutation-air evidence](docs/evidence/mutation-air-2026-10-02/README.md) |
| **Coverage-guided fuzzing** | No panic on the surface the fuzzer reached | Robustness evidence only, and shallow | [fuzz-w4](docs/evidence/fuzz-w4-2026-09-29/README.md), [fuzz-stateful](docs/evidence/fuzz-stateful-2026-10-01/README.md) |
| **Differential tests** | Native PX kernel and zkVM kernel agree (`kernel_diff`); rewritten RandomX interpreter matches the reference interpreter | Only the inputs exercised | `fuzz/fuzz_targets/kernel_diff.rs`; [STATUS.md §3](docs/STATUS.md) |
| **Independent test vectors** | CLSAG accept vectors and stealth derivations recomputed from the specification text; for Bulletproofs+, generators, commitments and transcript values recomputed (proof bytes are fixed inputs); plus regression pins | Written by the same project | [crypto/tests/vectors/](crypto/tests/vectors/) |
| **Independent golden vectors** | Difficulty rule, v1 fee, header bytes and mining blob, output MMR, PX `Hk`, seed format v1, regenerated from the spec by standard-library Python and compared in CI | Test tooling only; nothing shipped runs it | [tools/vectors/](tools/vectors/) |
| **RandomX known answers** | Official and salted vectors; the salted ones and the mining-blob known answer reproduced by the reference implementation v1.2.3 with only its salt changed, light mode only (freeze gate B4) | Full mode not run against the reference | [randomx/README.md](randomx/README.md) |
| **Golden fixtures** | Header bytes and id, a RandomX answer on a mining blob, a pinned PX transaction with full verdicts and a tamper sweep | The PX fixture is pinned and never regenerated in CI | `consensus/tests/golden.rs`; `node/tests/px_fixture.rs` |
| **Consensus fingerprints** | `blacksilk-node --print-manifest` hashes the rule set; each red-team consensus mutation changes the rules fingerprint | Rule code the samples do not reach (a rule only a PX proof or a full block exercises, or a reordered validation that keeps every sampled verdict) is told apart only by the build commit; reviewed changes are named in the revision list | `node/src/fingerprint.rs`; [tools/fingerprint-mutations.sh](tools/fingerprint-mutations.sh) |
| **Deterministic proofs** (PXDET-1) | Proof bytes depend only on program, input, binding and RNG seed | In-process determinism tested on Windows and in Linux CI; thread-count and cross-process identity measured on Windows only; identity across operating systems and CPU architectures not tested | `zkvm/tests/reproducible.rs` |
| **Reproducible guests** | The pinned kernel and vault programs rebuild to identical bytes on Windows, Linux x86_64 and Linux arm64 | An operator rebuild at the reveal is still owed | [zkvm/guests/README.md](zkvm/guests/README.md) |
| **Overflow-checked tests** | Most non-PX crates' tests (randomx, consensus, crypto, px-core, miner, tx, chain, wallet unit tests, p2p, node) also run with overflow checks and debug assertions | PX-proving tests excluded; rpc, zk, zkvm, px, the tools and the wallet's integration tests not run this way | CI job `overflow` |

Measured values, fingerprints and test counts are deliberately not copied here; their sources are linked.

### Pure Rust and `unsafe` code

- Every root-workspace crate root carries `#![forbid(unsafe_code)]` (checked by grep over the library and binary roots of all nineteen members), and the CI `lint` job checks every one of them.
- The only `unsafe` code in the repository is in the patched Plonky3 crates in `third_party/` (upstream's `unsafe`, unchanged) and the zkVM guest SDK's single `ecall` block (`zkvm/sdk/src/lib.rs`), which runs inside the virtual machine, never in a shipped binary. The guest programs (`zkvm/guests/`) use no `unsafe` but do not declare the `forbid` yet; adding it needs a guest rebuild, because their pinned binaries must stay byte-identical.
- There is no C, no C++ and no FFI in the project's own code. The fuzz binaries link LLVM's libFuzzer (C++) and are never part of the node, wallet or miner.
- Dependencies contain `unsafe` internally; [unsafe-inventory.md](docs/reviews/unsafe-inventory.md) counts it per crate (a review aid, not an assessment). Dependency rules and verdicts: [SECURITY.md](SECURITY.md) ("Dependency policy") and [dependency-review.md](docs/reviews/dependency-review.md).
- **Why.** Pure Rust without `unsafe` in BlackSilk's own code is a standing engineering decision with no exception for performance (decisions, "Engineering process"). Its accepted costs: no JIT RandomX miner, and no memory locking for keys ([STATUS.md §6](docs/STATUS.md)).

### CI gates

All workflows run with a read-only token, and third-party actions are pinned to full commit SHAs ([ci.yml](.github/workflows/ci.yml)).

| Gate | What it enforces |
|---|---|
| `consensus-gate` | A commit touching a consensus path carries a `Consensus-Change:` trailer naming its record, or `none:` with a reason |
| `lockfile-gate` | A commit changing any `Cargo.lock` names every crate it adds, re-versions, re-sources or re-checksums |
| `third-party-gate` | Each `third_party/` crate is the published crate plus exactly its allow-listed diff (`.github/scripts/third-party-gate.sh`); `tools/tpgate` checks dependency identity |
| `unicode-scan` | No invisible or bidirectional Unicode in tracked files ("Trojan Source") |
| `doc-lint` | No forbidden claims, retired identifiers, broken relative links or copied 64-hex digests in the docs |
| `cargo deny` | Advisories, native-code bans, crates.io only, licences, duplicate versions, allow-listed build scripts ([deny.toml](deny.toml)) |
| `cargo audit` | RustSec advisories for the main, fuzz and `tools/tpgate` lockfiles |
| `sys-crates` | No unreviewed `*-sys` crate and no C, C++ or assembly in any release target's build |
| `hazmat-policy` | Deterministic ML-KEM encapsulation only in `px/`, single-round AES only in `randomx/` |
| `unsafe-report` | Warns when the `unsafe` inventory no longer matches the lockfile (a warning, not a gate) |
| `check-test-features`, `build-guard` | Every test-only feature exports a build marker; a plain release build of every shipped binary shows no test-only code |
| Wasm freeze | `wasmi` never enters the main or fuzz lockfile |

**How the verdicts are protected.** The `gates` job extracts the gate scripts and `tools/tpgate` from a trusted earlier revision, so a commit that changes a gate is judged by the old gate ([SECURITY.md](SECURITY.md)). **Limits:** CODEOWNERS and branch protection are not configured (owner tasks), so the gates are advisory: a direct push lands before CI runs. The third-party allow-list certifies itself; the control is human review of every `third_party/` diff. CI results live on GitHub, not in the repository.

## Networks

| Network | Network id | Ports (RPC / P2P) | Block time | Initial difficulty `D0` | State |
|---|---|---|---|---|---|
| Mainnet | `0x000B1A6C` | 19333 / 19334 | 120 s | 100 000 | **Not launched.** `--network mainnet` is refused: its genesis is not final |
| Testnet (v3) | `0x0001D673` | 29333 / 29334 | 120 s | 100 (placeholder) | **Not launched.** `--network testnet` exits with status 2 until the v3 genesis is final |
| Regtest | `0x00DEB06E` | 39333 / 39334 | 10 s | 1 | Local only; available now |

All networks share LWMA window 75, median-time-past window 11, FTL 360 s and RandomX key epoch/lag 2048/64 (`consensus/src/params.rs`; [consensus.md §1](docs/consensus.md)).

- **Testnet.** The former v1 (`0x0001D670`) and v2 (`0x0001D672`) identities are retired, and network ids are never reused. The v3 network id is final, but the genesis time and `D0` are placeholders (`D0` must be measured on reference hardware before the beacon is committed, genesis gate F40-12), and `TESTNET_BEACON` is `None`. The final genesis is generated **only after the protocol freeze**, by the procedure in [testnet-v3-genesis.md](docs/testnet-v3-genesis.md) §6. Genesis ids are pinned by a test (`genesis_ids_are_pinned`) and not copied here.
- **Mainnet.** Parameters exist, but the genesis time is provisional and no beacon is committed.
- **Regtest.** Apart from its identity (network id, genesis time), every consensus rule is the same except the block time and `D0`; regtest also has no tip-age bound on template serving (node policy). The 10-second blocks let one machine run hours of chain activity (reorganizations, RandomX key switches, coinbase maturity) quickly. Private and loopback peer addresses are allowed by default.

**Why a beacon-derived genesis.** Under v2 the genesis was fixed in the source ahead of launch, so anyone with the source could mine before launch. The v3 genesis nonce is derived from a Bitcoin block hash that does not exist when every other field is announced, so nobody, the maintainer included, knows the genesis id or the first RandomX key in advance ([testnet-v3-genesis.md §1](docs/testnet-v3-genesis.md)). The derivation is in consensus code (`consensus/src/genesis.rs`), never a pasted nonce, and there is no runtime override (record `genesis-beacon` in [v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md)).

## Getting started (build, run, regtest)

### Binaries

| Binary | Crate | Role |
|---|---|---|
| `blacksilk-node` | `node/` | Full node: validation, storage, P2P, the local RPC |
| `blacksilk-miner` | `miner/` | Solo RandomX miner; talks only to its own node's RPC (`/info`, `/template`, `/tip`, `/block`) |
| `blacksilk-wallet` | `wallet/` | CLI wallet (v1 and PX) over the node's RPC |
| `blacksilk-genesis` | `tools/genesis/` | Genesis construction and verification (`generate --final` is reserved for the launch) |

Start-up checks: the node and miner run the [RandomX self-test](#the-randomx-crate-implementation-and-evidence); a binary written by `cargo test` carries test hooks, names them in `--version` and refuses every network but regtest; `blacksilk-node --version` prints the consensus, rules and identity fingerprints and the genesis id of every network, which operators compare against the release announcement ([testnet.md §2](docs/testnet.md)).

### Build

- **Toolchain.** Rust **1.98.1**, the version CI pins (`.github/workflows/ci.yml`). The consensus-pinned guest programs reproduce only with this exact rustc (`zkvm/guests/rust-toolchain.toml`). The repository root has no `rust-toolchain.toml`.
- **Windows.** Use the MSVC toolchain (`stable-x86_64-pc-windows-msvc`), because the GNU toolchain's `dlltool` cannot build the OS RNG crate. `.cargo/config.toml` passes `-Brepro` to the MSVC linker.
- **Linux.** No C compiler is needed. CI builds and tests on `ubuntu-24.04`.

```sh
cargo build --release   # for your own machine only
```

A plain `cargo build --release` embeds the build user's home directory in the binaries (panic locations). **Any binary that may leave your machine** (shared with someone, used in a trial, as evidence or for the genesis) is built from a clean checkout with:

```sh
bash tools/release-build.sh -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet
```

and checked as in [testnet.md §2](docs/testnet.md). Never use a binary that `cargo test` wrote: it carries test-only code. Two release builds of one commit are byte-identical on one Windows (MSVC) machine; reproducibility has not been shown across machines or on Linux or macOS ([STATUS.md §1](docs/STATUS.md)).

### Try it on regtest (local, 10-second blocks)

```sh
# 1. Node (RPC on 127.0.0.1:39333; writes ./regtest-data/rpc.cookie at every start)
./target/release/blacksilk-node --network regtest --data-dir ./regtest-data

# The miner and the wallet authenticate with the node's cookie.
export BLACKSILK_RPC_COOKIE=./regtest-data/rpc.cookie

# 2. Wallet (prints a 27-word seed and the primary address)
./target/release/blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 create --network regtest

# 3. Miner (light mode needs 256 MiB; full mode about 2.3 GiB, more while it prebuilds)
./target/release/blacksilk-miner --node 127.0.0.1:39333 --light --address <primary address>

# 4. Balance and transfers. Coinbase outputs unlock after 60 blocks,
#    other outputs after 10.
./target/release/blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 balance
./target/release/blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 transfer --to <address> --amount 1.5
```

Instead of the environment variable, pass `--rpc-cookie <path>` to the miner and wallet. For scripted use, set `BLACKSILK_WALLET_PASSWORD` instead of typing the password. `deploy/config/regtest.toml` is a regtest configuration template.

### Joining a network (once the testnet is enabled)

The testnet is disabled until the v3 genesis is generated at launch; until then `--network testnet` refuses to start. There are no public seed nodes: the built-in seed list is empty, and nodes are joined with explicit `--peer` addresses. Once it runs:

```sh
# Connect to known peers (repeatable); addresses are discovered from them.
blacksilk-node --network testnet --peer <ip>:29334

# Over Tor: every outbound connection through the Tor SOCKS proxy, no direct clearnet
# connection and no DNS lookup. Clearnet addresses are still dialled, through Tor exits.
blacksilk-node --network testnet --proxy 127.0.0.1:9050 --proxy-only --peer <onion>.onion:29334
```

The node never advertises its own address unless `--public-address` is given, and transactions submitted to its RPC are relayed with Dandelion++, not broadcast directly. For inbound connections over Tor, see [Tor and proxies](#tor-and-proxies). The testnet guide, [docs/testnet.md](docs/testnet.md), covers parameters, mining, Tor, Docker and systemd, operator requirements and the multi-machine test procedure.

## Configuration and RPC

### Configuration

The node reads an optional TOML file (`--config`). The command line overrides the file, the file overrides the defaults, and peer and seed lists from both are combined. Unknown keys are an error (`node/src/config.rs`). Templates are in [deploy/config/](deploy/config/): `testnet-node.toml`, `testnet-seed.toml`, `testnet-tor.toml`, `lab-testnet.toml` and `regtest.toml`.

| Option (file key) | Default | Meaning |
|---|---|---|
| `--network` (`network`) | `testnet` | `testnet` or `regtest`; `mainnet` is refused |
| `--data-dir` (`data_dir`) | the OS data directory + `BlackSilk/<network>` | Block store, address table, RPC cookie |
| `--rpc-bind` (`rpc_bind`) | `127.0.0.1:<RPC port>` | RPC listener (plaintext HTTP) |
| `--rpc-allow-host` (`rpc_allow_hosts`) | none | Extra host names the RPC answers to, e.g. an onion service name |
| `--p2p-bind` (`p2p.bind`), `--no-listen` | `0.0.0.0:<P2P port>`; no listener with `--proxy-only` | Inbound P2P |
| `--peer`, `--seed`, `--connect-only` | none | Peers to keep, discovery seeds, fixed topologies |
| `--proxy`, `--proxy-only` | none | SOCKS5 (Tor) for outbound connections |
| `--onion-inbound` (`p2p.onion_inbound`) | none | Loopback listener for the node's Tor hidden service, separate from the P2P port |
| `--public-address` | none | The only way the node advertises its own address |
| `--max-outbound`, `--max-inbound` | 8 / 64 | Connection limits |
| `--network-psk-file` (`p2p.network_psk_file`) | none | Pre-shared key for a closed network (required for the trial) |
| `--log` (`log`) | `info` | Log filter |

Operator and recovery flags have no configuration-file key: `--repair-store`, `--invalidate-block`, `--reconsider-block`, `--verify-store-pow`, `--mine-from-stale-tip`, `--mine-despite-operator-fork`, `--require-clean-build` (also `BLACKSILK_REQUIRE_CLEAN_BUILD=1`), `--randomx-self-test` and `--skip-randomx-self-test` (diagnosis only). See `blacksilk-node --help` and [testnet.md §4, §9](docs/testnet.md).

**Why these defaults.** They follow the privacy-first rule: the node never advertises its address unless told to; with `--proxy-only` it opens no clearnet listener unless one is bound (listening on every interface would reveal a Tor-only node's address) and resolves no host names (a local DNS lookup would tell the resolver that the host runs a node) ([p2p.md §11](docs/p2p.md)).

### RPC

The RPC is JSON over HTTP/1.1, **bound to loopback by default**, with twelve routes: `/info`, `/template`, `/tip`, `/block`, `/tx`, `/blocks`, `/headers`, `/distribution`, `/outputs`, `/px/commitments`, `/px/contracts` and `/tx/status` ([blocks.md §9](docs/blocks.md)). The RPC layer only decodes requests and bounds their size and cost; each handler is one chain-actor command. A guard runs in front of every route, in order:

1. **Host check.** The `Host` header must name loopback, the bound address or an allowed name (blocks DNS rebinding).
2. **Browser check.** A request with an `Origin` or `Sec-Fetch-*` header is refused; there is no CORS support.
3. **Cookie.** Every request, `/info` included, must carry the cookie: 32 random bytes the node writes to `<data dir>/rpc.cookie` at every start, compared in constant time.
4. **Body limits** per route.
5. **Admission.** A fixed number of concurrent requests per class; a full class is answered `503` at once.

The miner and the wallet read the cookie from `--rpc-cookie` or `BLACKSILK_RPC_COOKIE`. Because the connection is plaintext HTTP, **do not expose the RPC**; to reach a node from another machine, use SSH, a VPN or Tor ([blocks.md §9.1](docs/blocks.md)).

### Data directory and service operation

- **Permissions.** On Unix the data directory is created 0700 and its files 0600, and a too-open directory is tightened at start when it holds only the node's files; otherwise the node warns. On Windows the cookie relies on the directory's ACL, an accepted limitation ([testnet.md §4.5](docs/testnet.md)).
- **`originated.json`** is a plaintext list of the transactions the node originated. Keep the data directory private.
- **Linux service.** `deploy/scripts/install-linux.sh` installs systemd units that run as an unprivileged user with a read-only system. Exit statuses a restart would only repeat (configuration error, halt, stored-PoW mismatch, self-test failure) are not restarted ([testnet.md §4.2](docs/testnet.md)). A Docker image is in `deploy/docker/`.
- **Resource figures.** **Measured** figures for a node, a miner and a wallet proving PX transactions are in [testnet.md §12.1](docs/testnet.md); they come from one development machine and are orders of magnitude, not guarantees.

## Testing

### Testing tiers

| Tier | When | What |
|---|---|---|
| 1 | Locally, before every push | Workspace clippy with `-D warnings`, fmt, the gates, doc-lint, cargo deny, and every non-PX test of every crate |
| 2 | GitHub CI, every push | The PX-proving tests one at a time, the overflow-checked tests, guest reproducibility, the fuzz smoke run, full-mode RandomX vectors |
| 3 | Locally, before a push that changes consensus, PX or ZK code, and for evidence runs | The PX-proving suites as well |

A red CI run stops the line (decisions, "Engineering process"). CI also runs `zkvm-stress` weekly (and on manual runs), the only regression test for the Plonky3 spin-lock hang patched in `third_party/`: eight threads prove at once, and a hang fails the job after 20 minutes.

### Running the tests

**Memory warning.** Each test that builds a PX proof needs about 4 to 6 GB. Run in parallel, these tests exhausted a CI runner's memory, so CI runs them one at a time. Run them with `--test-threads=1`, one test process at a time, and only with at least 7 GB free ([impl-brief.md](docs/reviews/phase2-2026-09-27/impl-brief.md)). Some PX-proving tests sit in otherwise ordinary test binaries (for example two in `blacksilk-p2p --test network`); the CI `test` job lists them.

Use `--release`: PX proofs are far too slow unoptimized.

```sh
# Lint and format (tier 1)
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings

# Every test that is not #[ignore], including most PX-proving tests (hours); the
# ignored PX-proving tests, RandomX full mode and zkvm-stress run as separate CI
# steps (.github/workflows/ci.yml).
# --test-threads=1 keeps memory bounded, at the cost of time.
cargo test --locked --release --workspace -- --test-threads=1

# One PX-proving test binary on its own
cargo test --locked --release -p blacksilk-px --test proof -- --test-threads=1
cargo test --locked --release -p blacksilk-tx --test px_consensus -- --test-threads=1

# RandomX full mode against the official vectors (about 2.3 GiB of RAM)
cargo test --locked --release -p blacksilk-randomx -- --ignored --nocapture

# Commit gates and documentation checks, from the repository root.
# BASE HEAD limits the range; without it every commit after the gates'
# cut-over commit is checked (needs the full history).
bash .github/scripts/consensus-gate.sh origin/rebuild/core HEAD
bash .github/scripts/lockfile-gate.sh origin/rebuild/core HEAD
bash .github/scripts/unicode-scan.sh
bash .github/scripts/doc-lint.sh
bash tools/check-test-features.sh
cargo deny --locked check -D warnings
for f in tools/vectors/*.py; do python3 "$f" --check; done   # independent vectors
```

### Fuzzing

`fuzz/` is a separate workspace for coverage-guided fuzzing with cargo-fuzz and libFuzzer (C++ test tooling, linked only into the fuzz binaries). Targets cover the decoders (transactions, blocks, P2P messages, proofs, store records, seed words, ELF files), the transport, `Addr` message entries, record delivery, the PX kernel differential, and the stateful `peer_protocol`, `px_admission` and `scan_outputs` harnesses ([fuzz/fuzz_targets/](fuzz/fuzz_targets/)). The CI `fuzz-smoke` job runs every target for two minutes with debug assertions; longer campaigns are recorded under [docs/evidence/](docs/evidence/). Seeded pure-Rust fuzz tests also live in the crates' test suites (`BLACKSILK_FUZZ_ITERS`).

```sh
# nightly-2026-09-24 and cargo-fuzz 0.13.2, as in CI
cd fuzz && cargo +nightly-2026-09-24 run --locked --release --bin seeds && cd ..
TOOLCHAIN=nightly-2026-09-24 bash fuzz/run_campaign.sh 120   # seconds per target
```

On Windows, the campaign script needs MSVC's ASan runtime on `PATH`. The labnet (`tools/labnet/`) runs real node and miner processes on one machine for long-duration network tests.

## Repository structure

The root-workspace crates and their dependencies are in the [crate map](#crate-map-root-workspace).

| Path | Purpose |
|---|---|
| `randomx/`, `consensus/`, `crypto/`, `tx/`, `chain/`, `p2p/`, `rpc/` | Core libraries |
| `zk/`, `zkvm/`, `px-core/`, `px/` | Proof system, BVM-1 zkVM and PX |
| `node/`, `miner/`, `wallet/` | The three binaries |
| `tools/genesis/`, `tools/labnet/`, `tools/supply-audit/`, `tools/daa-sim/`, `tools/stratum-bridge/` | Root-workspace tools: genesis, lab network, supply check, difficulty simulation, the xmrig gate's stratum bridge |
| `tools/tpgate/` | The third-party gate's checker (its own workspace, so CI can build it from a trusted revision) |
| `tools/vectors/` | Independent standard-library Python vector generators (test tooling only) |
| `tools/*.sh` | Release build, build-flag and test-feature checks, boundary and fingerprint mutation scripts |
| `zkvm/guests/` | Guest programs (`sum`, `arith`, `kernel`, `vault`), a separate workspace built for `riscv32i-unknown-none-elf` with Zmmul under a pinned rustc; the `kernel` and `vault` ELFs are copied into `px/` and their ids pinned ([zkvm/guests/README.md](zkvm/guests/README.md)) |
| `zkvm/sdk/` | Guest SDK (entry point, syscalls, panic handler), used only by the guests |
| `fuzz/` | Coverage-guided fuzz targets (separate workspace, nightly toolchain) |
| `contracts/` | Frozen Wasm contract **research**: its own workspace, outside every build and binary, not consensus ([contracts/README.md](contracts/README.md)) |
| `third_party/` | Four Plonky3 0.7.0 crates with local patches, wired in through `[patch.crates-io]` and checked by the third-party gate ([third_party/README.md](third_party/README.md)) |
| `deploy/` | Configuration templates, systemd units, Docker image, install and health-check scripts |
| `docs/` | Specifications, [STATUS.md](docs/STATUS.md), decision and review records under `docs/reviews/`, evidence under `docs/evidence/`, PoW research under `docs/pow/` |
| `.github/` | CI workflows, gate scripts and issue templates |

The pre-rebuild code (`legacy/`, including the old marketplace) was removed from the tree in `cd7b728` (owner decision 2026-10-04), and the post-quantum signature research crate on 2026-10-05; both stay in the git history.

## Current status

**[docs/STATUS.md](docs/STATUS.md) is the single status source.** This README summarizes it and does not replace it.

- **Highest class reached.** Before the protocol freeze, the highest status class any v3 item can have is "Complete but requires further testing". The consensus rule set (STATUS §2) is in that class, row by row, with evidence.
- **Protocol freeze.** Not reached: the freeze gates are open (STATUS §5; [Roadmap](#roadmap)). Every consensus change until then resets the pinned fingerprints.
- **Testnet.** Disabled. The seven-device trial is blocked: it needs the freeze, the v3 genesis and the owner's approval.
- **Final genesis.** Blocked until the freeze.
- **Review.** Internal engineering work only; no external audit or independent review, and none is engaged.
- **Test counts, fingerprints and measured values** are not copied here; they are in the evidence directories and the pinning tests STATUS names.

## Known limitations

The full lists are STATUS §6 (accepted limitations) and §3.1 (decided but not built). The ones that matter most:

| Limitation | Source |
|---|---|
| **Not audited, not launched, not frozen.** See the status banner and [Current status](#current-status) | [STATUS.md](docs/STATUS.md) |
| **PoW honest majority is nominal (K1).** The salt stops only zero-effort `rx/0` redirection; a salted JIT miner or rented CPUs can out-mine a small testnet and reorganize it. No reorganization-depth limit or checkpoint (K4); park-on-deep-reorg is **planned** | STATUS §6; [testnet.md §12.6](docs/testnet.md) |
| **PX resource needs.** Proofs about 2.4 to 3.6 MB (**measured**), widest about 3.70 MB (**modelled**); proving peaks about 3.6 to 6.4 GB (**measured**); the memory-widest pair 10,585 MiB (**measured**, one run, within the 10.4 to 13.1 GB model). Arbitrary contracts need a 16 GB device (**measured** for the memory-widest pair; the size-widest shape is modelled). 3 transfers or 2 calls fit a block | [Proof sizes](#proof-sizes-proving-cost-and-the-block-budget) |
| **Memory growth.** Block bodies and undo data stay in memory; every restart re-validates every block and PX proof (PX-F1 to PX-F3) | STATUS §6 |
| **Network privacy.** Unpadded frames reveal which transactions a node originates (a PX transaction is unmistakable even over Tor); the handshake is recognizable; block origin is not protected; no onion-only outbound mode; no I2P; eclipse mitigations not tested against a real Sybil attack | [Networking](#networking); [p2p.md §1, §11](docs/p2p.md) |
| **Wallet.** No Tor or SOCKS support; plaintext HTTP to its node; no view-only mode in the CLI; only regtest wallets can be created today | [Wallets](#wallets) |
| **Statistical ring anonymity** (on v1 rings, a real input spent 12 blocks after receipt is the newest member in about 84–89 % of rings on a mature chain, a simulation estimate) and **small anonymity sets** on a trial network | [Privacy model](#privacy-model); [testnet.md §12.7](docs/testnet.md) |
| **Zero knowledge** is statistical and conditional (computational in practice); soundness figures are computed, not proven, and rest on an argued adaptation | [zk.md §9.3](docs/zk.md) |
| **Not post-quantum**; no memory locking for keys; the RPC cookie on Windows is protected only by directory permissions | STATUS §6 |
| **Not a general-purpose contract platform.** At most two functions per call; one demonstration contract; other contracts need host-side helpers | [px.md §10](docs/px.md) |
| **Release authentication.** No signing key and no signed tags; the trial uses a two-channel commit id. The CI gates are advisory without branch protection | STATUS §1 |
| **Not reproducible across machines.** Release builds are byte-identical only on one Windows (MSVC) machine so far | STATUS §1 |

## Roadmap

Every item below is **planned** unless marked otherwise. Nothing after the freeze starts before the freeze gates pass.

### 1. Freeze gates (before the freeze; open)

The main open gates; the full list is in [STATUS.md §5](docs/STATUS.md).

| Gate | What remains | Source |
|---|---|---|
| Mutation testing | Finish run F (`replay.rs`, the zk verify, config and params path, `randomx/`, both fingerprint modules, the supply audit) and re-run the invalidated chain mutants; run a census of the consensus code added after run E (PX-R, RX-SALT, the output root and mining blob, the RandomX interpreter rewrite) with zero unexplained survivors | STATUS §5, mutation-testing row |
| B2 size-widest measurement | Prover memory for the memory-widest PX pair is measured (10,585 MiB, within the model); still open: prove the size-widest V12 shape (non-vault programs, about 3.70 to 3.78 MB by model) and pin the V12 caps restated in the measuring example against tx | STATUS §5, B2 row |
| Freeze-commit verification | The full test suite on the freeze commit, including the PX-proving tests; every CI job green on GitHub; the fingerprint-mutation script re-run | STATUS §5; decisions "RT-FREEZE-V" |
| Full-mode RandomX against the reference | B4 reproduced the known answers in **light mode only**; full-mode hashing has not been run against the reference | STATUS §5, B4 row |
| Labnet reruns | The quiet-window reruns (ring topology, address relay, late joiner) | STATUS §5, labnet row |
| xmrig compatibility gate | **Passed** (Complete but requires further testing): 2,133 regtest blocks mined by real xmrig, across the first key switch, every result byte-equal to BlackSilk's hash; one machine and CPU. Confirms that the 47-byte mining blob needs only a salt-only xmrig patch ([Third-party miners](#third-party-miners-xmrig)) | STATUS §5, xmrig row; decisions "xmrig compatibility gate: before the freeze"; [xmrig-compatibility.md](docs/pow/xmrig-compatibility.md) (historical research) |
| Supply audit with a PX pool | **Not implemented**: a multi-machine 72-hour run | STATUS §5; [testnet.md §7](docs/testnet.md) |
| Second threat-model round | **Partially implemented**: the four internal reports are written; their P0 items are open STATUS rows | STATUS §5 |
| CI on the release commit | **Not verified**: all jobs green on GitHub; CI results live on GitHub, not in the repository | STATUS §5 |

### 2. Freeze, genesis and trial (after the gates)

1. **Protocol freeze.** The release-candidate commit is announced by its full id on two channels, and the documentation is reconciled again (gate B7).
2. **Genesis preconditions.** `D0` measured on the trial devices, a fresh network pre-shared key, the endpoint checklist on every device, and a genesis rehearsal (not yet implemented).
3. **Final genesis.** Derived from a Bitcoin block hash after a 48-hour announcement and recomputed independently by every operator ([testnet-v3-genesis.md §6](docs/testnet-v3-genesis.md)).
4. **Seven-device trial**, a closed testnet with the pre-shared key, after the owner's approval.

### 3. External mining (after the freeze)

- A pure-Rust stratum server, decided as an optional component.
- A pinned xmrig build with `rx/blacksilk` for the testnet, because upstream merges of new algorithms have historically taken long.
- An upstream xmrig pull request for `rx/blacksilk`, once the stratum server and a tested patch exist, made openly as AI-assisted work on behalf of the project (decisions, "Proof of work: SKC-1 research, the RandomX salt, the mining blob, xmrig").

### 4. Before a public testnet

The decided-but-not-built P0 and P1 items in STATUS §3.1, including fair block download, `MIN_CHAIN_WORK` and headers presync, and park-on-deep-reorg; the open relay-privacy items (onion-only Tor mode, the timing oracle); release signing with signed tags; branch protection; and built-in seed nodes run by independent operators. Wallet SOCKS5 support is also decided but not built (STATUS §3.1).

### 5. Before mainnet (research)

The decisions log reopens several topics before mainnet: the difficulty rule together with a finality option, a model of selfish mining, and private transaction broadcast. Transport v2 (padding, hybrid ML-KEM) is a design note only ([p2p.md §3.1](docs/p2p.md)). Post-quantum privacy is a research track with no design in the repository.

## Contributing

- **Security issues** go through private reporting, never a public issue ([Reporting security issues](#reporting-security-issues)). Bugs and feature requests use the templates in `.github/ISSUE_TEMPLATE/`.
- **Consensus changes** follow the 15-step discipline of [v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md): problem, demonstrated failure, prior art, alternatives, affected components, activation, compatibility, reorg, wallet, mining and P2P implications, vectors, regression tests, suite results, and open review points.
- **Commit trailers.** Every commit that touches a consensus path (listed in `.github/scripts/consensus-gate.sh`) carries one of these trailers in the **last paragraph** of the message, together with any `Co-Authored-By:` line and with no blank line between them:
  ```
  Consensus-Change: docs/reviews/v3-consensus-changes.md#<section>
  Consensus-Change: none: <why this edit does not change consensus>
  ```
  A commit that changes any `Cargo.lock` names every crate it adds, re-versions, re-sources or re-checksums (`.github/scripts/lockfile-gate.sh`).
- **Before every push (tier 1)**, run what the CI jobs `lint`, `gates`, `doc-lint` and `deny` check ([Testing](#testing)). For changes to consensus, PX or ZK code, also run the PX-proving tests locally with `--test-threads=1`.
- **Documentation.** A change that closes or alters a STATUS row edits that row in the same commit. `doc-lint` rejects forbidden claims, links to untracked files and copied 64-hex-digit values.
- **Pure Rust.** No C, C++ or FFI in the project's own code; every root-workspace crate root carries `#![forbid(unsafe_code)]`; new dependencies are crates.io crates under the licences allowed in `deny.toml`.

## Reporting security issues

**Do not open a public issue for a vulnerability.** The process is in [SECURITY.md](SECURITY.md):

- Report privately through GitHub's private vulnerability reporting ("Security" tab, "Report a vulnerability"). That repository setting was checked disabled on 2026-09-27 and its activation is pending with the maintainer. If the button is missing, open a public issue titled only "Security contact request", with no details; the maintainer will answer with a private channel.
- Acknowledgement within 2 working days, private handling until a fixed release is running, then publication, with credit if you wish ([testnet-incident-response.md](docs/testnet-incident-response.md)).
- Everything in the repository is in scope. The proof system, the consensus rules and anything that reveals private data are especially valuable. The known privacy limitations in [privacy-review.md](docs/reviews/privacy-review.md) are not new findings.

## Licence

**BlackSilk has no licence for its own code yet; the choice is an open owner decision** (`deny.toml`). The repository root has no `LICENSE` file, so until one is added no licence is granted for the project's own code. Two parts carry their own terms:

- `randomx/` is a Rust port of tevador/RandomX and is distributed under that project's BSD-3-Clause licence ([randomx/LICENSE](randomx/LICENSE)).
- The patched Plonky3 crates in `third_party/` keep their upstream licence, `MIT OR Apache-2.0` (each crate's `Cargo.toml`).

Dependencies are limited to the licences listed in [deny.toml](deny.toml) and checked by the CI job `deny`.

## Further reading

| Topic | Document |
|---|---|
| Status (single source) | [docs/STATUS.md](docs/STATUS.md) |
| Header chain, PoW, difficulty | [docs/consensus.md](docs/consensus.md) |
| Blocks, emission, node behaviour, RPC, wallet formats | [docs/blocks.md](docs/blocks.md) |
| v1 transactions and privacy model | [docs/transactions.md](docs/transactions.md) |
| P2P network | [docs/p2p.md](docs/p2p.md) |
| PX | [docs/px.md](docs/px.md) |
| ZK architecture and parameters | [docs/zk.md](docs/zk.md) |
| BVM-1 zkVM | [docs/zkvm.md](docs/zkvm.md) |
| Proof format and verifier rules | [docs/proof-system.md](docs/proof-system.md) |
| Contracts | [docs/contracts.md](docs/contracts.md) |
| Testnet operation | [docs/testnet.md](docs/testnet.md), [docs/testnet-v3-genesis.md](docs/testnet-v3-genesis.md), [docs/testnet-incident-response.md](docs/testnet-incident-response.md) |
| PoW research | [docs/pow/](docs/pow/) |
| RandomX implementation | [randomx/README.md](randomx/README.md) |
| Consensus change records | [docs/reviews/v3-consensus-changes.md](docs/reviews/v3-consensus-changes.md) |
| Decisions log | [docs/reviews/phase2-2026-09-27/decisions.md](docs/reviews/phase2-2026-09-27/decisions.md) |
| Assumptions and review status | [docs/reviews/assumptions.md](docs/reviews/assumptions.md), [docs/reviews/review-status.md](docs/reviews/review-status.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Historical internal findings log (not an audit) | [AUDIT.md](AUDIT.md) |
