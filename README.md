# BlackSilk

A privacy-first proof-of-work cryptocurrency written in pure Rust.

> **Status (2026-09-27): pre-testnet, hardening round in progress.** The components
> below are implemented and have internal tests. The software has **not** had an
> external security audit or any independent review; all security work so far is
> internal, and no external review is engaged or planned (owner decision 2026-09-25,
> [`docs/reviews/review-status.md`](docs/reviews/review-status.md)). It must not be used
> for anything of value. [`AUDIT.md`](AUDIT.md) is the project's **internal findings
> log**, not an external audit.
>
> **Testnet v2:** the v2 identity is approved and fixed in code. The seven-device
> trial is **not** authorized until the owner approves the readiness report after the
> hardening round
> ([`docs/reviews/completion-readiness-2026-09-26.md`](docs/reviews/completion-readiness-2026-09-26.md)
> §6). Gates: [`docs/testnet-launch-checklist.md`](docs/testnet-launch-checklist.md).

## What it is

| Area | Design | Spec |
|---|---|---|
| Proof of work | RandomX v1 (pure-Rust implementation, passes the official test vectors), Monero key schedule | [consensus.md](docs/consensus.md) |
| Difficulty | LWMA-1, 2-minute blocks | [consensus.md](docs/consensus.md) |
| Sender privacy | CLSAG ring signatures, ring size 16, key images | [transactions.md](docs/transactions.md) |
| Receiver privacy | one-time stealth outputs, view tags, subaddresses, **Janus anchor** | [transactions.md §3, §12](docs/transactions.md) |
| Amount privacy | Pedersen commitments, aggregated Bulletproofs+ | [transactions.md §6–7](docs/transactions.md) |
| Group | Ristretto255 (prime order) | [transactions.md §1](docs/transactions.md) |
| Emission | smooth curve to ~21 M BLK, then 0.6 BLK/block tail forever; no premine | [blocks.md §2](docs/blocks.md) |
| Private execution (PX) | private records and nullifiers, a fixed transfer kernel and private contract functions proven in the BVM-1 zkVM (Plonky3 STARK, parameter set BS-ZK-2). Transaction kinds 2 and 3 are **consensus rules from genesis** (testnet v2, not yet launched, will be the first public network to run them). Zero knowledge is claimed only as **statistical and conditional** ([zk-coverage.md](docs/reviews/zk-coverage.md)); proofs are about 2.2 MB (transfer) | [px.md](docs/px.md), [zk.md](docs/zk.md), [zkvm.md](docs/zkvm.md) |
| Network | encrypted (unauthenticated) transport, header-first sync, Dandelion++, bucketed address manager with eclipse mitigations (not tested against a real Sybil attack), peer scoring and bans, outbound SOCKS5/Tor | [p2p.md](docs/p2p.md) |

**What it is not (yet):**
- **Not post-quantum secure.** No part of the v1 transaction layer resists a quantum
  adversary ([transactions.md §11.6](docs/transactions.md)). Post-quantum work is a
  separate research track (`research/`).
- **No authenticated peers, no I2P.** P2P encryption stops passive observers, not an
  active man in the middle ([p2p.md §1](docs/p2p.md)). Tor works through its SOCKS5
  proxy for the node's outbound connections; I2P is not supported. The wallet has no
  Tor or TLS support: its RPC connection is plaintext HTTP, so use your own node.
- **Not a finished contract platform.** PX private contracts are in consensus, with one
  **demonstration** contract (the vault: no timeout, no refund, not trustless). The
  separate Wasm confidential-contract system ([contracts.md](docs/contracts.md)) has
  its engine and cryptography implemented but is **not integrated** into the chain and
  is not active on any network. The old marketplace stays parked in `legacy/`.

## Repository layout

| Directory | Purpose |
|---|---|
| `randomx/` | RandomX v1 (light and full mode) |
| `consensus/` | header format, PoW, difficulty, timestamps, chain selection |
| `crypto/` | Ristretto255 primitives, stealth outputs, Janus anchor, CLSAG, Bulletproofs+, contract signatures and claims |
| `tx/` | transaction format, validation rules (v1 and PX), builder, scanner, decoy selection |
| `chain/` | blocks, emission, chain manager (reorgs), mempool, block storage, addresses |
| `zk/` | proof-system configuration (Plonky3 0.7.0, BS-ZK-2) and its security parameters |
| `zkvm/` | BVM-1 zero-knowledge virtual machine: interpreter, constraint tables, guest SDK and guest programs |
| `px-core/` | PX hash `Hk`, records and the transfer kernel (`no_std`, shared with the guest) |
| `px/` | PX node state, wallet side, record delivery, kernel proofs, the vault |
| `contracts/` | Wasm confidential contracts: module profile, engine, contract state and state root (**not in consensus**) |
| `p2p/` | peer-to-peer network |
| `rpc/` | node RPC types and client |
| `node/` | `blacksilk-node` |
| `miner/` | `blacksilk-miner` |
| `wallet/` | `blacksilk-wallet` |
| `tools/labnet/` | long-duration multi-node lab test (latency, partitions, wallet traffic) |
| `fuzz/` | coverage-guided fuzz targets (separate workspace, nightly toolchain) |
| `third_party/` | three Plonky3 0.7.0 crates with a local lock-scope patch ([third_party/README.md](third_party/README.md)) |
| `deploy/` | node configuration templates, systemd units, Docker image, install scripts |

**Pure Rust, and `unsafe`:**
- Every workspace crate declares `#![forbid(unsafe_code)]`. The exception is the zkVM
  guest SDK (`zkvm/sdk`, built separately for the guest target), whose one `unsafe`
  block is the `ecall` instruction that runs inside the virtual machine; the guest
  programs themselves contain no `unsafe`.
- The patched crates in `third_party/` keep upstream Plonky3's own `unsafe` code
  unchanged, and dependencies contain `unsafe` internally
  ([dependency-review.md](docs/reviews/dependency-review.md)).
- There is no C, no C++ and no FFI in the project's own code. The fuzz binaries link
  LLVM's libFuzzer (C++), and are never part of the node, wallet or miner.

## Build and test

Requires Rust **1.98.1** (the version CI and the local evidence use; the
consensus-pinned guest programs reproduce only with this exact rustc,
`zkvm/guests/rust-toolchain.toml`). On Windows use the MSVC toolchain
(`stable-x86_64-pc-windows-msvc`), because the GNU toolchain's `dlltool` cannot build
the OS RNG crate.

```sh
cargo test --release --workspace  # about 450 tests; proofs make it slow (30-40 min)
cargo clippy --workspace --all-targets
cargo build --release
```

## Testnet

The testnet guide covers parameters, running a node, mining, Tor, Docker and systemd,
operator requirements and the multi-machine test procedure:
**[docs/testnet.md](docs/testnet.md)**. There are no public seed nodes: the built-in
seed list is empty, and nodes are joined with explicit `--peer` addresses.

## Try it on regtest (local, 10-second blocks)

```sh
# 1. Node (RPC on 127.0.0.1:39333)
blacksilk-node --network regtest --data-dir ./regtest-data

# 2. Wallet (prints a 27-word seed and the primary address)
blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 create --network regtest

# 3. Miner (light mode needs 256 MiB; full mode needs 2 GiB)
blacksilk-miner --node 127.0.0.1:39333 --light --address <primary address>

# 4. Balance and transfers. Coinbase outputs unlock after 60 blocks,
#    other outputs after 10.
blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 balance
blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 transfer --to <address> --amount 1.5
```

For scripted use, set `BLACKSILK_WALLET_PASSWORD` instead of typing the password.

## Joining a network

```sh
# Connect to known peers (repeatable); addresses are discovered from them.
blacksilk-node --network testnet --peer <ip>:29334

# Over Tor: all outbound connections through the Tor SOCKS proxy, no clearnet.
blacksilk-node --network testnet --proxy 127.0.0.1:9050 --proxy-only --peer <onion>.onion:29334
```

- The node never advertises its own address unless `--public-address` is given.
- Transactions submitted to the node's RPC are relayed with Dandelion++, not
  broadcast directly.
- Inbound connections over a Tor hidden service all arrive from 127.0.0.1, so they
  share one address's limits and bans (a known defect, N-6;
  [docs/testnet.md §4.3](docs/testnet.md)).

## Security notes

- The node RPC requires the node's cookie (`<data dir>/rpc.cookie`), but it is plaintext
  HTTP and binds to loopback by default. Do not expose
  it.
- A wallet using someone else's node reveals which ring members it fetches, and its
  RPC traffic is plaintext (the wallet has no Tor or TLS support). Use your own node
  ([blocks.md §9](docs/blocks.md)).
- Wallet files are encrypted with Argon2id and AES-256-GCM. The 27 seed words recover the
  keys and on-chain funds, but not everything: the stored rings of pending spends and
  contract records this wallet created for others live only in the wallet file. Back
  up the wallet file as well ([docs/testnet.md](docs/testnet.md), operator section).
