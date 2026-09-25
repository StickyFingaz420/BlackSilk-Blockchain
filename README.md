# BlackSilk

A privacy-first proof-of-work cryptocurrency written in pure Rust.

> **Status: under active rebuild, pre-testnet.** The components below are
> implemented and tested. The software has **not** had an external security audit or
> any independent review; all security work so far is internal
> ([`docs/reviews/review-status.md`](docs/reviews/review-status.md)). It must not be used
> for anything of value. See [`AUDIT.md`](AUDIT.md) for the
> full audit and open items.

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
| Network | encrypted transport, header-first sync, Dandelion++, eclipse-resistant address manager, peer scoring and bans, SOCKS5/Tor | [p2p.md](docs/p2p.md) |

**What it is not (yet):**
- **Not post-quantum secure.** No part of the transaction layer resists a quantum
  adversary ([transactions.md §11.6](docs/transactions.md)). Post-quantum work is a
  separate research track (`research/`).
- **No authenticated peers, no I2P.** P2P encryption stops passive observers, not an
  active man in the middle ([p2p.md §1](docs/p2p.md)). Tor works through its SOCKS5
  proxy; I2P is not supported yet.
- **Smart contracts are in development and not active on any network.** The design
  covers confidential contracts with anonymous callers and hidden amounts
  ([contracts.md](docs/contracts.md)). The engine and cryptography are implemented;
  chain integration is pending. Private execution with zero-knowledge proofs is a
  design for review ([zk.md](docs/zk.md)). The old marketplace stays parked in
  `legacy/`.

## Repository layout

| Crate | Purpose |
|---|---|
| `randomx/` | RandomX v1 (light and full mode) |
| `consensus/` | header format, PoW, difficulty, timestamps, chain selection |
| `crypto/` | Ristretto255 primitives, stealth outputs, Janus anchor, CLSAG, Bulletproofs+, contract signatures and claims |
| `tx/` | transaction format, validation rules, builder, scanner, decoy selection |
| `chain/` | blocks, emission, chain manager (reorgs), mempool, block storage, addresses |
| `contracts/` | confidential contracts: Wasm module profile, deterministic engine, contract state and state root (not yet in consensus) |
| `p2p/` | peer-to-peer network |
| `rpc/` | node RPC types and client |
| `node/` | `blacksilk-node` |
| `miner/` | `blacksilk-miner` |
| `wallet/` | `blacksilk-wallet` |
| `tools/labnet/` | long-duration multi-node lab test (latency, partitions, wallet traffic) |
| `deploy/` | node configuration templates, systemd units, Docker image, install scripts |

Every crate is pure Rust with `#![forbid(unsafe_code)]`. There is no C, no C++ and no
FFI in the project's own code.

## Build and test

Requires Rust stable (tested with 1.98). On Windows use the MSVC toolchain
(`stable-x86_64-pc-windows-msvc`), because the GNU toolchain's `dlltool` cannot build
the OS RNG crate.

```sh
cargo test --workspace            # ~175 tests
cargo clippy --workspace --all-targets
cargo build --release
```

## Testnet

The testnet guide covers parameters, running a node, mining, seed nodes, Tor, Docker
and systemd, and the multi-machine test procedure: **[docs/testnet.md](docs/testnet.md)**.

## Try it on regtest (local, 10-second blocks)

```sh
# 1. Node (RPC on 127.0.0.1:39333)
blacksilk-node --network regtest --data-dir ./regtest-data

# 2. Wallet (prints a 24-word seed and the primary address)
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

## Security notes

- The node RPC has no authentication and binds to loopback by default. Do not expose
  it.
- A wallet using someone else's node reveals which ring members it fetches. Use your
  own node ([blocks.md §9](docs/blocks.md)).
- Wallet files are encrypted with Argon2id and AES-256-GCM. The 24 words are the only
  backup.
