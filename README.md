# BlackSilk

A privacy-first proof-of-work cryptocurrency written in pure Rust.

> **Pre-testnet.** The current status (identity, testnet, open items, accepted
> limitations) is kept only in **[docs/STATUS.md](docs/STATUS.md)**. The components
> below are implemented and have internal tests. The software has **not** had an
> external security audit or any independent review; all security work is internal,
> and no external review is engaged or planned (owner decision 2026-09-25,
> [`docs/reviews/review-status.md`](docs/reviews/review-status.md)). It must not be used
> for anything of value. [`AUDIT.md`](AUDIT.md) is a historical **internal findings
> log**, not an audit.

## What it is

| Area | Design | Spec |
|---|---|---|
| Proof of work | RandomX v1 with BlackSilk's own Argon2 salt, `"BlackSilk/RandomX/v1"`; every other parameter is Monero's `rx/0` (pure-Rust implementation; the reference test vectors it still pins, with Monero's salt, and BlackSilk's own vectors are listed in [randomx/README.md](randomx/README.md)), Monero key schedule. The PoW input is a 47-byte mining blob (`BSilk/1`, the header's mining hash, an 8-byte nonce at byte 39), not the 172-byte header. Solo mining only: `blacksilk-miner` mines through the node's `/template`; the project has no pool or stratum server | [consensus.md §3](docs/consensus.md) |
| Difficulty | LWMA-1 with a 75-block window and a counted clock, 2-minute blocks | [consensus.md §4](docs/consensus.md) |
| Sender privacy | CLSAG ring signatures, ring size 16, key images | [transactions.md](docs/transactions.md) |
| Receiver privacy | one-time stealth outputs, view tags, subaddresses, **Janus anchor** | [transactions.md §3, §12](docs/transactions.md) |
| Amount privacy | Pedersen commitments, aggregated Bulletproofs+ | [transactions.md §6–7](docs/transactions.md) |
| Group | Ristretto255 (prime order) | [transactions.md §1](docs/transactions.md) |
| Emission | smooth curve to ~21 M BLK, then 0.6 BLK/block tail forever; no premine | [blocks.md §2](docs/blocks.md) |
| Private execution (PX) | private records and nullifiers, a fixed transfer kernel and private contract functions proven in the BVM-1 zkVM (Plonky3 STARK, parameter set BS-ZK-3). Transaction kinds 2 and 3 are **consensus rules from genesis**; no network running them has launched. Zero knowledge is claimed only as **statistical and conditional**, computational in practice ([zk-coverage.md](docs/reviews/zk-coverage.md)); proofs are about 2.4 MB (transfer) ([STATUS.md](docs/STATUS.md) §5, §6) | [px.md](docs/px.md), [zk.md](docs/zk.md), [zkvm.md](docs/zkvm.md) |
| Network | encrypted (unauthenticated) transport, header-first sync, Dandelion++, bucketed address manager with eclipse mitigations (not tested against a real Sybil attack), peer scoring and bans, outbound SOCKS5/Tor | [p2p.md](docs/p2p.md) |

**What it is not (yet):**
- **Not post-quantum secure.** No part of the v1 transaction layer resists a quantum
  adversary ([transactions.md §11.6](docs/transactions.md)). The tree holds no
  post-quantum code: the earlier signature research crate was removed on 2026-10-05
  and stays in the git history.
- **No authenticated peers, no I2P.** P2P encryption hides message contents from
  passive observers, not message sizes and timing, and not from an active man in the
  middle ([p2p.md §1](docs/p2p.md)); a closed network can add a pre-shared key. Tor works through its SOCKS5
  proxy for the node's outbound connections; I2P is not supported. The wallet has no
  Tor or TLS support: its RPC connection is plaintext HTTP, so use your own node.
- **Not a finished contract platform.** PX is the only consensus contract platform
  ([contracts.md](docs/contracts.md), "Private contracts on PX"), with one
  **demonstration** contract (the vault: not trustless, not an HTLC). The earlier Wasm
  confidential-contract design is **frozen research**, outside the build and not
  consensus on any network ([research/wasm-contracts.md](docs/research/wasm-contracts.md),
  [contracts/README.md](contracts/README.md)). The old marketplace and the rest of the
  pre-rebuild code (`legacy/`) were removed from the tree in `cd7b728` (owner
  decision 2026-10-04); they remain in the git history before that commit.
- **Not a strong PoW network yet.** The testnet's PoW is RandomX with BlackSilk's own
  salt. Stock `rx/0` hash power cannot be pointed at it unmodified, but anyone who
  adds the salt to a JIT miner (minutes of work) or rents generic CPUs can out-mine it
  (an accepted limitation, [docs/STATUS.md](docs/STATUS.md) §6).

## Repository layout

| Directory | Purpose |
|---|---|
| `randomx/` | RandomX v1 (light and full mode) |
| `consensus/` | header format, PoW, difficulty, timestamps, chain selection |
| `crypto/` | Ristretto255 primitives, stealth outputs, Janus anchor, CLSAG, Bulletproofs+ (and the Wasm research's signatures, membership proofs and claims, used by no consensus crate) |
| `tx/` | transaction format, validation rules (v1 and PX), builder, scanner, decoy selection |
| `chain/` | blocks, emission, chain manager (reorgs), mempool, block storage, addresses |
| `zk/` | proof-system configuration (Plonky3 0.7.0, parameter set BS-ZK-3) and its security parameters |
| `zkvm/` | BVM-1 zero-knowledge virtual machine: interpreter, constraint tables, guest SDK and guest programs |
| `px-core/` | PX hash `Hk`, records and the transfer kernel (`no_std`, shared with the guest) |
| `px/` | PX node state, wallet side, record delivery, kernel proofs, the vault |
| `contracts/` | frozen Wasm contract research: its own workspace, **outside the root workspace and every binary**, not consensus ([contracts/README.md](contracts/README.md)) |
| `p2p/` | peer-to-peer network |
| `rpc/` | node RPC types and client |
| `node/` | `blacksilk-node` |
| `miner/` | `blacksilk-miner` |
| `wallet/` | `blacksilk-wallet` |
| `tools/labnet/` | long-duration multi-node lab test (latency, partitions, wallet traffic) |
| `tools/genesis/` | beacon-derived genesis construction and verification |
| `tools/supply-audit/` | closed-set supply check for a trial |
| `tools/daa-sim/` | difficulty-rule simulation harness (evidence, not consensus) |
| `fuzz/` | coverage-guided fuzz targets (separate workspace, nightly toolchain) |
| `third_party/` | four Plonky3 0.7.0 crates with local patches: lock scope (`p3-dft`, `p3-fri`, `p3-merkle-tree`) and prover determinism, PXDET-1 (`p3-batch-stark`), checked by the third-party gate `tools/tpgate` ([third_party/README.md](third_party/README.md)) |
| `deploy/` | node configuration templates, systemd units, Docker image, install scripts |

**Pure Rust, and `unsafe`:**
- Every crate root of the root workspace (its library and binary targets) declares
  `#![forbid(unsafe_code)]`. The zkVM guest SDK (`zkvm/sdk`) and the guest programs
  (`zkvm/guests/`) are built separately for the guest target and are outside it: the
  SDK's one `unsafe` block is the `ecall` instruction that runs inside the virtual
  machine; the guest programs contain no `unsafe` but do not declare
  `#![forbid(unsafe_code)]`.
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
cargo test --release --workspace  # the PX proofs make it slow (tens of minutes)
cargo clippy --workspace --all-targets
cargo build --release              # for your own machine only
```

A plain `cargo build --release` embeds the build user's home directory in the
binaries (panic locations). **Any binary that may leave your machine** (shared with
someone, used in the trial, as evidence or for the genesis) is built with
`bash tools/release-build.sh -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet`
from a clean checkout, and checked as in
[docs/testnet.md §2](docs/testnet.md). Never use a binary that `cargo test` wrote: it
carries test-only code.

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

# 3. Miner (light mode needs 256 MiB; full mode about 2.3 GiB, more while it prebuilds)
blacksilk-miner --node 127.0.0.1:39333 --light --address <primary address>

# 4. Balance and transfers. Coinbase outputs unlock after 60 blocks,
#    other outputs after 10.
blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 balance
blacksilk-wallet -w miner.wallet --node 127.0.0.1:39333 transfer --to <address> --amount 1.5
```

For scripted use, set `BLACKSILK_WALLET_PASSWORD` instead of typing the password.

## Joining a network

The testnet is disabled until the v3 genesis is generated at launch: until then
`--network testnet` refuses to start ([docs/STATUS.md](docs/STATUS.md)). Once it runs:

```sh
# Connect to known peers (repeatable); addresses are discovered from them.
blacksilk-node --network testnet --peer <ip>:29334

# Over Tor: every outbound connection through the Tor SOCKS proxy, no direct clearnet
# connection and no DNS lookup. Clearnet addresses are still dialled, through Tor exits.
blacksilk-node --network testnet --proxy 127.0.0.1:9050 --proxy-only --peer <onion>.onion:29334
```

- The node never advertises its own address unless `--public-address` is given.
- Transactions submitted to the node's RPC are relayed with Dandelion++, not
  broadcast directly.
- For inbound connections over a Tor hidden service, forward the service to the
  node's onion listener (`--onion-inbound 127.0.0.1:<port>`), not to the P2P port;
  otherwise they all share one loopback address's limits and bans (N-6).
  `deploy/config/testnet-tor.toml` does this ([docs/testnet.md §4.3](docs/testnet.md)).
- `--proxy-only` dials clearnet addresses through Tor exits, which can read those
  unauthenticated connections like any man in the middle; there is no onion-only
  outbound setting yet ([docs/testnet.md §4.3](docs/testnet.md)).

## Security notes

- The node RPC requires the node's cookie (`<data dir>/rpc.cookie`), but it is plaintext
  HTTP and binds to loopback by default. Do not expose
  it.
- A wallet using someone else's node reveals its IP address, its scan start (the
  wallet's birthday), when it sends, and which transaction came from it; rings are
  chosen from the wallet's own output index, so ring members are not revealed. Its RPC
  traffic is plaintext (the wallet has no Tor or TLS support). Use your own node
  ([blocks.md §9](docs/blocks.md)).
- An observer of your node's own link (your ISP, or your Tor guard) can tell from
  message sizes and timing when your node originates a transaction, **v1 or PX**:
  frames are not padded. A PX transaction (about 2.4 MB or more) is unmistakable even over
  Tor; a v1 transaction (a few kB) is a weaker signal over Tor but not hidden
  ([docs/testnet.md §12.7](docs/testnet.md)).
- `originated.json` in the node's data directory lists every transaction the node
  originated: keep the data directory private
  ([docs/testnet.md §4.5](docs/testnet.md)).
- Wallet files are encrypted with Argon2id and AES-256-GCM. The 27 seed words recover the
  keys and on-chain funds, but not everything: the stored rings of pending spends and
  contract records this wallet created for others live only in the wallet file. Back
  up the wallet file as well ([docs/testnet.md](docs/testnet.md), operator section).
