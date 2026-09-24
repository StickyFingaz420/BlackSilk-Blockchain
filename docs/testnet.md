# BlackSilk Testnet Guide

This guide is for people running testnet nodes, miners and wallets, and for seed-node
operators. Protocol details are in [consensus.md](consensus.md),
[transactions.md](transactions.md), [blocks.md](blocks.md) and [p2p.md](p2p.md). The
current readiness status is in [AUDIT.md](../AUDIT.md).

> **Testnet coins have no value.** The testnet may be reset. A reset uses a new
> network id and genesis block, so old nodes simply stop connecting. Use the
> testnet to find problems, and report them.

## 1. Parameters

| | Testnet | Regtest (local only) |
|---|---|---|
| Network id | `0x0001D670` | `0x00DEB06E` |
| Genesis time | 2026-09-23 00:00:00 UTC (`1790121600`) | `1700000000` |
| Genesis id | `bbeb1a9fdb16cf416ddb505e8468a16b4308d15307d0a12d9ef4ecfefed12909` | `087d6fd4efbc45eb0a895dd0680a7fd305208cae239b1b4275d7148b29a569b7` |
| Genesis body | empty, no premine | empty |
| Block time | 120 s | 10 s |
| Starting difficulty | 100 | 1 |
| Difficulty | LWMA-1, 60 blocks | same |
| Proof of work | RandomX v1; the key changes every 2048 blocks, with a 64-block lag | same |
| First reward | 20.02716064 BLK; smooth curve with a 0.6 BLK tail | same |
| Coinbase maturity / spendable age | 60 / 10 blocks | same |
| Ports (RPC / P2P) | 29333 / 29334 | 39333 / 39334 |

The genesis ids are pinned by a test (`consensus/src/params.rs`), so an accidental
change fails the build.

## 2. Build

Rust stable. On Windows, use the MSVC toolchain.

```sh
cargo build --release -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet
```

The binaries are in `target/release/`. Everything is pure Rust; no C compiler is needed.

## 3. Quick start (one machine)

```sh
blacksilk-node --network testnet                    # P2P 0.0.0.0:29334, RPC 127.0.0.1:29333
blacksilk-wallet -w me.wallet create --network testnet
blacksilk-miner --address <address printed by create>   # add --light on machines with < 3 GB RAM
blacksilk-wallet -w me.wallet balance
```

Until built-in seeds exist (§6), give the node at least one peer:
`--peer <ip>:29334`, or `--seed <host>:29334`.

## 4. Running a node

### 4.1 Configuration

The node reads an optional TOML file (`--config`); command-line flags override it.
Templates are in `deploy/config/`:

| File | Use |
|---|---|
| `testnet-node.toml` | normal public node |
| `testnet-seed.toml` | seed node (§6) |
| `testnet-tor.toml` | node reachable only over Tor |
| `lab-testnet.toml` | private LAN/lab network with testnet rules (§7) |
| `regtest.toml` | local regtest |

Main options (`blacksilk-node --help` lists all of them):

| Option / key | Meaning |
|---|---|
| `--peer` / `p2p.peers` | peers to stay connected to |
| `--connect-only` / `p2p.connect_only` | outbound connections only to the peers above (fixed topologies) |
| `--seed` / `p2p.seeds` | seeds for discovery (host names allowed, except in proxy-only mode) |
| `--public-address` | advertise this address; unset means the node is never advertised |
| `--p2p-bind`, `--no-listen` | inbound connections |
| `--proxy`, `--proxy-only` | SOCKS5 (Tor) for outbound connections; proxy-only refuses clearnet |
| `--max-outbound`, `--max-inbound` | connection limits (8 / 64) |
| `--allow-private` | LAN/lab networks only: accept private addresses |
| `--log` | log filter, e.g. `info,blacksilk_p2p=debug` |

### 4.2 As a service (Linux)

```sh
sudo deploy/scripts/install-linux.sh                     # node
sudo deploy/scripts/install-linux.sh --miner <address>   # node + miner
deploy/scripts/check-node.sh                             # health
journalctl -u blacksilk-node -f                          # logs
```

The units in `deploy/systemd/` run as an unprivileged `blacksilk` user with a
read-only system, and can write only `/var/lib/blacksilk`. Open TCP 29334 inbound.
Never expose port 29333: the RPC has no authentication.

### 4.3 Over Tor

Use `deploy/config/testnet-tor.toml`:
- all outbound connections go through Tor's SOCKS port;
- inbound connections arrive through a hidden service that forwards to 127.0.0.1:29334;
- the node advertises only its `.onion` address.

In proxy-only mode seeds must be IP or `.onion` addresses, because resolving a host name
would use local DNS and reveal the node.

### 4.4 Docker

```sh
docker build -f deploy/docker/Dockerfile -t blacksilk .
docker run -d --name bs -p 29334:29334 -v bs-data:/data blacksilk
docker exec bs blacksilk-wallet -w /data/me.wallet create --network testnet
```

### 4.5 Data directory

| File | Content |
|---|---|
| `blocks.dat` | append-only block log; the node replays it at start (blocks.md §8) |
| `peers.json` | address table (p2p.md §9) |
| `bans.json` | banned IPs and their expiry |
| `LOCK` | prevents two nodes from sharing the directory |

To resync from scratch, stop the node and delete `blocks.dat`.

## 5. Mining

```sh
blacksilk-miner --node 127.0.0.1:29333 --address <testnet address> [--threads N] [--light]
```

- **Full mode** needs about 2.3 GiB of RAM and builds a 2 GiB dataset every 2048 blocks.
  It is much faster per hash.
- **Light mode** needs 256 MiB.
- Rewards pay a one-time stealth output to your address. They are spendable after 60
  blocks.

## 6. Seed nodes

A seed is an always-on, publicly reachable testnet node with a stable address. New nodes
use seeds only to find the network (p2p.md §9).

**To run one:**
1. Use a server with a static public IP (or a DNS name you control) and TCP 29334 open.
2. Start with `deploy/config/testnet-seed.toml`: set `public_address`, and list the other
   seeds in `peers`.
3. Run it for at least a week, and check `deploy/scripts/check-node.sh` regularly.
4. Add `"<host>:29334"` to `builtin_seeds()` in `node/src/config.rs`, in a reviewed change.

**Seeds are not trusted for correctness.** Nodes validate everything they receive.

**Seeds do see who connects, so:**
- run at least three seeds, under independent operators, in different networks;
- Tor users should list `.onion` seeds instead.

The built-in list is **empty on purpose** until real seed hosts exist.

## 7. Multi-machine test procedure (required before a public launch)

The long-duration **lab network** (`tools/labnet`, §8) ran on a single machine. It
emulates latency, jitter and partitions, but not real network conditions. Before a
public launch, run this procedure on at least **3 machines in 2 different networks**
(for example two cloud regions and one home connection):

1. **Set up.** On every machine: build (§2), then start a node with
   `lab-testnet.toml`. For a real internet test, use `testnet-node.toml` with
   `--peer` pointing to machine A.
2. **Automatic joining.** Give machines B and C only machine A as a peer.
   - Pass: within 5 minutes both show `peers ≥ 2` in `check-node.sh`.
   - This means they discovered each other through address exchange.
3. **Mining across machines.** Run a miner on A and one on C.
   - Pass: every node reports the same `tip`, and each miner's wallet receives rewards
     for blocks found on its own machine.
4. **Transaction propagation.** After 60 blocks, send a transfer from the wallet on A to
   an address of the wallet on C, submitted through B's RPC.
   - Pass: C's wallet shows it after the next block.
   - Pass: B's log does not show B announcing it before the embargo (Dandelion++ stem).
5. **Reorganization under real conditions.** Block traffic between {A} and {B, C} for
   20 minutes, e.g. `iptables -A INPUT -s <A> -j DROP` on B and C, with both sides
   mining. Then remove the rule.
   - Pass: within 5 minutes all tips are equal.
   - Pass: the minority side's logs contain `reorganization: disconnecting …`.
   - Pass: transactions from the orphaned side return to the mempool and confirm.
6. **Wallet sync from a fresh node.** Start a new node D, with an empty data directory,
   connected to one machine. When D reaches the tip, restore each wallet from its 24
   words against D:

   ```sh
   blacksilk-wallet -w fresh.wallet restore --network testnet
   blacksilk-wallet -w fresh.wallet --node <D> balance
   ```

   - Pass: the balance is identical to the original wallet's.
7. **Stability.** Keep everything running for at least 72 hours.
   - Pass: no crashes, flat memory, and all nodes on the same tip.

Record the results in AUDIT.md, in the testnet-readiness section.

## 8. Lab network tool (single machine)

```sh
cargo build --release -p blacksilk-node -p blacksilk-miner -p blacksilk-labnet
target/release/blacksilk-labnet --bin-dir target/release --out labnet-run \
    --nodes 5 --duration-mins 180 --latency-ms 80 --jitter-ms 60 \
    --partition-every-mins 25 --partition-mins 4 --tx-every-secs 20
```

**What it runs:**
- 5 regtest nodes, in a ring with chords;
- every link goes through a proxy that adds latency and jitter;
- a miner in each half of the network;
- wallets sending transactions through random nodes;
- periodic partitions between the two halves.

**What it checks at the end:**
- convergence;
- drained mempools;
- a late node that discovers peers and syncs;
- every wallet restored from its seed against that fresh node shows the same balance;
- Σ wallet balances equals the coins generated;
- no crashes;
- no misbehavior disconnects between honest nodes.

**Output:** `summary.json`, `metrics.csv` (every 15 s), `journal.log`, and each
process's log.

## 9. Monitoring and troubleshooting

| Symptom | Check |
|---|---|
| `peers: 0` | Firewall (TCP 29334); at least one `--peer` or `--seed`; `bans.json` |
| `header_height` > `height` for long | Bodies still downloading; watch the log for timeouts |
| `configuration error` at start | Typos in the TOML are errors by design (unknown keys are refused) |
| `… is in use by another node` | Another node uses the same data directory |
| Wallet `WrongNetwork` | Wallet and node on different networks |
| Wallet `insufficient unlocked funds` | Coinbase needs 60 blocks, other outputs 10 |
| A transfer never confirms | `blacksilk-wallet … clear-pending`, then sync again |

## 10. Private execution (PX)

**Compatibility.** Builds with PX accept transaction kinds 2 and 3 from genesis
(px.md §11). Older builds reject blocks that contain them, so the two versions fork.
Every node on one network must run a PX-capable build; a public PX trial therefore
starts with a testnet reset (a new network id and genesis), unless an activation
height is added first.

**Wallet commands:**

| Command | Effect |
|---|---|
| `px-address [--index N]` | Shows a PX address. Give each counterparty its own index |
| `px-balance` | `(total, spendable)` PX balance |
| `px-deposit --amount A` | v1 funds into PX. **The amount is public** |
| `px-send --to PXADDR --amount A` | A private payment. Proving takes about a minute |
| `px-withdraw --to ADDR --amount A` | PX funds to a v1 address. **The amount is public** |

Each PX transaction pays the same standard PX fee, `2 × MAX_PX_TX_SIZE` =
8 912 896 atomic units (≈ 0.089 BLK), so fees do not fingerprint transactions.

**Spendability.** A received record becomes spendable once the next height that is a
multiple of 16 is reached (canonical anchor, px.md §11.4).

**Privacy:** px.md §12 and `docs/reviews/privacy-review.md`.

**Capacity:** about 4 PX transactions per block (aggregation-study.md).

## 11. Security notes for operators

- **The RPC must stay on loopback.** It has no authentication, and `/block` and `/tx`
  cost CPU to validate.
- **Use your own node for your wallet.** A remote node learns which ring members you
  fetch (blocks.md §9).
- **P2P encryption is unauthenticated.** It protects against passive observers only
  (p2p.md §1).
- **Treat the testnet wallet file and its 24 words like real keys.** Keys reused on a
  future mainnet would be exposed.
