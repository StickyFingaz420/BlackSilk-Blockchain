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
| Network id | `0x0001D672` (testnet v2; v1 was `0x0001D670`) | `0x00DEB06E` |
| Genesis time | 2026-09-26 00:00:00 UTC (`1790380800`) | `1700000000` |
| Genesis id | `6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d` | `087d6fd4efbc45eb0a895dd0680a7fd305208cae239b1b4275d7148b29a569b7` |
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

Rust 1.98.1 (the version CI and the recorded evidence use). On Windows, use the MSVC
toolchain.

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

**Known defect with inbound Tor (N-6, open):**
- Every inbound connection from the hidden service reaches the node from
  `127.0.0.1`, so the node sees all inbound Tor peers as one IP address.
- Without `--allow-private` (the testnet default), the per-IP limit
  (`max_per_ip` = 2) caps inbound Tor connections at **2 in total**.
- A single misbehaving inbound Tor peer gets `127.0.0.1` banned for **24 hours**,
  which shuts out **every** inbound Tor peer for that time. (Bans are skipped only for
  outbound proxied connections, and for loopback when `--allow-private` is set.)
- `--allow-private` lifts both limits for loopback, but also accepts private LAN
  addresses; it is meant for lab networks.
- Outbound connections through the SOCKS proxy are not affected.

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

- **Full mode** needs about 2.3 GiB of RAM (the 2 GiB dataset plus about 0.3 GB). It
  is much faster per hash (§12.1).
  - The miner builds the dataset at start and again at every RandomX key switch
    (heights 2113, 4161, …). It stops hashing while it rebuilds: about 3 minutes with
    8 threads, about 20 minutes with 1 thread (measured 2026-09-27).
- **Light mode** needs 256 MiB and no dataset, but is much slower per hash.
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
   - Pass: no crashes, and all nodes on the same tip.
   - Record each node's resident memory (RSS) against its chain height. Memory grows
     with the chain, because every block body and its undo data stay in memory
     (PX-F1, PX-F2): about 7 KB per v1 block, up to about 8 MiB per full PX block.
     Fail only on growth the chain does not explain.

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
- periodic partitions between the two halves;
- with `--px-every-mins N`, private (PX) activity every N minutes: a deposit, a private
  payment or a withdrawal by a random wallet. Each proves for about a minute, during
  which the harness pauses.

**What it checks at the end:**
- convergence;
- drained mempools;
- a late node that discovers peers and syncs;
- every wallet restored from its seed against that fresh node shows the same balance,
  v1 and private;
- Σ wallet balances (v1 and private) equals the coins generated;
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
| A transfer never confirms | Run `sync` again later: the wallet rebroadcasts the same transaction every 20 blocks and releases its funds itself if the node finds it invalid. Use `clear-pending` only if the transaction certainly never left the wallet (docs/px.md §12) |
| `WARN … reorganization: disconnecting N block(s)` | A reorganization of 10 or more blocks: follow docs/testnet-incident-response.md |
| `block store: … corrupt record at offset … followed by valid data` at start | Real corruption in `blocks.dat` (not a crash, which the node repairs itself). Back up the data directory, then start once with `--repair-store`: the damaged part moves to `blocks.dat.damaged-<time>` and the node downloads the dropped blocks again (docs/blocks.md §8) |
| `block store: … refuses writes after a failed write` or `SubmitError::Store` in the log | The disk is full or failing. Free space, then restart the node; it resumes from the last stored block |
| `N stored block(s) without a stored parent were not replayed` at start | After a failed write: harmless, the node downloads them again |

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
| `px-send --to PXADDR --amount A` | A private payment. Proving takes about 45 s and a peak of about 3.8 GB of memory (§12.1) |
| `px-withdraw --to ADDR --amount A` | PX funds to a v1 address. **The amount is public** |
| `px-deploy --vault` (or `--program F.elf --budget …`) | Registers a private contract, paid with v1 funds |
| `px-contracts` / `px-records` | Deployed contracts / contract records this wallet holds |
| `px-vault-lock --contract C --amount A [--secret S] [--deliver-to PXADDR]` | Locks PX funds in the reference vault under a secret; the record goes to the claimer |
| `px-vault-claim --record CM --secret S [--to PXADDR]` | Claims a vault record privately; the fee comes from PX or v1 funds |
| `px-share --record CM --to PXADDR` / `px-import --share HEX` | Shares a contract record off chain / imports one |

Contract tooling is described in px.md §13. **The reference vault is a demonstration
contract: not production-ready and not trustless.** It has no timeout and no refund,
the locker also knows the secret (and can claim), and it is not a trustless swap. A
record the locker delivers to someone else is kept only in the locker's wallet file
and is not recovered by restoring from the seed (px.md §13.4).

Every PX transaction pays exactly the standard PX fee, a consensus rule:
`2 × MAX_PX_TX_SIZE` = 8 912 896 atomic units (≈ 0.089 BLK). So fees do not
fingerprint transactions or wallets.

**Spendability.** A received record becomes spendable once the next height that is a
multiple of 16 is reached (canonical anchor, px.md §11.4).

**Privacy:** px.md §12 and `docs/reviews/privacy-review.md`.

**Capacity:** about 4 PX transactions per block (aggregation-study.md).

## 11. Security notes for operators

- **The RPC must stay on loopback.** It has no authentication, and `/block` and `/tx`
  cost CPU to validate.
- **Use your own node for your wallet.** A remote node learns which ring members you
  fetch (blocks.md §9). The wallet has no Tor or TLS support: its RPC connection is
  plaintext HTTP, so a remote node, and anyone on the path, sees your requests and
  your IP address.
- **P2P encryption is unauthenticated.** It protects against passive observers only
  (p2p.md §1). An active man in the middle can also inject invalid messages under the
  peer's address, so that the victim bans the impersonated peer's IP for 24 hours, and
  can eclipse a node whose connections it controls.
- **Treat the testnet wallet file and its 24 words like real keys.** Keys reused on a
  future mainnet would be exposed.

## 12. Operator requirements and procedures

Status: **written 2026-09-27 from the code and the recorded measurements; not yet
used by an operator.** Figures come from one development machine (Windows 10, 8
logical CPUs) unless stated; treat them as orders of magnitude, not guarantees.

### 12.1 Hardware

| Role | Memory | CPU and time | Notes |
|---|---|---|---|
| Node | about 300 MB at start (267–297 MB peak per process in the local rehearsals, docs/evidence/labnet-2026-09-26/) | Verification of a PX proof takes about 0.21–0.27 s; light-mode RandomX about 0.45–0.75 s per header | **Grows with the chain:** every block body and its undo data stay in memory (PX-F1, PX-F2), about 7 KB per v1 block and up to about 8 MiB per full PX block. Plan disk and RAM for the length of the trial |
| Wallet proving a PX transaction | peak about **3.8 GB** (3,771 MB measured) | about 45 s (transfer) to 53 s (vault call) per proof, on all cores | Proving is local; a machine without the memory cannot send PX transactions |
| Miner, full mode | 2 GiB dataset plus about 0.3 GB | Dataset build about 180 s with 8 threads (179 s measured under load), about **20 minutes with 1 thread** (1,217–1,219 s measured, 2026-09-27); hashing about 100 ms per hash per thread (measured under load) | The build is **repeated at every RandomX key switch** (heights 2113, 4161, …), and the miner does not hash while it rebuilds |
| Miner, light mode | 256 MiB | about 0.45–0.75 s per hash per thread | No dataset; suitable for small machines, but finds far fewer blocks |

The per-hash figures under load were measured with the full test suite running at the
same time; idle figures are to be re-measured.

### 12.2 Clock synchronisation (required)

- Run NTP (or the OS time service) on every device, and check it before starting.
- A block is refused while its timestamp is more than **360 s** (the future-time limit,
  consensus.md §5) ahead of the receiving node's clock.
  - A node whose clock is **behind** by more than about 6 minutes refuses honest blocks
    until its clock catches up, so it falls behind the network.
  - A node whose clock is **ahead** by more than that mines blocks that the other nodes
    refuse, so its miner works on a private fork that is later discarded.
- Such refusals are not permanent verdicts: the block is accepted once the clocks
  agree. But while they last the network can split.

### 12.3 Network configuration

- **Peers:** there are no seed nodes; the built-in list is empty
  (`node/src/config.rs`). Give every node an explicit list: `--peer <ip>:29334` for at
  least one, better two, other trial devices. Addresses are then exchanged between
  peers.
- **Firewall:** open TCP **29334** (P2P) inbound on devices that should accept
  connections. **Block 29333** (RPC) from outside: the RPC has no authentication and
  must stay on loopback (the default).
- **Several devices behind one NAT** reach other nodes from one public IP. Without
  `--allow-private`, a node accepts at most `max_per_ip` = 2 inbound connections from
  one IP, and a ban of that IP (24 hours, after misbehaviour) shuts out every device
  behind it (bans are per exact IP, N-5). Prefer outbound `--peer` connections from
  such devices, and spread the trial over different networks.
- **Tor:** see §4.3, including the inbound defect N-6.
- **Wallets:** run each wallet against its own node on the same machine. The wallet's
  RPC connection is plaintext HTTP with no Tor or TLS support.

### 12.4 Backup and recovery

- **Back up the whole data directory and every wallet file,** not only the 24 words.
  Restoring from the seed does **not** recover:
  - the stored rings of pending or earlier spends (docs/reviews/wallet-review.md,
    W-5 residual): a later spend of the same output may then use a new ring, which the
    key image links to the earlier one;
  - contract records this wallet created and delivered to someone else (the
    creator's copy lives only in the wallet file, px.md §13.4);
  - contract records addressed to the wallet before its restore height.
- **A crash or power loss:** restart the node on the same data directory. A torn last
  record is truncated automatically; the node then re-validates every stored block,
  including every PX proof (about 0.2 s each), so restarts become slower as the chain
  grows (PX-F3).
- **Corruption in the middle of `blocks.dat`:** the node refuses to start. Back up the
  data directory, then start once with `--repair-store` (§9, blocks.md §8).
- **A full or failing disk:** free space or replace the disk, then restart (§9).
- **Resync from scratch:** stop the node, move `blocks.dat` aside, start again.

### 12.5 Testnet reset

The reset procedure and the rollback are in docs/testnet-reset-plan.md §4 and §6; the
trial's checks and the evidence to return are in docs/testnet-v2-validation.md. A reset
always uses a new network id; never reuse one for a different genesis.

### 12.6 Known limitations that affect operators

- Every block body and its undo data stay in memory (PX-F1, PX-F2); memory grows with
  the chain.
- Every restart re-validates every block, including every PX proof (PX-F3).
- Full-mode miners stop for about 3 to 20 minutes at every RandomX key switch while
  they rebuild the dataset (§5). The switch at height 2113 has been exercised only in
  a test with a short epoch (16 blocks, lag 4), never at 2113 with the network's
  parameters.
- No seed nodes; peers are configured by hand.
- Open P2P defects (docs/reviews/completion-readiness-2026-09-26.md §2–§3; the
  hardening round in AUDIT.md R14 addresses others):
  - N-4: connections that have not completed the handshake are not bounded;
  - N-5: bans are per exact IP, so they are easy to evade and hit every device behind
    one NAT;
  - N-6: inbound Tor peers share `127.0.0.1` (§4.3);
  - N-9: no eviction of inbound peers when the inbound slots are full;
  - N-11: relays of transactions with invalid signatures are not penalized (signature
    checks are contextual, so they are not scored as misbehaviour);
  - N-12: memory growth.
- Peers are not authenticated (§11).

### 12.7 What the trial can and cannot show

- **Anonymity:** v1 ring anonymity among only seven participants who all mine is not
  representative of a production anonymity set; the trial tests mechanics, not
  anonymity. The same holds for the PX pool, whose anonymity set is only the records
  the trial creates.
- **Security:** the trial shows operation, not security. The security assumptions are
  listed in docs/reviews/assumptions.md; the zero-knowledge claim is statistical and
  conditional, and its remaining assumptions are in docs/reviews/zk-coverage.md.

### 12.8 Troubleshooting

See §9, and docs/testnet-incident-response.md for anything that looks like a
consensus, security or privacy problem.
