# BlackSilk Testnet Guide

This guide is for people running testnet nodes, miners and wallets, and for seed-node
operators. Protocol details are in [consensus.md](consensus.md),
[transactions.md](transactions.md), [blocks.md](blocks.md) and [p2p.md](p2p.md). The
project and testnet status is kept only in [STATUS.md](STATUS.md).

> **Testnet coins have no value.** The testnet may be reset. A reset uses a new
> network id and genesis block, so old nodes simply stop connecting. Use the
> testnet to find problems, and report them.

> **The testnet is disabled** (current status: [STATUS.md](STATUS.md)). The v2
> identity (`0x0001D672`) is retired because this tree enforces rules v2 builds do not,
> so the two would fork. `blacksilk-node --network testnet` refuses to start until the
> v3 genesis is final (`ChainParams::genesis_is_final`, checked by
> `check_network_enabled` in `node/src/config.rs`): it is generated at launch, by the
> procedure and tool in docs/testnet-v3-genesis.md (`tools/genesis`).
> Until then, use `--network regtest` or the labnet harness. The v2 parameters below
> are kept for reference and will be replaced by v3's.

## 1. Parameters

| | Testnet | Regtest (local only) |
|---|---|---|
| Network id | `0x0001D672` (testnet v2; v1 was `0x0001D670`) | `0x00DEB06E` |
| Genesis time | 2026-09-26 00:00:00 UTC (`1790380800`) | `1700000000` |
| Genesis id | pinned by `genesis_ids_are_pinned` (`consensus/src/params.rs`); printed by `blacksilk-node --version` | same |
| Genesis body | empty, no premine | empty |
| Block time | 120 s | 10 s |
| Starting difficulty | 100 | 1 |
| Difficulty | LWMA-1, 75-block window (consensus.md §4) | same |
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

### 2.1 Operator check: identity (every device, before the trial)

Nodes built from different commits can agree on the genesis and still follow
different rules. They connect, and then fork on the first block that uses the
difference. Every crate version is `0.1.0`, so the version number alone does
not identify a build. Before the trial, **every device** compares three values
with the ones the release announcement publishes:

- the **genesis id** (full, 64 hex digits);
- the **consensus fingerprint** of the network (full, 64 hex digits);
- the **build commit**.

Where to read them:

- `blacksilk-node --version` prints the commit and, for every network, the
  fingerprint (the first 16 hex digits, then the full value) and the genesis id.
  `blacksilk-node -V` prints only the version and commit.
- The start-up log prints `blacksilk-node <version> commit <commit>`, then
  `<network>: genesis <id>, consensus fingerprint <fingerprint>`.
- The RPC `/info` returns `genesis_id`, `consensus_fingerprint`, `build_commit`
  and `version`. `deploy/scripts/check-node.sh` prints them.
- `blacksilk-miner --version` and `blacksilk-wallet --version` print the version
  and commit (see the limitation below).

Pass: all three values are identical on every device, and they match the
announcement. On any difference, stop. Do not start or keep mining until
the builds match.

**What the fingerprint covers.** It is a domain-separated hash
(`BlackSilk/v1/node/consensus-fingerprint/v1`, BLAKE2b) of a canonical,
length-prefixed encoding of the following consensus constants
(`node/src/fingerprint.rs`, `px/src/fingerprint.rs`):

- every `ChainParams` field, the genesis block bytes and id, and `TxRules`;
- the header, transaction, block and emission constants, and emission samples;
- the RandomX configuration;
- the proof-system parameter set (BS-ZK-3, `zk/src/params.rs`) and `PROOF_VERSION`;
- the BVM-1 limits;
- the PX kernel constants and hash domains;
- the kernel and vault program ids.

`node/tests/deploy_configs.rs` pins one value per network. Changing one is a
consensus change and needs a new network id. The values are deliberately not copied
here (a copy goes stale with every consensus change before the freeze): compare the
output of `blacksilk-node --version` with the signed release announcement, which
takes its values from that test at the release commit.

Limits of the check:

- **The fingerprint covers constants, not rule code.** A fix that changes
  validation logic without changing a constant leaves the fingerprint unchanged,
  and only the commit tells the two builds apart. So compare the commit as well.
- **The RandomX entries are copies.** They are the RandomX v1 values, because
  `blacksilk-randomx` does not export its configuration. The crate's official
  test vectors pin its behaviour.
- **There is no dirty flag.** The node reads the commit from `.git` directly
  (`node/build.rs`, without running `git`). It does not detect uncommitted
  changes. Build the trial binaries from a clean checkout of the announced
  commit.
- **A build without `.git` reports `commit unknown`.** This covers Docker (the
  `.dockerignore` excludes `.git`) and source archives. To record the commit,
  set `BLACKSILK_BUILD_COMMIT` in the build environment. A non-empty value
  always wins, so a release script can pass, for example,
  `BLACKSILK_BUILD_COMMIT=$(git describe --always --dirty)`. The Dockerfile
  does not forward the variable yet (it needs an `ARG BLACKSILK_BUILD_COMMIT`
  before `cargo build`).
- **The miner and wallet have no build script.** They report a commit only when
  `BLACKSILK_BUILD_COMMIT` is set at build time. Otherwise they report
  `unknown`.

## 3. Quick start (one machine)

```sh
blacksilk-node --network testnet                    # P2P 0.0.0.0:29334, RPC 127.0.0.1:29333
export BLACKSILK_RPC_COOKIE=<data dir>/rpc.cookie   # the RPC credential (§4.2)
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
| `--network-psk-file` / `[p2p] network_psk_file` | private networks only: a file holding a 64-hex-character pre-shared key; only nodes with the same key can connect, and an on-path attacker without it cannot read or inject P2P traffic (p2p.md §3). One leaked key opens the network to its holder; it gives no identity between members |
| `--rpc-allow-host` / `rpc_allow_hosts` | extra host names the RPC answers to besides loopback and its bound address, e.g. an onion service name (blocks.md §9.1) |
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

**Exit statuses.** The node exits 0 after a clean shutdown, 2 on a configuration error,
70 when a panic poisoned its chain lock (a restart replays the store and recovers), 65
when a block that passed validation failed to apply (a bug in the node, blocks.md §6),
and 1 on any other error (a failed block store included). The node unit restarts on
failure but not on 65 (`RestartPreventExitStatus=65`): a restart replays into the same
failure. The constants are `HALT_EXIT_CODE` and `POISONED_EXIT_CODE` in
`node/src/lib.rs`. If the node is started again by hand after a 65, the replay reaches
the same block at start-up and exits 65 again (`open_exit_code`), so the unit still
does not loop; report the block the log names (§9).
Never expose port 29333 (§11).

**RPC credential.** At every start the node writes a fresh random credential to
`<data dir>/rpc.cookie` (`/var/lib/blacksilk/testnet/rpc.cookie` with the templates) and
removes it at a clean shutdown; every RPC request must carry it (blocks.md §9.1).
- Clients take `--rpc-cookie <path>`, or the `BLACKSILK_RPC_COOKIE` environment variable:
  `blacksilk-miner`, `blacksilk-wallet` and `blacksilk-supply-audit`. The miner unit
  passes `--rpc-cookie`; change it if `node.toml` sets another `data_dir`.
- A restart writes a new credential. The miner reads the file again when the node
  refuses the old one; restart other long-running clients.
- On Linux the file is readable only by the node's user: run clients as that user,
  e.g. `sudo -u blacksilk deploy/scripts/check-node.sh`.
- On Windows the file inherits its directory's permissions. The default data directory
  under `%APPDATA%` is private to your user; a data directory elsewhere gets a warning,
  and you must make sure other users cannot read it.
- `curl` needs the header `Authorization: Bearer <contents of rpc.cookie>`. Pass it on
  standard input (`-H @-`, as `check-node.sh` does), not on the command line, which other
  local users can read.

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
| `blocks.dat` | append-only block log (format 2: bound to the network id and genesis); the node replays it at start (blocks.md §8) |
| `peers.json` | address table (p2p.md §9) |
| `bans.json` | banned IPs and their expiry |
| `LOCK` | prevents two nodes from sharing the directory |

To resync from scratch, stop the node and move `blocks.dat` aside (or delete it).

Use a separate data directory for each network. The default data directory is the same
for every testnet generation, so after a reset the node finds the old store there: a
store of another network or genesis is refused ("wrong network data directory"), and so
are stores written before the v3 store format, which are never migrated: a store
without a file header ("format 0", written before 2026-09-27) on testnet or mainnet, and
a "format version 1" store on any network. In each case the node starts only after
`blocks.dat` is moved aside; it then resyncs from its peers. Regtest still reads a
format 0 store as it is.

## 5. Mining

```sh
blacksilk-miner --node 127.0.0.1:29333 --rpc-cookie <node data dir>/rpc.cookie \
    --address <testnet address> [--threads N] [--light] [--prebuild] [--build-threads N]
```

- **Full mode** needs about 2.3 GiB of RAM (the 2 GiB dataset plus about 0.3 GB). It
  is much faster per hash (§12.1).
  - The dataset is built at start and again at every RandomX key switch (heights
    2113, 4161, …), on `--build-threads` background threads (default: a quarter of
    `--threads`, at least 1). Build times are in §12.1.
  - **Without `--prebuild` (the default):** at start and at a key switch the miner
    builds the key's light cache (about 1 s) and mines in light mode until the
    dataset is ready, then in full mode. The old dataset is freed first, so the peak
    stays at about 2.3 GiB. Hashing never stops for the build, but runs at light-mode
    speed meanwhile.
  - **With `--prebuild`:** during the 64 blocks before a switch, when the next key's
    block already exists, the miner reads its id from the node (`/blocks`, once per
    template height and parent) and builds the next dataset in the background while
    it mines. At the switch it swaps it in and keeps full-mode hashing. The previous
    dataset is kept for 144 blocks after the switch, for a reorganization back across
    it. Peak about **4.4 GiB** (two datasets and a cache). If the allocation fails,
    the miner falls back to the light-mode bridge above.
  - The template's key (`seed_id`) is always the one hashed with; a prebuilt dataset is
    used only if its key matches exactly.
- **Light mode** needs 256 MiB and no dataset, but is much slower per hash. With
  `--prebuild` it builds the next key's cache before the switch.
- **Errors:** an unreachable or busy node, or a template the miner cannot use (for
  example a transaction kind an outdated miner cannot decode), is logged and retried
  every 5 s. The miner exits with status 78 only when the configuration is wrong (a
  payout address not valid on the node's network, or an unknown network); the systemd
  unit does not restart it then (`RestartPreventExitStatus=78`).
- The miner logs its hash rate at info level every minute.
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
   connected to one machine. When D reaches the tip, restore each wallet from its 27
   seed words against D:

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

Record the results as an evidence directory under `docs/evidence/` and link it from
[STATUS.md](STATUS.md) (AUDIT.md is a historical log and is no longer updated).

### 7.1 Supply audit (closed trial only)

v1 amounts are hidden and spends are unlinkable, so nobody can compute the
circulating supply from the chain. In a closed trial where **every** wallet is kept,
the sum of all wallets can be compared with the chain's emission: an end-to-end
inflation check (validation item V14; review R15-7). On a public network it is
impossible, because not every wallet can be collected.

**Rules for the trial:**
- Every wallet that receives coins is part of the set, **miner payout wallets
  included**. Do not delete, re-create or "clean up" any wallet during the trial. One
  lost wallet makes the check impossible (its value shows as a positive difference).
- Pay only addresses of wallets in the set.
- Back up every wallet file (and its password) at the start.

**Procedure (at the end, and once in the middle):**
1. Stop all miners and wait until every node reports the same `tip`.
2. Collect every wallet file on one machine with a synchronized node. Passwords go in
   per-wallet files (one password per file, deleted afterwards) or are typed at the
   prompts.
3. Build the tool from the trial commit, then run it with every wallet listed:

   ```sh
   cargo build --release -p blacksilk-supply-audit
   blacksilk-supply-audit --node 127.0.0.1:29333 \
       --wallet miner-a.wallet --password-file miner-a.pw \
       --wallet miner-b.wallet --password-file miner-b.pw \
       ... \
       --expect-complete --json > supply-audit-<height>.json
   ```

   Run it again without `--json` for the readable form. `--height H` audits at an
   earlier block (for example the height agreed for the mid-trial check); wallets are
   rewound to it in memory.
4. Record the JSON output, the node's `/info` and the `git` commit of the build as
   evidence. The run passes when the exit code is 0 and `total_difference` is 0.

**What it does.** It syncs each wallet in memory to one block `H` (the node's height by
default), refuses to compare unless every wallet ends on the same block id as the node,
and checks that this block is still on the node's chain at the end. It never writes
wallet files unless `--save` is given, and never submits or rebroadcasts a
transaction. It also scans blocks `1..=H` itself and checks, from public fields:
`generated` against the emission formula (and the node's `/info` when `H` is the tip),
`Σ coinbase = generated + Σ fees` (fees go to miners, none are burned), and the PX pool
`Σ bridge_in − Σ bridge_out`, which stays ≥ 0 block by block.

**What it compares:**
- `v1_difference = generated − px_pool − Σ v1` and `px_difference = px_pool − Σ PX`.
- Counted: outputs and PX records **unspent on chain at `H`**, each once even when
  two wallets know it (duplicates are reported). Immature coinbase, outputs younger
  than 10 blocks and outputs reserved by an unconfirmed transaction are counted (they
  exist on chain) and shown separately. The change of an unconfirmed transaction is not
  counted (it does not exist yet); the mempool plays no role. PX contract records count
  once their commitment is on chain.

**Reading the result (exit code):**
- `0`, all differences zero: the listed wallets account for every coin.
- `3` (with `--expect-complete`), positive difference: value is held outside the set.
  Expected causes: a wallet missing from the list (the difference is exactly its
  holdings), a payment to an address nobody in the set owns, a payment to a subaddress
  beyond a wallet's scan window, or an output a wallet rejects as malformed.
- `2`, alarm: a chain check failed, or the wallets hold **more** than the chain
  created. Treat it as a possible inflation bug: halt and follow
  docs/testnet-incident-response.md.
- `1`: the audit could not run (wrong password, node still synchronizing, wallets on
  different blocks, a reorganization during the run). Fix the cause and rerun.

**Limitations.** The PX part is tested only with an empty pool: the automated test
(`cargo test -p blacksilk-supply-audit`) does no PX proving. The audit trusts the
node for proof of work, like the wallet. It is a functional check of the trial, not
proof that the supply is sound in general.

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

**Warm-up.** A labnet starts at the genesis difficulty (1 on regtest). Two miners
from there mine in lockstep and split into deep equal-work branches
(docs/evidence/labnet-reorg-2026-09-27), which says nothing about the network at a
working difficulty. So the first miner mines alone until the difficulty nears its
equilibrium: the warm-up ends when the mean interval of the last `--warmup-window`
blocks (default 30), as first seen by node 0, is at least `--warmup-ratio` (default
0.75) of the target block time, or after `--warmup-max-mins` (default 60) without
meeting it. Then the second miner starts, and `--duration-mins` counts from there.
With two miners the hash rate doubles, so blocks come faster than the target until
the difficulty rule has followed (about one 75-block window). `--no-warmup` starts
both miners at once.

**Reorganization metrics.** `reorganizations`, `max_reorg_depth` and `reorg_depths`
count only after the warm-up. The warm-up's are in `warmup_reorganizations` and
`warmup_max_reorg_depth`. `reorgs_by_phase` splits all of them (and
`blocks_found_by_phase` the miners' found blocks) into `warmup`, `connected`,
`partition`, `heal` (the first 60 s after a partition heals) and `final` (the end
checks), by the log position at each phase change.

**Evidence runs.** `summary.json` has `evidence: true` only if the checks passed, the
warm-up reached its criterion, the miners ran with `--prebuild`, and the measured
phase lasted at least 10 minutes; `evidence_notes` lists what is missing. Shorter
runs are not evidence. `--evidence` refuses to start with `--duration-mins` below 10
or with `--no-warmup`, turns on `--prebuild`, and exits with status 1 unless the run
is evidence.

**Output:** `summary.json`, `metrics.csv` (every 15 s, with the phase in the last
column), `journal.log`, and each process's log.

## 9. Monitoring and troubleshooting

| Symptom | Check |
|---|---|
| `peers: 0` | Firewall (TCP 29334); at least one `--peer` or `--seed`; `bans.json` |
| `header_height` > `height` for long | Bodies still downloading; watch the log for timeouts |
| `configuration error` at start | Typos in the TOML are errors by design (unknown keys are refused) |
| `… is in use by another node` | Another node uses the same data directory |
| Wallet `WrongNetwork` | Wallet and node on different networks |
| Wallet `insufficient unlocked funds` | Coinbase needs 60 blocks, other outputs 10 |
| A transfer never confirms | Run `sync` again later: the wallet checks on the same transaction every 20 blocks (`/tx/status`), sends it again at most once and only after the network has dropped it (2 190 blocks, docs/px.md §12), and releases its funds itself if the node finds it invalid. Use `clear-pending` only if the transaction certainly never left the wallet (docs/px.md §12) |
| `WARN … reorganization: disconnecting N block(s)` | A reorganization of 10 or more blocks: follow docs/testnet-incident-response.md |
| `block store: … corrupt record at offset … followed by valid data` at start | Real corruption in `blocks.dat`, or (rarely) a crash while writing a block whose data contains a record-shaped byte string; a plain crash is repaired by the node itself. Back up the data directory, then start once with `--repair-store` (logged as a warning; remove the flag afterwards): the damaged part moves to `blocks.dat.damaged-<time>` and the node downloads the dropped blocks again (docs/blocks.md §8) |
| The node exits with `block store write failed: free disk space / check the disk` | Several block writes in a row failed, or one could not be undone: the disk is full or failing. The node stops instead of re-downloading bodies it cannot store. Free space or fix the disk, then restart; it resumes from the last stored block |
| The node exits with status 65 and `applying block … at height …, which passed validation, failed` | A bug in the node: a valid block did not apply. The block is not marked invalid, and systemd does not restart the node (§4.2). Keep the data directory and the log, report the block id, and do not restart in a loop: the same block fails again. To run on without it, back up the data directory and start once with the `--invalidate-block <block id>` the message ends with (next row) |
| A block must not be followed (the halt above, or an incident notice naming a block) | Start once with `--invalidate-block <block id>` (the full 64-hex id; repeatable). The node logs `block … is marked invalid by the operator` and starts on the best other branch, or on the block's parent. The verdict is stored in `blocks.dat`, so the flag is not needed again; the node refuses the block and its descendants, however much work they carry, until `--reconsider-block <block id>` cancels it (for example after upgrading to a fixed build). Node policy, not consensus: other nodes are not affected (docs/blocks.md §8) |
| `configuration error: --invalidate-block …: expected a block id of 64 hex characters`, or `--invalidate-block …: the genesis block cannot be invalidated` (status 2) | A shortened or mistyped id (use the full id), or genesis; nothing was written |
| `block store: N block(s) invalidated by the operator` at start | The operator verdicts in force; `--reconsider-block` cancels one |
| `SubmitError::Store` in the log, node still running | A single failed block write, undone; the block is downloaded again. Repeated failures stop the node (row above) |
| `N stored block(s) without a stored parent were not replayed` at start | After a failed write: harmless, the node downloads them again |
| `N stored block(s) descend from blocks found invalid` at start | Harmless: blocks refused before the restart are refused again |
| `block store: … wrong network data directory` at start | The data directory holds another network's (or an old testnet's) store. Use a separate data directory per network, or move `blocks.dat` aside to resync (§4.5) |
| `block store: … format 0, no file header` or `… format version 1` at start | A store from before the v3 store format; it is never migrated. Stop the node, move `blocks.dat` aside and start again to resync (§4.5). `--repair-store` does not apply |
| `block store: … damaged file header` or `… not a block store` at start | The first 48 bytes of `blocks.dat` are damaged, or the file is something else. Back up the data directory, move `blocks.dat` aside and resync |
| `block store: … record at offset … is not valid` or `… unknown record type` at start | A record with a correct checksum that this build cannot read: the store was written by a newer build (run that build) or is corrupt. Nothing is truncated; back up the data directory, then move `blocks.dat` aside to resync |

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
| `px-deploy --vault` (or `--program F.elf --budget … --out-words N`, one `--budget` and one `--out-words` per `--program`) | Registers a private contract, paid with v1 funds. `--out-words` is the exact number of public output words each call of that function publishes (contracts.md §5); check it with a dry run of the function before deploying, because a wrong count makes every call invalid |
| `px-contracts` / `px-records` | Deployed contracts / contract records this wallet holds |
| `px-vault-lock --contract C --amount A [--secret S] [--deliver-to PXADDR]` | Locks PX funds in the reference vault under a secret; the record goes to the claimer |
| `px-vault-claim --record CM --secret S [--to PXADDR]` | Claims a vault record privately; the fee comes from PX or v1 funds |
| `px-share --record CM --to PXADDR` / `px-import --share HEX` | Shares a contract record off chain / imports one |

Contract tooling is described in px.md §13. **The reference vault is a demonstration
contract, not production-ready and not trustless.** It is not an HTLC. The vault
program supports a timeout and refund (contracts.md §8), but `px-vault-lock` sets no
timeout, so the wallet's locks have no refund path; the locker also knows the secret
(and can claim), and it is not a trustless swap. A
record the locker delivers to someone else is kept only in the locker's wallet file
and is not recovered by restoring from the seed (px.md §13.4).

Every PX transaction pays exactly the standard PX fee, a consensus rule:
`2 × MAX_PX_TX_SIZE` = 8 912 896 atomic units (≈ 0.089 BLK). So fees do not
fingerprint transactions or wallets.

**Spendability.** A received record becomes spendable once the canonical anchor reaches
it: the highest multiple of 16 at least 3 blocks below the wallet's tip (px.md §11.4),
so within 18 blocks of its confirmation (about 36 minutes at 120 s).

**Privacy:** px.md §12 and `docs/reviews/privacy-review.md`.

**Capacity:** the 8 MiB block PX budget holds 3 transfers or vault calls at the
measured proof sizes (4 × 2.18 MB exceeds it), fewer for wider shapes: an estimated 2
for a call with two functions, and 1 at the 4 MiB `MAX_PROOF_BYTES` cap. The widest
shape is not yet measured (aggregation-study.md).

## 11. Security notes for operators

- **The RPC must stay on loopback.** Every request needs the node's cookie (§4.2), but
  the connection is plaintext HTTP: on any other path the cookie and every request can
  be read. `/block` and `/tx` also cost CPU to validate. The node warns at start when
  its RPC is bound to a non-loopback address. To reach it remotely, use SSH, a VPN or
  Tor, and add the name used to `--rpc-allow-host`.
- **Protect the cookie like a password while the node runs.** Anyone who can read
  `rpc.cookie` can use the RPC; that includes malware running as the node's user.
- **Use your own node for your wallet.** Rings are chosen from the wallet's own
  output index, so a remote node does not learn ring members, but it does learn your
  IP address, your scan start (the wallet's birthday), when you send (`/distribution`
  then `/tx`) and which transaction came from your IP (blocks.md §9). The wallet has no
  Tor or TLS support: its RPC connection is plaintext HTTP, so anyone on the path sees
  the same.
- **P2P encryption is unauthenticated.** It protects against passive observers only
  (p2p.md §1). An active man in the middle can also inject invalid messages under the
  peer's address, so that the victim bans the impersonated peer's IP for 24 hours, and
  can eclipse a node whose connections it controls.
- **Treat the testnet wallet file and its 27 seed words like real keys.** Keys reused on a
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
| Miner, full mode | 2 GiB dataset plus about 0.3 GB; about 4.4 GiB peak with `--prebuild` | Dataset build about 180 s with 8 threads (179 s measured under load), about **20 minutes with 1 thread** (1,217–1,219 s measured, 2026-09-27); hashing about 100 ms per hash per thread (measured under load) | The build is **repeated at every RandomX key switch** (heights 2113, 4161, …). It runs in the background: the miner mines in light mode meanwhile, or, with `--prebuild`, builds before the switch (§5) |
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
  connections. **Block 29333** (RPC) from outside: it must stay on loopback (the
  default). The cookie authenticates requests, but the RPC is plaintext HTTP (§11).
- **Several devices behind one NAT** reach other nodes from one public IP. Without
  `--allow-private`, a node accepts at most `max_per_ip` = 2 inbound connections from
  one IP, and a ban of that IP (24 hours, after misbehaviour) shuts out every device
  behind it (bans are per exact IP, N-5). Prefer outbound `--peer` connections from
  such devices, and spread the trial over different networks.
- **Tor:** see §4.3, including the inbound defect N-6.
- **Wallets:** run each wallet against its own node on the same machine. The wallet's
  RPC connection is plaintext HTTP with no Tor or TLS support.

### 12.4 Backup and recovery

- **Back up the whole data directory and every wallet file,** not only the 27 seed words.
  Restoring from the seed does **not** recover:
  - the stored rings of pending or earlier spends (docs/reviews/wallet-review.md,
    W-5 residual): a later spend of the same output may then use a new ring, which the
    key image links to the earlier one;
  - contract records this wallet created and delivered to someone else (the
    creator's copy lives only in the wallet file, px.md §13.4);
  - contract records addressed to the wallet before its restore height.
  - the secrets of vault locks made with `--secret`, `--secret-file` or
    `--secret-prompt` (a derived secret is recovered for a vault record the wallet holds,
    px.md §13.4).
- **A crash or power loss:** restart the node on the same data directory. A torn last
  record is truncated automatically; the node then re-validates every stored block,
  including every PX proof (about 0.2 s each), so restarts become slower as the chain
  grows (PX-F3).
- **Corruption in the middle of `blocks.dat`:** the node refuses to start. Back up the
  data directory, then start once with `--repair-store` (§9, blocks.md §8).
- **A full or failing disk:** free space or replace the disk, then restart (§9).
- **Resync from scratch:** stop the node, move `blocks.dat` aside, start again.
- **A halt that repeats at every start** (`applying block … which passed validation,
  failed`): the stored block fails to apply again because the replay rebuilds the same
  state (blocks.md §8). Keep the data directory and report the block id
  (docs/testnet-incident-response.md); resyncing reaches the same block. An operator
  override (`--invalidate-block`) is planned, not implemented.

### 12.5 Testnet reset

The reset procedure and the rollback are in docs/testnet-reset-plan.md §4 and §6; the
trial's checks and the evidence to return are in docs/testnet-v2-validation.md. A reset
always uses a new network id; never reuse one for a different genesis.

### 12.6 Known limitations that affect operators

- **Proof of work gives no honest-majority guarantee against outsiders.** The PoW is
  exactly Monero's RandomX (`rx/0`). Stock JIT miners (for example xmrig) and rented
  `rx/0` hash rate are roughly 50–100× faster per core than the project's safe-Rust
  miner, and the no-`unsafe` policy rules out a JIT here. Anyone who points such a
  miner at the network can out-mine all honest devices and reorganize the chain.
  The controlled trial relies on its peers being configured by hand and on no one
  doing this; its PoW security is nominal (reviews R1-C2, R15-2). The mainnet choice
  (standard RandomX, a BlackSilk-specific configuration, or an optional reviewed JIT
  miner) is an open owner decision.
- Every block body and its undo data stay in memory (PX-F1, PX-F2); memory grows with
  the chain.
- Every restart re-validates every block, including every PX proof (PX-F3).
- At every RandomX key switch a full-mode miner without `--prebuild` mines in light
  mode (much slower) for the 3 to 20 minutes of the dataset build (§5). The prebuild
  and the light-mode bridge are tested with a short epoch (16 blocks, lag 4; `miner`
  tests); a full-mode miner has not yet crossed 2113 with the network's parameters.
- No seed nodes; peers are configured by hand.
- Open P2P defects (docs/reviews/completion-readiness-2026-09-26.md §2–§3; the
  current list is in [STATUS.md](STATUS.md)). N-4 (unbounded pre-handshake
  connections, fixed in `12ce4cb`: handshakes count against the limits) and N-11
  (fixed in `54c4827`: invalid signatures are penalized when every ring member is at
  least 60 blocks deep, p2p.md §10) are closed. Still open:
  - N-5: bans are per exact IP, so they are easy to evade and hit every device behind
    one NAT;
  - N-6: inbound Tor peers share `127.0.0.1` (§4.3);
  - N-9: no eviction of inbound peers when the inbound slots are full;
  - N-12: memory growth.
- Peers are not authenticated (§11).

### 12.7 What the trial can and cannot show

- **Anonymity:** v1 ring anonymity among only seven participants who all mine is not
  representative of a production anonymity set; the trial tests mechanics, not
  anonymity. The same holds for the PX pool, whose anonymity set is only the records
  the trial creates.
- **Origin of a PX transaction.** A PX transaction is about 2.2 MB (a transfer) to
  2.7 MB (a vault call); a v1 transfer is a few kB. No transport hides a 2.2 MB upload
  from the origin's ISP, or from its Tor guard: an observer of a node's own link sees
  that it sent a PX transaction, even over Tor. Dandelion++ helps only against spy
  nodes, and on PX paths its protection is weaker than on v1 paths (an origin is named
  first about 3.6 times as often in a simulation, dossier 33 §3.4). Padding does not
  remove the PX-versus-v1 distinction; smaller proofs would (dossier 33 §3.7,
  docs/reviews/phase2-2026-09-27/research/33-dandelion-network-privacy.md).
- **Security:** the trial shows operation, not security. The security assumptions are
  listed in docs/reviews/assumptions.md; the zero-knowledge claim is statistical and
  conditional, and its remaining assumptions are in docs/reviews/zk-coverage.md.

### 12.8 Troubleshooting

See §9, and docs/testnet-incident-response.md for anything that looks like a
consensus, security or privacy problem.
