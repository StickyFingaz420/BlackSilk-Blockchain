# blacksilk-miner

The BlackSilk RandomX miner (safe Rust, the workspace's own RandomX crate). It mines in
one of two modes:

- **Node mode** (the default): templates from your own node's RPC, blocks submitted to
  it. Usage and options: [docs/testnet.md](../docs/testnet.md) §5.
- **Pool mode** (`--pool`): jobs from a BlackSilk Pool over its stratum protocol
  (the pool repository's `docs/PROTOCOL.md`), shares submitted to the pool. Below.

Status of pool mode: complete but requires further testing. It is tested against an
in-process fake pool (`miner/tests/pool.rs`) and in one manual smoke run against the real pool
on synthetic work (below), not with real network work.

## Pool mode

```sh
blacksilk-miner --pool <host:port> --pool-mode pooled|solo --accept-fee <basis points> \
    --address <payout address> [--threads N] [--light] [--build-threads N] \
    [--require-clean-build] [--skip-randomx-self-test]
```

- `--pool`: the pool's stratum port, `host:port`, plain TCP. No scheme
  (`stratum+tcp://` is refused).
- `--pool-mode`: the payout mode you accept, `pooled` or `solo`. No default.
- `--accept-fee`: the fee you accept, in basis points (200 = 2.00 %, at most 10 000).
  No default. It must equal the fee the pool publishes for that mode.
- `--address`: your payout address, sent as the stratum `login`. Its network (testnet,
  mainnet, regtest) is read from the address itself; a build with test-only code
  mines only for regtest addresses, as in node mode.
- `--node`, `--rpc-cookie`, `--refresh` and `--prebuild` do not apply (`--rpc-cookie`
  is refused with `--pool`). No node, RPC cookie or wallet keys are needed.

### Fee and mode: explicit confirmation

The miner sends `pass = "mode=<mode>;fee=<bp>"` in its login. The pool refuses a login
whose mode or fee is not its current policy (`Fee mismatch: …`); the miner then stops
with exit status 78 (a configuration error; the systemd unit does not restart it),
because only you can decide to accept another fee. The login reply's `blacksilk`
object must restate exactly the accepted mode and fee; if it states others, or has no
such object (a pool with `stratum.login_extension = false`), the miner also refuses to
mine (status 78). The miner logs the confirmed mode, fee and policy version at login,
and the pool's notice as a warning: for pooled mode, BlackSilk Pool discloses that
until its first payout snapshot (and during checkpoint gaps) pooled work is
share-only, so no block can be found on it. A pool that marks its work as synthetic
is logged as such: those shares earn nothing.

### What the miner checks

Every message from the pool is untrusted:

- Lines longer than 16 384 bytes, or not UTF-8, end the connection.
- A message that is not JSON of the expected shape, repeats a field, or answers no
  request ends the session. A notification other than `job` is logged and ignored.
- A job is refused, and the session ended, unless: its `job_id` is a canonical decimal;
  its `blob` is exactly 47 bytes, starts with `BSilk/1` and has zero bytes at 39..43
  (the miner's nonce space); its `target` is 16 hex characters and not zero; its
  `algo` is `rx/blacksilk`; its `seed_hash` is 32 bytes. Nothing in a job is used as
  a path or a size.
- The session id must be 16 hex characters. Pool-supplied text (errors, notices) is
  logged with control characters (including the C1 next line U+0085), the line and
  paragraph separators U+2028 and U+2029, and Unicode format characters
  (bidirectional overrides, zero-width characters) replaced and cut at 2 048
  characters. Per-job lines,
  unknown-notification and dropped-share warnings are limited to one per second, with
  a count of the lines held back.

After a session ends the miner reconnects with a pause of 2 s doubling to 60 s (reset
after a session that lasted a minute). It sends `keepalived` after 60 s without
traffic and ends a session after 180 s without any message from the pool.

### Mining

Each job is mined with a RandomX context for its `seed_hash` (light mode with
`--light`, else the 2 GiB dataset, built on all threads at start; at a key switch the
miner mines in light mode while the new dataset is built). Only bytes 39..43 of the
blob are iterated, from a random 32-bit start per job (a start at 0, as xmrig's,
fingerprints the miner); bytes 43..47 are the pool's extranonce and are kept. A hash
is submitted when its last 8 bytes, read little-endian, are below the job's target;
the pool recomputes every share. At most 32 submits are outstanding; a share found
beyond that, or while the queue from the hashing threads (256 events) is full, is
dropped and counted (a full submit window is also warned about). A window that stays
full for 60 s without a reply ends the session (reconnect). The pool's lines are
read only as fast as the miner handles them, so a flooding pool is slowed by TCP flow
control.

### Privacy and security limits

- **No TLS.** The payout address, the accepted fee and every share travel in clear
  text and can be read or altered on the path. For a remote pool, run a local TLS
  client proxy (for example stunnel in client mode) to the pool's TLS port, or a local
  forwarder to its onion service, and point `--pool` at `127.0.0.1:<local port>`. The
  miner warns at start when `--pool` is not a loopback address. It has no SOCKS
  support of its own, and a host name in `--pool` is resolved with the system
  resolver.
- **The pool sees** your payout address, your IP address (unless you connect through
  Tor), your share rate (and so your hash rate) and the `agent` string
  (`blacksilk-miner/<version>`, no OS or CPU details).
- **No job-details check.** The miner cannot see what block a job's mining hash
  commits to (PROTOCOL.md section 7, a design not implemented by the pool): it trusts
  the pool to mine for the network and to pay as stated.
- **Speed.** The safe-Rust RandomX here has no JIT; xmrig with BlackSilk's salt is far
  faster per core. Pool mode makes no claim to compete with it.

### Testing against a real pool

The tests run an in-process fake pool (`cargo test -p blacksilk-miner --test pool`).
For the real pool on synthetic work, build BlackSilk Pool's server from its repository
with its `test-work` feature and start it with its `config/synthetic.example.toml`
(stratum on 127.0.0.1:3333; the pool's README), then either run the miner, for example

```sh
blacksilk-miner --pool 127.0.0.1:3333 --pool-mode pooled --accept-fee 200 \
    --address <regtest address> --light --threads 2
```

or the opt-in test, which mines for 120 s and expects accepted shares:

```sh
BLACKSILK_POOL_TEST=127.0.0.1:3333 cargo test -p blacksilk-miner --test pool -- --ignored
```

Manual run, 2026-10-17, one Windows machine, loopback, the pool at its `dev/phase4-clean`
head built with `test-work` (synthetic work, light-mode validator), the miner a debug
build of this branch in light mode on 2 threads (about 4 H/s):

- `--pool-mode solo --accept-fee 200`: refused by the pool (`Fee mismatch: solo fee is
  300 bp (policy 1)`), the miner exited with status 78 without mining;
- `--pool-mode pooled --accept-fee 200`: login confirmed (mode, fee, policy 1), the
  share-only notice and the synthetic-work warning logged; 10 shares submitted and 10
  accepted in 300 s across 5 jobs (new synthetic tips and a VarDiff change);
- the opt-in test: 7 shares submitted, 6 accepted, 1 rejected (not logged by the test;
  most likely `Stale job` after a synthetic tip change);
- the pool stopped while the miner was connected: the miner reconnected with pauses
  of 2, 4, 8, 16, 32 and 60 s.

This is a smoke run on synthetic work, not evidence for network work, and not a
measurement of performance.
