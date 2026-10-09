# Mining BlackSilk regtest with xmrig (through tools/stratum-bridge)

How to mine BlackSilk **regtest** blocks with a locally built xmrig, through the
loopback stratum bridge in `tools/stratum-bridge`. This is how the pre-freeze
xmrig compatibility gate was run; its results are in
[the gate evidence](../evidence/xmrig-gate-2026-10-09/README.md).

**What this is not.**
- `blacksilk-stratum-bridge` is an evidence and test tool. It is not a production
  pool, it serves regtest only, and it binds to loopback addresses only. It is not
  part of the release package (`tools/release-build.sh` does not build it by
  default).
- The project does not distribute an xmrig binary or an xmrig patch. You build
  xmrig yourself, from upstream source, with the change described below.
- A stratum server for public networks and a pinned xmrig build are planned after
  the consensus freeze. Neither exists yet. Until then, `blacksilk-miner` (solo,
  through the node's `/template`) is the supported miner.

## 1. The xmrig change (`rx/blacksilk`), in prose

BlackSilk's proof of work is RandomX **v1** with one parameter changed: the
Argon2 salt is `BlackSilk/RandomX/v1` (20 bytes) instead of Monero's
`RandomX\x03`. Everything else (program size, instruction frequencies, AES keys,
dataset and cache sizes) is the `rx/0` configuration. The PoW input is the
47-byte mining blob with the nonce at byte 39 ([consensus.md](../consensus.md) §3).

The gate used xmrig v6.26.0 with a small local change in six files:

1. a new algorithm id `rx/blacksilk` in the algorithm enum, name table, alias table
   and algorithm list (a RandomX-family id with `rx/0`'s scratchpad sizes and an
   unused coin byte);
2. a RandomX configuration derived from xmrig's **v1 base configuration**, whose
   constructor sets only the Argon2 salt to `BlackSilk/RandomX/v1`;
3. the mapping from that algorithm id to that configuration in `RxAlgo::base()`
   (without it xmrig silently falls back to the `rx/0` configuration, the wrong
   salt);
4. for the gate only, the donation level set to 0 (default and minimum), so xmrig
   never opens a donation-pool connection.

**v1 versus v2.** xmrig 6.26.0 also ships RandomX v2 (`rx/2`). BlackSilk uses v1,
so the configuration must derive from the v1 base, never from the Monero v2
configuration. A later xmrig release may restructure these classes; the change
has only been checked against v6.26.0.

Check a build before mining: xmrig's built-in benchmark `--bench=1M --algo=rx/0`
must reproduce xmrig's own reference hash sum (the shared v1 code path is
intact), and `--algo=rx/blacksilk` must give a different sum (the salt is active).
The gate evidence records both.

## 2. Running it (regtest, one machine)

Build the node, the bridge and a wallet from a clean tree:

```
bash tools/release-build.sh -p blacksilk-node -p blacksilk-stratum-bridge -p blacksilk-wallet
```

Start a regtest node and get a payout address:

```
blacksilk-node --network regtest --data-dir <dir> --no-p2p
blacksilk-wallet -w <wallet file> --node 127.0.0.1:39333 --rpc-cookie <dir>/rpc.cookie create --network regtest
blacksilk-wallet -w <wallet file> --node 127.0.0.1:39333 --rpc-cookie <dir>/rpc.cookie address
```

Start the bridge:

```
blacksilk-stratum-bridge serve --node 127.0.0.1:39333 --rpc-cookie <dir>/rpc.cookie \
  --listen 127.0.0.1:3334 --payout <regtest address> --min-share-diff <about 3 x your hash rate> \
  --log-stratum stratum.log --log-submits submits.jsonl
```

- `--min-share-diff` is a floor on the share difficulty. The bridge verifies every
  share with light-mode RandomX (about 1 s per share at the bridge and the node
  together), so the floor keeps the share rate near one every 3 s.
- The test knobs `--allow-session-diff` and `--negative-control-algo rx/0` are for
  the gate's probe and negative control. The bridge refuses them, and refuses to
  serve at all, on any network other than regtest.

Point xmrig at the bridge with a config like this (the gate's `gate.json` is in the
evidence folder):

```
"pools": [{ "url": "127.0.0.1:3334", "algo": "rx/blacksilk", "user": "x", "pass": "x",
            "nicehash": false, "keepalive": true, "tls": false }],
"donate-level": 0,
"randomx": { "mode": "fast", "1gb-pages": false }
```

Both `"mode": "fast"` (xmrig's 2 GiB dataset) and `"mode": "light"` work. In fast
mode, check xmrig's log for `dataset ready` and for the absence of
`switching to slow mode`: without enough free memory xmrig falls back to light
mode by itself.

After a run, `blacksilk-stratum-bridge recompute --log submits.jsonl --only-agent XMRig/`
recomputes every xmrig submission offline and fails on any mismatch.

## 3. How the bridge fits xmrig to BlackSilk

- **Nonce.** BlackSilk's header nonce is 64 bits (blob bytes 39 to 47, little
  endian). xmrig writes only a 32-bit nonce at byte 39. The bridge puts a fresh
  random 32-bit extranonce at bytes 43 to 47 of every job and rebuilds the header
  nonce as `(extranonce << 32) | xmrig's 32 bits`.
- **Target.** Each job carries `target64 = min(ceil(2^64 / d), 2^64 - 1)` as 16 hex
  characters (little endian). xmrig then logs the job difficulty as `d - 1`. The
  bridge decides acceptance with the full 256-bit check against the block
  difficulty, not with xmrig's 64-bit filter.
- **Seed.** Each job carries the template's RandomX key as `seed_hash`. xmrig
  re-keys from that field alone; in the gate it re-initialised its dataset by
  itself at the first key switch (regtest height 2113).
- **Share floor.** While the block difficulty is below the floor, xmrig submits
  only hashes that meet the floor; a hash that meets the block difficulty but not
  the floor is a valid block that is never submitted. That loss is accepted for a
  test tool.

## 4. Privacy note: xmrig's nonce fingerprint

xmrig counts the low 32 bits of the nonce up from a small per-thread start (in the
gate, never above about 114,000 per job). The bridge randomizes the high 32 bits,
but blocks mined with xmrig remain distinguishable from `blacksilk-miner` blocks,
which start from a random 64-bit nonce. Anyone mining with xmrig through a bridge
like this one publishes that fingerprint in every block. A future stratum server
could reduce it (for example by randomizing more of the nonce space), at some cost
in search space per job; nothing is decided yet.

## 5. Limits of what has been checked

The gate ran on one machine with one CPU (one Argon2 and AES code path in xmrig),
with light-mode verification in the bridge and the node, and crossed one RandomX
key switch. xmrig's fast mode agreeing byte for byte with BlackSilk's light mode is
supporting evidence; it is not the full-mode comparison against the RandomX
reference implementation. See the gate evidence for the counts and the open
limits.
