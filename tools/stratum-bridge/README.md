# blacksilk-stratum-bridge

An evidence and test tool for the pre-freeze xmrig compatibility gate. It is
not part of the release package (`tools/release-build.sh` does not build it),
no node, miner or wallet links it, and it is not a pool: it serves regtest
only.

What it is:

- `blacksilk-stratum-bridge serve`: a Monero-style stratum server bound to a
  loopback address, in front of one regtest node. A locally patched xmrig
  (`rx/blacksilk`) mines through it. Blocks come from
  `blacksilk_miner::build_block`, the PoW input from `BlockHeader::pow_blob`,
  the hash from the node's `RandomXPow::pow_hash`, the target check from
  `check_hash`, and node access from `blacksilk_rpc::Client`. The bridge
  compares every result byte for byte with its own hash and logs a
  `GATE-MISMATCH` when xmrig disagrees; it never retries or rewrites a blob.
- `blacksilk-stratum-bridge recompute --log <submits.jsonl>`: recomputes every
  logged submission offline with `blacksilk-randomx` light mode (stale,
  duplicate and `Busy` ones included) and exits 1 on any mismatch.
- `blacksilk-stratum-probe`: the client that sends the invalid shares xmrig
  never sends (`cases`, `replay`), and a block that misses its difficulty
  straight to the node (`direct-to-node`). Each case expects one exact reply.

The nonce layout: xmrig writes a little-endian u32 at blob bytes 39..43 (kept
zero in the job), the bridge puts a fresh random extranonce at 43..47, and the
header nonce is `(extranonce << 32) | u32::from_le_bytes(<the 4 bytes>)`
(docs/consensus.md §3). The job target is `min(⌈2^64/d⌉, u64::MAX)` as 16 hex
characters of its little-endian bytes; acceptance is decided by the block's
difficulty with `check_hash`.

Test knobs, refused unless the node reports regtest: `--allow-session-diff`
(a login `pass` of `diff=N` sets the session floor, for the probe) and
`--negative-control-algo rx/0` (jobs labelled `rx/0`, no block ever
submitted, results identified as Monero `rx/0` hashes).

Tests: `tests/bridge.rs` (fake proof of work, the same instance in the node and
the bridge) and `tests/real_pow.rs` (the node's real `RandomXPow`, shared by
the node and the bridge, about 1 GiB at the peak; run it with
`--test-threads=1`). No real xmrig has been run against it yet; the gate's
evidence will be recorded separately.
