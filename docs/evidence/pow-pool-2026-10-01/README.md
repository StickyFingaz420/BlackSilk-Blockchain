# PoW hashing pool: header verification timing (W4-POWPOOL, 2026-10-01)

Internal engineering measurement, not an audit. It measures one change:
`CachedPow::compute_parallel` (chain/src/manager/pow_cache.rs) used to start
scoped threads on every call, and the p2p header worker calls it once per
proof-of-work chunk of `pow_threads` headers. Now one thread hashes inline on
the caller's thread, and more threads use a persistent pool owned by the
`CachedPow` (docs/p2p.md §6, item 3).

## What was run

- **Harness:** `chain/tests/pow_pool_bench.rs` (ignored tests), release
  profile. It hashes a batch in chunks of `pow_threads` jobs, one
  `compute_parallel` call per chunk, as `p2p/src/net/headers.rs` does
  (`sync_policy::pow_chunk`; with `seed_lag` 64 the chunk equals
  `pow_threads` here). It times the hashing only, not the chain actor's
  acceptance between chunks.
- **Real RandomX:** `RandomXPow` (pure-Rust light mode, the node's header PoW
  function), 200 header-sized inputs under one key. The key's cache is built
  before timing, as a node keeps its hot keys built. A fresh `CachedPow` per
  `pow_threads` value (so its pool start-up is included in the timing).
- **Cheap headers:** INV-PEN's case, a one-Blake2b stand-in PoW: 300
  one-thread chunks, and a 31-header batch in 2-thread chunks.
- **Builds:** "before" is the harness built on base 48d3d1f (the harness file
  added, nothing else changed); "after" is the same harness at 283300e. Both
  are kept in the scratch dir outside the repo (sha256 `f0d7ce17…` and
  `9863b779…`).
- **Load:** `measure.sh <exe> <tag> <procs> 200 [chain dir]`: 0 or 8 bash
  busy-loop processes, started and stopped by PID by the script. The host has 8
  logical CPUs (Windows 10). Other agents' work may have added ambient
  load; the runs are single samples.
- **Logs:** `logs/` (every figure below is taken from them):
  `before-*.log` and `after-*.log` for this measurement, `rt-ab.log` for
  the second one below.

## Results

Real RandomX, 200 headers, total ms (ms per header):

| pow_threads | idle before | idle after | 8 busy, before (r1 / r2) | 8 busy, after (r1 / r2) |
|---|---|---|---|---|
| 1 | 110,640 (553) | 109,633 (548) | 245,451 / 224,018 | 141,222 / 164,113 |
| 2 | 62,937 (315) | 57,111 (286) | 191,102 / 147,096 | 96,951 / 151,161 |
| 4 | 34,585 (173) | 31,846 (159) | 124,536 / 97,992 | 56,294 / 103,005 |

The digest of the 200 stored hashes is `397a067cf99748da` in every run,
before and after, for every thread count.

Cheap headers (INV-PEN's A/B), ms, three runs each:

| case | idle before | idle after | 8 busy before (r1, r2) | 8 busy after (r1, r2) |
|---|---|---|---|---|
| 300 × 1-thread chunks | 38, 39, 35 | 0, 1, 0 | 32,834, 32,017, 31,576; 15,059, 14,818, 24,392 | 1, 1, 1; 1, 1, 0 |
| 31 headers, 2-thread chunks | 3, 3, 3 | 0, 0, 0 | 2,137, 1,475, 2,771; 1,252, 981, 1,757 | 0, 0, 0; 0, 0, 0 |

Digests are identical before and after (`6b952b4d184bcdee`,
`c409d6a547ac5494`).

## Reading

- **One thread:** the per-chunk spawn is gone. Under load the 200-header
  real-RandomX batch took 141-164 s against 224-245 s before (about 0.3-0.5 s
  less per header); idle the difference is within noise.
- **Two and four threads, real RandomX:** idle 8-9 % faster. Under load the
  first pair of runs shows about 2× faster, the second pair shows no
  difference (151 vs 147 s, 103 vs 98 s). With a hash of 0.5-1.2 s the
  spawn cost is a small share of a multi-thread chunk, and the loaded runs
  vary more than that share; these runs do not show a reliable gain for
  `pow_threads` > 1 under load.
- **Cheap headers:** the 13-130 ms per-chunk cost INV-PEN measured is gone
  (300 chunks: 15-33 s before, 1 ms after, under load). This is what the
  p2p tests' stand-in PoW sees, and the bound on how long a batch of
  already cheap work can be stalled by thread start-up.

## Second, independent measurement (RT-POWPOOL)

The red-team pass ran its own A/B with the same two harness binaries
(`logs/rt-ab.log`), interleaved: three rounds, alternating which build ran
first, at ambient load ("L0"; other agents were busy, which is why the cheap
"before" case varies from 3 to 22 s) and under 8 busy loops ("L8"); 40
real-RandomX headers at pow_threads 1 and 2. ms per header:

| | pow_threads 1, before | 1, after | 2, before | 2, after |
|---|---|---|---|---|
| L0 (r1, r2, r3) | 1015, 894, 893 | 815, 875, 816 | 443, 498, 501 | 516, 456, 487 |
| L8 (r1, r2, r3) | 1622, 1790, 1558 | 973, 870, 829 | 1082, 765, 1165 | 1111, 1059, 1008 |

Digests are identical in every run (`a708129e5a6ddd50` for RandomX). It
reproduces the one-thread gain under load (0.6-0.9 s less per header) and
shows no reliable change at 2 threads.

**RT's observation:** under heavy load, 2 threads were slower per header
than 1 thread after the change (L8: 1008-1111 ms against 829-973 ms). Light-mode
RandomX is memory-bound, and 8 busy loops on 8 logical CPUs (hyperthreads)
leave the second thread little to gain. The default `pow_threads` (every
available thread, `p2p/src/net/config.rs`) is left unchanged. It should be
measured on a real multi-core testnet host before it is tuned.

## Limits

- Single samples under an uncontrolled ambient load; no confidence
  intervals.
- Hashing only: the chain actor's per-chunk acceptance and the p2p plumbing
  are not in these figures.
- One host (8 logical CPUs, Windows). Thread start-up cost differs by OS.
