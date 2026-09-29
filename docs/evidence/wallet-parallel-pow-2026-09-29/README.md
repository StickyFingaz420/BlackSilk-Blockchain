# Wallet header check: parallel proof of work (W3-39c), 2026-09-29

Internal engineering measurement, not an audit.

## What was measured

The restore header check computes the light-mode RandomX hash of the node's last 720
headers (`wallet::DENSE_POW_TAIL`, RTW3-5) and of a sample of the others
(`wallet/src/headers.rs`). Before W3-39c it computed them one at a time, on the calling
thread. Since W3-39c the cheap checks run in order and the hashes they call for are
computed in batches on every available thread. All threads share `RandomXPow`'s one
light cache per key, and each hash builds its own light-mode VM over it.

## Machine and conditions

- Windows 10, 8 logical CPUs, release build.
- The machine was shared with other agents' builds and tests. The "before" run also
  overlapped a 2-job cargo build in this worktree. The figures are indications, not
  benchmarks.

## Results

| Run | Commit | Threads | Hashes | Time |
|---|---|---|---|---|
| `header_feed_cost_for_3000_headers` (restore at 3 000: feed + dense tail + sample) | base `49423b7` | 1 | 741 | 530.5 s |
| same test | W3-39c | 8 | 741 | 82.1 s |
| `dense_tail_pow_720_headers_sequential_and_parallel` (720 headers, cache prebuilt) | W3-39c | 1 | 719 | 410.0 s (570 ms per hash) |
| same test | W3-39c | 8 | 719 | 78.8 s (110 ms per hash) |

In the second test one of the 720 headers has difficulty 1, which every hash meets, so it
is not hashed.

## Commands

```
# before (base binary built at 49423b7)
blacksilk_wallet-<hash>.exe header_feed_cost_for_3000_headers --ignored --nocapture
# after
cargo test --locked --release -p blacksilk-wallet --lib -- --ignored --nocapture \
  --test-threads=1 header_feed_cost_for_3000_headers dense_tail_pow_720
```

## Equality of verdicts

`wallet::tests_sync::parallel_and_sequential_verdicts_agree` checks 10 valid and forged
chains. The forgeries are proofs of work and difficulties placed before, after and
across the 256-job batch boundaries. The one-by-one check and the parallel one (1, 2, 4
and 8 threads) refuse the same header with the same message, or both accept.
`a_parallel_restore_refuses_at_the_forged_block` checks the restore path: the blocks
below a forged header are applied, and none from it on.
