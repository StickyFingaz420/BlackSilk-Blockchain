# Wallet header feed: cost of a restore check from the genesis (W3-39b)

Internal engineering measurement, one run on one machine; not a benchmark suite.

**Command** (release build, `CARGO_BUILD_JOBS=2`, Windows 10, shared 16 GB machine):

```
cargo test --locked --release -p blacksilk-wallet --lib -- --ignored --nocapture header_feed_cost
```

**What it does.** `wallet::tests_sync::header_feed_cost_for_3000_headers` builds a
regtest mock chain of 3,000 blocks whose difficulty rises above 1, restores a wallet at
height 3,000 and syncs it: the header check reads headers 1 to 2,999 from `/headers`
and checks them from the genesis, then scans block 3,000. It runs twice: with a
stand-in proof of work (link, version, LWMA and timestamp checks only), and with
RandomX light mode computing every sampled hash (the result is then accepted, since the
mock chain is mined with the stand-in). The second run includes building the light-mode
caches of the key blocks it needs (heights 0 and 2,048). The number of sampled hashes
is random (`HEADER_SAMPLES` = 16 expected, plus the first scanned header and the tip;
difficulty-1 headers are never hashed).

**Output (2026-09-28, branch `w3-wsync2`):**

```
stand-in: sync 8.9697ms; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 0
RandomX light: sync 8.1943688s; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 12
```

**Reading.** For about 3,000 headers the feed is 300 KB (600 KB as hex in JSON) in two
requests, and the rule checks take milliseconds; the cost of a restore check is the
RandomX light-mode work (caches and sampled hashes), about 8 s in this run. The
download grows by 100 bytes per header, the RandomX part with the number of key epochs
the sample touches (at most one cache per sampled epoch).
