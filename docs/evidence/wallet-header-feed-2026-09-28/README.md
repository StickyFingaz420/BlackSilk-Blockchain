# Wallet header feed: cost of a restore check from the genesis (W3-39b)

> Historical record (2026-09-28). Superseded where it conflicts with the code: the header is 172 bytes (f5daa0e), so the download grows by 172 bytes per header; parallel header hashing was done afterwards, see [wallet-parallel-pow-2026-09-29](../wallet-parallel-pow-2026-09-29/README.md). Current: [docs/consensus.md](../../consensus.md), [docs/STATUS.md](../../STATUS.md).

Internal engineering measurement, one run per configuration on one machine; not a
benchmark suite.

**Command** (release build, `CARGO_BUILD_JOBS=2`, Windows 10, shared 16 GB machine):

```
cargo test --locked --release -p blacksilk-wallet --lib -- --ignored --nocapture header_feed_cost
```

**What it does.** `wallet::tests_sync::header_feed_cost_for_3000_headers` builds a
regtest mock chain of 3,000 blocks whose difficulty rises above 1, restores a wallet at
height 3,000 and syncs it: the header check reads headers 1 to 2,999 from `/headers`
and checks them from the genesis, then scans block 3,000. It runs twice: with a
stand-in proof of work (link, version, LWMA and timestamp checks only), and with
RandomX light mode computing every hash the check asks for (the result is then
accepted, since the mock chain is mined with the stand-in). The second run includes
building the light-mode caches of the key blocks it needs (heights 0 and 2,048).
Difficulty-1 headers are never hashed.

**Run 1: sampled check only** (the first W3-39b commit: `HEADER_SAMPLES` = 16 expected,
plus the first scanned header and the tip):

```
stand-in: sync 8.9697ms; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 0
RandomX light: sync 8.1943688s; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 12
```

**Run 2: with the dense tail** (RTW3-5: every one of the last 720 headers, plus the
sample below them):

```
stand-in: sync 19.3604ms; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 0
RandomX light: sync 767.7137335s; 2999 headers requested (299900 bytes, 599800 hex) in 2 requests; RandomX hashes so far 736
```

**Reading.** For about 3,000 headers the feed is 300 KB (600 KB as hex in JSON) in two
requests, and the rule checks take milliseconds. The cost of a restore check is the
RandomX light-mode work: with the dense tail about 736 hashes, about 1 s each on this
machine, one at a time, so a restore of a chain at least 720 blocks long spends about
13 minutes in the check (routine checked syncs hash only their new headers). The hashes
are independent and could run on several threads; that is not done yet. The download
grows by 100 bytes per header.
