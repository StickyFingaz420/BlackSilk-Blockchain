# R12: Performance and scalability of the whole system (internal review, 2026-09-27)

**Reviewer:** R12. This is internal review, not an audit.
**Tree reviewed:** `f677e55` (includes WIP `7826289`), read-only. No builds were run.
**Scope:** a quantitative resource model of BlackSilk, covering:
- validation cost, block limits, throughput;
- chain growth, node RAM, startup;
- initial sync, propagation, P2P bandwidth;
- mempool, wallet scanning, mining.

For each area it names the binding constraint and the improvements available.

**Cross-references (other reviewers, not re-reported as new):**
- **R9 (RandomX):** light-hash cost, the R9-R2 optimisation programme, per-hop PoW latency (R9-8), rentable Monero hashrate.
- **R10 (storage/node):** R10-1 low-work side bodies kept in RAM; R10-6 PX undo ~4.2 KB/block; R10-7 PX ciphertexts duplicated in RAM.

Where this report overlaps with them, it quantifies at system level and does not claim the finding as its own.

**Evidence tags** (as in the brief):
- **[math]:** mathematically established from constants or struct layouts;
- **[meas: …]:** measured, with the source named;
- **[src]:** read in the source;
- **[est]:** estimate, derived from the measured anchors below;
- **[assumed]:** an assumption, stated;
- **[unknown]:** not known.

---

## 0. Executive summary

**Binding constraints, in the order they bite:**

1. **Node RAM is O(chain), with about 4.5× expansion for v1 data** [src + math].
   - Every body, all undo data and the whole state live in RAM, and the decoded form is much larger than the wire form: a `Point` is 192 B in RAM against 32 B on the wire.
   - There is a fixed floor of about 6 KB of RAM per block, even for empty blocks.
   - Time to exhaust 16 GB of RAM, by scenario:

     | Scenario | Time to 16 GB |
     |---|---|
     | Idle chain | ~10 years |
     | Light testnet use | ~5 months |
     | Moderate adoption | ~16 days |
     | Saturated v1 | ~8 days |
     | Full blocks | ~2.4 days |

   - Spam that fills blocks costs about 0.4 BLK per block, roughly 2% of the block reward, and costs a miner nothing in its own blocks.
2. **Every restart re-validates the whole chain, PX proofs included, on one thread** [src].
   - For one year of moderate use that is about 22 h per restart.
   - For one year of saturated v1 use it is about 4 days.
3. **New-node sync is bounded by pure-Rust light RandomX, 0.45–0.75 s per header** [meas: brief/R9].
   - 1 month of chain: ~34 min on 8 threads.
   - 1 year: ~6.9 h on 8 threads.
   - 5 years: ~34 h on 8 threads.
   - Divide by the thread count; on 1 thread, 5 years take about 11 days.
   - Body validation and download add to this, and dominate in any non-idle scenario.
4. **PX capacity and bytes.**
   - A block holds **3** PX transfers (2.18 MB each), not the "about 4" the docs state. That is 0.025 PX tx/s, or 2,160 per day.
   - One PX transaction is about 1,400× the bytes of a v1 transfer, so even modest PX use dominates chain growth: 0.5 PX per block is about 790 MB/day.
5. **Worst-case block validation time is set by the PX byte budget, not by the v1 weight limit** (new, R12-2).
   - Deploy and PX v1 inputs have weight 0, so an 8 MiB budget of 64-input deploys carries about **12,100 CLSAGs**, roughly 25–50 s of single-thread validation [est].
   - The v1 limit allows at most about 886 CLSAGs, roughly 2.7 s.
   - A miner can build such a block for about 0.17 BLK in fees, paid to itself.
6. **Propagation.** Each hop pays:
   - light-mode PoW, 0.45–0.75 s;
   - full-body transfer, with no compact blocks;
   - re-verification of every v1 signature and range proof, with no v1 verification cache.

   Estimated stale rate: ~3% for empty blocks, ~12% for full ones [est/assumed network].
7. **Wallets.**
   - Wallet sync downloads every full block, PX proofs included, as hex JSON: 2× the chain bytes.
   - The PX commitment tree is rebuilt from genesis on every sync and every spend.
   - PX record scanning costs O(addresses) per record, with ML-KEM key generation inside the loop.
   - The node's `/px/commitments` RPC copies every PX record ever created, ciphertexts included, under the chain lock, on every call (R12-3).

**Testnet verdict (performance only):** acceptable for a trial of a few weeks at low load.
- On a 16 GB node, every limit above is out of reach for light testnet use (S1) for months.
- Before the testnet, three cheap items should land:
  - R12-2: bound the validation cost of the PX budget;
  - R12-3: the O(N)-per-call RPC under the lock;
  - the PX-undo delta (R10-6).
- The "3 PX per block" doc correction (R12-10) should also land before the testnet.
- A mainnet capacity target cannot be set before three things exist: persistent state, snapshot restart and parallel/cached verification.
- A PX throughput target additionally needs lighter proofs or aggregation.

**Order-of-magnitude levers** (§15 has details):

| Lever | Gain | Effort | Consensus |
|---|---|---|---|
| Persistent state + bodies off-RAM + compact output set | RAM O(chain) → O(cache): 100–1000× | L | none |
| State snapshot at restart | restart hours/days → seconds/minutes | M | none |
| Parallel verification (inputs, txs, proofs) | ×cores (4–16×) on IBD, replay, reorg | S–M | none |
| v1 verification cache keyed on the resolved ring | per-hop v1 cost → ~0 | S–M | none |
| Compact block relay | −50% bandwidth; hop time independent of block size | M | none (P2P) |
| Optional full-mode PoW verification at the tip (R9 O7) | hop PoW 0.75 → 0.1 s | S–M | none |
| RandomX interpreter programme (R9 O1–O6) | light 4–7× | M | none |
| Wallet compact-scan RPC | wallet download 50–700× smaller | S–M | none |
| Pruning of the prunable section | disk −78% (v1), −99% (PX) for pruned nodes | M–L | none |
| Query policy / width reduction | PX bytes −35–65%, 3 → 6–9 PX/block | M each + review | CONSENSUS, new identity |
| Recursion/aggregation | PX chain bytes ~3 KB/tx + one aggregate; 10–100× | XL | CONSENSUS |

---

## 1. Inputs to the model

### 1.1 Consensus and policy constants [src]

| Constant | Value | Where |
|---|---|---|
| Target block time `T` | 120 s (regtest 10 s) | `consensus/src/params.rs:48-66` |
| Blocks per day / per year | 720 / 262,800 | [math] |
| RandomX epoch / lag | 2048 / 64 | `consensus/src/params.rs:106-107` |
| `MAX_BLOCK_WEIGHT` | 600,000 | `tx/src/params.rs:59` |
| `COINBASE_RESERVE` | 3,000 | `chain/src/mempool.rs:43` |
| `MAX_PX_BLOCK_BYTES` | 8 MiB = 8,388,608 | `tx/src/params.rs:23` |
| `MAX_BLOCK_BYTES` | 1,000,000 + 8 MiB + 64 KiB = 9,454,144 | `chain/src/block.rs:10` |
| `MAX_BLOCK_TXS` | 10,000 | `chain/src/block.rs:13` |
| `MAX_TX_SIZE` (v1) | 100,000 | `tx/src/params.rs:44` |
| `MAX_PX_TX_SIZE` | 4 MiB + 256 KiB = 4,456,448 | `tx/src/params.rs:17` |
| `MAX_DEPLOY_TX_SIZE` | 1 MiB | `tx/src/params.rs:19` |
| `MAX_INPUTS` / `MAX_OUTPUTS` | 64 / 16 (also for PX and deploy v1 parts) | `tx/src/params.rs:46-48`, `tx/src/px.rs:616-619` |
| Ring size | 16 | `crypto/src/clsag.rs` |
| `FEE_PER_WEIGHT` (v1) | 20 atomic per weight unit | `tx/src/params.rs:57` |
| `PX_FEE_PER_BYTE` (PX, deploy) | 2 atomic per byte | `tx/src/params.rs:25` |
| `PX_STANDARD_FEE` | 8,912,896 atomic (0.089 BLK) | `tx/src/params.rs:31` |
| COIN; initial reward; tail | 10^8; ≈20.03 BLK; 0.6 BLK | `chain/src/emission.rs:4-10` |
| Mempool caps | v1 50 MB, PX 64 MiB (encoded) | `chain/src/mempool.rs:39-41` |
| PX `ROOT_WINDOW`; tree depth | 100; 32 (capacity 2^32) | `px/src/state.rs:26`, `px-core/src/kernel.rs:52` |
| P2P | 8 outbound / 64 inbound; 16 blocks in flight per peer; `MAX_HEADERS` 2,000 | `p2p/src/net.rs:42,96-97`, `p2p/src/message.rs:14` |
| PX relay | 0.2/s per peer (burst 4); 2/s global (burst 10) | docs/p2p.md §rate limits |
| RPC | `/blocks` ≤ 100 blocks and ≤ 64 MiB; `/px/commitments` ≤ 65,536 per call | `rpc/src/lib.rs:17-19,166` |

### 1.2 Measured anchors

| Quantity | Value | Source |
|---|---|---|
| PX transfer proof | 2,178,213–2,180,408 B; prove 44.6–45.2 s; verify 0.207–0.212 s | [meas: `C:\bszkeval\bench-optA-summary.txt`, AUDIT R13] |
| PX vault (kernel + 1 function) | 2,687,952–2,688,822 B; prove 52.7–53.0 s; verify 0.254–0.265 s | same |
| Prover peak memory | 3,771 MB | same |
| Full validation of one 1-in/2-out v1 transfer (CLSAG + single BP+ + ring resolution) | 6.8 ms | [meas: `chain/tests/manager.rs:965` `mempool_revalidation_cost_per_transaction`] |
| Extension-path revalidation | 6.3 µs per transfer | [meas: docs/blocks.md §7] |
| RandomX light | 450 ms (idle) to 750 ms (under load) per hash per thread | [meas: brief/R9] |
| RandomX full | ~100 ms per hash per thread; dataset 179 s on 8 threads, ~20 min on 1 | [meas: brief] |
| RandomX cache build | ~0.6 s, 256 MiB | [src: `consensus/src/pow.rs:52`] |
| Replay of near-empty blocks | 16 blocks in 28 ms (≈1.75 ms/block; old R4 figure) | [meas: AUDIT R4] |

### 1.3 Derived unit costs [est]

The 6.8 ms anchor is the only v1 crypto measurement.

**Split, estimated from curve25519-dalek characteristics:**
- CLSAG verification with a 16-member ring: per member, a 3-term and a 2-term vartime MSM plus one hash-to-point (`crypto/src/clsag.rs:275-286`). That gives **t_clsag ≈ 2–4 ms per input**; this report uses 3 ms.
- Single 2-output BP+: ~3 ms. Inside a block batch (`crypto/src/bulletproofs_plus.rs:529`), the marginal cost is **t_bp ≈ 0.3–1 ms** per 2-output proof; this report uses 0.5 ms.

**Needed:** a `cargo bench` split of CLSAG, single BP+ and batched BP+ at 1, 10 and 380 proofs (§19).

**PX verification:**
- this report uses **t_px ≈ 0.235 s** (the midpoint of the measured range);
- Plonky3's `parallel` feature is on (`zk/Cargo.toml`), so this is wall-clock time on a multi-core machine. The single-core figure is [unknown];
- adversarial proofs (ZK-F4, known) are [unknown]. A plausible upper bound is proportional to proof bytes: ≤ 4 MiB / 2.18 MB ≈ 1.9×, so ~0.45 s [est].

### 1.4 Sizes on the wire

**v1 transfer size** (`docs/transactions.md` §4.2, `tx/src/builder.rs:103-122`) [math]:

```
size(n,k) = 3 + n·(32 + ring_bytes) + 1 + k·121 + fee_varint(3) + 32·n + BP(k) + 576·n
BP(k)     = 32·(6 + 2·log2(64·M)),  M = next_pow2(k)
weight    = size + (M>2 ? (320·M − BP)·4/5 : 0)
```

- `ring_bytes` ≈ 34: the first index plus 15 deltas of 1–3 bytes [assumed; it grows slowly with the output count].

| Shape | Bytes | Weight | Per block (597,000 weight) | tx/s |
|---|---|---|---|---|
| 1-in/2-out | 1,563 | 1,563 | 381 | **3.2** |
| 2-in/2-out | 2,237 | 2,237 | 266 | **2.2** |
| 64-in/2-out | 44,025 | 44,025 | 13 (≈ 886 inputs) | — |
| 1-in/16-out | 3,449 | 6,879 | 86 (1,390 outputs) | — |

`standard_fee(1,2)` = 20 × 1,723 = 34,460 atomic (0.00034 BLK) [math].

**PX:**
- transfer tx ≈ 2.20 MB; vault ≈ 2.70 MB; ciphertext 1,241 B per output; 2 outputs and 2 nullifiers per tx [meas/src].
- Capacity per block:
  - ⌊8,388,608 / 2.20 MB⌋ = **3** transfers;
  - ⌊8,388,608 / 2.70 MB⌋ = **3** vault calls;
  - a maximum-size PX tx (4,456,448 B) fits **1** per block [math].
- **Empty block:** header 100 B + count + coinbase ≈ 93 B, plus the store record (12 + 32 B) ≈ **240 B on disk** [math].

---

## 2. Throughput

| Layer | Formula | Value |
|---|---|---|
| v1 tx/s | (597,000 / size) / 120 | 3.2 (1-in/2-out), 2.2 (2-in/2-out) |
| v1 tx/day | ×720 | 275k / 192k |
| PX tx/s | ⌊8 MiB / size⌋ / 120 | **0.025** (2,160/day, 788k/year) |
| Combined max | | ≈ 3.2 v1 + 0.025 PX tx/s |

**Comparison [assumed]:** Monero processes roughly 25–30k tx/day, so the v1 layer has ~7–10× headroom. The PX layer is far below any private-payments use (0.025 tx/s).

**Attacker cost to fill a block** [math]:
- **v1:** 597,000 × 20 = 11.94M atomic = **0.119 BLK**.
- **PX:** 3 × 0.089 = **0.267 BLK**. The proofs also need ~135 CPU-s per 120 s (1.1 cores) and 3.8 GB.
- **Deploys:** 8 MiB × 2 = 16.8M atomic = **0.168 BLK**, and they need **no proof**.

Per byte, the PX/deploy space is **10× cheaper** than v1 space: 2 atomic per byte against 20 per weight unit. Deploys are the cheapest way to grow the chain and node RAM: ≈ 20 BLK per GB, against ≈ 200 BLK per GB for v1.

Filling every block costs ≈ 0.39 BLK/block ≈ 280 BLK/day. That is ≈ 1.9% of issuance (≈ 14,400 BLK/day). Fees on self-mined blocks return to the miner.

---

## 3. Per-block validation cost

`validate_block_transactions_cached` (`tx/src/validate.rs:724-936`) runs on **one thread**, under the chain lock, in this order:
- structure;
- root;
- weight/budget;
- balance;
- uniqueness;
- ring resolution + CLSAG, input by input;
- one BP+ batch;
- PX proofs, skipped if the tx id is in the mempool.

**Formula:**

```
t_block = t_fixed + N_in·t_clsag + N_bp·t_bp + N_px_uncached·t_px
```

- `t_fixed` ≈ 1–2 ms (coinbase, PX state apply with 32 Poseidon2 for the root, the undo clone, the mempool pass).

| Scenario (per block) | N_in | N_bp | N_px | t_block, cold (replay/IBD) | t_block, at tip (PX cached) |
|---|---|---|---|---|---|
| S0 idle: coinbase only | 0 | 0 | 0 | ~2 ms | ~2 ms |
| S1 light testnet: 5 v1 (1-in) + 0.05 PX | 5 | 5 | 0.05 | ~30 ms | ~20 ms |
| S2 adoption: 35 v1 (1.6 in avg) + 0.5 PX | 56 | 35 | 0.5 | ~0.30 s | ~0.19 s |
| S3 v1 saturated: 381 × 1-in/2-out | 381 | 381 | 0 | ~1.33 s | ~1.33 s |
| S4 full: S3 + 3 PX | 381 | 384 | 3 | ~2.0 s | ~1.33 s |
| S5 v1 input-max: 13 × 64-in | 886 | 13 | 0 | ~2.7 s | ~2.7 s |
| **S6 deploy-CLSAG block** (R12-2) | **~12,100** | 189 | 0 | **~25–50 s** | **~25–50 s** |

The S6 construction is in R12-2 (§14).

---

## 4. Chain growth (disk, `blocks.dat`)

**Formula:**

```
bytes/block = 240 + N_v1·(1,563 + (ins−1)·674) + N_px·2.2 MB
```

| Scenario | Per block | Per day | Per year | 5 years |
|---|---|---|---|---|
| S0 idle | 0.24 KB | 0.17 MB | **63 MB** | 0.3 GB |
| S1 light testnet | 118 KB | 85 MB | **31 GB** | 155 GB |
| S2 adoption | 1.17 MB | 842 MB | **307 GB** | 1.5 TB |
| S3 v1 saturated | 594 KB | 428 MB | **156 GB** | 0.78 TB |
| S4 full (3 PX) | 7.2 MB | 5.2 GB | **1.9 TB** | 9.5 TB |
| S4′ full (8 MiB deploys) | 9.0 MB | 6.5 GB | **2.36 TB** | 11.8 TB |

**PX share** [math]:
- in S1, PX is 93% of the bytes (0.05 × 2.2 MB = 110 KB of 118 KB);
- in S2, it is 94%.

**The chain size is a PX-proof problem.**

**Prunable share:**
- **v1:** BP+ 640 + CLSAG 576 = 1,216 of 1,563 B = **78%** of a 1-in/2-out transfer is in the prunable section (`docs/transactions.md` §4.4).
- **PX:** ~99% of a PX tx is proof.

**Tree capacity:** 2^32 commitments at ≤ 6 per block last about 2,700 years. It does not bind [math].

**fsync:** one `sync_data` per stored block (`chain/src/store.rs:135`).
- That is 720/day, harmless at the tip.
- During IBD it is 262,800 fsyncs per chain-year: ~44 min on a 10 ms-fsync HDD [assumed device].

---

## 5. Node RAM

### 5.1 Per-component model [src + math]

Sizes are for x86-64. `Point` = 32 B of bytes + a 160 B `RistrettoPoint` = **192 B** (`crypto/src/point.rs:13-16`).

| Component | Where | Size |
|---|---|---|
| Header entry (`Entry`, key, children map, `main`, `connected`, `generated`, `CachedPow`) | `consensus/src/chain.rs:107-132`, `chain/src/manager.rs:36-40,149-165` | ~0.45 KB/block |
| **PX undo per block: `Frontier` clone 1,032 B + 100-root `VecDeque` clone 3,200 B + overhead** | `px/src/state.rs:100-106` (R10-6) | **~4.3 KB/block, including empty blocks** |
| `BlockUndo` (tx hashes 32 B/tx, key images 32 B/input) | `tx/src/state.rs:55-63` | ~0.15 KB + 32/tx + 32/input |
| Coinbase body + its output record | `chain/src/manager.rs:158` | ~0.9 KB/block |
| **Fixed floor** | | **≈ 6 KB/block ≈ 1.6 GB/year** |
| v1 tx body, decoded (1-in/2-out): input 320 + 2 outputs 1,202 + pseudo-out 192 + BP+ ~3,360 (17 points) + CLSAG 736 | `tx/src/types.rs:18-50`, `crypto/src/bulletproofs_plus.rs:71-80`, `crypto/src/clsag.rs:37-41` | ~6.0 KB against 1.56 KB encoded (3.8×) |
| v1 state per output: `OutputRecord` (2 Points + 9 B) ≈ 400 B + one-time-key set ≈ 48 B | `tx/src/state.rs:41-52`, `tx/src/validate.rs:34-39` | ~450 B/output |
| v1 state per input: key-image set | | ~50 B/input |
| **v1 total** | | **≈ 4.5× encoded bytes** |
| PX tx: proof `Vec<u8>` ≈ 1.0× encoded, plus `px_records` duplicating ciphertexts (R10-7), plus nullifier set and log | `tx/src/state.rs:20-31,158-175` | ≈ 1.0–1.01× |
| Deploy: body + decoded `Program` in `registry`, forever | `tx/src/state.rs:176-190` | ≥ 1× [unknown decode factor] |

**Per-block RAM:**

```
RAM/block ≈ 6 KB + 4.5·v1_bytes + 1.0·px_bytes
```

### 5.2 RAM growth and time to OOM

| Scenario | RAM/day | RAM/year | Days to 16 GB | Days to 64 GB |
|---|---|---|---|---|
| S0 idle | 4.3 MB | 1.6 GB | ~3,700 (10 y) | — |
| S1 light testnet | 109 MB | 40 GB | **~147** | ~590 |
| S2 adoption | 1.0 GB | 372 GB | **~16** | ~63 |
| S3 v1 saturated | 1.9 GB | 704 GB | **~8** | ~33 |
| S4 full | 6.7 GB | 2.4 TB | **~2.4** | ~10 |

**Transient peaks on top of these:**
- **Startup:** `FileStore::load` reads the whole `blocks.dat` into one `Vec` and then copies every payload (`chain/src/store.rs:193-205`). The peak is **≥ 2× the file size** plus decoded bodies as they are replayed.
- **IBD:** up to 16 blocks in flight per peer × 9.45 MB ≈ 151 MB per peer (8 outbound ≈ 1.2 GB) of frames.
- **Mempool:** v1 50 MB encoded ≈ 190–225 MB decoded, plus 64 MiB PX.
- **R10-1:** cheap low-work side-branch bodies go into the same RAM.

**Conclusion:** RAM is the first binding constraint in every non-idle scenario. The testnet (S1, weeks) is safe on 16 GB.

---

## 6. Startup time (replay)

`ChainManager::open` (`chain/src/manager.rs:171-240`) replays every stored block through `submit_inner` → `sync_state` → full body validation. PoW hashes are trusted from the store (known). The mempool is empty during replay, so **every PX proof is re-verified** (known, PX-F3).

**Formula:**

```
t_restart ≈ read(blocks.dat) + Σ t_block(cold)
```

| Scenario | 1 month | 1 year | 5 years |
|---|---|---|---|
| S0 idle | ~40 s | ~8 min | ~40 min |
| S1 light testnet | ~11 min | **~2.2 h** | ~11 h |
| S2 adoption | ~1.8 h | **~22 h** | ~4.6 days |
| S3 v1 saturated | ~8 h | **~4.0 days** | ~20 days |
| S4 full | ~12 h | **~6.2 days** | ~31 days |

Reading the file adds disk time: 307 GB for one S2 year is ~10–40 min at 125–500 MB/s. Given §5, the startup peak RAM is the harder limit.

---

## 7. Initial block download (new node)

**Formula:**

```
T_IBD ≈ T_hdr + max(T_dl, T_val)      (bodies download while earlier ones validate)
T_hdr = N·t_light / p + (N/2048)·0.6 s
T_dl  = chain_bytes / bandwidth
T_val = Σ t_block(cold)               (one thread today)
```

`p` = `pow_threads` = `available_parallelism()` (`p2p/src/net.rs:104`), and `t_light` = 0.75 s under load (0.45 s idle: multiply by 0.6).

**Header PoW only** [math on meas]:

| Chain age (N) | p = 1 | p = 4 | p = 8 |
|---|---|---|---|
| 1 month (21,600) | 4.5 h | 1.1 h | **34 min** |
| 1 year (262,800) | 55 h | 13.7 h | **6.9 h** |
| 5 years (1,314,000) | 11.4 days | 2.9 days | **34 h** |

**Total IBD with 8 PoW threads, 100 Mbit/s, one-thread validation** [est]:

| Scenario | 1 month | 1 year | 5 years |
|---|---|---|---|
| S0 idle | ~35 min | ~7 h | ~35 h |
| S1 light testnet | ~45 min | ~9 h (val 2.2 h, dl 0.7 h) | ~2 days |
| S2 adoption | ~2.4 h | **~29 h** (val 22 h, dl 6.8 h) | ~6 days |
| S4 full | ~13 h | **~7 days** (val 6.2 days, dl 2.2 days) | ~5 weeks |

**Notes:**
- Full-mode verification (R9 O7) does **not** help IBD materially [math]. Per epoch at 8 threads:
  - full mode: 179 s (dataset) + 2,048 × 0.1 s / 8 = 205 s;
  - light mode: 2,048 × 0.75 / 8 = 192 s.

  It helps at the tip, where one hash lies on the critical path (§8).
- Monero-style fast sync (PoW and signatures skipped below an embedded hash) would remove T_hdr and most of T_val. That is a K4/owner decision (assume-valid), policy only.

---

## 8. Block propagation and stale rate

**Per-hop model** [assumed network: 4 hops, 50 Mbit/s, RTT 0.2 s]:

```
t_hop = RTT (header announce + GetBlocks) + B/bw + t_light + t_block(tip)
P(stale) ≈ 1 − exp(−hops·t_hop / T)
```

| Block | t_hop | 4 hops | Stale ≈ |
|---|---|---|---|
| Empty | 0.2 + 0 + 0.75 + 0.002 ≈ 0.95 s | 3.8 s | **3.1%** |
| S2 (1.17 MB) | 0.2 + 0.19 + 0.75 + 0.19 ≈ 1.33 s | 5.3 s | 4.3% |
| S4 (9 MB, PX cached) | 0.2 + 1.44 + 0.75 + 1.33 ≈ 3.7 s | 15 s | **~12%** |
| S6 deploy-CLSAG block | ≈ 36 s | ~145 s | the network stalls; the producer gets a head start |
| After compact blocks + v1 cache + O7 | 0.2 + 0.01 + 0.1 + 0.02 ≈ 0.33 s | 1.3 s | ~1.1% |

**Why it matters:**
- Stale rate is a centralization force: large or well-connected miners lose less.
- It is also a selfish-mining multiplier.
- R9-8 reports the PoW part (2–3%). This table adds the size and verification terms.

**What is on the critical path today** [src]:
- the header, then the RandomX light hash;
- then `GetBlocks` for the **full body**: there are no compact blocks (`p2p/src/message.rs:44-60`);
- then full v1 verification: only PX proofs are cached (`tx/src/validate.rs:926-934`).

---

## 9. P2P bandwidth

**Per node, steady state** [est]:

```
download ≈ 2 × chain_growth + inv overhead
```

- Each transaction arrives once as `Tx` and again inside the `Block`.
- **Inv overhead:** 32 B per tx id per announcing peer. On a node with 72 peers this is ≈ 2.3 KB per v1 tx, **more than the 1.56 KB tx itself**.

| Scenario | Download/day | Average | Burst |
|---|---|---|---|
| S1 | ~0.2 GB | 0.02 Mbit/s | a PX tx 2.2 MB |
| S2 | ~1.7 GB | 0.16 Mbit/s | 1.2 MB block |
| S4′ | ~13 GB | 1.2 Mbit/s | 9 MB block, several MB per tx |

**Upload:**
- A public node serving IBD uploads (number of syncing peers) × chain size.
- `SERVE_BLOCKS_PER_REQUEST` = 16 and `BLOCKS_IN_FLIGHT` = 16 per peer (`p2p/src/net.rs:42-43`).
- Serving encodes blocks under the chain lock (known: chain lock on async threads).

**Assessment:** bandwidth is not the binding constraint; RAM and CPU are. Compact blocks would halve steady-state download and decouple hop time from block size.

---

## 10. Mempool

**Bounds** [src]:
- v1 50 MB encoded ≈ 32,000 1-in transfers (the code comment says ~20,000 of 2.5 kB);
- PX 64 MiB ≈ 29 PX txs, verified once on admission: 29 × 0.235 s ≈ 7 s total;
- the relay budget limits PX admission to 2/s globally, ≈ 0.47 CPU-s/s.

**Per-block maintenance after an extension:** 20,000 × 6.3 µs = 0.13 s [meas].

**After a reorg:** 20,000 × 6.8 ms = **136 s under the chain lock** (known). Parallel revalidation would cut this to ~17 s on 8 cores. A ring-keyed verification cache (R12-12) would cut it to about the extension cost.

**Template:** `select` is a sort per call. It is cheap at these sizes [src].

**Backlog:** there is no expiry (known). At 3 PX per block, a full PX pool is ~10 blocks of backlog.

---

## 11. Wallet scanning

**v1** [src: `docs/transactions.md` §3.3]:
- one variable-base scalar multiplication per output (≈ 50 µs [est]);
- a view tag filters 255/256 of foreign outputs;
- the subaddress table makes the cost independent of the number of subaddresses.

| Scenario | Outputs/block | CPU per chain-year |
|---|---|---|
| S2 | 71 | ~16 min |
| S3 | 761 | ~2.8 h |

**Download (R12-7):** the wallet fetches `/blocks`, which returns full blocks, PX proofs included, hex-encoded in JSON.

| Scenario | Wallet download per chain-year |
|---|---|
| S2 | **~614 GB** |
| S4 | ~3.8 TB |

A compact scan feed would cut this to:
- v1: outputs, key images and the fee context, ≈ 0.4 KB per tx;
- PX: nullifiers, commitments and ciphertexts, ≈ 2.6 KB per tx.

Total ≈ 17 KB/block in S2 (≈ 4.5 GB/year; 9 GB as hex): **~70× smaller in S2, ~700× for PX-heavy data**. Privacy is unchanged: the wallet still downloads everything, without filtering.

**PX records (R12-9)** (`wallet/src/px.rs:334-339`):
- For each record, and each address index `0..=issued+20`, the wallet calls:
  - `account.delivery_keys(index)`: an **ML-KEM-768 key generation from seed** plus a view scalar (`px/src/delivery.rs:93-100`);
  - `account.owner(index)`: Poseidon2;
  - then one Ristretto scalar multiplication and a view-tag check.
- Cost [est]: ≈ 0.12 ms per (record, index), so ≈ 2.5 ms per record for a fresh wallet (21 indices). It grows linearly with issued addresses: ≈ 120 ms per record at 1,000 addresses.

| Scenario | Fresh wallet | 1,000 addresses |
|---|---|---|
| S4 (6 records/block) | ~1.1 h per chain-year | ~53 h |

**PX tree (R12-8)** (`wallet/src/px.rs:479-492`):
- `tree_at` rebuilds the full commitment tree from all commitments, stored as hex `String`s.
- Each append costs exactly 32 Poseidon2 permutations (`px/src/tree.rs:111-130`).
- This happens on every `sync` (the root check at `wallet/src/px.rs:444`) and every PX spend (`wallet/src/wallet.rs:1173,1213,1553`).

| Scenario | Commitments/year | Perms | Time per sync or spend |
|---|---|---|---|
| S2 | 263k | 8.4M | ≈ 4–17 s |
| S4 | 1.58M | 50M | ≈ 25–100 s; tree memory ≈ 2N × 32 B ≈ 100 MB |

**Node side (R12-3):** each `/px/commitments` call runs `px_records(0, u64::MAX)`, which clones **every PX record in history, ciphertexts included**, under the chain lock, and then returns ≤ 65,536 of them (`node/src/lib.rs:264-285`, `tx/src/state.rs:113-119`).

| Scenario | Copy per call | Copied per full wallet sync |
|---|---|---|
| S2, 1 year | ≈ 370 MB | ≈ 1.5 GB (4 calls) |
| S4, 1 year | ≈ 2.2 GB | ≈ 53 GB (24 calls, quadratic) |

In S4 each call holds the lock for seconds, and consensus processing stalls meanwhile.

`/distribution` also returns O(height) numbers per call (`node/src/lib.rs:330-338`): ~2 MB of JSON per chain-year. Acceptable.

**Proving (client):** 45–53 s and 3.8 GB per PX transaction [meas]. This is the practical wallet floor; it rules out phones. It is documented (zk.md §11).

---

## 12. Mining and PoW

These items are R9's; the system-level numbers are restated here.
- **Hashrate:**
  - pure Rust ≈ 10 H/s per thread (full mode) against ≈ 700 H/s per thread for JIT RandomX (R9: 1.4 ms/hash) — about **70× slower**;
  - the algorithm and parameters are identical to Monero's (`randomx/src/config.rs:7` `RandomX\x03`), so rentable Monero hashrate applies directly (R9 §4.4).

  Both are fairness and security limits of the design, not throughput limits.
- **Seed switch:** a 179 s stall (8 threads) every 2,048 blocks, ≈ 0.07% (R9-R4).
- **Initial difficulty:** testnet `D0` = 100 gives ~10 s at 10 H/s; LWMA-60 adapts. Mainnet `D0` = 100,000 needs ≈ 833 H/s for 120 s blocks: ~80 pure-Rust threads, or 1–2 JIT cores. This is sensible only if the launch hashrate is known.

---

## 13. Binding constraints: summary table

| # | Constraint | Binds in | Order of magnitude today | Fix class |
|---|---|---|---|---|
| B1 | RAM = O(chain) × 4.5 for v1; 6 KB/block floor | S1 in months; S2 in weeks; S4 in days | 1.6–2,400 GB/year | engineering (L) |
| B2 | Restart = full revalidation, one thread | S1 onward | hours to days per restart | engineering (M) |
| B3 | Header PoW in IBD (light RandomX) | all, growing linearly | 6.9 h/year at 8 threads | engineering (M), policy (assume-valid) |
| B4 | Body validation in IBD, one thread | S2 onward | 22 h per S2-year | engineering (S–M) |
| B5 | PX bytes per tx (2.2 MB) → 3 PX/block, chain growth | any PX use | 0.025 PX tx/s | CONSENSUS (M–XL) |
| B6 | PX-budget validation amplification (deploy CLSAGs) | adversarial miner | 25–50 s per block | CONSENSUS (S) |
| B7 | Propagation (PoW + full body + v1 re-verification) | all | 3–12% stale | engineering (M) |
| B8 | Wallet sync bytes and PX tree/scan | S2 onward | 614 GB/year download; O(N) per sync | engineering (S–M) |

---

## 14. Findings

The format follows the brief. "Known" means it is in the brief's list or in R9/R10; such items are deepened or quantified here, not claimed as new.

### R12-1: Node RAM grows as O(chain), with a ~4.5× decode factor and a 6 KB/block floor
- **Class:** Accepted limitation (known PX-F1/PX-F2, R10-6), quantified.
- **Severity:** medium for the testnet; **critical for mainnet**.
- **Location:**
  - `chain/src/manager.rs:158` (`bodies: HashMap<Hash, Vec<Transaction>>`);
  - `tx/src/state.rs:41-63`;
  - `crypto/src/point.rs:13-16`;
  - `px/src/state.rs:100-106`.
- **Scenario:** a spammer, or a miner stuffing its own blocks, fills blocks for 0.39 BLK each. 16 GB nodes run out of memory in ~2.4 days (S4) or ~8 days (S3, v1 only, 0.12 BLK/block). They then crash-loop, because the replay needs even more RAM (2× file size at load).
- **New detail:**
  - the 192 B in-RAM `Point` makes decoded v1 data ~3.8× its wire size;
  - the output set alone costs ~450 B per output (≈ 88 GB/year in S3);
  - the startup peak is ≥ 2× `blocks.dat` (`chain/src/store.rs:193-205`).
- **Evidence:** [src], [math] for struct sizes, [est] for the per-tx totals.
- **Confidence:** high on the direction, medium (±30%) on the factors.

### R12-2: The PX byte budget allows ~14× more CLSAG work per block than the v1 weight limit
- **Class:** Not implemented (a cost bound for weight-0 inputs); new. It deepens the known "deploys act as cheap transfers".
- **Severity:** **medium** for the testnet (griefing by any miner); high for mainnet.
- **Location:**
  - `tx/src/types.rs:452-458`: `weight()` = 0 for PX and deploy;
  - `tx/src/px.rs:595-597`: the deploy fee is 2 atomic/B, with no BP+ clawback;
  - `tx/src/px.rs:616-619, 714-735`: ≤ 64 inputs each;
  - `tx/src/validate.rs:878-900`: CLSAG per input, serial.
- **Construction:**
  - a minimal deploy with 64 inputs, 2 outputs and one tiny program is ≈ 44.3 KB;
  - ⌊8,388,608 / 44,338⌋ = 189 deploys = **12,096 CLSAG verifications**;
  - at 2–4 ms each, that is **~25–50 s** of single-thread validation per block [est];
  - the v1 weight limit caps a block at ~886 inputs (~2.7 s).
- **Cost to the miner:** ≈ 0.17 BLK in fees, paid to itself. The miner also needs 12,096 spendable outputs, which it can create cheaply over time.
- **Effect:**
  - every node stalls ~25–50 s under the chain lock (block processing is still on the read loop, known);
  - IBD and replay slow down;
  - the stale-rate advantage for the producer (§8) grows.

  PX transactions can also carry 64 weight-0 inputs each, but the proof bytes bound them to ≤ 3 × 64.
- **Confidence:** high on the count [math]; medium on seconds (t_clsag is estimated).
- **Recommendation R12-2:** bound verification work across the whole block, for example one of:
  - (a) count the v1 part of PX and deploy transactions (inputs, outputs, BP+ clawback) against `MAX_BLOCK_WEIGHT`, with the PX budget counting only the PX-specific bytes; or
  - (b) add a block-level "signature operations" limit (Σ inputs ≤ ~1,000, or cost units: CLSAG = 1, BP+ output = k/…), which is Bitcoin's sigops model.

  Option (a) also fixes the 10× cheaper fee per byte for deploy CLSAG bytes. Deploy/PX `min_fee` would become `px_bytes·2 + v1_weight·20`.

  | Attribute | Assessment |
  |---|---|
  | Why | bounds worst-case validation to about the v1 figure |
  | Security | + (DoS, propagation fairness) |
  | Privacy | none. PX fees stay uniform (the PX standard fee would add a fixed v1 component per input shape, or input counts are bounded); **check the P-7 fee-uniformity rule before choosing (a)** |
  | Performance | worst-case block 25–50 s → ≤ 3 s |
  | Complexity | low |
  | Consensus | **CONSENSUS** |
  | Testnet identity | yes, but it fits the planned v3 genesis (M1) |
  | Difficulty | S |
  | Priority | **P1** (before or with the v3 genesis) |

### R12-3: `/px/commitments` copies every PX record in history under the chain lock on every call
- **Class:** Partially implemented; new. R10-7 notes the duplicated ciphertexts; this is the per-call O(N) and the quadratic sync.
- **Severity:** medium. The RPC binds to 127.0.0.1 by default (`node/src/config.rs:190-192`); an exposed RPC or a local wallet on a big chain triggers it.
- **Location:** `node/src/lib.rs:264-285`; `tx/src/state.rs:113-119`.
- **Scenario:** in S4 after 1 year, one call clones ≈ 2.2 GB and holds the chain lock for seconds. A syncing wallet makes N/65,536 calls, so ~53 GB is copied. Meanwhile block and tx processing stall. Repeated calls give a local DoS.
- **Fix:**
  - keep a commitments-only index (`Vec<(u64, Digest)>` by position);
  - serve `from..from+65,536` by slice;
  - move ciphertexts out of RAM entirely (R10-7).

  | Attribute | Assessment |
  |---|---|
  | Consensus | none |
  | Identity | no |
  | Difficulty | S |
  | Priority | **P2** (before the testnet if cheap) |
  | Privacy | none |
  | Security | + (lock-hold DoS) |
  | Performance | O(N) → O(k) |

- **Confidence:** high [src].

### R12-4: A restart costs a full single-threaded revalidation, and loading costs 2× the file in RAM
- **Class:** Accepted limitation (known PX-F3), quantified; the 2× load peak deepens R10.
- **Severity:** medium for the testnet (S1: ~2 h per restart after a year; weeks of testnet use cost minutes); high for mainnet.
- **Location:** `chain/src/manager.rs:171-259`; `chain/src/store.rs:193-205`.
- **Numbers:** §6.
- **Fix, in increasing order of effort:**
  - (a) stream `load` record by record (S);
  - (b) on replay, trust the node's own validated store for signatures and proofs, as it already trusts stored PoW hashes. Mark blocks "validated" through a checksummed state root or journal. This is the same trust model (S–M);
  - (c) persistent state and snapshots, so a restart is O(snapshot) (L; §15).

  Consensus: none. Identity: no. Priority: P2 for (a) and (b); P3 for (c) before mainnet.
- **Confidence:** high.

### R12-5: IBD is bounded by header PoW and one-thread body validation
- **Class:** Accepted limitation (known; R9-8), quantified at system level (§7).
- **Severity:** low for the testnet; medium for mainnet.
- **New nuance:** full-mode verification (R9 O7) does not speed up IBD (§7 math). The effective IBD levers are:
  - a faster light mode (R9 O2);
  - parallel body validation;
  - an assume-valid policy (K4, owner decision).
- **Confidence:** high on the header part; medium on body validation.

### R12-6: Per-hop propagation includes block-size and v1-verification terms
- **Class:** Partially implemented; new as a combined model. The PoW term is R9-8.
- **Severity:** low for the testnet (empty blocks: ~3%); medium for mainnet (~12% for full blocks).
- **Location:** `p2p/src/message.rs:44-60` (no compact blocks); `tx/src/validate.rs:878-921` (v1 always re-verified).
- **Fix:** R12-12 (v1 verification cache), compact blocks (M), and R9 O7 at the tip. Consensus: none.
- **Confidence:** low–medium. The network topology and bandwidth are [assumed].

### R12-7: Wallet sync downloads full blocks, PX proofs included, as hex JSON
- **Class:** Not implemented (compact scan); new.
- **Severity:** low for the testnet; medium for mainnet.
- **Location:** `wallet/src/wallet.rs:497-535`; `node/src/lib.rs:222-257`.
- **Scenario:** a wallet restoring one S2-year downloads ~614 GB. Over a remote node at 100 Mbit/s that is ≈ 14 h.
- **Fix:** a `/scan` endpoint, or a block form stripped of the prunable sections and PX proofs, still unfiltered (every wallet gets every block's scan data). Include `prefix_hash`/`tx_hash` so the wallet can still check `tx_root`.

  | Attribute | Assessment |
  |---|---|
  | Consensus | none |
  | Privacy | neutral |
  | Difficulty | S–M |
  | Priority | P2 |

- **Confidence:** high.

### R12-8: The wallet rebuilds the PX tree from genesis on every sync and spend
- **Class:** Partially implemented; new.
- **Severity:** low for the testnet; medium at scale.
- **Location:** `wallet/src/px.rs:422-492`; `wallet/src/wallet.rs:1173,1213,1553`.
- **Cost:** 32 Poseidon2 per commitment for the whole history, per call. Commitments are stored as hex `String`s (~120 B each against 40 B binary).
- **Fix:** keep an incremental tree:
  - store the frontier plus the witnesses (authentication paths) of owned records and update them per append, as Zcash wallets do;
  - or persist `levels` and append only new commitments;
  - store digests in binary.

  Consensus: none. Difficulty: S–M. Priority: P2.
- **Privacy:** positive. Paths are still computed locally.
- **Confidence:** high.

### R12-9: PX scanning costs O(addresses) per record, with ML-KEM key generation in the inner loop
- **Class:** Partially implemented; new.
- **Severity:** low for the testnet; medium at scale.
- **Location:** `wallet/src/px.rs:334-339`; `px/src/wallet.rs:69-83`; `px/src/delivery.rs:93-100, 194-212`.
- **Fixes:**
  - **Short term (S):** cache `DeliveryKeys` and `owner` per index, derived once and zeroized on drop. This removes the keygen from the loop (≈ 2× [est]).
  - **Structural (M–L, needs privacy review):**
    - a Sapling-style shared incoming viewing key over diversified bases makes the EC tag check O(1) per record for any number of addresses;
    - the address index then travels encrypted under the EC shared secret, so exactly one ML-KEM decapsulation follows a tag match.
    - The ML-KEM keys stay per address (a shared ek would link addresses).
    - Delivery is wallet-level (not in the kernel statement) [src: px.md §6], so this is **not consensus**, but it changes the address format.
- **Priority:** P3. The short-term fix is P2.
- **Confidence:** medium (unit costs are estimated).

### R12-10: Docs overstate PX capacity ("about 4 per block"); the true figure is 3, and 1 for a maximum-size PX tx
- **Class:** doc error; new.
- **Severity:** low.
- **Location:** docs/px.md §8 and §11.5; docs/zk.md §11 and §11.1; docs/reviews/aggregation-study.md §4.
- **Cause:** the figure was right at 2.05 MB (4 × 2.05 < 8.39 MB). Terminal blinding (R12) made the transfer 2.18 MB (4 × 2.20 > 8.39).
- **Fix:** update to "3 transfers or 3 vault calls; 1 maximum-size PX tx". Mention to A16b (docs).
- **Confidence:** high [math].

### R12-11: Block validation is single-threaded
- **Class:** Not implemented.
- **Severity:** low (efficiency).
- **Location:** `tx/src/validate.rs:878-900` (CLSAG loop), `:926-934` (PX proofs).
- **Why:** CLSAGs of different inputs are independent; PX proofs are independent; the BP+ batch can be split.
- **Gain:** × cores for IBD, replay, reorg and propagation.
- **Implementation:** `std::thread::scope` (no new dependency; Plonky3 already brings rayon).
- **Determinism:** the verdict is deterministic (all-or-nothing). Report the **lowest** failing index so the logged `BlockError` is stable.
- **Attributes:** Consensus none; Identity no; Difficulty S–M; Priority P2.
- **Confidence:** high.

### R12-12: No v1 verification cache; cache soundness must key on the resolved ring, not only the tx id
- **Class:** Not implemented; new design note.
- **Severity:** low–medium.
- **Location:** `chain/src/manager.rs:448-455` (only PX proofs are cached, via `mempool.contains`).
- **Design:**
  - BP+ validity is stateless, so it can be cached by tx hash.
  - CLSAG validity depends on the ring members that the global indices resolve to, which **differ across branches** (a reorg changes the output ordering).
  - The cache key must therefore be `(tx_hash, H(resolved ring members of every input))`.
  - Do **not** reuse the `mempool.contains` shortcut for CLSAGs. During a reorg, blocks of the new branch are connected before the mempool is revalidated, so a pooled tx's verdict can be stale for that branch.
- **Gain:**
  - tip validation of mempool-known transactions ≈ ring resolution only;
  - post-reorg mempool revalidation drops from 136 s to seconds.
- **Attributes:** Consensus none; Identity no; Difficulty S–M; Priority P2.
- **Confidence:** high on the soundness requirement [src], medium on the gain.

### R12-13: The deploy registry and the PX logs are RAM-resident and unbounded
- **Class:** Accepted limitation (part of PX-F1).
- **Severity:** low for the testnet.
- **Location:** `tx/src/state.rs:46-52,176-190`.
- **Detail:** deploys at 0.021 BLK per MiB (2 atomic/B) are the cheapest RAM filler; the decoded `Program`s stay in RAM forever.
- **Fix:** R12-2 (a) for pricing; persistent registry storage (L).
- **Priority:** P3.

### R12-14: `CachedPow` and the header tree grow without bound
- **Class:** known (R9-6), quantified.
- **Severity:** info.
- **Size:** ≈ 100 B/header for the cache and ≈ 0.45 KB/header in total, ≈ 118 MB per chain-year. Attacker-driven growth is CPU-bound: at most ≈ 1 KB/s at 8 threads.
- **Fix:** see R9-6.

### Items verified as fine (Complete and verified / Complete but requires further testing)
- **Extension-path mempool revalidation:** 6.3 µs per tx [meas: `revalidation_after_an_extension_agrees_with_full_validation`, `mempool_revalidation_cost_per_transaction`]. Complete and verified.
- **PX proof cache soundness at block connect:** keyed by tx id, which commits to the proof (`tx/src/validate.rs:715-723`) [src; test: `mempool_contents_never_change_a_blocks_verdict`]. Complete and verified.
- **BP+ block batching with 128-bit random weights** (`crypto/src/bulletproofs_plus.rs:529-542`): the right design. Its cost is complete but requires further testing (no benchmark).
- **PX relay CPU bound:** ≤ 2 proofs/s ≈ 0.47 CPU-s/s whatever the peer count (docs/p2p.md). Complete but requires further testing: the adversarial proof cost is unmeasured (ZK-F4).
- **Eviction is one sort per admission** [test: `eviction_under_a_flood_stays_fast`]. Complete and verified.
- **Tree capacity** does not bind (~2,700 years) [math].

---

## 15. Improvement catalogue (order of magnitude, effort, consensus)

| # | Improvement | Gain | Why needed | Security | Privacy | Complexity | Consensus | Identity | Difficulty | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| I1 | **PX undo as a delta**: the evicted root + a pushed flag; frontier only if changed (R10-6) | −4.2 KB/block (−1.1 GB/year idle) | RAM floor | neutral (test: apply∘undo = id) | none | low | none | no | S | **P1** (cheap) |
| I2 | Store bodies as encoded bytes (or file offsets), decode on use | v1 body RAM −75% | B1 | neutral | none | low | none | no | S | P2 |
| I3 | Compact output set: bytes only, decompress on use (+~8% CLSAG time) | 450 → ~90 B/output | B1 | neutral | none | low | none | no | S | P2 |
| I4 | Streaming `load`; trust the own validated store on replay (as for PoW) | restart peak RAM 2× → 1×; restart time → I/O + apply | B2 | trusts own disk, same model as PoW | none | low–medium | none | no | S–M | P2 |
| I5 | **Persistent state + block index on disk** (pure-Rust KV such as `redb`/`fjall`, reviewed for `unsafe`; or a custom append log + index) + state snapshots | RAM O(chain) → O(cache); restart → seconds | B1/B2 at mainnet | + (no OOM) | none | high | none | no | **L** (4–8 weeks) | P3, **mainnet blocker** |
| I6 | Parallel verification (CLSAG per input, PX per tx, split BP+ batch) | ×cores on IBD, replay, reorg, propagation | B4/B7 | neutral | none | medium | none | no | S–M | P2 |
| I7 | v1 verification cache keyed on (tx, resolved ring) (R12-12) | per-hop v1 ≈ 0; reorg revalidation 136 s → s | B7 | neutral if keyed right | none | medium | none | no | S–M | P2 |
| I8 | Compact block relay (short ids + fill-in) | −50% bandwidth; hop time independent of size | B7 | neutral | neutral (Dandelion stem txs are simply fetched) | medium | none (P2P) | no | M | P3 |
| I9 | R9 O2 (light mode), O7 (full-mode tip verification), R9-R4 prebuild | light 4–7×; tip hop 0.75 → 0.1 s | B3/B7 | + | none | medium | none | no | M | P2/P3 (R9) |
| I10 | Assume-valid (PoW and signatures below a release-embedded hash) | IBD ≈ download time | B3/B4 | trust in the release (K4) | none | low | policy | no | S | owner decision |
| I11 | **Block-level verification-cost bound (R12-2)** | worst-case block 25–50 s → ≤ 3 s | B6 | + | check P-7 | low | **CONSENSUS** | yes (fold into v3) | S | **P1** |
| I12 | `/px/commitments` index; ciphertexts out of RAM (R12-3, R10-7) | O(N) → O(k) per call | B8 | + | none | low | none | no | S | P2 |
| I13 | Wallet compact-scan RPC (R12-7) | wallet download 70–700× less | B8 | neutral | neutral | low | none | no | S–M | P2 |
| I14 | Incremental wallet tree + record witnesses (R12-8) | per-sync O(N·32) → O(new·32) | B8 | neutral | + | low | none | no | S–M | P2 |
| I15 | Cache PX delivery keys per index; then shared-ivk scanning (R12-9) | 2× now; O(addr) → O(1) later | B8 | neutral | needs review for the ivk design | medium | none (address format) | no | S / M–L | P2 / P3 |
| I16 | Pruning of the prunable section (CLSAG, BP+, PX proof) after depth D; archival service bit | disk −78% (v1), −99% (PX) for pruned nodes | chain growth | neutral (archival nodes needed for IBD) | none | medium | none | no | M–L | P3 |
| I17 | PX width reduction (aggregation-study §3.2) | PX bytes −10–25% | B5 | needs the mutation/forgery cycle | none | high | CONSENSUS (proof format) | yes | M each | P3 |
| I18 | Query policy (Johnson ≥ 120 only: 49–71 queries) | PX bytes −35–55% → 5–7 PX/block | B5 | lower unique-decoding margin (owner) | none | low code, high review | CONSENSUS | yes | S code / L review | owner |
| I19 | Recursion/aggregation (dedicated recursion AIR, ~10^5 rows per inner proof); optionally a final "shrink" proof at a larger blow-up (~100–300 KB [assumed from other STARK systems]) | PX chain bytes/tx → ~3 KB + one aggregate per block; capacity 10–100× (bounded by aggregator proving: N × 10^5 rows) | B5 | new circuit, own review | none (no witnesses move) | very high | CONSENSUS | yes | **XL** (3–6 months + review) | P3, before any mainnet PX capacity target |
| I20 | Blow-up 16 (fewer queries) | proof ~−40% [est]; proving 2× time and memory (45 → 90 s, 3.8 → ~7.6 GB) | B5 | same bits | none | low | CONSENSUS | yes | S | not recommended (breaks the 4 GB wallet target) |

**Things that should not be pursued:**
- a RandomX JIT: it needs `unsafe` and W^X memory, contrary to project policy (R9);
- delegated or remote proving: it breaks witness privacy (zk.md §11.3);
- SNARK wrapping over pairing curves: trusted setup and non-transparency conflict with the design goals; the pure-Rust options are immature.

---

## 16. Subsystem answers (the 13 questions, condensed)

| Subsystem | Implemented / correct | Incomplete / fragile / exploitable | Inefficient / does not scale | Redesign / innovate | Before testnet | Defer | Never change |
|---|---|---|---|---|---|---|---|
| **Block validation** (`tx/src/validate.rs`) | Cheap-first ordering; BP+ batch; PX proof cache (sound) | R12-2 PX-budget CLSAG amplification (exploitable by a miner) | One thread; no v1 cache | Sigops-style cost bound; ring-keyed cache | R12-2 bound (with v3) | Parallelism (P2), cache (P2) | Full validation of every received block; the PX cache key = tx id (commits to the proof) |
| **State and storage** (`tx/src/state.rs`, `chain/src/store.rs`, manager) | Exact undo; CRC log; fsync before apply | Everything in RAM; load peak 2×; undo snapshot per block | O(chain) RAM, O(chain) restart | Disk state + snapshots | I1 (undo delta); streaming load | I5 persistence (mainnet blocker) | Invariant "state = apply(connected)"; exact per-block undo semantics |
| **Sync / IBD** (p2p, manager) | Headers-first; parallel header PoW in chunks; blocks-in-flight cap | Header PoW 0.75 s; bodies one-threaded | 34 h of headers per 5 chain-years at 8 threads | Assume-valid (owner); faster light mode | — | R9 O2, parallel validation | No depth limit or checkpoint silently added (K4 is the owner's call) |
| **Propagation / P2P** | Encrypted transport; rate limits; requested-block exemption | Full-body relay; v1 re-verification per hop | Stale 3–12% [est] | Compact blocks | — | I7, I8, O7 | Dandelion++ ordering for local txs |
| **Mempool** | Byte caps; one-sort eviction; cheap extension revalidation | Reorg full revalidation 136 s (known); no expiry (known) | — | Ring-keyed cache | (known items in flight) | I7 | First-seen conflict rule |
| **PX layer** | 3 PX/block budget; uniform fee; relay caps | Docs say 4 (R12-10); adversarial verification cost unknown (ZK-F4) | 2.2 MB per tx → chain growth dominated by PX | Width, queries, recursion | Doc fix; measure ZK-F4 | I17–I19 | BS-ZK-2 without a full analysis and owner decision |
| **Wallet** | View-tag scanning; O(1) subaddress table (v1) | R12-3 RPC; R12-7/8/9 | Full-block download; O(N) tree; O(addr) PX scan | Compact scan; incremental tree; shared ivk | R12-3 (node side) | I13–I15 | Unfiltered download (privacy) |
| **Mining / PoW** | Spec-conformant RandomX; parallel header hashing | ~70× slower than JIT; seed stall; rental risk (R9) | Light verification 0.75 s | R9 O-programme, O7 | — (R9 P2 items) | RandomX v2, merge mining (owner) | Software FP rounding; RandomX v1 until a deliberate decision |

---

## 17. Before testnet / deferrable / never change

**Before the testnet (performance-related, all S):**
1. **R12-2:** a block-level verification-cost bound, or charging v1 weight for PX/deploy inputs. CONSENSUS; fold it into the planned v3 genesis. P1.
2. **I1:** the PX undo delta. Not consensus. P1, because it is cheap and removes 1.1 GB/year of idle RAM.
3. **R12-3:** the `/px/commitments` index. Not consensus. P2.
4. **R12-10:** the doc correction (3 PX per block). Hand it to A16b.
5. Benchmarks (§19), so that later decisions rest on measurements.

**Deferrable to after the trial (P2/P3):**
- I2–I8, I12–I16: engineering, with no consensus effect;
- I5 persistent state (a hard mainnet blocker);
- I17–I19 PX size and aggregation: CONSENSUS, owner decisions.

**Never change** (risk without enough benefit):
- full validation of every received block (no "trust the peer");
- the PX proof cache key (tx id);
- ring size and the BS-ZK-2 constants, except through the full analysis and owner process;
- the "no unsafe" RandomX (no JIT);
- local-only proving;
- a CLSAG cache keyed by tx id alone.

---

## 18. Corrections to known statements

- **"About 4 PX transactions per 8 MiB block"** (px.md §8 and §11.5, zk.md §11, aggregation-study §4): it is **3** since terminal blinding, and **1** for a maximum-size PX tx. R12-10.
- **The code comment "about 20,000 one-input transfers of ~2.5 kB"** (`chain/tests/manager.rs`): a 1-in/2-out transfer is ~1.56 kB, so a 50 MB pool holds ~32,000. The reorg revalidation extrapolation is then ~218 s, not 136 s [est].
- **The aggregation study's "a flooding peer can make a node verify at most 2 proofs per second":** correct for relay. Blocks can still force up to 3 uncached PX verifications (plus up to 12,000 deploy CLSAGs, R12-2) per block, bounded only by PoW.

---

## 19. Measurements needed

None of these were run: this review had no builds.

1. `cargo bench` for:
   - CLSAG verification (16 members);
   - single BP+ at k = 2 and 16;
   - batched BP+ at 1, 10 and 381 proofs;
   - ring resolution.

   These replace the [est] split of 6.8 ms.
2. PX verification pinned to 1 thread (`RAYON_NUM_THREADS=1`) against the default, plus a maximum-size adversarial proof (ZK-F4).
3. A synthetic S3, S4 and S6 block: `submit_block` wall time and peak RSS.
4. RSS after replaying 10k, 50k and 100k blocks of S0 and S1 on regtest, to validate the 6 KB/block floor and the 4.5× factor.
5. Wallet: `tree_at` time at 10^5 and 10^6 commitments; PX scan per record at 21 and 1,000 addresses.
6. `/px/commitments` latency and allocation at 10^5 records.
