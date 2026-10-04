# SKC-1: combined research summary (independent cross-check of Reports A and B)

> Historical record (2026-10-04). Superseded where it conflicts with the code: RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca), so the "rx/0 for testnet" recommendation was not followed; the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5). Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

- Role: independent cross-checker, fresh context. **Internal research, not an audit.** Nothing here authorises a PoW or consensus change, or production activation.
- Date: 2026-10-04. Repository read-only (`rebuild/core` @ 8ccc24c). No builds, tests or benchmarks were run. Nothing was written outside `C:/bszkeval/skc1-combined/`.
- Inputs:
  - Report A (crypto/algorithm): `C:/bszkeval/skc1-a/skc1-research-A.md`
  - Report B (performance/hardware/economics): `C:/bszkeval/skc1-b/skc1-research-B.md`
  - Prior repository analysis that neither report used fully:
    - `docs/reviews/full-review-2026-09-27/I4-sustainability-scaling-pq.md` §2 and §7.2 (already proposes a salt-only mainnet config, rejects merge mining, J1/J3 miner options and a halt-on-deep-reorg flag);
    - `R9-randomx.md`, `R1-consensus.md`, `R8-p2p.md`, `R12-performance.md`, `SX1`/`SX2` cross-reviews.
- Labels:
  - **CONFIRMED**: a primary or near-primary source checked today.
  - **CORRECTED**: a claim in A, B or the repository that the evidence contradicts or materially refines.
  - **UNVERIFIABLE**: no primary source found today.

---

## 1. Verdict

- **SKC-1 as proposed: REDESIGN REQUIRED.** Both reports reached this independently, and the cross-check confirms it.
  - Its 32 MiB per-nonce, symmetric-memory design fits in on-die SRAM on an ASIC: about 8–20 mm² at 5–7 nm.
  - It repeats the CryptoNight pattern, which got ASICs and needed four PoW forks.
  - Its mixer (SilkMix) and graph are unanalysed.
  - Its header-to-scratchpad binding is unspecified, which is a possible total break.
- **A redesigned "SKC-1r"** (an Argon2d-style PoW) remains **INSUFFICIENT EVIDENCE**. At most it justifies an isolated offline research prototype against the A §10 and B §6 gates.
- **The actual threat is rented or shared RandomX hashpower against a small chain.** It is real and cheap. No option below makes a small PoW chain secure against a determined renter; each only raises cost or friction.
- **Recommended plan:** §6. Every PoW, consensus or finality change in it is marked **OWNER APPROVAL**.

---

## 2. Fact verification

| # | Claim (source) | Status | Evidence / correction |
|---|---|---|---|
| F1 | RandomX ASICs exist: Antminer X5 at 212 kH/s and 1350 W, about 6.4 J/kH (A, B) | **CONFIRMED** (vendor/retail specs) | Kryptex pool article; asicminervalue. The Bitmain support page returned 403 and was not read. |
| F2 | "X5 energy advantage about 1–1.2× (A) / 1–2× (B) over a modern CPU" | **CORRECTED** | Both reports benchmarked against the X5. The **X9** (1 MH/s, 2472 W, 2.47 J/kH ≈ 405 H/J; vendor/retail) is about **3–4× a Ryzen 7950X/9950X**: 7950X ≈ 95 H/J (21.9 kH/s at 230 W, hashrate.no); 9950X ≈ 104–122 H/J. RandomX's ASIC margin is still small, but it is now about 3–4×, not "about parity". It is still far below B's SKC-1 SRAM-ASIC estimate of 10–200×. |
| F3 | X5/X9 can mine arbitrary RandomX inputs | **Partly CONFIRMED / UNVERIFIABLE** | Retail and pool sources say the X5 mines Tari RandomX and Zephyr, i.e. other rx/0 chains with their own keys and blobs over stratum (secondary sources). So **any rx/0 chain, BlackSilk included, is X5/X9-mineable via a stratum adapter.** Whether they can mine a *different salt or config* is **UNVERIFIABLE**. sech1 (SChernykh) reported on bitcointalk that the X5 is a cluster of RISC-V CPUs (SG2042) with DDR4 SODIMMs; if so, a variant needs only a recompile, but stock firmware is closed. |
| F4 | Qubic and Monero, Aug 2025: 6-block reorg, ~60 orphans (A, B); "peer-reviewed measurement finds no sustained 51%" (A) | **CORRECTED** (understated) | **(a)** Both reports omit the **18-block reorg of 2025-09-14** (heights 3,499,659–3,499,676, ~118 tx unconfirmed, ~36–43 min of history), Monero's deepest ever. Sources: CoinDesk 2025-09-15, Decrypt, The Block, WeebDataHoarder timeline. The MRL then proposed opt-in rolling DNS checkpoints as an "emergency bandaid". **(b)** arXiv 2512.01437 (Lee and Kim, "Inside Qubic's Selfish Mining Campaign on Monero") is a **preprint** (v. 2026-08-01); peer review is not confirmed. Its numbers, measured 2025-09-29 to 10-17: mean Qubic share 23.38%, 28.33% in active periods, hourly peaks near or briefly above 50%, never ≥51% daily or weekly. It earned **4.0% less** than honest mining. **(c)** B's "Qubic moved ~2.6 GH/s" is **UNVERIFIABLE**. The paper implies about 1.4–1.8 GH/s on average, with higher hourly peaks. |
| F5 | NiceHash RandomX: 0.12 GH/s at 0.4732 BTC/GH/day ≈ $40k/GH/day (B) | **CONFIRMED** (point-in-time) | NiceHash page, window 2026-10-03 07:50 to 2026-10-04 07:40: 0.1209 GH/s; 0.4732 BTC/GH/day ≈ 40,193 USDT; 24 h volume ≈ 4.9k USDT. One MH/s for a day ≈ **$40**. The market is shallow relative to Monero (~2%) but is 10²–10⁵× any plausible BlackSilk honest hashrate. |
| F6 | Monero hashrate about 5.8–6.4 GH/s (B) | **CONFIRMED** | coinwarz: 6.15 GH/s on 2026-10-04 (peak 7.54 GH/s, 2026-01-16). |
| F7 | RandomX v2 released 2026-03-25 (A) | **CONFIRMED** | GitHub API: tag `v2.0` published_at `2026-03-25T10:29:38Z`. I4's "2026-03-30" is the Monero X post date, not the release date: **CORRECTED** in I4. |
| F8 | Monero activation of v2: unknown (A [U]) | **CONFIRMED: not activated** | Monero PR #10038 ("support RandomX V2 and commitments in v17") is **open**, unmerged, milestone "fcmp++ hf", last updated 2026-09-19. No activation height. xmrig v6.26.0 reportedly supports rx/v2 (search result, not fetched directly). |
| F9 | CryptoNight variant 2 added division and sqrt (Monero PR #4218) | **CONFIRMED** | Author SChernykh, merged 2018-09-11: 64:32 integer division + 64-bit integer sqrt + a 64-byte-line shuffle. |
| F9b | CryptoNight ASIC outcomes | **CONFIRMED** (secondary/historical press) | Antminer X3 announced March 2018. Bricked by the v7 fork on 2018-04-06. CNv2 (v8) on 2018-10-18 halved network hashrate, consistent with ASIC/FPGA removal. CN-R followed in March 2019, and RandomX on 2019-11-30. |
| F10 | SRAM: N5 HD ~31.8 Mib/mm², so 32 MiB ≈ 8 mm² (A); V-Cache 64 MB ≈ 36–41 mm² at N7, so 32 MiB ≈ 18–20 mm² (B) | **CONFIRMED and reconciled** | WikiChip: N5 HD bitcell 0.021 µm², ~32 Mib/mm² with ~30% assist overhead. N3E has the same bitcell (scaling stalled). A counts the array; B counts a shipped product die including periphery and TSVs. **The range is 8–20 mm² for 32 MiB.** The conclusion is the same: dozens of instances fit on one die. |
| F11 | 64-bit DIV latency: Skylake 39–94 (B) / "10–90" (A); Zen 4 10–18 (B) | **CONFIRMED** (minor refinement) | uops.info DIV r64 latency: Skylake 35–90; Ice Lake / Alder Lake-P 14; Zen 2 8–39; Zen 3/4 9–17. B's figures are IDIV-like and within a few cycles. Agner Fog was not re-fetched; uops.info is the stronger primary source. |
| F12 | Pure-Rust light verification ~0.45–0.75 s/header (repo) | **CONFIRMED** | `docs/consensus.md` §10 and `docs/p2p.md` §12 say "about 0.45 s". `R1-consensus.md:335` measures ~0.75 s under load. Evidence log `docs/evidence/pow-pool-2026-10-01/logs/after-idle.log`: **548.2 ms/header** on 1 thread, 285.6 ms on 2, 159.2 ms on 4; cache build + 1 hash = 1226 ms. |
| F13 | Pure-Rust miner 50–100× slower than xmrig (repo R1/SX1); ~70× (R12:528) | **CONFIRMED as a repo estimate** | ~10 H/s/thread in safe Rust vs ~700 H/s/thread JIT. The JIT figure is 1.4 ms/hash from the tevador README (i9-9900K), **not measured on BlackSilk hardware**. R9 §4 estimates the safe-Rust ceiling after O1–O6 at **5–15× slower than JIT**: "the gap cannot be closed in safe Rust". |
| F14 | Attacker/verifier asymmetry 300–500× (A, citing R9) | **CORRECTED** (context) | `SX2-systems-crossreview.md:45,146`: this holds only at difficulty ≈ 1. At testnet D0 = 100 it is about **4–7×**. It becomes large again only if difficulty collapses (genesis-era forks), which the work gate now targets. |
| F15 | Merge mining with Monero (Tari) | **CONFIRMED** (Tari RFC-0132 / RFC-0131) | See §4(b). Tari headers carry `MoneroPowData` (Monero header, `randomx_key` = **Monero's seed**, tx count, merkle root, coinbase merkle proof, partial Keccak state of the coinbase, coinbase `extra`, aux-chain merkle proof). The merge-mining hash is Blake2b-256 of the Tari header without nonce and PoW, committed in the Monero coinbase `extra`. A seed may be used for at most 3000 blocks. Tari runs 4 lanes (RxM merged, RxT native, SHA3x, Cuckaroo29), with per-lane LWMA over 90 blocks. |
| F16 | RandomX designers recommend unique per-project configs | **CONFIRMED** | `tevador/RandomX doc/configuration.md`: "We recommend each project using RandomX to select a unique configuration to prevent network attacks from hashpower rental services". On `RANDOMX_ARGON_SALT`: "Every implementation should choose a unique salt value." The same document says changing other defaults "is not recommended", except functionally-equivalent instruction-frequency pairs. |
| F17 | xmrig adapts to variants quickly | **CONFIRMED** (stronger than stated) | xmrig ships rx/0, rx/wow, rx/arq, rx/sfx, rx/keva, rx/graft, rx/yada and MoneroV2 configs (`src/crypto/randomx/randomx.cpp`). **Safex's variant is a one-line constructor**: `ArgonSalt = "RandomSFX\x01";`. A salt-only BlackSilk variant is therefore minutes of work for anyone who builds xmrig. "Hours" (R9) is generous. |
| F18 | Bonneau 2016; ProgPoW Kik exploit; Argon2 1.33× tradeoff; scrypt CMC | **Not re-fetched** | Well known and consistent with the literature. A's citations look correct. Treat them as A's, not re-verified. |

---

## 3. A vs B: agreements, disagreements, resolutions

### Agreements (both reports; consistent with this cross-check)

1. **REDESIGN REQUIRED.** SKC-1 is not superior to RandomX on the evidence.
2. A 32 MiB per-nonce scratchpad is SRAM-feasible on an ASIC, so algorithmic ASIC resistance is weak.
3. A one-pass graph with uniform parents has a TMTO tail weakness: late blocks are rarely referenced. The fix is an Argon2-style index map, more than one pass, or a second phase.
4. The nonce and full header must enter the memory-hard state through a wide (≥256-bit) binding (ProgPoW/Kik class). The proposal leaves this unspecified, and that is potentially fatal.
5. Real advantages:
   - no per-epoch 256 MiB cache;
   - simpler, deterministic, safe Rust with no JIT gap;
   - cheaper verification than pure-Rust RandomX light mode.
6. The real driver is rentable or shared RandomX hashpower. Rental cannot be defeated by any algorithm on a small chain (Bonneau).
7. Any switch is a consensus change needing owner approval. Keep RandomX v1 for the testnet.

### Disagreements and resolutions

| Topic | A | B | Resolution |
|---|---|---|---|
| **Division** | Remove, or use a reciprocal multiply. It adds latency, not CPU specificity; an ASIC divider is cheap; it causes inter-CPU unfairness. | A real anti-GPU lever *combined with the per-nonce memory cap* (low GPU occupancy cannot hide emulated 64-bit division). It hurts Skylake-era Intel and is weak against ASICs. | **Partly resolved.** Both are right on their own axis and agree it does nothing against ASICs (F9b history; RandomX design.md). The Skylake penalty is confirmed (35–90 vs 9–17 cycles, F11). B's GPU benefit is a model, not a measurement: it depends on VRAM latency and the SASS instruction count of 64-bit division. **Unresolved quantitatively.** Division must not be counted as a security argument. Whether it is worth its CPU-fairness cost depends on B's GPU lab (Lab 2). |
| **Verification cost** | "One hash" (cheap). | 15–80 ms and 32 MiB per header, symmetric with mining. | **B is correct.** Per-nonce memory hardness means a verifier pays one full miner hash, not a cheap check. It is still 7–30× cheaper than today's 548 ms pure-Rust light verify. |
| **GPU outlook** | Plausibly GPU-competitive or GPU-favoured (Ethash analogy). | GPU about 1–3× a desktop CPU in J/H, because occupancy is capped at ~700 nonces in 24 GB. | **Unresolved.** B's model is more specific, but its key inputs are unmeasured. |
| **ASIC/CPU magnitude** | Qualitative ("on-die SRAM regime"). | 10–200× (energy model). | Direction confirmed (F10). The magnitude is an estimate with wide error bars, so treat it as "≫ RandomX's 3–4×" (F2). |
| **RandomX ASIC margin** | ~1–1.2× | ~1.2–1.6× (X5) | **Both CORRECTED** to ~3–4× with the X9 (F2). |
| **RandomX config variant** | Parameter-level variant "within documented bounds" separates only the zero-effort path. | First-line option; breaks plug-and-play NiceHash/Qubic. | **Resolved:** **salt-only** (F16). The designers recommend it, and every audited instruction and VM rule stays intact. Other parameters are "not recommended" by the designers, so A's "parameter-level" should be narrowed to the salt. Both agree, correctly, that it stops only zero-effort redirection (F17). |
| **Merge mining** | Impossible as designed (no aux-PoW). | Listed as an alternative (Tari model). | **Resolved:** technically possible only with an aux-PoW header redesign and acceptance of Monero's seeds. **Not recommended** (§4(b)), in agreement with the repository's prior rejection (I4 §2.3). |
| **Qubic facts** | Aug 2025, ~6-block reorgs, "peer-reviewed" no sustained 51%. | 6-block reorg, ~2.6 GH/s. | **CORRECTED** (F4): the 18-block reorg of 2025-09-14 is the relevant worst case. The arXiv paper is a preprint. 2.6 GH/s is unverified. |

### What both reports missed

- The repository already has a decision-ready analysis (I4 §2, §7.2), which this summary aligns with:
  - salt-only on mainnet;
  - typed `PowConfig` plus offline salt vectors at P2;
  - merge mining rejected;
  - J1 stratum bridge or J3 interpreter work;
  - halt-on-deep-reorg as an off-by-default flag.
- RandomX's ASIC margin with the X9 is 3–4×, not parity.
- The 18-block Monero reorg, and Monero's own response (opt-in rolling DNS checkpoints).

---

## 4. Alternatives against the actual threat (rented or shared RandomX hashpower)

### (a) BlackSilk-specific RandomX configuration (salt only)

- **Effect:**
  - removes **zero-effort** redirection: stock xmrig, NiceHash's rx/0 market, Qubic's and pools' rx/0 stratum, and X5/X9 stock firmware (whether they can do variants is unverifiable, F3);
  - NiceHash has no market for an unlisted variant;
  - a determined attacker needs a one-line xmrig patch (F17) and generic CPU or cloud capacity.
- **Cost:** low (S–M).
  - The Argon2 salt is a single constant, but the repository needs a typed `PowConfig`.
  - The official rx/0 vectors must keep running in `Monero_v1` mode.
  - BlackSilk-salt vectors would be generated offline with the reference implementation, as test tooling only (I4 P2).
- **Consensus impact:** yes (PoW identity, fingerprint, genesis). Best done at the v3 or mainnet genesis.
- **Timing:** I4 recommends rx/0 for the controlled testnet and deciding salt-only for mainnet before the final genesis freeze. If Monero activates v2 first, consider salt-on-v2 (F8: not activated; no date).
- **Privacy/decentralisation:**
  - neutral on privacy;
  - mildly positive on decentralisation, because it removes the largest pools' zero-cost redirection;
  - it also removes plug-and-play honest xmrig mining, unless BlackSilk publishes the variant or a J1 bridge.

### (b) Merge mining with Monero (Tari RxM model)

- **How it works** (F15): the Monero coinbase `extra` commits a hash of the BlackSilk header. The BlackSilk header carries an aux-PoW blob (Monero header, coinbase proof, partial Keccak state, `randomx_key` = Monero's seed).
- **Required changes:**
  - a variable-length aux-PoW field (hundreds of bytes), which breaks the fixed 100/140 B header;
  - a PoW-excluding "mining hash";
  - validators building RandomX caches for **Monero-chosen seeds**, which BlackSilk cannot verify without tracking Monero (a cross-chain dependency and a new cache-build DoS surface; Tari only bounds seed reuse to 3000 blocks);
  - following Monero's PoW upgrades (v2/v17), which gives Monero governance a hand in BlackSilk's PoW;
  - it is incompatible with (a).
- **Security model:** it borrows only the share of Monero hashrate whose pools opt in. Any large Monero pool, Qubic included, can attack at zero opportunity cost. There are historical pool-majority episodes (Namecoin/F2Pool; CoiledCoin from memory, unverified).
- **Privacy:**
  - the merge-mining tag links BlackSilk blocks to Monero pool identities and payout patterns (cross-chain miner clustering);
  - it concentrates block production in a few pools, which concentrates miner IP metadata.
- **Cost:** XL. **Timing:** a consensus redesign of header and PoW.
- **Recommendation:** **NOT RECOMMENDED.** This agrees with I4 §2.3 and R15.

### (c) SKC-1 redesign

- **Effect:**
  - no liquid rental market at launch;
  - an attacker needs a kernel (days to weeks), then generic CPU or GPU cloud. B's model estimates that a few hundred dollars of GPU cloud overwhelms a hobbyist CPU network if the GPU ratio is ≥1;
  - one SKC-1 ASIC or FPGA would own the chain.
- **Cost:** XL.
  - New primitive and spec, a second implementation, a TMTO simulator, a GPU lab, multi-pass internal review, and a possible external cryptanalysis (owner decision).
  - No external reference vectors.
- **Consensus impact:** total (new PoW, deletes the seed machinery).
- **Timing:** not credible before the v3 freeze. Earliest is a scheduled post-launch fork after a research prototype passes the gates.
- **Privacy/decentralisation:**
  - closes the honest-miner gap (safe Rust near-optimal), which is positive;
  - favours memory-channel-rich servers and large-L3 parts (B §1.3), which is negative.
- **Recommendation:** an isolated research prototype only, **never for activation** without owner approval and evidence.

### (d) Policy measures

1. **Confirmation-depth guidance plus reorg and hashrate-anomaly alerts.**
   - No consensus change; cheap; recommended now.
   - Monero's 10-block lock was exceeded by an 18-block reorg (F4), so guidance must scale with value and observed hashrate share, not a fixed 10.
2. **Halt-on-deep-reorg flag** (I4 §7.2: K ≥ 720, operator override, off by default on the testnet).
   - Bounds rewrite damage and the size of undo data.
   - Splits the network visibly under attack.
   - It is a *local* finality rule, which is a soft consensus property. **OWNER APPROVAL** before it is on by default anywhere.
3. **Minimum chain work.** Today there is no hard-coded minimum (`docs/p2p.md` §12; `chain/src/sync_policy.rs` uses the dynamic `anti_dos_threshold`).
   - A mainnet `min_chain_work` constant updated per release is an IBD anti-DoS and eclipse measure, not protection against a majority attacker.
   - It is node policy, but it embeds a release-time trust assumption.
4. **Checkpoints, DNS or developer-signed.**
   - Monero adopted these only as an opt-in emergency bandaid.
   - They conflict with BlackSilk's decentralisation stance (no trusted operators).
   - **Not recommended** beyond advisory assume-valid for sync (I4).
   - Any such step needs **OWNER APPROVAL**.

### (e) A faster honest pure-Rust miner (no JIT)

- **Effect:**
  - R9's O1–O6 programme (SoA dataset build, cheaper rounding emulation, safe prefetch-by-load, and others) is estimated to reach 5–15× slower than JIT, from ~70× (F13). It cannot close the gap.
  - It also cuts the verification cost (light hashing) and the 179 s seed-switch stall, which is the bigger security win (§5).
- **Cost:** M. **Consensus impact:** none, guarded by the official vectors and full/light agreement tests.
- **Timing:** can be done any time. Per R9 it is P2 before the testnet for O0–O2. The git log shows no O1–O6 work yet (unverified beyond the log).
- **Privacy/decentralisation:** positive. The J1 option (a pure-Rust stratum bridge so honest users can run third-party JIT miners outside the build) closes the gap fully, but it is a policy question under the pure-Rust rule (**OWNER**).

### Comparison table

| Option | Stops zero-effort rental | Stops a determined renter | Cost | Consensus | Before v3 freeze? | Privacy | Decentralisation | Verdict |
|---|---|---|---|---|---|---|---|---|
| (a) Salt-only RandomX | **Yes** | No (1-line xmrig patch) | S–M | Yes (identity) | Decide before mainnet genesis; vectors/config now | Neutral | + (if variant published) | **Recommended for mainnet decision** (OWNER) |
| (b) Merge mining | n/a (invites Monero pools) | No (zero-cost pool attack) | XL | Yes (header/aux-PoW, foreign seeds) | No | **−** (cross-chain linkage) | − (pool concentration) | **Not recommended** |
| (c) SKC-1(r) | Yes (no market at launch) | No (GPU cloud / first ASIC) | XL | Total | No | Neutral | ± | **Research prototype only** |
| (d1) Confirmation guidance + alerts | No | Mitigates harm | S | None | Yes | Neutral | Neutral | **Do now** |
| (d2) Halt-on-deep-reorg flag | No | Bounds depth of damage | M | Local finality (soft) | Flag yes, default-on later | Neutral | − (operator decisions) | Flag now; defaults OWNER |
| (d3) Min chain work | No | No (anti-DoS / IBD only) | S | Policy | Mainnet | Neutral | Mild trust | Mainnet release policy |
| (d4) Checkpoints | No | Yes, by trust | S | Effectively yes | — | Neutral | **−** | **Not recommended** |
| (e) Faster safe interpreter | No | No (gap 70× → ~5–15×) | M | None | Yes | Neutral | + | **Do (P2)**, mainly for verification |
| (e') J1 stratum bridge | No | Raises honest hashrate | S–M | None | Yes | Neutral | + | OWNER (pure-Rust policy) |

---

## 5. Separate issue: header PoW verification cost (anti-DoS, independent of SKC-1)

### Facts (F12, F14)

- Pure-Rust light verification is ~0.55 s per header single-threaded (0.16 s with 4 threads) plus 256 MiB per key.
- A new key costs ~1.2 s of cache build.
- A JIT attacker mines at ~1.4 ms per hash, so the asymmetry is ~4–7× at testnet D0 = 100 and ~300–500× only if difficulty collapses toward 1.

### Existing mitigations (verified in code and docs)

- **Work gate (R1-C1).** `chain/src/sync_policy.rs` (`anti_dos_threshold`, `worth_verifying`; `ANTI_DOS_BLOCKS = 144`):
  - RandomX runs only for headers whose claimed work makes them competitive;
  - deep cheap branches must show ≥ ½ of our work per height;
  - difficulty fields are pre-checked without PoW;
  - this closes most of R9-2's genesis-era branch attack.
- **Seed guards.** `seed_is_live` stops unknown-version headers from forcing cache builds. `pow_chunk` stops an unverified header in the same chunk from keying another. Caches are built outside the lock and bounded (`MAX_CACHES`; `docs/consensus.md` §9; RT-MUT bounded cache store).
- **Queue bounds** (`docs/p2p.md` §6):
  - one batch in flight per peer;
  - a bounded queue per IP and in total;
  - batches from departed or banned senders are not hashed;
  - hashing stops when the sender leaves.
- **Scoring** (`docs/p2p.md` §10): invalid PoW or a bad difficulty scores 100, which means a 24 h ban (IPv6 per /64). An unsolicited multi-header batch scores 10.

### Residual risk (open)

- **Single-header announcements.** A single plausible header that extends the tip passes the gate and costs one light hash before it fails. Bans are per IP or /64, and **Tor onion inbound peers cannot be banned** (`docs/p2p.md` §12). R8 estimated ≈1.5 bad headers/s keeps the single header worker busy with address rotation. Neither the docs nor this check shows it closed.
- **No hard-coded minimum chain work**, no asmap, and none of these mechanisms has run against a live adversary (`docs/p2p.md` §12).
- Wallets also verify headers in light mode (256 MiB plus ~0.5 s per header; A §1.3).

### Options (no consensus change)

1. **R9 O1–O2:** faster light hashing (option e).
2. **Presync-style per-peer rate limits on single-header announcements**, plus cost accounting for onion peers (per-connection token buckets).
3. **An Equi-X admission puzzle** for unsolicited headers or inbound connections. R9 proposed this for P2P only, not consensus; it would need its own review.
4. A release-time `min_chain_work` for mainnet.

### How the PoW options interact with this issue

- SKC-1 would cut per-header cost to ~25–70 ms, but this does not by itself justify a new PoW.
- RandomX v2 "commitments" do not provide a cheap pre-filter (R9, assumed).
- Salt-only (a) does not change verification cost.

---

## 6. Recommended ordered plan for the rental-hashpower threat

Research recommendation only. **Nothing here authorises production activation.**

**No approval needed** (docs, tests, node policy within delegated routine work):
1. **Document honestly** (consensus.md, the K1 assumption, operator and user guides):
   - a small RandomX chain is cheaply attackable; ~1 MH/s·day ≈ $40 on NiceHash (F5);
   - Qubic's 18-block Monero reorg (F4) is the realistic precedent;
   - the testnet stays rx/0 (I4 §2.4).
2. **Confirmation-depth guidance plus reorg and hashrate-share monitoring alerts** (d1).
3. **Verification anti-DoS hardening** (§5):
   - R9 O0–O2 interpreter work (e);
   - rate limits and cost accounting for single-header announcements, including onion peers.
4. **Typed `PowConfig` with salt-only variant support plus offline-generated BlackSilk-salt vectors**, inactive (I4 P2). This makes decision 5 cheap and safe and keeps the official rx/0 vectors in CI.

**OWNER APPROVAL required** (PoW, consensus, finality or policy-identity decisions):

5. **Mainnet PoW identity, before the final genesis freeze:** salt-only RandomX (a). Optionally on v2 if Monero has activated it with stable official vectors by then (F8).
6. **Halt-on-deep-reorg:** ship the flag off by default now (policy). Turning it on by default and choosing K (≥720) need approval.
7. **Mainnet `min_chain_work` release policy.**
8. **The J1 stratum bridge** (honest users running third-party JIT miners): a pure-Rust-policy decision.
9. **SKC-1r:** whether to fund an isolated offline research prototype against the A §10 and B §6 gates. It needs a separate machine, nothing in the BlackSilk tree, and no consensus code. Any activation would be a separate later decision with evidence and possible external cryptanalysis.

**Not recommended:** merge mining (b); developer or DNS checkpoints as finality (d4); multi-algorithm lanes; Wownero-style parameter changes beyond the salt.

---

## 7. Unresolved questions

1. Can X5/X9 firmware mine a non-rx/0 RandomX config, and how quickly? (F3)
2. Monero v2/v17 activation timing (F8). It affects whether BlackSilk's rx/0 remains "Monero's algorithm" and the choice of mainnet base (v1 or v2).
3. SKC-1: the GPU ratio, the value of division, the TMTO curve and the ASIC magnitude are all model outputs (B §8, A §9). They are unresolved until isolated labs run.
4. Actual JIT/xmrig performance on BlackSilk-typical hardware (the 1.4 ms figure comes from the README). Measured pure-Rust gains after O1–O2.
5. Whether R8's single-header DoS residual is already closed in code. This check reviewed docs and `sync_policy.rs` only.
6. Expected honest hashrate at testnet and mainnet launch (B §4.4 assumes 4–40 kH/s pure-Rust or 0.1–1 MH/s xmrig). This sets every rental-cost number.
7. The Qubic paper's peer-review status, and the exact hashrate Qubic redirected at the 2025-09-14 peak.

---

## Sources (checked 2026-10-04)

- arXiv 2512.01437 (abs and HTML): https://arxiv.org/abs/2512.01437
- 18-block reorg:
  - https://www.coindesk.com/web3/2025/09/15/monero-suffers-deepest-ever-blockchain-reorganization-invalidating-118-transactions
  - https://github.com/WeebDataHoarder/Monero-Timeline-Sep14
  - https://decrypt.co/339424/moneros-largest-reorg-erases-36-minutes-transaction-history
  - MRL (unofficial) on rolling DNS checkpoints: https://x.com/moneroresearchl/status/1969133611149390026
- RandomX v2.0 release: https://api.github.com/repos/tevador/RandomX/releases/tags/v2.0 (published 2026-03-25T10:29:38Z)
- Monero PR #10038 (open): https://github.com/monero-project/monero/pull/10038 ; https://api.github.com/repos/monero-project/monero/pulls/10038
- RandomX configuration.md: https://github.com/tevador/RandomX/blob/master/doc/configuration.md
- xmrig variants:
  - https://xmrig.com/docs/algorithms
  - https://raw.githubusercontent.com/xmrig/xmrig/master/src/crypto/randomx/randomx.cpp
  - rx/v2 PR: https://github.com/xmrig/xmrig/pull/3769 (search result)
- Monero PR #4218: https://github.com/monero-project/monero/pull/4218
- CryptoNight fork history (secondary press):
  - https://cointelegraph.com/news/monero-hard-fork-appears-successful-as-devs-shun-bitmains-asic-miners
  - https://coinguides.org/monero-network-upgrade-v8-cnv2-beryllium-bullet/
- Antminer X5/X9 (vendor/retail):
  - https://pool.kryptex.com/articles/antminer-x5-en
  - https://www.asicminervalue.com/miners/bitmain/antminer-x9-1m
  - https://pool.kryptex.com/articles/how-to-mine-tari-randomx-en
  - X5 architecture discussion (sech1, JayDDee): https://bitcointalk.org/index.php?topic=5465216.0
- CPU efficiency: https://www.hashrate.no/cpus/7950x ; https://hashrate.no/cpus/9950x_
- NiceHash: https://www.nicehash.com/algorithm/randomxmonero
- Monero hashrate: https://www.coinwarz.com/mining/monero/hashrate-chart
- DIV latency: https://uops.info/html-instr/DIV_R64.html
- SRAM density:
  - https://fuse.wikichip.org/news/3398/tsmc-details-5-nm/
  - https://fuse.wikichip.org/news/7343/iedm-2022-did-we-just-witness-the-death-of-sram/
  - https://fuse.wikichip.org/news/5531/amd-3d-stacks-sram-bumplessly/ (via B)
- Tari: https://rfc.tari.com/RFC-0132_Merge_Mining_Monero ; https://rfc.tari.com/RFC-0131_Mining
- Repository (read-only):
  - `docs/consensus.md` §9–10
  - `docs/p2p.md` §6, §10, §12
  - `chain/src/sync_policy.rs`
  - `docs/evidence/pow-pool-2026-10-01/logs/after-idle.log`
  - `docs/reviews/full-review-2026-09-27/{R1,R8,R9,R12,I4,SX1,SX2}*.md`
