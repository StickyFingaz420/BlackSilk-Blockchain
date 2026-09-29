# Wave 4 coverage-guided fuzz campaign, optimized with debug assertions (W4-FUZZ)

Internal engineering evidence, not an audit. One Windows machine, one fuzzer process at
a time, 30 minutes per target. The campaign found no crash, leak, timeout, OOM or
artifact in these runs. That shows what these inputs reached in this time; it does not
show that these decoders are free of bugs, and it covers no stateful surface (chain,
mempool, peer protocol) and no proof verification.

## What ran
- **Commit:** the fuzz binaries were built from the tree committed as `9023201` (base
  `d6f4609`, branch `w4-fuzz`). `9023201` adds the `transport_handshake` target, the
  exact `kernel_diff` oracle, and the two F41-1 seeds (below).
- **Toolchain:**
  - `rustc 1.100.0-nightly (6eeff9a52 2026-09-23)` and `cargo 1.100.0-nightly
    (98a09e7e7 2026-09-21)`, `x86_64-pc-windows-msvc`;
  - cargo-fuzz 0.13.2 and libfuzzer-sys 0.4.13 (fuzz/Cargo.lock);
  - AddressSanitizer runtime `clang_rt.asan_dynamic-x86_64.dll` from MSVC
    14.44.35207 (`VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64`), on `PATH`.
  - CI pins nightly-2026-09-24; this local nightly is one day older.
- **Machine:** Intel i7-6700 (4 cores, 8 threads), 15.9 GB RAM, Windows 10.
  - A mutation-testing run shared the machine throughout, so rates are lower than on an
    idle machine and are not comparable with the 2026-09-25 campaign.
- **Flags:** built and run with `-O -a`, optimized with debug assertions, which also
  turns on rustc's overflow checks. This is the first long campaign with these flags
  (campaigns before 2026-09-27 ran without `-a`).
- **Build:** `cargo +nightly-x86_64-pc-windows-msvc fuzz build -O -a --fuzz-dir .`
  (from `fuzz/`, `CARGO_TARGET_DIR=C:/bszkeval/t-w4-fuzz`, `CARGO_BUILD_JOBS=2`).
- **Run:** per target, the flags of `fuzz/run_campaign.sh`, against a copy of the
  corpus outside the repository, with artifacts written there too
  ([run/run1.sh](run/run1.sh), driven one target after the other by
  [run/chain.sh](run/chain.sh)):

  ```
  cargo +nightly-x86_64-pc-windows-msvc fuzz run -O -a --fuzz-dir . <target> <scratch>/corpus/<target> -- \
    -max_total_time=1800 -timeout=60 -print_final_stats=1 -artifact_prefix=<scratch>/artifacts/<target>/ <per-target limits>
  ```

  The per-target limits are the script's:
  - `proof_decode`: `-max_len=4194304 -rss_limit_mb=4096`;
  - `zkvm_elf`: 32,768; `kernel_diff`: 8,192; `seed_words`: 1,024;
  - `store_records`: `-max_len=262144 -malloc_limit_mb=32`;
  - `transport_recv` and `transport_handshake`: `-max_len=65536 -malloc_limit_mb=32`;
  - every other target: 65,536.

  `proof_decode` ran last, after a free-memory check (8.1 GB free).
- **Starting corpora:**
  - the local corpora of the earlier campaigns (`fuzz/corpus/`, untracked, from
    2026-09-25) for the seven older targets;
  - plus a fresh run of the seed generator at this commit (`cargo +nightly build
    --locked --release --bin seeds`, then `seeds.exe` in the scratch directory),
    whose files replace their same-named older versions;
  - only the generated seeds for the five newer targets (their W3 corpora were not
    kept).

## Results

Per target: executions, rate, edge coverage (`cov`) and features (`ft`) at start
(`INITED`) and end (`DONE`), corpus files before and after, and the execution at which
the last new unit was found. Source: [run/summary.txt](run/summary.txt), from the
libFuzzer logs, via [run/table.sh](run/table.sh).

| Target | Time (s) | Executions | Exec/s | cov/ft start | cov/ft end | Corpus files | New units | Last new unit at | Peak RSS (MB) | Artifacts |
|---|---|---|---|---|---|---|---|---|---|---|
| `tx_decode` | 1,803 | 3,772,740 | 2,094 | 2269/4322 | 2614/5781 | 1,346 → 1,657 | 538 | 89 % of the run | 596 | 0 |
| `block_decode` | 1,806 | 1,943,303 | 1,079 | 1210/2221 | 1417/3184 | 514 → 593 | 174 | 86 % | 531 | 0 |
| `p2p_message` | 1,804 | 45,360,615 | 25,186 | 757/1371 | 862/2309 | 324 → 600 | 910 | 93 % | 744 | 0 |
| `zkvm_elf` | 1,811 | 1,822,382 | 1,011 | 1912/8206 | 1919/8601 | 1,336 → 1,524 | 209 | 99 % | 428 | 0 |
| `kernel_diff` | 1,803 | 233,869 | 129 | 1974/8761 | 1978/9308 | 961 → 1,191 | 293 | 88 % | 541 | 0 |
| `delivery_open` | 1,804 | 980,176 | 544 | 1548/2071 | 1548/2071 | 24 → 24 | 0 | none | 454 | 0 |
| `proof_decode` | 1,803 | 344,990 | 191 | 1189/3429 | 1224/3574 | 1,559 → 2,253 | 787 | 94 % | 645 | 0 |
| `store_records` | 1,810 | 161,870 | 89 | 822/1183 | 1017/2947 | 12 → 347 | 1,511 | 100 % | 551 | 0 |
| `seed_words` | 1,804 | 1,835,999 | 1,019 | 738/1081 | 886/2570 | 12 → 408 | 2,755 | 42 % | 674 | 0 |
| `transport_recv` | 1,803 | 653,698 | 362 | 1729/2318 | 1882/5780 | 11 → 287 | 924 | 99 % | 909 | 0 |
| `transport_handshake` (new) | 1,802 | 5,213,135 | 2,894 | 1216/1712 | 1221/1787 | 9 → 29 | 52 | 0 % (execution 147) | 436 | 0 |
| `addr_v2` | 1,803 | 18,211,048 | 10,111 | 625/948 | 886/3722 | 8 → 333 | 947 | 99 % | 762 | 0 |

- **Total:** 80,533,825 executions in 21,656 s (6.0 h). Every fuzzer exited 0. No
  artifact was written, and no log contains `ERROR`, `panicked`, `WARNING`, a leak or
  an out-of-memory report.
- **Slowest unit:** under 1 s for every target (`stat::slowest_unit_time_sec: 0`).

## Coverage, read honestly
- **Still finding new units at the end** (the last new unit came after 85 % of the
  run): `tx_decode`, `block_decode`, `p2p_message`, `zkvm_elf`, `kernel_diff`,
  `proof_decode`, `store_records`, `transport_recv`, `addr_v2`.
  - For these, 30 minutes did not saturate the feature count, so longer runs would
    add coverage.
  - `store_records` (89/s) and `kernel_diff` (129/s) are the slowest; they need hours,
    not minutes.
- **Edge coverage nearly flat despite new features:** `zkvm_elf` (+7 edges) and
  `kernel_diff` (+4 edges). New units there are new paths through edges already
  covered, mostly value-dependent paths through the interpreter.
- **Plateaued early:**
  - `transport_handshake`: its last new unit came at execution 147. The surface is a
    32-byte key decode (dalek), the identity check and the first 20 bytes of a frame,
    so this is expected.
  - `seed_words`: its last new unit came at 42 % of the run.
  - `delivery_open`: no new unit at all, as in every earlier campaign. Without the
    recipient's keys, every input stops at the view tag or the AEAD, so this target
    shows "no panic, nothing opens", not deep coverage of the record decoder.
- **Decode only:** `proof_decode` exercises the strict proof decoder, not the verifier.
  Verifier fuzzing, when it exists, can show robustness and non-malleability, not
  soundness (decisions, Agent 41, F41-8).

## Findings and their resolution
No crash, leak, timeout, OOM or artifact came out of this campaign. These harness
defects were found while preparing it, and are fixed in `9023201`:

1. **W4F-1, `proof_decode` limit (fixed).** A current transfer proof is 2,399,314 bytes
   (the seed generator's output at this commit). `run_campaign.sh` passed
   `-max_len=2200000`, and libFuzzer truncates longer seed files when it loads them.
   - So every campaign and CI smoke run since the proofs grew beyond 2.2 MB loaded the
     only real proof seed truncated, and it never decoded.
   - The corpus from 2026-09-25 holds proofs of the older format (the largest is
     2,184,722 bytes).
   - **Fix:** the limit is now 4,194,304 (`zk::params::MAX_PROOF_BYTES`), the largest
     proof the decoder accepts. This run loaded the full 2,399,314-byte seed.
2. **F41-1, no decodable PX seed (fixed).** The PX transaction seed (2,417,954 bytes)
   is over `tx_decode`'s 65,536-byte limit, so it was truncated at load too. Without
   it, `check_px_structure`, `check_px_balance` and `binding` were reached only if the
   fuzzer rebuilt a PX encoding by itself.
   - **Fix:** `seeds.rs` writes `tx_decode/px_short_proof` (the same transaction with
     a 64-byte proof blob, 4,077 bytes; the decoder treats the proof as opaque,
     length-prefixed bytes) and `block_decode/block_px`, a block carrying it (5,562
     bytes).
3. **F41-2, loose `kernel_diff` oracle (fixed).** The differential target, and
   `px/tests/fuzz.rs`, accepted any (native rejection, guest trap) pair.
   - **Fix:** a counting `Source` records whether the native kernel read past the end
     of its words. A guest trap now matches a native rejection only if it is
     `InputExhausted` and the native kernel did read past the end (or the input is
     over `MAX_INPUT_WORDS`). A native read past the end with a guest that exited
     normally is a divergence too.
   - **Demonstrated:** with the guest's cycle limit cut to 1,000 in the test (a local
     edit, not committed), `mutated_witnesses_get_the_same_verdict_natively_and_in_the_guest`
     fails with `NonCanonical: guest Trap { clk: 1000, pc: 80016, kind: CycleLimit }`.
     The old `(Err(_), Err(_))` arm accepts that silently.
   - With the real cycle limit, the test passes at 5,000 iterations (1,830 accepted,
     2,152 rejected with identical codes, 1,018 trapped on short input), and the
     30-minute `kernel_diff` run above found no divergence.

## New target: `transport_handshake`
- **What it covers:** the key exchange is the first thing a node reads from an
  unauthenticated peer, and no target covered it. `transport_recv` starts after a
  handshake between two honest sides.
- **Input:** a mode byte (which side the victim is on; whether to map the key bytes to
  a valid group element), up to 32 key bytes, then raw bytes.
- **Invariants:**
  - a key cut short is an end of stream;
  - the handshake succeeds exactly for a canonical, non-identity Ristretto255
    encoding, and refuses anything else with `BadKey`;
  - afterwards, bytes from a peer without the session keys never yield a payload:
    `Decrypt` from 20 bytes on, an end of stream below that.
- **Stable driver:** `p2p/tests/fuzz_handshake.rs` runs the same body in `cargo test`
  (20,009 inputs with `BLACKSILK_FUZZ_ITERS=20000`, no failure).

## Untrusted-input surfaces with no fuzz target
- **Per-peer P2P protocol:** the state machine in `p2p/src/net.rs` (handshake order,
  `GetHeaders`/`Headers`/`GetBlocks` flow, penalties, Dandelion). Individual messages
  are fuzzed (`p2p_message`, `addr_v2`); the protocol is not. It needs a sans-IO core
  first (F41-9).
- **RPC request parsing:**
  - the node's request guard (`node/src/guard.rs`: `Host` and `Authorization`
    parsing, content type, body limits) has unit tests only;
  - bodies are parsed by serde_json into derived types, and HTTP by hyper and axum.
  - A target would pull the node crate (axum, hyper, tokio) into the fuzz workspace,
    or needs the host parser exported. Not added.
- **Wallet side of node responses:**
  - the headers feed (`wallet/src/wallet/sync.rs`, `for_each_header` and
    `node_id_at`: hex, fixed-size chunks, `BlockHeader::from_bytes`);
  - the block entries (`decode_block`, which is `Block::decode`, fuzzed).
  - Header decoding is reached through `block_decode` and the `Headers` message in
    `p2p_message`; the paging and height checks are not fuzzed.
- **Wallet file and JSON state** (`wallet/src/wallet/persistence.rs`, serde_json):
  local, semi-trusted input; no target.
- **Proof verification:** CLSAG, BP+ and the Plonky3 verifier (W41-4, W41-5); and
  stealth output scanning.
- **Stateful consensus surfaces:** `HeaderChain`, `ChainManager` and mempool sequences
  (`header_chain`/`chain_manager` in dossier 41).
- **RandomX:** program decoding and the soft FPU.
- **SOCKS5 replies** (`p2p/src/socks5.rs`): tied to a `TcpStream`. Source-read: every
  read is bounded (at most 2 + 4 + 1 + 257 bytes).

## Corpora
- **Nothing from the grown corpora is committed.** Full corpora stay local (decisions,
  Agent 41), and minimized regressions go under `fuzz/regressions/` only for a failure;
  this campaign had none.
- **The two new seeds are generated,** not committed: `seeds.rs` writes them
  reproducibly, and CI's fuzz smoke runs the generator.
- **Where the corpora are:** in the campaign's scratch directory
  (`C:/bszkeval/w4-fuzz-scratch/corpus/`). The repository's untracked `fuzz/corpus/`
  was not changed. Copying the grown corpora there (or into a corpus store) is left to
  the coordinator.
- **Size:** after the run, 9,246 files and 377,141,651 bytes over the 12 targets
  (`proof_decode`: 2,253 files and 365,010,870 bytes). Before, with the generated
  seeds included: 6,116 files and 364,743,468 bytes. Per target:
  [run/corpus-before.txt](run/corpus-before.txt) and
  [run/corpus-after.txt](run/corpus-after.txt) (files, bytes).

## Limits of this evidence
- **Scope:** 30 minutes per target on a shared machine is a smoke-plus campaign, not
  saturation (see Coverage).
- **Oracles:** libFuzzer finds only what a target asserts or what panics or aborts.
  Debug assertions and overflow checks were on in every crate in the build, including
  dependencies and `third_party`.
- **Platform:** one platform (Windows, MSVC, AddressSanitizer). The CI fuzz smoke runs
  the same targets on Linux for 2 minutes each.
