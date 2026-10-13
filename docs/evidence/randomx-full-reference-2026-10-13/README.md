# Freeze gate: RandomX full (dataset) mode against the reference implementation

Date: 2026-10-13. Repo state checked: `rebuild/core` HEAD `cf2414e` (working tree clean before and
after; nothing was written to the repository during the runs).

## Purpose

Freeze gate B4 ([randomx-reference evidence](../randomx-reference-2026-10-04/README.md)) compared
BlackSilk's RandomX with the reference implementation in light mode only. Full (dataset) mode, the mode
miners use, had not been run against the reference: BlackSilk's own full mode was compared only with
its own light mode (CI `randomx-full` job), and xmrig's fast mode was supporting evidence only. This run
closes that gap for the inputs listed below.

**Result: no mismatch.** For every vector, the reference in full mode (6 runs per vector), BlackSilk's
pure-Rust full mode and the expected hash pinned in the repository are equal, and BlackSilk's light hash
equals its full hash.

## What was compared

- Reference: tevador/RandomX tag `v1.2.3`, commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`, the two B4
  library builds reused (not rebuilt):
  - stock (salt `"RandomX\x03"`), the control;
  - salted: the only change is `RANDOMX_ARGON_SALT "BlackSilk/RandomX/v1"` in `src/configuration.h` and
    its mirror `src/asm/configuration.asm` (one line each).
- Toolchain for the drivers: MSVC 14.44 (VS 2022 Community), `cl /O2 /EHsc /MD`.
- Drivers (public API only): per key, `randomx_init_cache`, then `randomx_init_dataset` over all
  34,078,719 items (4 threads), cache released, then one `randomx_create_vm(flags, nullptr, dataset)` per
  VM setup and `randomx_calculate_hash`. One ~2.08 GiB dataset per process at a time; one process at a time.
- Full mode only. Two dataset-initialisation paths times three VM setups, so 6 reference runs per vector:
  - `init-jit`: cache flags `0x6a` (JIT-compiled SuperscalarHash, AVX2 Argon2);
  - `init-interp`: cache flags `0x0` (interpreted SuperscalarHash, reference Argon2);
  - VM `interp`, flags `0x4` (interpreter, software AES); `jit`, flags `0xc` (JIT, software AES);
    `auto`, flags `0x6e` (JIT, hardware AES). All with `RANDOMX_FLAG_FULL_MEM`.
  - No large pages, no `RANDOMX_FLAG_SECURE`.
- BlackSilk side: a scratch copy of the `randomx` crate made with `git archive cf2414e randomx`
  (byte-identical source), with the repository's release profile and its `Cargo.lock` at `cf2414e`
  (resolved versions identical: aes 0.8.4, blake2 0.10.6, cipher 0.4.4, cpufeatures 0.2.17,
  digest 0.10.7), built `--offline --release` with rustc 1.98.1. One added example, `full_corpus.rs`,
  uses only the public API: `Cache::new` (BlackSilk salt), `Vm::light` as a cross-check,
  `Dataset::new(&cache, 4)`, `self_test::check_dataset` and `Vm::full`. A row fails if full differs from
  the expected hash or light differs from full.
- Expected values come from the repository at `cf2414e`:
  - 1a–1f: `randomx/src/self_test.rs` `VECTORS` (the published tevador/RandomX test vectors);
  - bs-1a–bs-1f: `randomx/src/self_test.rs` `BLACKSILK_VECTORS` (same values as `lib.rs` `BS_1A..BS_1F`);
  - mining blob: `consensus/tests/golden.rs` `randomx_known_answer_on_a_mining_blob`, key = the regtest
    genesis id `3dbdba2a...cc106141` (pinned in `genesis_ids_golden` and `params.rs`), input = the sample
    header's `pow_blob(0x00DEB06E)`;
  - corpus: `randomx/tests/data/randomx-reference-light-v1.txt`, all 26 lines (L1–L16 random cases,
    L17–L24 edge cases, L25 the IMUL_RCP power-of-two NOP case of run G3, L26 the 783:42 case).

## Results

| set | vectors | reference full-mode hashes | BlackSilk full mode | result |
|---|---|---|---|---|
| stock control, official 1a–1f | 6 | 36 / 36 equal to the published values | through the ignored test below | all equal |
| salted bs-1a–bs-1f + mining-blob known answer `410e353c...` | 7 | 42 / 42 | 7 / 7, light = full | all equal |
| corpus `randomx-reference-light-v1.txt`, 26 lines (incl. L25, L26) | 26 | 156 / 156 | 26 / 26, light = full | all equal |

BlackSilk full mode on the salted vectors and the corpus: 33 / 33, and light = full on all 33.
`check_dataset` (sampled dataset items recomputed from the cache) passed on every key.

The crate's ignored full-mode tests also passed at `cf2414e` (scratch copy), 4 of 4 in 1212 s:
`cargo test --offline --release --lib -- --ignored --test-threads=1 full_mode the_dataset_check_rejects_another_cache`.
- `tests::full_mode_matches_light_mode`: official 1a–1f with the Monero salt in full mode, bs-1a–bs-1c,
  and 512 random inputs per key (full = light) over 4 datasets;
- `self_test::tests::the_full_mode_check_passes`, `the_full_mode_check_detects_a_wrong_answer`,
  `the_dataset_check_rejects_another_cache`.

The other three ignored tests (`fpu_oracle_full`, `pinned_digest_large`, `write_reference_requests`)
are not full-mode tests and were not run.

### Per-vector table

Long keys and inputs are shortened to `first16...last8 (hex length)`; `-` is empty. "ref" is the one
distinct value printed by all 6 reference runs; "BS" is BlackSilk's full-mode hash (and its light hash).
Every row: expected = ref (6/6) = BS full = BS light.

Stock build, Monero salt (BlackSilk side through `full_mode_matches_light_mode`):

| vector | expected = ref (6/6) | |
|---|---|---|
| 1a | 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f | MATCH |
| 1b | 300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969 | MATCH |
| 1c | c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8 | MATCH |
| 1d | e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc | MATCH |
| 1e | c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1 | MATCH |
| 1f | 78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8 | MATCH |

Salted build, `"BlackSilk/RandomX/v1"`:

| vector | key | input | expected = ref (6/6) = BS | |
|---|---|---|---|---|
| bs-1a | 74657374206b657920303030 | 5468697320697320612074657374 | 424838440b398cd20d703905167a6d07b19816b0ab246b678218649fa7d70802 | MATCH |
| bs-1b | 74657374206b657920303030 | 4c6f72656d206970...616d6574 (52 hex) | 7d742273815a73a2fea8b7e0102bf8b47d6b7cd2657a3cd7a7d2dd9f4e798d8f | MATCH |
| bs-1c | 74657374206b657920303030 | 73656420646f2065...69717561 (130 hex) | 182e687dcbd7d60daecef46c8b7a3369fa0b0e5517d21b57a31b1bf7ff9c5bb6 | MATCH |
| bs-1d | 74657374206b657920303031 | 73656420646f2065...69717561 (130 hex) | 7c5f9da95f68936abddc00535549716ccb5c1c5965fe31fc7cd8d047950bcede | MATCH |
| bs-1e | 74657374206b657920303031 | 0b0b98bea7e805e0...bd82f416 (152 hex) | a4687b72af500c1e764655b42db9580ee0b72a6c06b8020d97597ec037b2c1bf | MATCH |
| bs-1f | 7797373ea4633194...1710abe8 (62 hex) | 1010e1eaf8cf067b...c5a9bb0d (152 hex) | 2d2e59cff0b64955878021d9c35b3300f93980434522b15e8cde421210ca35ae | MATCH |
| blob | 3dbdba2aca8842cd...cc106141 (64 hex) | 4253696c6b2f31c5...00000000 (94 hex) | 410e353c0ecbcea5389d97931ed60ce2a4382c30619de617728a4d858e2d97c1 | MATCH |

Salted build, corpus `randomx/tests/data/randomx-reference-light-v1.txt`:

| line | key | input | expected = ref (6/6) = BS | |
|---|---|---|---|---|
| L1 | 2c8adf922d084f42...c60dbdaa (64 hex) | 04621feb990122bb...0a765e5e (94 hex) | c79b62dac799676f470ac9b9831809cd453e958ba94c5fcc2f0be80f35b42fe3 | MATCH |
| L2 | 2c8adf922d084f42...c60dbdaa (64 hex) | b76f1840ff0d78e2...ad8ddd3d (152 hex) | 55f0114e005a5329c3ac69292c66c1c94d0abe14bc473b3f25cb01a28603bf7a | MATCH |
| L3 | 2c8adf922d084f42...c60dbdaa (64 hex) | be8b592b4127dbbf...8e44fd2c (200 hex) | 3a6bbc86e77043f618117e194b7f28ff8e81a720abeb9f21b8ba259cf6d17897 | MATCH |
| L4 | 2c8adf922d084f42...c60dbdaa (64 hex) | - | 2d476bf4fc32ebfb27f31e57bed4dbdb80b8f137779918d397a46b29983faa33 | MATCH |
| L5 | 2c8adf922d084f42...c60dbdaa (64 hex) | 46 | e091856763ad72cb51148dc837c9fd2105e16df1d66d7f4f334cd67132fce5e6 | MATCH |
| L6 | 2c8adf922d084f42...c60dbdaa (64 hex) | 0c5db1ef19fe864e...163431db (126 hex) | 26a9590777dce0a41e9e8203b0de684234add4b31079cfe2863143b917b4686f | MATCH |
| L7 | 2c8adf922d084f42...c60dbdaa (64 hex) | 178db17ad31a1b54...c2508d5d (128 hex) | 08ff7170d8e84898463b0071d43c3fb115e37b4e68c29a4f3a6e5eb4f7a4ccc2 | MATCH |
| L8 | 2c8adf922d084f42...c60dbdaa (64 hex) | b6fb078fd3781b5e...c7b67ff4 (256 hex) | f355f3c852fc5f26d2b1eeb976ecb3f6f1e6e19ebb915a2772d469cdaa74c1ec | MATCH |
| L9 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | 078da24c507e74d8...d23e28a9 (94 hex) | a125583ec9b2354cae12da38553dead8264cac074ca3240b3bc3c1c53b889bf2 | MATCH |
| L10 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | a6701a111df9b3a9...82ba8b18 (152 hex) | 1ce54fa3ffb8f3cc31887cceceace606952d2ff470c6d256ec1a62a487cf5a1e | MATCH |
| L11 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | bf86fcb8b46e1c01...6f273769 (200 hex) | 2556e7bba1e25fd511f0f6dceef60af8c420bfe44827b549c8c0c1e8fbbad230 | MATCH |
| L12 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | - | ab491b8fb05954f48e623e6982ea08160925d5ba69277a169f2a3c8223989813 | MATCH |
| L13 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | be | dc30de6583e2018d6b3edceec4165c9ec313de8c3c216193555e4b1979463c70 | MATCH |
| L14 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | 2e572a2f917607a5...9c2efb3c (126 hex) | 076f2f3ef693f1b0bd8976c1a9c3403d0b864281e4cbcc04493b17d5569c7f6d | MATCH |
| L15 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | a274184491773d4e...44af71d4 (128 hex) | 57dbd0f684f0eaa94e20157453c7523eb7119f3eb855cab3f5549b91b085d49b | MATCH |
| L16 | e32db2b1c5264f07...c2e7ecd1 (64 hex) | 4f8998da7c4d164b...2f463086 (256 hex) | de4010c00fe6bae14ef140049a0e32cc0880b73ae3fe05ca8c9fcfb5611770c3 | MATCH |
| L17 | - | - | e34a69baf8675acb0eeb4bd3090b52351be6ec627ab1c70cff17df883e901381 | MATCH |
| L18 | 68 | 8e598501dc1c00b3...92e9fa84 (94 hex) | 22517eb572f627dcf0272d2d3ac02f97f3f680186328dd96e9bd47e2a97544a4 | MATCH |
| L19 | bbe905b8459e352e...38b521f6 (62 hex) | bc03751d9b35a6e6...697f3b8a (152 hex) | 8475af6ffcdd8b6e1e54462502235efd85d72c6f679eb4fe9a572cf2f29432eb | MATCH |
| L20 | dae5caaf2b364de6...1ad8c7f3 (120 hex) | 839cf3e874d344b9...ec3736b3 (200 hex) | 594abc4726fc0115198ab32150e173eb4f171e566f74f6a53d9e2f91ef12b022 | MATCH |
| L21 | 76069c03d4e9d6e1...358b7961 (122 hex) | 42a9840971516fbf...b82a066c (200 hex) | be78f1a18ad04f409c710ac55309591cb64ce5843704167dffe28b4921409725 | MATCH |
| L22 | bdf5f5b5a405b114...e16d14c4 (256 hex) | e5 | 49cda9fac1950272644ea9e0f1e5ce69c78a9cdd9bbf7e08745886938d6be855 | MATCH |
| L23 | 13bf8f7961a44df3...8c07ffdc (64 hex) | 448b6d27c9fbe0c7...9ab2033e (2000 hex) | fa89b62ea98fa3de6ff8a32186e8e0666bc8fbde146f5bb619be857470c6f465 | MATCH |
| L24 | 4705848262a87331...407266f1 (64 hex) | f4db5a858840c1b8...fcda0c7c (4096 hex) | 1900c6c0c66afeb70c05e4c35da260acba50a92ffd99dbb2ddd5b551dc04ab1a | MATCH |
| L25 | 74657374206b657920303030 | 4733207263702070...36343232 (42 hex) | 344e12551fd2c74bef690027a37b3924520828a6aa62b085573c98bc053f187b | MATCH |
| L26 | 7278726561636831...00000000 (64 hex) | 5468697320697320612074657374 | 95a05dbf5a7cc171eaba3cf9da8fbf07bbc57f6a6539e35a8d4d34d95471034a | MATCH |

### Cross-checks made when recording this evidence

- Every non-comment row of the 8 raw outputs (6 reference, 2 BlackSilk) was re-read: printed hash =
  expected (and light = full on the BlackSilk side) on 18 + 18 + 21 + 21 + 78 + 78 reference rows and
  7 + 26 BlackSilk rows; each reference output covers every vector under `interp`, `jit` and `auto`.
- The key, input and hash of every corpus row, per VM setup and per initialisation path, and of every
  BlackSilk corpus row, equal the 26 lines of the corpus file at `cf2414e`. The corpus copy used for the
  runs differs from the committed file only in line endings (CRLF).
- Every expected value of the vector sets is found in the repository at `cf2414e` (`randomx/src/lib.rs`,
  `randomx/src/self_test.rs`, `consensus/tests/golden.rs`).

## A false alarm, explained

The first salted corpus run with `init-jit` reported 3 mismatches. Cause: the corpus was fed through a
PowerShell pipe, which put a byte-order mark in front of the first line, a comment. The driver then read
that line as a vector (key `0101`, expected `light-mode`) and flagged it under all three VM setups; all
78 rows of the 26 real lines matched in that run. The run was repeated with `cmd` file redirection:
78 / 78 equal. Every later run reads the file directly. The faulty output is kept, under its own name,
with the internal records.

The `exit=` field is empty in the footers of the two BlackSilk example runs (a PowerShell
`Start-Process` exit-code quirk, fixed afterwards in the runner); the evidence for those runs is their
per-row verdicts and `RESULT: ALL MATCH` lines.

## Resources and time

One dataset process at a time; another agent was building on the machine, so the times are indicative.

| run | keys | dataset init per key | total wall | peak memory |
|---|---|---|---|---|
| reference stock, init-jit | 3 | 7.5–8.2 s (4 threads) | 25.8 s | 2.29 GiB |
| reference stock, init-interp | 3 | 234–320 s (4 threads) | 830 s | 2.29 GiB |
| reference salted vectors, init-jit | 4 | 7.1–7.5 s | 31.5 s | 2.29 GiB |
| reference salted vectors, init-interp | 4 | 211–230 s | 886 s | 2.29 GiB |
| reference corpus, init-jit | 12 | ~7 s | 92.8 s | 2.29 GiB |
| reference corpus, init-interp | 12 | ~200 s | 2384 s | 2.29 GiB |
| BlackSilk salted vectors (full + light) | 4 | 193–198 s (4 threads) | 794 s | 2.29 GiB (polled) |
| BlackSilk corpus (full + light) | 12 | 198–207 s (4 threads) | 2421 s | 2.29 GiB (polled) |
| BlackSilk ignored full-mode tests | 8 datasets | 118–123 s (8 threads) | 1212 s | not measured |

From the test output, BlackSilk's full-mode hash takes about 48 ms on one thread; light mode about
550 ms per hash.

## Limits

- Evidence for these inputs only (6 + 7 + 26 vectors, plus the crate tests' random inputs compared
  full against light), not a proof for all keys and inputs.
- One x86-64 Windows machine: Intel i7-6700 (4C/8T, AES-NI, AVX2). Not run on aarch64 or any other
  platform or CPU.
- BlackSilk's software-AES path was not forced: the `aes` crate selects AES-NI at run time
  (`cpufeatures`), and this CPU has it. The reference side ran both software and hardware AES.
- Large pages and `RANDOMX_FLAG_SECURE` were not exercised on the reference side.
- This is an internal comparison run, not an external review.

## Internal records (outside the repository)

The raw outputs, drivers, scripts and build log are internal records under `C:\bszkeval\rx-ref\full\`
(reference side) and `C:\bszkeval\rx-ref\bsfull\` (BlackSilk scratch copy). They are not copied here;
no binaries are kept in the repository.

- Driver sources: `kat-full-common.h`, `kat-full.cpp` (vectors built in, expected set chosen by the
  build's salt), `kat-full-corpus.cpp` (corpus format on stdin); `blacksilk-full_corpus.rs` (the
  BlackSilk example).
- Scripts: `build-full.bat`, `run-peak.ps1`, `run-rest.ps1`, `compare.sh` (three-way comparison;
  exits 1 on any mismatch). Build log: `build-full.log`.
- Inputs: `corpus-light-v1.txt`, `vectors-bs.txt`.
- Raw outputs: `out-stock-init{jit,interp}.txt`, `out-bs-init{jit,interp}.txt`,
  `out-corpus-bs-init{jit,interp}.txt`, `out-blacksilk-full-{vectors,corpus}.txt`,
  `out-blacksilk-ignored-tests.txt`, and the false-alarm run
  `out-corpus-bs-initjit-PSPIPE-ARTEFACT.txt`.
- Summary and tables: `RESULTS-full.md`, `table-stock.md`, `table-bs.md`, `table-corpus.md`.
