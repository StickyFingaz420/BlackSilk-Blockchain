# blacksilk-randomx

Pure-Rust implementation of the RandomX proof-of-work, **version 1**. It is the single
RandomX implementation for the BlackSilk node (verification) and miner (hashing).

BlackSilk's RandomX is the reference configuration (Monero's `rx/0`) with **one**
change: the Argon2 salt is `"BlackSilk/RandomX/v1"` instead of `"RandomX\x03"`
(`Variant::BlackSilk`, the default of `Cache::new`; record
[#rx-salt](../docs/reviews/v3-consensus-changes.md#rx-salt)). The RandomX designers
recommend a unique salt per project (`doc/configuration.md`), and advise against
changing any other parameter. `Cache::with_variant(key, Variant::MoneroRx0)` builds
the reference cache, used only for the official test vectors. The salt stops stock
`rx/0` hash power from mining BlackSilk unmodified; a miner that adds the salt (a
one-line change) can.

It is a port of the reference implementation,
[tevador/RandomX](https://github.com/tevador/RandomX) (BSD-3-Clause, see `LICENSE`),
and follows its specification (`doc/specs.md`).

## Usage

```rust
use blacksilk_randomx::{Cache, Dataset, Vm};

// Verification ("light mode"): 256 MiB cache, dataset items computed on demand.
let cache = Cache::new(key);
let hash = Vm::light(&cache).hash(input);

// Mining ("full mode"): ~2 GiB dataset, much faster per hash.
let dataset = Dataset::new(&cache, threads);
let hash = Vm::full(&dataset).hash(input);
```

Both modes produce identical hashes. Building a `Cache` is expensive (~0.6 s), so
reuse it for as long as the key stays the same.

## Structure

| Module | Spec | Contents |
|---|---|---|
| `argon2d.rs` | 7.1 | Argon2d memory fill for the cache (raw memory, `outlen = 0`) |
| `superscalar.rs` | 6 | Blake2Generator, SuperscalarHash generator (CPU port model), reciprocal |
| `dataset.rs` | 7.2–7.3 | `Cache`, dataset item computation, parallel `Dataset` expansion |
| `aes_gen.rs` | 3.2–3.4 | AesGenerator1R, AesGenerator4R, AesHash1R |
| `vm.rs` | 2, 4, 5 | program generation, instruction decoding and execution, hash chain |
| `fpu.rs` | 4.3 | IEEE 754 arithmetic under the four rounding modes |
| `config.rs` | 1 | consensus parameters (must never change), BlackSilk's salt and the reference salt |
| `hash.rs` | — | Blake2b helpers (`Hash512`, `Hash256`, Argon2's `H'`) |
| `self_test.rs` | — | start-up self-test: the known answers 1a–1f and bs-1a–bs-1f in light mode, and a miner's dataset check (`check_dataset`) |

## Design notes

- **No `unsafe`, no FFI, no C.** `#![forbid(unsafe_code)]`. Dependencies are the
  RustCrypto `blake2` and `aes` crates (and, in tests only, RustCrypto `argon2` as an
  independent check of the cache fill). `aes::hazmat` provides single AES rounds with
  exact AESENC/AESDEC semantics, and uses AES-NI when available.
- **Software rounding modes.** RandomX switches the FPU rounding mode (`CFROUND`).
  Rust cannot do that soundly, because LLVM assumes round-to-nearest. So every
  operation is computed with round-to-nearest and then corrected by one ulp when needed.
  The sign of the exact error comes from error-free transforms (TwoSum, Dekker
  TwoProduct) on power-of-two-rescaled operands. Results are therefore bit-identical
  on every platform.
- **Overflow is consensus-critical.** The e registers exceed `f64::MAX` in real programs:
  official vector 1b does so thousands of times. Directed rounding modes must then
  produce `±MAX` or `±inf` exactly as IEEE 754 prescribes. This is implemented and tested.

## Verification status

`cargo test -p blacksilk-randomx` runs these vectors, transcribed from the reference
`src/tests/tests.cpp` (tevador/RandomX v1.2.3) and run with the reference salt
(`Variant::MoneroRx0`), and all pass:

| Test | Checks |
|---|---|
| Cache initialization | 3 cache words (0, 1568413, 33554431) for key `test key 000` |
| SuperscalarHash generator | Blake2b of the 10 programs generated for key `test key 000` |
| `randomx_reciprocal` | 7 values |
| Dataset initialization | word 0 of items 0, 10M, 20M, 30M (key `test key 000`) |
| AesGenerator1R | one 32-byte block |
| Hash tests 1a–1e | end-to-end light-mode hashes, keys `test key 000` and `test key 001` |
| Hash test 1f | end-to-end light-mode hash, 31-byte key, 76-byte input: the ISUB_R edge case (src = dst, immediate 0x80000000) added upstream in PR #326 |

With BlackSilk's salt (`Variant::BlackSilk`):

| Test | Checks |
|---|---|
| `argon2_crate_fills_the_same_cache` | all 33,554,432 cache words of `test key 000` equal the RustCrypto `argon2` crate's `fill_memory` (an independent Argon2d), for BlackSilk's salt and the reference salt |
| `blacksilk_cache_initialization` | the same 3 cache words as the reference test, pinned (all differ from the reference's) |
| `blacksilk_vectors` | bs-1a to bs-1f: the keys and inputs of 1a–1f hashed with BlackSilk's salt; bs-1a is the consensus fingerprint's known answer |
| `tests/equivalence.rs` `reference_corpus` | 24 light-mode answers of the reference (v1.2.3, only the salt changed; `tests/data/randomx-reference-light-v1.txt`): the 16 cases of the pinned digest (2 random 32-byte keys, inputs of 0 to 255 bytes) and 8 edge cases (keys of 0, 1, 31, 60, 61 and 128 bytes, inputs up to 2048 bytes) |
| `tests/equivalence.rs` `pinned_digest` | Blake2b over the 16 hashes above; the pin is the reference's digest |
| `tests/equivalence.rs` `pinned_digest_large` (ignored) | the same over 256 cases (8 keys); the pin is the reference's digest |
| `fpu_oracle` (`src/fpu_oracle.rs`) | add, sub, mul, div and sqrt in all four rounding modes, bit for bit against an IEEE 754 oracle (`rustc_apfloat`, a port of LLVM APFloat, test-only; sqrt from exact binary128 comparisons): 10^5 samples per op and mode from the RandomX-reachable domain plus wide normal operands per `cargo test`, 10^7 in the ignored `fpu_oracle_full`, and edge cases (ties, exact results, MAX, overflow, ±0, ±2^-1008, +inf) |

`tests/support/mod.rs` is the equivalence harness for any future optimized path: deterministic cases, the digest, and `differential` (a candidate hash function against the current one, reporting the first differing case).

The BlackSilk answers were generated by this crate. The salt enters only the Argon2
fill, which the `argon2` comparison checks independently; everything after the fill
is salt-independent code covered by the official vectors. The reference C++
implementation (v1.2.3, with only the salt changed) reproduced bs-1a to bs-1f and the
mining-blob known answer of `consensus/tests/golden.rs`, in light mode only (freeze
gate B4, docs/evidence/randomx-reference-2026-10-04/). Full mode was not run against
the reference.

What this does **not** cover:
- The reference's instruction-level decode/execute tests (including its floating-point
  rounding-mode cases) are not ported.
- AesGenerator4R and AesHash1R have no direct vector (the reference has none either);
  they are pinned only through the end-to-end hashes.
- The comparison with the reference is small: the 6 official hashes above (3 keys),
  bs-1a to bs-1f, one known answer in BlackSilk's PoW shape
  (`randomx_known_answer_on_a_mining_blob` in `consensus/tests/golden.rs`), and the
  equivalence corpus (24 answers committed, 256 more through the large digest), over
  22 keys in all. Light mode only.
- The equivalence harness compares whole hashes only: the VM state after one program
  or iteration is private to `vm.rs`, so a divergence is located to a (key, input)
  pair, not to an instruction.
- The FPU oracle samples the domain RandomX reaches; outside it (subnormal operands or
  results) `fpu.rs` is not IEEE-exact and is not compared.
- Follow-up: the comment at the top of `fpu.rs` says f registers stay below ~3e14
  (2^48). That is too low: FSCAL flips the low 4 exponent bits, so an f value in
  [2^33, 2^34) becomes one in [2^48, 2^49); FADD_R can push it past 2^49, and a
  second FSCAL then gives about 2^64·(1 + 2^-9). f reaches about 2^64. The oracle
  samples up to 2^65 (`src/fpu_oracle.rs`); the `fpu.rs` comment (and the FSCAL-of-zero
  case, ±2^-1008, which it also omits) is left for a change that may edit that file.

`cargo test --release -p blacksilk-randomx -- --ignored` builds the full 2 GiB dataset
for each of the three reference keys and for BlackSilk's `test key 000`, and checks
that full mode reproduces vectors 1a–1f and bs-1a to bs-1c and agrees with light mode
on 512 random inputs per key (CI job `randomx-full`, Linux).

Not implemented: RandomX v2 (`RANDOMX_FLAG_V2`). The reference's JIT-specific tests
don't apply.

## Performance

Release build on the development machine (8 threads):

| Operation | Time |
|---|---|
| Cache initialization | ~0.63 s |
| Light-mode hash | ~0.45 s |
| Full dataset expansion | ~133 s |

Light mode is adequate for verifying blocks at a 120 s target. Faster superscalar
execution and full-mode mining throughput are planned optimizations.
`cargo run --release -p blacksilk-randomx --example bench` measures this.
