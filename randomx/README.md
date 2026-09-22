# blacksilk-randomx

Pure-Rust implementation of the RandomX proof-of-work, **version 1** (the variant
Monero uses). It is the single RandomX implementation for the BlackSilk node
(verification) and miner (hashing).

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
| `config.rs` | 1 | consensus parameters (must never change) |

## Design notes

- **No `unsafe`, no FFI, no C.** `#![forbid(unsafe_code)]`. Dependencies are the
  RustCrypto `blake2` and `aes` crates. `aes::hazmat` provides single AES rounds with
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

`cargo test -p blacksilk-randomx` runs every applicable test vector from the reference
`src/tests/tests.cpp`, and all pass:

| Test | Checks |
|---|---|
| Cache initialization | 3 cache words for key `test key 000` |
| SuperscalarHash generator | Blake2b of all 10 generated programs |
| `randomx_reciprocal` | 7 values |
| Dataset initialization | items 0, 10M, 20M, 30M |
| AesGenerator1R | one 32-byte block |
| Hash tests 1a–1e | end-to-end hashes for both reference keys |

The crate also has unit tests of the rounding emulation (directed rounding, signed
zeros, rescaled residuals, overflow, infinity propagation).

`cargo test --release -p blacksilk-randomx -- --ignored` builds the full 2 GiB
dataset and checks that full mode reproduces vector 1a.

Not covered: RandomX v2 (`RANDOMX_FLAG_V2`) is not implemented. The reference's
JIT-specific tests don't apply.

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
