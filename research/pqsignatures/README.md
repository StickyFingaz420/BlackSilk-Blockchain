# pqsignatures

**Status: parked research prototype.** It is excluded from the BlackSilk
workspace (root `Cargo.toml` `exclude`), is not built or tested by CI, has not
been reviewed, and no BlackSilk crate uses it (AUDIT.md S7). Do not use it to
protect anything.

Thin wrappers around third-party post-quantum signature crates:
- Dilithium2 via `crystals-dilithium` (round-3 Dilithium, **not** FIPS 204 ML-DSA)
- Falcon512 via `falcon-rust` 0.1.x (young, unaudited)

## Features
- No key zeroization (the key types are the upstream crates' own)
- Property-based and negative testing
- Idiomatic error handling
- Serialization/deserialization helpers

## Quick Start
```rust
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
// Dilithium2
let (pk, sk) = Dilithium2::keypair();
let msg = b"hello";
let sig = Dilithium2::sign(&sk, msg);
assert!(Dilithium2::verify(&pk, msg, &sig));
// Falcon512
let (pk, sk) = Falcon512::keypair();
let sig = Falcon512::sign(&sk, msg);
assert!(Falcon512::verify(&pk, msg, &sig));
```

## Integration Example
To use in another crate (e.g., wallet):
```rust
use pqsignatures::{Dilithium2, PQSignatureScheme};
// Generate keys and sign a transaction
let (pk, sk) = Dilithium2::keypair();
let tx_bytes = b"tx data";
let sig = Dilithium2::sign(&sk, tx_bytes);
// Verify signature in node
assert!(Dilithium2::verify(&pk, tx_bytes, &sig));
```

## Test Suite
- Run `cargo test -p pqsignatures` for all positive, negative, and fuzz tests.
- Falcon512 fuzzing is limited for performance reasons.

## Security Notes
- Secret keys are not zeroized by this crate. `src/hybrid.rs` and
  `src/mldsa44.rs` are not modules of the crate (never compiled) and do not
  build as written.
- No constant-time property is claimed or verified: it depends entirely on the
  upstream crates, which have not been reviewed.
- `.github/workflows/ci.yml` and `tests/kat_test.py` here are never run (the
  workflow is not under the repository's root `.github/`; the KAT files it
  expects do not exist).
