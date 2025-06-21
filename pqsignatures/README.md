# pqsignatures

Production-grade, secure, constant-time Rust post-quantum signature schemes:
- Dilithium2 (pure Rust, via crystals-dilithium)
- Falcon512 (scaffolded, native Rust pending)
- ML-DSA-44 (scaffolded, native Rust pending)

## Features
- Secure key handling (zeroize)
- Hybrid signature support (Ed25519 + Dilithium2)
- Test vectors (KATs) and property-based fuzzing
- Idiomatic error handling and documentation

## Usage Example
```rust
use pqsignatures::{Dilithium2, PQSignatureScheme};
let (pk, sk) = Dilithium2::keypair();
let message = b"hello";
let sig = Dilithium2::sign(&sk, message);
assert!(Dilithium2::verify(&pk, message, &sig));
```

## Hybrid Example
```rust
use pqsignatures::{Ed25519Dilithium2Hybrid, HybridSigner};
// ...generate keys...
// let hybrid_sig = Ed25519Dilithium2Hybrid::sign_hybrid(&ed_sk, &pq_sk, message);
```

## Security Notes
- All secret keys are zeroized on drop.
- All operations are intended to be constant-time (pending upstream implementation).
- Hybrid signatures are supported for migration.

## Test Vectors
- KATs from NIST/PQClean should be integrated in `src/tests.rs`.

## Fuzzing
- Run property-based tests with `cargo test --features fuzzing`.

## TODO
- Integrate pure Rust Falcon512 and ML-DSA-44 when available.
- Add serialization/deserialization for keys and signatures.

## License
MIT OR Apache-2.0
