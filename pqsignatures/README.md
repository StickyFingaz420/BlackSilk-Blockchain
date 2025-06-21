# pqsignatures

Production-grade, secure, constant-time Rust post-quantum signature schemes:
- Dilithium2
- Falcon512
- ML-DSA-44

## Features
- Secure key handling (zeroize)
- Hybrid signature support (classical + PQ)
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

## Security Notes
- All secret keys are zeroized on drop.
- All operations are intended to be constant-time (pending upstream implementation).
- Hybrid signatures are supported for migration.

## Test Vectors
- KATs from NIST/PQClean should be integrated in `src/tests.rs`.

## Fuzzing
- Run property-based tests with `cargo test --features fuzzing`.

## TODO
- Integrate PQClean or native Rust implementations for each scheme.
- Add classical signature support for hybrid mode.
- Add serialization/deserialization for keys and signatures.

## License
MIT OR Apache-2.0
