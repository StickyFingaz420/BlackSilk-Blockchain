# pqsignatures

Research code, unreviewed and not used by the chain: post-quantum signature
scheme wrappers in Rust. It is outside the workspace (root `Cargo.toml`
`exclude`), and no CI job builds or tests it. Nothing here is claimed to be
production-grade or constant-time.

Wrapped schemes:
- Dilithium2 (pure Rust, via crystals-dilithium)
- Falcon512 (pure Rust, via falcon-rust)

## Features
- Secret keys are the upstream crates' types; no zeroization is added (see Security Notes)
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
- Run `cargo test --manifest-path research/pqsignatures/Cargo.toml` for the
  positive, negative and fuzz tests. There are no known-answer (KAT) tests.
- Falcon512 fuzzing is limited for performance reasons.

## Security Notes
- Zeroization on drop is not provided by this crate: `Dilithium2` and `Falcon512`
  return the upstream crates' secret-key types unwrapped (`hybrid.rs` and
  `mldsa44.rs` are not compiled: they are not modules of `lib.rs`).
- Constant-time behaviour is not verified; it depends on the upstream crates.
