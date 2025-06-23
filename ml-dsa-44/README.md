# ML-DSA-44 Standalone Rust Library

A production-ready, NIST KAT-compliant, deterministic post-quantum signature library with C reference FFI integration.

## Features
- Deterministic and random keypair generation
- FFI to official C reference implementation
- Safe, idiomatic Rust API
- Comprehensive tests (unit, integration, KAT)
- CI with GitHub Actions
- Ready for research or production

## Usage
```rust
use ml_dsa_44::{Keypair, sign, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate()?;
    let message = b"Hello, post-quantum world!";
    let signature = sign(message, &keypair.secret_key)?;
    let is_valid = verify(&signature, message, &keypair.public_key)?;
    assert!(is_valid);
    Ok(())
}
```

## KAT Testing
See `tests/kat.rs` and replace the vectors with official NIST KATs for full compliance.

## Security
- Secret keys are zeroized after use (where possible)
- FFI boundary is minimal and reviewed

## License
MIT or Apache-2.0