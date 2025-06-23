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

## Workspace Integration

To use ML-DSA-44 in any crate in your workspace:

```rust
use ml_dsa_44::{Keypair, sign, verify};

fn main() {
    let keypair = Keypair::generate().expect("Keygen failed");
    let message = b"Hello, BlackSilk!";
    let signature = sign(message, &keypair.secret_key).expect("Sign failed");
    let is_valid = verify(&signature, message, &keypair.public_key).expect("Verify failed");
    println!("Signature valid: {}", is_valid);
}
```

- Add `ml-dsa-44 = { path = "ml-dsa-44" }` to your crate's `Cargo.toml` dependencies.
- See `tests/integration.rs` for more examples.

## KAT Testing
See `tests/kat.rs` and replace the vectors with official NIST KATs for full compliance.

## Security
- Secret keys are zeroized after use (where possible)
- FFI boundary is minimal and reviewed

## License
MIT or Apache-2.0