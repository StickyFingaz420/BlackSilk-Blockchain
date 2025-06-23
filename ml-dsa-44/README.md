# ML-DSA-44 Rust Library

**Module-Lattice-Based Digital Signature Algorithm (ML-DSA-44)**

## Overview
ML-DSA-44 is a post-quantum digital signature algorithm designed to be secure against attacks by quantum computers. This Rust library provides a safe, ergonomic interface to the ML-DSA-44 implementation.

## Key Features
- Post-quantum security: Resistant to quantum computer attacks
- Deterministic key generation: Generate keys from seeds for reproducible results
- Context-aware signing: Support for additional context data in signatures
- Memory-safe: Safe Rust API with proper error handling
- Zero-copy operations: Efficient memory usage where possible

## Algorithm Parameters
| Parameter   | Size (bytes) |
|------------|--------------|
| Public Key | 1,312        |
| Secret Key | 2,560        |
| Signature  | ≤ 2,420      |
| Seed       | 32           |

## Quick Start Example
```rust
use ml_dsa_44::{Keypair, sign, verify};

// Generate keypair
let keypair = Keypair::generate()?;

// Sign message
let message = b"Hello, post-quantum world!";
let signature = sign(message, &keypair.secret_key)?;

// Verify signature
let is_valid = verify(&signature, message, &keypair.public_key)?;
assert!(is_valid);
```

For more, see the [examples directory](examples/) and the API reference below.

## Table of Contents

- [Installation](#installation)
- [Building from Source](#building-from-source)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Integration Guide](#integration-guide)
- [Testing](#testing)
- [Performance](#performance)
- [Security Considerations](#security-considerations)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ml-dsa-44 = "0.1.0"
```

### Prerequisites

- **Rust**: 1.70.0 or newer
- **C Compiler**: GCC or Clang (for building C implementation)
- **Build tools**: `cc` crate handles C compilation automatically

## Building from Source

```bash
# Clone the repository
git clone https://github.com/your-username/ml-dsa-44-rust
cd ml-dsa-44-rust

# Build in debug mode
cargo build

# Build in release mode (recommended for production)
cargo build --release

# Build with optimizations for your CPU
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Build Requirements

The library requires several C source files to be present in the project root:

- `ntt.c` - Number Theoretic Transform operations
- `packing.c` - Key and signature packing/unpacking
- `poly.c` - Polynomial operations
- `polyvec.c` - Polynomial vector operations
- `reduce.c` - Modular reduction operations
- `rounding.c` - Rounding operations
- `sign.c` - Core signing algorithm
- `symmetric-shake.c` - SHAKE hash functions
- `fips202.c` - FIPS 202 implementation
- `randombytes.c` - Random number generation
- `memory_cleanse.c` - Secure memory clearing

## API Reference

### Types

#### `Keypair`
Contains public and secret key pair.

```rust
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
```

#### `PublicKey`
Public key (1,312 bytes).

```rust
pub struct PublicKey(pub [u8; 1312]);
```

#### `SecretKey`
Secret key (2,560 bytes).

```rust
pub struct SecretKey(pub [u8; 2560]);
```

#### `Signature`
Digital signature with variable length data.

```rust
pub struct Signature {
    pub data: Vec<u8>,
}
```

#### `MlDsaError`
Error types for ML-DSA operations.

```rust
pub enum MlDsaError {
    KeyGeneration,    // Key generation failed
    Signing,          // Signing operation failed
    Verification,     // Verification operation failed
    InvalidSignature, // Signature is invalid
    InvalidInput,     // Input parameters are invalid
}
```

### Key Generation

#### `Keypair::generate() -> Result<Keypair>`
Generate a new keypair using system randomness.

```rust
use ml_dsa_44::Keypair;

let keypair = Keypair::generate()?;
```

#### `Keypair::from_seed(seed: &[u8; 32]) -> Result<Keypair>`
Generate keypair deterministically from a 32-byte seed.

```rust
use ml_dsa_44::Keypair;

let seed = [42u8; 32];
let keypair = Keypair::from_seed(&seed)?;
```

### Signing Functions

#### `sign(message: &[u8], secret_key: &SecretKey) -> Result<Signature>`
Sign a message with the secret key.

```rust
use ml_dsa_44::{sign, Keypair};

let keypair = Keypair::generate()?;
let message = b"Hello, world!";
let signature = sign(message, &keypair.secret_key)?;
```

#### `sign_with_context(message: &[u8], context: &[u8], secret_key: &SecretKey) -> Result<Signature>`
Sign a message with additional context data.

```rust
use ml_dsa_44::{sign_with_context, Keypair};

let keypair = Keypair::generate()?;
let message = b"Hello, world!";
let context = b"application-specific-context";
let signature = sign_with_context(message, context, &keypair.secret_key)?;
```

### Verification Functions

#### `verify(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool>`
Verify a signature against a message and public key.

```rust
use ml_dsa_44::{sign, verify, Keypair};

let keypair = Keypair::generate()?;
let message = b"Hello, world!";
let signature = sign(message, &keypair.secret_key)?;
let is_valid = verify(&signature, message, &keypair.public_key)?;
assert!(is_valid);
```

#### `verify_with_context(signature: &Signature, message: &[u8], context: &[u8], public_key: &PublicKey) -> Result<bool>`
Verify a context-aware signature.

```rust
use ml_dsa_44::{sign_with_context, verify_with_context, Keypair};

let keypair = Keypair::generate()?;
let message = b"Hello, world!";
let context = b"application-specific-context";
let signature = sign_with_context(message, context, &keypair.secret_key)?;
let is_valid = verify_with_context(&signature, message, context, &keypair.public_key)?;
assert!(is_valid);
```

### Constants

```rust
pub mod constants {
    pub const PUBLIC_KEY_BYTES: usize = 1312;
    pub const SECRET_KEY_BYTES: usize = 2560;
    pub const SIGNATURE_BYTES: usize = 2420;
    pub const SEED_BYTES: usize = 32;
}
```

## Usage Examples

### Basic Example

```rust
use ml_dsa_44::{Keypair, sign, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keypair
    let keypair = Keypair::generate()?;
    
    // Sign message
    let message = b"Hello, post-quantum world!";
    let signature = sign(message, &keypair.secret_key)?;
    
    // Verify signature
    let is_valid = verify(&signature, message, &keypair.public_key)?;
    assert!(is_valid);
    
    println!("Signature verified successfully!");
    Ok(())
}
```

### Deterministic Key Generation

```rust
use ml_dsa_44::Keypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a fixed seed for reproducible keys
    let seed = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    ];
    
    // Generate keypair from seed
    let keypair = Keypair::from_seed(&seed)?;
    
    // This will always generate the same keypair
    let keypair2 = Keypair::from_seed(&seed)?;
    assert_eq!(keypair.public_key.0, keypair2.public_key.0);
    
    println!("Deterministic key generation successful!");
    Ok(())
}
```

### Context-Aware Signing

```rust
use ml_dsa_44::{Keypair, sign_with_context, verify_with_context};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate()?;
    
    let message = b"Important document";
    let context = b"document-signing-v1.0";
    
    // Sign with context
    let signature = sign_with_context(message, context, &keypair.secret_key)?;
    
    // Verify with context
    let is_valid = verify_with_context(
        &signature, 
        message, 
        context, 
        &keypair.public_key
    )?;
    
    assert!(is_valid);
    println!("Context-aware signature verified!");
    Ok(())
}
```

### Key Serialization

```rust
use ml_dsa_44::Keypair;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate()?;
    
    // Save public key
    fs::write("public_key.bin", &keypair.public_key.0)?;
    
    // Save secret key (be careful with this!)
    fs::write("secret_key.bin", &keypair.secret_key.0)?;
    
    // Load keys back
    let public_key_data = fs::read("public_key.bin")?;
    let secret_key_data = fs::read("secret_key.bin")?;
    
    // Reconstruct keys
    let public_key = ml_dsa_44::PublicKey(
        public_key_data.try_into()
            .map_err(|_| "Invalid public key size")?
    );
    let secret_key = ml_dsa_44::SecretKey(
        secret_key_data.try_into()
            .map_err(|_| "Invalid secret key size")?
    );
    
    println!("Keys saved and loaded successfully!");
    Ok(())
}
```

## Integration Guide

### Adding to Existing Project

1. Add dependency to `Cargo.toml`:
```toml
[dependencies]
ml-dsa-44 = "0.1.0"
```

2. Import in your code:
```rust
use ml_dsa_44::{Keypair, sign, verify, MlDsaError};
```

3. Handle errors appropriately:
```rust
match keypair_result {
    Ok(keypair) => {
        // Use keypair
    },
    Err(MlDsaError::KeyGeneration) => {
        // Handle key generation failure
    },
    Err(e) => {
        // Handle other errors
        eprintln!("ML-DSA error: {}", e);
    }
}
```

### Web Service Integration

```rust
use ml_dsa_44::{Keypair, sign, verify};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SignRequest {
    message: Vec<u8>,
    context: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct SignResponse {
    signature: Vec<u8>,
}

async fn sign_endpoint(
    req: SignRequest,
    keypair: &Keypair,
) -> Result<SignResponse, Box<dyn std::error::Error>> {
    let signature = if let Some(context) = req.context {
        ml_dsa_44::sign_with_context(&req.message, &context, &keypair.secret_key)?
    } else {
        sign(&req.message, &keypair.secret_key)?
    };
    
    Ok(SignResponse {
        signature: signature.data,
    })
}
```

### Configuration Management

```rust
use ml_dsa_44::Keypair;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Config {
    use_deterministic_keys: bool,
    key_seed: Option<[u8; 32]>,
}

impl Config {
    fn generate_keypair(&self) -> Result<Keypair, ml_dsa_44::MlDsaError> {
        if self.use_deterministic_keys {
            if let Some(seed) = self.key_seed {
                Keypair::from_seed(&seed)
            } else {
                // Generate a random seed and save it
                let seed = rand::random::<[u8; 32]>();
                Keypair::from_seed(&seed)
            }
        } else {
            Keypair::generate()
        }
    }
}
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run only comprehensive test
cargo test --test comprehensive

# Run comprehensive test with output
cargo test --test comprehensive -- --nocapture

# Run specific test
cargo test test_signature_verification

# Run tests in release mode (faster)
cargo test --release
```

### Test Coverage

The library includes comprehensive tests covering:

- **Basic functionality**: Key generation, signing, verification
- **Deterministic behavior**: Reproducible key generation from seeds
- **Context-aware operations**: Signing and verification with context
- **Error handling**: Invalid inputs, malformed signatures
- **Edge cases**: Empty messages, large messages, malformed data
- **Performance**: Benchmark signing/verification operations
- **Security**: Signature malleability, cross-verification

### Custom Test Example

```rust
#[cfg(test)]
mod tests {
    use ml_dsa_44::{Keypair, sign, verify};

    #[test]
    fn test_my_use_case() {
        let keypair = Keypair::generate().unwrap();
        let message = b"My specific test message";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        let is_valid = verify(&signature, message, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }
}
```

## Performance

### Typical Performance (on modern x86_64)

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | ~0.1ms | Random generation |
| Key Generation (seed) | ~0.1ms | Deterministic |
| Signing | ~0.2ms | Per signature |
| Verification | ~0.1ms | Per verification |

### Optimization Tips

1. **Reuse keypairs**: Key generation is the most expensive operation
2. **Batch operations**: Process multiple signatures together when possible
3. **Release builds**: Always use `--release` for production
4. **CPU-specific optimizations**: Use `RUSTFLAGS="-C target-cpu=native"`

### Performance Testing

```rust
use ml_dsa_44::{Keypair, sign, verify};
use std::time::Instant;

fn benchmark_operations() {
    let keypair = Keypair::generate().unwrap();
    let message = b"Benchmark message";
    let iterations = 1000;
    
    // Benchmark signing
    let start = Instant::now();
    for _ in 0..iterations {
        let _signature = sign(message, &keypair.secret_key).unwrap();
    }
    let sign_duration = start.elapsed();
    
    // Benchmark verification
    let signature = sign(message, &keypair.secret_key).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _valid = verify(&signature, message, &keypair.public_key).unwrap();
    }
    let verify_duration = start.elapsed();
    
    println!("Signing: {:.2} ops/sec", iterations as f64 / sign_duration.as_secs_f64());
    println!("Verification: {:.2} ops/sec", iterations as f64 / verify_duration.as_secs_f64());
}
```

## Security Considerations

### Key Management

- **Secret key protection**: Store secret keys securely, never log or transmit them
- **Key rotation**: Regularly generate new keypairs for long-term use
- **Deterministic keys**: Only use seeds from cryptographically secure sources

### Signature Security

- **Context separation**: Use different contexts for different applications
- **Message integrity**: Ensure messages haven't been modified before signing
- **Signature validation**: Always verify signatures before trusting signed data

### Memory Security

- **Secure clearing**: The library attempts to clear sensitive data from memory
- **Stack protection**: Avoid storing keys in variables that might be swapped to disk
- **Heap management**: Consider using secure allocators for sensitive operations

### Best Practices

```rust
use ml_dsa_44::{Keypair, sign_with_context, verify_with_context};

// Good: Use application-specific context
let context = b"myapp-document-signing-v1.0";
let signature = sign_with_context(message, context, &secret_key)?;

// Good: Verify with same context  
let is_valid = verify_with_context(&signature, message, context, &public_key)?;

// Good: Handle errors appropriately
match verify(&signature, message, &public_key) {
    Ok(true) => {
        // Signature is valid
    },
    Ok(false) => {
        // Signature is invalid - handle as security event
    },
    Err(e) => {
        // Verification failed - handle as error
    }
}
```

### Threat Model

ML-DSA-44 provides security against:
- **Classical computers**: Traditional cryptographic attacks
- **Quantum computers**: Shor's algorithm and other quantum attacks
- **Signature forgery**: Creating valid signatures without the secret key
- **Message modification**: Detecting changes to signed messages

ML-DSA-44 does NOT protect against:
- **Side-channel attacks**: Timing, power analysis (implementation-dependent)
- **Compromised secret keys**: If secret key is leaked, signatures can be forged
- **Weak randomness**: Poor entropy sources can compromise key generation

## Troubleshooting

### Common Issues

**Build fails with "C compiler not found"**
- Install GCC or Clang
- On Ubuntu/Debian: `sudo apt install build-essential`
- On macOS: Install Xcode command line tools

**Linker errors about missing symbols**
- Ensure all C source files are present in project root
- Check that `build.rs` lists all required C files

**Tests fail intermittently**
- May indicate issues with random number generation
- Check that `randombytes.c` is properly implemented

**Performance is slower than expected**
- Build with `--release` flag
- Consider CPU-specific optimizations

### Debug Mode

```rust
// Enable debug output (if available)
std::env::set_var("RUST_LOG", "debug");

// Or use println! debugging
let signature = sign(message, &secret_key)?;
println!("Signature length: {}", signature.data.len());
```

For additional support, please check the GitHub repository issues or create a new issue with:
- Rust version (`rustc --version`)
- Operating system and architecture
- Complete error messages
- Minimal reproduction case