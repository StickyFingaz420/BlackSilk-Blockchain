# Post-Quantum Cryptography Integration for BlackSilk Blockchain

This crate provides safe Rust wrappers for post-quantum signature schemes (Dilithium, Falcon) using libbitcoinpqc.

## Features
- Deterministic keypair generation from seed (SHA384)
- Signature creation and verification
- FFI bindings to libbitcoinpqc

## Usage

- Add this crate as a dependency in your workspace.
- Build libbitcoinpqc as described in the main README.
- Use `pqcrypto::wrapper::{keypair_from_seed, sign, verify, seed_from_phrase}` in your wallet, runtime, or contract logic.

## Building

1. Clone and build libbitcoinpqc:
   ```sh
   git clone https://github.com/bitcoin/libbitcoinpqc.git
   cd libbitcoinpqc && mkdir build && cd build
   cmake .. && make
   ```
2. Build this crate:
   ```sh
   cargo build
   ```

## License
MIT
