# ml-dsa44-standalone

**Status (June 2025):**

This crate is intended to provide a fully native Rust implementation of the ML-DSA-44 post-quantum signature scheme for integration with the BlackSilk project.

## Current State
- The only available pure Rust implementation is the [`ml-dsa`](https://crates.io/crates/ml-dsa) crate, which is pre-release and depends on unstable versions of the `signature`, `pkcs8`, and `der` crates.
- As of June 2025, the dependency tree for `ml-dsa` is broken and cannot be built due to upstream incompatibilities between `pkcs8` and `der`.
- This is a known issue in the Rust post-quantum ecosystem. See [ml-dsa issues](https://github.com/novifinancial/ml-dsa/issues) for updates.

## What to do
- Track the upstream `ml-dsa` crate for updates and fixes.
- When the dependencies are fixed, this crate can be built and tested as part of a dual-crate, all-native Rust PQ signature solution.
- For now, use the `pqsignatures` crate for Dilithium2 and Falcon512 (and hybrid/Ed25519) in production.

## References
- [ml-dsa crate on crates.io](https://crates.io/crates/ml-dsa)
- [ml-dsa GitHub repository](https://github.com/novifinancial/ml-dsa)
- [RustCrypto/pkcs8](https://github.com/RustCrypto/formats/tree/master/pkcs8)
- [RustCrypto/der](https://github.com/RustCrypto/formats/tree/master/der)

---

*This file will be updated when the Rust PQ ecosystem stabilizes and ML-DSA-44 becomes buildable in pure Rust.*
