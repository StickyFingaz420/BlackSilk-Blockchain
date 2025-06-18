# Adding New Algorithms to pqcrypto_native

To add a new post-quantum signature algorithm:

1. **Create a module** under `src/algorithms/` (e.g., `src/algorithms/sphincsplus.rs`).
2. **Define a struct** (e.g., `SphincsPlus`) and implement the `SignatureScheme` trait for it.
3. **Use the type-safe wrappers** (`PublicKey<N>`, `SecretKey<N>`, `Signature<N>`) for all key and signature types.
4. **Ensure all secret material is zeroized** (use the wrappers and `Zeroize` trait).
5. **Implement deterministic key generation** from a seed, and provide `sign` and `verify` methods.
6. **Document the module** with Rustdoc comments and usage examples.
7. **Add tests** (including KATs) in `tests/`.
8. **Expose the algorithm** in `src/algorithms/mod.rs` and add a variant to the `Algo` enum in `src/lib.rs`.
9. **Add a feature flag** in `Cargo.toml` if the algorithm is optional.
10. **(Optional) Add feature-gated backends**: Use `#[cfg(feature = "pure")]` and `#[cfg(feature = "pqclean")]` to select between implementations. See `src/algorithms/dilithium.rs` for an example.

## Selecting a backend
- By default, the `pure` (pure Rust) backend is enabled.
- To use a different backend (e.g., PQClean), build with:
  - `cargo build --no-default-features --features pqclean`
- You can add more backends by following the pattern in `dilithium.rs`.

See `src/algorithms/dilithium.rs` and `src/traits.rs` for reference implementations.
