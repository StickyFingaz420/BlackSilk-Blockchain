//! ML-DSA-44 parameters and constants (NIST FIPS 204 Table 1)
// These are for the ML-DSA-44 (Dilithium2) parameter set. Adjust as needed for other sets.

/// Degree of polynomials
pub const N: usize = 256;
/// Modulus
pub const Q: i32 = 8380417;
/// Number of rows in matrix A
pub const K: usize = 4;
/// Number of columns in matrix A
pub const L: usize = 4;
/// Seed bytes for keygen
pub const SEED_BYTES: usize = 32;
/// Public key size in bytes
pub const PUBLIC_KEY_BYTES: usize = 1312;
/// Secret key size in bytes
pub const SECRET_KEY_BYTES: usize = 2544;
/// Signature size in bytes
pub const SIGNATURE_BYTES: usize = 2420;
/// Challenge hash output size
pub const CRH_BYTES: usize = 48;
/// Bytes for random coins in signing
pub const CTILDE_BYTES: usize = 32;

// Noise and sampling parameters
pub const ETA: u8 = 2;
pub const TAU: usize = 39;
pub const BETA: i32 = 78;
pub const GAMMA1: i32 = (1 << 17);
pub const GAMMA2: i32 = ((Q - 1) / 88);
pub const OMEGA: usize = 80;

// Packing parameters
pub const POLY_BYTES: usize = 416;
pub const POLYVEC_BYTES: usize = K * POLY_BYTES;

// NTT parameters (see PQClean and FIPS 204)
pub const ROOT_OF_UNITY: i32 = 1753; // Placeholder, set correct value for NTT

// ...add any additional constants as needed for implementation
