/// ML-DSA-44 constant parameters
pub const SEED_BYTES: usize = 32;
pub const CRH_BYTES: usize = 64;
pub const TR_BYTES: usize = 64;
pub const RND_BYTES: usize = 32;
pub const N: usize = 256;
pub const Q: u32 = 8380417;
pub const D: u32 = 13;
pub const ROOT_OF_UNITY: u32 = 1753;

pub const K: usize = 4;
pub const L: usize = 4;
pub const ETA: u32 = 2;
pub const TAU: usize = 39;
pub const BETA: u32 = 78;
pub const GAMMA1: u32 = 1 << 17;
pub const GAMMA2: u32 = (Q - 1) / 88;
pub const OMEGA: usize = 80;
pub const CTILDE_BYTES: usize = 32;
pub const POLY_BYTES: usize = N * 4; // Each coefficient uses 4 bytes

pub const POLYT1_PACKED_BYTES: usize = 320;
pub const POLYT0_PACKED_BYTES: usize = 416;
pub const POLYVECH_PACKED_BYTES: usize = OMEGA + K;
pub const POLYZ_PACKED_BYTES: usize = 576;
pub const POLYW1_PACKED_BYTES: usize = 192;
pub const POLYETA_PACKED_BYTES: usize = 96;

pub const T0_BYTES: usize = K * POLYT0_PACKED_BYTES;
pub const S1_BYTES: usize = L * POLYETA_PACKED_BYTES;
pub const S2_BYTES: usize = K * POLYETA_PACKED_BYTES;

// Public key bytes: seed + K*T1 packed
pub const CRYPTO_PUBLIC_KEY_BYTES: usize = SEED_BYTES + K * POLYT1_PACKED_BYTES;

// Secret key bytes: 2*seed + tr + L*eta + K*eta + K*t0
pub const CRYPTO_SECRET_KEY_BYTES: usize = 2 * SEED_BYTES + TR_BYTES + S1_BYTES + S2_BYTES + T0_BYTES;

// Signature bytes: ctilde + L*z + h
pub const CRYPTO_SIGNATURE_BYTES: usize = CTILDE_BYTES + L * POLYZ_PACKED_BYTES + POLYVECH_PACKED_BYTES;
