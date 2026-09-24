//! BlackSilk private execution (PX) core: the `Hk` hash, keys, records,
//! nullifiers, the commitment-tree hash and the private-transfer kernel
//! (docs/zk.md §4, §6; docs/px.md).
//!
//! **One source for every party.** This crate has no dependencies and no
//! allocation. The same code is compiled
//! - natively, for nodes and wallets (with the Plonky3 Poseidon2 permutation),
//! - and to `riscv32i-unknown-none-elf`, as the kernel guest program that the
//!   zkVM proves (with the `POSEIDON2` syscall).
//!
//! So what a proof establishes is exactly what [`kernel::transfer`] computes;
//! there is no separate circuit description that could drift from it.
//!
//! **Arithmetic.** Values are `u64` and sums `u128`, computed by the guest
//! with ordinary integer instructions, which the zkVM proves exactly. There is
//! no field wrap-around to guard against (zk.md §6.4): field elements occur
//! only as hash inputs and outputs, and every one read from a witness is
//! checked to be canonical.

#![no_std]
#![forbid(unsafe_code)]

pub mod call;
pub mod hash;
pub mod kernel;
pub mod record;

pub use hash::{Digest, Permutation, ZERO_DIGEST};

/// The BabyBear prime `p = 2^31 − 2^27 + 1`.
pub const P: u32 = 0x7800_0001;

/// `a + b mod p` for canonical `a`, `b`.
#[inline]
pub fn add(a: u32, b: u32) -> u32 {
    debug_assert!(a < P && b < P);
    let s = a + b; // < 2^32
    if s >= P {
        s - P
    } else {
        s
    }
}

/// Is `x` a canonical field element?
#[inline]
pub fn canonical(x: u32) -> bool {
    x < P
}
