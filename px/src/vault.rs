//! The reference private contract: a hash-locked vault (docs/px.md §7.4,
//! §13), host side.
//!
//! The function program is `zkvm/guests/vault`, pinned as `px/vault.elf` with
//! its program id in `px/vault.id`. This module builds, for each call, the
//! function's private input and the kernel's view of the same call (the
//! [`FunctionWitness`] from which the kernel recomputes `io_hash`).
//!
//! - `LOCK` (selector 0): creates a record of the vault contract holding
//!   `value` under `lock = Hk(LOCK, secret)` in output slot `j`.
//! - `CLAIM` (selector 1): given the vault record in input slot `i` and the
//!   secret, approves consuming it and pays its value to `recipient` (an
//!   owner tag) in output slot `j`.
//!
//! The function's public output after `io_hash ‖ contract` is its selector,
//! so an observer learns that a vault was locked or claimed, and nothing
//! else.
//!
//! **A demonstration contract: not production-ready, not trustless**
//! (docs/px.md §13.4).
//! - **No timeout:** a vault stays claimable forever.
//! - **No refund:** there is no function that returns the value to the
//!   locker, except claiming it with the secret.
//! - **The locker knows the secret,** so the locker can claim too. Whoever
//!   holds the secret and the record's opening can claim.
//! - It is therefore **not a trustless swap**. A hash-time-locked contract
//!   needs a timelock and a refund function, which this vault does not have.

use crate::perm::HostPerm;
use blacksilk_px_core::call::OutSpec;
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::FunctionWitness;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use std::sync::{Arc, OnceLock};

/// The vault function program (RISC-V ELF), rebuilt by `zkvm/guests/build.sh`.
pub const VAULT_ELF: &[u8] = include_bytes!("../vault.elf");

/// The program id (hex), pinned in `px/vault.id`; a test checks it.
pub const VAULT_PROGRAM_ID: &str = include_str!("../vault.id");

/// Domain of the lock hash (an application domain, outside PX's range).
pub const LOCK_DOMAIN: u32 = 0x5641_0001;

/// Selectors, the function's public output.
pub const LOCK: u32 = 0;
pub const CLAIM: u32 = 1;

/// The registered row budget: measured use of the larger of LOCK and CLAIM
/// plus about 6% (`px/tests/unified.rs::budgets_leave_headroom`).
pub const BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_200,
    add: 4_300,
    bit: 200,
    lt: 3_400,
    shift: 200,
    mul: 200,
    poseidon: 22,
};

pub fn program() -> Arc<Program> {
    static P: OnceLock<Arc<Program>> = OnceLock::new();
    P.get_or_init(|| Arc::new(Program::from_elf(VAULT_ELF).expect("the vault ELF loads")))
        .clone()
}

/// `Hk(LOCK, secret)`: what a vault record stores in its data field.
pub fn lock_of(secret: &Digest) -> Digest {
    hash(&mut HostPerm::new(), LOCK_DOMAIN, &[secret])
}

fn words(parts: &[&[u32]]) -> Vec<u32> {
    parts.concat()
}

/// LOCK of `value` under `lock`, creating the vault record in output slot
/// `j`: the function's input and the kernel's view of the call.
pub fn lock_call(
    contract: &Digest,
    value: u64,
    lock: &Digest,
    j: usize,
    blind: &Digest,
) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[LOCK],
        contract,
        blind,
        &[value as u32, (value >> 32) as u32],
        lock,
        &[j as u32],
    ]);
    let mut spec = [None; 2];
    spec[j] = Some(OutSpec {
        owner: ZERO_DIGEST,
        contract: *contract,
        value,
        data: *lock,
    });
    let fw = FunctionWitness {
        contract: *contract,
        blind: *blind,
        approve: [false; 2],
        spec,
    };
    (input, fw)
}

/// CLAIM of vault record `rec` (kernel input slot `i`), paying its value to
/// `recipient` (an owner tag) in output slot `j`.
pub fn claim_call(
    rec: &Record,
    secret: &Digest,
    recipient: &Digest,
    i: usize,
    j: usize,
    blind: &Digest,
) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[CLAIM],
        &rec.contract,
        blind,
        &[rec.value as u32, (rec.value >> 32) as u32],
        &rec.data,
        &rec.rho,
        &rec.rcm,
        secret,
        recipient,
        &[i as u32, j as u32],
    ]);
    let mut approve = [false; 2];
    approve[i] = true;
    let mut spec = [None; 2];
    spec[j] = Some(OutSpec {
        owner: *recipient,
        contract: ZERO_DIGEST,
        value: rec.value,
        data: [0; 8],
    });
    let fw = FunctionWitness {
        contract: rec.contract,
        blind: *blind,
        approve,
        spec,
    };
    (input, fw)
}
