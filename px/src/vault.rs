//! The reference private contract: a hash-locked vault with an optional
//! timeout and refund (docs/contracts.md §8), host side.
//!
//! The function program is `zkvm/guests/vault`, pinned as `px/vault.elf` with
//! its program id in `px/vault.id`. This module builds, for each call, the
//! function's private input and the kernel's view of the same call (the
//! [`FunctionWitness`] from which the kernel recomputes `io_hash`).
//!
//! A vault record of contract `C` stores its [`Terms`] as
//! `data = Hk(TERMS, C ‖ claim_lock ‖ refund_lock ‖ timeout₁₆[4])`, with
//! `claim_lock = Hk(LOCK, C ‖ secret)` and `refund_lock = Hk(REFUND, C ‖
//! refund_secret)` (0 without a timeout). Both locks bind the contract id,
//! so a secret reused across vault instances opens only its own (F-28-7).
//!
//! - `LOCK` (selector 0): creates a record of the vault contract holding
//!   `value` under the terms, in output slot `j`.
//! - `CLAIM` (selector 1): given the vault record in input slot `i` and the
//!   secret, approves consuming it and pays its value to `recipient` (an
//!   owner tag) in output slot `j`. With a timeout `T`, only in a transaction
//!   whose validity window ends before `T` (`not_after ≠ 0`, `not_after < T`).
//! - `REFUND` (selector 2): the same with the refund secret, only in a
//!   transaction whose window starts at `T` or later (`not_before ≥ T`).
//!
//! The window is the transaction's (PX6): the function echoes it in its
//! prefix and the verifier builds the prefix from the transaction, so a claim
//! and a refund of one record are never both includable at one height.
//!
//! The function's public output after the prefix is its selector, so an
//! observer learns that a vault was locked, claimed or refunded, the
//! transaction's window, and nothing else.
//!
//! **A demonstration contract** (docs/contracts.md §8), with known limits:
//! - **Whoever made the claim secret can claim.** A swap needs the
//!   counterparty to choose the secret and hand over only its lock
//!   ([`lock_call`] takes [`Terms`], not the secret).
//! - **Censorship:** a miner can delay a claim until the timeout passes;
//!   leave a margin.
//! - **Delivery (PX-F4):** whoever builds a transaction chooses the new
//!   record's `rcm` and writes its ciphertext.

use crate::perm::HostPerm;
use blacksilk_px_core::call::{OutSpec, Window};
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::FunctionWitness;
use blacksilk_px_core::record::{limbs, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use std::sync::{Arc, OnceLock};

/// The vault function program (RISC-V ELF), rebuilt by `zkvm/guests/build.sh`.
pub const VAULT_ELF: &[u8] = include_bytes!("../vault.elf");

/// The program id (hex), pinned in `px/vault.id`; a test checks it.
pub const VAULT_PROGRAM_ID: &str = include_str!("../vault.id");

/// Application hash domains (outside PX's range): the claim lock, the
/// refund lock and the terms.
pub const LOCK_DOMAIN: u32 = 0x5641_0001;
pub const REFUND_DOMAIN: u32 = 0x5641_0002;
pub const TERMS_DOMAIN: u32 = 0x5641_0003;

/// Selectors, the function's public output.
pub const LOCK: u32 = 0;
pub const CLAIM: u32 = 1;
pub const REFUND: u32 = 2;

/// Public output words after the prefix (the selector); the vault is
/// registered with this `out_words` (F-28-5).
pub const OUT_WORDS: u32 = 1;

/// The registered row budget: measured use of the largest of LOCK, CLAIM
/// and REFUND plus about 6% (`px/tests/unified.rs::budgets_leave_headroom`).
pub const BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_700,
    add: 4_300,
    bit: 260,
    lt: 3_900,
    shift: 240,
    mul: 240,
    poseidon: 27,
};

pub fn program() -> Arc<Program> {
    static P: OnceLock<Arc<Program>> = OnceLock::new();
    P.get_or_init(|| Arc::new(Program::from_elf(VAULT_ELF).expect("the vault ELF loads")))
        .clone()
}

/// `Hk(LOCK, contract ‖ secret)`: the claim lock.
pub fn lock_of(contract: &Digest, secret: &Digest) -> Digest {
    hash(&mut HostPerm::new(), LOCK_DOMAIN, &[contract, secret])
}

/// `Hk(REFUND, contract ‖ refund_secret)`: the refund lock.
pub fn refund_lock_of(contract: &Digest, refund_secret: &Digest) -> Digest {
    hash(
        &mut HostPerm::new(),
        REFUND_DOMAIN,
        &[contract, refund_secret],
    )
}

/// The terms a vault record's data commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub claim_lock: Digest,
    /// Zero without a timeout.
    pub refund_lock: Digest,
    /// The first height at which a refund may be included; 0 for none.
    pub timeout: u64,
}

impl Terms {
    /// Claimable with `secret` at any time, never refundable.
    pub fn claim_only(contract: &Digest, secret: &Digest) -> Terms {
        Terms {
            claim_lock: lock_of(contract, secret),
            refund_lock: ZERO_DIGEST,
            timeout: 0,
        }
    }

    /// The record data: `Hk(TERMS, contract ‖ claim_lock ‖ refund_lock ‖
    /// timeout₁₆[4])`.
    pub fn data(&self, contract: &Digest) -> Digest {
        hash(
            &mut HostPerm::new(),
            TERMS_DOMAIN,
            &[
                contract,
                &self.claim_lock,
                &self.refund_lock,
                &limbs(self.timeout),
            ],
        )
    }
}

/// The data of a vault record of `contract` claimable with `secret` and
/// without a refund ([`Terms::claim_only`]).
pub fn record_data(contract: &Digest, secret: &Digest) -> Digest {
    Terms::claim_only(contract, secret).data(contract)
}

fn words(parts: &[&[u32]]) -> Vec<u32> {
    parts.concat()
}

fn u64_words(v: u64) -> [u32; 2] {
    [v as u32, (v >> 32) as u32]
}

/// LOCK of `value` under `terms`, creating the vault record in output slot
/// `j` of a transaction with validity window `window`: the function's input
/// and the kernel's view of the call. The terms hold locks, not secrets.
pub fn lock_call(
    contract: &Digest,
    value: u64,
    terms: &Terms,
    j: usize,
    blind: &Digest,
    window: &Window,
) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[LOCK],
        contract,
        blind,
        &window.words(),
        &u64_words(value),
        &terms.claim_lock,
        &terms.refund_lock,
        &u64_words(terms.timeout),
        &[j as u32],
    ]);
    let mut spec = [None; 2];
    spec[j] = Some(OutSpec {
        owner: ZERO_DIGEST,
        contract: *contract,
        value,
        data: terms.data(contract),
    });
    let fw = FunctionWitness {
        contract: *contract,
        blind: *blind,
        approve: [false; 2],
        spec,
    };
    (input, fw)
}

/// CLAIM ([`CLAIM`], with the claim secret and the record's `refund_lock`)
/// or REFUND ([`REFUND`], with the refund secret and the record's
/// `claim_lock`) of vault record `rec` (kernel input slot `i`), paying its
/// value to `recipient` (an owner tag) in output slot `j`.
#[allow(clippy::too_many_arguments)]
fn release_call(
    selector: u32,
    rec: &Record,
    secret: &Digest,
    other_lock: &Digest,
    timeout: u64,
    recipient: &Digest,
    i: usize,
    j: usize,
    blind: &Digest,
    window: &Window,
) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[selector],
        &rec.contract,
        blind,
        &window.words(),
        &u64_words(rec.value),
        other_lock,
        &u64_words(timeout),
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

/// CLAIM of vault record `rec` (kernel input slot `i`) with `secret`, paying
/// its value to `recipient` in output slot `j`. `terms` are the record's
/// (their `claim_lock` must be `lock_of(contract, secret)`). With a timeout,
/// `window` must end before it.
#[allow(clippy::too_many_arguments)]
pub fn claim_call(
    rec: &Record,
    secret: &Digest,
    terms: &Terms,
    recipient: &Digest,
    i: usize,
    j: usize,
    blind: &Digest,
    window: &Window,
) -> (Vec<u32>, FunctionWitness) {
    release_call(
        CLAIM,
        rec,
        secret,
        &terms.refund_lock,
        terms.timeout,
        recipient,
        i,
        j,
        blind,
        window,
    )
}

/// REFUND of vault record `rec` with `refund_secret`: as [`claim_call`], with
/// a `window` that starts at or after the timeout.
#[allow(clippy::too_many_arguments)]
pub fn refund_call(
    rec: &Record,
    refund_secret: &Digest,
    terms: &Terms,
    recipient: &Digest,
    i: usize,
    j: usize,
    blind: &Digest,
    window: &Window,
) -> (Vec<u32>, FunctionWitness) {
    release_call(
        REFUND,
        rec,
        refund_secret,
        &terms.claim_lock,
        terms.timeout,
        recipient,
        i,
        j,
        blind,
        window,
    )
}
