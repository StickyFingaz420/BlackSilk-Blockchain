//! Example private contract function (docs/contracts.md §8): a hash-locked
//! vault with an optional timeout and refund.
//!
//! A vault record of contract `C` stores its **terms** in its data field:
//!
//! ```text
//! data        = Hk(TERMS,  C ‖ claim_lock ‖ refund_lock ‖ timeout₁₆[4])
//! claim_lock  = Hk(LOCK,   C ‖ secret)
//! refund_lock = Hk(REFUND, C ‖ refund_secret)     (0 when timeout = 0)
//! ```
//!
//! - `LOCK` (selector 0): creates a record of this contract holding `value`
//!   under the terms, in output slot `j`. `timeout = 0` means no refund, and
//!   then `refund_lock` must be 0.
//! - `CLAIM` (selector 1): given the vault record in input slot `i` and the
//!   secret, approves consuming it and pays its value to `recipient` in
//!   output slot `j`. With a timeout, only while the transaction's validity
//!   window ends before it (`not_after ≠ 0` and `not_after < timeout`).
//! - `REFUND` (selector 2): the same with the refund secret, only once the
//!   window starts at or after the timeout (`not_before ≥ timeout`).
//!
//! The window is read from the input and echoed in the function prefix,
//! which the verifier builds from the transaction's own window (PX6), so a
//! claim and a refund can never both be valid at one height. Both locks bind
//! the contract id, so a secret reused across vault instances opens only its
//! own (F-28-7).
//!
//! Everything but the contract id, the selector and the (hiding) `io_hash` is
//! private. Rejected calls halt with exit code 2; no proof of exit 0 exists.
#![no_std]
#![no_main]

use blacksilk_px_core::call::{function_prefix, Call, OutSpec, Window, ABI_VERSION};
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::{N_IN, N_OUT};
use blacksilk_px_core::record::{limbs, Record};
use blacksilk_px_core::{canonical, Digest, Permutation, ZERO_DIGEST};
use blacksilk_zkvm_sdk as sdk;

/// Application domains (outside PX's `0x0050_58xx` range): the claim lock,
/// the refund lock and the terms.
const LOCK: u32 = 0x5641_0001;
const REFUND: u32 = 0x5641_0002;
const TERMS: u32 = 0x5641_0003;

struct Syscall;

impl Permutation for Syscall {
    fn permute(&mut self, state: &mut [u32; 16]) {
        sdk::poseidon2(state);
    }

    // An invalid Hk input halts like a panic (exit code 1), without a
    // panic's source location in the program (R15-6).
    fn invalid_input(&mut self) -> ! {
        sdk::halt(1)
    }
}

fn digest() -> Digest {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = sdk::read();
        if !canonical(*x) {
            sdk::halt(2);
        }
    }
    d
}

fn u64_word() -> u64 {
    let lo = sdk::read() as u64;
    lo | ((sdk::read() as u64) << 32)
}

fn slot(n: usize) -> usize {
    let s = sdk::read() as usize;
    if s >= n {
        sdk::halt(2);
    }
    s
}

fn terms(
    perm: &mut Syscall,
    contract: &Digest,
    claim_lock: &Digest,
    refund_lock: &Digest,
    timeout: u64,
) -> Digest {
    hash(
        perm,
        TERMS,
        &[contract, claim_lock, refund_lock, &limbs(timeout)],
    )
}

fn main() {
    let perm = &mut Syscall;
    let selector = sdk::read();
    let contract = digest();
    let blind = digest();
    let window = Window {
        not_before: u64_word(),
        not_after: u64_word(),
    };
    let mut call = Call {
        contract,
        approve: [None; N_IN],
        spec: [None; N_OUT],
        blind,
    };
    match selector {
        0 => {
            let value = u64_word();
            let claim_lock = digest();
            let refund_lock = digest();
            let timeout = u64_word();
            let j = slot(N_OUT);
            if timeout == 0 && refund_lock != ZERO_DIGEST {
                sdk::halt(2);
            }
            call.spec[j] = Some(OutSpec {
                owner: ZERO_DIGEST,
                contract,
                value,
                data: terms(perm, &contract, &claim_lock, &refund_lock, timeout),
            });
        }
        1 | 2 => {
            let value = u64_word();
            // The other party's lock, then the rest of the terms and the
            // record's opening.
            let other_lock = digest();
            let timeout = u64_word();
            let rho = digest();
            let rcm = digest();
            let secret = digest();
            let recipient = digest();
            let i = slot(N_IN);
            let j = slot(N_OUT);
            let data = if selector == 1 {
                // CLAIM: before the timeout, if there is one.
                if timeout != 0 && (window.not_after == 0 || window.not_after >= timeout) {
                    sdk::halt(2);
                }
                let claim_lock = hash(perm, LOCK, &[&contract, &secret]);
                terms(perm, &contract, &claim_lock, &other_lock, timeout)
            } else {
                // REFUND: from the timeout on; never without one.
                if timeout == 0 || window.not_before < timeout {
                    sdk::halt(2);
                }
                let refund_lock = hash(perm, REFUND, &[&contract, &secret]);
                terms(perm, &contract, &other_lock, &refund_lock, timeout)
            };
            let vault = Record {
                owner: ZERO_DIGEST,
                contract,
                asset: ZERO_DIGEST,
                value,
                data,
                rho,
                rcm,
            };
            call.approve[i] = Some(vault.commit(perm));
            call.spec[j] = Some(OutSpec {
                owner: recipient,
                contract: ZERO_DIGEST,
                value,
                data: [0; 8],
            });
        }
        _ => sdk::halt(2),
    }
    for w in function_prefix(ABI_VERSION, &call.io_hash(perm), &contract, &window) {
        sdk::write(w);
    }
    sdk::write(selector);
}

sdk::entry!(main);
