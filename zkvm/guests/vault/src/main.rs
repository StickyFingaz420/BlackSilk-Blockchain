//! Example private contract function (docs/px.md §7.4): a hash-locked vault.
//!
//! - `LOCK` (selector 0): creates a record of this contract holding `value`
//!   under `lock = Hk(LOCK, secret)` in output slot `j`.
//! - `CLAIM` (selector 1): given the vault record in input slot `i` and the
//!   secret, approves consuming it and pays its value to `recipient` in
//!   output slot `j`.
//!
//! Everything but the contract id, the selector and the (hiding) `io_hash` is
//! private. Rejected calls halt with exit code 2; no proof of exit 0 exists.
#![no_std]
#![no_main]

use blacksilk_px_core::call::{function_prefix, Call, OutSpec};
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::{N_IN, N_OUT};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{canonical, Digest, Permutation, ZERO_DIGEST};
use blacksilk_zkvm_sdk as sdk;

/// Domain of the vault's lock hash (application domain, outside PX's range).
const LOCK: u32 = 0x5641_0001;

struct Syscall;

impl Permutation for Syscall {
    fn permute(&mut self, state: &mut [u32; 16]) {
        sdk::poseidon2(state);
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

fn value() -> u64 {
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

fn main() {
    let perm = &mut Syscall;
    let selector = sdk::read();
    let contract = digest();
    let blind = digest();
    let mut call = Call {
        contract,
        approve: [None; N_IN],
        spec: [None; N_OUT],
        blind,
    };
    match selector {
        0 => {
            let value = value();
            let lock = digest();
            let j = slot(N_OUT);
            call.spec[j] = Some(OutSpec {
                owner: ZERO_DIGEST,
                contract,
                value,
                data: lock,
            });
        }
        1 => {
            let value = value();
            let lock = digest();
            let rho = digest();
            let rcm = digest();
            let secret = digest();
            let recipient = digest();
            let i = slot(N_IN);
            let j = slot(N_OUT);
            if hash(perm, LOCK, &[&secret]) != lock {
                sdk::halt(2);
            }
            let vault = Record {
                owner: ZERO_DIGEST,
                contract,
                asset: ZERO_DIGEST,
                value,
                data: lock,
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
    for w in function_prefix(&call.io_hash(perm), &contract) {
        sdk::write(w);
    }
    sdk::write(selector);
}

sdk::entry!(main);
