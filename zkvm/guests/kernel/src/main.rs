//! The PX kernel (docs/px.md §4, §7): `blacksilk_px_core::kernel`
//! run over the private input, with the `POSEIDON2` syscall as permutation.
//! On success it writes the public statement and halts with 0; on a rejected
//! witness it halts with the error's exit code, for which no proof of exit 0
//! exists.
#![no_std]
#![no_main]

use blacksilk_px_core::kernel::{self, Source};
use blacksilk_px_core::Permutation;
use blacksilk_zkvm_sdk as sdk;

struct Syscall;

impl Permutation for Syscall {
    fn permute(&mut self, state: &mut [u32; 16]) {
        sdk::poseidon2(state);
    }
}

struct Input;

impl Source for Input {
    fn next(&mut self) -> u32 {
        sdk::read()
    }
}

fn main() {
    match kernel::transfer(&mut Syscall, &mut Input) {
        Ok(public) => public.write(sdk::write),
        Err(e) => sdk::halt(e.exit_code()),
    }
}

sdk::entry!(main);
