//! The BVM-1 loader and interpreter: arbitrary ELF files never panic the
//! loader, and whatever loads never panics the interpreter.
#![no_main]
use blacksilk_zkvm::{run, Program};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Program::from_elf(data) {
        let _ = run(&p, &[1, 2, 3, 4, 5, 6, 7, 8], 1 << 14);
    }
});
