//! The PX kernel, differentially: for any input words, the native kernel and
//! the kernel program in the zkVM give the same verdict (docs/px.md §4): the
//! same public output, the same error code, or a guest trap where the native
//! kernel read past the end of its input and rejected.
#![no_main]
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, public_words};
use blacksilk_px_core::kernel::{self, SliceSource};
use blacksilk_zkvm::{run, MAX_CYCLES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (chunks, _) = data.as_chunks::<4>();
    let words: Vec<u32> = chunks.iter().map(|c| u32::from_le_bytes(*c)).collect();
    let native = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words));
    let guest = run(&kernel_program(), &words, MAX_CYCLES);
    match (native, guest) {
        (Ok(p), Ok(exec)) => {
            assert_eq!(exec.exit_code, 0);
            assert_eq!(exec.output, public_words(&p));
        }
        (Err(e), Ok(exec)) => {
            assert_eq!(exec.exit_code, e.exit_code(), "{e:?}");
            assert!(exec.output.is_empty());
        }
        (Err(_), Err(_)) => {}
        (Ok(_), Err(t)) => panic!("native accepted, guest trapped: {t:?}"),
    }
});
