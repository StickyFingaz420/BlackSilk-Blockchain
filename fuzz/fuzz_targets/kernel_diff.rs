//! The PX kernel, differentially: for any input words, the native kernel and
//! the kernel program in the zkVM give the same verdict (docs/px.md §4): the
//! same public output, the same error code, or a guest trap where the native
//! kernel read past the end of its input and rejected.
//!
//! The trap case is exact (F41-2): the only guest trap that matches a native
//! rejection is `InputExhausted`, and only when the native kernel did read
//! past the end of the same words (or the input is longer than the guest
//! accepts at all). Any other trap on an input the native kernel rejects
//! with a specific code (a cycle limit, an out-of-range access, a
//! non-canonical field word) is a divergence between the two kernels.
#![no_main]
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, public_words};
use blacksilk_px_core::kernel::{self, SliceSource, Source};
use blacksilk_zkvm::{run, TrapKind, MAX_CYCLES, MAX_INPUT_WORDS};
use libfuzzer_sys::fuzz_target;

/// The native source, counting how many words the kernel asked for.
struct Counting<'a> {
    inner: SliceSource<'a>,
    reads: usize,
}

impl Source for Counting<'_> {
    fn next(&mut self) -> u32 {
        self.reads += 1;
        self.inner.next()
    }
}

fuzz_target!(|data: &[u8]| {
    let (chunks, _) = data.as_chunks::<4>();
    let words: Vec<u32> = chunks.iter().map(|c| u32::from_le_bytes(*c)).collect();
    let mut source = Counting {
        inner: SliceSource::new(&words),
        reads: 0,
    };
    let native = kernel::transfer(&mut HostPerm::new(), &mut source);
    let over_read = source.reads > words.len();
    let guest = run(&kernel_program(), &words, MAX_CYCLES);
    match (native, guest) {
        (Ok(p), Ok(exec)) => {
            assert!(!over_read, "native accepted after reading past the end");
            assert_eq!(exec.exit_code, 0);
            assert_eq!(exec.output, public_words(&p));
        }
        (Err(e), Ok(exec)) => {
            assert!(!over_read, "{e:?}: native read past the end, guest exited");
            assert_eq!(exec.exit_code, e.exit_code(), "{e:?}");
            assert!(exec.output.is_empty());
        }
        (Err(e), Err(t)) => {
            assert_eq!(t.kind, TrapKind::InputExhausted, "{e:?}: guest {t:?}");
            assert!(
                over_read || words.len() > MAX_INPUT_WORDS,
                "{e:?}: guest ran out of input, native did not"
            );
        }
        (Ok(_), Err(t)) => panic!("native accepted, guest trapped: {t:?}"),
    }
});
