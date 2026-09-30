//! Target body: the PX kernel, differentially (docs/px.md §4). For any input
//! words, the native kernel and the kernel program in the zkVM give the same
//! verdict. Shared by fuzz_targets/kernel_diff.rs and px/tests/fuzz.rs.
//!
//! Invariants, beyond "no panic":
//! - both accept, with the same public output; and the accepted execution
//!   fits the prover's per-execution budget for its function count
//!   (`prove::kernel_budget(n_fn)`, RT-FUZZ). An accepted witness over it is
//!   one the prover refuses (`OverBudget`): the kernel's rules and its
//!   budgets disagree, a liveness failure for an honest user (RTW1C-1);
//! - or both reject, with the same error code and no output;
//! - or the guest traps with `InputExhausted` exactly where the native
//!   kernel read past the end of its words (F41-2). Any other trap on an
//!   input the native kernel rejects (a cycle limit, an out-of-range access,
//!   a non-canonical field word) is a divergence between the two kernels,
//!   and so is a native read past the end where the guest exited normally.
//!
//! Inputs longer than `MAX_INPUT_WORDS` are out of scope: the guest refuses
//! them before executing (an input cap of the zkVM, not of the kernel), and
//! no caller comes near it (the campaign caps inputs at 8,192 bytes, 2,048
//! words; a PX witness is under 1,000 words).

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_budget, kernel_program, over_budget, public_words};
use blacksilk_px_core::kernel::{self, SliceSource, Source};
use blacksilk_zkvm::air::trace::usage;
use blacksilk_zkvm::{run, TrapKind, MAX_CYCLES, MAX_INPUT_WORDS};

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

/// The common verdict of the two kernels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Accepted, with this many functions.
    Accepted(usize),
    Rejected,
    /// The guest ran out of input where the native kernel read past the end.
    ShortInput,
    /// Longer than the guest accepts (not checked).
    OutOfScope,
}

/// The input bytes as little-endian words (a trailing partial word is
/// dropped).
pub fn words(data: &[u8]) -> Vec<u32> {
    let (chunks, _) = data.as_chunks::<4>();
    chunks.iter().map(|c| u32::from_le_bytes(*c)).collect()
}

pub fn run_bytes(data: &[u8]) {
    check(&words(data));
}

/// Runs both kernels on `words` and asserts that they agree.
pub fn check(words: &[u32]) -> Verdict {
    if words.len() > MAX_INPUT_WORDS {
        return Verdict::OutOfScope;
    }
    let mut source = Counting {
        inner: SliceSource::new(words),
        reads: 0,
    };
    let native = kernel::transfer(&mut HostPerm::new(), &mut source);
    let over_read = source.reads > words.len();
    let guest = run(&kernel_program(), words, MAX_CYCLES);
    match (native, guest) {
        (Ok(p), Ok(exec)) => {
            assert!(!over_read, "native accepted after reading past the end");
            assert_eq!(exec.exit_code, 0);
            assert_eq!(exec.output, public_words(&p));
            let used = usage(&kernel_program(), &exec);
            if let Some((table, u, b)) = over_budget(&used, &kernel_budget(p.n_fn)) {
                panic!(
                    "an accepted witness (n_fn = {}) is over its prover budget: {table} {u} > {b}",
                    p.n_fn
                );
            }
            Verdict::Accepted(p.n_fn)
        }
        (Err(e), Ok(exec)) => {
            assert!(!over_read, "{e:?}: native read past the end, guest exited");
            assert_eq!(exec.exit_code, e.exit_code(), "{e:?}");
            assert!(exec.output.is_empty());
            Verdict::Rejected
        }
        (Err(e), Err(t)) => {
            assert_eq!(t.kind, TrapKind::InputExhausted, "{e:?}: guest {t:?}");
            assert!(over_read, "{e:?}: guest ran out of input, native did not");
            Verdict::ShortInput
        }
        (Ok(_), Err(t)) => panic!("native accepted, guest trapped: {t:?}"),
    }
}
