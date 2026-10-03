//! The zkVM's stream limits (docs/zkvm.md §5: input ≤ 2^16 words, output
//! ≤ 2^12 words) are interpreter limits; the BVM-1 constraints do not count
//! READs or WRITEs (RT-MUTAIR, W4-MUTAIR spec-to-constraint note 2). PX does
//! not rely on the circuit for them. These tests pin the consensus facts
//! that keep every PX statement inside both limits, so a change of a PX
//! parameter that breaks them fails here rather than silently widening the
//! set of provable statements.
//!
//! - **Outputs.** The verifier builds every claimed output itself: the
//!   kernel's public statement (a fixed layout) and, per function, the prefix
//!   followed by exactly the registered `out_words` (≤ `MAX_FN_OUTPUT_WORDS`,
//!   checked at decode and in validation). The circuit binds the number of
//!   WRITEs to the claimed length exactly (`OUT = N_OUT` on the HALT row, and
//!   the OUTPUT table consumes each claimed word once).
//! - **Inputs.** The kernel's CPU table has the fixed height of its budget, so
//!   it executes fewer than `2^16` instructions, hence fewer READs. A
//!   function's READs are bounded only by its registered cycle budget
//!   (≤ `MAX_CYCLES`); its input is private witness either way.

use blacksilk_px::prove::{kernel_budget, public_words};
use blacksilk_px_core::call::{MAX_FN, PREFIX_WORDS};
use blacksilk_px_core::kernel::{Public, N_IN, N_OUT};
use blacksilk_tx::params::MAX_FN_OUTPUT_WORDS;
use blacksilk_zkvm::{MAX_INPUT_WORDS, MAX_OUTPUT_WORDS};

#[test]
fn px_statements_stay_within_the_zkvm_stream_limits() {
    // A function's claimed output: the prefix and its registered words.
    assert!(PREFIX_WORDS + MAX_FN_OUTPUT_WORDS <= MAX_OUTPUT_WORDS);
    for n_fn in 0..=MAX_FN {
        let public = Public {
            anchor: [0; 8],
            nullifiers: [[0; 8]; N_IN],
            commitments: [[0; 8]; N_OUT],
            bridge_in: 0,
            bridge_out: 0,
            n_fn,
            functions: [([0; 8], [0; 8]); MAX_FN],
        };
        // The kernel's claimed output has a fixed length per `n_fn`.
        assert!(
            public_words(&public).len() <= MAX_OUTPUT_WORDS,
            "n_fn {n_fn}"
        );
        // One READ per CPU row at most, and the kernel's CPU table has the
        // fixed height `pow2(cycles)`; one row is the HALT.
        let rows = kernel_budget(n_fn).cycles.next_power_of_two();
        assert!(rows <= MAX_INPUT_WORDS, "n_fn {n_fn}: {rows} kernel rows");
    }
}
