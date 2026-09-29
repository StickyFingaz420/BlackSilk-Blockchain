//! The proof decoder's PX limits (`blacksilk_px::prove::PROOF_LIMITS`,
//! RT-FUZZ-1) hold for every PX statement: no valid PX proof is refused by
//! the decoder's bounds. No proving: the table counts, widths and quotient
//! chunk counts are those `verify` derives from the statement.

use blacksilk_px::prove::{kernel_budget, kernel_program, PROOF_LIMITS};
use blacksilk_px_core::call::MAX_FN;
use blacksilk_zk::DecodeLimits;
use blacksilk_zkvm::air::trace::{
    self, Part, Statement, BASE_TABLES, MAX_EXECUTIONS, TABLES_PER_EXTRA,
};

/// A statement of the kernel and `n_fn` vault calls, with PX budgets.
fn statement(n_fn: usize) -> Statement {
    let mut st = Statement::single(kernel_program(), 0, vec![0; 64], [0; 32]);
    st.budget = Some(kernel_budget(n_fn));
    for _ in 0..n_fn {
        st.others.push(Part {
            program: blacksilk_px::vault::program(),
            exit_code: 0,
            output: vec![0; 12],
            budget: Some(blacksilk_px::vault::BUDGET),
        });
    }
    st
}

#[test]
fn every_px_statement_is_within_the_decoder_limits() {
    let mut widest = 0;
    let mut most_chunks = 0;
    for n_fn in 0..=MAX_FN {
        let st = statement(n_fn);
        let airs = trace::tables(&st);
        assert!(airs.len() <= PROOF_LIMITS.max_instances, "n_fn {n_fn}");
        let degree_bits: Vec<usize> = st
            .shape()
            .expect("PX statements have a fixed shape")
            .iter()
            .map(|h| h.trailing_zeros() as usize + 1)
            .collect();
        let chunks = blacksilk_zk::analysis::quotient_chunks(&airs, &degree_bits);
        println!(
            "n_fn {n_fn}: {} tables, quotient chunks {chunks:?}",
            airs.len()
        );
        if n_fn == 0 {
            // As in the real transfer proof (px/tests/proof.rs).
            assert_eq!(chunks, [4, 4, 4, 4, 16, 4, 4, 8, 8, 8, 4, 8, 4]);
        }
        most_chunks = most_chunks.max(chunks.into_iter().max().unwrap());
        let widths = blacksilk_zk::analysis::trace_widths(&airs);
        widest = widest.max(widths.into_iter().max().unwrap());
    }
    // The widest statement has exactly the limit's tables.
    assert_eq!(
        trace::tables(&statement(MAX_FN)).len(),
        PROOF_LIMITS.max_instances
    );
    assert!(most_chunks <= PROOF_LIMITS.max_quotient_chunks);
    // The trace width bounds `trace_local`/`trace_next`; the permutation
    // openings and every other committed matrix count toward the committed
    // columns, whose total the widest PX proof keeps within the envelope
    // (zkvm/tests/multi.rs, measured on a real proof).
    assert!(widest <= PROOF_LIMITS.max_opened_width);
    println!("widest table {widest} columns, most quotient chunks {most_chunks}");
    assert_eq!(
        PROOF_LIMITS,
        DecodeLimits {
            max_instances: 23,
            ..DecodeLimits::ENVELOPE
        }
    );
}

// The envelope covers every BVM-1 statement, up to `MAX_EXECUTIONS` (33 tables).
const _: () = assert!(
    BASE_TABLES + TABLES_PER_EXTRA * (MAX_EXECUTIONS - 1)
        < DecodeLimits::ENVELOPE.max_instances + 1
);
