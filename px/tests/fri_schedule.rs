//! R4-02: the canonical FRI folding schedule for every consensus PX shape,
//! computed natively (no proving).
//!
//! A PX proof has the fixed shape of the kernel's budget for `n_fn` functions
//! plus each function's registered budget (`px::prove`). The verifier requires
//! the folding schedule to be `blacksilk_zk::honest_fri_schedule` of the
//! proof's degree bits. This test derives, for each shape of the transactions
//! the tree builds (a plain transfer, one and two vault calls), the degree
//! bits from the statement alone and checks the schedule is well formed and
//! stops at every table height. That the p3-fri prover uses the same schedule
//! is checked on real proofs by `zk/tests/proofs.rs`
//! (`honest_proofs_use_the_canonical_fri_schedule`) and on PX proofs by every
//! test that verifies one (`tx/tests/px_consensus.rs`).

use blacksilk_px::prove::{kernel_budget, kernel_program};
use blacksilk_px::vault;
use blacksilk_zk::params;
use blacksilk_zkvm::air::trace::{Part, Statement};

/// The degree bits of a shaped statement: `log2(height) + 1` per table.
fn degree_bits(st: &Statement) -> Vec<usize> {
    st.shape()
        .expect("a shaped statement")
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect()
}

/// The kernel with `n_fn` vault calls. Output lengths set only the output
/// tables' heights, which are at the minimum for every PX statement.
fn shape(n_fn: usize) -> Statement {
    let mut st = Statement::single(kernel_program(), 0, vec![0; 64], [0; 32]);
    st.budget = Some(kernel_budget(n_fn));
    for _ in 0..n_fn {
        st.others.push(Part {
            program: vault::program(),
            exit_code: 0,
            output: vec![0; 17],
            budget: Some(vault::BUDGET),
        });
    }
    st
}

#[test]
fn every_consensus_shape_has_a_well_formed_canonical_schedule() {
    let log_final = params::LOG_BLOWUP + params::LOG_FINAL_POLY_LEN;
    for n_fn in 0..=2 {
        let dbs = degree_bits(&shape(n_fn));
        let s = blacksilk_zk::honest_fri_schedule(&dbs);
        let top = dbs.iter().max().unwrap() + params::LOG_BLOWUP;
        assert_eq!(s.iter().sum::<usize>(), top - log_final, "n_fn {n_fn}");
        assert!(s.iter().all(|&a| (1..=params::MAX_LOG_ARITY).contains(&a)));
        let mut visited = vec![top];
        for a in &s {
            visited.push(visited.last().unwrap() - a);
        }
        for db in &dbs {
            assert!(visited.contains(&(db + params::LOG_BLOWUP)));
        }
        println!("n_fn {n_fn}: degree bits {dbs:?}, schedule {s:?}");
    }
}
