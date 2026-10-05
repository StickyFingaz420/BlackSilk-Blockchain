//! The proof decoder's PX limits (`blacksilk_px::prove::PROOF_LIMITS`,
//! RT-FUZZ-1) hold for every PX statement: no valid PX proof is refused by
//! the decoder's bounds. No proving: the table counts, widths and quotient
//! chunk counts are those `verify` derives from the statement.

use blacksilk_px::prove::{
    check_shape, check_shape_bits, kernel_budget, kernel_program, public_words, FunctionCall,
    VerifyError, PROOF_LIMITS,
};
use blacksilk_px::vault;
use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION, MAX_FN};
use blacksilk_px_core::kernel::{Public, N_IN, N_OUT};
use blacksilk_px_core::Digest;
use blacksilk_zk::{DecodeLimits, ZkError};
use blacksilk_zkvm::air::trace::{
    self, Budget, Part, Statement, BASE_TABLES, MAX_EXECUTIONS, TABLES_PER_EXTRA,
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
        println!("n_fn {n_fn}: trace widths {widths:?}");
        if n_fn == 0 {
            // The real transfer proof's `trace_local` lengths
            // (px/tests/proof.rs).
            assert_eq!(
                widths,
                [18, 38, 16, 29, 103, 27, 24, 34, 44, 53, 16, 540, 9]
            );
        }
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

// The shape check on degree bits (`check_shape_bits`, RT-PXDOS F1), without
// proving (mutation run D): before it only the proving tests reached it.

const CONTRACT: Digest = [3; 8];

fn public(n_fn: usize) -> Public {
    Public {
        anchor: [1; 8],
        nullifiers: [[2; 8]; N_IN],
        commitments: [[4; 8]; N_OUT],
        bridge_in: 5,
        bridge_out: 6,
        n_fn,
        functions: [(CONTRACT, [7; 8]); MAX_FN],
    }
}

fn call() -> FunctionCall {
    FunctionCall {
        program: vault::program(),
        abi: ABI_VERSION,
        outputs: vec![8; 12],
    }
}

/// The vault is registered to `CONTRACT`, nothing else anywhere.
fn registered(contract: &Digest, id: &[u8; 32]) -> Option<Budget> {
    (*contract == CONTRACT && *id == vault::program().id()).then_some(vault::BUDGET)
}

/// The degree bits `verify` requires for the statement of `public` and
/// `calls` (built here as `prove::statement` builds it; under zero knowledge
/// a table of height `h` has `log2(h) + 1` degree bits).
fn degree_bits(
    public: &Public,
    calls: &[FunctionCall],
    window: &Window,
    h_tx: [u8; 32],
) -> Vec<usize> {
    let mut st = Statement::single(kernel_program(), 0, public_words(public), h_tx);
    st.budget = Some(kernel_budget(public.n_fn));
    for (c, (contract, io_hash)) in calls.iter().zip(&public.functions) {
        let mut output = function_prefix(c.abi, io_hash, contract, window).to_vec();
        output.extend(&c.outputs);
        st.others.push(Part {
            program: c.program.clone(),
            exit_code: 0,
            output,
            budget: Some(vault::BUDGET),
        });
    }
    st.shape()
        .expect("a fixed shape")
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect()
}

/// The encoding of a proof with one empty instance per entry of `bits` and
/// those degree bits: it decodes under `PROOF_LIMITS` (no vector is beyond a
/// cap, and the canonical-form rules hold), so its degree bits reach the
/// shape check, but it verifies nothing.
fn hollow_proof(bits: &[usize]) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    let mut b = vec![blacksilk_zk::PROOF_VERSION];
    b.push(1); // the main commitment: one root
    b.extend([0; 32]);
    b.push(0); // no permutation commitment
    b.push(1); // the quotient commitment
    b.extend([0; 32]);
    b.push(0); // no random commitment
    varint(&mut b, bits.len() as u64);
    for _ in bits {
        // trace_local empty; trace_next and both preprocessed openings
        // absent; no quotient chunks; no random opening; both permutation
        // openings empty.
        b.extend([0; 8]);
    }
    b.extend([2, 0, 0]); // the hidden openings: main and quotient rounds, no matrices
    b.extend([0; 5]); // FRI: commitments, witnesses, input batches, openings, final polynomial
    b.extend([0; 4]); // the query grinding witness
    b.push(0); // no lookup terminals
    varint(&mut b, bits.len() as u64);
    for &x in bits {
        varint(&mut b, x as u64);
    }
    b
}

#[test]
fn the_shape_check_accepts_exactly_the_statements_degree_bits() {
    let h_tx = [9; 32];
    let w = Window::UNBOUNDED;
    for n_fn in 0..=MAX_FN {
        let p = public(n_fn);
        let calls = vec![call(); n_fn];
        let bits = degree_bits(&p, &calls, &w, h_tx);
        let check = |p: &Public, calls: &[FunctionCall], bits: &[usize]| {
            check_shape_bits(p, calls, &w, h_tx, bits, registered)
        };
        let mismatch =
            |r: Result<(), VerifyError>| matches!(r, Err(VerifyError::Proof(ZkError::Shape(_))));
        assert_eq!(check(&p, &calls, &bits), Ok(()), "n_fn {n_fn}");
        // Every table's degree bits, one more or one fewer.
        for i in 0..bits.len() {
            for d in [bits[i] + 1, bits[i] - 1] {
                let mut b = bits.clone();
                b[i] = d;
                assert!(
                    mismatch(check(&p, &calls, &b)),
                    "n_fn {n_fn}, table {i}: {d}"
                );
            }
        }
        // A table missing or one too many.
        assert!(mismatch(check(&p, &calls, &bits[1..])), "n_fn {n_fn}");
        let mut b = bits.clone();
        b.push(bits[0]);
        assert!(mismatch(check(&p, &calls, &b)), "n_fn {n_fn}");
        // A call count other than the statement's.
        assert_eq!(
            check(&p, &vec![call(); n_fn + 1], &bits),
            Err(VerifyError::Shape)
        );
        if n_fn > 0 {
            assert_eq!(check(&p, &calls[1..], &bits), Err(VerifyError::Shape));
            // The last function's program is not registered to its contract.
            let mut q = p;
            q.functions[n_fn - 1].0 = [5; 8];
            assert_eq!(
                check(&q, &calls, &degree_bits(&q, &calls, &w, h_tx)),
                Err(VerifyError::Unregistered(n_fn - 1))
            );
        }
        // `check_shape` reads only a decoded proof's degree bits.
        let ok = blacksilk_zk::decode_proof_with(&hollow_proof(&bits), &PROOF_LIMITS)
            .expect("the hollow proof decodes");
        assert_eq!(ok.degree_bits, bits);
        assert_eq!(check_shape(&p, &calls, &w, h_tx, &ok, registered), Ok(()));
        let bad = blacksilk_zk::decode_proof_with(&hollow_proof(&bits[1..]), &PROOF_LIMITS)
            .expect("the hollow proof decodes");
        assert!(mismatch(check_shape(
            &p, &calls, &w, h_tx, &bad, registered
        )));
    }
    // More functions than `MAX_FN` (a hand-built statement): `Shape`, never
    // a panic.
    let mut p = public(MAX_FN);
    p.n_fn = MAX_FN + 1;
    assert_eq!(
        check_shape_bits(&p, &vec![call(); MAX_FN + 1], &w, h_tx, &[], registered),
        Err(VerifyError::Shape)
    );
}

/// Defence in depth (record `px-deploy-row-caps`): a registered budget above
/// the deploy caps, which no valid deploy can register, makes a statement
/// with a table taller than 2^PX_MAX_LOG_HEIGHT, and the shape check refuses
/// it with `Shape` whatever the degree bits. At 2^16 rows it is accepted.
#[test]
fn the_shape_check_refuses_a_table_above_the_px_height() {
    use blacksilk_px::prove::PX_MAX_LOG_HEIGHT;
    assert_eq!(PX_MAX_LOG_HEIGHT, 16);
    let h_tx = [9; 32];
    let w = Window::UNBOUNDED;
    let p = public(1);
    let calls = vec![call()];
    for (cycles, ok) in [(1usize << 16, true), ((1 << 16) + 1, false)] {
        let budget = Budget {
            cycles,
            ..vault::BUDGET
        };
        let reg = |c: &Digest, id: &[u8; 32]| registered(c, id).map(|_| budget);
        // The degree bits of this statement (the function's CPU table at
        // `pow2(cycles)` rows).
        let mut bits = degree_bits(&p, &calls, &w, h_tx);
        bits[BASE_TABLES + 3] = cycles.next_power_of_two().trailing_zeros() as usize + 1;
        let r = check_shape_bits(&p, &calls, &w, h_tx, &bits, reg);
        if ok {
            assert_eq!(r, Ok(()), "{cycles} cycles");
        } else {
            assert_eq!(r, Err(VerifyError::Shape), "{cycles} cycles");
        }
    }
}

/// E18's premise (docs/reviews/mutation-exemptions.md): the quotient chunk
/// count of every table of every PX statement does not depend on the trace
/// length, over the whole range of degree bits `verify` accepts, so the
/// helper's trace length cannot change a result. This fails if a table's
/// constraint degree ever comes to depend on its height (RT-MUTD).
#[test]
fn quotient_chunks_do_not_depend_on_the_trace_length() {
    use blacksilk_zk::params::{MAX_LOG_HEIGHT, MIN_LOG_HEIGHT};
    for n_fn in 0..=MAX_FN {
        let st = statement(n_fn);
        let airs = trace::tables(&st);
        let base =
            blacksilk_zk::analysis::quotient_chunks(&airs, &vec![MIN_LOG_HEIGHT + 1; airs.len()]);
        for db in MIN_LOG_HEIGHT + 2..=MAX_LOG_HEIGHT + 1 {
            assert_eq!(
                blacksilk_zk::analysis::quotient_chunks(&airs, &vec![db; airs.len()]),
                base,
                "n_fn {n_fn}, degree bits {db}"
            );
        }
    }
}

/// `verify` judges the statement before the proof (mutation run E): with
/// the statement's call count and registered programs a hollow proof of
/// the right shape reaches the proof check and fails it; another call count,
/// more functions than `MAX_FN` (a hand-built statement) and an unregistered
/// program are refused first, without a panic. `verify_transfer` takes
/// statements without functions only.
#[test]
fn verify_judges_the_statement_before_the_proof() {
    use blacksilk_px::prove::{verify, verify_transfer};
    let h_tx = [9; 32];
    let w = Window::UNBOUNDED;
    let failed_proof = |r: Result<(), VerifyError>| matches!(r, Err(VerifyError::Proof(_)));
    for n_fn in 0..=MAX_FN {
        let p = public(n_fn);
        let calls = vec![call(); n_fn];
        let bits = degree_bits(&p, &calls, &w, h_tx);
        let proof = blacksilk_zk::decode_proof_with(&hollow_proof(&bits), &PROOF_LIMITS)
            .expect("the hollow proof decodes");
        assert!(
            failed_proof(verify(&p, &calls, &w, h_tx, &proof, registered)),
            "n_fn {n_fn}"
        );
        assert_eq!(
            verify(&p, &vec![call(); n_fn + 1], &w, h_tx, &proof, registered),
            Err(VerifyError::Shape)
        );
        if n_fn > 0 {
            assert_eq!(
                verify(&p, &calls[1..], &w, h_tx, &proof, registered),
                Err(VerifyError::Shape)
            );
            let mut q = p;
            q.functions[n_fn - 1].0 = [5; 8];
            assert_eq!(
                verify(&q, &calls, &w, h_tx, &proof, registered),
                Err(VerifyError::Unregistered(n_fn - 1))
            );
            assert_eq!(verify_transfer(&p, h_tx, &proof), Err(VerifyError::Shape));
        } else {
            assert!(failed_proof(verify_transfer(&p, h_tx, &proof)));
        }
    }
    let mut p = public(MAX_FN);
    p.n_fn = MAX_FN + 1;
    let proof = blacksilk_zk::decode_proof_with(&hollow_proof(&[1]), &PROOF_LIMITS).unwrap();
    assert_eq!(
        verify(&p, &vec![call(); MAX_FN + 1], &w, h_tx, &proof, registered),
        Err(VerifyError::Shape)
    );
}
