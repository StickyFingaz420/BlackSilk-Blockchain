//! Measurement (docs/reviews/aggregation-study.md §1): where the bytes of a
//! transfer proof go, from the proof's own structure (postcard sizes of each
//! part). `cargo run --release -p blacksilk-px --example proof_breakdown`

use blacksilk_px::prove::prove_transfer;
use blacksilk_px::state::State;
use blacksilk_px::wallet::{self, Account};
use rand_chacha::rand_core::SeedableRng;
use serde::Serialize;

fn size<T: Serialize + ?Sized>(x: &T) -> usize {
    postcard::to_allocvec(x).unwrap().len()
}

fn pct(part: usize, total: usize) -> String {
    format!("{part:>9} B  {:5.1}%", 100.0 * part as f64 / total as f64)
}

fn main() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let alice = Account::from_seed(&[7; 32]);
    let w = wallet::witness(
        State::new().root(),
        1000,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, alice.owner(0), 600),
            wallet::output(&mut rng, alice.owner(1), 400),
        ],
    );
    let (_, proof) = prove_transfer(&w, [1; 32], &mut rng).unwrap();
    let total = blacksilk_zk::encode_proof(&proof).len();
    let (random_openings, fri) = &proof.opening_proof;
    println!("transfer proof: {total} bytes");
    println!(
        "  commitments                 {}",
        pct(size(&proof.commitments), total)
    );
    println!(
        "  out-of-domain openings      {}",
        pct(size(&proof.opened_values), total)
    );
    println!(
        "  hiding-polynomial openings  {}",
        pct(size(random_openings), total)
    );
    println!(
        "  FRI commit-phase roots      {}",
        pct(size(&fri.commit_phase_commits), total)
    );
    println!(
        "  FRI final polynomial        {}",
        pct(size(&fri.final_poly), total)
    );
    let mut rows = 0;
    let mut auth = 0;
    for (r, batch) in fri.input_openings.iter().enumerate() {
        let (salts, paths) = &batch.opening_proof;
        let (v, s, p) = (size(&batch.opened_values), size(salts), size(paths));
        println!(
            "  input round {r}: opened rows {}, salts {}, pruned paths {}",
            pct(v, total),
            pct(s, total),
            pct(p, total)
        );
        rows += v;
        auth += s + p;
    }
    let mut fold_rows = 0;
    let mut fold_auth = 0;
    for (l, step) in fri.commit_phase_openings.iter().enumerate() {
        let (v, a) = (size(&step.sibling_values), size(&step.opening_proof));
        println!(
            "  FRI layer {l} (arity 2^{}): siblings {}, authentication {}",
            step.log_arity,
            pct(v, total),
            pct(a, total)
        );
        fold_rows += v;
        fold_auth += a;
    }
    println!("totals:");
    println!("  input rows opened           {}", pct(rows, total));
    println!("  input authentication        {}", pct(auth, total));
    println!("  FRI siblings                {}", pct(fold_rows, total));
    println!("  FRI authentication          {}", pct(fold_auth, total));
}
