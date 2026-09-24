//! Diagnostic: where the bytes of a transfer proof go, per table.
//! `cargo run --release -p blacksilk-px --example proof_report`

use blacksilk_px::prove::prove_transfer;
use blacksilk_px::state::State;
use blacksilk_px::wallet::{self, Account};
use rand_chacha::rand_core::SeedableRng;
use std::time::Instant;

const NAMES: [&str; 12] = [
    "byte",
    "program",
    "image",
    "mem_init",
    "cpu",
    "add",
    "bit",
    "lt",
    "shift",
    "mul",
    "output",
    "poseidon2",
];

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
    let t = Instant::now();
    let (_, proof) = prove_transfer(&w, [1; 32], &mut rng).unwrap();
    let prove = t.elapsed();
    let (mut main, mut perm, mut quot) = (0, 0, 0);
    for (i, inst) in proof.opened_values.instances.iter().enumerate() {
        let b = &inst.base_opened_values;
        let q: usize = b.quotient_chunks.iter().map(|c| c.len()).sum();
        println!(
            "{:10} main {:4}  perm {:4}  quotient {:3}  rows 2^{}",
            NAMES[i],
            b.trace_local.len(),
            inst.permutation_local.len(),
            q,
            proof.degree_bits[i] - 1
        );
        main += b.trace_local.len();
        perm += inst.permutation_local.len();
        quot += q;
    }
    let total = blacksilk_zk::encode_proof(&proof).len();
    println!("sum: main {main}, perm {perm} (ext elements), quotient {quot} (ext elements)");
    println!("total {total} bytes; prove {prove:.1?}");
}
