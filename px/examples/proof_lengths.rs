//! Measurement (privacy review P-5): encoded lengths of transfer proofs with
//! different witnesses. Field elements are fixed-width, so any variation
//! comes from the pruned Merkle query paths (how many nodes the query
//! positions share), not from the witness.
//! `cargo run --release -p blacksilk-px --example proof_lengths -- [count]`

use blacksilk_px::prove::prove_transfer;
use blacksilk_px::state::State;
use blacksilk_px::wallet::{self, Account};
use rand_chacha::rand_core::{RngCore, SeedableRng};

fn main() {
    let count: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(6);
    let alice = Account::from_seed(&[7; 32]);
    let mut lengths = Vec::new();
    for k in 0..count {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1_000 + k);
        // Different amounts and owners every time: different witnesses.
        let amount = 1 + rng.next_u64() % 1_000_000;
        let split = rng.next_u64() % amount;
        let w = wallet::witness(
            State::new().root(),
            amount,
            0,
            [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
            [
                wallet::output(&mut rng, alice.owner(k as u32), split),
                wallet::output(&mut rng, alice.owner(1_000 + k as u32), amount - split),
            ],
        );
        let (_, proof) = prove_transfer(&w, [k as u8; 32], &mut rng).unwrap();
        let total = blacksilk_zk::encode_proof(&proof).len();
        let opening = postcard::to_allocvec(&proof.opening_proof).unwrap().len();
        println!("proof {k}: {total} bytes (opening proof {opening})");
        lengths.push(total);
    }
    let min = *lengths.iter().min().unwrap();
    let max = *lengths.iter().max().unwrap();
    let mean = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;
    println!(
        "{count} proofs: min {min}, max {max}, spread {} bytes ({:.2}%), mean {mean:.0}",
        max - min,
        100.0 * (max - min) as f64 / mean
    );
}
