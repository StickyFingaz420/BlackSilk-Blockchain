//! Measurement (privacy review P-5): do proof lengths differ between two
//! classes of witness of the same shape? Class A is a deposit (two dummy
//! inputs, bridge-in); class B is a private payment (two real inputs). Proofs
//! alternate between the classes; a permutation test on the difference of
//! mean lengths estimates how likely the observed difference is if length is
//! independent of the class.
//! `cargo run --release -p blacksilk-px --example proof_length_distribution -- [per class]`

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::prove_transfer;
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn sd(v: &[f64]) -> f64 {
    let m = mean(v);
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)).sqrt()
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);
    let alice = Account::from_seed(&[7; 32]);
    let mut perm = HostPerm::new();
    // Two records of Alice's in a tree, for the payments.
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let mut tree = Tree::new(&mut perm);
    let recs: Vec<Record> = (0..2)
        .map(|i| {
            Record::plain(
                alice.owner(i),
                500 + i as u64,
                [0; 8],
                wallet::random_digest(&mut rng),
                wallet::random_digest(&mut rng),
            )
        })
        .collect();
    let pos: Vec<u64> = recs
        .iter()
        .map(|r| {
            let cm = r.commit(&mut perm);
            tree.append(&mut perm, cm).unwrap()
        })
        .collect();
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for k in 0..2 * n {
        let mut rng = ChaCha20Rng::seed_from_u64(5_000 + k as u64);
        let w = if k % 2 == 0 {
            let amount = 1 + rng.next_u64() % 1_000_000;
            wallet::witness(
                State::new().root(),
                amount,
                0,
                [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
                [
                    wallet::output(&mut rng, alice.owner(10), amount),
                    wallet::empty_output(&mut rng),
                ],
            )
        } else {
            let inputs = [
                alice.spend(0, &recs[0], pos[0], tree.path(pos[0]).unwrap()),
                alice.spend(1, &recs[1], pos[1], tree.path(pos[1]).unwrap()),
            ];
            wallet::witness(
                tree.root(),
                0,
                0,
                inputs,
                [
                    wallet::output(&mut rng, alice.owner(11), 700),
                    wallet::output(&mut rng, alice.owner(12), 301),
                ],
            )
        };
        let (_, proof) = prove_transfer(&w, [k as u8; 32], &mut rng).unwrap();
        let len = blacksilk_zk::encode_proof(&proof).len() as f64;
        println!(
            "{} {k}: {len} bytes",
            if k % 2 == 0 { "deposit" } else { "payment" }
        );
        if k % 2 == 0 {
            a.push(len)
        } else {
            b.push(len)
        }
    }
    let observed = (mean(&a) - mean(&b)).abs();
    println!(
        "deposit: mean {:.0}, sd {:.0}, min {}, max {}",
        mean(&a),
        sd(&a),
        a.iter().cloned().fold(f64::MAX, f64::min),
        a.iter().cloned().fold(0.0, f64::max)
    );
    println!(
        "payment: mean {:.0}, sd {:.0}, min {}, max {}",
        mean(&b),
        sd(&b),
        b.iter().cloned().fold(f64::MAX, f64::min),
        b.iter().cloned().fold(0.0, f64::max)
    );
    // Permutation test: relabel the pooled lengths at random.
    let pooled: Vec<f64> = a.iter().chain(&b).cloned().collect();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let rounds = 20_000;
    let mut at_least = 0;
    for _ in 0..rounds {
        let mut v = pooled.clone();
        for i in (1..v.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
        let d = (mean(&v[..n]) - mean(&v[n..])).abs();
        if d >= observed {
            at_least += 1;
        }
    }
    println!(
        "difference of means {observed:.0} bytes; permutation p = {:.3} ({rounds} rounds)",
        at_least as f64 / rounds as f64
    );
}
