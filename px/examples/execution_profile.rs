//! Measures whether the kernel's execution path depends on private data.
//!
//! The Program table's LogUp terminal is published in every proof and is a
//! function of the per-instruction execution counts alone
//! (docs/reviews/internal-review-log.md, ZK-F29). If those counts differ between
//! witnesses an observer cannot tell apart otherwise, a proof reveals the
//! difference. This runs the kernel in the interpreter (no proving) for many
//! witnesses of every transfer class, with varied amounts and keys, and
//! reports which count vectors occur.
//!
//! `cargo run --release -p blacksilk-px --example execution_profile -- [witnesses per class]`

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, witness_words};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::Witness;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];

struct Fixture {
    alice: Account,
    tree: Tree,
    user: Vec<(Record, u64)>,
}

fn fixture() -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[7; 32]);
    let mut tree = Tree::new(&mut perm);
    let mut user = Vec::new();
    for i in 0..4u32 {
        let r = Record::plain(
            alice.owner(i),
            1_000 + i as u64,
            [0; 8],
            wallet::random_digest(&mut rng),
            wallet::random_digest(&mut rng),
        );
        let cm = r.commit(&mut perm);
        user.push((r, tree.append(&mut perm, cm).unwrap()));
    }
    let mut vaults = Vec::new();
    for _ in 0..4 {
        let secret = wallet::random_digest(&mut rng);
        let r = Record {
            owner: ZERO_DIGEST,
            contract: C,
            asset: ZERO_DIGEST,
            value: 500,
            data: vault::lock_of(&secret),
            rho: wallet::random_digest(&mut rng),
            rcm: wallet::random_digest(&mut rng),
        };
        let cm = r.commit(&mut perm);
        // Vault records are in the tree, as in the proof-length campaign.
        vaults.push((r, tree.append(&mut perm, cm).unwrap(), secret));
    }
    Fixture { alice, tree, user }
}

fn transfer_witness(f: &Fixture, class: &str, k: usize, rng: &mut ChaCha20Rng) -> Witness {
    let spend = |i: usize| {
        let (r, pos) = &f.user[i];
        f.alice.spend(i as u32, r, *pos, f.tree.path(*pos).unwrap())
    };
    let root = f.tree.root();
    let amount = 1 + rng.next_u64() % 1_000_000;
    let i = k % 4;
    let j = (k + 1) % 4;
    match class {
        "deposit" => wallet::witness(
            State::new().root(),
            amount,
            0,
            [wallet::dummy_input(rng), wallet::dummy_input(rng)],
            [
                wallet::output(rng, f.alice.owner(20), amount),
                wallet::empty_output(rng),
            ],
        ),
        "pay2" => {
            let total = f.user[i].0.value + f.user[j].0.value;
            let pay = rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                0,
                [spend(i), spend(j)],
                [
                    wallet::output(rng, f.alice.owner(21), pay),
                    wallet::output(rng, f.alice.owner(22), total - pay),
                ],
            )
        }
        "pay1" => {
            let total = f.user[i].0.value;
            let pay = rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                0,
                [spend(i), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, f.alice.owner(23), pay),
                    wallet::output(rng, f.alice.owner(24), total - pay),
                ],
            )
        }
        "withdraw" => {
            let total = f.user[i].0.value;
            let out = 1 + rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                out,
                [spend(i), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, f.alice.owner(25), total - out),
                    wallet::empty_output(rng),
                ],
            )
        }
        _ => unreachable!(),
    }
}

/// Execution count per instruction index, and the total cycles.
fn profile(w: &Witness) -> (Vec<u32>, usize) {
    let prog = kernel_program();
    let words = witness_words(w);
    let exec =
        blacksilk_zkvm::run(&prog, &words, blacksilk_zkvm::MAX_CYCLES).expect("the kernel runs");
    assert_eq!(exec.exit_code, 0, "an accepted witness");
    let mut counts = vec![0u32; prog.code.len()];
    for s in &exec.steps {
        counts[((s.pc - prog.code_base) / 4) as usize] += 1;
    }
    (counts, exec.steps.len())
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(20);
    let f = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let mut profiles: BTreeMap<Vec<u32>, Vec<String>> = BTreeMap::new();
    let mut cycles: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for class in ["deposit", "pay2", "pay1", "withdraw"] {
        for k in 0..n {
            let w = transfer_witness(&f, class, k, &mut rng);
            let (counts, c) = profile(&w);
            let e = cycles.entry(class.to_string()).or_insert((usize::MAX, 0));
            e.0 = e.0.min(c);
            e.1 = e.1.max(c);
            let classes = profiles.entry(counts).or_default();
            if !classes.iter().any(|x| x == class) {
                classes.push(class.to_string());
            }
        }
    }
    println!("witnesses per class: {n}");
    for (class, (lo, hi)) in &cycles {
        println!("{class}: cycles {lo}..={hi}");
    }
    println!("distinct execution-count vectors: {}", profiles.len());
    for (i, classes) in profiles.values().enumerate() {
        println!("  profile {i}: classes {classes:?}");
    }
    let per_class_unique = profiles.values().all(|c| c.len() == 1);
    println!(
        "classes separable by the Program-table multiplicities alone: {}",
        if profiles.len() > 1 && per_class_unique {
            "YES (every profile belongs to one class)"
        } else if profiles.len() > 1 {
            "PARTLY"
        } else {
            "no (one profile for all)"
        }
    );
}
