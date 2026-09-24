//! Diagnostic: cycle count and per-table trace heights of the kernel on a
//! typical transfer. `cargo run --release -p blacksilk-px --example
//! kernel_cycles [kernel.elf]` (defaults to the pinned kernel).

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use blacksilk_zkvm::{run, Program, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use std::sync::Arc;

fn main() {
    let program = match std::env::args().nth(1) {
        Some(path) => Arc::new(Program::from_elf(&std::fs::read(path).unwrap()).unwrap()),
        None => kernel_program(),
    };
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let mut perm = HostPerm::new();
    let mut tree = Tree::new(&mut perm);
    let alice = Account::from_seed(&[1; 32]);
    let mut inputs = Vec::new();
    for i in 0..2u32 {
        let rec = Record::plain(
            alice.owner(i),
            500,
            [0; 8],
            wallet::random_digest(&mut rng),
            wallet::random_digest(&mut rng),
        );
        let cm = rec.commit(&mut perm);
        let pos = tree.append(&mut perm, cm).unwrap();
        inputs.push((i, rec, pos));
    }
    let ins = inputs
        .iter()
        .map(|(i, rec, pos)| alice.spend(*i, rec, *pos, tree.path(*pos).unwrap()))
        .collect::<Vec<_>>();
    let outs = [
        wallet::output(&mut rng, alice.owner(5), 600),
        wallet::output(&mut rng, alice.owner(6), 400),
    ];
    let w = wallet::witness(tree.root(), 0, 0, [ins[0].clone(), ins[1].clone()], outs);
    let exec = run(&program, &witness_words(&w), MAX_CYCLES).unwrap();
    assert_eq!(exec.exit_code, 0);
    let mut ops = std::collections::BTreeMap::new();
    for s in &exec.steps {
        *ops.entry(format!("{:?}", s.instr.op)).or_insert(0u32) += 1;
    }
    println!("cycles {}", exec.steps.len());
    println!("instruction mix {ops:?}");
}
