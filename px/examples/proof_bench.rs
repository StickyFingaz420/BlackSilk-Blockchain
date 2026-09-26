//! Proof size, proving and verification time, and per-table layout, for a
//! transfer and a vault LOCK (the before/after measurement for ZK-F29/F30
//! changes). `cargo run --release -p blacksilk-px --example proof_bench -- [rounds]`

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, prove_transfer, verify_transfer};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::Witness;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];

struct Fixture {
    alice: Account,
    tree: Tree,
    user: Vec<(Record, u64)>,
    vaults: Vec<(Record, u64, Digest)>,
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
        vaults.push((r, tree.append(&mut perm, cm).unwrap(), secret));
    }
    Fixture {
        alice,
        tree,
        user,
        vaults,
    }
}

fn registry(contract: &Digest, program: &[u8; 32]) -> Option<blacksilk_zkvm::air::trace::Budget> {
    (*contract == C && *program == vault::program().id()).then_some(vault::BUDGET)
}

fn vault_witness(f: &Fixture, class: &str, k: usize, rng: &mut ChaCha20Rng) -> (Witness, Vec<u32>) {
    let blind = wallet::random_digest(rng);
    match class {
        "lock" => {
            let (r, pos) = &f.user[k % 4];
            let value = 1 + rng.next_u64() % r.value;
            let secret = wallet::random_digest(rng);
            let lock = vault::lock_of(&secret);
            let (input, fw) = vault::lock_call(&C, value, &lock, 0, &blind);
            let mut w = wallet::witness(
                f.tree.root(),
                0,
                0,
                [
                    f.alice
                        .spend((k % 4) as u32, r, *pos, f.tree.path(*pos).unwrap()),
                    wallet::dummy_input(rng),
                ],
                [
                    wallet::contract_output(rng, C, value, lock),
                    wallet::output(rng, f.alice.owner(26), r.value - value),
                ],
            );
            w.n_fn = 1;
            w.functions[0] = Some(fw);
            (w, input)
        }
        "claim" => {
            let (r, pos, secret) = &f.vaults[k % 4];
            let recipient = f.alice.owner(27);
            let (input, fw) = vault::claim_call(r, secret, &recipient, 0, 0, &blind);
            let mut w = wallet::witness(
                f.tree.root(),
                0,
                0,
                [
                    wallet::contract_input(rng, r, *pos, f.tree.path(*pos).unwrap()),
                    wallet::dummy_input(rng),
                ],
                [
                    wallet::output(rng, recipient, r.value),
                    wallet::empty_output(rng),
                ],
            );
            w.n_fn = 1;
            w.functions[0] = Some(fw);
            (w, input)
        }
        _ => unreachable!(),
    }
}

fn layout(proof: &blacksilk_zk::Proof) -> (usize, usize, usize, Vec<(usize, usize, usize)>) {
    let mut per = Vec::new();
    let (mut main, mut perm) = (0, 0);
    for (i, inst) in proof.opened_values.instances.iter().enumerate() {
        let b = &inst.base_opened_values;
        per.push((
            b.trace_local.len(),
            inst.permutation_local.len(),
            proof.degree_bits[i] - 1,
        ));
        main += b.trace_local.len();
        perm += inst.permutation_local.len();
    }
    (main, perm, per.len(), per)
}

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(3);
    let f = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let alice = Account::from_seed(&[7; 32]);
    let (mut tp, mut tv, mut sz) = (0f64, 0f64, 0usize);
    let mut last = None;
    for _ in 0..rounds {
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
        let (public, proof) = prove_transfer(&w, [1; 32], &mut rng).unwrap();
        tp += t.elapsed().as_secs_f64();
        let t = Instant::now();
        verify_transfer(&public, [1; 32], &proof).unwrap();
        tv += t.elapsed().as_secs_f64();
        sz += blacksilk_zk::encode_proof(&proof).len();
        last = Some(proof);
    }
    let n = rounds as f64;
    let (main, perm, tables, per) = layout(last.as_ref().unwrap());
    println!(
        "transfer: {rounds} proofs; mean size {} B; mean prove {:.1} s; mean verify {:.3} s",
        sz / rounds,
        tp / n,
        tv / n
    );
    println!("transfer layout: {tables} tables; opened main cols {main}; perm cols (ext) {perm}");
    for (i, (m, p, h)) in per.iter().enumerate() {
        println!("  table {i:2}: main {m:4} perm {p:3} rows 2^{h}");
    }
    let (mut tp, mut tv, mut sz) = (0f64, 0f64, 0usize);
    for k in 0..rounds {
        let (w, input) = vault_witness(&f, "lock", k, &mut rng);
        let t = Instant::now();
        let (public, calls, proof) = prove::prove(
            &w,
            &[(vault::program(), input, vault::BUDGET)],
            [2; 32],
            &mut rng,
        )
        .unwrap();
        tp += t.elapsed().as_secs_f64();
        let t = Instant::now();
        prove::verify(&public, &calls, [2; 32], &proof, registry).unwrap();
        tv += t.elapsed().as_secs_f64();
        sz += blacksilk_zk::encode_proof(&proof).len();
    }
    println!(
        "vault lock: {rounds} proofs; mean size {} B; mean prove {:.1} s; mean verify {:.3} s",
        sz / rounds,
        tp / n,
        tv / n
    );
    let _ = rng.next_u32();
}
