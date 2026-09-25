//! Statistical campaign for privacy review P-5: proof lengths across witness
//! classes and execution paths.
//!
//! Shape "transfer" (no function): `deposit` (two dummy inputs, bridge-in),
//! `pay2` (two real inputs), `pay1` (one real input and a dummy), `withdraw`
//! (a real input, bridge-out). Shape "vault" (one function): `lock` (a user
//! record locked into a vault record), `claim` (a vault record claimed).
//!
//! For every proof it records the total length and the size of the Merkle
//! authentication data, and **asserts** that everything else has the same
//! encoded length for every proof of the shape. For every pair of classes of
//! one shape it runs permutation tests (20,000 relabellings) on the
//! difference of means and on the Kolmogorov–Smirnov statistic.
//!
//! `cargo run --release -p blacksilk-px --example proof_length_campaign -- <per transfer class> <per vault class> <csv path>`

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, prove_transfer};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::Witness;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::io::Write;

const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];

fn size<T: Serialize + ?Sized>(x: &T) -> usize {
    postcard::to_allocvec(x).unwrap().len()
}

/// `(total length, authentication-data length, sum of all other parts)`.
fn measure(proof: &blacksilk_zk::Proof) -> (usize, usize, usize) {
    let (_, fri) = &proof.opening_proof;
    let mut auth = 0;
    for batch in &fri.input_openings {
        auth += size(&batch.opening_proof.1);
    }
    for step in &fri.commit_phase_openings {
        auth += size(&step.opening_proof);
    }
    let total = blacksilk_zk::encode_proof(proof).len();
    (total, auth, total - auth)
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn sd(v: &[f64]) -> f64 {
    let m = mean(v);
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)).sqrt()
}

/// Two-sample Kolmogorov–Smirnov statistic.
fn ks(a: &[f64], b: &[f64]) -> f64 {
    let mut xs: Vec<f64> = a.iter().chain(b).cloned().collect();
    xs.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let cdf = |v: &[f64], x: f64| v.iter().filter(|&&y| y <= x).count() as f64 / v.len() as f64;
    xs.iter()
        .map(|&x| (cdf(a, x) - cdf(b, x)).abs())
        .fold(0.0, f64::max)
}

/// Permutation p-values for the difference of means and the KS statistic.
fn permutation(a: &[f64], b: &[f64], rng: &mut ChaCha20Rng) -> (f64, f64) {
    let (dm, dk) = ((mean(a) - mean(b)).abs(), ks(a, b));
    let pooled: Vec<f64> = a.iter().chain(b).cloned().collect();
    let rounds = 20_000;
    let (mut m, mut k) = (0, 0);
    for _ in 0..rounds {
        let mut v = pooled.clone();
        for i in (1..v.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
        let (x, y) = v.split_at(a.len());
        if (mean(x) - mean(y)).abs() >= dm {
            m += 1;
        }
        if ks(x, y) >= dk {
            k += 1;
        }
    }
    (m as f64 / rounds as f64, k as f64 / rounds as f64)
}

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

fn report(shape: &str, classes: &[(&str, Vec<f64>)], out: &mut impl Write) {
    writeln!(out, "# shape {shape}").unwrap();
    for (name, v) in classes {
        println!(
            "{shape}/{name}: n {}, mean {:.0}, sd {:.0}, min {}, max {}",
            v.len(),
            mean(v),
            sd(v),
            v.iter().cloned().fold(f64::MAX, f64::min),
            v.iter().cloned().fold(0.0, f64::max)
        );
    }
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for a in 0..classes.len() {
        for b in a + 1..classes.len() {
            let (pm, pk) = permutation(&classes[a].1, &classes[b].1, &mut rng);
            println!(
                "{shape}: {} vs {}: mean difference {:.0} bytes, p(mean) = {pm:.3}, KS {:.3}, p(KS) = {pk:.3}",
                classes[a].0,
                classes[b].0,
                (mean(&classes[a].1) - mean(&classes[b].1)).abs(),
                ks(&classes[a].1, &classes[b].1)
            );
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n_transfer: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(50);
    let n_vault: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(30);
    let csv = args.get(3).cloned().unwrap_or("proof_lengths.csv".into());
    let mut out = std::fs::File::create(&csv).unwrap();
    writeln!(out, "shape,class,index,total_bytes,auth_bytes,other_bytes").unwrap();
    let f = fixture();

    // Transfer shape: classes interleaved.
    let names = ["deposit", "pay2", "pay1", "withdraw"];
    let mut lens: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut other: Option<usize> = None;
    for k in 0..n_transfer * names.len() {
        let c = k % names.len();
        let mut rng = ChaCha20Rng::seed_from_u64(10_000 + k as u64);
        let w = transfer_witness(&f, names[c], k / names.len(), &mut rng);
        let (_, proof) = prove_transfer(&w, [k as u8; 32], &mut rng).unwrap();
        let (total, auth, rest) = measure(&proof);
        assert_eq!(
            *other.get_or_insert(rest),
            rest,
            "non-authentication length differs"
        );
        writeln!(out, "transfer,{},{k},{total},{auth},{rest}", names[c]).unwrap();
        out.flush().unwrap();
        lens[c].push(total as f64);
    }
    let transfer: Vec<(&str, Vec<f64>)> = names.iter().cloned().zip(lens).collect();

    // Vault shape.
    let names = ["lock", "claim"];
    let mut lens: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut other: Option<usize> = None;
    for k in 0..n_vault * names.len() {
        let c = k % names.len();
        let mut rng = ChaCha20Rng::seed_from_u64(20_000 + k as u64);
        let (w, input) = vault_witness(&f, names[c], k / names.len(), &mut rng);
        let h = [k as u8; 32];
        let (public, calls, proof) =
            prove::prove(&w, &[(vault::program(), input, vault::BUDGET)], h, &mut rng).unwrap();
        assert_eq!(prove::verify(&public, &calls, h, &proof, registry), Ok(()));
        let (total, auth, rest) = measure(&proof);
        assert_eq!(
            *other.get_or_insert(rest),
            rest,
            "non-authentication length differs"
        );
        writeln!(out, "vault,{},{k},{total},{auth},{rest}", names[c]).unwrap();
        out.flush().unwrap();
        lens[c].push(total as f64);
    }
    let vaultc: Vec<(&str, Vec<f64>)> = names.iter().cloned().zip(lens).collect();

    report("transfer", &transfer, &mut out);
    report("vault", &vaultc, &mut out);
    println!("every proof of each shape had the same non-authentication length");
}
