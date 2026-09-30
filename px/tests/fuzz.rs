//! Fuzzing of the PX kernel and record delivery (pure Rust, seeded,
//! repeatable; `BLACKSILK_FUZZ_ITERS` scales the campaign).
//!
//! - **Kernel, native vs guest (differential):** mutated witnesses (random
//!   words changed, truncated, extended) must give the same verdict natively
//!   and in the zkVM: the same public output, or the same error exit code,
//!   or an `InputExhausted` guest trap exactly where the native kernel read
//!   past the end (F41-2: any other trap is a divergence); an accepted
//!   witness fits its prover budget. The oracle is the `kernel_diff` fuzz
//!   target's body (fuzz/src/targets/kernel_diff.rs), over witnesses with
//!   0, 1 and 2 functions.
//! - **Delivery:** mutated ciphertexts never open and never panic.

#[path = "../../fuzz/src/targets/kernel_diff.rs"]
#[allow(dead_code)] // `run_bytes` is the fuzz target's entry.
mod kernel_diff;
#[path = "../../fuzz/src/targets/kernel_shapes.rs"]
mod shapes;

use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::witness_words;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use kernel_diff::Verdict;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn iters(default: usize) -> usize {
    std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn mutated_witnesses_get_the_same_verdict_natively_and_in_the_guest() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[1; 32]);
    let mut tree = Tree::new(&mut perm);
    let rec = Record::plain(
        alice.owner(0),
        700,
        [0; 8],
        wallet::random_digest(&mut rng),
        wallet::random_digest(&mut rng),
    );
    let cm = rec.commit(&mut perm);
    let pos = tree.append(&mut perm, cm).unwrap();
    let w = wallet::witness(
        tree.root(),
        0,
        0,
        [
            alice.spend(0, &rec, pos, tree.path(pos).unwrap()),
            wallet::dummy_input(&mut rng),
        ],
        [
            wallet::output(&mut rng, alice.owner(1), 300),
            wallet::output(&mut rng, alice.owner(2), 400),
        ],
    );
    // The plain transfer above, and one honest witness of every function
    // count (n_fn = 1, 2; fuzz/src/targets/kernel_shapes.rs).
    let mut bases = vec![witness_words(&w)];
    let all = shapes::valid_shapes();
    for n_fn in 1..=blacksilk_px_core::call::MAX_FN {
        let (k, shape) = all
            .iter()
            .enumerate()
            .find(|(_, s)| s.fns.len() == n_fn)
            .expect("a shape with n_fn functions");
        bases.push(witness_words(&shape.witness(k as u64)));
    }
    for base in &bases {
        assert!(matches!(kernel_diff::check(base), Verdict::Accepted(_)));
    }
    let n = iters(400);
    let (mut accepted, mut rejected, mut trapped) = ([0; 3], 0, 0);
    for _ in 0..n {
        let base = &bases[rng.next_u32() as usize % bases.len()];
        let mut v = base.clone();
        match rng.next_u32() % 5 {
            0 | 1 => {
                for _ in 0..1 + rng.next_u32() % 3 {
                    let i = rng.next_u32() as usize % v.len();
                    v[i] = match rng.next_u32() % 4 {
                        0 => rng.next_u32(),
                        1 => v[i] ^ 1,
                        2 => blacksilk_px_core::P,
                        _ => 0,
                    };
                }
            }
            2 => {
                let i = rng.next_u32() as usize % v.len();
                v[i] = v[i].wrapping_add(1);
            }
            3 => v.truncate(rng.next_u32() as usize % v.len()),
            _ => v.extend((0..1 + rng.next_u32() % 8).map(|_| rng.next_u32())),
        }
        match kernel_diff::check(&v) {
            Verdict::Accepted(n_fn) => accepted[n_fn] += 1,
            Verdict::Rejected => rejected += 1,
            Verdict::ShortInput => trapped += 1,
            Verdict::OutOfScope => unreachable!("a witness is far shorter"),
        }
    }
    println!("{n} mutated witnesses: {accepted:?} accepted by n_fn (identical output, within budget), {rejected} rejected identically, {trapped} trapped (short input)");
}

#[test]
fn mutated_ciphertexts_never_open_and_never_panic() {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let bob = Account::from_seed(&[2; 32]);
    let addr = bob.address(0);
    let keys = bob.delivery_keys(0);
    let rho = wallet::random_digest(&mut rng);
    let rec = Record::plain(addr.owner, 5, [0; 8], rho, wallet::random_digest(&mut rng));
    let cm = rec.commit(&mut HostPerm::new());
    let c = delivery::seal(&mut rng, &[0x5e; 32], &addr, &rec, &cm).unwrap();
    assert!(delivery::open(&keys, &addr.owner, &c, &cm, &rho).is_some());
    let n = iters(3000);
    for _ in 0..n {
        let mut m = c.clone();
        match rng.next_u32() % 4 {
            0 => {
                let i = rng.next_u32() as usize % m.len();
                m[i] ^= 1 << (rng.next_u32() % 8);
            }
            1 => m.truncate(rng.next_u32() as usize % m.len()),
            2 => m.push(rng.next_u32() as u8),
            _ => {
                for x in m.iter_mut() {
                    *x = rng.next_u32() as u8;
                }
            }
        }
        assert!(delivery::open(&keys, &addr.owner, &m, &cm, &rho).is_none());
    }
    println!("{n} mutated ciphertexts: none opened, no panic");
}
