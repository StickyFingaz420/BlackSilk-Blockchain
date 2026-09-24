//! Fuzzing of the PX kernel and record delivery (pure Rust, seeded,
//! repeatable; `BLACKSILK_FUZZ_ITERS` scales the campaign).
//!
//! - **Kernel, native vs guest (differential):** mutated witnesses (random
//!   words changed, truncated, extended) must give the same verdict natively
//!   and in the zkVM: the same public output, or the same error exit code
//!   (or a guest trap when the native kernel read past the end).
//! - **Delivery:** mutated ciphertexts never open and never panic.

use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, public_words, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::{self, SliceSource};
use blacksilk_px_core::record::Record;
use blacksilk_zkvm::{run, MAX_CYCLES};
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
    let base = witness_words(&w);
    let n = iters(400);
    let (mut accepted, mut rejected, mut trapped) = (0, 0, 0);
    for _ in 0..n {
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
        let native = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&v));
        let guest = run(&kernel_program(), &v, MAX_CYCLES);
        match (native, guest) {
            (Ok(p), Ok(exec)) => {
                assert_eq!(exec.exit_code, 0);
                assert_eq!(exec.output, public_words(&p));
                accepted += 1;
            }
            (Err(e), Ok(exec)) => {
                assert_eq!(exec.exit_code, e.exit_code(), "{e:?}");
                assert!(exec.output.is_empty());
                rejected += 1;
            }
            // The guest traps reading past the end of its input; the native
            // kernel reads u32::MAX there and must reject too.
            (Err(_), Err(_)) => trapped += 1,
            (Ok(_), Err(t)) => panic!("native accepted, guest trapped: {t:?}"),
        }
    }
    println!("{n} mutated witnesses: {accepted} accepted (identical output), {rejected} rejected identically, {trapped} trapped (short input)");
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
    let c = delivery::seal(&mut rng, &addr, &rec, &cm).unwrap();
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
