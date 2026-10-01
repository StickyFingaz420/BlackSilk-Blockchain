//! Killing tests for survivors of the px-core mutation census (W4-MUT,
//! docs/evidence/mutation-2026-09-29/). px-core's own source is not edited
//! for tests: its guest build is consensus-pinned (`px/kernel.id`), so the
//! tests live here, next to the other px-core oracles.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, public_words, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::OutSpec;
use blacksilk_px_core::hash::{domain, hash, Sponge};
use blacksilk_px_core::kernel::{self, Error, FunctionWitness, Public, SliceSource, Witness};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, Permutation, P};
use blacksilk_zkvm::{run, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::panic::{catch_unwind, AssertUnwindSafe};

const MARK: &str = "Hk input refused by the invalid-input hook";

/// The host permutation with an invalid-input hook that panics with [`MARK`],
/// so that a test tells the hook apart from any other panic (an overflow
/// check, `add`'s debug assertion). In the guest the hook halts with exit
/// code 1 and nothing else stops a bad input: a release build has neither
/// overflow checks nor debug assertions (R15-6).
struct Marked(HostPerm);

impl Permutation for Marked {
    fn permute(&mut self, state: &mut [u32; 16]) {
        self.0.permute(state)
    }

    fn invalid_input(&mut self) -> ! {
        panic!("{MARK}")
    }
}

/// Whether `f` stops in the invalid-input hook (and not elsewhere).
fn refused_by_the_hook(f: impl FnOnce(&mut Marked)) -> bool {
    let mut perm = Marked(HostPerm::new());
    match catch_unwind(AssertUnwindSafe(|| f(&mut perm))) {
        Ok(()) => false,
        Err(e) => e.downcast_ref::<String>().is_some_and(|m| m == MARK),
    }
}

/// `Sponge::absorb` sends each invalid input to the hook on its own: a
/// non-canonical element while elements are still owed, at the first and at a
/// later rate position, and a canonical element beyond the declared length
/// (W4-MUT: either `||` of the guard mutated to `&&` survived, the bad input
/// then reaching a debug assertion or an overflow check instead of the hook).
/// `finish` refuses a short input the same way, and a well-formed input
/// reaches no hook and equals `hash`.
#[test]
fn sponge_refuses_each_invalid_input_through_the_hook() {
    for bad in [P, P + 1, u32::MAX] {
        assert!(
            refused_by_the_hook(|perm| {
                let mut s = Sponge::new(domain::NK, 3);
                s.absorb(perm, bad);
            }),
            "non-canonical {bad:#x} as the first element"
        );
        assert!(
            refused_by_the_hook(|perm| {
                let mut s = Sponge::new(domain::NK, 12);
                s.absorb_all(perm, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
                s.absorb(perm, bad);
            }),
            "non-canonical {bad:#x} after a permutation"
        );
    }
    for declared in [0u32, 1, 7, 8, 9] {
        assert!(
            refused_by_the_hook(|perm| {
                let mut s = Sponge::new(domain::NK, declared);
                for x in 0..=declared {
                    s.absorb(perm, x);
                }
            }),
            "element {} of {declared} declared",
            declared + 1
        );
    }
    assert!(refused_by_the_hook(|perm| {
        let mut s = Sponge::new(domain::NK, 9);
        s.absorb_all(perm, &[1; 8]);
        let _ = s.finish(perm);
    }));

    let input: Vec<u32> = (0..17).map(|i| (i * 0x0765_4321) % P).collect();
    let mut perm = Marked(HostPerm::new());
    for len in [0, 1, 8, 9, 16, 17] {
        let mut s = Sponge::new(domain::RECORD, len as u32);
        s.absorb_all(&mut perm, &input[..len]);
        let d: Digest = s.finish(&mut perm);
        assert_eq!(d, hash(&mut perm, domain::RECORD, &[&input[..len]]));
    }
}

/// `hash` refuses a non-canonical element through the hook as well.
#[test]
fn hash_refuses_a_non_canonical_element_through_the_hook() {
    for at in [0usize, 5, 8, 11] {
        assert!(refused_by_the_hook(|perm| {
            let mut xs = [3u32; 12];
            xs[at] = P;
            let _ = hash(perm, domain::NK, &[&xs[..6], &xs[6..]]);
        }));
    }
}

/// The kernel natively and the pinned guest in the interpreter: the same
/// verdict, and on success the same output words.
fn both(w: &Witness) -> Result<Public, Error> {
    let words = witness_words(w);
    let native = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words));
    let exec = run(&kernel_program(), &words, MAX_CYCLES).expect("the kernel halts");
    match &native {
        Ok(p) => {
            assert_eq!(exec.exit_code, 0, "the guest refused what native accepted");
            assert_eq!(exec.output, public_words(p), "guest output differs");
        }
        Err(e) => assert_eq!(exec.exit_code, e.exit_code(), "guest verdict for {e:?}"),
    }
    native
}

/// Bridge amounts of 2^32 or more are written low word first, then the high
/// word (W4-MUT: `v >> 32` mutated to `v << 32` survived, every test bridge
/// being below 2^32). The layout is checked word by word, and a transfer that
/// bridges such amounts yields the guest's exact output natively.
#[test]
fn public_words_carry_the_high_word_of_each_bridge_amount() {
    let d = |x: u32| [x; 8];
    let public = Public {
        anchor: d(1),
        nullifiers: [d(2), d(3)],
        commitments: [d(4), d(5)],
        bridge_in: 0x0000_0007_0000_0009,
        bridge_out: 0x0000_000B_0000_000D,
        n_fn: 0,
        functions: [(d(0), d(0)); 2],
    };
    let words = public_words(&public);
    assert_eq!(words.len(), 1 + 8 * 5 + 4 + 1);
    assert_eq!(words[0], kernel::VERSION);
    assert_eq!(&words[41..45], &[9, 7, 0xD, 0xB]);
    assert_eq!(words[45], 0);

    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let bob = Account::from_seed(&[2; 32]);
    let root = Tree::new(&mut HostPerm::new()).root();
    let big = (5u64 << 32) + 7;
    let w = wallet::witness(
        root,
        big,
        (1 << 32) + 3,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, bob.owner(0), (4 << 32) + 4),
            wallet::empty_output(&mut rng),
        ],
    );
    let p = both(&w).expect("balanced");
    assert_eq!((p.bridge_in, p.bridge_out), (big, (1 << 32) + 3));
}

/// A digest with two equal nonzero words differs from zero, and two digests
/// that differ in two words by the same bits differ (W4-MUT: `digest_eq`'s
/// fold `acc | (x ^ y)` mutated to `acc ^ (x ^ y)` survived; the XOR fold
/// calls such digests equal). Two consequences are checked natively and in
/// the guest: a contract output with an owner, whose contract `[9, 9, 0, …]`
/// the mutant takes for zero, is refused (PX-F5); and an anchor that differs
/// from the real root by the same bit in two words is not a membership proof.
#[test]
fn digests_differing_in_two_words_by_the_same_bits_are_not_equal() {
    let mut rng = ChaCha20Rng::seed_from_u64(43);
    let mut perm = HostPerm::new();
    let bob = Account::from_seed(&[2; 32]);
    let root = Tree::new(&mut perm).root();
    let mut w = wallet::witness(
        root,
        5000,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, bob.owner(0), 5000),
            wallet::empty_output(&mut rng),
        ],
    );
    both(&w).expect("the base witness is valid");
    w.outputs[0].contract = [9, 9, 0, 0, 0, 0, 0, 0];
    assert_eq!(both(&w).err(), Some(Error::ContractOutputOwner));

    // A real spend of Alice's record, then the same witness under an anchor
    // with the same bit flipped in two words (both stay canonical).
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
    let spend = alice.spend(0, &rec, pos, tree.path(pos).unwrap());
    let mut w = wallet::witness(
        tree.root(),
        0,
        0,
        [spend, wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, bob.owner(1), 700),
            wallet::empty_output(&mut rng),
        ],
    );
    both(&w).expect("a valid spend");
    let bit = (0..30)
        .map(|b| 1u32 << b)
        .find(|&m| (w.anchor[0] ^ m) < P && (w.anchor[1] ^ m) < P)
        .expect("a bit that keeps both words canonical");
    w.anchor[0] ^= bit;
    w.anchor[1] ^= bit;
    assert_eq!(both(&w).err(), Some(Error::NotInTree));
}

/// A transaction with one function of contract `c`: 500 bridged in, output 0
/// is a new record of `c` and output 1 a payout of 0 to Bob, both specified
/// by the function.
fn one_function(rng: &mut ChaCha20Rng, c: Digest) -> Witness {
    let bob = Account::from_seed(&[2; 32]);
    let root = Tree::new(&mut HostPerm::new()).root();
    let data = wallet::random_digest(rng);
    let outputs = [
        wallet::contract_output(rng, c, 500, data),
        wallet::output(rng, bob.owner(0), 0),
    ];
    let spec = |o: &kernel::OutputWitness| OutSpec {
        owner: o.owner,
        contract: o.contract,
        value: o.value,
        data: o.data,
    };
    let fw = FunctionWitness {
        contract: c,
        blind: wallet::random_digest(rng),
        approve: [false; 2],
        spec: [Some(spec(&outputs[0])), Some(spec(&outputs[1]))],
    };
    let inputs = [wallet::dummy_input(rng), wallet::dummy_input(rng)];
    let mut w = wallet::witness(root, 500, 0, inputs, outputs);
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    w
}

/// An output must equal its specification in every field: owner, contract,
/// value and data, each checked alone (W4-MUT: each `&` of the comparison
/// mutated to `|` survived, since no native test called a function; the
/// proving tests that do were outside the census). Natively and in the guest.
///
/// Every edited witness is otherwise valid: balanced (the value cases move
/// `bridge_in` with the output), and a contract edit goes to contract 0, so
/// that no other rule (`Unbalanced`, `Unauthorized`) refuses it. A mutant
/// that skips one field of the comparison therefore ACCEPTS an output the
/// function did not specify. The control: the same witness with the
/// function's specification updated to the edited output is accepted.
#[test]
fn a_specified_output_must_match_in_every_field() {
    let mut rng = ChaCha20Rng::seed_from_u64(44);
    let c = wallet::random_digest(&mut rng);
    let base = one_function(&mut rng, c);
    let public = both(&base).expect("the specified outputs are valid");
    assert_eq!(public.n_fn, 1);
    assert_eq!(public.functions[0].0, c);

    let other = wallet::random_digest(&mut rng);
    type Edit = fn(&mut Witness, &Digest);
    let cases: [(&str, Edit); 5] = [
        ("owner", |w, o| w.outputs[1].owner = *o),
        ("contract", |w, _| w.outputs[0].contract = [0; 8]),
        ("value", |w, _| {
            w.outputs[0].value -= 1;
            w.bridge_in -= 1;
        }),
        ("data", |w, _| w.outputs[0].data[3] ^= 1),
        ("payout value", |w, _| {
            w.outputs[1].value += 1;
            w.bridge_in += 1;
        }),
    ];
    for (name, edit) in cases {
        let mut w = base.clone();
        edit(&mut w, &other);
        assert_eq!(
            both(&w).err(),
            Some(Error::SpecMismatch),
            "{name} differs from the spec"
        );
        // Control: specify exactly the edited outputs, and it is accepted.
        let mut f = w.functions[0].expect("one function");
        for (j, o) in w.outputs.iter().enumerate() {
            f.spec[j] = Some(OutSpec {
                owner: o.owner,
                contract: o.contract,
                value: o.value,
                data: o.data,
            });
        }
        w.functions[0] = Some(f);
        both(&w).unwrap_or_else(|e| panic!("{name}: the edited witness is otherwise valid: {e:?}"));
    }
}

/// Two functions may not both specify one output (W4-MUT: the specifier
/// count `specs += 1` mutated to `-=` or `*=` survived). Natively and in the
/// guest; with the second function specifying nothing the transfer is valid.
#[test]
fn two_functions_may_not_specify_the_same_output() {
    let mut rng = ChaCha20Rng::seed_from_u64(45);
    let c = wallet::random_digest(&mut rng);
    let mut w = one_function(&mut rng, c);
    let first = w.functions[0].expect("one function");
    let second = FunctionWitness {
        contract: wallet::random_digest(&mut rng),
        blind: wallet::random_digest(&mut rng),
        approve: [false; 2],
        spec: [None, None],
    };
    w.n_fn = 2;
    w.functions[1] = Some(second);
    assert_eq!(both(&w).expect("a second, idle function").n_fn, 2);
    // The payout (output 1, a user record) specified by both functions.
    w.functions[1] = Some(FunctionWitness {
        spec: [None, first.spec[1]],
        ..second
    });
    assert_eq!(both(&w).err(), Some(Error::SpecConflict));
}

/// BabyBear addition reduces exactly at `p`: a sum equal to `p` is 0, never
/// the non-canonical `p` (boundary pass of run C: `s >= P` → `s > P` passed
/// every px-core oracle, since no test added two elements summing to `p`).
#[test]
fn field_addition_reduces_a_sum_of_exactly_p_to_zero() {
    use blacksilk_px_core::{add, canonical};
    assert_eq!(add(1, P - 1), 0);
    assert_eq!(add(P - 1, 1), 0);
    assert_eq!(add(P / 2, P - P / 2), 0);
    assert_eq!(add(P - 1, P - 1), P - 2);
    assert_eq!(add(2, P - 1), 1);
    assert_eq!(add(0, P - 1), P - 1);
    assert_eq!(add(0, 0), 0);
    for (a, b) in [(1, P - 1), (P - 1, P - 1), (12_345, P - 12_345)] {
        assert!(canonical(add(a, b)), "{a} + {b}");
    }
}
