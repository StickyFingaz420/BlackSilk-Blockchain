//! The PX kernel: native and guest executions agree, every check rejects the
//! witnesses it must reject, and successful executions do constant work
//! (docs/px.md §9).

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, public_words, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::{self, Error, Public, SliceSource, Witness};
use blacksilk_px_core::record::{Keys, Record};
use blacksilk_px_core::{Digest, P};
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::{run, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct World {
    rng: ChaCha20Rng,
    tree: Tree,
    alice: Account,
    bob: Account,
    /// Alice's records in the tree: (address index, record, position).
    notes: Vec<(u32, Record, u64)>,
}

impl World {
    fn new(seed: u64) -> World {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut perm = HostPerm::new();
        let mut tree = Tree::new(&mut perm);
        let alice = Account::from_seed(&[1; 32]);
        let bob = Account::from_seed(&[2; 32]);
        let mut notes = Vec::new();
        // Other people's records around Alice's.
        for i in 0..20u32 {
            let filler = wallet::random_digest(&mut rng);
            tree.append(&mut perm, filler).unwrap();
            if i % 7 == 3 {
                let index = i;
                let rec = Record::plain(
                    alice.owner(index),
                    1_000 + i as u64,
                    [0; 8],
                    wallet::random_digest(&mut rng),
                    wallet::random_digest(&mut rng),
                );
                let cm = rec.commit(&mut perm);
                let pos = tree.append(&mut perm, cm).unwrap();
                notes.push((index, rec, pos));
            }
        }
        World {
            rng,
            tree,
            alice,
            bob,
            notes,
        }
    }

    fn input(&self, k: usize) -> kernel::InputWitness {
        let (index, rec, pos) = &self.notes[k];
        self.alice
            .spend(*index, rec, *pos, self.tree.path(*pos).unwrap())
    }

    fn value(&self, k: usize) -> u64 {
        self.notes[k].1.value
    }

    /// Alice spends notes 0 and 1: pays Bob 1500 and herself the change.
    fn transfer(&mut self) -> Witness {
        let total = self.value(0) + self.value(1);
        let inputs = [self.input(0), self.input(1)];
        let outputs = [
            wallet::output(&mut self.rng, self.bob.owner(0), 1500),
            wallet::output(&mut self.rng, self.alice.owner(9), total - 1500),
        ];
        wallet::witness(self.tree.root(), 0, 0, inputs, outputs)
    }
}

fn native(w: &Witness) -> Result<Public, Error> {
    let words = witness_words(w);
    kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words))
}

/// Runs the guest in the interpreter: (exit code, output).
fn guest(w: &Witness) -> (u32, Vec<u32>) {
    let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).expect("the kernel halts");
    (exec.exit_code, exec.output)
}

fn both(w: &Witness) -> Result<Public, Error> {
    let n = native(w);
    let (code, out) = guest(w);
    match &n {
        Ok(p) => {
            assert_eq!(code, 0);
            assert_eq!(out, public_words(p), "guest output differs from native");
        }
        Err(e) => {
            assert_eq!(code, e.exit_code(), "guest exit code differs for {e:?}");
            assert!(out.is_empty(), "a rejected witness must not write output");
        }
    }
    n
}

#[test]
fn a_real_transfer_is_accepted_natively_and_by_the_guest() {
    let mut world = World::new(1);
    let w = world.transfer();
    let public = both(&w).expect("valid transfer");
    assert_eq!(public.anchor, world.tree.root());
    assert_ne!(public.nullifiers[0], public.nullifiers[1]);
    // Recipients can recompute their records from the statement.
    let mut perm = HostPerm::new();
    for j in 0..2 {
        let rec = wallet::created_record(&public, j, &w.outputs[j]);
        assert_eq!(rec.commit(&mut perm), public.commitments[j]);
    }
    let bob_rec = wallet::created_record(&public, 0, &w.outputs[0]);
    assert_eq!(bob_rec.owner, world.bob.owner(0));
    assert_eq!(bob_rec.value, 1500);
    // Output rho values differ (no Faerie Gold within a transaction).
    assert_ne!(
        wallet::created_record(&public, 0, &w.outputs[0]).rho,
        wallet::created_record(&public, 1, &w.outputs[1]).rho
    );
}

#[test]
fn dummies_and_bridges_are_accepted() {
    let mut world = World::new(2);
    // Bridge 5000 in, no real inputs.
    let inputs = [
        wallet::dummy_input(&mut world.rng),
        wallet::dummy_input(&mut world.rng),
    ];
    let outputs = [
        wallet::output(&mut world.rng, world.bob.owner(1), 4000),
        wallet::output(&mut world.rng, world.bob.owner(2), 1000),
    ];
    let w = wallet::witness(world.tree.root(), 5000, 0, inputs, outputs);
    both(&w).unwrap();
    // One real input, one dummy, bridge the whole value out.
    let v = world.value(2);
    let inputs = [world.input(2), wallet::dummy_input(&mut world.rng)];
    let outputs = [
        wallet::empty_output(&mut world.rng),
        wallet::empty_output(&mut world.rng),
    ];
    let w = wallet::witness(world.tree.root(), 0, v, inputs, outputs);
    both(&w).unwrap();
}

/// Every kernel check, violated alone, rejects the witness: natively and in
/// the guest, with the same error.
#[test]
fn every_check_rejects_its_violation() {
    let mut world = World::new(3);
    let base = world.transfer();
    both(&base).unwrap();
    let mut cases: Vec<(&str, Witness, Error)> = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut Witness), e: Error| {
        let mut w = base.clone();
        f(&mut w);
        cases.push((name, w, e));
    };
    // Balance: one unit too many out, or too few.
    add("more out", &|w| w.outputs[0].value += 1, Error::Unbalanced);
    add("less out", &|w| w.outputs[1].value -= 1, Error::Unbalanced);
    add("bridge out", &|w| w.bridge_out = 1, Error::Unbalanced);
    add("bridge in", &|w| w.bridge_in = 1, Error::Unbalanced);
    // 64-bit wrap-around cannot balance: sums are exact.
    add(
        "wrap",
        &|w| {
            w.outputs[0].value = u64::MAX;
            w.outputs[1].value = w.inputs[0].value + w.inputs[1].value + 1;
        },
        Error::Unbalanced,
    );
    // Membership: the record must be in the tree under the anchor.
    add("value", &|w| w.inputs[0].value += 1, Error::NotInTree);
    add("rho", &|w| w.inputs[1].rho[3] ^= 1, Error::NotInTree);
    add("rcm", &|w| w.inputs[0].rcm[0] ^= 1, Error::NotInTree);
    add("data", &|w| w.inputs[0].data[7] = 1, Error::NotInTree);
    add("position", &|w| w.inputs[0].position ^= 1, Error::NotInTree);
    add("path", &|w| w.inputs[1].path[17][2] ^= 1, Error::NotInTree);
    add("anchor", &|w| w.anchor[0] ^= 1, Error::NotInTree);
    // Authorization: another key or address cannot spend the record.
    add("sk", &|w| w.inputs[0].sk[5] ^= 1, Error::NotInTree);
    add("diversifier", &|w| w.inputs[1].d[0] ^= 1, Error::NotInTree);
    // A dummy flag on a real record with value is refused.
    add(
        "dummy with value",
        &|w| w.inputs[0].dummy = true,
        Error::DummyWithValue,
    );
    // The same record twice (double spend inside one transfer).
    add(
        "duplicate",
        &|w| {
            w.inputs[1] = w.inputs[0].clone();
            w.outputs[1].value = w.inputs[0].value * 2 - 1500;
        },
        Error::DuplicateNullifier,
    );
    // Encoding.
    add(
        "non-canonical",
        &|w| w.inputs[0].rcm[4] = P,
        Error::NonCanonical,
    );
    add(
        "non-canonical out",
        &|w| w.outputs[1].owner[0] = u32::MAX,
        Error::NonCanonical,
    );
    let mut n = 0;
    for (name, w, e) in &cases {
        assert_eq!(both(w).err(), Some(*e), "case {name}");
        n += 1;
    }
    // Non-boolean dummy flag and wrong version need raw words.
    let words = witness_words(&base);
    let dummy_flag = 1 + 8 + 2 + 2 + 1; // after the function count
    for (idx, value, e) in [
        (dummy_flag, 2u32, Error::NotBoolean),
        (0, kernel::VERSION - 1, Error::Version),
    ] {
        let mut v = words.clone();
        v[idx] = value;
        let native = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&v));
        assert_eq!(native.err(), Some(e));
        let exec = run(&kernel_program(), &v, MAX_CYCLES).unwrap();
        assert_eq!(exec.exit_code, e.exit_code());
        n += 1;
    }
    // A truncated witness traps in the guest (no proof of exit 0).
    let short = &words[..words.len() - 1];
    assert!(kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(short)).is_err());
    assert!(run(&kernel_program(), short, MAX_CYCLES).is_err());
    println!("{n} rejection cases");
}

/// A record paid to Bob cannot be spent by Alice, even with the right
/// position and path.
#[test]
fn only_the_owner_can_spend() {
    let mut world = World::new(4);
    let mut perm = HostPerm::new();
    let rec = Record::plain(
        world.bob.owner(3),
        777,
        [0; 8],
        wallet::random_digest(&mut world.rng),
        wallet::random_digest(&mut world.rng),
    );
    let cm = rec.commit(&mut perm);
    let pos = world.tree.append(&mut perm, cm).unwrap();
    let path = world.tree.path(pos).unwrap();
    let inputs = |acct: &Account, rng: &mut ChaCha20Rng| {
        [acct.spend(3, &rec, pos, path), wallet::dummy_input(rng)]
    };
    let outputs = [
        wallet::output(&mut world.rng, world.alice.owner(0), 777),
        wallet::empty_output(&mut world.rng),
    ];
    let root = world.tree.root();
    let thief = wallet::witness(
        root,
        0,
        0,
        inputs(&world.alice, &mut world.rng),
        outputs.clone(),
    );
    assert_eq!(both(&thief).err(), Some(Error::NotInTree));
    let owner = wallet::witness(root, 0, 0, inputs(&world.bob, &mut world.rng), outputs);
    both(&owner).unwrap();
}

/// Nullifiers depend on the nullifier key: the same record spent under a
/// different key gives a different nullifier, and nullifiers of distinct
/// records differ.
#[test]
fn nullifiers_are_unique_and_key_dependent() {
    let mut world = World::new(5);
    let p1 = both(&world.transfer()).unwrap();
    let p2 = both(&world.transfer()).unwrap();
    // Same inputs, fresh outputs: the nullifiers are the same (a double spend
    // across transactions is detected by the state), commitments differ.
    assert_eq!(p1.nullifiers, p2.nullifiers);
    assert_ne!(p1.commitments, p2.commitments);
    let mut perm = HostPerm::new();
    let k1 = Keys::derive(&mut perm, &[1; 8]);
    let k2 = Keys::derive(&mut perm, &[2; 8]);
    let rho: Digest = [3; 8];
    let cm: Digest = [4; 8];
    use blacksilk_px_core::record::nullifier;
    assert_ne!(
        nullifier(&mut perm, &k1.nk, &rho, &cm),
        nullifier(&mut perm, &k2.nk, &rho, &cm)
    );
}

/// Trace heights (public in the proof) are the same for every successful
/// witness shape: dummies, positions, values, bridges.
#[test]
fn successful_executions_have_identical_trace_heights() {
    let mut world = World::new(6);
    let mut witnesses = vec![world.transfer()];
    let v = world.value(2);
    let i2 = world.input(2);
    let d = wallet::dummy_input(&mut world.rng);
    let o = [
        wallet::output(&mut world.rng, world.bob.owner(0), v),
        wallet::empty_output(&mut world.rng),
    ];
    witnesses.push(wallet::witness(
        world.tree.root(),
        0,
        0,
        [i2.clone(), d.clone()],
        o.clone(),
    ));
    witnesses.push(wallet::witness(
        world.tree.root(),
        0,
        0,
        [d.clone(), i2],
        o.clone(),
    ));
    let d2 = wallet::dummy_input(&mut world.rng);
    witnesses.push(wallet::witness(world.tree.root(), v, 0, [d, d2], o));
    let mut heights: Option<Vec<usize>> = None;
    let mut cycles = Vec::new();
    for w in &witnesses {
        let public = both(w).unwrap();
        let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).unwrap();
        cycles.push(exec.steps.len());
        let st = Statement {
            program: kernel_program(),
            exit_code: 0,
            output: public_words(&public),
            binding: [0; 32],
            others: Vec::new(),
            budget: None,
        };
        let h: Vec<usize> = trace::build(&st, &exec)
            .iter()
            .map(|t| t.values.len() / t.width)
            .collect();
        match &heights {
            None => heights = Some(h),
            Some(prev) => assert_eq!(prev, &h, "trace heights differ"),
        }
    }
    println!("kernel cycles per witness: {cycles:?}; heights {heights:?}");
}
