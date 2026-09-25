//! End to end: a private transfer is proven with the kernel program, the proof
//! verifies for exactly its public statement and transaction hash, and the
//! state accepts it once (docs/px.md §9).

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{kernel_program, prove_transfer, verify_transfer, TransferError};
use blacksilk_px::state::{State, StateError};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::kernel::Error;
use blacksilk_px_core::record::Record;
use rand_chacha::rand_core::SeedableRng;
use std::time::Instant;

/// The pinned kernel program id (hex). Changing the kernel changes the
/// consensus statement: update this only together with a version bump.
const KERNEL_ID: &str = blacksilk_px::prove::KERNEL_PROGRAM_ID;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn the_kernel_program_id_is_pinned() {
    assert_eq!(hex(&kernel_program().id()), KERNEL_ID.trim());
}

#[test]
fn a_private_transfer_proves_verifies_and_applies_once() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[7; 32]);
    let bob = Account::from_seed(&[8; 32]);

    // Alice bridges 1000 in (a transfer with dummy inputs).
    let mut state = State::new();
    let mut tree = Tree::new(&mut perm);
    let outs = [
        wallet::output(&mut rng, alice.owner(0), 600),
        wallet::output(&mut rng, alice.owner(1), 400),
    ];
    let w0 = wallet::witness(
        state.root(),
        1000,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        outs.clone(),
    );
    let t = Instant::now();
    let (p0, proof0) = prove_transfer(&w0, [1; 32], &mut rng).expect("proves");
    let prove_time = t.elapsed();
    let bytes = blacksilk_zk::encode_proof(&proof0);
    // The encoding round-trips under the strict decoder and its size cap.
    assert!(bytes.len() <= blacksilk_zk::params::MAX_PROOF_BYTES);
    let decoded = blacksilk_zk::decode_proof(&bytes).expect("decodes");
    assert_eq!(blacksilk_zk::encode_proof(&decoded), bytes);
    let t = Instant::now();
    assert_eq!(verify_transfer(&p0, [1; 32], &proof0), Ok(()));
    let verify_time = t.elapsed();
    println!(
        "transfer proof: {} bytes, prove {:.1?}, verify {:.1?}",
        bytes.len(),
        prove_time,
        verify_time
    );
    state.apply_block(&[p0]).unwrap();
    let recs: Vec<Record> = (0..2)
        .map(|j| wallet::created_record(&p0, j, &outs[j]))
        .collect();
    let mut positions = Vec::new();
    for (j, r) in recs.iter().enumerate() {
        let cm = r.commit(&mut perm);
        assert_eq!(cm, p0.commitments[j]);
        positions.push(tree.append(&mut perm, cm).unwrap());
    }
    assert_eq!(tree.root(), state.root());
    assert_eq!(state.pool(), 1000);

    // Alice pays Bob 700 privately, keeping 300.
    let inputs = [
        alice.spend(0, &recs[0], positions[0], tree.path(positions[0]).unwrap()),
        alice.spend(1, &recs[1], positions[1], tree.path(positions[1]).unwrap()),
    ];
    let outs = [
        wallet::output(&mut rng, bob.owner(0), 700),
        wallet::output(&mut rng, alice.owner(2), 300),
    ];
    let w1 = wallet::witness(state.root(), 0, 0, inputs, outs);
    let h_tx = [2; 32];
    let (p1, proof1) = prove_transfer(&w1, h_tx, &mut rng).expect("proves");
    assert_eq!(verify_transfer(&p1, h_tx, &proof1), Ok(()));
    // Deposit (dummy inputs, bridge-in) and payment (real inputs) have the
    // same fixed shape: the proof does not reveal which kind it is.
    assert_eq!(proof0.degree_bits, proof1.degree_bits);
    // Byte length (privacy review P-5): every part of the proof has the same
    // encoded length for both witnesses, except the pruned Merkle paths,
    // whose size depends only on where the (public) query positions fall.
    // A Plonky3 change that makes any other part variable fails here.
    let (fixed0, paths0) = length_parts(&proof0);
    let (fixed1, paths1) = length_parts(&proof1);
    assert_eq!(fixed0, fixed1, "witness-independent parts");
    println!(
        "pruned paths: {paths0} and {paths1} bytes; everything else {} bytes",
        fixed0.iter().sum::<usize>()
    );

    // The proof is bound to every public field and to the transaction.
    let mut bad = Vec::new();
    for k in 0..8 {
        let mut p = p1;
        match k {
            0 => p.anchor[0] ^= 1,
            1 => p.nullifiers[0][3] ^= 1,
            2 => p.nullifiers[1][7] ^= 1,
            3 => p.commitments[0][0] ^= 1,
            4 => p.commitments[1][5] ^= 1,
            5 => p.bridge_in = 1,
            6 => p.bridge_out = 1,
            _ => p.nullifiers.swap(0, 1),
        }
        bad.push(verify_transfer(&p, h_tx, &proof1).is_err());
    }
    bad.push(verify_transfer(&p1, [3; 32], &proof1).is_err());
    bad.push(verify_transfer(&p0, [1; 32], &proof1).is_err());
    assert!(bad.iter().all(|x| *x), "{bad:?}");

    // The state accepts the transfer once.
    state.apply_block(&[p1]).unwrap();
    assert_eq!(
        state.apply_block(&[p1]).err(),
        Some(StateError::DoubleSpend(p1.nullifiers[0]))
    );
    assert_eq!(state.pool(), 1000);
}

fn size<T: serde::Serialize + ?Sized>(x: &T) -> usize {
    postcard::to_allocvec(x).unwrap().len()
}

/// The encoded sizes of every part of a proof except its Merkle
/// authentication data (in a fixed order), and the total size of that data:
/// the pruned paths of the input openings and the FRI layers' openings.
fn length_parts(proof: &blacksilk_zk::Proof) -> (Vec<usize>, usize) {
    let (random, fri) = &proof.opening_proof;
    let mut fixed = vec![
        size(&proof.commitments),
        size(&proof.opened_values),
        size(&proof.degree_bits),
        size(random),
        size(&fri.commit_phase_commits),
        size(&fri.commit_pow_witnesses),
        size(&fri.final_poly),
        size(&fri.query_pow_witness),
    ];
    let mut paths = 0;
    for batch in &fri.input_openings {
        let (salts, pruned) = &batch.opening_proof;
        fixed.push(size(&batch.opened_values));
        fixed.push(size(salts));
        paths += size(pruned);
    }
    for step in &fri.commit_phase_openings {
        fixed.push(size(&step.log_arity));
        fixed.push(size(&step.sibling_values));
        paths += size(&step.opening_proof);
    }
    // Everything not listed (version byte, envelope, any other field) must be
    // witness-independent too.
    let total = blacksilk_zk::encode_proof(proof).len();
    let rest = total - fixed.iter().sum::<usize>() - paths;
    fixed.push(rest);
    (fixed, paths)
}

#[test]
fn an_invalid_witness_is_refused_before_proving() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12);
    let alice = Account::from_seed(&[7; 32]);
    let w = wallet::witness(
        State::new().root(),
        10,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, alice.owner(0), 11),
            wallet::empty_output(&mut rng),
        ],
    );
    assert!(matches!(
        prove_transfer(&w, [0; 32], &mut rng),
        Err(TransferError::Rejected(Error::Unbalanced))
    ));
}
