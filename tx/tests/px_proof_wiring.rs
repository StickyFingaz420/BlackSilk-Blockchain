//! PX5's first two steps without proving (mutation run D): the strict,
//! bounded proof decoding under `blacksilk_px::prove::PROOF_LIMITS`
//! (`decode_px_proof`, RT-FUZZ-1) and the shape check on the decoded degree
//! bits (`check_px_proof_shape`, `check_px_proof_shape_bits`, RT-PXDOS F1).
//! A hollow proof (empty instances, chosen degree bits) decodes and reaches
//! the shape check, but verifies nothing. Real proofs go through the same
//! steps in `px_consensus.rs`.

mod common;

use blacksilk_px::prove::{kernel_budget, kernel_program, public_words, PROOF_LIMITS};
use blacksilk_px::state::State as PxState;
use blacksilk_tx::params::PX_STANDARD_FEE;
use blacksilk_tx::px::PxTx;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::validate::{
    check_px_proof, check_px_proof_shape, check_px_proof_shape_bits, decode_px_proof, TxError,
};
use blacksilk_zkvm::air::trace::Statement;
use common::*;

/// A chain with a PX pool and three blocks.
fn chain(seed: u64) -> TestNet {
    let mut net = TestNet::new(seed, 0);
    net.chain =
        MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(4, [7; 8], 1 << 60));
    for _ in 0..3 {
        net.mine(vec![], &mut []).unwrap();
    }
    net
}

/// A PX transfer (no functions) without v1 inputs, carrying `proof`.
fn px(net: &TestNet, proof: Vec<u8>) -> PxTx {
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        window: Default::default(),
        anchor: net.chain.px().root(),
        nullifiers: [[1; 8], [2; 8]],
        commitments: [[3; 8], [4; 8]],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof,
    }
}

/// The degree bits of `tx`'s statement (a transfer: the kernel alone), as
/// `blacksilk_px::prove` derives them.
fn degree_bits(tx: &PxTx, net: &TestNet) -> Vec<usize> {
    let mut st = Statement::single(
        kernel_program(),
        0,
        public_words(&tx.public()),
        tx.binding(net.rules.domain()),
    );
    st.budget = Some(kernel_budget(0));
    st.shape()
        .expect("a fixed shape")
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect()
}

/// The encoding of a proof with one empty instance per entry of `bits`
/// (no openings, no FRI rounds) and those degree bits: it decodes, but
/// verifies nothing.
fn hollow_proof(bits: &[usize]) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    let mut b = vec![blacksilk_zk::PROOF_VERSION];
    b.push(1); // the main commitment: one root
    b.extend([0; 32]);
    b.push(0); // no permutation commitment
    b.push(1); // the quotient commitment
    b.extend([0; 32]);
    b.push(0); // no random commitment
    varint(&mut b, bits.len() as u64);
    for _ in bits {
        b.extend([0; 8]); // an instance with nothing opened
    }
    b.extend([2, 0, 0]); // the hidden openings: two rounds, no matrices
    b.extend([0; 5]); // FRI: commitments, witnesses, input batches, openings, final polynomial
    b.extend([0; 4]); // the query grinding witness
    b.push(0); // no lookup terminals
    varint(&mut b, bits.len() as u64);
    for &x in bits {
        varint(&mut b, x as u64);
    }
    b
}

#[test]
fn a_decodable_proof_reaches_the_shape_check_and_only_its_degree_bits_matter() {
    let net = chain(1);
    let rules = net.rules;
    let bits = degree_bits(&px(&net, vec![]), &net);
    println!("a transfer's degree bits: {bits:?}");
    assert!(bits.len() > 1);

    // The statement's shape: decoded, and the shape check passes, from the
    // proof and from its degree bits alone.
    let tx = px(&net, hollow_proof(&bits));
    let proof = decode_px_proof(&tx).expect("a hollow proof decodes");
    assert_eq!(proof.degree_bits, bits);
    assert_eq!(
        check_px_proof_shape(&tx, &net.chain, &rules, &proof),
        Ok(())
    );
    assert_eq!(
        check_px_proof_shape_bits(&tx, &net.chain, &rules, &bits),
        Ok(())
    );
    // It verifies nothing: the full check refuses it (without a panic).
    assert_eq!(
        check_px_proof(&tx, &net.chain, &rules),
        Err(TxError::PxProof)
    );

    // Any other shape is the stateless `PxProof`, from the decoded proof or
    // its degree bits: a table more or fewer, or one table's height.
    let mut more = bits.clone();
    more.push(bits[0]);
    let mut higher = bits.clone();
    higher[0] += 1;
    for other in [bits[1..].to_vec(), more, higher, vec![]] {
        let tx = px(&net, hollow_proof(&other));
        let proof = decode_px_proof(&tx).expect("decodes");
        assert_eq!(
            check_px_proof_shape(&tx, &net.chain, &rules, &proof),
            Err(TxError::PxProof),
            "{other:?}"
        );
        assert_eq!(
            check_px_proof_shape_bits(&tx, &net.chain, &rules, &other),
            Err(TxError::PxProof),
            "{other:?}"
        );
        assert_eq!(
            check_px_proof(&tx, &net.chain, &rules),
            Err(TxError::PxProof)
        );
    }
}

#[test]
fn px_proofs_decode_under_the_px_limits_not_the_envelope() {
    let net = chain(2);
    // At the PX limit (the widest PX statement's tables), and one table over
    // it: the latter is within the envelope of every BVM-1 statement, but no
    // PX statement has that many tables.
    let at = hollow_proof(&[10; PROOF_LIMITS.max_instances]);
    let over = hollow_proof(&[10; PROOF_LIMITS.max_instances + 1]);
    assert!(decode_px_proof(&px(&net, at)).is_ok());
    assert!(blacksilk_zk::decode_proof(&over).is_ok());
    assert_eq!(
        decode_px_proof(&px(&net, over)).map(|_| ()),
        Err(TxError::PxProof)
    );
    // Bytes that do not decode.
    for junk in [vec![], vec![1, 2, 3], vec![0xA5; 4096]] {
        assert_eq!(
            decode_px_proof(&px(&net, junk.clone())).map(|_| ()),
            Err(TxError::PxProof),
            "{junk:?}"
        );
    }
}
