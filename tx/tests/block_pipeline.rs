//! Block-validation cost order (dossier 10 item 1, F10-2; decisions "Agent
//! 10"). Policy: verdicts are identical in any order, only which error is
//! reported and how much work precedes it change.
//!
//! A PX transaction's proof is decoded and shape-checked before any CLSAG of
//! the block is verified, so a block of PX transactions with valid ring
//! signatures and malformed proofs (empty, truncated, garbage) is rejected
//! with zero CLSAG verifications.
//!
//! **How CLSAG verifications are counted.** Through the chain view: a CLSAG
//! is verified only over a ring resolved with `ChainView::output` (one call
//! per ring member, `resolve_input_rings`), so a view counting `output` calls
//! bounds the CLSAG work from above. Zero `output` calls means zero CLSAG
//! verifications. No test hook in the library is needed.

mod common;

use blacksilk_crypto::clsag::{self, RingMember};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::{Point, Scalar};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_px_core::Digest;
use blacksilk_tx::builder::Decoy;
use blacksilk_tx::params::{PX_STANDARD_FEE, RING_SIZE};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::scan::OwnedOutput;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::{Input, Transaction};
use blacksilk_tx::validate::{
    validate_block_transactions_cached, validate_px_without_proof, BlockError, ChainView,
    OutputRecord, TxError,
};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use common::*;
use std::cell::Cell;
use std::sync::Arc;

/// The chain as seen at the parent, with the PX side open (every anchor is
/// recent, the pool is large) and every ring-member lookup counted.
struct Counting<'a> {
    inner: &'a MemoryChain,
    ring_lookups: Cell<usize>,
}

impl<'a> Counting<'a> {
    fn new(inner: &'a MemoryChain) -> Self {
        Self {
            inner,
            ring_lookups: Cell::new(0),
        }
    }
}

impl ChainView for Counting<'_> {
    fn output(&self, i: u64) -> Option<OutputRecord> {
        self.ring_lookups.set(self.ring_lookups.get() + 1);
        self.inner.output(i)
    }
    fn is_key_image_spent(&self, k: &Point) -> bool {
        self.inner.is_key_image_spent(k)
    }
    fn px_is_recent_root(&self, _: &Digest) -> bool {
        true
    }
    fn px_nullifier_spent(&self, nf: &Digest) -> bool {
        self.inner.px_nullifier_spent(nf)
    }
    fn px_pool(&self) -> u128 {
        u64::MAX as u128
    }
    fn px_function(&self, c: &Digest, id: &[u8; 32]) -> Option<(Arc<Program>, Budget)> {
        self.inner.px_function(c, id)
    }
    fn px_contract_exists(&self, c: &Digest) -> bool {
        self.inner.px_contract_exists(c)
    }
    fn px_tree_size(&self) -> u64 {
        self.inner.px_tree_size()
    }
}

/// A PX transaction spending the miner's output `real` into the PX pool
/// (`bridge_in`), with a valid CLSAG over its signature message and `proof`
/// as its proof bytes. Nullifiers are made unique by `seed`.
fn px_spend(net: &mut TestNet, real: &OwnedOutput, seed: u32, proof: Vec<u8>) -> PxTx {
    let miner = net.miner_clone();
    let plan = net.plan(real);
    let real = &plan.real;
    let p = miner
        .keys
        .one_time_secret(real.subaddress, &real.output_key_offset);
    let key_image = clsag::key_image(&p, &real.key.one_time_key);
    // No hidden outputs: the pseudo-output is `amount·H` and the whole
    // amount, less the fee, enters the pool.
    let pseudo_out = Point::from_point(commit(real.amount, &Scalar::ZERO));
    let mut members = plan.decoys.clone();
    members.push(Decoy {
        global_index: real.global_index,
        key: real.key,
    });
    members.sort_by_key(|d| d.global_index);
    let pos = members
        .iter()
        .position(|d| d.global_index == real.global_index)
        .unwrap();
    let ring: [RingMember; RING_SIZE] = std::array::from_fn(|j| RingMember {
        one_time_key: members[j].key.one_time_key,
        commitment: members[j].key.commitment,
    });
    let mut tx = PxTx {
        inputs: vec![Input {
            key_image,
            ring: std::array::from_fn(|j| members[j].global_index),
        }],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: real.amount - PX_STANDARD_FEE,
        bridge_out: 0,
        anchor: [7; 8],
        nullifiers: [[seed; 8], [seed + 1_000_000; 8]],
        commitments: [[seed + 2; 8], [seed + 3; 8]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![pseudo_out],
        range_proof: None,
        signatures: vec![],
        proof,
    };
    let message = tx.signature_message(net.rules.domain());
    let (sig, _) = clsag::sign(
        &message,
        &ring,
        &pseudo_out,
        pos,
        &p,
        &real.mask,
        &mut net.rng,
    )
    .unwrap();
    tx.signatures.push(sig);
    tx
}

/// F10-2: a block of PX transactions whose ring signatures are all valid and
/// whose proofs are malformed is rejected with the stateless `PxProof` of
/// the first one, after zero ring lookups (hence zero CLSAG verifications).
#[test]
fn malformed_px_proofs_are_rejected_before_any_clsag() {
    let mut net = TestNet::new(31, 90);
    let garbage: Vec<Vec<u8>> = vec![
        vec![],                                           // empty
        vec![blacksilk_zk::PROOF_VERSION],                // version only
        vec![blacksilk_zk::PROOF_VERSION, 0xFF, 0xFF, 1], // truncated body
        vec![0xA5; 4096],                                 // garbage
    ];
    for (case, proof) in garbage.into_iter().enumerate() {
        let height = net.height();
        let owned: Vec<OwnedOutput> = net
            .miner
            .spendable(height)
            .into_iter()
            .take(3)
            .cloned()
            .collect();
        let pxs: Vec<PxTx> = owned
            .iter()
            .enumerate()
            .map(|(i, o)| px_spend(&mut net, o, 100 * case as u32 + i as u32 + 1, proof.clone()))
            .collect();
        // Every transaction is valid but for its proof: its CLSAG verifies.
        for px in &pxs {
            let view = Counting::new(&net.chain);
            assert_eq!(
                validate_px_without_proof(px, &view, height, &net.rules),
                Ok(()),
                "case {case}"
            );
            assert_eq!(view.ring_lookups.get(), RING_SIZE);
        }
        let fees = PX_STANDARD_FEE * pxs.len() as u64;
        let mut txs = vec![net.coinbase(fees)];
        txs.extend(pxs.into_iter().map(|t| Transaction::Px(Box::new(t))));
        let ctx = net.context(&txs);
        let view = Counting::new(&net.chain);
        let got =
            validate_block_transactions_cached(&txs, &ctx, &view, &net.rules, &mut rng(3), &|_| {
                false
            });
        assert_eq!(
            got,
            Err(BlockError::Tx {
                index: 1,
                error: TxError::PxProof
            }),
            "case {case}"
        );
        assert_eq!(
            view.ring_lookups.get(),
            0,
            "case {case}: no ring resolved, no CLSAG verified"
        );
    }
}
