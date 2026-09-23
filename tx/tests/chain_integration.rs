//! Transactions on top of the header chain: block bodies committed by `tx_root`,
//! validated against `HeaderChain` decisions, including a reorganization that
//! returns a transaction to the mempool.

mod common;

use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, HeaderChain, PowFunction, HEADER_VERSION};
use blacksilk_tx::types::{Hash, Transaction};
use blacksilk_tx::validate::{
    validate_block_transactions, validate_transfer, BlockContext, BlockError,
};
use blacksilk_tx::ChainView;
use common::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Every hash is zero, so every header meets any difficulty. The RandomX path is
/// covered by the consensus crate's end-to-end tests.
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// A node: header chain plus transaction state (`net.chain`).
struct Node {
    headers: HeaderChain,
    bodies: HashMap<Hash, Vec<Transaction>>,
    net: TestNet,
}

impl Node {
    fn new(seed: u64) -> Self {
        let params = ChainParams::regtest();
        let mut net = TestNet::new(seed, 0);
        // Genesis: provisional, no transactions (consensus.md §1, tx_root = 0).
        net.chain.apply_block(&[]);
        Self {
            headers: HeaderChain::new(params, Arc::new(ZeroPow)),
            bodies: HashMap::new(),
            net,
        }
    }

    /// Mines a block with `transfers` on `parent` and feeds it through the header
    /// chain; applies any resulting reorganization to the transaction state.
    fn mine_on(
        &mut self,
        parent: Hash,
        transfers: Vec<blacksilk_tx::Transfer>,
        nonce: u64,
    ) -> Result<Hash, BlockError> {
        let t = self.headers.template_on(parent).expect("known parent");
        let fees: u64 = transfers.iter().map(|t| t.fee).sum();
        // The coinbase must carry the height of the block being built.
        let cb = blacksilk_tx::builder::build_coinbase(
            t.height,
            &[blacksilk_tx::builder::Payment {
                address: self.net.miner.primary(),
                amount: REWARD + fees,
            }],
            &self.net.miner.keys.hedge_secret(),
            &mut self.net.rng,
        )
        .unwrap();
        let mut txs = vec![Transaction::Coinbase(cb)];
        txs.extend(transfers.into_iter().map(Transaction::from));
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(self.headers.params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
        };
        let now = header.timestamp;
        let accepted = self.headers.accept(header, now).expect("valid header");
        self.bodies.insert(accepted.id, txs);
        if let Some(reorg) = accepted.reorg {
            for _ in &reorg.disconnected {
                assert!(self.net.chain.undo_block());
            }
            for id in &reorg.connected {
                let body = self.bodies[id].clone();
                let h = self.headers.header(id).unwrap();
                let ctx = BlockContext {
                    height: h.height,
                    reward: REWARD,
                    tx_root: h.tx_root,
                };
                validate_block_transactions(
                    &body,
                    &ctx,
                    &self.net.chain,
                    &self.net.rules,
                    &mut self.net.rng,
                )?;
                let first = self.net.chain.apply_block(&body);
                let height = h.height;
                self.net.miner.observe(&body, height, first);
            }
        }
        Ok(accepted.id)
    }

    fn mine(&mut self, transfers: Vec<blacksilk_tx::Transfer>) -> Hash {
        let tip = self.headers.tip_id();
        self.mine_on(tip, transfers, 0).unwrap()
    }
}

#[test]
fn transactions_follow_the_best_chain_through_a_reorg() {
    let mut node = Node::new(40);
    for _ in 0..90 {
        node.mine(vec![]);
    }
    assert_eq!(node.net.chain.next_height(), node.headers.height() + 1);

    // A payment is mined on branch A.
    let alice = Wallet::new(&mut rng(41));
    let tx = node
        .net
        .pay(&node.net.miner_clone(), &[(alice.primary(), 777)]);
    let fork_parent = node.headers.tip_id();
    let a1 = node.mine(vec![tx.clone()]);
    assert!(node.net.chain.is_key_image_spent(&tx.inputs[0].key_image));

    // Branch B (without the payment) overtakes A: two blocks on the same parent.
    let b1 = node.mine_on(fork_parent, vec![], 1).unwrap();
    assert!(node.headers.is_on_main(&a1), "equal work: first seen stays");
    let _b2 = node.mine_on(b1, vec![], 1).unwrap();
    assert!(!node.headers.is_on_main(&a1));
    assert!(
        !node.net.chain.is_key_image_spent(&tx.inputs[0].key_image),
        "payment undone"
    );
    assert!(!node.net.chain.has_one_time_key(&tx.outputs[0].one_time_key));

    // The payment is valid again on the new best chain and can be re-mined.
    let h = node.net.chain.next_height();
    assert_eq!(
        validate_transfer(&tx, &node.net.chain, h, &node.net.rules),
        Ok(())
    );
    node.mine(vec![tx.clone()]);
    assert!(node.net.chain.is_key_image_spent(&tx.inputs[0].key_image));
    assert_eq!(node.net.chain.next_height(), node.headers.height() + 1);
}

#[test]
fn header_commits_to_the_body() {
    let mut node = Node::new(42);
    let id = node.mine(vec![]);
    let header = *node.headers.header(&id).unwrap();
    let body = node.bodies[&id].clone();
    let good = BlockContext {
        height: header.height,
        reward: REWARD,
        tx_root: header.tx_root,
    };
    // Re-validating against the parent state succeeds...
    node.net.chain.undo_block();
    assert_eq!(
        validate_block_transactions(&body, &good, &node.net.chain, &node.net.rules, &mut rng(0)),
        Ok(())
    );
    // ...and a body swapped under the same header does not.
    let mut other = body.clone();
    if let Transaction::Coinbase(c) = &mut other[0] {
        c.outputs[0].enc_anchor[0] ^= 1;
    }
    assert_eq!(
        validate_block_transactions(&other, &good, &node.net.chain, &node.net.rules, &mut rng(0)),
        Err(BlockError::TxRootMismatch)
    );
}
