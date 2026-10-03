//! The PX half of the supply audit's chain scan (F40-9; mutation run F).
//!
//! The regtest test (`regtest.rs`) runs the audit end to end but has no PX
//! transaction (proving is too costly there), so `px_pool`, the bridge sums,
//! the PX fees and the "PX pool below zero" alarm were never computed on
//! anything but zero. Here `scan_chain` reads a hand-built chain from an
//! in-memory node: PX transactions are only decoded by the scan, never
//! verified, so they carry no proof. What this does not cover: the wallet
//! side of the PX half (records held and their deduplication, and
//! `px_difference` in `audit`), which needs proven PX transactions.

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::block_reward;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_rpc as rpc;
use blacksilk_supply_audit::scan_chain;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::px::{PxTx, Window};
use blacksilk_tx::types::Transaction;
use blacksilk_wallet::node::NodeApi;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// `blacksilk_px::delivery::CIPHERTEXT_BYTES` (not a dependency of this
/// crate): a PX transaction with another length does not decode, so a
/// change shows as a decode failure here.
const CIPHERTEXT_BYTES: usize = 32 + 1 + 1088 + 104 + 16;

/// A node that serves `blocks` (heights 1, 2, …) and nothing else.
struct Chain {
    blocks: Vec<Block>,
    network_id: u32,
}

impl NodeApi for Chain {
    fn info(&self) -> Result<rpc::Info, String> {
        Err("not served".into())
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        let blocks = (from..from + count)
            .filter_map(|h| {
                let b = self.blocks.get(usize::try_from(h).ok()?.checked_sub(1)?)?;
                Some(rpc::BlockEntry {
                    height: h,
                    id: hex::encode(b.id(self.network_id)),
                    first_output: 0,
                    hex: hex::encode(b.encode()),
                })
            })
            .collect();
        Ok(rpc::Blocks { blocks })
    }
    fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
        Err("not served".into())
    }
    fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
        Err("not served".into())
    }
    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        Err("not served".into())
    }
    fn px_commitments(&self, _: u64) -> Result<rpc::PxCommitments, String> {
        Err("not served".into())
    }
    fn px_contracts(&self, _: u64) -> Result<rpc::PxContracts, String> {
        Err("not served".into())
    }
}

/// A PX transaction without inputs, outputs or functions: only its fee
/// and bridge amounts matter to the scan.
fn px(fee: u64, bridge_in: u64, bridge_out: u64) -> Transaction {
    Transaction::Px(Box::new(PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in,
        bridge_out,
        window: Window::UNBOUNDED,
        anchor: [0; 8],
        nullifiers: [[1; 8], [2; 8]],
        commitments: [[3; 8], [4; 8]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }))
}

/// Builds blocks 1.. on genesis; block `i` holds `pxs[i]` and a coinbase
/// paying its reward plus its fees plus `overpay[i]`.
fn chain(p: &ChainParams, pxs: Vec<Vec<Transaction>>, overpay: &[u64]) -> Vec<Block> {
    let mut rng = ChaCha20Rng::seed_from_u64(40_9);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let mut prev = p.genesis_id();
    let mut generated = 0;
    let mut out = Vec::new();
    for (i, txs) in pxs.into_iter().enumerate() {
        let height = i as u64 + 1;
        let reward = block_reward(height, generated);
        generated += reward;
        let fees: u64 = txs
            .iter()
            .map(|t| match t {
                Transaction::Px(t) => t.fee,
                _ => 0,
            })
            .sum();
        let cb = build_coinbase(
            height,
            &[Payment {
                address: keys.address(SubaddressIndex::PRIMARY),
                amount: reward + fees + overpay[i],
            }],
            &keys.hedge_secret(),
            &mut rng,
        )
        .unwrap();
        let mut all = vec![Transaction::Coinbase(cb)];
        all.extend(txs);
        let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
        let b = Block {
            header: BlockHeader {
                version: HEADER_VERSION,
                height,
                prev_id: prev,
                timestamp: 1_700_000_000 + height * 120,
                difficulty: 1,
                tx_root: tx_root(&ids),
                nonce: 0,
            },
            txs: all,
        };
        prev = b.id(p.network_id);
        out.push(b);
    }
    out
}

/// Bridges into and out of the pool, PX fees, and a pool that would go below
/// zero: the sums, the pool after each block (in block order, clamped at 0
/// with an alarm) and the coinbase check with PX fees.
#[test]
fn the_scan_sums_the_px_half_of_the_chain() {
    let p = ChainParams::regtest();
    let blocks = chain(
        &p,
        vec![
            vec![],
            vec![px(5, 1_000, 0), px(7, 300, 100)],
            vec![px(3, 0, 1_150)],
            vec![px(11, 40, 100)],
            vec![px(2, 60, 0)],
        ],
        &[0; 5],
    );
    let tip = blocks[4].id(p.network_id);
    let node = Chain {
        blocks,
        network_id: p.network_id,
    };
    let (c, failures) = scan_chain(&node, p.network_id, p.genesis_id(), 5, &tip).unwrap();
    assert_eq!(c.blocks, 5);
    assert_eq!((c.px_txs, c.transfers, c.px_deploys), (5, 0, 0));
    assert_eq!(c.fees, 5 + 7 + 3 + 11 + 2);
    assert_eq!(c.bridge_in, 1_000 + 300 + 40 + 60);
    assert_eq!(c.bridge_out, 100 + 1_150 + 100);
    // 0 → 1 200 → 50 → 0 (40 in, 100 out: below zero, clamped) → 60.
    assert_eq!(c.px_pool, 60);
    assert_eq!(failures, vec!["PX pool below zero in block 4".to_string()]);
    let generated: u64 = {
        let mut g = 0;
        for h in 1..=5 {
            g += block_reward(h, g);
        }
        g
    };
    assert_eq!(c.generated, generated);
    assert_eq!(c.coinbase_paid, u128::from(generated) + c.fees);
}

/// The pool is exact at zero: bridging out everything that came in is no
/// alarm, and a coinbase that pays one atomic unit more than its reward and
/// PX fees is reported for its block.
#[test]
fn the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported() {
    let p = ChainParams::regtest();
    let blocks = chain(
        &p,
        vec![vec![px(1, 500, 0)], vec![px(1, 0, 500)], vec![px(4, 0, 0)]],
        &[0, 0, 1],
    );
    let tip = blocks[2].id(p.network_id);
    let node = Chain {
        blocks,
        network_id: p.network_id,
    };
    let (c, failures) = scan_chain(&node, p.network_id, p.genesis_id(), 3, &tip).unwrap();
    assert_eq!(c.px_pool, 0);
    assert_eq!((c.bridge_in, c.bridge_out), (500, 500));
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].starts_with("block 3: coinbase pays"),
        "{failures:?}"
    );
}
