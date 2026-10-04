//! A deterministic regtest chain for the stateful fuzz targets
//! (`peer_protocol`, `px_admission`) and their stable twins, which include
//! this file by path next to their target body (as `crate::chain_fixture`).
//!
//! Proof of work is a constant zero hash (regtest difficulty), and every
//! random choice comes from seeded generators, so the same calls build the
//! same blocks, transactions and chain state byte for byte: the seed
//! generator (`src/seeds.rs`) and a fuzz target that rebuilds the chain
//! agree on it.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Decoy, InputPlan, Payment, SpendableOutput};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

/// Meets any difficulty.
pub struct ZeroPow;

impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

pub fn params() -> ChainParams {
    ChainParams::regtest()
}

/// A regtest chain at its genesis, in memory.
pub fn open() -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(
        p,
        rules,
        Arc::new(ZeroPow),
        Box::new(MemoryStore::default()),
        [7; 32],
    )
    .expect("a regtest chain opens")
}

/// Mines blocks paying a fixed wallet.
pub struct Miner {
    pub keys: WalletKeys,
    pub rng: ChaCha20Rng,
}

impl Miner {
    pub fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Self { keys, rng }
    }

    /// The next block on `m`'s tip, carrying the template's transactions.
    pub fn block(&mut self, m: &ChainManager) -> Block {
        let t = m.template();
        let fees: u64 = t.txs.iter().map(Transaction::fee).sum();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward + fees,
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .expect("a coinbase");
        let mut txs = vec![Transaction::Coinbase(cb)];
        txs.extend(t.txs.iter().cloned());
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        Block { header, txs }
    }

    /// Mines the next block on `m`.
    pub fn mine(&mut self, m: &mut ChainManager) -> Block {
        let b = self.block(m);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now).expect("a valid block");
        b
    }
}

/// The wallet's outputs on `m`'s connected chain.
fn owned(m: &ChainManager, keys: &WalletKeys) -> Vec<OwnedOutput> {
    let table = SubaddressTable::new(keys.view_keys(), 1, 5);
    let mut out = Vec::new();
    for h in 1..=m.height() {
        let b = m.block_at(h).expect("a connected block");
        let first = m.state().first_output_at(h).expect("its first output");
        out.extend(scan_block(keys.view_keys(), &table, &b.txs, h, first).owned);
    }
    out
}

/// A spend of the `nth` unspent, spendable output of `keys` on `m`, with a
/// ring from the chain's decoy selection.
pub fn plan_nth(
    m: &ChainManager,
    keys: &WalletKeys,
    nth: usize,
    rng: &mut ChaCha20Rng,
) -> InputPlan {
    let height = m.height() + 1;
    let age = |coinbase: bool| {
        if coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        }
    };
    let real = owned(m, keys)
        .into_iter()
        .filter(|o| {
            height >= o.height + age(o.coinbase)
                && !m.state().is_key_image_spent(&o.key_image(keys))
        })
        .nth(nth)
        .expect("a spendable output");
    let state = m.state();
    let ring = select_ring(
        rng,
        &state.cumulative_outputs(),
        height,
        120,
        real.global_index,
        |i| {
            state
                .output(i)
                .is_some_and(|r| height >= r.height + age(r.coinbase))
        },
    )
    .expect("a ring");
    InputPlan {
        real: SpendableOutput::from(&real),
        decoys: ring
            .iter()
            .filter(|&&i| i != real.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: state.output(i).expect("a ring member").key,
            })
            .collect(),
    }
}
