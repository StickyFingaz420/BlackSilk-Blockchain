//! Mempool expiry and the recently-expired guard through the chain manager
//! (policy; docs/blocks.md §7; dossiers 12 P3 and 38 §3.4): a transaction
//! pooled for `MEMPOOL_EXPIRY_BLOCKS` leaves the pool, is refused as
//! `Expired` on the local origination paths for `RECENTLY_EXPIRED_BLOCKS`
//! while peers' relay and stem admit it (RTW1B-1), and is admitted again
//! afterwards. A reorganization returning it from a disconnected block pools
//! it again, with a fresh admission height, and clears its guard entry.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, Template};
use blacksilk_chain::mempool::{MempoolError, MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS};
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn open() -> ChainManager {
    let p = ChainParams::regtest();
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [7; 32],
    )
    .unwrap()
}

struct Miner {
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Miner {
    fn build(&mut self, t: &Template, txs: Vec<Transaction>, nonce: u64) -> Block {
        let fees: u64 = txs.iter().map(Transaction::fee).sum();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward + fees,
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let mut all = vec![Transaction::Coinbase(cb)];
        all.extend(txs);
        let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&all);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(ChainParams::regtest().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        Block { header, txs: all }
    }

    /// A block on `parent` with exactly `txs` (none from the pool); its id.
    fn mine_on(
        &mut self,
        m: &mut ChainManager,
        parent: Hash,
        txs: Vec<Transaction>,
        nonce: u64,
    ) -> Hash {
        let t = m.template_on(&parent).unwrap();
        let b = self.build(&t, txs, nonce);
        let now = b.header.timestamp;
        m.submit_block(b, now).expect("valid block").id
    }

    /// Coinbase-only blocks on the tip until the next height is `next`.
    fn mine_until_next(&mut self, m: &mut ChainManager, next: u64) {
        while m.height() + 1 < next {
            let tip = m.tip_id();
            self.mine_on(m, tip, vec![], 0);
        }
    }
}

/// A 1-input transfer from the miner's first mature coinbase.
fn transfer(m: &ChainManager, miner: &Miner, rng: &mut ChaCha20Rng) -> Transaction {
    let height = m.height() + 1;
    let table = SubaddressTable::new(miner.keys.view_keys(), 1, 5);
    let b = m.block_at(1).unwrap();
    let first = m.state().first_output_at(1).unwrap();
    let owned = scan_block(miner.keys.view_keys(), &table, &b.txs, 1, first)
        .owned
        .remove(0);
    assert!(height >= owned.height + COINBASE_MATURITY);
    let state = m.state();
    let ring = select_ring(
        rng,
        &state.cumulative_outputs(),
        height,
        120,
        owned.global_index,
        |i| {
            state.output(i).is_some_and(|r| {
                let age = if r.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                height >= r.height + age
            })
        },
    )
    .unwrap();
    let decoys = ring
        .iter()
        .filter(|&&i| i != owned.global_index)
        .map(|&i| Decoy {
            global_index: i,
            key: state.output(i).unwrap().key,
        })
        .collect();
    let (to, _) = WalletKeys::generate(rng);
    Transaction::from(
        build_transfer(
            &miner.keys,
            vec![InputPlan {
                real: SpendableOutput::from(&owned),
                decoys,
            }],
            &[Payment {
                address: to.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &miner.keys.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, m.rules()),
            m.rules(),
            rng,
        )
        .unwrap(),
    )
}

#[test]
fn a_pooled_transaction_expires_is_guarded_and_comes_back_after_a_reorganization() {
    let mut m = open();
    let mut rng = ChaCha20Rng::seed_from_u64(0xE1);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let mut miner = Miner {
        keys,
        rng: ChaCha20Rng::seed_from_u64(0xE2),
    };
    miner.mine_until_next(&mut m, 81);
    let tx = transfer(&m, &miner, &mut rng);
    let id = m.submit_tx(tx.clone()).unwrap();
    let admitted = m.height() + 1;
    assert_eq!(m.mempool().admitted_at(&id), Some(admitted));

    // Pooled until the next height reaches admission + expiry, exactly.
    let expiry = admitted + MEMPOOL_EXPIRY_BLOCKS;
    miner.mine_until_next(&mut m, expiry - 1);
    assert!(m.mempool().contains(&id), "one block before expiry");
    miner.mine_until_next(&mut m, expiry);
    assert!(!m.mempool().contains(&id), "expired at admission + 2160");
    assert!(m.mempool().is_empty());

    // The guard: refused on the local origination paths (`/tx` with and
    // without P2P) for RECENTLY_EXPIRED_BLOCKS blocks; a peer's relay or
    // stem is admitted (RTW1B-1: no Dandelion black hole).
    assert_eq!(m.submit_local_tx(tx.clone()), Err(MempoolError::Expired));
    assert_eq!(m.check_local_tx(&tx), Err(MempoolError::Expired));
    assert_eq!(m.check_tx(&tx), Ok(id), "RTW1B-1: the stem path admits it");
    miner.mine_until_next(&mut m, expiry + RECENTLY_EXPIRED_BLOCKS - 5);
    assert_eq!(m.submit_local_tx(tx.clone()), Err(MempoolError::Expired));
    assert_eq!(m.check_tx(&tx), Ok(id));
    assert!(m.mempool().is_empty(), "checks add nothing");

    // Reorganization: a block that still carries the transaction (mined by
    // a node that never expired it) connects, then a heavier branch from
    // its parent disconnects it. The returned transaction is pooled again
    // although this node expired it recently, admitted for the new next
    // height (a fresh expiry window).
    let parent = m.tip_id();
    let with_tx = miner.mine_on(&mut m, parent, vec![tx.clone()], 1);
    assert_eq!(m.tip_id(), with_tx);
    assert!(m.state().block_tx_hashes(m.height()).unwrap().contains(&id));
    let side = miner.mine_on(&mut m, parent, vec![], 2);
    assert_eq!(m.tip_id(), with_tx, "equal work: the first branch stays");
    let side_tip = miner.mine_on(&mut m, side, vec![], 3);
    assert_eq!(m.tip_id(), side_tip, "the heavier branch is connected");
    let next = m.height() + 1;
    assert!(
        next < expiry + RECENTLY_EXPIRED_BLOCKS,
        "inside the guard window"
    );
    assert!(m.mempool().contains(&id), "returned and readmitted");
    assert_eq!(m.mempool().admitted_at(&id), Some(next));
    assert!(
        !m.mempool().recently_expired(&id, next),
        "a successful readmission clears the guard entry"
    );
    assert!(!m.state().is_key_image_spent(&tx.key_images()[0]));

    // It is mined normally from the pool.
    let t = m.template();
    assert_eq!(t.txs.len(), 1);
    let b = miner.build(&t, t.txs.clone(), 0);
    let now = b.header.timestamp;
    m.submit_block(b, now).unwrap();
    assert!(m.mempool().is_empty());
}
