//! A regtest no-op activation end to end at the chain-manager level
//! (docs/consensus.md §11; docs/reviews/v3-upgrade-mechanism.md §2.4–§2.5).
//!
//! The schedule here is test-only: two epochs identical except the branch id,
//! the second active from [`ACTIVATION`]. It exercises what the built-in
//! one-epoch schedules never do:
//! - blocks are validated with the rules of their own height;
//! - the pool admits under the next block's rules and is flushed when the tip
//!   crosses the activation (in either direction);
//! - old-branch transactions are refused after the activation, in the pool
//!   and in blocks; new-branch ones are refused before it and accepted after;
//! - templates carry the epoch's header version and only transactions of the
//!   next block's rule set.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template};
use blacksilk_chain::mempool::MempoolError;
use blacksilk_chain::store::{BlockStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::schedule::{Epoch, Schedule, BRANCH_ID_V3, VERIFIER_PX_1};
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{BlockError, ChainView, TxError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

/// The first height of the second epoch.
const ACTIVATION: u64 = 110;
const NEXT_BRANCH: u32 = 0x4253_7634;

static NOOP_UPGRADE: [Epoch; 2] = [
    Epoch {
        name: "v3",
        activation_height: 0,
        header_version: 1,
        branch_id: BRANCH_ID_V3,
        verifier_id: VERIFIER_PX_1,
    },
    Epoch {
        name: "noop",
        activation_height: ACTIVATION,
        header_version: 1,
        branch_id: NEXT_BRANCH,
        verifier_id: VERIFIER_PX_1,
    },
];

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    let mut p = ChainParams::regtest();
    p.schedule = Schedule::new(&NOOP_UPGRADE);
    p
}

fn open() -> ChainManager {
    let p = params();
    // `TxRules::for_chain` refuses a multi-epoch schedule: the manager gets
    // the first epoch's rules and derives the others per height.
    let rules = TxRules::at_height(&p, 0);
    let store: Box<dyn BlockStore> = Box::<MemoryStore>::default();
    ChainManager::open(p, rules, Arc::new(ZeroPow), store, [7; 32]).unwrap()
}

struct Miner {
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Miner {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Self { keys, rng }
    }

    fn build(&mut self, t: &Template, txs: Vec<Transaction>) -> Block {
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
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 10 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        Block { header, txs: all }
    }

    /// A block with exactly `txs` on the tip (not from the pool).
    fn mine_with(
        &mut self,
        m: &mut ChainManager,
        txs: Vec<Transaction>,
    ) -> Result<Hash, SubmitError> {
        let t = m.template_on(&m.tip_id()).unwrap();
        let b = self.build(&t, txs);
        let now = b.header.timestamp;
        m.submit_block(b, now).map(|s| s.id)
    }

    /// The node's own template on its tip.
    fn mine_template(&mut self, m: &mut ChainManager) -> Block {
        let t = m.template();
        let b = self.build(&t, t.txs.clone());
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now)
            .expect("the template's block connects");
        b
    }
}

fn scan_all(m: &ChainManager, keys: &WalletKeys) -> Vec<OwnedOutput> {
    let table = SubaddressTable::new(keys.view_keys(), 1, 5);
    let mut out = Vec::new();
    for h in 1..=m.height() {
        let b = m.block_at(h).unwrap();
        let first = m.state().first_output_at(h).unwrap();
        out.extend(scan_block(keys.view_keys(), &table, &b.txs, h, first).owned);
    }
    out
}

/// A transfer of the `nth` spendable output of `from`, signed under `rules`.
fn transfer(
    m: &ChainManager,
    from: &WalletKeys,
    nth: usize,
    rules: &TxRules,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let height = m.height() + 1;
    let owned = scan_all(m, from)
        .into_iter()
        .filter(|o| {
            let age = if o.coinbase {
                COINBASE_MATURITY
            } else {
                SPENDABLE_AGE
            };
            height >= o.height + age && !m.state().is_key_image_spent(&o.key_image(from))
        })
        .nth(nth)
        .expect("a spendable output");
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
    let plan = InputPlan {
        real: SpendableOutput::from(&owned),
        decoys: ring
            .iter()
            .filter(|&&i| i != owned.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: state.output(i).unwrap().key,
            })
            .collect(),
    };
    Transaction::from(
        build_transfer(
            from,
            vec![plan],
            &[Payment {
                address: from.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &from.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, rules),
            rules,
            rng,
        )
        .unwrap(),
    )
}

fn invalid_signature(r: Result<Hash, MempoolError>) -> bool {
    matches!(
        r,
        Err(MempoolError::Invalid(TxError::InvalidSignature { .. }))
    )
}

#[test]
fn a_no_op_activation_flushes_the_pool_and_switches_the_branch() {
    let mut m = open();
    let mut miner = Miner::new(1);
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    // 100 blocks: about 40 mature coinbase outputs, 16-member rings.
    for _ in 0..100 {
        miner.mine_template(&mut m);
    }
    let keys = miner.keys.clone();
    let old = m.rules_at(ACTIVATION - 1);
    let new = m.rules_at(ACTIVATION);
    assert_eq!(old.branch_id, BRANCH_ID_V3);
    assert_eq!(new.branch_id, NEXT_BRANCH);
    assert_eq!(m.next_rules(), old);

    // Below the activation: old-branch transactions are admitted, new-branch
    // ones are refused.
    let pooled = transfer(&m, &keys, 0, &old, &mut rng);
    let pooled_id = m.submit_tx(pooled.clone()).unwrap();
    let early = transfer(&m, &keys, 1, &new, &mut rng);
    assert!(invalid_signature(m.submit_tx(early.clone())));
    assert_eq!(m.mempool().validated_under(), Some(old.domain()));

    // Mine coinbase-only blocks up to the last block of the first epoch; the
    // old-branch transaction stays pooled while the next block is in its epoch.
    while m.height() < ACTIVATION - 2 {
        miner.mine_with(&mut m, vec![]).unwrap();
    }
    assert!(m.mempool().contains(&pooled_id));
    assert_eq!(m.template().txs.len(), 1, "offered below the activation");
    // Block A - 1: the next block is the first of the new epoch. The pool is
    // flushed: its transaction is signed for the old branch.
    miner.mine_with(&mut m, vec![]).unwrap();
    assert_eq!(m.height(), ACTIVATION - 1);
    assert!(m.mempool().is_empty(), "flushed at the activation");
    assert_eq!(m.mempool().validated_under(), Some(new.domain()));
    assert_eq!(m.next_rules(), new);

    // At the activation: the old-branch transaction is refused, in the pool
    // and in a block; the template carries no transaction of the old rules.
    assert!(invalid_signature(m.submit_tx(pooled.clone())));
    assert!(m.template().txs.is_empty());
    let tip = m.tip_id();
    match miner.mine_with(&mut m, vec![pooled.clone()]) {
        Err(SubmitError::Body(BlockError::Tx {
            error: TxError::InvalidSignature { .. },
            ..
        })) => {}
        r => panic!("an old-branch transaction in block A must be invalid, got {r:?}"),
    }
    assert_eq!(m.tip_id(), tip);

    // New-branch transactions are accepted and mined at the activation.
    let late = transfer(&m, &keys, 1, &new, &mut rng);
    let late_id = m.submit_tx(late).unwrap();
    let t = m.template();
    assert_eq!(t.height, ACTIVATION);
    assert_eq!(t.version, 1);
    assert_eq!(t.txs.len(), 1);
    let b = miner.mine_template(&mut m);
    assert_eq!(m.height(), ACTIVATION);
    assert!(b.txs.iter().any(|tx| tx.hash() == late_id));
    assert!(m.mempool().is_empty());

    // A block below the activation still validates under the old rules: a
    // side branch from A - 2 holding the old-branch transaction at A - 1.
    let fork_parent = m
        .block_at(ACTIVATION - 2)
        .unwrap()
        .header
        .id(m.params().network_id);
    let t = m.template_on(&fork_parent).unwrap();
    assert_eq!(t.height, ACTIVATION - 1);
    let side = miner.build(&t, vec![pooled]);
    let now = side.header.timestamp;
    let s = m
        .submit_block(side, now)
        .expect("valid under the first epoch's rules");
    assert!(!s.on_best_chain, "less work than the main chain");
}

/// A reorganization across the activation returns the disconnected blocks'
/// transactions to the pool under the new rules: an old-branch transaction
/// mined below the activation is not re-pooled once the next block is in the
/// new epoch, and its output can be spent again by a new-branch transaction.
#[test]
fn transactions_returned_across_the_activation_are_revalidated_under_the_new_rules() {
    let mut m = open();
    let mut miner = Miner::new(3);
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    for _ in 0..ACTIVATION - 5 {
        miner.mine_template(&mut m);
    }
    let fork = m.tip_id(); // height A - 5
    let keys = miner.keys.clone();
    let old = m.rules_at(ACTIVATION - 4);
    let new = m.rules_at(ACTIVATION);
    let tx_old = transfer(&m, &keys, 0, &old, &mut rng);
    let id = m.submit_tx(tx_old.clone()).unwrap();
    let b = miner.mine_template(&mut m); // height A - 4, holds tx_old
    assert!(b.txs.iter().any(|t| t.hash() == id));
    while m.height() < ACTIVATION - 1 {
        miner.mine_with(&mut m, vec![]).unwrap();
    }
    // A longer branch from A - 5, without tx_old, to A + 1.
    let mut parent = fork;
    for _ in 0..6 {
        let t = m.template_on(&parent).unwrap();
        let b = miner.build(&t, vec![]);
        let now = b.header.timestamp;
        parent = m.submit_block(b, now).unwrap().id;
    }
    assert_eq!(m.tip_id(), parent);
    assert_eq!(m.height(), ACTIVATION + 1);
    // tx_old came back from the disconnected block but is signed for the old
    // branch: not pooled.
    assert!(!m.mempool().contains(&id));
    assert!(m.mempool().is_empty());
    assert_eq!(m.mempool().validated_under(), Some(new.domain()));
    assert!(invalid_signature(m.submit_tx(tx_old)));
    // The same output, re-signed for the new branch, is accepted.
    let again = transfer(&m, &keys, 0, &new, &mut rng);
    m.submit_tx(again).unwrap();
}
