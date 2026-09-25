//! Chain manager: emission enforcement, body/header handling, reorganizations with
//! transactions, invalid blocks, mempool, and persistence with replay.

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::block_reward;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template};
use blacksilk_chain::mempool::MempoolError;
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{
    BlockHeader, ChainParams, Hash, HeaderError, PowFunction, HEADER_VERSION,
};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::{Transaction, Transfer};
use blacksilk_tx::validate::{BlockError, ChainView};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Zero hash: meets any difficulty. Counts calls to show replay skips PoW.
#[derive(Default)]
struct ZeroPow {
    calls: AtomicUsize,
}
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        self.calls.fetch_add(1, Ordering::SeqCst);
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open(store: Box<dyn BlockStore>, pow: Arc<ZeroPow>) -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(p, rules, pow, store, [7; 32]).unwrap()
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

    /// Builds a block from a template, with an optional coinbase amount override.
    fn build(
        &mut self,
        t: &Template,
        txs: Vec<Transaction>,
        claim: Option<u64>,
        nonce: u64,
    ) -> Block {
        let fees: u64 = txs.iter().map(Transaction::fee).sum();
        let amount = claim.unwrap_or(t.reward + fees);
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount,
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let mut all = vec![Transaction::Coinbase(cb)];
        all.extend(txs);
        let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
        };
        Block { header, txs: all }
    }

    fn mine_tip(&mut self, m: &mut ChainManager) -> Block {
        let t = m.template();
        let txs = t.txs.clone();
        let b = self.build(&t, txs, None, 0);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now).expect("valid block");
        b
    }
}

/// Wallet view of the manager's connected chain.
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

fn pay(
    m: &ChainManager,
    from: &WalletKeys,
    to: &WalletKeys,
    amount: u64,
    rng: &mut ChaCha20Rng,
) -> Transfer {
    let height = m.height() + 1;
    let owned = scan_all(m, from)
        .into_iter()
        .find(|o| {
            let age = if o.coinbase {
                COINBASE_MATURITY
            } else {
                SPENDABLE_AGE
            };
            height >= o.height + age && !m.state().is_key_image_spent(&o.key_image(from))
        })
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
    let decoys = ring
        .iter()
        .filter(|&&i| i != owned.global_index)
        .map(|&i| Decoy {
            global_index: i,
            key: state.output(i).unwrap().key,
        })
        .collect();
    let plan = InputPlan {
        real: SpendableOutput::from(&owned),
        decoys,
    };
    let fee = standard_fee(1, 2, m.rules());
    build_transfer(
        from,
        vec![plan],
        &[Payment {
            address: to.address(SubaddressIndex::PRIMARY),
            amount,
        }],
        &from.address(SubaddressIndex::PRIMARY),
        fee,
        m.rules(),
        rng,
    )
    .unwrap()
}

#[test]
fn emission_is_enforced_exactly() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(1);
    let mut expected_g = 0u64;
    for h in 1..=20 {
        assert_eq!(m.template().reward, block_reward(h, expected_g));
        miner.mine_tip(&mut m);
        expected_g += block_reward(h, expected_g);
    }
    assert_eq!(m.generated(), expected_g);
    let balance: u64 = scan_all(&m, &miner.keys)
        .iter()
        .map(|o| o.received.amount)
        .sum();
    assert_eq!(
        balance, expected_g,
        "the miner received exactly the emission"
    );

    // One unit too much, and one too little, are both invalid.
    let tip = m.tip_id();
    for delta in [1i64, -1] {
        let t = m.template();
        let claim = (t.reward as i64 + delta) as u64;
        let b = miner.build(&t, vec![], Some(claim), 0);
        let now = b.header.timestamp;
        match m.submit_block(b.clone(), now) {
            Err(SubmitError::Body(BlockError::CoinbaseAmount { .. })) => {}
            other => panic!("expected CoinbaseAmount, got {other:?}"),
        }
        assert_eq!(m.tip_id(), tip, "tip unchanged");
        // Its children are rejected as descendants of an invalid block.
        let child_t = Template {
            height: t.height + 1,
            prev_id: b.id(params().network_id),
            ..t.clone()
        };
        let child = miner.build(&child_t, vec![], None, 0);
        let now = child.header.timestamp;
        assert!(matches!(
            m.submit_block(child, now),
            Err(SubmitError::Header(HeaderError::InvalidParent))
        ));
    }
}

#[test]
fn body_must_match_header() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(2);
    let t = m.template();
    let good = miner.build(&t, vec![], None, 0);
    let other = miner.build(&t, vec![], None, 0); // different coinbase randomness
    let mismatched = Block {
        header: good.header,
        txs: other.txs,
    };
    let now = good.header.timestamp;
    assert!(matches!(
        m.submit_block(mismatched, now),
        Err(SubmitError::BodyMismatch)
    ));
    assert_eq!(m.height(), 0, "nothing was accepted");
    // The header itself is still acceptable with its real body.
    m.submit_block(good.clone(), now).unwrap();
    assert_eq!(m.height(), 1);
    assert!(matches!(
        m.submit_block(good, now),
        Err(SubmitError::Duplicate)
    ));
}

#[test]
fn transactions_survive_reorgs_via_the_mempool() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(3);
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..80 {
        miner.mine_tip(&mut m);
    }
    let tx = pay(&m, &miner.keys, &alice, 12_345, &mut rng);
    let id = m.submit_tx(Transaction::from(tx.clone())).unwrap();
    assert_eq!(
        m.submit_tx(Transaction::from(tx.clone())),
        Err(MempoolError::AlreadyKnown)
    );
    // A double spend of the same output is refused by the pool.
    let conflicting = pay(&m, &miner.keys, &alice, 999, &mut rng);
    assert_eq!(
        m.submit_tx(Transaction::from(conflicting)),
        Err(MempoolError::Conflict)
    );

    let fork_parent = m.tip_id();
    let t = m.template();
    assert_eq!(t.txs.len(), 1);
    assert_eq!(t.fees, tx.fee);
    miner.mine_tip(&mut m); // block A1 includes the payment
    assert!(!m.mempool().contains(&id));
    assert_eq!(scan_all(&m, &alice).len(), 1);
    let g_a = m.generated();

    // Branch B: two coinbase-only blocks on the same parent overtake A1.
    let tb1 = m.template_on(&fork_parent).unwrap();
    let b1 = miner.build(&tb1, vec![], None, 1);
    let now = b1.header.timestamp;
    let s = m.submit_block(b1.clone(), now).unwrap();
    assert!(!s.on_best_chain, "equal work: first seen stays");
    let tb2 = m.template_on(&b1.id(params().network_id)).unwrap();
    let b2 = miner.build(&tb2, vec![], None, 1);
    let now = b2.header.timestamp;
    let s = m.submit_block(b2, now).unwrap();
    assert!(s.on_best_chain);
    assert_eq!(m.deepest_reorg(), 1, "A1 was disconnected");

    // The payment is undone and back in the mempool; emission is per height.
    assert!(scan_all(&m, &alice).is_empty());
    assert!(m.mempool().contains(&id), "returned to the mempool");
    assert_eq!(m.generated(), g_a + block_reward(m.height(), g_a));
    // ...and confirms again on the new branch.
    miner.mine_tip(&mut m);
    assert_eq!(scan_all(&m, &alice).len(), 1);
    assert!(m.mempool().is_empty());
}

#[test]
fn invalid_side_branch_body_is_rejected_when_it_would_win() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(4);
    for _ in 0..3 {
        miner.mine_tip(&mut m);
    }
    let parent = m.tip_id();
    let a1 = miner.mine_tip(&mut m);
    // B1 over-claims its reward; its header is valid, so it is stored as a side branch.
    let tb1 = m.template_on(&parent).unwrap();
    let b1 = miner.build(&tb1, vec![], Some(tb1.reward + 1), 7);
    let now = b1.header.timestamp;
    assert!(
        m.submit_block(b1.clone(), now).is_ok(),
        "side branch body not checked yet"
    );
    // B2 would make branch B heavier: connecting B1 fails, B is invalidated, A stays.
    let tb2 = m.template_on(&b1.id(params().network_id)).unwrap();
    let b2 = miner.build(&tb2, vec![], None, 7);
    let now = b2.header.timestamp;
    let r = m.submit_block(b2, now);
    assert!(r.is_err() || !r.unwrap().on_best_chain);
    assert_eq!(m.tip_id(), a1.id(params().network_id));
    assert!(matches!(
        m.invalid_reason(&b1.id(params().network_id)),
        Some(BlockError::CoinbaseAmount { .. })
    ));
}

#[test]
fn restart_replays_the_store_without_recomputing_pow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let (tip, height, outputs, generated, spent) = {
        let pow = Arc::new(ZeroPow::default());
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), pow.clone());
        let mut miner = Miner::new(5);
        for _ in 0..75 {
            miner.mine_tip(&mut m);
        }
        let tx = pay(&m, &miner.keys, &alice, 5_000, &mut rng);
        let ki = tx.inputs[0].key_image;
        m.submit_tx(Transaction::from(tx)).unwrap();
        miner.mine_tip(&mut m);
        // A side branch block is stored too.
        let side = m.template_on(&m.headers().main_id_at(70).unwrap()).unwrap();
        let s = miner.build(&side, vec![], None, 9);
        let now = s.header.timestamp;
        m.submit_block(s, now).unwrap();
        assert!(pow.calls.load(Ordering::SeqCst) >= 77);
        (
            m.tip_id(),
            m.height(),
            m.state().output_count(),
            m.generated(),
            ki,
        )
    };

    let pow = Arc::new(ZeroPow::default());
    let m = open(Box::new(FileStore::open(&path).unwrap()), pow.clone());
    assert_eq!(
        pow.calls.load(Ordering::SeqCst),
        0,
        "stored PoW hashes are reused"
    );
    assert_eq!(m.tip_id(), tip);
    assert_eq!(m.height(), height);
    assert_eq!(m.state().output_count(), outputs);
    assert_eq!(m.generated(), generated);
    assert!(m.state().is_key_image_spent(&spent));
    assert_eq!(scan_all(&m, &alice).len(), 1);
}

#[test]
fn restart_after_torn_write_recovers_previous_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let tip_before_last = {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let mut miner = Miner::new(6);
        for _ in 0..5 {
            miner.mine_tip(&mut m);
        }
        let id = m.tip_id();
        miner.mine_tip(&mut m);
        id
    };
    let len = std::fs::metadata(&path).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(len - 10).unwrap();
    drop(f);
    let m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    assert_eq!(m.height(), 5);
    assert_eq!(m.tip_id(), tip_before_last);
}

// ---------------------------------------------------------------- header-first sync

/// Two managers: `src` mines, `dst` receives headers first and bodies later.
fn mined_source(blocks: u64, seed: u64) -> (ChainManager, Vec<Block>) {
    let mut src = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(seed);
    let bs = (0..blocks).map(|_| miner.mine_tip(&mut src)).collect();
    (src, bs)
}

#[test]
fn headers_without_bodies_do_not_move_the_state() {
    let (_, blocks) = mined_source(30, 20);
    let mut dst = open(Box::<MemoryStore>::default(), Arc::default());
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    let now = headers.last().unwrap().timestamp;
    assert_eq!(dst.accept_headers(&headers, now), Ok(30));
    assert_eq!(dst.header_height(), 30);
    assert_eq!(dst.height(), 0, "no bodies yet");
    let missing = dst.missing_bodies(100);
    assert_eq!(missing.len(), 30);
    assert_eq!(missing[0].0, 1);
    // Re-sending the same headers is harmless.
    assert_eq!(dst.accept_headers(&headers, now), Ok(0));
    // Bodies arriving out of order connect as soon as the gap closes.
    for b in blocks.iter().skip(1).rev() {
        let now = b.header.timestamp;
        dst.submit_block(b.clone(), now).unwrap();
    }
    assert_eq!(dst.height(), 0);
    dst.submit_block(blocks[0].clone(), blocks[0].header.timestamp)
        .unwrap();
    assert_eq!(dst.height(), 30);
    assert!(dst.missing_bodies(10).is_empty());
}

#[test]
fn heavier_header_branch_without_bodies_keeps_the_current_chain() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(21);
    for _ in 0..5 {
        miner.mine_tip(&mut m);
    }
    let fork = m.headers().main_id_at(2).unwrap();
    let tip = m.tip_id();
    // A 5-block side branch from height 2 (heavier: reaches height 7), headers only.
    let mut parent = fork;
    let mut side = Vec::new();
    for i in 0..5 {
        let t = m.template_on(&parent).unwrap();
        let b = miner.build(&t, vec![], None, 100 + i);
        parent = b.id(params().network_id);
        m.accept_headers(&[b.header], b.header.timestamp).unwrap();
        side.push(b);
    }
    assert_eq!(m.header_height(), 7);
    assert_eq!(
        m.tip_id(),
        tip,
        "state stays on the chain whose bodies we have"
    );
    assert_eq!(m.height(), 5);
    // Partial bodies with less work than the current tip: still no switch.
    for b in &side[..2] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.tip_id(), tip);
    // All bodies: the heavier branch wins.
    for b in &side[2..] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.height(), 7);
    assert_eq!(m.tip_id(), side[4].id(params().network_id));
}

#[test]
fn locator_and_headers_after() {
    let (src, blocks) = mined_source(100, 22);
    let loc = src.locator();
    assert_eq!(loc[0], src.tip_id());
    assert_eq!(*loc.last().unwrap(), params().genesis_id());
    assert!(loc.len() <= 64);
    // Dense near the tip, then sparse.
    assert_eq!(loc[1], blocks[98].id(params().network_id));
    // A peer that knows up to block 40 gets 41.. from us.
    let peer_locator = vec![blocks[39].id(params().network_id), params().genesis_id()];
    let hs = src.headers_after(&peer_locator, &[0; 32], 2000);
    assert_eq!(hs.len(), 60);
    assert_eq!(hs[0].height, 41);
    let stop = blocks[49].id(params().network_id);
    assert_eq!(src.headers_after(&peer_locator, &stop, 2000).len(), 10);
    assert_eq!(src.headers_after(&peer_locator, &[0; 32], 5).len(), 5);
    // Unknown locator: from genesis.
    assert_eq!(src.headers_after(&[[9; 32]], &[0; 32], 2000).len(), 100);
}

#[test]
fn pow_jobs_use_seeds_from_the_batch() {
    use blacksilk_consensus::seed_height;
    // Long enough to cross the first RandomX key change (2048 + 64).
    let (src, blocks) = mined_source(2200, 23);
    let dst = open(Box::<MemoryStore>::default(), Arc::default());
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    let (_, jobs) = dst.pow_jobs(&headers).expect("extends genesis");
    for (h, (seed, bytes)) in headers.iter().zip(&jobs) {
        assert_eq!(bytes, &h.to_bytes());
        let sh = seed_height(h.height, 2048, 64);
        assert_eq!(
            *seed,
            src.headers().main_id_at(sh).unwrap(),
            "height {}",
            h.height
        );
    }
    assert!(
        jobs.iter().any(|(s, _)| *s != params().genesis_id()),
        "a key change is covered"
    );
    // Not a chain / unknown parent: no jobs.
    assert!(dst.pow_jobs(&headers[1..]).is_none());
    let mut broken = headers[..3].to_vec();
    broken.swap(1, 2);
    assert!(dst.pow_jobs(&broken).is_none());
}

/// The `nth` mature, unspent output of `from`, with a ring.
fn plan_nth(m: &ChainManager, from: &WalletKeys, nth: usize, rng: &mut ChaCha20Rng) -> InputPlan {
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
    InputPlan {
        real: SpendableOutput::from(&owned),
        decoys: ring
            .iter()
            .filter(|&&i| i != owned.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: state.output(i).unwrap().key,
            })
            .collect(),
    }
}

/// A node restarted from its block file rebuilds the PX state exactly: the
/// commitment tree, the pool, the nullifiers, the contract registry and the
/// registration list wallets download (docs/px.md §11.3, §13.4).
#[test]
fn restart_rebuilds_the_px_state_exactly() {
    use blacksilk_px::wallet::{self as pxw, Account};
    use blacksilk_tx::px::Registration;
    use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (tip, root, pool, nullifiers, log, contract) = {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let mut miner = Miner::new(8);
        for _ in 0..75 {
            miner.mine_tip(&mut m);
        }
        let rules = *m.rules();
        // A PX deposit (a real proof) and a contract deploy, from two outputs.
        let amount = 5_000_000;
        let plan = plan_nth(&m, &miner.keys, 0, &mut miner.rng);
        let acct = Account::from_seed(&[3; 32]);
        let rng = &mut miner.rng;
        let witness = pxw::witness(
            m.state().px().root(),
            amount,
            0,
            [pxw::dummy_input(rng), pxw::dummy_input(rng)],
            [
                pxw::output(rng, acct.owner(0), amount),
                pxw::empty_output(rng),
            ],
        );
        let primary = miner.keys.address(SubaddressIndex::PRIMARY);
        let deposit = build_px(
            PxPlan {
                keys: Some(&miner.keys),
                inputs: vec![plan],
                change: Some(primary),
                payouts: vec![],
                witness,
                recipients: [Some(acct.address(0)), None],
                functions: vec![],
                fee: px_standard_fee(),
            },
            &rules,
            &mut miner.rng,
        )
        .unwrap();
        m.submit_tx(Transaction::Px(Box::new(deposit))).unwrap();
        let plan = plan_nth(&m, &miner.keys, 1, &mut miner.rng);
        let deploy = build_deploy(
            &miner.keys,
            vec![plan],
            &[Payment {
                address: primary,
                amount: 0,
            }],
            &primary,
            [4; 32],
            vec![Registration {
                elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
                budget: blacksilk_px::vault::BUDGET,
            }],
            &rules,
            &mut miner.rng,
        )
        .unwrap();
        let contract = deploy.contract_id();
        m.submit_tx(Transaction::PxDeploy(Box::new(deploy)))
            .unwrap();
        miner.mine_tip(&mut m);
        let s = m.state();
        assert_eq!(s.px_pool(), amount as u128, "the deposit is in the block");
        assert_eq!(s.px_contract_log().len(), 1, "the deploy is in the block");
        (
            m.tip_id(),
            s.px().root(),
            s.px_pool(),
            s.px_nullifiers(0, u64::MAX),
            s.px_contract_log().to_vec(),
            contract,
        )
    };

    let m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    let s = m.state();
    assert_eq!(m.tip_id(), tip);
    assert_eq!(s.px().root(), root);
    assert_eq!(s.px_pool(), pool);
    assert_eq!(s.px_nullifiers(0, u64::MAX), nullifiers);
    assert_eq!(s.px_contract_log(), log.as_slice());
    assert!(s.px_contract_exists(&contract));
    assert_eq!(
        s.px_function(&contract, &blacksilk_px::vault::program().id())
            .map(|f| f.1),
        Some(blacksilk_px::vault::BUDGET)
    );
}
