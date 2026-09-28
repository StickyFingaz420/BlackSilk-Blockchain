//! `GET /tx/status` (docs/blocks.md §9): `pooled`, `confirmed` with the
//! height, or `unknown`. A transaction still in this node's Dandelion++
//! stem answers `unknown`: the RPC never reports stem state (F36-11), which
//! would tell anyone who can query the node which transactions it
//! originated or relays in the stem.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_node::serve::{self, RpcSettings};
use blacksilk_node::{tx_status, App, Shared};
use blacksilk_p2p::dandelion::DandelionParams;
use blacksilk_p2p::{NetConfig, Network};
use blacksilk_rpc::{Client, TxStatus};
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

struct Miner {
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Miner {
    /// Mines one block on the tip, with the mempool's transactions.
    fn mine(&mut self, shared: &Shared) {
        let mut c = shared.lock().unwrap();
        let t = c.template();
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
        .unwrap();
        let mut txs = vec![Transaction::Coinbase(cb)];
        txs.extend(t.txs.iter().cloned());
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(c.params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        let b = Block { header, txs };
        let now = b.header.timestamp;
        c.submit_block(b, now).unwrap();
    }

    /// A one-input transfer from the miner's first mature coinbase.
    fn payment(&mut self, shared: &Shared) -> Transaction {
        let c = shared.lock().unwrap();
        let table = SubaddressTable::new(self.keys.view_keys(), 1, 2);
        let next = c.height() + 1;
        let mut owned = None;
        'scan: for h in 1..=c.height() {
            let b = c.block_at(h).unwrap();
            let first = c.state().first_output_at(h).unwrap();
            for o in scan_block(self.keys.view_keys(), &table, &b.txs, h, first).owned {
                if next >= o.height + COINBASE_MATURITY
                    && !c.state().is_key_image_spent(&o.key_image(&self.keys))
                {
                    owned = Some(o);
                    break 'scan;
                }
            }
        }
        let owned = owned.expect("a mature coinbase");
        let state = c.state();
        let ring = select_ring(
            &mut self.rng,
            &state.cumulative_outputs(),
            next,
            120,
            owned.global_index,
            |i| {
                state.output(i).is_some_and(|r| {
                    let age = if r.coinbase {
                        COINBASE_MATURITY
                    } else {
                        SPENDABLE_AGE
                    };
                    next >= r.height + age
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
        let rules = *c.rules();
        let (dest, _) = WalletKeys::generate(&mut self.rng);
        let tx = build_transfer(
            &self.keys,
            vec![InputPlan {
                real: SpendableOutput::from(&owned),
                decoys,
            }],
            &[Payment {
                address: dest.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &self.keys.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, &rules),
            &rules,
            &mut self.rng,
        )
        .unwrap();
        Transaction::from(tx)
    }
}

fn chain() -> Shared {
    let p = ChainParams::regtest();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [9; 32],
    )
    .unwrap();
    Arc::new(Mutex::new(m))
}

fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(secs), "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The node's RPC (`serve::run`, with its cookie) and P2P: a transaction
/// submitted to it is held in the stem and answers `unknown`; once the
/// embargo fluffs it into the mempool it answers `pooled`; once mined,
/// `confirmed` at its height.
#[test]
fn a_stem_transaction_is_unknown_then_pooled_then_confirmed() {
    let shared = chain();
    let mut miner = Miner {
        keys: WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(1)).0,
        rng: ChaCha20Rng::seed_from_u64(2),
    };
    for _ in 0..(COINBASE_MATURITY + 20) {
        miner.mine(&shared);
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut cfg = NetConfig::new(ChainParams::regtest().network_id);
    cfg.listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.allow_private = true;
    cfg.tick = Duration::from_millis(50);
    // No peer ever connects: a local transaction is held in the stempool
    // until the embargo fluffs it (docs/p2p.md §8).
    let embargo = Duration::from_secs(4);
    cfg.dandelion = DandelionParams {
        embargo_base: embargo,
        embargo_mean: Duration::from_millis(1),
        ..DandelionParams::default()
    };
    // One chain actor for P2P and RPC, as in the node.
    let (chain, _actor) = blacksilk_chain::actor::spawn_shared(shared.clone(), Default::default());
    let net = rt
        .block_on(Network::start_with(cfg, chain.clone()))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = l.local_addr().unwrap();
    let app = App {
        chain,
        net: Some(net.clone()),
        mining: Default::default(),
    };
    let data = dir.path().to_path_buf();
    rt.spawn(async move {
        serve::run(
            l,
            app,
            &data,
            RpcSettings::default(),
            std::future::pending(),
        )
        .await
    });
    let cookie = dir.path().join(blacksilk_rpc::COOKIE_FILE);
    wait_until("cookie written", 10, || cookie.exists());
    let client = Client::new(&addr.to_string())
        .with_cookie_file(&cookie)
        .unwrap();

    let tx = miner.payment(&shared);
    let id = tx.hash();
    assert_eq!(client.tx_status(&id).unwrap(), TxStatus::Unknown);
    let submitted = Instant::now();
    let r = client.submit_tx(&tx.encode()).unwrap();
    assert!(r.accepted, "{:?}", r.error);
    assert!(net.stempool_contains(&id), "held in the stem");
    assert!(!shared.lock().unwrap().mempool().contains(&id));
    // While it is in the stem, the node reports nothing about it.
    let status = client.tx_status(&id).unwrap();
    assert!(
        net.stempool_contains(&id) && submitted.elapsed() < embargo,
        "the embargo passed during the check; rerun"
    );
    assert_eq!(status, TxStatus::Unknown, "stem state reported");

    // The embargo fluffs it into the mempool.
    wait_until("fluffed", 30, || {
        shared.lock().unwrap().mempool().contains(&id)
    });
    assert_eq!(client.tx_status(&id).unwrap(), TxStatus::Pooled);

    miner.mine(&shared);
    let height = shared.lock().unwrap().height();
    assert_eq!(
        client.tx_status(&id).unwrap(),
        TxStatus::Confirmed { height }
    );
    assert_eq!(client.tx_status(&[7; 32]).unwrap(), TxStatus::Unknown);
}

/// The function behind the route, on the chain alone.
#[test]
fn tx_status_reads_the_mempool_and_the_connected_chain() {
    let shared = chain();
    let mut miner = Miner {
        keys: WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(3)).0,
        rng: ChaCha20Rng::seed_from_u64(4),
    };
    for _ in 0..(COINBASE_MATURITY + 20) {
        miner.mine(&shared);
    }
    let tx = miner.payment(&shared);
    let id = tx.hash();
    assert_eq!(tx_status(&shared.lock().unwrap(), &id), TxStatus::Unknown);
    shared.lock().unwrap().submit_tx(tx).unwrap();
    assert_eq!(tx_status(&shared.lock().unwrap(), &id), TxStatus::Pooled);
    miner.mine(&shared);
    let m = shared.lock().unwrap();
    assert_eq!(
        tx_status(&m, &id),
        TxStatus::Confirmed { height: m.height() }
    );
    // A coinbase is a confirmed transaction too.
    let cb = m.block_at(5).unwrap().txs[0].hash();
    assert_eq!(tx_status(&m, &cb), TxStatus::Confirmed { height: 5 });
}
