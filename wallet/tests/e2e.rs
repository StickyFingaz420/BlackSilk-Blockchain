//! End to end over the real RPC server: node (chain manager + axum router),
//! miner library, and wallets moving funds, including persistence, restore from
//! mnemonic and a reorganization seen by the wallets.

use blacksilk_chain::emission::{block_reward, COIN};
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, Network, PowFunction};
use blacksilk_crypto::keys::Address;
use blacksilk_node::{router, Shared};
use blacksilk_rpc::{self as rpc, Client};
use blacksilk_tx::params::TxRules;
use blacksilk_wallet::file::KdfParams;
use blacksilk_wallet::{load, save, Wallet, WalletError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

/// Every hash meets every difficulty (the RandomX path is tested in the consensus
/// and miner crates).
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

struct Net {
    _rt: tokio::runtime::Runtime,
    shared: Shared,
    client: Client,
    rng: ChaCha20Rng,
    rules: TxRules,
}

impl Net {
    fn start() -> Self {
        let params = ChainParams::regtest();
        let rules = TxRules::for_chain(&params);
        let manager = ChainManager::open(
            params,
            rules,
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [3; 32],
        )
        .unwrap();
        let shared: Shared = Arc::new(Mutex::new(manager));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(shared.clone());
        rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _rt: rt,
            shared,
            client: Client::new(&addr.to_string()),
            rng: ChaCha20Rng::seed_from_u64(1),
            rules,
        }
    }

    fn time_for(height: u64) -> u64 {
        ChainParams::regtest().genesis.timestamp + 120 * height
    }

    /// Mines one block on the node's template through the RPC, paying `to`.
    fn mine(&mut self, to: &Address) -> rpc::Template {
        let t = self.client.template().unwrap();
        let b =
            blacksilk_miner::build_block(&t, to, &[9; 32], Self::time_for(t.height), &mut self.rng)
                .unwrap();
        let r = self.client.submit_block(&b.encode()).unwrap();
        assert!(r.accepted, "{:?}", r.error);
        t
    }

    fn mine_n(&mut self, n: u64, to: &Address) {
        for _ in 0..n {
            self.mine(to);
        }
    }

    /// Mines a coinbase-only block on an arbitrary parent (to build a fork).
    fn mine_on(&mut self, parent: &Hash, to: &Address, nonce: u64) -> Hash {
        let mut m = self.shared.lock().unwrap();
        let t = m.template_on(parent).unwrap();
        let rt = rpc::Template {
            height: t.height,
            prev_id: hex::encode(t.prev_id),
            difficulty: t.difficulty,
            seed_id: hex::encode(t.seed_id),
            min_timestamp: t.min_timestamp,
            reward: t.reward,
            fees: 0,
            txs: vec![],
        };
        let mut b = blacksilk_miner::build_block(
            &rt,
            to,
            &[9; 32],
            Self::time_for(t.height),
            &mut self.rng,
        )
        .unwrap();
        b.header.nonce = nonce;
        let now = b.header.timestamp;
        m.submit_block(b, now).unwrap().id
    }
}

fn wallet(seed: u8) -> Wallet {
    Wallet::from_seed(Network::Regtest, [seed; 32], 1)
}

#[test]
fn funds_move_between_wallets_over_rpc() {
    let mut net = Net::start();
    let mut miner = wallet(1);
    let mut alice = wallet(2);
    let mut bob = wallet(3);
    let miner_addr = miner.primary();

    net.mine_n(90, &miner_addr);
    assert_eq!(miner.sync(&net.client).unwrap(), 90);
    let mut expected = 0u64;
    for h in 1..=90 {
        expected += block_reward(h, expected);
    }
    let b = miner.balance();
    assert_eq!(b.total, expected);
    assert!(
        b.unlocked > 0 && b.unlocked < b.total,
        "only mature coinbases are unlocked"
    );

    // Miner -> Alice, to a subaddress.
    let alice_sub_str = alice.address(0, 3);
    let alice_sub =
        blacksilk_chain::address::decode_address(Network::Regtest, &alice_sub_str).unwrap();
    let (_, _fee1) = miner
        .transfer(&net.client, &alice_sub, 5 * COIN, &net.rules, &mut net.rng)
        .unwrap();
    assert_eq!(net.client.info().unwrap().mempool_txs, 1);
    net.mine(&miner_addr);
    assert_eq!(net.client.info().unwrap().mempool_txs, 0);
    alice.sync(&net.client).unwrap();
    assert_eq!(alice.balance().total, 5 * COIN);
    assert_eq!(alice.balance().unlocked, 0, "10-block spendable age");
    miner.sync(&net.client).unwrap();
    let reward91 = block_reward(91, expected);
    // Input − payment − fee comes back as change; the fee returns in block 91's
    // coinbase along with its reward.
    assert_eq!(miner.balance().total, b.total - 5 * COIN + reward91);

    // Alice -> Bob after the spendable age.
    net.mine_n(10, &miner_addr);
    alice.sync(&net.client).unwrap();
    assert_eq!(alice.balance().unlocked, 5 * COIN);
    let (_, fee2) = alice
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    net.mine(&miner_addr);
    bob.sync(&net.client).unwrap();
    alice.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, COIN);
    assert_eq!(alice.balance().total, 4 * COIN - fee2);

    // Insufficient funds is reported, not attempted.
    assert!(matches!(
        bob.transfer(
            &net.client,
            &alice_sub,
            100 * COIN,
            &net.rules,
            &mut net.rng
        ),
        Err(WalletError::InsufficientFunds { .. })
    ));

    // Encrypted file round trip and restore from mnemonic give the same view.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alice.wallet");
    let fast = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };
    save(&alice, &path, b"correct horse", fast).unwrap();
    assert!(load(&path, b"wrong").is_err());
    let reloaded = load(&path, b"correct horse").unwrap();
    assert_eq!(reloaded.balance(), alice.balance());
    let mut restored = Wallet::from_mnemonic(Network::Regtest, &alice.mnemonic(), 1).unwrap();
    restored.address(0, 3); // the subaddress must be within the scanned window
    restored.sync(&net.client).unwrap();
    assert_eq!(restored.balance(), alice.balance());
}

#[test]
fn wallet_follows_a_reorganization() {
    let mut net = Net::start();
    let mut miner = wallet(4);
    let mut bob = wallet(5);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();

    miner
        .transfer(
            &net.client,
            &bob.primary(),
            2 * COIN,
            &net.rules,
            &mut net.rng,
        )
        .unwrap();
    let fork_parent = { net.shared.lock().unwrap().tip_id() };
    net.mine(&miner_addr); // A91 confirms the payment
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, 2 * COIN);

    // A heavier branch without the payment replaces A91.
    let b91 = net.mine_on(&fork_parent, &miner_addr, 1);
    net.mine_on(&b91, &miner_addr, 1);
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, 0, "payment rolled back with the reorg");
    assert_eq!(
        net.client.info().unwrap().mempool_txs,
        1,
        "payment back in the mempool"
    );

    // It confirms again in the next block.
    net.mine(&miner_addr);
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, 2 * COIN);
}

#[test]
fn wrong_network_is_refused() {
    let net = Net::start();
    let mut w = Wallet::from_seed(Network::Testnet, [6; 32], 1);
    assert!(matches!(
        w.sync(&net.client),
        Err(WalletError::WrongNetwork { .. })
    ));
}

#[test]
fn rpc_rejects_malformed_and_oversized_requests() {
    let net = Net::start();
    let r = net.client.submit_tx(&[1, 2, 3]);
    assert!(matches!(r, Err(rpc::RpcError::Status(400, _))));
    assert!(matches!(
        net.client.blocks(0, 1000),
        Err(rpc::RpcError::Status(400, _))
    ));
    assert!(matches!(
        net.client.outputs(&vec![0; 2000]),
        Err(rpc::RpcError::Status(400, _))
    ));
    assert!(matches!(
        net.client.outputs(&[999_999]),
        Err(rpc::RpcError::Status(404, _))
    ));
    let r = net.client.submit_block(&[0; 50]).unwrap_err();
    assert!(matches!(r, rpc::RpcError::Status(400, _)));
}

#[test]
fn stale_pending_spends_expire_but_late_confirmation_still_counts() {
    let mut net = Net::start();
    let mut miner = wallet(7);
    let bob = wallet(8);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let before = miner.balance();
    miner
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    assert!(miner.has_pending());
    assert!(
        miner.balance().total < before.total,
        "pending input not counted"
    );
    // 20 blocks that do not include the transaction (coinbase-only, on the tip).
    for i in 0..20 {
        let tip = { net.shared.lock().unwrap().tip_id() };
        net.mine_on(&tip, &miner_addr, 1000 + i);
    }
    miner.sync(&net.client).unwrap();
    assert!(!miner.has_pending(), "expired after 20 blocks");
    // The transaction was still in the mempool: once mined, the spend is detected.
    net.mine(&miner_addr);
    miner.sync(&net.client).unwrap();
    let mut bob = bob;
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, COIN);
    // Miner: 111 rewards (90 + 20 + 1, fees returned) minus the payment.
    let mut expected = 0u64;
    for h in 1..=111 {
        expected += block_reward(h, expected);
    }
    assert_eq!(miner.balance().total, expected - COIN);
}

/// Private execution end to end over RPC (docs/px.md §11): deposit into PX,
/// a private payment, a withdrawal to a v1 address; wallets discover records
/// by scanning blocks and the bulk commitment list, and their PX state
/// survives an encrypted save and load.
#[test]
fn private_funds_move_over_rpc() {
    let mut net = Net::start();
    let mut miner = wallet(11);
    let mut alice = wallet(12);
    let mut bob = wallet(13);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();

    // Deposit: v1 funds into the miner's PX address 0.
    let deposit = 2 * COIN;
    let (_, fee) = miner
        .px_deposit(&net.client, deposit, &net.rules, &mut net.rng)
        .expect("deposit");
    net.mine(&miner_addr);
    miner.sync(&net.client).unwrap();
    // Spendable once the canonical anchor height reaches the record.
    assert_eq!(miner.px_balance(), (deposit, 0));
    net.mine_n(16, &miner_addr);
    miner.sync(&net.client).unwrap();
    assert_eq!(miner.px_balance(), (deposit, deposit));

    // Private payment to Alice.
    let alice_px = alice.px_address(0);
    let to = blacksilk_chain::address::decode_px_address(Network::Regtest, &alice_px).unwrap();
    let pay = COIN;
    miner
        .px_send(&net.client, &to, pay, &net.rules, &mut net.rng)
        .expect("private send");
    net.mine(&miner_addr);
    net.mine_n(16, &miner_addr);
    miner.sync(&net.client).unwrap();
    alice.sync(&net.client).unwrap();
    assert_eq!(alice.px_balance(), (pay, pay));
    assert_eq!(miner.px_balance().0, deposit - pay - fee);

    // The PX state survives the encrypted wallet file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alice.wallet");
    let kdf = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    save(&alice, &path, b"pw", kdf).unwrap();
    let mut alice = load(&path, b"pw").unwrap();
    assert_eq!(alice.px_balance(), (pay, pay));

    // Alice withdraws to Bob's v1 address (clear payout).
    let out = pay - fee;
    alice
        .px_withdraw(&net.client, &bob.primary(), out, &net.rules, &mut net.rng)
        .expect("withdraw");
    net.mine(&miner_addr);
    alice.sync(&net.client).unwrap();
    bob.sync(&net.client).unwrap();
    assert_eq!(alice.px_balance(), (0, 0));
    assert_eq!(bob.balance().total, out);
}

/// PX records follow a reorganization (docs/px.md §11.4): a deposit's record
/// disappears with the block that created it, and the wallet's commitment
/// list is rewound so that its tree root matches the node's again. The
/// deposit returns to the node's mempool and confirms again.
#[test]
fn px_records_follow_a_reorganization() {
    let mut net = Net::start();
    let mut miner = wallet(14);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();

    let deposit = 3 * COIN;
    miner
        .px_deposit(&net.client, deposit, &net.rules, &mut net.rng)
        .expect("deposit");
    let fork_parent = { net.shared.lock().unwrap().tip_id() };
    net.mine(&miner_addr); // A91 confirms the deposit
    miner.sync(&net.client).unwrap();
    assert_eq!(miner.px_balance().0, deposit);

    // A heavier branch without the deposit replaces A91.
    let b91 = net.mine_on(&fork_parent, &miner_addr, 1);
    net.mine_on(&b91, &miner_addr, 1);
    miner
        .sync(&net.client)
        .expect("the rewound tree matches the node's root");
    assert_eq!(
        miner.px_balance(),
        (0, 0),
        "record rolled back with the reorg"
    );
    assert_eq!(
        net.client.info().unwrap().mempool_txs,
        1,
        "deposit back in the mempool"
    );

    // It confirms again, and becomes spendable at the next canonical anchor.
    net.mine(&miner_addr);
    net.mine_n(16, &miner_addr);
    miner.sync(&net.client).unwrap();
    assert_eq!(miner.px_balance(), (deposit, deposit));
}
