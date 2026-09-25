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
use blacksilk_wallet::node::NodeApi;
use blacksilk_wallet::{load, save, Wallet, WalletError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cell::{Cell, RefCell};
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

/// How `Flaky` answers a submission.
#[derive(Clone, Copy)]
enum Submit {
    /// Pass it to the node.
    Forward,
    /// Pass it to the node, then report a transport failure (the node has it,
    /// the wallet cannot know).
    ForwardThenFail,
    /// Report that the node found it invalid, without passing it on.
    Invalid,
    /// Keep it (`Flaky::sent`) and report it accepted, without passing it on.
    Record,
}

/// The real client, with submissions answered as `mode` says; counts them.
struct Flaky<'a> {
    inner: &'a Client,
    mode: Submit,
    submits: Cell<u32>,
    sent: RefCell<Vec<Vec<u8>>>,
    /// Every `/outputs` request, in order.
    queries: RefCell<Vec<Vec<u64>>>,
    /// Report at most this height (a node behind the wallet).
    height_cap: Option<u64>,
    /// At submission, read this wallet file (password `pw`) and record
    /// whether it already holds the reservation.
    check_file: Option<std::path::PathBuf>,
    saved_before_submit: Cell<Option<bool>>,
}

impl<'a> Flaky<'a> {
    fn new(inner: &'a Client, mode: Submit) -> Self {
        Self {
            inner,
            mode,
            submits: Cell::new(0),
            sent: RefCell::new(Vec::new()),
            queries: RefCell::new(Vec::new()),
            height_cap: None,
            check_file: None,
            saved_before_submit: Cell::new(None),
        }
    }
}

impl NodeApi for Flaky<'_> {
    fn info(&self) -> Result<rpc::Info, String> {
        let mut i = NodeApi::info(self.inner)?;
        if let Some(cap) = self.height_cap {
            i.height = i.height.min(cap);
            i.header_height = i.header_height.min(cap);
        }
        Ok(i)
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        NodeApi::blocks(self.inner, from, count)
    }
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String> {
        NodeApi::distribution(self.inner, to)
    }
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
        self.queries.borrow_mut().push(indices.to_vec());
        NodeApi::outputs(self.inner, indices)
    }
    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
        NodeApi::px_commitments(self.inner, from)
    }
    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
        NodeApi::px_contracts(self.inner, from)
    }
    fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String> {
        self.submits.set(self.submits.get() + 1);
        self.sent.borrow_mut().push(tx.to_vec());
        if let Some(path) = &self.check_file {
            let on_disk = load(path, b"pw").map(|w| w.has_pending()).unwrap_or(false);
            self.saved_before_submit.set(Some(on_disk));
        }
        match self.mode {
            Submit::Forward => NodeApi::submit_tx(self.inner, tx),
            Submit::ForwardThenFail => {
                NodeApi::submit_tx(self.inner, tx)?;
                Err("connection reset".into())
            }
            Submit::Invalid => Ok(rpc::SubmitResult {
                accepted: false,
                id: None,
                on_best_chain: None,
                error: Some("Invalid(RingMemberUnknown)".into()),
            }),
            Submit::Record => Ok(rpc::SubmitResult {
                accepted: true,
                id: None,
                on_best_chain: None,
                error: None,
            }),
        }
    }
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
    miner.sync(&net.client).unwrap();
    assert!(!miner.has_pending(), "confirmed");

    // A heavier branch without the payment replaces A91.
    let b91 = net.mine_on(&fork_parent, &miner_addr, 1);
    net.mine_on(&b91, &miner_addr, 1);
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, 0, "payment rolled back with the reorg");
    // The payer's inputs are reserved again, not released: the payment is
    // back in the pool, and a new spend of them would use new rings.
    miner.sync(&net.client).unwrap();
    assert!(miner.has_pending(), "re-reserved after the reorg");
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
fn an_unconfirmed_transaction_keeps_its_inputs_and_is_rebroadcast_unchanged() {
    let mut net = Net::start();
    let mut miner = wallet(7);
    let bob = wallet(8);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let before = miner.balance();
    let (id, _) = miner
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    assert!(miner.has_pending());
    assert!(
        miner.balance().total < before.total,
        "pending input not counted"
    );
    // The node reports a resubmission of a pooled transaction as "already
    // pooled", which the wallet relies on (rpc::SubmitResult::already_pooled).
    let bytes = {
        let m = net.shared.lock().unwrap();
        m.mempool().get(&id).expect("pooled").encode()
    };
    assert!(net.client.submit_tx(&bytes).unwrap().already_pooled());
    // 20 blocks that do not include the transaction (coinbase-only, on the tip).
    for i in 0..20 {
        let tip = { net.shared.lock().unwrap().tip_id() };
        net.mine_on(&tip, &miner_addr, 1000 + i);
    }
    // The wallet rebroadcasts it and keeps the inputs reserved: releasing them
    // would let a new transaction spend the same output with a new ring.
    let node = Flaky::new(&net.client, Submit::Forward);
    miner.sync(&node).unwrap();
    assert_eq!(node.submits.get(), 1, "rebroadcast once");
    assert!(miner.has_pending(), "still reserved after 20 blocks");
    // Once mined, the spend is detected.
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
    assert!(!miner.has_pending());
}

#[test]
fn an_uncertain_submission_keeps_the_inputs_reserved_across_a_restart() {
    let mut net = Net::start();
    let mut miner = wallet(9);
    let mut bob = wallet(10);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let before = miner.balance();
    // The node receives the transaction, but the wallet sees a transport error.
    let node = Flaky::new(&net.client, Submit::ForwardThenFail);
    let err = miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap_err();
    assert!(matches!(err, WalletError::Uncertain(_)), "{err}");
    assert!(miner.has_pending(), "inputs stay reserved");
    assert!(miner.balance().total < before.total);
    // The reservation and the stored transaction survive a save and load.
    let dir = std::env::temp_dir().join(format!("bs-uncertain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.bin");
    let kdf = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };
    save(&miner, &path, b"pw", kdf).unwrap();
    let mut miner = load(&path, b"pw").unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert!(miner.has_pending());
    // It was in fact pooled: it confirms and both wallets see it.
    net.mine(&miner_addr);
    miner.sync(&net.client).unwrap();
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, COIN);
    assert!(!miner.has_pending());
}

#[test]
fn a_stored_transaction_the_node_finds_invalid_releases_its_inputs() {
    let mut net = Net::start();
    let mut miner = wallet(11);
    let bob = wallet(12);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let before = miner.balance();
    miner
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    for i in 0..20 {
        let tip = { net.shared.lock().unwrap().tip_id() };
        net.mine_on(&tip, &miner_addr, 2000 + i);
    }
    // A full pool or a transport error keeps the reservation...
    miner
        .sync(&Flaky::new(&net.client, Submit::ForwardThenFail))
        .unwrap();
    assert!(miner.has_pending());
    // ...an invalid verdict releases it: the transaction can never be mined.
    let node = Flaky::new(&net.client, Submit::Invalid);
    miner.sync(&node).unwrap();
    assert_eq!(node.submits.get(), 1);
    assert!(!miner.has_pending(), "released");
    assert!(
        miner.balance().total > before.total,
        "the 20 new rewards and the released input"
    );
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

/// Private contracts end to end (docs/px.md §13): the reference vault is
/// deployed, Alice locks funds in it for Bob (the record's ciphertext goes to
/// Bob), shares the opening with Carol off chain, and Bob, who holds no PX
/// funds, claims with the secret, paying the fee from v1 funds. Every holder
/// of the opening sees the record consumed.
#[test]
fn a_vault_is_deployed_locked_delivered_shared_and_claimed_over_rpc() {
    use blacksilk_px::vault;
    use blacksilk_tx::px::Registration;
    use blacksilk_wallet::px::{digest_hex, RecordSource};

    let mut net = Net::start();
    let mut alice = wallet(21);
    let mut bob = wallet(22);
    let mut carol = wallet(23);
    let a_addr = alice.primary();
    net.mine_n(90, &a_addr);
    alice.sync(&net.client).unwrap();

    // Alice deploys the vault (v1 funds) and pays Bob v1 funds for his fee.
    let (_, contract, _) = alice
        .px_deploy(
            &net.client,
            vec![Registration {
                elf: vault::VAULT_ELF.to_vec(),
                budget: vault::BUDGET,
            }],
            &net.rules,
            &mut net.rng,
        )
        .expect("deploy");
    net.mine(&a_addr);
    alice.sync(&net.client).unwrap();
    let known = alice
        .px_contracts()
        .iter()
        .find(|c| c.id == digest_hex(&contract))
        .expect("the deployed contract is indexed");
    assert_eq!(known.programs[0].id, hex::encode(vault::program().id()));
    // A wallet created after the deploy (scanning from a later height) still
    // knows the contract: the registration list is downloaded whole.
    let tip = net.client.info().unwrap().height;
    let mut late = Wallet::from_seed(Network::Regtest, [24; 32], tip + 1);
    late.sync(&net.client).unwrap();
    assert!(late
        .px_contracts()
        .iter()
        .any(|c| c.id == digest_hex(&contract) && c.programs == known.programs));
    alice
        .transfer(&net.client, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .expect("v1 payment to Bob");
    net.mine(&a_addr);

    // Alice moves funds into PX.
    alice.sync(&net.client).unwrap();
    alice
        .px_deposit(&net.client, 3 * COIN, &net.rules, &mut net.rng)
        .expect("deposit");
    net.mine(&a_addr);
    net.mine_n(16, &a_addr);
    alice.sync(&net.client).unwrap();

    // LOCK 1 BLK for Bob: the record is delivered to Bob's PX address.
    let secret = blacksilk_px::wallet::random_digest(&mut net.rng);
    let bob_px =
        blacksilk_chain::address::decode_px_address(Network::Regtest, &bob.px_address(0)).unwrap();
    let (_, record) = alice
        .px_vault_lock(
            &net.client,
            &contract,
            COIN,
            &secret,
            Some(&bob_px),
            &net.rules,
            &mut net.rng,
        )
        .expect("lock");
    assert_eq!(alice.px_contract_records()[0].height, None, "unconfirmed");
    net.mine(&a_addr);
    net.mine_n(16, &a_addr);
    alice.sync(&net.client).unwrap();
    bob.sync(&net.client).unwrap();
    let hex_record = digest_hex(&record);
    let mine = &alice.px_contract_records()[0];
    assert_eq!(
        (&mine.commitment, mine.source, mine.value),
        (&hex_record, RecordSource::Created, COIN)
    );
    assert!(mine.height.is_some() && mine.position.is_some());
    let got = &bob.px_contract_records()[0];
    assert_eq!(
        (&got.commitment, got.source, got.value),
        (&hex_record, RecordSource::Received { index: 0 }, COIN)
    );
    // Contract records are not the holder's funds.
    assert_eq!(bob.px_balance(), (0, 0));

    // Alice shares the opening with Carol, who imports it.
    let carol_px =
        blacksilk_chain::address::decode_px_address(Network::Regtest, &carol.px_address(0))
            .unwrap();
    let shared = alice
        .px_share(&record, &carol_px, &mut net.rng)
        .expect("share");
    assert!(
        bob.px_import(&shared).is_err(),
        "a share opens only for its addressee"
    );
    carol.sync(&net.client).unwrap();
    assert_eq!(carol.px_import(&shared).expect("import"), record);
    carol.sync(&net.client).unwrap();
    let theirs = &carol.px_contract_records()[0];
    assert_eq!(theirs.source, RecordSource::Imported);
    assert!(theirs.height.is_some(), "confirmed by the commitment list");

    // A wrong secret is refused before any proving.
    let wrong = blacksilk_px::wallet::random_digest(&mut net.rng);
    assert!(matches!(
        bob.px_vault_claim(&net.client, &record, &wrong, None, &net.rules, &mut net.rng),
        Err(WalletError::Contract(_))
    ));

    // Bob claims to his own PX address; he has no PX funds, so the fee is
    // paid from his v1 funds.
    let (_, value) = bob
        .px_vault_claim(
            &net.client,
            &record,
            &secret,
            None,
            &net.rules,
            &mut net.rng,
        )
        .expect("claim");
    assert_eq!(value, COIN);
    net.mine(&a_addr);
    net.mine_n(16, &a_addr);
    for w in [&mut alice, &mut bob, &mut carol] {
        w.sync(&net.client).unwrap();
        let r = &w.px_contract_records()[0];
        assert!(r.spent_height.is_some(), "every holder sees the claim");
    }
    assert_eq!(bob.px_balance(), (COIN, COIN));
    assert!(bob.balance().total < COIN, "the fee came from v1 funds");
    // A spent vault cannot be claimed again.
    assert!(matches!(
        bob.px_vault_claim(
            &net.client,
            &record,
            &secret,
            None,
            &net.rules,
            &mut net.rng
        ),
        Err(WalletError::Contract(_))
    ));

    // Bob now holds PX funds: he locks half of them in a vault for himself and
    // claims it, the claim's fee paid from a PX record (not from v1).
    let fee = blacksilk_tx::px_builder::px_standard_fee();
    let second = blacksilk_px::wallet::random_digest(&mut net.rng);
    let (_, record2) = bob
        .px_vault_lock(
            &net.client,
            &contract,
            COIN / 2,
            &second,
            None,
            &net.rules,
            &mut net.rng,
        )
        .expect("second lock");
    net.mine(&a_addr);
    net.mine_n(16, &a_addr);
    bob.sync(&net.client).unwrap();
    let v1_before = bob.balance().total;
    bob.px_vault_claim(
        &net.client,
        &record2,
        &second,
        None,
        &net.rules,
        &mut net.rng,
    )
    .expect("claim with the fee from PX");
    net.mine(&a_addr);
    net.mine_n(16, &a_addr);
    bob.sync(&net.client).unwrap();
    assert_eq!(bob.balance().total, v1_before, "no v1 funds used");
    // COIN − (lock fee) − (claim fee): the vault's value came back.
    assert_eq!(bob.px_balance(), (COIN - 2 * fee, COIN - 2 * fee));
    let r2 = bob
        .px_contract_records()
        .iter()
        .find(|r| r.commitment == digest_hex(&record2))
        .unwrap();
    assert!(r2.spent_height.is_some());
}

/// A vault lock whose submission outcome is unknown keeps the creator's copy
/// of the record: the transaction did reach the node, and without the copy the
/// locked funds could not be opened (docs/reviews/wallet-review.md W-4).
#[test]
fn an_uncertain_vault_lock_keeps_the_record_opening() {
    use blacksilk_px::vault;
    use blacksilk_tx::px::Registration;

    let mut net = Net::start();
    let mut alice = wallet(25);
    let a_addr = alice.primary();
    net.mine_n(90, &a_addr);
    alice.sync(&net.client).unwrap();
    let (_, contract, _) = alice
        .px_deploy(
            &net.client,
            vec![Registration {
                elf: vault::VAULT_ELF.to_vec(),
                budget: vault::BUDGET,
            }],
            &net.rules,
            &mut net.rng,
        )
        .expect("deploy");
    net.mine(&a_addr);
    alice.sync(&net.client).unwrap();
    alice
        .px_deposit(&net.client, 3 * COIN, &net.rules, &mut net.rng)
        .expect("deposit");
    net.mine_n(17, &a_addr);
    alice.sync(&net.client).unwrap();

    let secret = blacksilk_px::wallet::random_digest(&mut net.rng);
    let node = Flaky::new(&net.client, Submit::ForwardThenFail);
    let err = alice
        .px_vault_lock(
            &node,
            &contract,
            COIN,
            &secret,
            None,
            &net.rules,
            &mut net.rng,
        )
        .unwrap_err();
    assert!(matches!(err, WalletError::Uncertain(_)), "{err}");
    assert_eq!(alice.px_contract_records().len(), 1, "the opening is kept");
    assert_eq!(alice.px_contract_records()[0].height, None);
    // The lock was in fact pooled: once mined, the wallet holds a confirmed
    // record it can open.
    net.mine(&a_addr);
    alice.sync(&net.client).unwrap();
    let r = &alice.px_contract_records()[0];
    assert!(r.height.is_some(), "confirmed");
    assert_eq!(r.value, COIN);
}

/// Key image → ring of every v1 input of an encoded transfer.
fn rings_of(bytes: &[u8]) -> std::collections::BTreeMap<[u8; 32], [u64; 16]> {
    use blacksilk_tx::types::Transaction;
    match Transaction::decode(bytes).unwrap() {
        Transaction::Transfer(t) => t
            .inputs
            .iter()
            .map(|i| (*i.key_image.bytes(), i.ring))
            .collect(),
        other => panic!("not a transfer: {other:?}"),
    }
}

/// Spending an output again after an earlier transaction may have been
/// relayed reuses that transaction's ring, so the two share every member and
/// their intersection reveals nothing new (docs/reviews/wallet-review.md W-5).
/// Both ways inputs come free again are covered: `clear-pending`, and an
/// `Invalid` verdict on the stored transaction.
#[test]
fn an_output_spent_again_reuses_its_ring() {
    let mut net = Net::start();
    let mut miner = wallet(27);
    let bob = wallet(28);
    let mut carol = wallet(26);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    // Carol owns exactly one output, so every spend of hers spends it.
    miner
        .transfer(
            &net.client,
            &carol.primary(),
            5 * COIN,
            &net.rules,
            &mut net.rng,
        )
        .unwrap();
    net.mine_n(11, &miner_addr);
    carol.sync(&net.client).unwrap();
    let spend = |carol: &mut Wallet, net: &mut Net| {
        let node = Flaky::new(&net.client, Submit::Record);
        carol
            .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
            .unwrap();
        let rings = rings_of(&node.sent.borrow()[0]);
        assert_eq!(rings.len(), 1, "her one output");
        rings
    };

    // The first spend "leaves" the wallet (recorded, not mined).
    let first = spend(&mut carol, &mut net);
    // Freed by clear-pending, spent again: the same ring.
    carol.clear_pending();
    let second = spend(&mut carol, &mut net);
    assert_eq!(first, second, "ring reused after clear-pending");

    // Freed by an Invalid verdict 20 blocks later, spent again: the same ring.
    for i in 0..20 {
        let tip = { net.shared.lock().unwrap().tip_id() };
        net.mine_on(&tip, &miner_addr, 3000 + i);
    }
    carol
        .sync(&Flaky::new(&net.client, Submit::Invalid))
        .unwrap();
    assert!(!carol.has_pending(), "released");
    let third = spend(&mut carol, &mut net);
    assert_eq!(second, third, "ring reused after the Invalid verdict");

    // The ring survives a save and load.
    let dir = std::env::temp_dir().join(format!("bs-rings-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.bin");
    let kdf = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };
    save(&carol, &path, b"pw", kdf).unwrap();
    let mut carol = load(&path, b"pw").unwrap();
    std::fs::remove_dir_all(&dir).ok();
    carol.clear_pending();
    let fourth = spend(&mut carol, &mut net);
    assert_eq!(third, fourth, "ring reused after a restart");
}

/// A refusal does not unpin the rings: the node's answer cannot be verified
/// (a node could claim "Invalid" and relay anyway), and reusing a ring that
/// never became public costs nothing (docs/reviews/wallet-review.md, review F5).
#[test]
fn a_refused_transaction_still_pins_its_rings() {
    let mut net = Net::start();
    let mut miner = wallet(29);
    let bob = wallet(30);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let node = Flaky::new(&net.client, Submit::Invalid);
    let err = miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap_err();
    assert!(matches!(err, WalletError::Rejected(_)), "{err}");
    assert!(!miner.has_pending(), "the inputs are released");
    let refused = rings_of(&node.sent.borrow()[0]);
    let node = Flaky::new(&net.client, Submit::Record);
    miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    let next = rings_of(&node.sent.borrow()[0]);
    for (k, r) in &refused {
        if let Some(n) = next.get(k) {
            assert_eq!(n, r, "the ring is reused");
        }
    }
}

/// The node never learns which ring member is real from the wallet's
/// queries: every `/outputs` request contains the real output, and there is
/// exactly one request per input (review F2).
#[test]
fn ring_queries_never_single_out_the_real_input() {
    let mut net = Net::start();
    let mut miner = wallet(31);
    let bob = wallet(32);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let node = Flaky::new(&net.client, Submit::Record);
    miner
        .transfer(&node, &bob.primary(), 3 * COIN, &net.rules, &mut net.rng)
        .unwrap();
    let rings = rings_of(&node.sent.borrow()[0]);
    let queries = node.queries.borrow();
    assert_eq!(queries.len(), rings.len(), "one request per input");
    for ring in rings.values() {
        // The request for this ring contains all 16 members.
        assert!(
            queries.iter().any(|q| ring.iter().all(|i| q.contains(i))),
            "a request contains the whole ring, the real input included"
        );
    }
}

/// A node behind the wallet makes it rewind, but it must not forget its
/// stored transactions or rings; once the node catches up, the inputs are
/// reserved again (review F3).
#[test]
fn a_node_behind_the_wallet_does_not_make_it_forget_its_transactions() {
    let mut net = Net::start();
    let mut miner = wallet(33);
    let bob = wallet(34);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let node = Flaky::new(&net.client, Submit::Record);
    miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    let first = rings_of(&node.sent.borrow()[0]);
    assert!(miner.has_pending());
    // A node far behind: the wallet rewinds below every input.
    let mut behind = Flaky::new(&net.client, Submit::Forward);
    behind.height_cap = Some(5);
    miner.sync(&behind).unwrap();
    assert_eq!(miner.synced_height(), 5);
    // Caught up: the stored transaction is still there, its inputs reserved.
    miner.sync(&net.client).unwrap();
    assert!(miner.has_pending(), "reserved again");
    miner.clear_pending();
    let node = Flaky::new(&net.client, Submit::Record);
    miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap();
    let again = rings_of(&node.sent.borrow()[0]);
    for (k, r) in &first {
        if let Some(n) = again.get(k) {
            assert_eq!(n, r, "the ring survived the rewind");
        }
    }
}

/// Save-before-send: with autosave, a transaction whose outcome is unknown
/// is already on disk with its reservation, without any later save (review F1).
#[test]
fn the_wallet_is_saved_before_a_transaction_leaves_it() {
    let mut net = Net::start();
    let mut miner = wallet(35);
    let bob = wallet(36);
    let miner_addr = miner.primary();
    net.mine_n(90, &miner_addr);
    miner.sync(&net.client).unwrap();
    let dir = std::env::temp_dir().join(format!("bs-autosave-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.bin");
    let kdf = KdfParams {
        m_kib: 256,
        t: 1,
        p: 1,
    };
    miner.set_autosave(&path, b"pw", kdf);
    let mut node = Flaky::new(&net.client, Submit::ForwardThenFail);
    node.check_file = Some(path.clone());
    let err = miner
        .transfer(&node, &bob.primary(), COIN, &net.rules, &mut net.rng)
        .unwrap_err();
    assert!(matches!(err, WalletError::Uncertain(_)));
    assert_eq!(
        node.saved_before_submit.get(),
        Some(true),
        "on disk, reserved, when the transaction was handed to the node"
    );
    // As if the process had been killed now: only what is on disk remains.
    drop(miner);
    let on_disk = load(&path, b"pw").unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        on_disk.has_pending(),
        "the reservation was saved before sending"
    );
}

/// A reorganization deeper than the wallet's 720 kept block ids makes it
/// rescan from its restore height; before the fix it was taken for a fresh
/// wallet and kept outputs of the abandoned branch (review F4).
#[test]
fn a_reorganization_deeper_than_the_kept_window_rescans() {
    let mut net = Net::start();
    let mut miner = wallet(37);
    let other = wallet(38);
    let miner_addr = miner.primary();
    net.mine_n(20, &miner_addr);
    let fork_parent = { net.shared.lock().unwrap().tip_id() };
    net.mine_n(740, &miner_addr);
    miner.sync(&net.client).unwrap();
    assert_eq!(miner.synced_height(), 760);
    // A heavier branch from height 20, paying someone else.
    let mut tip = fork_parent;
    for i in 0..741 {
        tip = net.mine_on(&tip, &other.primary(), 10_000 + i);
    }
    assert_eq!(net.client.info().unwrap().height, 761);
    miner.sync(&net.client).unwrap();
    assert_eq!(miner.synced_height(), 761);
    let mut expected = 0u64;
    for h in 1..=20 {
        expected += block_reward(h, expected);
    }
    assert_eq!(
        miner.balance().total,
        expected,
        "only the first 20 rewards remain"
    );
}
