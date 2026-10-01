//! PX in consensus (docs/px.md §11): real PX transactions and a private
//! contract deploy, validated as blocks and applied to the chain state, with
//! the attacks consensus must stop.

mod common;

use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_px_core::kernel::Witness;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{PxDeploy, PxTx, Registration, Window, ABI_VERSION};
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, FunctionRun, PxPlan};
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_mempool_tx, ChainView};
use blacksilk_tx::{BlockError, TxError};
use common::*;

/// A wallet's view of the PX part of the chain: the tree and its records.
struct PxWallet {
    account: Account,
    /// Received and unspent: (address index, record, position).
    records: Vec<(u32, Record, u64)>,
}

impl PxWallet {
    fn new(seed: u8) -> Self {
        Self {
            account: Account::from_seed(&[seed; 32]),
            records: Vec::new(),
        }
    }

    /// Scans every PX record of the chain with addresses 0..4 (docs/px.md §6).
    fn scan(&mut self, chain: &MemoryChain) {
        self.records.clear();
        let mut perm = HostPerm::new();
        let spent: Vec<Digest> = chain
            .px_nullifiers(0, u64::MAX)
            .into_iter()
            .map(|x| x.1)
            .collect();
        for e in chain.px_records(0, u64::MAX) {
            let rho = blacksilk_px_core::record::output_rho(&mut perm, &e.nf0, e.slot);
            for index in 0..4 {
                let keys = self.account.delivery_keys(index);
                if let Some(rec) = delivery::open(
                    &keys,
                    &self.account.owner(index),
                    &e.ciphertext,
                    &e.commitment,
                    &rho,
                ) {
                    let nf = blacksilk_px_core::record::nullifier(
                        &mut perm,
                        &self.account.keys().nk,
                        &rec.rho,
                        &e.commitment,
                    );
                    if !spent.contains(&nf) {
                        self.records.push((index, rec, e.position));
                    }
                }
            }
        }
    }

    fn balance(&self) -> u64 {
        self.records.iter().map(|r| r.1.value).sum()
    }
}

/// The full commitment tree of the chain (wallets keep one for paths).
fn tree(chain: &MemoryChain) -> Tree {
    let mut perm = HostPerm::new();
    let mut t = Tree::new(&mut perm);
    for e in chain.px_records(0, u64::MAX) {
        assert_eq!(t.append(&mut perm, e.commitment).unwrap(), e.position);
    }
    assert_eq!(t.root(), chain.px().root());
    t
}

fn empty_witness(
    net: &mut TestNet,
    bridge_in: u64,
    bridge_out: u64,
    outputs: [blacksilk_px_core::kernel::OutputWitness; 2],
) -> Witness {
    let root = net.chain.px().root();
    pxw::witness(
        root,
        bridge_in,
        bridge_out,
        [
            pxw::dummy_input(&mut net.rng),
            pxw::dummy_input(&mut net.rng),
        ],
        outputs,
    )
}

fn px_block(net: &mut TestNet, txs: Vec<Transaction>) -> Result<(), BlockError> {
    let fees: u64 = txs.iter().map(Transaction::fee).sum();
    let mut all = vec![net.coinbase(fees)];
    all.extend(txs);
    net.submit(all, &mut [])
}

/// Miner funds bridge `amount` into PX, paid to `to` (output slot 0).
fn bridge_in(net: &mut TestNet, to: &PxWallet, amount: u64) -> PxTx {
    bridge_in_skipping(net, to, amount, 0)
}

/// As [`bridge_in`], funded by the miner's `skip`-th suitable output.
fn bridge_in_skipping(net: &mut TestNet, to: &PxWallet, amount: u64, skip: usize) -> PxTx {
    let fee = px_standard_fee();
    let miner = net.miner_clone();
    let height = net.height();
    let real = miner
        .spendable(height)
        .into_iter()
        .filter(|o| o.received.amount as u128 >= amount as u128 + fee as u128)
        .nth(skip)
        .expect("a large enough miner output")
        .clone();
    let plan = net.plan(&real);
    let out0 = pxw::output(&mut net.rng, to.account.owner(0), amount);
    let out1 = pxw::empty_output(&mut net.rng);
    let witness = empty_witness(net, amount, 0, [out0, out1]);
    let rules = net.rules;
    build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.primary()),
            payouts: vec![],
            witness,
            recipients: [Some(to.account.address(0)), None],
            functions: vec![],
            fee,
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    )
    .expect("bridge-in builds")
}

#[test]
fn private_payments_through_consensus() {
    let mut net = TestNet::new(71, 130);
    let mut alice = PxWallet::new(1);
    let mut bob = PxWallet::new(2);
    let fee = px_standard_fee();

    // 1. Bridge-in: v1 funds into PX (the fee is paid from v1).
    let t = std::time::Instant::now();
    let tx = bridge_in(&mut net, &alice, 50_000_000);
    println!(
        "bridge-in built in {:.1?}, {} bytes",
        t.elapsed(),
        tx.encoded_len()
    );
    let tx = Transaction::Px(Box::new(tx));
    assert_eq!(
        validate_mempool_tx(&tx, &net.chain, net.height(), &net.rules),
        Ok(())
    );
    px_block(&mut net, vec![tx.clone()]).expect("bridge-in block");
    assert_eq!(net.chain.px_pool(), 50_000_000);
    alice.scan(&net.chain);
    assert_eq!(alice.balance(), 50_000_000);

    // A replay of the same transaction is refused (key image and nullifiers).
    assert!(px_block(&mut net, vec![tx]).is_err());

    // 2. Alice pays Bob privately; the fee comes out of PX (bridge_out = fee).
    let tr = tree(&net.chain);
    let (index, rec, pos) = alice.records[0];
    let input = alice.account.spend(index, &rec, pos, tr.path(pos).unwrap());
    let outs = [
        pxw::output(&mut net.rng, bob.account.owner(1), 30_000_000),
        pxw::output(&mut net.rng, alice.account.owner(2), 20_000_000 - fee),
    ];
    let w = pxw::witness(
        tr.root(),
        0,
        fee,
        [input, pxw::dummy_input(&mut net.rng)],
        outs,
    );
    let rules = net.rules;
    let pay = build_px(
        PxPlan {
            keys: None,
            inputs: vec![],
            change: None,
            payouts: vec![],
            witness: w,
            recipients: [Some(bob.account.address(1)), Some(alice.account.address(2))],
            functions: vec![],
            fee,
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    )
    .expect("payment builds");
    // The fee is exactly the standard fee (privacy review P-7): a higher or
    // lower one is refused before the proof is even looked at.
    for delta in [1i64, -1] {
        let mut t2 = pay.clone();
        t2.fee = (t2.fee as i64 + delta) as u64;
        t2.bridge_out = (t2.bridge_out as i64 + delta) as u64; // keeps v1 balanced
        assert_eq!(
            validate_mempool_tx(
                &Transaction::Px(Box::new(t2.clone())),
                &net.chain,
                net.height(),
                &net.rules
            ),
            Err(TxError::PxFeeNotStandard { fee: t2.fee })
        );
    }
    // Tampering is detected: any other public change breaks the proof binding.
    let mut t3 = pay.clone();
    t3.ciphertexts[0][100] ^= 1;
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(t3)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxProof)
    );
    // The same transaction on another network does not verify.
    let mut other = net.rules;
    other.network_id ^= 1;
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(pay.clone())),
            &net.chain,
            net.height(),
            &other
        ),
        Err(TxError::PxProof)
    );
    // Block level: a corrupted proof is refused (PX5). A proof cache keyed by
    // transaction id (validate_block_transactions_cached) cannot be used to
    // smuggle one in: the id commits to the proof bytes.
    let mut t4 = pay.clone();
    let mid = t4.proof.len() / 2;
    t4.proof[mid] ^= 1;
    let t4 = Transaction::Px(Box::new(t4));
    let pay = Transaction::Px(Box::new(pay));
    assert_ne!(t4.hash(), pay.hash());
    assert!(matches!(
        px_block(&mut net, vec![t4]),
        Err(BlockError::Tx {
            error: TxError::PxProof,
            ..
        })
    ));
    px_block(&mut net, vec![pay.clone()]).expect("payment block");
    assert_eq!(net.chain.px_pool(), 50_000_000 - fee as u128);
    alice.scan(&net.chain);
    bob.scan(&net.chain);
    assert_eq!(bob.balance(), 30_000_000);
    assert_eq!(alice.balance(), 20_000_000 - fee);
    // Double spend of the same record in a later block: refused.
    assert!(matches!(
        px_block(&mut net, vec![pay]),
        Err(BlockError::Tx {
            error: TxError::PxNullifierSpent { .. },
            ..
        })
    ));

    // 3. Bob bridges out to a clear v1 payout.
    let mut bob_v1 = Wallet::new(&mut net.rng);
    let tr = tree(&net.chain);
    let (index, rec, pos) = bob.records[0];
    let input = bob.account.spend(index, &rec, pos, tr.path(pos).unwrap());
    let out_amount = 30_000_000 - fee;
    let w = pxw::witness(
        tr.root(),
        0,
        30_000_000,
        [input, pxw::dummy_input(&mut net.rng)],
        [
            pxw::empty_output(&mut net.rng),
            pxw::empty_output(&mut net.rng),
        ],
    );
    let out = build_px(
        PxPlan {
            keys: None,
            inputs: vec![],
            change: None,
            payouts: vec![Payment {
                address: bob_v1.primary(),
                amount: out_amount,
            }],
            witness: w,
            recipients: [None, None],
            functions: vec![],
            fee,
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    )
    .expect("bridge-out builds");
    let fees = out.fee;
    let mut all = vec![net.coinbase(fees), Transaction::Px(Box::new(out))];
    let all2 = all.clone();
    net.submit(std::mem::take(&mut all), &mut [&mut bob_v1])
        .expect("bridge-out block");
    assert_eq!(bob_v1.balance(), out_amount as u128);
    assert_eq!(
        net.chain.px_pool(),
        50_000_000 - 2 * fee as u128 - out_amount as u128
    );

    // 4. A reorganization undoes PX state exactly.
    let (root, pool) = (net.chain.px().root(), net.chain.px_pool());
    assert!(net.chain.undo_block());
    assert_ne!(net.chain.px().root(), root);
    let ctx = net.context(&all2);
    blacksilk_tx::validate::validate_block_transactions(
        &all2,
        &ctx,
        &net.chain,
        &net.rules,
        &mut net.rng,
    )
    .expect("the undone block is valid again");
    net.chain.apply_block(&all2).unwrap();
    assert_eq!((net.chain.px().root(), net.chain.px_pool()), (root, pool));
}

/// A transaction cannot create PX value, and anchors must be recent. (The
/// pool rule itself, `pool ≥ 0`, can only be reached with an invalid proof;
/// it is tested at the state level in `px/tests/state.rs`.)
#[test]
fn value_cannot_be_created_and_anchors_must_be_recent() {
    let mut net = TestNet::new(72, 130);
    let alice = PxWallet::new(3);
    let fee = px_standard_fee();
    // Paying a fee out of PX with nothing inside: no witness exists.
    let rules = net.rules;
    let outs = [
        pxw::empty_output(&mut net.rng),
        pxw::empty_output(&mut net.rng),
    ];
    let w = empty_witness(&mut net, 0, fee, outs);
    let drain = build_px(
        PxPlan {
            keys: None,
            inputs: vec![],
            change: None,
            payouts: vec![],
            witness: w,
            recipients: [None, None],
            functions: vec![],
            fee,
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    );
    // The kernel itself refuses: dummy inputs have no value to pay the fee.
    assert!(drain.is_err());

    // A stale anchor (older than the root window) is refused: build a
    // transaction on the current root, change the tree, then let the window
    // move past the old root.
    let tx = bridge_in(&mut net, &alice, 10_000_000);
    let other = bridge_in_skipping(&mut net, &alice, 10_000_000, 1);
    px_block(&mut net, vec![Transaction::Px(Box::new(other))]).expect("tree changes");
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(tx.clone())),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Ok(()),
        "a root of the last block is still a valid anchor"
    );
    for _ in 0..blacksilk_px::state::ROOT_WINDOW {
        net.mine(vec![], &mut []).unwrap();
    }
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(tx)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxUnknownAnchor)
    );
}

/// A deploy of the reference vault (its registered budget, ABI and output
/// words) from the miner's first spendable output.
fn vault_deploy(net: &mut TestNet, salt: u8) -> PxDeploy {
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plan = net.plan(&real);
    let rules = net.rules;
    build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [salt; 32],
        vec![Registration::new(
            vault::VAULT_ELF.to_vec(),
            vault::BUDGET,
            vault::OUT_WORDS,
        )],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// LOCK: the miner bridges `value` into a vault record of `contract` under
/// `terms` (output slot 0), mined in a block. Returns the vault record.
fn lock_vault(net: &mut TestNet, contract: Digest, value: u64, terms: &vault::Terms) -> Record {
    let blind = pxw::random_digest(&mut net.rng);
    let window = Window::UNBOUNDED;
    let (lock_input, fw) = vault::lock_call(&contract, value, terms, 0, &blind, &window);
    let fee = px_standard_fee();
    let miner = net.miner_clone();
    let real = miner
        .spendable(net.height())
        .into_iter()
        .find(|o| o.received.amount as u128 >= (value + fee) as u128)
        .unwrap()
        .clone();
    let plan = net.plan(&real);
    let data = terms.data(&contract);
    let outs = [
        pxw::contract_output(&mut net.rng, contract, value, data),
        pxw::empty_output(&mut net.rng),
    ];
    let mut w = empty_witness(net, value, 0, outs.clone());
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let rules = net.rules;
    let lock_tx = build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.primary()),
            payouts: vec![],
            witness: w,
            recipients: [None, None],
            functions: vec![FunctionRun {
                program: vault::program(),
                input: lock_input,
                budget: vault::BUDGET,
            }],
            fee,
            window,
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    )
    .expect("LOCK builds");
    let rho =
        blacksilk_px_core::record::output_rho(&mut HostPerm::new(), &lock_tx.nullifiers[0], 0);
    let rec = Record {
        owner: ZERO_DIGEST,
        contract,
        asset: ZERO_DIGEST,
        value,
        data,
        rho,
        rcm: outs[0].rcm,
    };
    assert_eq!(rec.commit(&mut HostPerm::new()), lock_tx.commitments[0]);
    px_block(net, vec![Transaction::Px(Box::new(lock_tx))]).expect("LOCK block");
    rec
}

/// A CLAIM (`vault::CLAIM`, with the claim secret) or a REFUND
/// (`vault::REFUND`, with the refund secret) of the vault record `rec` under
/// `terms`, paying `to`, in a transaction with validity window `window`; the
/// fee comes from the miner's v1 funds. Built and proven, not mined.
#[allow(clippy::too_many_arguments)]
fn release_vault(
    net: &mut TestNet,
    selector: u32,
    rec: &Record,
    secret: &Digest,
    terms: &vault::Terms,
    to: &PxWallet,
    window: Window,
) -> PxTx {
    let tr = tree(&net.chain);
    let cm = rec.commit(&mut HostPerm::new());
    let pos = net
        .chain
        .px_records(0, u64::MAX)
        .iter()
        .find(|e| e.commitment == cm)
        .unwrap()
        .position;
    let blind = pxw::random_digest(&mut net.rng);
    let recipient = to.account.owner(0);
    let (input, fw) = if selector == vault::CLAIM {
        vault::claim_call(rec, secret, terms, &recipient, 0, 0, &blind, &window)
    } else {
        vault::refund_call(rec, secret, terms, &recipient, 0, 0, &blind, &window)
    };
    let fee = px_standard_fee();
    let miner = net.miner_clone();
    let real = miner
        .spendable(net.height())
        .into_iter()
        .find(|o| o.received.amount as u128 >= fee as u128)
        .unwrap()
        .clone();
    let plan = net.plan(&real);
    let mut w = pxw::witness(
        tr.root(),
        0,
        0,
        [
            pxw::contract_input(&mut net.rng, rec, pos, tr.path(pos).unwrap()),
            pxw::dummy_input(&mut net.rng),
        ],
        [
            pxw::output(&mut net.rng, recipient, rec.value),
            pxw::empty_output(&mut net.rng),
        ],
    );
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let rules = net.rules;
    build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.primary()),
            payouts: vec![],
            witness: w,
            recipients: [Some(to.account.address(0)), None],
            functions: vec![FunctionRun {
                program: vault::program(),
                input,
                budget: vault::BUDGET,
            }],
            fee,
            window,
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut net.rng,
    )
    .expect("the release builds")
}

#[test]
fn a_private_contract_is_deployed_and_used_through_consensus() {
    let mut net = TestNet::new(73, 130);
    let mut bob = PxWallet::new(4);

    // Deploy the vault contract.
    let deploy = vault_deploy(&mut net, 9);
    let contract = deploy.contract_id();
    let vault = vault::program();
    let dtx = Transaction::PxDeploy(Box::new(deploy));
    assert_eq!(
        validate_mempool_tx(&dtx, &net.chain, net.height(), &net.rules),
        Ok(())
    );
    let deploy_block = vec![net.coinbase(dtx.fee()), dtx.clone()];
    net.submit(deploy_block.clone(), &mut [])
        .expect("deploy block");
    assert!(net.chain.px_contract_exists(&contract));
    // The registration list wallets download (`/px/contracts`) gains the
    // contract, and a reorganization removes it again exactly.
    let deploy_height = net.height() - 1;
    assert_eq!(
        net.chain.px_contract_log().last(),
        Some(&(deploy_height, contract))
    );
    let log_len = net.chain.px_contract_log().len();
    assert!(net.chain.undo_block());
    assert!(!net.chain.px_contract_exists(&contract));
    assert_eq!(net.chain.px_contract_log().len(), log_len - 1);
    net.chain.apply_block(&deploy_block).unwrap();
    assert_eq!(
        net.chain.px_contract_log().last(),
        Some(&(deploy_height, contract))
    );
    assert!(net.chain.px_contract_exists(&contract));
    // The registry records the budget, the call ABI and the output words.
    assert_eq!(
        net.chain
            .px_function(&contract, &vault.id())
            .map(|f| (f.budget, f.abi, f.out_words)),
        Some((vault::BUDGET, ABI_VERSION, vault::OUT_WORDS))
    );
    // The same deploy again: refused (key image, and the contract id).
    assert!(px_block(&mut net, vec![dtx]).is_err());

    // LOCK: the miner bridges 5 000 000 into a vault record of the contract,
    // claimable with the secret, without a timeout.
    let secret: Digest = [5, 6, 7, 8, 9, 10, 11, 12];
    let terms = vault::Terms::claim_only(&contract, &secret);
    let value = 5_000_000u64;
    let vault_rec = lock_vault(&mut net, contract, value, &terms);

    // CLAIM: Bob, knowing the secret, takes the vault's value privately.
    let claim = release_vault(
        &mut net,
        vault::CLAIM,
        &vault_rec,
        &secret,
        &terms,
        &bob,
        Window::UNBOUNDED,
    );
    // An unregistered program cannot stand in for the contract's function.
    let mut forged = claim.clone();
    forged.functions[0].program_id[0] ^= 1;
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(forged)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxUnregistered { function: 0 })
    );
    // F-28-5: a call publishing another number of output words than its
    // program's registered `out_words` is refused, before the proof.
    let mut padded = claim.clone();
    padded.functions[0].outputs.push(0);
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(padded)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxOutputWords { function: 0 })
    );
    assert!(TxError::PxOutputWords { function: 0 }.is_stateless());
    // PX6: the window is in the prefix, so it is covered by the v1
    // signatures (checked before PX5; this claim pays its fee from v1 funds)
    // and by h_tx, the proof's binding (px/tests/unified.rs checks that the
    // proof alone refuses another window). The same transaction with another
    // window is refused.
    let mut rewindowed = claim.clone();
    rewindowed.window.not_after = net.height() + 100;
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(rewindowed)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::InvalidSignature { input: 0 })
    );
    // PX5's shape step (dossier 10 F10-2): a well-formed proof of another
    // statement shape is refused as the stateless `PxProof` once PX3 holds,
    // before any ring or CLSAG. Here the claim's one-function proof sits in
    // the same transaction with its call removed (a kernel-only statement),
    // which also breaks its CLSAG: the shape step reports it first.
    let mut reshaped = claim.clone();
    reshaped.functions.clear();
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(reshaped)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxProof)
    );
    // The CLAIM is mined together with a kernel-only bridge-in, both proofs
    // verified by the block (no cache): each proof is shape-checked against
    // its own statement, whatever the other transactions of the block are
    // (run C mutation census: a block of one statement shape did not
    // notice a proof checked against another transaction's statement).
    let carol = PxWallet::new(5);
    let deposit = bridge_in_skipping(&mut net, &carol, 1_000_000, 1);
    assert_ne!(deposit.inputs[0].key_image, claim.inputs[0].key_image);
    assert!(deposit.functions.is_empty());
    px_block(
        &mut net,
        vec![
            Transaction::Px(Box::new(deposit)),
            Transaction::Px(Box::new(claim)),
        ],
    )
    .expect("CLAIM block");
    bob.scan(&net.chain);
    assert_eq!(bob.balance(), value);
    // The vault record is spent: its nullifier is on chain. The pool holds
    // the locked value and the bridge-in.
    assert_eq!(net.chain.px_pool(), value as u128 + 1_000_000);
}

/// PX6 and the vault refund (W28-4) through consensus, with real proofs: a
/// vault locked with a timeout `T` is refunded by a transaction whose window
/// starts at `T`. The refund is premature at `T − 1` (contextual, never
/// scored), valid at `T` and later, and a block at `T − 1` cannot include
/// it, even when its proof was already verified (the cache vouches only for
/// the proof, AT-5).
#[test]
fn a_vault_refund_obeys_its_validity_window_through_consensus() {
    let mut net = TestNet::new(79, 130);
    let mut carol = PxWallet::new(6);
    let deploy = vault_deploy(&mut net, 11);
    let contract = deploy.contract_id();
    px_block(&mut net, vec![Transaction::PxDeploy(Box::new(deploy))]).expect("deploy block");

    let secret: Digest = [21, 22, 23, 24, 25, 26, 27, 28];
    let refund_secret: Digest = [31, 32, 33, 34, 35, 36, 37, 38];
    let timeout = net.height() + 3;
    let terms = vault::Terms {
        claim_lock: vault::lock_of(&contract, &secret),
        refund_lock: vault::refund_lock_of(&contract, &refund_secret),
        timeout,
    };
    let value = 3_000_000u64;
    let rec = lock_vault(&mut net, contract, value, &terms);
    assert!(net.height() < timeout);

    let window = Window {
        not_before: timeout,
        not_after: 0,
    };
    let refund = Transaction::Px(Box::new(release_vault(
        &mut net,
        vault::REFUND,
        &rec,
        &refund_secret,
        &terms,
        &carol,
        window,
    )));
    // Every height below T: premature, contextual (a relaying peer is not
    // penalized).
    for h in net.height()..timeout {
        assert_eq!(
            validate_mempool_tx(&refund, &net.chain, h, &net.rules),
            Err(TxError::PxWindow),
            "height {h}"
        );
    }
    assert!(!TxError::PxWindow.is_stateless());
    // At T and after: valid, proof included.
    for h in [timeout, timeout + 1, timeout + 1000] {
        assert_eq!(
            validate_mempool_tx(&refund, &net.chain, h, &net.rules),
            Ok(()),
            "height {h}"
        );
    }
    // Mine up to T − 1: a block at T − 1 cannot include the refund, even with
    // its proof vouched for by the cache.
    while net.height() < timeout - 1 {
        net.mine(vec![], &mut []).unwrap();
    }
    assert_eq!(net.height(), timeout - 1);
    let fees = refund.fee();
    let early = vec![net.coinbase(fees), refund.clone()];
    let ctx = net.context(&early);
    let vouched = |_: &blacksilk_tx::types::Hash| true;
    assert_eq!(
        blacksilk_tx::validate::validate_block_transactions_cached(
            &early,
            &ctx,
            &net.chain,
            &net.rules,
            &mut net.rng,
            &vouched
        ),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxWindow
        })
    );
    net.mine(vec![], &mut []).unwrap();
    assert_eq!(net.height(), timeout);
    px_block(&mut net, vec![refund]).expect("the refund at T");
    carol.scan(&net.chain);
    assert_eq!(carol.balance(), value);
}
