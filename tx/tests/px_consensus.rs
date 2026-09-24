//! PX in consensus (docs/px.md §11): real PX transactions and a private
//! contract deploy, validated as blocks and applied to the chain state, with
//! the attacks consensus must stop.

mod common;

use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_px_core::call::OutSpec;
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::{FunctionWitness, Witness};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{PxTx, Registration};
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, FunctionRun, PxPlan};
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_mempool_tx, ChainView};
use blacksilk_tx::{BlockError, TxError};
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use common::*;
use std::sync::Arc;

const VAULT_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../px/tests/fixtures/vault.elf"
));
const VAULT_BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_200,
    add: 4_300,
    bit: 200,
    lt: 3_400,
    shift: 200,
    mul: 200,
    poseidon: 22,
};
const LOCK: u32 = 0x5641_0001;

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
        },
        &rules,
        &mut net.rng,
    )
    .expect("payment builds");
    // Tampering is detected: any public change breaks the proof binding.
    let mut t2 = pay.clone();
    t2.bridge_out += 1;
    t2.fee += 1;
    assert_eq!(
        validate_mempool_tx(
            &Transaction::Px(Box::new(t2)),
            &net.chain,
            net.height(),
            &net.rules
        ),
        Err(TxError::PxProof)
    );
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
    net.chain.apply_block(&all2);
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

#[test]
fn a_private_contract_is_deployed_and_used_through_consensus() {
    let mut net = TestNet::new(73, 130);
    let mut bob = PxWallet::new(4);
    let miner = net.miner_clone();
    let rules = net.rules;

    // Deploy the vault contract.
    let height = net.height();
    let real = miner.spendable(height)[0].clone();
    let plan = net.plan(&real);
    let deploy = build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [9; 32],
        vec![Registration {
            elf: VAULT_ELF.to_vec(),
            budget: VAULT_BUDGET,
        }],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds");
    let contract = deploy.contract_id();
    let vault = Arc::new(Program::from_elf(VAULT_ELF).unwrap());
    let dtx = Transaction::PxDeploy(Box::new(deploy));
    assert_eq!(
        validate_mempool_tx(&dtx, &net.chain, net.height(), &net.rules),
        Ok(())
    );
    px_block(&mut net, vec![dtx.clone()]).expect("deploy block");
    assert!(net.chain.px_contract_exists(&contract));
    assert_eq!(
        net.chain.px_function(&contract, &vault.id()).map(|f| f.1),
        Some(VAULT_BUDGET)
    );
    // The same deploy again: refused (key image, and the contract id).
    assert!(px_block(&mut net, vec![dtx]).is_err());

    // LOCK: the miner bridges 5 000 000 into a vault record of the contract.
    let secret: Digest = [5, 6, 7, 8, 9, 10, 11, 12];
    let lock = hash(&mut HostPerm::new(), LOCK, &[&secret]);
    let blind = pxw::random_digest(&mut net.rng);
    let value = 5_000_000u64;
    let lock_input: Vec<u32> = [
        &[0u32][..],
        &contract,
        &blind,
        &[value as u32, (value >> 32) as u32],
        &lock,
        &[0],
    ]
    .concat();
    let fw = FunctionWitness {
        contract,
        blind,
        approve: [false; 2],
        spec: [
            Some(OutSpec {
                owner: ZERO_DIGEST,
                contract,
                value,
                data: lock,
            }),
            None,
        ],
    };
    let fee = px_standard_fee();
    let height = net.height();
    let miner = net.miner_clone();
    let real = miner
        .spendable(height)
        .into_iter()
        .find(|o| o.received.amount as u128 >= (value + fee) as u128)
        .unwrap()
        .clone();
    let plan = net.plan(&real);
    let outs = [
        pxw::contract_output(&mut net.rng, contract, value, lock),
        pxw::empty_output(&mut net.rng),
    ];
    let mut w = empty_witness(&mut net, value, 0, outs.clone());
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let lock_tx = build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.primary()),
            payouts: vec![],
            witness: w,
            recipients: [None, None],
            functions: vec![FunctionRun {
                program: vault.clone(),
                input: lock_input,
                budget: VAULT_BUDGET,
            }],
            fee,
        },
        &rules,
        &mut net.rng,
    )
    .expect("LOCK builds");
    let nf0 = lock_tx.nullifiers[0];
    let lock_cm = lock_tx.commitments[0];
    px_block(&mut net, vec![Transaction::Px(Box::new(lock_tx))]).expect("LOCK block");

    // CLAIM: Bob, knowing the secret, takes the vault's value privately.
    let rho = blacksilk_px_core::record::output_rho(&mut HostPerm::new(), &nf0, 0);
    let vault_rec = Record {
        owner: ZERO_DIGEST,
        contract,
        asset: ZERO_DIGEST,
        value,
        data: lock,
        rho,
        rcm: outs[0].rcm,
    };
    assert_eq!(vault_rec.commit(&mut HostPerm::new()), lock_cm);
    let tr = tree(&net.chain);
    let pos = net
        .chain
        .px_records(0, u64::MAX)
        .iter()
        .find(|e| e.commitment == lock_cm)
        .unwrap()
        .position;
    let blind = pxw::random_digest(&mut net.rng);
    let recipient = bob.account.owner(0);
    let claim_input: Vec<u32> = [
        &[1u32][..],
        &contract,
        &blind,
        &[value as u32, (value >> 32) as u32],
        &lock,
        &rho,
        &vault_rec.rcm,
        &secret,
        &recipient,
        &[0, 0],
    ]
    .concat();
    let fw = FunctionWitness {
        contract,
        blind,
        approve: [true, false],
        spec: [
            Some(OutSpec {
                owner: recipient,
                contract: ZERO_DIGEST,
                value,
                data: [0; 8],
            }),
            None,
        ],
    };
    let height = net.height();
    let miner = net.miner_clone();
    let real = miner
        .spendable(height)
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
            pxw::contract_input(&mut net.rng, &vault_rec, pos, tr.path(pos).unwrap()),
            pxw::dummy_input(&mut net.rng),
        ],
        [
            pxw::output(&mut net.rng, recipient, value),
            pxw::empty_output(&mut net.rng),
        ],
    );
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let claim = build_px(
        PxPlan {
            keys: Some(&miner.keys),
            inputs: vec![plan],
            change: Some(miner.primary()),
            payouts: vec![],
            witness: w,
            recipients: [Some(bob.account.address(0)), None],
            functions: vec![FunctionRun {
                program: vault.clone(),
                input: claim_input,
                budget: VAULT_BUDGET,
            }],
            fee,
        },
        &rules,
        &mut net.rng,
    )
    .expect("CLAIM builds");
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
    px_block(&mut net, vec![Transaction::Px(Box::new(claim))]).expect("CLAIM block");
    bob.scan(&net.chain);
    assert_eq!(bob.balance(), value);
    // The vault record is spent: its nullifier is on chain.
    assert_eq!(net.chain.px_pool(), value as u128);
}
