//! One negative test per block rule (B1–B7, the coinbase structure and the
//! PX byte budget), each asserting the exact `BlockError` the chain manager
//! reports, and the block decoding boundaries (dossier 01 F-02;
//! docs/transactions.md §16 "one negative test per rule").
//!
//! Every rejection is paired with the accepted case at the boundary, so a
//! test cannot pass because the block fails for another reason.
//!
//! Covered elsewhere (not repeated here): `DeployBytesExceeded`
//! (`tx/tests/deploy_rules.rs::a_block_over_the_deploy_budget_is_invalid`),
//! `RangeProofBatch` (`tx/tests/adversarial.rs::inflation_with_negative_output_is_rejected`)
//! and the transaction rules reported as `BlockError::Tx` (tx/tests).

use blacksilk_chain::block::{Block, BlockDecodeError, MAX_BLOCK_BYTES, MAX_BLOCK_TXS};
use blacksilk_chain::manager::{ChainManager, SubmitError, Submitted};
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_crypto::Point;
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::codec::{DecodeError, Writer};
use blacksilk_tx::params::{
    TxRules, MAX_COINBASE_OUTPUTS, MAX_PX_BLOCK_BYTES, MAX_PX_TX_SIZE, PX_STANDARD_FEE,
};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::types::{Coinbase, CoinbaseOutput, Transaction};
use blacksilk_tx::validate::{
    validate_block_transactions, BlockContext, BlockError, ChainView, TxError,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

/// Zero hash: meets any difficulty (PoW is not under test here).
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

struct Env {
    m: ChainManager,
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Env {
    fn new() -> Self {
        Self::with_rules(TxRules::for_chain(&params()))
    }

    /// A manager with caller-supplied fee/weight rules (`ChainManager::open`
    /// takes them from the caller today, dossier 01 F-07).
    fn with_rules(rules: TxRules) -> Self {
        let m = ChainManager::open(
            params(),
            rules,
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [7; 32],
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0xB10C);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Env { m, keys, rng }
    }

    fn reward(&self) -> u64 {
        self.m.template().reward
    }

    /// A coinbase for the next block with `n` outputs to distinct
    /// subaddresses, paying `total` (split as evenly as possible).
    fn coinbase(&mut self, n: usize, total: u64) -> Coinbase {
        let height = self.m.height() + 1;
        let payouts: Vec<Payment> = (0..n as u64)
            .map(|i| Payment {
                address: self.keys.address(SubaddressIndex::new(0, i as u32 + 1)),
                amount: total / n as u64 + u64::from(i < total % n as u64),
            })
            .collect();
        build_coinbase(height, &payouts, &self.keys.hedge_secret(), &mut self.rng).unwrap()
    }

    /// The next block with exactly `txs` as its body (honest header, correct
    /// `tx_root`).
    fn block(&self, txs: Vec<Transaction>) -> Block {
        let t = self.m.template();
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
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
        };
        Block { header, txs }
    }

    fn submit(&mut self, b: Block) -> Result<Submitted, SubmitError> {
        let now = b.header.timestamp;
        self.m.submit_block(b, now)
    }

    /// Submits `txs` as the next block and returns the body error.
    fn reject(&mut self, txs: Vec<Transaction>) -> BlockError {
        let b = self.block(txs);
        match self.submit(b) {
            Err(SubmitError::Body(e)) => e,
            other => panic!("expected a body rejection, got {other:?}"),
        }
    }

    /// Submits `txs` as the next block, which must connect.
    fn accept(&mut self, txs: Vec<Transaction>) {
        let b = self.block(txs);
        let r = self.submit(b).expect("a valid block");
        assert!(r.on_best_chain);
    }

    fn honest_coinbase(&mut self) -> Transaction {
        let reward = self.reward();
        Transaction::Coinbase(self.coinbase(1, reward))
    }
}

fn identity() -> Point {
    Point::decode(&[0; 32]).unwrap()
}

// ---------------------------------------------------------------- B1, B2, B3

#[test]
fn b1_the_first_transaction_must_be_the_only_coinbase() {
    let mut env = Env::new();
    assert_eq!(env.reject(vec![]), BlockError::MissingCoinbase);
    // A body whose first transaction is not a coinbase.
    let px = Transaction::Px(Box::new(px_tx(1, 1024)));
    assert_eq!(env.reject(vec![px]), BlockError::MissingCoinbase);
    // A second coinbase.
    let reward = env.reward();
    let a = Transaction::Coinbase(env.coinbase(1, reward));
    let b = Transaction::Coinbase(env.coinbase(1, 0));
    assert_eq!(
        env.reject(vec![a.clone(), b]),
        BlockError::UnexpectedCoinbase { index: 1 }
    );
    env.accept(vec![a]);
}

#[test]
fn b2_the_coinbase_height_is_the_block_height() {
    let mut env = Env::new();
    let reward = env.reward();
    for found in [0, 2] {
        let mut cb = env.coinbase(1, reward);
        cb.height = found;
        assert_eq!(
            env.reject(vec![Transaction::Coinbase(cb)]),
            BlockError::CoinbaseHeight { expected: 1, found }
        );
    }
    let cb = env.honest_coinbase();
    env.accept(vec![cb]);
}

#[test]
fn b3_the_coinbase_pays_exactly_reward_plus_fees() {
    let mut env = Env::new();
    let reward = env.reward();
    for claimed in [reward + 1, reward - 1] {
        let cb = Transaction::Coinbase(env.coinbase(1, claimed));
        assert_eq!(
            env.reject(vec![cb]),
            BlockError::CoinbaseAmount {
                claimed: claimed as u128,
                allowed: reward as u128,
            }
        );
    }
    let cb = env.honest_coinbase();
    env.accept(vec![cb]);
}

// ---------------------------------------------------------------- B7: coinbase structure

#[test]
fn b7_coinbase_output_count_is_1_to_16() {
    let mut env = Env::new();
    let reward = env.reward();
    let mut none = env.coinbase(1, reward);
    none.outputs.clear();
    assert_eq!(
        env.reject(vec![Transaction::Coinbase(none)]),
        BlockError::CoinbaseOutputCount(0)
    );
    // 17 outputs: a valid 16-output coinbase plus one more (sorted, distinct
    // and paying the same total, so only the count is wrong).
    let sixteen = env.coinbase(MAX_COINBASE_OUTPUTS, reward);
    let mut seventeen = env.coinbase(MAX_COINBASE_OUTPUTS, reward - 1);
    let extra = env.coinbase(1, 1).outputs[0].clone();
    seventeen.outputs.push(extra);
    seventeen.outputs.sort_by_key(|o| o.one_time_key);
    assert_eq!(
        env.reject(vec![Transaction::Coinbase(seventeen)]),
        BlockError::CoinbaseOutputCount(MAX_COINBASE_OUTPUTS + 1)
    );
    // Exactly 16 is valid.
    env.accept(vec![Transaction::Coinbase(sixteen)]);
}

#[test]
fn b7_coinbase_keys_are_not_the_identity() {
    let mut env = Env::new();
    let reward = env.reward();
    let base = env.coinbase(2, reward);
    for j in 0..2 {
        let mut cb = base.clone();
        cb.outputs[j].one_time_key = identity();
        cb.outputs.sort_by_key(|o| o.one_time_key);
        let output = cb
            .outputs
            .iter()
            .position(|o| o.one_time_key == identity())
            .unwrap();
        assert_eq!(
            env.reject(vec![Transaction::Coinbase(cb)]),
            BlockError::CoinbaseOutputKeyIdentity { output }
        );
        let mut cb = base.clone();
        cb.outputs[j].ephemeral = identity();
        assert_eq!(
            env.reject(vec![Transaction::Coinbase(cb)]),
            BlockError::CoinbaseEphemeralIdentity { output: j }
        );
    }
    env.accept(vec![Transaction::Coinbase(base)]);
}

#[test]
fn b7_coinbase_outputs_are_strictly_sorted() {
    let mut env = Env::new();
    let reward = env.reward();
    let cb = env.coinbase(3, reward);
    let mut unsorted = cb.clone();
    unsorted.outputs.swap(0, 2);
    assert_eq!(
        env.reject(vec![Transaction::Coinbase(unsorted)]),
        BlockError::CoinbaseOutputsNotSorted
    );
    env.accept(vec![Transaction::Coinbase(cb)]);
}

/// Within-transaction one-time-key distinctness of the coinbase. D8 option B
/// keeps this rule: a coinbase repeating a key is rejected (by the strict sort,
/// before any uniqueness set is consulted).
#[test]
fn b7_a_coinbase_repeating_a_one_time_key_is_rejected() {
    let mut env = Env::new();
    let reward = env.reward();
    let mut cb = env.coinbase(2, reward);
    cb.outputs[1].one_time_key = cb.outputs[0].one_time_key;
    assert_eq!(
        env.reject(vec![Transaction::Coinbase(cb)]),
        BlockError::CoinbaseOutputsNotSorted
    );
    let cb = env.honest_coinbase();
    env.accept(vec![cb]);
}

/// D8 option B (docs/reviews/v3-consensus-changes.md §1): a coinbase key
/// equal to an existing output key is valid. It was invalid under the former
/// rule C4 (`CoinbaseDuplicateOneTimeKey`). The replayed output is a second
/// output with the same key at a new global index; the owner's wallet credits
/// at most one of them (docs/transactions.md §12.5).
#[test]
fn b4_a_coinbase_key_already_on_chain_is_valid() {
    let mut env = Env::new();
    let first = env.honest_coinbase();
    env.accept(vec![first.clone()]);
    let Transaction::Coinbase(first) = first else {
        unreachable!()
    };
    let reward = env.reward();
    let replay = Coinbase {
        height: 2,
        outputs: vec![CoinbaseOutput {
            amount: reward,
            ..first.outputs[0].clone()
        }],
    };
    env.accept(vec![Transaction::Coinbase(replay)]);
    let key = first.outputs[0].one_time_key;
    let copies = (0..env.m.state().output_count())
        .filter(|&i| env.m.state().output(i).unwrap().key.one_time_key == key)
        .count();
    assert_eq!(copies, 2);
}

/// D8 option B: a later transaction of the same block reusing a coinbase key
/// is not a block error. Here the transaction is a PX transaction with a
/// payout carrying the coinbase's key; the block fails only at that
/// transaction's own later rule (its padding proof does not decode), never at
/// a key-uniqueness rule (`DuplicateOneTimeKey` under the former C4).
#[test]
fn b4_a_coinbase_key_reused_in_the_same_block_is_not_a_uniqueness_error() {
    let mut env = Env::new();
    let reward = env.reward();
    let cb = env.coinbase(1, reward + PX_STANDARD_FEE);
    let mut px = px_tx(1, 1024);
    px.payouts = vec![CoinbaseOutput {
        amount: 1,
        ..cb.outputs[0].clone()
    }];
    px.bridge_out = PX_STANDARD_FEE + 1;
    assert_eq!(
        env.reject(vec![
            Transaction::Coinbase(cb),
            Transaction::Px(Box::new(px))
        ]),
        BlockError::Tx {
            index: 1,
            error: TxError::PxProof,
        }
    );
}

// ---------------------------------------------------------------- B5, B6

#[test]
fn b5_the_body_must_match_the_tx_root() {
    // The manager compares the body with the header before validation, so a
    // mismatch never reaches the body rules (and the header is not stored).
    let mut env = Env::new();
    let cb = env.honest_coinbase();
    let mut b = env.block(vec![cb.clone()]);
    b.header.tx_root[0] ^= 1;
    assert!(matches!(env.submit(b), Err(SubmitError::BodyMismatch)));
    // The body rule itself, on the same state.
    let txs = vec![cb.clone()];
    let mut ctx = BlockContext {
        height: 1,
        reward: env.reward(),
        tx_root: tx_root(&[cb.hash()]),
    };
    let rules = env.m.next_rules();
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    assert_eq!(
        validate_block_transactions(&txs, &ctx, env.m.state(), &rules, &mut rng),
        Ok(())
    );
    ctx.tx_root[31] ^= 0x80;
    assert_eq!(
        validate_block_transactions(&txs, &ctx, env.m.state(), &rules, &mut rng),
        Err(BlockError::TxRootMismatch)
    );
    env.accept(vec![cb]);
}

#[test]
fn b6_block_weight_is_capped() {
    // The weight of an honest coinbase-only block, then managers whose
    // weight limit is exactly that and one less.
    let mut probe = Env::new();
    let cb = probe.honest_coinbase();
    let weight = cb.weight();
    let rules = |max| TxRules {
        max_block_weight: max,
        ..TxRules::for_chain(&params())
    };
    let mut env = Env::with_rules(rules(weight - 1));
    assert_eq!(
        env.reject(vec![cb.clone()]),
        BlockError::WeightExceeded {
            weight: weight as u128,
            max: weight - 1,
        }
    );
    let mut env = Env::with_rules(rules(weight));
    env.accept(vec![cb]);
}

/// A PX transaction that passes every structure check without a proof: no
/// inputs or outputs, the standard fee paid out of the pool (`bridge_out`),
/// and `proof_bytes` of padding. Its encoded size grows with `proof_bytes`.
fn px_tx(seed: u32, proof_bytes: usize) -> PxTx {
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        anchor: [0; 8],
        nullifiers: [[seed; 8], [seed + 1_000_000; 8]],
        commitments: [[seed + 2; 8], [seed + 3; 8]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![0xA5; proof_bytes],
    }
}

/// A PX transaction of exactly `size` encoded bytes.
fn px_tx_of_size(seed: u32, size: u64) -> PxTx {
    let mut proof = size as usize;
    loop {
        let tx = px_tx(seed, proof);
        let len = tx.encoded_len() as u64;
        if len == size {
            return tx;
        }
        proof = (proof as i64 + size as i64 - len as i64) as usize;
    }
}

fn px_block(env: &mut Env, sizes: &[u64]) -> Vec<Transaction> {
    let reward = env.reward();
    let fees = PX_STANDARD_FEE * sizes.len() as u64;
    let mut txs = vec![Transaction::Coinbase(env.coinbase(1, reward + fees))];
    for (i, &s) in sizes.iter().enumerate() {
        let tx = px_tx_of_size(10 * i as u32 + 1, s);
        assert!(tx.encoded_len() <= MAX_PX_TX_SIZE, "each transaction fits");
        txs.push(Transaction::Px(Box::new(tx)));
    }
    txs
}

#[test]
fn b6_px_bytes_are_capped_at_the_px_budget() {
    let mut env = Env::new();
    let half = MAX_PX_BLOCK_BYTES / 2;
    // MAX + 1 bytes over two transactions of at most MAX_PX_TX_SIZE each.
    let over = px_block(&mut env, &[half, half + 1]);
    let px: u64 = over.iter().map(Transaction::px_bytes).sum();
    assert_eq!(px, MAX_PX_BLOCK_BYTES + 1);
    assert_eq!(
        env.reject(over),
        BlockError::PxBytesExceeded {
            bytes: MAX_PX_BLOCK_BYTES + 1,
            max: MAX_PX_BLOCK_BYTES,
        }
    );
    // Exactly MAX passes the budget and fails only at a later rule of the
    // first PX transaction (its padding proof does not decode).
    let at = px_block(&mut env, &[half, half]);
    let px: u64 = at.iter().map(Transaction::px_bytes).sum();
    assert_eq!(px, MAX_PX_BLOCK_BYTES);
    assert_eq!(
        env.reject(at),
        BlockError::Tx {
            index: 1,
            error: TxError::PxProof
        }
    );
}

// ---------------------------------------------------------------- decoding boundaries

fn header_bytes(env: &Env) -> Vec<u8> {
    env.block(vec![]).header.to_bytes().to_vec()
}

#[test]
fn decode_rejects_more_than_max_block_bytes() {
    let mut env = Env::new();
    let cb = env.honest_coinbase();
    let mut bytes = env.block(vec![cb]).encode();
    // Exactly MAX_BLOCK_BYTES: not refused for size (trailing padding is the
    // only fault).
    bytes.resize(MAX_BLOCK_BYTES, 0);
    assert_eq!(
        Block::decode(&bytes),
        Err(BlockDecodeError::Framing(DecodeError::TrailingBytes))
    );
    bytes.push(0);
    assert_eq!(Block::decode(&bytes), Err(BlockDecodeError::TooLarge));
}

#[test]
fn decode_bounds_the_transaction_count() {
    let mut env = Env::new();
    let header = header_bytes(&env);
    let count_only = |n: u64| {
        let mut w = Writer::new();
        w.bytes(&header);
        w.varint(n);
        w.into_bytes()
    };
    for n in [0, MAX_BLOCK_TXS + 1] {
        assert_eq!(
            Block::decode(&count_only(n)),
            Err(BlockDecodeError::Framing(DecodeError::CountOutOfRange {
                what: "block transactions",
                count: n,
            })),
            "count {n}"
        );
    }
    // MAX_BLOCK_TXS transactions decode (and re-encode canonically); one
    // more, with the same bytes otherwise, does not.
    let cb = env.honest_coinbase();
    let mut b = env.block(vec![cb; MAX_BLOCK_TXS as usize]);
    let bytes = b.encode();
    assert!(bytes.len() <= MAX_BLOCK_BYTES);
    assert_eq!(Block::decode(&bytes).as_ref(), Ok(&b));
    let extra = b.txs[0].clone();
    b.txs.push(extra);
    assert_eq!(
        Block::decode(&b.encode()),
        Err(BlockDecodeError::Framing(DecodeError::CountOutOfRange {
            what: "block transactions",
            count: MAX_BLOCK_TXS + 1,
        }))
    );
}
