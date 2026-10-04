//! Block non-malleability (T-1 a).
//!
//! Exhaustive single-byte mutations of a valid block (coinbase + transfer).
//! Every mutant that still decodes must re-encode to exactly its own bytes, and
//! must either have a different block id, or keep the id with a body that no
//! longer matches the header's `tx_root` (which the node refuses: shown for a
//! sample through `submit_block`). So no second encoding of a valid block
//! carries the same id.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError};
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

fn block_on(
    m: &ChainManager,
    keys: &WalletKeys,
    txs: Vec<Transaction>,
    rng: &mut ChaCha20Rng,
) -> Block {
    let t = m.template();
    let fees: u64 = txs.iter().map(Transaction::fee).sum();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: keys.address(SubaddressIndex::PRIMARY),
            amount: t.reward + fees,
        }],
        &keys.hedge_secret(),
        rng,
    )
    .unwrap();
    let mut all = vec![Transaction::Coinbase(cb)];
    all.extend(txs);
    let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
    let (output_count, output_root) = t.outputs_after(&all);
    let genesis_time = m.params().genesis.timestamp;
    Block {
        header: BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(genesis_time + 10 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
            output_count,
            output_root,
            px_root: t.px_root,
        },
        txs: all,
    }
}

/// A manager 90 blocks high and a valid next block that spends one output.
fn fixture() -> (ChainManager, Block) {
    let p = ChainParams::regtest();
    let rules = TxRules::for_chain(&p);
    let mut m = ChainManager::open(
        p,
        rules,
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [7; 32],
    )
    .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(601);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..90 {
        let b = block_on(&m, &keys, vec![], &mut rng);
        let now = b.header.timestamp;
        m.submit_block(b, now).unwrap();
    }

    // Spend the first mature output.
    let height = m.height() + 1;
    let table = SubaddressTable::new(keys.view_keys(), 1, 5);
    let b1 = m.block_at(1).unwrap();
    let first = m.state().first_output_at(1).unwrap();
    let owned = scan_block(keys.view_keys(), &table, &b1.txs, 1, first)
        .owned
        .remove(0);
    let state = m.state();
    let mature = |i: u64| {
        state.output(i).is_some_and(|r| {
            let age = if r.coinbase {
                COINBASE_MATURITY
            } else {
                SPENDABLE_AGE
            };
            height >= r.height + age
        })
    };
    let ring = select_ring(
        &mut rng,
        &state.cumulative_outputs(),
        height,
        10,
        owned.global_index,
        mature,
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
    let tx = build_transfer(
        &keys,
        vec![InputPlan {
            real: SpendableOutput::from(&owned),
            decoys,
        }],
        &[Payment {
            address: alice.address(SubaddressIndex::PRIMARY),
            amount: 5_000,
        }],
        &keys.address(SubaddressIndex::PRIMARY),
        standard_fee(1, 2, m.rules()),
        m.rules(),
        &mut rng,
    )
    .unwrap();
    let block = block_on(&m, &keys, vec![Transaction::from(tx)], &mut rng);
    (m, block)
}

#[test]
fn decodable_block_mutants_change_the_id_or_break_the_body() {
    let (mut m, block) = fixture();
    let nid = m.params().network_id;
    let id = block.id(nid);
    let bytes = block.encode();
    assert_eq!(Block::decode(&bytes).as_ref(), Ok(&block));

    let mutations: [fn(u8) -> u8; 4] = [|b| b ^ 0x01, |b| b ^ 0x80, |_| 0x00, |_| 0xff];
    let (mut mutants, mut decoded, mut new_id, mut body_mismatch) = (0, 0, 0, 0);
    let mut same_id_samples = Vec::new();
    for pos in 0..bytes.len() {
        for f in mutations {
            let mut mb = bytes.clone();
            mb[pos] = f(mb[pos]);
            if mb == bytes {
                continue;
            }
            mutants += 1;
            let Ok(b) = Block::decode(&mb) else {
                continue;
            };
            decoded += 1;
            assert_eq!(b.encode(), mb, "byte {pos}: not canonical");
            if b.id(nid) != id {
                new_id += 1;
                continue;
            }
            // Same header, so the body changed: it must not match tx_root.
            assert_ne!(
                b.compute_tx_root(),
                b.header.tx_root,
                "byte {pos}: same id, different body, matching tx_root"
            );
            body_mismatch += 1;
            if same_id_samples.len() < 8 && pos % 97 == 0 {
                same_id_samples.push(b);
            }
        }
    }
    println!(
        "block: {} bytes, {mutants} mutants, {decoded} decoded: {new_id} with a new id, \
         {body_mismatch} with the same id and a mismatching body",
        bytes.len()
    );
    assert!(new_id > 0 && body_mismatch > 0);

    // The node refuses same-id mutants, then accepts the original.
    let now = block.header.timestamp;
    for b in same_id_samples {
        assert!(matches!(
            m.submit_block(b, now),
            Err(SubmitError::BodyMismatch)
        ));
    }
    let height = m.height();
    m.submit_block(block, now).unwrap();
    assert_eq!(m.height(), height + 1);
}
