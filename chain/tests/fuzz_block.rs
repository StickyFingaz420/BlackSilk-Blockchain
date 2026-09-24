//! Mutation fuzzing of block decoding (pure Rust, seeded, repeatable;
//! `BLACKSILK_FUZZ_ITERS` scales it): mutants of a real block never panic
//! the decoder, and a successful decode re-encodes to the identical bytes.

use blacksilk_chain::block::Block;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn mutated_blocks_never_panic_and_decode_canonically() {
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let payouts: Vec<Payment> = (0..4)
        .map(|i| Payment {
            address: keys.address(SubaddressIndex::new(0, i)),
            amount: 1000 + i as u64,
        })
        .collect();
    let cb = build_coinbase(1, &payouts, &[1; 32], &mut rng).unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    let ids: Vec<_> = txs.iter().map(Transaction::hash).collect();
    let genesis = ChainParams::regtest().genesis;
    let block = Block {
        header: BlockHeader {
            version: HEADER_VERSION,
            height: 1,
            prev_id: [1; 32],
            timestamp: genesis.timestamp + 120,
            difficulty: 1,
            tx_root: tx_root(&ids),
            nonce: 0,
        },
        txs,
    };
    let bytes = block.encode();
    assert_eq!(Block::decode(&bytes), Ok(block));
    let n: usize = std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let mut decoded = 0;
    for _ in 0..n {
        let mut m = bytes.clone();
        match rng.next_u32() % 4 {
            0 => {
                let i = rng.next_u32() as usize % m.len();
                m[i] ^= 1 << (rng.next_u32() % 8);
            }
            1 => m.truncate(rng.next_u32() as usize % m.len()),
            2 => m.extend((0..1 + rng.next_u32() % 32).map(|_| rng.next_u32() as u8)),
            _ => {
                let i = rng.next_u32() as usize % m.len();
                m[i] = 0xff;
            }
        }
        if let Ok(b) = Block::decode(&m) {
            decoded += 1;
            assert_eq!(b.encode(), m, "decode∘encode must be the identity");
        }
    }
    println!("{n} mutated blocks: {decoded} still decoded (all canonical); no panic");
}
