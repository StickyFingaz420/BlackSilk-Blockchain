//! Mutation fuzzing of the p2p message decoder (pure Rust, seeded,
//! repeatable; `BLACKSILK_FUZZ_ITERS` scales it): mutants of every message
//! kind and random frames decode without a panic, and a successful decode
//! re-encodes to the identical bytes.

use blacksilk_consensus::ChainParams;
use blacksilk_p2p::message::Message;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn iters() -> usize {
    std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000)
}

#[test]
fn mutated_messages_never_panic_and_decode_canonically() {
    let genesis = ChainParams::regtest().genesis;
    let seeds = vec![
        Message::Verack,
        Message::Ping(7),
        Message::GetAddr,
        Message::GetHeaders {
            locator: vec![[1; 32], [2; 32]],
            stop: [0; 32],
        },
        Message::Headers(vec![genesis, genesis]),
        Message::GetBlocks(vec![[3; 32]]),
        Message::Block(vec![1, 2, 3, 4]),
        Message::InvTx(vec![[4; 32], [5; 32]]),
        Message::Tx(vec![9; 100]),
        Message::StemTx(vec![8; 50]),
    ];
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let n = iters();
    let mut decoded = 0;
    for seed in &seeds {
        let bytes = seed.encode();
        assert_eq!(Message::decode(&bytes).as_ref(), Ok(seed));
        for _ in 0..n / seeds.len() {
            let mut m = bytes.clone();
            match rng.next_u32() % 4 {
                0 => {
                    let i = rng.next_u32() as usize % m.len();
                    m[i] ^= 1 << (rng.next_u32() % 8);
                }
                1 => m.truncate(rng.next_u32() as usize % m.len()),
                2 => m.extend((0..1 + rng.next_u32() % 16).map(|_| rng.next_u32() as u8)),
                _ => {
                    let i = rng.next_u32() as usize % m.len();
                    m[i] = 0xff;
                }
            }
            if let Ok(msg) = Message::decode(&m) {
                decoded += 1;
                assert_eq!(msg.encode(), m, "decode∘encode must be the identity");
            }
        }
    }
    for _ in 0..n {
        let len = rng.next_u32() as usize % 256;
        let v: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
        if let Ok(msg) = Message::decode(&v) {
            assert_eq!(msg.encode(), v);
        }
    }
    println!("{n} mutants and {n} random frames: {decoded} mutants still decoded (all canonical); no panic");
}
