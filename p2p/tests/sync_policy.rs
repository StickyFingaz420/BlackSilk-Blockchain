//! Header-sync policy against RandomX key abuse (07 W3 / 31 S2, F07-4 and
//! F31-8): the proof-of-work chunk is capped by the key lag, so no header is
//! hashed under a key taken from an unverified header of its own chunk.

mod common;

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{
    seed_height, BlockHeader, Hash, HeaderChain, PowFunction, HEADER_VERSION, NONCE_OFFSET,
};
use blacksilk_p2p::message::Message;
use blacksilk_p2p::{NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
use common::{fast_config, params, raw_handshake, recv_until, ZeroPow};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Proof of work that fails headers carrying `BAD_NONCE` (the largest hash
/// meets no difficulty above 1), passes all others, and records every key it
/// is asked to hash under: where `RandomXPow` would build that key's cache.
const BAD_NONCE: u64 = 0xBAD0_BAD0;
#[derive(Default)]
struct SeedRecordingPow(Mutex<Vec<Hash>>);
impl PowFunction for SeedRecordingPow {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        self.0.lock().unwrap().push(*seed);
        let nonce = u64::from_le_bytes(blob[NONCE_OFFSET..NONCE_OFFSET + 8].try_into().unwrap());
        if nonce == BAD_NONCE {
            [0xff; 32]
        } else {
            [0; 32]
        }
    }
}

/// `n` linked headers on genesis, 1 s apart (the difficulty rises above 1),
/// valid under a PoW function accepting everything; the header at height
/// `bad` carries `BAD_NONCE`.
fn header_branch(n: usize, bad: u64) -> Vec<BlockHeader> {
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: if t.height == bad { BAD_NONCE } else { 0 },
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// F07-4 / F31-8 (07 T9): on a host with 128 PoW threads, a batch that
/// extends our tip across a key block S with junk proof of work at S, and
/// continues past S + lag + 1 (whose key is that fake S), must not make the
/// node hash anything under the fake key. Before the cap, the chunk was
/// `pow_threads` headers, so S and S + 65 were hashed together and the fake
/// key keyed a cache build before S's proof of work failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_junk_key_block_never_keys_a_hash_in_its_own_batch() {
    let p = params();
    let (s, lag) = (p.seed_epoch, p.seed_lag);
    assert_eq!((s, lag), (2048, 64));
    let tip = s - 8;
    let branch = header_branch((s + lag + 60) as usize, s);
    let fake_key = branch[(s - 1) as usize].id(p.network_id);
    assert_eq!(branch[(s - 1) as usize].height, s);
    let keyed_by_fake = branch
        .iter()
        .filter(|h| seed_height(h.height, s, lag) == s)
        .count();
    assert!(keyed_by_fake > 50, "the batch reaches past S + lag");
    assert!(
        branch[(s - 1) as usize].difficulty > 1,
        "junk PoW fails at S"
    );

    let pow = Arc::new(SeedRecordingPow::default());
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow.clone(),
        Box::<MemoryStore>::default(),
        [5; 32],
    )
    .unwrap();
    {
        let mut m = m;
        for part in branch[..tip as usize].chunks(500) {
            m.accept_headers(part, u64::MAX / 2).unwrap();
        }
        let chain: SharedChain = Arc::new(Mutex::new(m));
        let mut cfg: NetConfig = fast_config(&[]);
        cfg.pow_threads = 128;
        let net = Network::start(cfg, chain.clone()).await.unwrap();
        let addr = net.local_addr().unwrap();
        pow.0.lock().unwrap().clear();

        let (_, mut r, mut w) = raw_handshake(addr, s + lag + 100, 5.0)
            .await
            .expect("handshake");
        let mut other = Vec::new();
        assert!(
            recv_until(&mut r, 5.0, &mut other, |m| matches!(
                m,
                Message::GetHeaders { .. }
            ))
            .await
            .is_some(),
            "the node asks for headers"
        );
        let batch = branch[tip as usize..].to_vec();
        w.send(&Message::Headers(batch).encode()).await.unwrap();
        // Verified once the header worker has hashed the header at S.
        let deadline = Instant::now() + Duration::from_secs(20);
        while net.header_queue_len() > 0 || pow.0.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "batch not verified");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while net.header_queue_len() > 0 {
            assert!(Instant::now() < deadline, "batch not verified");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let seeds = pow.0.lock().unwrap().clone();
        let under_fake = seeds.iter().filter(|k| **k == fake_key).count();
        assert_eq!(
            under_fake,
            0,
            "{under_fake} of {} hashes ran under the key of an unverified header",
            seeds.len()
        );
        assert!(
            seeds.len() <= lag as usize,
            "at most one capped chunk: {}",
            seeds.len()
        );
        assert!(
            chain.lock().unwrap().header_height() < s,
            "junk at S rejected"
        );
    }
}
