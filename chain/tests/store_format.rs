//! The `blocks.dat` format and its identity binding at the chain-manager level
//! (docs/blocks.md §8): stores from before the v3 format (headerless format 0,
//! format 1) are refused on the public networks with remediation text, a store
//! of another network or genesis is refused, and replay reaches the state a
//! fresh sync reaches.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, Template};
use blacksilk_chain::store::{
    BlockStore, Checkpoint, FileStore, InvalidMarker, InvalidOrigin, Marker, MemoryStore,
    StoreIdentity,
};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Zero hash: meets any difficulty (every network's).
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

fn open_with(p: &ChainParams, store: Box<dyn BlockStore>) -> io::Result<ChainManager> {
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(p),
        Arc::new(ZeroPow),
        store,
        [7; 32],
    )
}

fn open_path(p: &ChainParams, path: &Path) -> io::Result<ChainManager> {
    open_with(p, Box::new(FileStore::open(path).unwrap()))
}

struct Miner {
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Miner {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Self { keys, rng }
    }

    /// A coinbase-only block on template `t`, optionally over-claiming its
    /// reward (a valid header with an invalid body).
    fn build(&mut self, p: &ChainParams, t: &Template, claim: Option<u64>, nonce: u64) -> Block {
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: claim.unwrap_or(t.reward),
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let txs = vec![Transaction::Coinbase(cb)];
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(p.genesis.timestamp + p.target_block_time * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        Block { header, txs }
    }

    /// `n` valid blocks on `parent`, submitted to `m`.
    fn mine_on(&mut self, m: &mut ChainManager, parent: Hash, n: usize, nonce: u64) -> Vec<Block> {
        let p = m.params().clone();
        let mut out = Vec::new();
        let mut prev = parent;
        for _ in 0..n {
            let t = m.template_on(&prev).unwrap();
            let b = self.build(&p, &t, None, nonce);
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
            prev = b.id(p.network_id);
            out.push(b);
        }
        out
    }
}

/// `n` coinbase-only blocks of network `p`, mined on a volatile node.
fn chain_of(p: &ChainParams, n: usize, seed: u64) -> Vec<Block> {
    let mut m = open_with(p, Box::<MemoryStore>::default()).unwrap();
    let out = Miner::new(seed).mine_on(&mut m, p.genesis_id(), n, 0);
    assert_eq!(HEADER_VERSION, out[0].header.version);
    out
}

/// A record of the pre-v3 layout (formats 0 and 1): "BSB1" ‖ LE32 length ‖
/// LE32 crc32(payload) ‖ payload, payload = pow hash ‖ block bytes.
fn legacy_record(block: &Block) -> Vec<u8> {
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&block.encode());
    let mut r = b"BSB1".to_vec();
    r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    r.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    r.extend_from_slice(&payload);
    r
}

/// The format 1 file header (2026-09-27 until the v3 format).
fn format1_header(p: &ChainParams) -> Vec<u8> {
    let mut h = b"BSBH".to_vec();
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&p.network_id.to_le_bytes());
    h.extend_from_slice(&p.genesis_id());
    let crc = crc32fast::hash(&h);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

/// F35-1: a headerless (format 0) store holding valid blocks of the node's
/// own network is refused on testnet and mainnet, before anything is read
/// or written: its network cannot be verified (every store written before
/// 2026-09-27 belongs to a pre-v3 network). The error says what to do.
/// On the base commit the store was accepted and replayed.
#[test]
fn a_legacy_headerless_store_is_refused_on_testnet_and_mainnet() {
    for p in [ChainParams::testnet(), ChainParams::mainnet()] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let blocks = chain_of(&p, 2, 1);
        let bytes: Vec<u8> = blocks.iter().flat_map(legacy_record).collect();
        std::fs::write(&path, &bytes).unwrap();
        let err = open_path(&p, &path).err().expect("legacy store refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        let msg = err.to_string();
        assert!(msg.contains("format 0"), "{msg}");
        assert!(msg.contains("move"), "remediation: {msg}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
    }
}

/// A format 1 store (file header version 1, untyped records: pre-freeze
/// labnet stores) is refused on every network with resync advice: v3 stores
/// start at the typed-record format and are never migrated. On the base
/// commit it was the current format and was replayed.
#[test]
fn a_format_1_store_is_refused_with_resync_advice() {
    for p in [
        ChainParams::regtest(),
        ChainParams::testnet(),
        ChainParams::mainnet(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let blocks = chain_of(&p, 2, 2);
        let mut bytes = format1_header(&p);
        bytes.extend(blocks.iter().flat_map(legacy_record));
        std::fs::write(&path, &bytes).unwrap();
        let err = open_path(&p, &path).err().expect("format 1 refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        let msg = err.to_string();
        assert!(msg.contains("format version 1"), "{msg}");
        assert!(msg.contains("resync"), "remediation: {msg}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
    }
}

/// Regtest keeps reading a headerless store as it is (docs/blocks.md §8):
/// its blocks replay, new blocks are appended in its own layout, and the
/// file is never rewritten.
#[test]
fn a_legacy_headerless_store_is_still_read_on_regtest() {
    let p = ChainParams::regtest();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = chain_of(&p, 3, 3);
    let legacy: Vec<u8> = blocks[..2].iter().flat_map(legacy_record).collect();
    std::fs::write(&path, &legacy).unwrap();
    {
        let mut m = open_path(&p, &path).unwrap();
        assert_eq!(m.height(), 2);
        m.submit_block(blocks[2].clone(), blocks[2].header.timestamp)
            .unwrap();
    }
    let now = std::fs::read(&path).unwrap();
    assert_eq!(now[..legacy.len()], legacy[..], "nothing rewritten");
    assert_eq!(now[legacy.len()..], legacy_record(&blocks[2])[..]);
    let m = open_path(&p, &path).unwrap();
    assert_eq!(m.height(), 3);
    assert_eq!(m.tip_id(), blocks[2].id(p.network_id));
}

/// A store of one network is refused by a node of another network, and by
/// a node of the same network id with another genesis, with nothing
/// changed; the right network still opens it.
#[test]
fn a_store_of_another_network_or_genesis_is_refused() {
    let p = ChainParams::testnet();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = chain_of(&p, 2, 4);
    {
        let mut m = open_path(&p, &path).unwrap();
        for b in &blocks {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
    }
    let bytes = std::fs::read(&path).unwrap();
    let mut other_genesis = p.clone();
    other_genesis.genesis.timestamp += 1;
    assert_eq!(other_genesis.network_id, p.network_id);
    assert_ne!(other_genesis.genesis_id(), p.genesis_id());
    for other in [
        ChainParams::mainnet(),
        ChainParams::regtest(),
        other_genesis,
    ] {
        let err = open_path(&other, &path).err().expect("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("wrong network data directory"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
    }
    assert_eq!(open_path(&p, &path).unwrap().height(), 2);
}

/// Everything a restart must reproduce: the connected chain, emission, the
/// v1 output set, the PX state (root, pool, tree size, record and nullifier
/// logs, contract log), invalid verdicts and kept bodies of `ids`, and the
/// (empty) mempool. Not the deepest reorganization: it is per session.
fn snapshot(m: &ChainManager, ids: &[Hash]) -> String {
    let s = m.state();
    let h = m.height();
    let connected: Vec<Hash> = (0..=h)
        .map(|i| m.block_at(i).unwrap().id(m.params().network_id))
        .collect();
    let marks: Vec<String> = ids
        .iter()
        .map(|id| format!("{:?}/{}", m.invalid_reason(id), m.has_body(id)))
        .collect();
    format!(
        "tip {:?} h {h} gen {} connected {connected:?} outputs {} {:?} \
         px root {:?} pool {} size {} records {:?} nullifiers {:?} contracts {:?} \
         marks {marks:?} pool_txs {}",
        m.tip_id(),
        m.generated(),
        s.output_count(),
        s.cumulative_outputs(),
        s.px().root(),
        s.px().pool(),
        s.px().size(),
        s.px_records(0, h),
        s.px_nullifiers(0, h),
        s.px_contract_log(),
        m.mempool().len(),
    )
}

/// Blocks of a small history with a reorganization and an invalid body, in
/// arrival order, and the ids of every block.
fn history(p: &ChainParams) -> (Vec<Block>, Vec<Hash>) {
    let mut src = open_with(p, Box::<MemoryStore>::default()).unwrap();
    let mut miner = Miner::new(5);
    let g = p.genesis_id();
    let main = miner.mine_on(&mut src, g, 6, 0);
    // A heavier side branch from height 3 (heights 4..=7), then an invalid
    // block on it (over-claimed reward) and a valid sibling of that block.
    let mut scratch = open_with(p, Box::<MemoryStore>::default()).unwrap();
    for b in &main[..3] {
        scratch.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    let side = miner.mine_on(&mut scratch, main[2].id(p.network_id), 4, 9);
    let t = scratch.template();
    let bad = miner.build(p, &t, Some(t.reward + 1), 10);
    let next = miner.build(p, &t, None, 11);
    let blocks: Vec<Block> = main.into_iter().chain(side).chain([bad, next]).collect();
    let ids = blocks.iter().map(|b| b.id(p.network_id)).collect();
    (blocks, ids)
}

fn submit(m: &mut ChainManager, b: &Block) {
    let _ = m.submit_block(b.clone(), b.header.timestamp);
}

/// Replay equivalence (docs/blocks.md §8): a node that syncs the blocks
/// fresh, a node that restarts from its store after every block, and a node
/// whose store also holds markers (checkpoints, which this build does not
/// trust, and verdict markers, which it re-checks) reach one identical state,
/// including the PX state. An operator marker is honoured: the replay
/// reaches the state of a node that never saw that block.
#[test]
fn replay_reaches_the_state_of_a_fresh_sync() {
    let p = ChainParams::regtest();
    let (blocks, ids) = history(&p);
    let mut fresh = open_with(&p, Box::<MemoryStore>::default()).unwrap();
    for b in &blocks {
        submit(&mut fresh, b);
    }
    assert_eq!(fresh.height(), 8, "the side branch and its last block");
    assert_eq!(fresh.deepest_reorg(), 3);
    assert!(fresh.invalid_reason(&ids[10]).is_some(), "the bad block");
    let want = snapshot(&fresh, &ids);

    let dir = tempfile::tempdir().unwrap();
    // Restart after every block.
    let path = dir.path().join("each.dat");
    for (i, b) in blocks.iter().enumerate() {
        let mut m = open_path(&p, &path).unwrap();
        submit(&mut m, b);
        let before = snapshot(&m, &ids[..=i]);
        drop(m);
        let m = open_path(&p, &path).unwrap();
        assert_eq!(snapshot(&m, &ids[..=i]), before, "after block {i}");
    }
    assert_eq!(snapshot(&open_path(&p, &path).unwrap(), &ids), want);

    // One session, then markers appended by another writer, then a restart.
    let path = dir.path().join("marked.dat");
    {
        let mut m = open_path(&p, &path).unwrap();
        for b in &blocks[..11] {
            submit(&mut m, b);
        }
    }
    {
        let mut s = FileStore::open(&path).unwrap();
        s.bind(&StoreIdentity::of(&p)).unwrap();
        s.load().unwrap();
        s.append_marker(&Marker::Checkpoint(Checkpoint {
            tip_id: ids[9],
            height: 7,
            state_digest: [0xee; 32],
            fingerprint: [0xdd; 32],
            build_commit: "not-trusted".into(),
        }))
        .unwrap();
        s.append_marker(&Marker::Invalid(InvalidMarker {
            id: ids[10],
            origin: InvalidOrigin::Verdict,
            reason: "CoinbaseAmount".into(),
        }))
        .unwrap();
    }
    {
        let mut m = open_path(&p, &path).unwrap();
        submit(&mut m, &blocks[11]);
    }
    let replayed = open_path(&p, &path).unwrap();
    assert_eq!(snapshot(&replayed, &ids), want);
    assert_eq!(replayed.deepest_reorg(), 3, "the replay reorganizes too");

    // An operator marker is honoured (on the base commit, bff3a62, the store
    // was refused): the replay reaches the state of a node that never saw
    // the operator's block.
    {
        let mut s = FileStore::open(&path).unwrap();
        s.bind(&StoreIdentity::of(&p)).unwrap();
        s.load().unwrap();
        s.append_marker(&Marker::Invalid(InvalidMarker {
            id: ids[11],
            origin: InvalidOrigin::Operator,
            reason: String::new(),
        }))
        .unwrap();
    }
    let mut without = open_with(&p, Box::<MemoryStore>::default()).unwrap();
    for b in &blocks[..11] {
        submit(&mut without, b);
    }
    let replayed = open_path(&p, &path).unwrap();
    assert!(replayed.operator_invalidated(&ids[11]));
    assert_eq!(snapshot(&replayed, &ids), snapshot(&without, &ids));
}

/// A crash at every byte of the store, at every write (file header, each
/// block, a marker): the node restarts with every block whose record was
/// complete, no other, and the file cut back to the last complete record; it
/// then syncs the rest to the same tip.
#[test]
fn a_crash_at_every_write_boundary_loses_no_confirmed_block() {
    let p = ChainParams::regtest();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = chain_of(&p, 5, 6);
    let ids: Vec<Hash> = blocks.iter().map(|b| b.id(p.network_id)).collect();
    // Record ends and how many blocks each prefix holds.
    let mut ends: Vec<(usize, u64)> = Vec::new();
    {
        let mut m = open_path(&p, &path).unwrap();
        ends.push((std::fs::metadata(&path).unwrap().len() as usize, 0));
        for (i, b) in blocks.iter().enumerate() {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
            ends.push((
                std::fs::metadata(&path).unwrap().len() as usize,
                i as u64 + 1,
            ));
            if i == 2 {
                drop(m);
                let mut s = FileStore::open(&path).unwrap();
                s.bind(&StoreIdentity::of(&p)).unwrap();
                s.load().unwrap();
                s.append_marker(&Marker::Checkpoint(Checkpoint {
                    tip_id: ids[2],
                    height: 3,
                    state_digest: [1; 32],
                    fingerprint: [2; 32],
                    build_commit: String::new(),
                }))
                .unwrap();
                drop(s);
                ends.push((std::fs::metadata(&path).unwrap().len() as usize, 3));
                m = open_path(&p, &path).unwrap();
            }
        }
    }
    let full = std::fs::read(&path).unwrap();
    assert_eq!(ends.last().unwrap().0, full.len());
    let cut_path = dir.path().join("cut.dat");
    for cut in 0..=full.len() {
        std::fs::write(&cut_path, &full[..cut]).unwrap();
        let mut m = open_path(&p, &cut_path).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        let (kept, height) = ends
            .iter()
            .rev()
            .find(|(end, _)| *end <= cut)
            .copied()
            .unwrap_or((ends[0].0, 0));
        assert_eq!(m.height(), height, "cut {cut}");
        if height > 0 {
            assert_eq!(m.tip_id(), ids[height as usize - 1], "cut {cut}");
        }
        assert_eq!(
            std::fs::metadata(&cut_path).unwrap().len() as usize,
            kept,
            "cut {cut}"
        );
        // Resync the rest (at record boundaries and a sample of other cuts,
        // to bound the run time).
        if cut == kept || cut % 13 == 0 {
            for b in &blocks[height as usize..] {
                m.submit_block(b.clone(), b.header.timestamp).unwrap();
            }
            drop(m);
            let m = open_path(&p, &cut_path).unwrap();
            assert_eq!(m.tip_id(), ids[4], "cut {cut}");
        }
    }
}
