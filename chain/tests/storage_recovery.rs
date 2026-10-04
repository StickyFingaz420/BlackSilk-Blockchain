//! Storage failure injection and recovery (docs/blocks.md §8): torn writes at
//! every byte of the last record, failed writes during sync and reorganizations,
//! a full disk, restarts after each, and replay order.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template, STORE_FAILURE_LIMIT};
use blacksilk_chain::store::{BlockStore, FileStore, Record, StoreIdentity};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::BlockError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

thread_local! {
    /// The body of every block this test built, by id: the output range a
    /// template on a branch extends (B-OMR) needs the bodies the manager
    /// does not hold (headers sent alone, bodies dropped as invalid).
    static BUILT: std::cell::RefCell<std::collections::HashMap<Hash, Vec<Transaction>>> =
        Default::default();
}

/// Records `b`'s body ([`BUILT`]) and returns it.
fn remember(b: Block) -> Block {
    let id = b.id(params().network_id);
    BUILT.with(|m| m.borrow_mut().insert(id, b.txs.clone()));
    b
}

/// The body of a block this test built.
fn known_body(id: &Hash) -> Option<Vec<Transaction>> {
    BUILT.with(|m| m.borrow().get(id).cloned())
}

/// Zero hash: meets any difficulty.
struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open(store: Box<dyn BlockStore>) -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(p, rules, Arc::new(ZeroPow), store, [7; 32]).unwrap()
}

fn open_file(path: &Path) -> ChainManager {
    open(Box::new(FileStore::open(path).unwrap()))
}

fn id(b: &Block) -> Hash {
    b.id(params().network_id)
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

    /// A coinbase-only block on template `t`, optionally over-claiming.
    fn build(&mut self, t: &Template, claim: Option<u64>, nonce: u64) -> Block {
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
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        remember(Block { header, txs })
    }

    /// Builds (without submitting) `n` blocks on `parent`, using `m` for the
    /// first template and extending the templates itself (coinbase-only
    /// blocks: the template depends only on the header chain).
    fn mine_on(&mut self, m: &mut ChainManager, parent: Hash, n: usize, tag: u64) -> Vec<Block> {
        let mut out = Vec::new();
        let mut p = parent;
        for _ in 0..n {
            let t = m.template_on_with(&p, &known_body).unwrap();
            let b = self.build(&t, None, tag);
            m.submit_block(b.clone(), b.header.timestamp)
                .expect("valid block");
            p = id(&b);
            out.push(b);
        }
        out
    }
}

/// A chain of `n` blocks mined on a volatile source node.
fn source_chain(n: usize, seed: u64) -> Vec<Block> {
    let mut src = open(Box::<blacksilk_chain::store::MemoryStore>::default());
    let mut miner = Miner::new(seed);
    let g = params().genesis_id();
    miner.mine_on(&mut src, g, n, 0)
}

/// A file store whose appends fail on command, writing nothing (as `FileStore`
/// guarantees after undoing a failed append). With `poison`, a failure also
/// makes the store report a permanent failure (a write that could not be
/// undone).
struct FailingStore {
    inner: FileStore,
    fail: Arc<AtomicBool>,
    poison: bool,
    poisoned: bool,
}

impl FailingStore {
    fn new(path: &Path, fail: Arc<AtomicBool>, poison: bool) -> Self {
        Self {
            inner: FileStore::open(path).unwrap(),
            fail,
            poison,
            poisoned: false,
        }
    }
}

impl BlockStore for FailingStore {
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> std::io::Result<()> {
        if self.poisoned || self.fail.load(Ordering::SeqCst) {
            self.poisoned |= self.poison;
            return Err(std::io::Error::other("injected: no space left on device"));
        }
        self.inner.append(pow_hash, block)
    }
    fn load(&mut self) -> std::io::Result<Vec<Record>> {
        self.inner.load()
    }
    fn bind(&mut self, identity: &StoreIdentity) -> std::io::Result<()> {
        self.inner.bind(identity)
    }
    fn failed(&self) -> bool {
        self.poisoned
    }
}

/// A crash while the last record is being written, cut at every byte offset:
/// every restart succeeds and keeps all earlier blocks; the store is
/// appendable again afterwards.
#[test]
fn a_crash_at_any_byte_of_the_last_record_keeps_every_earlier_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = source_chain(6, 1);
    {
        let mut m = open_file(&path);
        for b in &blocks[..5] {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
    }
    let before_last = std::fs::read(&path).unwrap();
    {
        let mut m = open_file(&path);
        m.submit_block(blocks[5].clone(), blocks[5].header.timestamp)
            .unwrap();
    }
    let full = std::fs::read(&path).unwrap();
    assert!(full.starts_with(&before_last));
    let start = before_last.len();
    let cut_path = dir.path().join("cut.dat");
    for cut in start..full.len() {
        std::fs::write(&cut_path, &full[..cut]).unwrap();
        let mut m = open_file(&cut_path);
        assert_eq!(m.height(), 5, "cut at {cut}");
        assert_eq!(m.tip_id(), id(&blocks[4]), "cut at {cut}");
        assert_eq!(
            std::fs::metadata(&cut_path).unwrap().len() as usize,
            start,
            "torn tail truncated (cut at {cut})"
        );
        // The lost block is accepted again and survives the next restart.
        m.submit_block(blocks[5].clone(), blocks[5].header.timestamp)
            .unwrap();
        drop(m);
        assert_eq!(open_file(&cut_path).height(), 6, "cut at {cut}");
    }
    // The complete file loads all blocks.
    std::fs::write(&cut_path, &full).unwrap();
    assert_eq!(open_file(&cut_path).height(), 6);
}

/// A full disk (every append fails): after `STORE_FAILURE_LIMIT` failures in a
/// row the manager reports a failed store, refuses every block without
/// touching headers or state, and a restart resumes from the last stored block.
#[test]
fn a_full_disk_fails_the_store_without_changing_state() {
    // The limit as specified (docs/blocks.md: 3 writes in a row), written as
    // a number so that a change of the constant is noticed (mutation run E).
    assert_eq!(STORE_FAILURE_LIMIT, 3);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = source_chain(10, 2);
    let fail = Arc::new(AtomicBool::new(false));
    {
        let mut m = open(Box::new(FailingStore::new(&path, fail.clone(), false)));
        for b in &blocks[..4] {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
        // One failure, then success: the counter resets.
        fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            m.submit_block(blocks[4].clone(), blocks[4].header.timestamp),
            Err(SubmitError::Store(_))
        ));
        assert!(!m.store_failed(), "a single failure is not fatal");
        fail.store(false, Ordering::SeqCst);
        m.submit_block(blocks[4].clone(), blocks[4].header.timestamp)
            .unwrap();
        assert_eq!(m.height(), 5);

        // The disk fills up for good.
        fail.store(true, Ordering::SeqCst);
        let (tip, outputs, generated) = (m.tip_id(), m.state().output_count(), m.generated());
        for (k, b) in blocks[5..5 + STORE_FAILURE_LIMIT as usize]
            .iter()
            .enumerate()
        {
            assert!(!m.store_failed(), "not yet after {k} failure(s)");
            assert!(matches!(
                m.submit_block(b.clone(), b.header.timestamp),
                Err(SubmitError::Store(_))
            ));
        }
        assert!(m.store_failed());
        let header_height = m.header_height();
        // Every further block is refused before its header is looked at.
        let next = &blocks[5 + STORE_FAILURE_LIMIT as usize];
        assert!(matches!(
            m.submit_block(next.clone(), next.header.timestamp),
            Err(SubmitError::Store(_))
        ));
        // Even once space is back: the node must restart.
        fail.store(false, Ordering::SeqCst);
        assert!(matches!(
            m.submit_block(blocks[5].clone(), blocks[5].header.timestamp),
            Err(SubmitError::Store(_))
        ));
        assert!(m.store_failed());
        assert_eq!(m.header_height(), header_height, "no header added");
        assert_eq!(m.height(), 5);
        assert_eq!(m.tip_id(), tip);
        assert_eq!(m.state().output_count(), outputs);
        assert_eq!(m.generated(), generated);
    }
    // Restart: resumes from block 5, and syncs the rest.
    let mut m = open_file(&path);
    assert_eq!(m.height(), 5);
    assert!(!m.store_failed());
    for b in &blocks[5..] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.height(), 10);
    drop(m);
    assert_eq!(open_file(&path).height(), 10);
}

/// A store that reports a permanent failure (a failed write that could not be
/// undone) fails the manager at once.
#[test]
fn a_write_that_cannot_be_undone_fails_the_store_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = source_chain(4, 3);
    let fail = Arc::new(AtomicBool::new(false));
    let mut m = open(Box::new(FailingStore::new(&path, fail.clone(), true)));
    m.submit_block(blocks[0].clone(), blocks[0].header.timestamp)
        .unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(m
        .submit_block(blocks[1].clone(), blocks[1].header.timestamp)
        .is_err());
    assert!(m.store_failed(), "after one failure");
    assert_eq!(m.height(), 1);
    drop(m);
    assert_eq!(open_file(&path).height(), 1);
}

/// A write failure on the block that would trigger a reorganization: no
/// reorganization happens (the block was not stored, so it is not used), the
/// block is accepted when offered again, and restarts reproduce each state.
#[test]
fn a_store_failure_during_a_reorg_and_restart_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let fail = Arc::new(AtomicBool::new(false));
    let mut miner = Miner::new(4);
    let g = params().genesis_id();
    let (main_tip, side) = {
        let mut m = open(Box::new(FailingStore::new(&path, fail.clone(), false)));
        let main = miner.mine_on(&mut m, g, 6, 0);
        // A side branch from height 3: blocks at heights 4..=7, built on a
        // scratch node so that `m` receives them one by one.
        let mut scratch = open(Box::<blacksilk_chain::store::MemoryStore>::default());
        for b in &main[..3] {
            scratch.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
        let side = miner.mine_on(&mut scratch, id(&main[2]), 4, 9);
        for b in &side[..3] {
            let s = m.submit_block(b.clone(), b.header.timestamp).unwrap();
            assert!(!s.on_best_chain, "not heavier yet");
        }
        assert_eq!(m.tip_id(), id(&main[5]));
        // The block that makes the branch heavier cannot be stored.
        fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            m.submit_block(side[3].clone(), side[3].header.timestamp),
            Err(SubmitError::Store(_))
        ));
        assert_eq!(m.tip_id(), id(&main[5]), "no reorganization");
        assert_eq!(m.height(), 6);
        assert_eq!(m.deepest_reorg(), 0);
        (id(&main[5]), side)
    };
    // Restart with the failed block missing: the main chain, side blocks kept.
    {
        let mut m = open_file(&path);
        assert_eq!(m.tip_id(), main_tip);
        assert!(m.has_body(&id(&side[2])), "side branch replayed");
        // Offered again (the header chain lost it with the restart).
        let s = m
            .submit_block(side[3].clone(), side[3].header.timestamp)
            .unwrap();
        assert!(s.on_best_chain);
        assert_eq!(m.height(), 7);
        assert_eq!(m.deepest_reorg(), 3);
    }
    // Restart after the reorganization: the branch is the chain.
    let m = open_file(&path);
    assert_eq!(m.tip_id(), id(&side[3]));
    assert_eq!(m.height(), 7);
}

/// The same failure without a restart: the node accepts the block when it is
/// offered again, and reorganizes then.
#[test]
fn a_reorg_block_whose_write_failed_is_accepted_when_offered_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let fail = Arc::new(AtomicBool::new(false));
    let mut miner = Miner::new(5);
    let g = params().genesis_id();
    let mut m = open(Box::new(FailingStore::new(&path, fail.clone(), false)));
    let main = miner.mine_on(&mut m, g, 4, 0);
    let mut scratch = open(Box::<blacksilk_chain::store::MemoryStore>::default());
    for b in &main[..2] {
        scratch.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    let side = miner.mine_on(&mut scratch, id(&main[1]), 3, 9);
    for b in &side[..2] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    fail.store(true, Ordering::SeqCst);
    assert!(m
        .submit_block(side[2].clone(), side[2].header.timestamp)
        .is_err());
    assert_eq!(m.tip_id(), id(&main[3]));
    fail.store(false, Ordering::SeqCst);
    assert!(
        m.submit_block(side[2].clone(), side[2].header.timestamp)
            .unwrap()
            .on_best_chain
    );
    assert_eq!(m.tip_id(), id(&side[2]));
    drop(m);
    assert_eq!(open_file(&path).tip_id(), id(&side[2]));
}

/// Descendants of a block found invalid, stored before it (headers first):
/// the replay refuses them as such. Before 2026-09-27 a grandchild stored
/// before its parent was released after the parent's refusal, failed with
/// `UnknownParent`, and the node refused to start.
#[test]
fn replay_skips_descendants_of_an_invalid_block_stored_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(6);
    let g = params().genesis_id();
    let tip = {
        let mut m = open_file(&path);
        let main = miner.mine_on(&mut m, g, 5, 0);
        // Side branch from height 3: X (over-claims its reward), Y, Z.
        let tx = m.template_on_with(&id(&main[2]), &known_body).unwrap();
        let x = miner.build(&tx, Some(tx.reward + 1), 7);
        // Y and Z extend X; their templates come from X's header, accepted
        // first (header-first sync).
        m.accept_headers(&[x.header], x.header.timestamp).unwrap();
        let ty = m.template_on_with(&id(&x), &known_body).unwrap();
        let y = miner.build(&ty, None, 7);
        m.accept_headers(&[y.header], y.header.timestamp).unwrap();
        let tz = m.template_on_with(&id(&y), &known_body).unwrap();
        let z = miner.build(&tz, None, 7);
        m.accept_headers(&[z.header], z.header.timestamp).unwrap();
        assert_eq!(m.header_height(), 6, "the branch's headers are heavier");
        assert_eq!(m.height(), 5, "no bodies yet");
        // Bodies arrive in reverse: Z and Y are stored before X.
        m.submit_block(z.clone(), z.header.timestamp).unwrap();
        m.submit_block(y.clone(), y.header.timestamp).unwrap();
        assert!(matches!(
            m.submit_block(x.clone(), x.header.timestamp),
            Err(SubmitError::Body(BlockError::CoinbaseAmount { .. }))
        ));
        assert_eq!(m.tip_id(), id(&main[4]));
        m.tip_id()
    };
    let m = open_file(&path);
    assert_eq!(m.tip_id(), tip, "the node restarts on the valid chain");
    assert_eq!(m.height(), 5);
}

/// Blocks stored before their parent are replayed in storage order once the
/// parent arrives. Between equal-work siblings the one that became
/// body-complete first is kept, and siblings released together complete in
/// body arrival order, live and on replay alike: the tip is the sibling whose
/// **body** was stored first, whichever **header** arrived first (docs/blocks.md
/// §6, §8). Before 2026-09-27 the live node kept the first *header* seen, so a
/// restart could come back on the other sibling.
#[test]
fn siblings_stored_before_their_parent_replay_in_storage_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = source_chain(5, 7);
    let mut miner = Miner::new(8);
    let (a, b) = {
        let mut m = open_file(&path);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        m.accept_headers(&headers, headers[4].timestamp).unwrap();
        let t = m.template_on_with(&id(&blocks[4]), &known_body).unwrap();
        let a = miner.build(&t, None, 1);
        let b = miner.build(&t, None, 2);
        // B's header arrives first; A's body is stored first.
        m.accept_headers(&[b.header], b.header.timestamp).unwrap();
        m.accept_headers(&[a.header], a.header.timestamp).unwrap();
        for blk in &blocks[..4] {
            m.submit_block(blk.clone(), blk.header.timestamp).unwrap();
        }
        m.submit_block(a.clone(), a.header.timestamp).unwrap();
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
        m.submit_block(blocks[4].clone(), blocks[4].header.timestamp)
            .unwrap();
        assert_eq!(m.height(), 6);
        assert_eq!(m.tip_id(), id(&a), "live: first stored body wins");
        (a, b)
    };
    let m = open_file(&path);
    assert_eq!(m.height(), 6);
    assert_eq!(m.tip_id(), id(&a), "restart: first stored body wins");
    assert!(m.has_body(&id(&b)));
}

/// Mid-file corruption is refused at start (nothing truncated) and the
/// operator's repair keeps the valid prefix; the node then syncs the rest.
#[test]
fn mid_file_corruption_is_refused_then_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let blocks = source_chain(8, 9);
    let mut ends = Vec::new();
    {
        let mut m = open_file(&path);
        for b in &blocks {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
            ends.push(std::fs::metadata(&path).unwrap().len() as usize);
        }
    }
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[ends[2] + 40] ^= 0x10; // inside block 4's record
    let len = bytes.len();
    bytes.truncate(len - 3); // and a torn last record
    std::fs::write(&path, &bytes).unwrap();
    let p = params();
    let err = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::new(FileStore::open(&path).unwrap()),
        [7; 32],
    )
    .err()
    .expect("refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing truncated");
    assert_eq!(
        FileStore::repair(&path, 99).unwrap() as usize,
        bytes.len() - ends[2]
    );
    let mut m = open_file(&path);
    assert_eq!(m.height(), 3, "the valid prefix");
    for b in &blocks[3..] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.height(), 8);
}
