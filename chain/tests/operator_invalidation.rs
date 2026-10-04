//! Operator invalidation (docs/blocks.md §8, dossier 35 S5, F48-5): the
//! operator marks a block invalid (`--invalidate-block`, or
//! [`ChainManager::invalidate_block`] on a running manager); the verdict is
//! a typed `Invalid { Operator }` record in the block store, so it survives
//! restarts. The block and its descendants are never connected, and the node
//! follows the best valid branch that remains. `--reconsider-block` appends
//! a record that cancels the operator's earlier verdict. Genesis cannot be
//! invalidated.
//!
//! On the base commit (bff3a62) a store holding an operator marker was
//! refused by `ChainManager::open`, and neither API existed.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, OperatorMark, OperatorMarked, SubmitError, Template};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

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

fn open_with(store: Box<dyn BlockStore>) -> io::Result<ChainManager> {
    let p = params();
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        store,
        [7; 32],
    )
}

fn open_path(path: &Path) -> io::Result<ChainManager> {
    open_with(Box::new(FileStore::open(path).unwrap()))
}

fn volatile() -> ChainManager {
    open_with(Box::<MemoryStore>::default()).unwrap()
}

/// Marks `id` in the store at `path` as the node's flag does, before `open`.
fn mark(path: &Path, id: Hash, action: OperatorMark) -> io::Result<OperatorMarked> {
    let mut s = FileStore::open(path).unwrap();
    ChainManager::mark_stored_block(&params(), &mut s, id, action)
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

    fn build(&mut self, t: &Template, nonce: u64) -> Block {
        let p = params();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
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

    /// `n` valid blocks on `m`'s tip, submitted to `m`.
    fn mine(&mut self, m: &mut ChainManager, n: usize, nonce: u64) -> Vec<Block> {
        (0..n)
            .map(|_| {
                let b = self.build(&m.template(), nonce);
                m.submit_block(b.clone(), b.header.timestamp).unwrap();
                b
            })
            .collect()
    }
}

/// The blocks of the tests:
/// - `main`: heights 1..=5 on genesis;
/// - `side`: heights 2..=4 on `main[0]` (less work than `main`);
/// - `sibling`: height 4 on `main[2]` (a sibling of `main[3]`).
struct Blocks {
    main: Vec<Block>,
    side: Vec<Block>,
    sibling: Block,
}

fn blocks() -> Blocks {
    let mut miner = Miner::new(0x35b);
    let mut src = volatile();
    let main = miner.mine(&mut src, 5, 0);
    let mut s = volatile();
    submit(&mut s, &main[0]).unwrap();
    let side = miner.mine(&mut s, 3, 1);
    let mut s = volatile();
    for b in &main[..3] {
        submit(&mut s, b).unwrap();
    }
    let sibling = miner.mine(&mut s, 1, 2).remove(0);
    Blocks {
        main,
        side,
        sibling,
    }
}

fn id(b: &Block) -> Hash {
    b.id(params().network_id)
}

fn submit(m: &mut ChainManager, b: &Block) -> Result<(), SubmitError> {
    m.submit_block(b.clone(), b.header.timestamp).map(|_| ())
}

/// What a restart must reproduce here: the connected chain and its state.
fn snapshot(m: &ChainManager) -> String {
    let connected: Vec<Hash> = (0..=m.height())
        .map(|h| m.block_at(h).unwrap().id(m.params().network_id))
        .collect();
    format!(
        "h {} tip {:?} gen {} outputs {} connected {connected:?}",
        m.height(),
        m.tip_id(),
        m.generated(),
        m.state().output_count()
    )
}

/// The state a node reaches that only ever saw `bs`.
fn fresh(bs: &[&Block]) -> String {
    let mut m = volatile();
    for b in bs {
        submit(&mut m, b).unwrap();
    }
    snapshot(&m)
}

/// Invalidating the connected tip on a running manager moves the chain to
/// its parent; the verdict is persisted, so a restart (twice) keeps it, and
/// the block is refused if it arrives again.
#[test]
fn invalidating_the_tip_reorgs_to_its_parent_and_survives_restarts() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let tip = id(&bs.main[4]);
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main {
            submit(&mut m, b).unwrap();
        }
        assert_eq!(m.height(), 5);
        m.invalidate_block(tip).unwrap();
        assert!(m.operator_invalidated(&tip));
        assert_eq!(
            snapshot(&m),
            fresh(&bs.main[..4].iter().collect::<Vec<_>>())
        );
        assert!(submit(&mut m, &bs.main[4]).is_err(), "refused live");
    }
    let want = fresh(&bs.main[..4].iter().collect::<Vec<_>>());
    for restart in 0..2 {
        let mut m = open_path(&path).unwrap();
        assert_eq!(snapshot(&m), want, "restart {restart}");
        assert!(m.operator_invalidated(&tip), "restart {restart}");
        assert!(m.invalid_reason(&tip).is_none(), "not a rule verdict");
        assert!(submit(&mut m, &bs.main[4]).is_err(), "restart {restart}");
        assert_eq!(snapshot(&m), want, "restart {restart}");
    }
}

/// Invalidating a buried block of the connected chain reorganizes to the
/// best remaining branch (here the lighter side branch), both on a running
/// manager and through the pre-open path the node's flag uses; every later
/// restart reaches the state of a node that never saw the invalid blocks.
#[test]
fn invalidating_a_buried_block_reorgs_to_the_best_other_branch() {
    let bs = blocks();
    let want = fresh(&[&bs.main[0], &bs.side[0], &bs.side[1], &bs.side[2]]);
    let dir = tempfile::tempdir().unwrap();
    for live in [true, false] {
        let path = dir.path().join(format!("live-{live}.dat"));
        {
            let mut m = open_path(&path).unwrap();
            for b in bs.main.iter().chain(&bs.side) {
                submit(&mut m, b).unwrap();
            }
            assert_eq!(m.tip_id(), id(&bs.main[4]));
            if live {
                m.invalidate_block(id(&bs.main[1])).unwrap();
                assert_eq!(snapshot(&m), want);
                assert_eq!(m.deepest_reorg(), 4);
            }
        }
        if !live {
            assert_eq!(
                mark(&path, id(&bs.main[1]), OperatorMark::Invalidate).unwrap(),
                OperatorMarked::Appended { height: Some(2) }
            );
        }
        for restart in 0..2 {
            let m = open_path(&path).unwrap();
            assert_eq!(snapshot(&m), want, "live {live} restart {restart}");
            for b in &bs.main[1..] {
                assert!(!m.has_body(&id(b)), "invalid bodies dropped from memory");
            }
        }
    }
}

/// Descendants of an invalidated block are refused when they arrive after
/// the verdict, live and after a restart; so is the block itself.
#[test]
fn descendants_arriving_later_are_refused() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let bad = id(&bs.main[2]);
    let want = fresh(&[&bs.main[0], &bs.main[1]]);
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main[..3] {
            submit(&mut m, b).unwrap();
        }
        m.invalidate_block(bad).unwrap();
        assert_eq!(snapshot(&m), want);
        for b in [&bs.main[3], &bs.sibling, &bs.main[2]] {
            assert!(
                matches!(submit(&mut m, b), Err(SubmitError::Header(_))),
                "refused live"
            );
        }
        assert!(submit(&mut m, &bs.main[4]).is_err());
        assert_eq!(snapshot(&m), want);
    }
    let mut m = open_path(&path).unwrap();
    assert_eq!(snapshot(&m), want);
    for b in [&bs.main[2], &bs.main[3], &bs.sibling, &bs.main[4]] {
        assert!(submit(&mut m, b).is_err(), "refused after a restart");
    }
    assert_eq!(snapshot(&m), want);
    // The valid side branch is still followed when it arrives.
    for b in &bs.side {
        submit(&mut m, b).unwrap();
    }
    assert_eq!(m.tip_id(), id(&bs.side[2]));
}

/// The node's flag marks a block the store does not hold yet (for example
/// one named in an incident notice): the verdict applies when it arrives,
/// and to its descendants.
#[test]
fn a_block_marked_before_it_arrives_is_never_connected() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    assert_eq!(
        mark(&path, id(&bs.main[2]), OperatorMark::Invalidate).unwrap(),
        OperatorMarked::Appended { height: None }
    );
    let want = fresh(&[&bs.main[0], &bs.main[1]]);
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main {
            let _ = submit(&mut m, b);
        }
        assert_eq!(snapshot(&m), want);
        assert!(m.operator_invalidated(&id(&bs.main[2])));
    }
    assert_eq!(snapshot(&open_path(&path).unwrap()), want);
}

/// `--reconsider-block` cancels the operator's verdict: the next start
/// connects the block and its descendants again. Marking a block twice, or
/// reconsidering one the operator never invalidated, changes nothing.
#[test]
fn reconsider_cancels_the_operator_verdict() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main {
            submit(&mut m, b).unwrap();
        }
    }
    let all = fresh(&bs.main.iter().collect::<Vec<_>>());
    let bad = id(&bs.main[2]);
    assert_eq!(
        mark(&path, bad, OperatorMark::Reconsider).unwrap(),
        OperatorMarked::Unchanged,
        "nothing to reconsider"
    );
    assert_eq!(
        mark(&path, bad, OperatorMark::Invalidate).unwrap(),
        OperatorMarked::Appended { height: Some(3) }
    );
    let len = std::fs::metadata(&path).unwrap().len();
    assert_eq!(
        mark(&path, bad, OperatorMark::Invalidate).unwrap(),
        OperatorMarked::Unchanged,
        "already invalid"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        len,
        "nothing appended"
    );
    assert_eq!(
        snapshot(&open_path(&path).unwrap()),
        fresh(&[&bs.main[0], &bs.main[1]])
    );
    assert_eq!(
        mark(&path, bad, OperatorMark::Reconsider).unwrap(),
        OperatorMarked::Appended { height: Some(3) }
    );
    let m = open_path(&path).unwrap();
    assert_eq!(snapshot(&m), all);
    assert!(!m.operator_invalidated(&bad));
    drop(m);
    // A later verdict wins again.
    mark(&path, bad, OperatorMark::Invalidate).unwrap();
    assert_eq!(
        snapshot(&open_path(&path).unwrap()),
        fresh(&[&bs.main[0], &bs.main[1]])
    );
}

/// Genesis cannot be invalidated, by either path; nothing is written.
#[test]
fn invalidating_genesis_is_refused() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let g = params().genesis_id();
    let mut m = open_path(&path).unwrap();
    submit(&mut m, &bs.main[0]).unwrap();
    let len = std::fs::metadata(&path).unwrap().len();
    let err = m.invalidate_block(g).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("genesis"), "{err}");
    assert_eq!(m.height(), 1);
    drop(m);
    let err = mark(&path, g, OperatorMark::Invalidate).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("genesis"), "{err}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
    assert_eq!(open_path(&path).unwrap().height(), 1);
}

/// A crash while the record after an operator marker was being written:
/// the torn tail is truncated, the marker (complete before it) is kept and
/// honoured.
#[test]
fn a_torn_tail_right_after_a_marker_keeps_the_marker() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main {
            submit(&mut m, b).unwrap();
        }
    }
    mark(&path, id(&bs.main[3]), OperatorMark::Invalidate).unwrap();
    let marked = std::fs::read(&path).unwrap();
    // The first bytes of a block record: its frame claims more than follows.
    let mut torn = b"BSR2".to_vec();
    torn.extend_from_slice(&500u32.to_le_bytes());
    torn.extend_from_slice(&[0xab; 4]);
    torn.extend_from_slice(&[0x01; 40]);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&torn)
        .unwrap();
    let want = fresh(&bs.main[..3].iter().collect::<Vec<_>>());
    assert_eq!(snapshot(&open_path(&path).unwrap()), want);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        marked,
        "only the torn tail cut"
    );
    assert_eq!(snapshot(&open_path(&path).unwrap()), want);
}

/// F48-5 escape: a block that passed validation but failed to apply halts
/// the manager (injected here: no valid block fails to apply). The running
/// manager refuses the operator's call and points to the flag; the flag,
/// before the next start, makes the node start on the block's parent
/// without validating or applying the block again.
#[test]
fn an_apply_halt_is_escaped_with_the_flag() {
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let suspect = id(&bs.main[2]);
    {
        let mut m = open_path(&path).unwrap();
        for b in &bs.main[..2] {
            submit(&mut m, b).unwrap();
        }
        m.fail_next_apply_for_tests();
        let _ = submit(&mut m, &bs.main[2]);
        assert!(m.apply_halted());
        assert_eq!(m.height(), 2);
        let err = m.invalidate_block(suspect).unwrap_err();
        assert!(err.to_string().contains("--invalidate-block"), "{err}");
    }
    assert_eq!(
        mark(&path, suspect, OperatorMark::Invalidate).unwrap(),
        OperatorMarked::Appended { height: Some(3) }
    );
    let m = open_path(&path).unwrap();
    assert_eq!(snapshot(&m), fresh(&[&bs.main[0], &bs.main[1]]));
    assert!(m.halted().is_none());
}

/// Blocks in the store at `path`, by id (operator markers left out).
fn stored_ids(path: &Path) -> Vec<Hash> {
    use blacksilk_chain::store::{Record, StoreIdentity};
    let mut store = FileStore::open(path).unwrap();
    store.bind(&StoreIdentity::of(&params())).unwrap();
    store
        .load()
        .unwrap()
        .into_iter()
        .filter_map(|r| match r {
            Record::Block((_, bytes)) => {
                Some(Block::decode(&bytes).unwrap().id(params().network_id))
            }
            Record::Marker(_) => None,
        })
        .collect()
}

/// S5b (owed by W3-35b; demonstrated on the base, 49423b7: `accept_headers`
/// took the marked header and its descendants, and listed their bodies for
/// download): a verdict given before the block arrives applies when its
/// header arrives. The header is refused as a descendant of an invalid block
/// is (`InvalidParent`, which the P2P layer does not penalize); its
/// descendants' headers are refused by the pre-check, before any proof of
/// work; no body of them is asked for, and a body that arrives anyway is
/// refused before it is stored.
#[test]
fn a_marked_header_and_its_descendants_are_refused_at_header_time() {
    use blacksilk_consensus::HeaderError::{InvalidParent, UnknownParent};
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let bad = id(&bs.main[2]);
    let headers: Vec<BlockHeader> = bs.main.iter().map(|b| b.header).collect();
    let now = headers.last().unwrap().timestamp;
    let below = fresh(&[&bs.main[0], &bs.main[1]]);
    {
        let mut m = open_path(&path).unwrap();
        m.invalidate_block(bad).unwrap();
        assert_eq!(
            m.accept_headers(&headers, now),
            Err((2, InvalidParent)),
            "the marked header is refused, its parent kept"
        );
        assert!(m.header(&id(&bs.main[1])).is_some());
        assert_eq!(m.headers().is_valid(&bad), Some(false));
        assert_eq!(
            m.headers().height(),
            2,
            "the best header chain ends below it"
        );
        // Its descendants, in a later batch, are refused without any work.
        assert_eq!(
            m.precheck_headers(&headers[3..], now),
            Err((0, InvalidParent))
        );
        assert_eq!(
            m.accept_headers(&headers[3..], now),
            Err((0, InvalidParent))
        );
        assert!(m.header(&id(&bs.main[3])).is_none());
        // The same batch again: refused at the marked header, nothing new.
        assert_eq!(m.accept_headers(&headers, now), Err((2, InvalidParent)));
        // Only the bodies below it are wanted.
        let wanted: Vec<Hash> = m.missing_bodies(16).into_iter().map(|e| e.1).collect();
        assert_eq!(wanted, vec![id(&bs.main[0]), id(&bs.main[1])]);
        for b in &bs.main[..2] {
            submit(&mut m, b).unwrap();
        }
        assert!(m.missing_bodies(16).is_empty());
        // Bodies that arrive anyway are refused, and never stored.
        for b in &bs.main[2..] {
            // A grandchild's parent was refused, so it is not even known.
            assert!(
                matches!(
                    submit(&mut m, b),
                    Err(SubmitError::Header(InvalidParent | UnknownParent))
                ),
                "height {}",
                b.header.height
            );
        }
        assert_eq!(snapshot(&m), below);
        // The heavier refused chain is reported as far as it is known: the
        // marked header, fully checked on arrival (RTW3-8).
        let fork = m
            .operator_fork()
            .expect("the marked header outweighs the tip");
        assert_eq!((fork.block, fork.branch_height), (bad, 3));
    }
    assert_eq!(stored_ids(&path), vec![id(&bs.main[0]), id(&bs.main[1])]);
    // A restart keeps refusing it.
    let mut m = open_path(&path).unwrap();
    assert_eq!(snapshot(&m), below);
    assert_eq!(m.accept_headers(&headers, now), Err((2, InvalidParent)));
    assert!(m.missing_bodies(16).is_empty());
}

/// S5b through a whole block (the local miner's, or one relayed before its
/// header): a marked block whose header was never seen is refused before
/// its body is stored, and so are its descendants.
#[test]
fn a_marked_block_is_refused_before_its_body_is_stored() {
    use blacksilk_consensus::HeaderError::{InvalidParent, UnknownParent};
    let bs = blocks();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let bad = id(&bs.main[2]);
    {
        let mut m = open_path(&path).unwrap();
        m.invalidate_block(bad).unwrap();
        for b in &bs.main[..2] {
            submit(&mut m, b).unwrap();
        }
        for b in &bs.main[2..] {
            // A grandchild's parent was refused, so it is not even known.
            assert!(
                matches!(
                    submit(&mut m, b),
                    Err(SubmitError::Header(InvalidParent | UnknownParent))
                ),
                "height {}",
                b.header.height
            );
        }
        assert_eq!(snapshot(&m), fresh(&[&bs.main[0], &bs.main[1]]));
        assert!(!m.has_body(&bad));
    }
    assert_eq!(stored_ids(&path), vec![id(&bs.main[0]), id(&bs.main[1])]);
}
