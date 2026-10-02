//! Adversarial sync tests (dossier 39 W1, W5; CB-B2 rebroadcast note): a
//! scripted node (`mock_chain`) that lies about the PX commitment list, its
//! blocks or its headers, against the wallet's own tree and header check.

use super::mock_chain::{MockChain, ZeroPow};
use super::*;
use crate::px::digest_hex;
use blacksilk_consensus::{BlockHeader, Hash, PowFunction};
use blacksilk_px_core::Digest;
use std::sync::Arc;

fn wallet() -> Wallet {
    Wallet::from_seed(Network::Regtest, [7; 32], 1)
}

/// A chain of `n` blocks with one PX transaction at each height of `px`.
fn chain_with(seed: u64, n: u64, px: &[u64]) -> MockChain {
    let mut chain = MockChain::new(seed);
    let to = wallet().primary();
    for h in 1..=n {
        chain.mine(&to, usize::from(px.contains(&h)));
    }
    chain
}

/// F39-1 (demonstrated on the base, 47179f1: the wallet anchored at the
/// root of block 33 the node chose): a node relabels the heights of its
/// commitment list so that the tree at the canonical anchor (32) would hold
/// block 33's commitments too, and reports another height so no root check
/// runs. The wallet builds its tree from the blocks: it anchors at the
/// chain's root of block 32, and does not even ask for the list (it scans
/// from block 1).
#[test]
fn a_node_cannot_choose_the_anchor_root() {
    let mut chain = chain_with(1, 40, &[5, 20, 33, 35]);
    chain.lies.relabel = Some(Box::new(|_, h| if h == 33 { 32 } else { h }));
    chain.lies.report_height = Some(39);
    let mut w = wallet();
    assert_eq!(w.sync(&chain).unwrap(), 40);
    let (anchor, root) = w.px.anchor_root(40).unwrap();
    assert_eq!(anchor, 32);
    assert_eq!(
        root, chain.roots[32],
        "the chain's root at the canonical anchor"
    );
    assert_ne!(root, chain.roots[33]);
    assert!(chain.commitment_requests.borrow().is_empty());
    // Every root of the wallet's window is the chain's.
    let t = w.px.tree.as_ref().unwrap();
    for h in 0..=40u64 {
        assert_eq!(
            t.root_at(h).map(|r| r.0),
            Some(chain.roots[h as usize]),
            "{h}"
        );
    }
    assert!(t.is_confirmed(), "no backfill: built from the genesis");
}

/// A wallet restored above the genesis takes the commitments below its
/// restore height from the node's list, once. An honest list gives the
/// chain's roots, and the first PX transaction anchored at a root that
/// includes a scanned commitment binds it to the chain.
#[test]
fn an_honest_backfill_is_confirmed_by_a_later_anchor() {
    let mut chain = chain_with(2, 60, &[3, 10, 11, 25]);
    let mut w = Wallet::from_seed(Network::Regtest, [7; 32], 31);
    assert_eq!(w.sync(&chain).unwrap(), 60);
    assert_eq!(chain.commitment_requests.borrow().len(), 1, "fetched once");
    let t = w.px.tree.as_ref().unwrap();
    assert_eq!((t.base_height(), t.base_size()), (30, 8));
    for h in 0..=60u64 {
        assert_eq!(
            t.root_at(h).map(|r| r.0),
            Some(chain.roots[h as usize]),
            "{h}"
        );
    }
    assert!(
        !t.is_confirmed(),
        "nothing anchored after a scanned commitment yet"
    );
    // Until confirmed, an anchor whose tree holds only the backfill is
    // refused until the backfill's end has left the root window.
    assert!(matches!(
        w.px.anchor_root(60),
        Err(WalletError::PxNotReady(_))
    ));
    // A PX transaction at 70 (anchored at 64) after a scanned one at 62.
    let to = wallet().primary();
    for h in 61..=70 {
        chain.mine(&to, usize::from(h == 62 || h == 70));
    }
    w.sync(&chain).unwrap();
    let t = w.px.tree.as_ref().unwrap();
    assert!(t.is_confirmed());
    assert_eq!(w.px.anchor_root(70).unwrap(), (64, chain.roots[64]));
    assert_eq!(chain.commitment_requests.borrow().len(), 1, "never again");
}

/// Without a confirming anchor, a root holding only backfilled commitments
/// is usable once the backfill's end has left the root window (a shortened
/// list then gives a root no block accepts), and never below the restore
/// height.
#[test]
fn an_unconfirmed_backfill_is_used_only_once_it_cannot_steer_the_anchor() {
    let mut chain = chain_with(3, 40, &[3, 10]);
    let mut w = Wallet::from_seed(Network::Regtest, [7; 32], 38);
    // Synced to 40: the anchor (32) lies below the restore height.
    w.sync(&chain).unwrap();
    let e = w.px.anchor_root(40).unwrap_err().to_string();
    assert!(e.contains("below this wallet's restore height"), "{e}");
    let to = wallet().primary();
    while chain.height() < 136 {
        chain.mine(&to, 0);
    }
    w.sync(&chain).unwrap();
    assert!(matches!(
        w.px.anchor_root(136),
        Err(WalletError::PxNotReady(_))
    ));
    chain.mine(&to, 0);
    w.sync(&chain).unwrap();
    assert_eq!(w.px.anchor_root(137).unwrap(), (128, chain.roots[128]));
}

/// A node that shortens, alters or pads the list below the restore height
/// is caught by the first PX transaction anchored after it: the block is
/// refused, and the tree is rebuilt from a fresh list at the next sync (from
/// an honest node, here).
#[test]
fn a_lying_backfill_is_refused_and_replaced() {
    type Lie = Box<dyn Fn(&mut MockChain)>;
    let lies: Vec<(&str, Lie)> = vec![
        ("omitted", Box::new(|c| c.lies.omit = vec![5])),
        (
            "replaced",
            Box::new(|c| c.lies.replace = Some((2, [1, 2, 3, 4, 5, 6, 7, 8]))),
        ),
        (
            "relabelled into the backfill",
            // The first commitments after the restore height (block 32)
            // reported as block 30's: the list runs ahead of the chain.
            Box::new(|c| {
                c.lies.relabel = Some(Box::new(|_, h| if h == 32 { 30 } else { h }));
            }),
        ),
    ];
    for (what, lie) in lies {
        let mut chain = chain_with(4, 40, &[3, 10, 11, 25, 32, 36]);
        lie(&mut chain);
        let mut w = Wallet::from_seed(Network::Regtest, [7; 32], 31);
        let e = w.sync(&chain).unwrap_err();
        assert!(matches!(e, WalletError::BadNodeData(_)), "{what}: {e}");
        assert!(w.px.tree.is_none(), "{what}: dropped");
        assert_eq!(w.synced_height(), 30, "{what}: back to the restore height");
        // An honest node: the tree is rebuilt, and the chain's.
        chain.lies = Default::default();
        assert_eq!(w.sync(&chain).unwrap(), 40, "{what}");
        assert_eq!(
            w.px.tree.as_ref().unwrap().root(),
            chain.roots[40],
            "{what}"
        );
    }
}

/// A node that serves blocks the consensus PX state refuses (a PX
/// transaction whose anchor is no recent root: a forged chain) is refused
/// at that block; the wallet stays at the block before it.
#[test]
fn a_block_with_an_anchor_outside_the_window_is_refused() {
    let mut chain = chain_with(5, 30, &[4, 12]);
    let mut w = wallet();
    w.sync(&chain).unwrap();
    chain.forge = true;
    let to = wallet().primary();
    let stale = chain.px_tx_anchored([9, 9, 9, 9, 9, 9, 9, 9]);
    chain.mine_with(&to, vec![stale]);
    chain.mine(&to, 0);
    let e = w.sync(&chain).unwrap_err();
    assert!(e.to_string().contains("anchor"), "{e}");
    assert_eq!(w.synced_height(), 30);
    assert_eq!(w.px.tree.as_ref().unwrap().height(), 30);
}

/// Records paid to the wallet get witnesses whose paths verify against the
/// wallet's own root at the anchor, equal to the reference tree's paths,
/// and the tree follows a reorganization that replaces them.
#[test]
fn witnesses_verify_and_follow_a_reorganization() {
    let w0 = wallet();
    let addr = |w: &Wallet, i| w.px_account.address(i);
    let build = |seed: u64, fork: Option<u64>| {
        let mut chain = MockChain::new(seed);
        let to = w0.primary();
        for h in 1..=45u64 {
            let fork_side = fork.is_some_and(|f| h > f);
            let txs = match h {
                7 => vec![chain.px_tx_paying([Some((addr(&w0, 0), 50, [0; 8])), None])],
                20 => vec![
                    chain.px_tx(),
                    chain.px_tx_paying([None, Some((addr(&w0, 1), 70, [0; 8]))]),
                ],
                33 if !fork_side => {
                    vec![chain.px_tx_paying([Some((addr(&w0, 0), 90, [0; 8])), None])]
                }
                34 if fork_side => vec![chain.px_tx(), chain.px_tx()],
                _ => vec![],
            };
            chain.mine_with(&to, txs);
        }
        chain
    };
    let a = build(6, None);
    let mut w = wallet();
    w.sync(&a).unwrap();
    assert_eq!(w.px.records.len(), 3);
    let check = |w: &Wallet, chain: &MockChain| {
        let (anchor, root) = w.px.anchor_root(chain.height()).unwrap();
        assert_eq!(root, chain.roots[anchor as usize]);
        let mut perm = blacksilk_px::perm::HostPerm::new();
        let mut reference = blacksilk_px::tree::Tree::new(&mut perm);
        for (h, cm) in &chain.commitments {
            if *h <= anchor {
                reference.append(&mut perm, *cm).unwrap();
            }
        }
        assert_eq!(reference.root(), root);
        let mut n = 0;
        for r in &w.px.records {
            let pos = r.position.unwrap();
            if r.height > anchor {
                assert!(w.px.path(pos, anchor, &root).is_err(), "above the anchor");
                continue;
            }
            let path = w.px.path(pos, anchor, &root).unwrap();
            assert_eq!(Some(path), reference.path(pos));
            n += 1;
        }
        n
    };
    // The payment at 33 is above the anchor (32): no path yet.
    assert_eq!(check(&w, &a), 2);
    // Another branch from block 32 replaces the payment at 33.
    let b = build(6, Some(30));
    assert_eq!(b.id(30), a.id(30));
    assert_ne!(b.id(33), a.id(33));
    w.sync(&b).unwrap();
    assert_eq!(
        w.px.records.len(),
        2,
        "the payment at 33 went with its block"
    );
    assert_eq!(w.px.tree.as_ref().unwrap().root(), b.roots[45]);
    assert_eq!(check(&w, &b), 2);
    // And the tree survives the wallet file.
    let loaded = Wallet::from_json(&w.to_json()).unwrap();
    assert_eq!(loaded.px.tree, w.px.tree);
    assert_eq!(check(&loaded, &b), 2);
}

/// Stand-in proof of work: every hash meets every difficulty, except the
/// headers listed, whose hash meets none above 1; counts the hashes.
#[derive(Default)]
struct BadPow {
    bad: std::sync::Mutex<Vec<[u8; blacksilk_consensus::HEADER_SIZE]>>,
    calls: std::sync::atomic::AtomicU64,
}

impl PowFunction for BadPow {
    fn pow_hash(&self, _: &Hash, header: &[u8]) -> Hash {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.bad.lock().unwrap().iter().any(|b| b[..] == *header) {
            [0xff; 32]
        } else {
            [0; 32]
        }
    }
}

/// A chain whose difficulty rises above 1 (blocks faster than the target).
fn fast_chain(seed: u64, n: u64) -> MockChain {
    let mut chain = MockChain::new(seed);
    chain.spacing = 1;
    let to = wallet().primary();
    for _ in 0..n {
        chain.mine(&to, 0);
    }
    chain
}

fn restored(pow: Option<Arc<dyn PowFunction>>, restore: u64) -> Wallet {
    let mut w = Wallet::from_mnemonic(Network::Regtest, &wallet().mnemonic(), restore).unwrap();
    w.set_header_pow(pow.unwrap_or_else(|| Arc::new(ZeroPow)));
    w
}

/// W5 (demonstrated on the base, 47179f1: the restore accepted it): a
/// restore from a node serving a header whose difficulty is not the LWMA
/// rule's is refused, at any position, and nothing from that block on is
/// applied.
#[test]
fn a_restore_refuses_a_header_with_the_wrong_difficulty() {
    for bad in [30u64, 12] {
        let mut chain = fast_chain(7, 30);
        let honest = chain.blocks[bad as usize].header.difficulty;
        assert!(honest > 1);
        // The forged header (and every later one relinked to it).
        chain.blocks[bad as usize].header.difficulty = honest - 1;
        for h in bad + 1..=30 {
            let prev = chain.id(h - 1);
            chain.blocks[h as usize].header.prev_id = prev;
        }
        let mut w = restored(None, 1);
        assert!(w.verifies_headers());
        let e = w.sync(&chain).unwrap_err();
        assert!(e.to_string().contains("LWMA"), "{e}");
        assert_eq!(w.synced_height(), bad - 1);
    }
    // The honest chain passes, and the check stops once caught up.
    let chain = fast_chain(7, 30);
    let mut w = restored(None, 1);
    assert_eq!(w.sync(&chain).unwrap(), 30);
    assert!(!w.verifies_headers(), "routine syncs are opt-in");
}

/// W5: a header whose proof of work does not meet its difficulty is
/// refused when it is the tip (always checked) or sampled (here every
/// header is); with RandomX (the default) a chain mined with a stand-in
/// fails too.
#[test]
fn a_restore_refuses_a_header_with_bad_proof_of_work() {
    let chain = fast_chain(8, 30);
    for bad in [30u64, 17] {
        let pow = Arc::new(BadPow::default());
        pow.bad
            .lock()
            .unwrap()
            .push(chain.blocks[bad as usize].header.to_bytes());
        let mut w = restored(Some(pow.clone()), 1);
        w.set_header_samples(u64::MAX);
        let e = w.sync(&chain).unwrap_err();
        assert!(e.to_string().contains("proof of work"), "{bad}: {e}");
        assert_eq!(w.synced_height(), bad - 1);
    }
    // With the default rate, the last `DENSE_POW_TAIL` headers are all
    // hashed (RTW3-5), and far fewer than all of those below them.
    let pow = Arc::new(BadPow::default());
    let long = fast_chain(9, 1_000);
    let mut w = restored(Some(pow.clone()), 1);
    w.sync(&long).unwrap();
    let calls = pow.calls.load(std::sync::atomic::Ordering::Relaxed);
    let tail = super::DENSE_POW_TAIL;
    assert!(
        (tail..tail + 60).contains(&calls),
        "{calls} hashes for 1 000 headers"
    );
}

/// RTW3-5 (demonstrated by the red team on 403e924: 25 of 30 restores
/// accepted it): a forgery of block `h` forces the node to relink every
/// block after it, so a forged region is a suffix of its chain, and the
/// node chooses how short. Here the 4 headers below the tip carry no proof
/// of work. The last `DENSE_POW_TAIL` headers are all hashed: every restore
/// refuses, whether it scans them or reads them from the header feed.
#[test]
fn a_short_forged_suffix_is_refused() {
    let chain = fast_chain(21, 400);
    let pow = Arc::new(BadPow::default());
    for h in 396..400u64 {
        assert!(chain.blocks[h as usize].header.difficulty > 1);
        pow.bad
            .lock()
            .unwrap()
            .push(chain.blocks[h as usize].header.to_bytes());
    }
    for restore in [1, 200, 398, 400] {
        for _ in 0..5 {
            let mut w = restored(Some(pow.clone()), restore);
            let e = w.sync(&chain).unwrap_err().to_string();
            assert!(e.contains("proof of work"), "{restore}: {e}");
            // No block of the forged suffix was scanned.
            assert!(w.synced_height() < 396.max(restore), "{restore}");
        }
    }
}

/// RTW3-15: an imported record already on chain, in a block the wallet
/// scanned, is placed from the commitments its tree keeps: no commitment
/// list is downloaded for it (such a download told the node that the wallet
/// holds a record whose position it does not know). Its witness verifies at
/// the wallet's anchor. A record not in those blocks stays looked for, with
/// a warning.
#[test]
fn an_imported_record_is_placed_without_a_download() {
    use crate::px::RecordSource;
    use blacksilk_px_core::record::Record;
    let record = Record {
        owner: blacksilk_px_core::ZERO_DIGEST,
        contract: [4, 0, 0, 0, 0, 0, 0, 0],
        asset: blacksilk_px_core::ZERO_DIGEST,
        value: 5,
        data: [0; 8],
        rho: [1, 0, 0, 0, 0, 0, 0, 0],
        rcm: [2, 0, 0, 0, 0, 0, 0, 0],
    };
    let cm = record.commit(&mut blacksilk_px::perm::HostPerm::new());
    let mut chain = MockChain::new(23);
    let to = wallet().primary();
    for h in 1..=40u64 {
        let txs = match h {
            12 => {
                let mut t = chain.px_tx();
                t.commitments[1] = cm;
                vec![t]
            }
            20 => vec![chain.px_tx()],
            _ => vec![],
        };
        chain.mine_with(&to, txs);
    }
    let mut w = wallet();
    w.sync(&chain).unwrap();
    w.px.add_contract_record(&record, &cm, RecordSource::Imported, None);
    w.px.contract_records[0].lookup = true;
    let unknown = Record { value: 6, ..record };
    let unknown_cm = unknown.commit(&mut blacksilk_px::perm::HostPerm::new());
    w.px.add_contract_record(&unknown, &unknown_cm, RecordSource::Imported, None);
    w.px.contract_records[1].lookup = true;
    chain.commitment_requests.borrow_mut().clear();
    w.sync(&chain).unwrap();
    assert!(chain.commitment_requests.borrow().is_empty(), "no download");
    let r = &w.px.contract_records[0];
    assert_eq!((r.position, r.height, r.lookup), (Some(1), Some(12), false));
    let (anchor, root) = w.px.anchor_root(40).unwrap();
    assert_eq!(root, chain.roots[anchor as usize]);
    w.px.path(1, anchor, &root).unwrap();
    assert!(w.px.contract_records[1].lookup, "still looked for");
    assert!(w
        .take_warnings()
        .iter()
        .any(|m| m.contains("imported record")));
}

/// A chain of `n` blocks whose tip is `age` seconds old by the local clock
/// (spacing chosen to end there; difficulty 1).
fn chain_ending(seed: u64, n: u64, age: u64) -> MockChain {
    let mut chain = MockChain::new(seed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let genesis = chain.params.genesis.timestamp;
    chain.spacing = (now - age - genesis) / n;
    let to = wallet().primary();
    for _ in 0..n {
        chain.mine(&to, 0);
    }
    chain
}

/// RTW3-6 (demonstrated by the red team on 403e924: a restore accepted a
/// tip 1 048 days old without a word): a node that withholds its newest
/// blocks shows a stale tip. The wallet reports its age, warns past
/// `STALE_TIP_WARN_BLOCKS` target times plus the future time limit, and
/// refuses to build a transaction past `STALE_TIP_REFUSE_BLOCKS` of them,
/// unless told the network has really stalled.
#[test]
fn a_withheld_tip_is_reported_and_blocks_transactions() {
    let p = ChainParams::regtest();
    let (warn, refuse) = super::stale_tip_limits(&p);
    // As specified (docs/blocks.md, tip age): 10 and 60 target block times
    // plus the future time limit, written out (mutation run E).
    let (t, ftl) = (p.target_block_time, p.future_time_limit);
    assert_eq!((warn, refuse), (10 * t + ftl, 60 * t + ftl));
    for (age, warned, refused) in [
        (0, false, false),
        (warn + 60, true, false),
        (refuse + 60, true, true),
    ] {
        let chain = chain_ending(22, 40, age);
        let mut w = restored(None, 1);
        assert_eq!(w.sync(&chain).unwrap(), 40, "{age}");
        let (h, seen) = w.tip_age().unwrap();
        assert_eq!(h, 40);
        assert!(seen >= age && seen < age + 60, "{age}: {seen}");
        let warnings = w.take_warnings();
        assert_eq!(
            warnings
                .iter()
                .any(|m| m.contains("old by this computer's clock")),
            warned,
            "{age}: {warnings:?}"
        );
        let r = w.check_fresh_tip();
        assert_eq!(
            matches!(r, Err(WalletError::StaleTip { height: 40, .. })),
            refused,
            "{age}: {r:?}"
        );
        // And so does every transaction path, before anything is built.
        let to = wallet().primary();
        let rules = blacksilk_tx::params::TxRules::at_height(&ChainParams::regtest(), 41);
        let mut rng =
            <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(1);
        let e = w.transfer(&chain, &to, 1, &rules, &mut rng).unwrap_err();
        assert_eq!(
            matches!(e, WalletError::StaleTip { .. }),
            refused,
            "{age}: {e}"
        );
        w.set_allow_stale_tip(true);
        assert!(w.check_fresh_tip().is_ok());
    }
}

/// W5, W3-39b: a restore from a height above the genesis checks the header
/// chain from the genesis (read from the header feed, in one request here:
/// no block below the restore height is downloaded for it), and a routine
/// sync checks only when asked.
#[test]
fn the_header_check_from_a_later_restore_and_opt_in() {
    let mut chain = fast_chain(10, 200);
    let mut w = restored(None, 150);
    assert_eq!(w.sync(&chain).unwrap(), 200);
    assert_eq!(w.headers_checked_through(), Some(200));
    assert!(chain.header_requests.borrow().contains(&(1, 149)));
    // Routine syncs are not checked unless asked...
    let to = wallet().primary();
    chain.mine(&to, 0);
    let tip = chain.height() as usize;
    chain.blocks[tip].header.difficulty += 1;
    let mut unchecked = Wallet::from_json(&w.to_json()).unwrap();
    assert!(!unchecked.verifies_headers());
    assert_eq!(unchecked.sync(&chain).unwrap(), 201);
    // ...and refused when asked.
    w.set_verify_headers(true);
    w.set_header_pow(Arc::new(ZeroPow));
    assert!(w.sync(&chain).is_err());
    assert_eq!(w.synced_height(), 200);
    // The unchecked wallet's header chain is no longer checked from the
    // genesis: a check asked for later starts from the genesis again.
    assert_eq!(unchecked.headers_checked_through(), None);
}

/// W3-39b cost measurement (ignored; run with `--ignored --nocapture`): a
/// restore at the tip of a chain of 3 000 headers reads them from the header
/// feed and checks them from the genesis, with the stand-in proof of work
/// (the LWMA, time and link checks alone) and with RandomX light mode (the
/// sampled hashes are computed, then accepted: the chain is mined with the
/// stand-in).
#[test]
#[ignore]
fn header_feed_cost_for_3000_headers() {
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Measured(blacksilk_consensus::RandomXPow, AtomicU64);
    impl PowFunction for Measured {
        fn pow_hash(&self, seed: &Hash, header: &[u8]) -> Hash {
            self.1.fetch_add(1, Ordering::Relaxed);
            let _ = self.0.pow_hash(seed, header);
            [0; 32]
        }
    }
    let chain = fast_chain(18, 3_000);
    let light = Arc::new(Measured(
        blacksilk_consensus::RandomXPow::new(),
        AtomicU64::new(0),
    ));
    for (name, pow) in [
        ("stand-in", Arc::new(ZeroPow) as Arc<dyn PowFunction>),
        ("RandomX light", light.clone() as Arc<dyn PowFunction>),
    ] {
        let mut w = restored(Some(pow), 3_000);
        chain.header_requests.borrow_mut().clear();
        let t = std::time::Instant::now();
        assert_eq!(w.sync(&chain).unwrap(), 3_000);
        let elapsed = t.elapsed();
        let reqs = chain.header_requests.borrow();
        let headers: u64 = reqs.iter().map(|r| r.1).sum();
        eprintln!(
            "{name}: sync {elapsed:?}; {headers} headers requested ({} bytes, {} hex) in {} \
             requests; RandomX hashes so far {}",
            headers * 100,
            headers * 200,
            reqs.len(),
            light.1.load(Ordering::Relaxed)
        );
    }
}

/// W3-39b: a checked wallet's next check continues from its own last
/// headers (checked from the genesis by the restore, and saved in the
/// wallet file): it reads no header below them, across a RandomX key
/// switch whose key block lies below them.
#[test]
fn a_later_check_continues_from_the_wallets_own_checked_headers() {
    let mut chain = fast_chain(17, 2_150);
    let mut w = restored(None, 2_000);
    assert_eq!(w.sync(&chain).unwrap(), 2_150);
    assert_eq!(w.headers_checked_through(), Some(2_150));
    let to = wallet().primary();
    // Past the key switch at 2 113, the key block is 2 048, below the 87
    // headers the wallet keeps (2 064 to 2 150).
    while chain.height() < 2_200 {
        chain.mine(&to, 0);
    }
    let mut w = Wallet::from_json(&w.to_json()).unwrap();
    w.set_header_pow(Arc::new(ZeroPow));
    w.set_verify_headers(true);
    chain.header_requests.borrow_mut().clear();
    assert_eq!(w.sync(&chain).unwrap(), 2_200);
    assert_eq!(w.headers_checked_through(), Some(2_200));
    assert!(
        chain
            .header_requests
            .borrow()
            .iter()
            .all(|&(from, _)| from >= 2_150),
        "{:?}",
        chain.header_requests.borrow()
    );
    // A forged header after it is still refused.
    chain.mine(&to, 0);
    let tip = chain.height() as usize;
    // Any change forges it; `^= 1` and not `+= 1`, which overflows the
    // fixture's maximal difficulty under overflow checks (run C).
    chain.blocks[tip].header.difficulty ^= 1;
    assert!(w.sync(&chain).is_err());
}

/// CB-B2 note (demonstrated on the base, 47179f1: the transaction was kept
/// and its input stayed reserved): a stored PX transaction whose validity
/// window (PX6) has passed can never be mined; it is dropped and its input
/// released, with a warning.
#[test]
fn a_px_transaction_past_its_window_is_dropped_not_rebroadcast() {
    let mut chain = chain_with(11, 20, &[]);
    let mut w = wallet();
    w.sync(&chain).unwrap();
    let mut tx = chain.px_tx();
    tx.window = blacksilk_tx::px::Window {
        not_before: 0,
        not_after: 22,
    };
    w.px.records.push(crate::px::StoredRecord {
        index: 0,
        height: 5,
        commitment: digest_hex(&[1; 8]),
        position: Some(0),
        value: 5,
        data: digest_hex(&[0; 8]),
        rho: digest_hex(&[2; 8]),
        rcm: digest_hex(&[3; 8]),
        nullifier: digest_hex(&tx.nullifiers[0]),
        spent_height: None,
        pending: true,
        pending_height: 8,
        sibling: None,
    });
    w.pending_txs.push(PendingTx {
        tx: hex::encode(blacksilk_tx::types::Transaction::Px(Box::new(tx)).encode()),
        relayed_height: 8,
        branch_id: None,
        state: RebroadcastState::Uncertain,
        checked_height: 8,
    });
    // At 20 (next block 21, inside the window but within the expiring-soon
    // margin): kept and not sent (pools refuse it).
    w.refresh_pending(&chain);
    assert_eq!(w.pending_txs.len(), 1);
    assert!(w.px.records[0].pending);
    let to = wallet().primary();
    chain.mine(&to, 0);
    chain.mine(&to, 0);
    w.sync(&chain).unwrap();
    // At 22 the next block (23) is past the window.
    assert!(w.pending_txs.is_empty(), "dropped: its window has passed");
    assert!(!w.px.records[0].pending, "its input is released");
    assert!(w
        .take_warnings()
        .iter()
        .any(|m| m.contains("validity window")));
}

/// The wallet's commitment tree (with witnesses) survives the wallet file,
/// and a damaged tree is refused at load.
#[test]
fn the_tree_survives_the_wallet_file_and_a_damaged_one_is_refused() {
    let chain = chain_with(12, 40, &[3, 17, 30]);
    let mut w = wallet();
    w.sync(&chain).unwrap();
    let loaded = Wallet::from_json(&w.to_json()).unwrap();
    assert_eq!(loaded.px.tree, w.px.tree);
    let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
    let last = json["px"]["tree"]["window"].as_array().unwrap().len() - 1;
    json["px"]["tree"]["window"][last][0] = serde_json::Value::String(digest_hex(&[5; 8]));
    assert!(Wallet::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
    // A file written before the wallet's own tree (a `commitments` list):
    // rebuilt by a rescan, with a warning.
    let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
    json["px"].as_object_mut().unwrap().remove("tree");
    json["px"]["commitments"] = serde_json::json!([[3, digest_hex(&[1; 8])]]);
    let mut old = Wallet::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(old.take_warnings().iter().any(|m| m.contains("rescans")));
    assert_eq!(old.sync(&chain).unwrap(), 40);
    assert_eq!(old.px.tree.as_ref().unwrap().root(), chain.roots[40]);
}

/// W3-39b item 1 (header feed): a node serves a chain whose headers are
/// consistent with the LWMA rule from `difficulty_ancestors` headers before
/// the restore height on, but lighter than the rule from the genesis gives
/// below that (difficulty 1 where the honest chain's has risen). A restore
/// above those headers is refused: the check recomputes the difficulty from
/// the genesis. Honest restores at any height pass.
#[test]
fn a_restore_refuses_a_chain_lighter_than_the_genesis_rule() {
    let ancestors = ChainParams::regtest().difficulty_ancestors() as u64;
    let honest = fast_chain(13, 200);
    for restore in [ancestors + 20, 150] {
        let start = restore - ancestors;
        let mut chain = MockChain::new(13);
        chain.spacing = 1;
        chain.difficulty = Some(Box::new(move |h| (h < start).then_some(1)));
        let to = wallet().primary();
        for _ in 0..200 {
            chain.mine(&to, 0);
        }
        assert!(honest.blocks[start as usize - 1].header.difficulty > 1);
        let mut w = restored(None, restore);
        let e = w.sync(&chain).unwrap_err();
        assert!(e.to_string().contains("LWMA"), "{restore}: {e}");
        assert_eq!(w.synced_height(), restore - 1, "{restore}: nothing scanned");
    }
    for restore in [1, ancestors, ancestors + 1, 150, 200] {
        let mut w = restored(None, restore);
        assert_eq!(w.sync(&honest).unwrap(), 200, "{restore}");
        assert_eq!(w.headers_checked_through(), Some(200), "{restore}");
    }
}

/// W3-39b item 3 (the stale-tip relabel residual of W3-39): the node
/// withholds the block of a PX transaction (tip 152 of 160) and lists that
/// block's commitments under a height below the restore height (31). No PX
/// transaction lies between, so no anchor binds the backfill, and from 131
/// on the unconfirmed backfill may be used: the wallet's root at the
/// canonical anchor (144) would be the chain's root of block 153, a root no
/// honest wallet anchors at. The backfill's last block is checked against
/// the list: refused, and rebuilt from an honest node.
#[test]
fn a_stale_tip_cannot_relabel_withheld_commitments_into_the_backfill() {
    for relabelled in [30u64, 25] {
        let mut chain = chain_with(14, 160, &[3, 10, 25, 153]);
        chain.lies.tip = Some(152);
        chain.lies.relabel = Some(Box::new(move |_, h| if h == 153 { relabelled } else { h }));
        let mut w = Wallet::from_seed(Network::Regtest, [7; 32], 31);
        let r = w.sync(&chain);
        if let Ok(synced) = r {
            let anchor = w.px.anchor_root(synced);
            panic!(
                "{relabelled}: accepted; synced {synced}, anchor {:?} (chain root at 153: {})",
                anchor.map(|(h, r)| (h, digest_hex(&r))),
                digest_hex(&chain.roots[153])
            );
        }
        assert!(
            matches!(r, Err(WalletError::BadNodeData(_))),
            "{relabelled}: {r:?}"
        );
        assert!(w.px.tree.is_none(), "{relabelled}: dropped");
        chain.lies = Default::default();
        assert_eq!(w.sync(&chain).unwrap(), 160);
        assert_eq!(w.px.anchor_root(160).unwrap(), (144, chain.roots[144]));
    }
}

/// A chain with a vault deploy at 5 and a deploy of the vault with two
/// output words at 8 (valid on chain, uncallable as the vault), `n` blocks.
fn deploy_chain(seed: u64, n: u64) -> (MockChain, Digest, Digest) {
    use blacksilk_px::vault;
    use blacksilk_tx::px::Registration;
    let mut chain = MockChain::new(seed);
    let to = wallet().primary();
    let good = Registration::new(vault::VAULT_ELF.to_vec(), vault::BUDGET, vault::OUT_WORDS);
    let mut odd = good.clone();
    odd.out_words = 2;
    for h in 1..=n {
        let deploys = match h {
            5 => vec![chain.deploy(vec![good.clone()])],
            8 => vec![chain.deploy(vec![odd.clone()])],
            _ => vec![],
        };
        chain.mine_deploys(&to, vec![], deploys);
    }
    let id = |i: usize| crate::px::digest_from_hex(&chain.contracts[i].id).unwrap();
    let (a, b) = (id(0), id(1));
    (chain, a, b)
}

/// W3-39b item 2: registrations come from the deploys the wallet scans, not
/// from the node's list: a node that serves a wrong program id for one
/// contract and hides another changes nothing. The wallet knows every
/// registered program's ABI and output words, and refuses a vault
/// registered with two output words (it could never be called: funds locked
/// in it would be lost).
#[test]
fn registrations_come_from_scanned_deploys() {
    use blacksilk_px::vault;
    let (mut chain, good, odd) = deploy_chain(15, 20);
    chain.lies.contracts = Some(Box::new(|l| {
        l[0].programs[0].id = "ab".repeat(32);
        l.remove(1);
    }));
    let mut w = wallet();
    assert_eq!(w.sync(&chain).unwrap(), 20);
    assert_eq!(w.px.vault_budget(&good).unwrap(), vault::BUDGET);
    let e = w.px.vault_budget(&odd).unwrap_err().to_string();
    assert!(e.contains("output word"), "{e}");
}

/// W3-39b item 2: below the restore height the registrations come from the
/// deploy blocks the node lists, each checked against the header chain; a
/// node that lies about a registration (a program id, a budget, a deploy
/// listed at another height) or alters a deploy in the block it serves (its
/// output words) is refused. An honest node gives the chain's registrations.
#[test]
fn a_lying_registration_below_the_restore_height_is_detected() {
    use blacksilk_px::vault;
    use blacksilk_tx::types::Transaction;
    type Lie = Box<dyn Fn(&mut MockChain)>;
    let lies: Vec<(&str, Lie)> = vec![
        (
            "program id",
            Box::new(|c| {
                c.lies.contracts = Some(Box::new(|l| l[0].programs[0].id = "ab".repeat(32)))
            }),
        ),
        (
            "budget",
            Box::new(|c| c.lies.contracts = Some(Box::new(|l| l[1].programs[0].budget[0] += 1))),
        ),
        (
            "out words",
            Box::new(|c| {
                c.lies.alter_block = Some((
                    8,
                    Box::new(|b| {
                        for t in &mut b.txs {
                            if let Transaction::PxDeploy(d) = t {
                                d.programs[0].out_words = vault::OUT_WORDS;
                            }
                        }
                    }),
                ))
            }),
        ),
        (
            "height",
            // The deploy of block 8 listed at 5: block 5 holds one deploy.
            Box::new(|c| c.lies.contracts = Some(Box::new(|l| l[1].height = 5))),
        ),
    ];
    for restored_wallet in [false, true] {
        let fresh = || {
            if restored_wallet {
                restored(None, 20)
            } else {
                Wallet::from_seed(Network::Regtest, [7; 32], 20)
            }
        };
        for (what, lie) in &lies {
            let (mut chain, _, _) = deploy_chain(16, 40);
            lie(&mut chain);
            let mut w = fresh();
            let r = w.sync(&chain);
            assert!(
                matches!(r, Err(WalletError::BadNodeData(_))),
                "{what} ({restored_wallet}): {r:?}"
            );
        }
        let (chain, good, odd) = deploy_chain(16, 40);
        let mut w = fresh();
        assert_eq!(w.sync(&chain).unwrap(), 40);
        assert_eq!(w.px.vault_budget(&good).unwrap(), vault::BUDGET);
        let e = w.px.vault_budget(&odd).unwrap_err().to_string();
        assert!(e.contains("output word"), "{e}");
    }
}

/// W3-39c: the header check's verdict does not depend on how its
/// proof-of-work checks run. A reference check computes each header's work
/// as it arrives, on one thread (the check before W3-39c); the deferred
/// check queues them and computes them in parallel batches (`POW_BATCH`),
/// on 1, 2, 4 and 8 threads. On a mixed set of valid chains and chains with
/// forged proofs of work and forged difficulties (before, after and across
/// batch boundaries), both refuse the same header with the same message, or
/// both accept.
#[test]
fn parallel_and_sequential_verdicts_agree() {
    use crate::headers::{HeaderCheck, POW_BATCH};
    const N: u64 = 700;
    let chain = fast_chain(21, N);
    let params = ChainParams::regtest();
    let honest: Vec<BlockHeader> = (1..=N).map(|h| chain.blocks[h as usize].header).collect();
    let b = POW_BATCH as u64;
    // (heights whose proof of work fails, height whose difficulty is forged)
    let scenarios: Vec<(Vec<u64>, Option<u64>)> = vec![
        (vec![], None),
        (vec![650], None),
        (vec![100, 600], None),
        (vec![300], Some(500)),
        (vec![550], Some(200)),
        (vec![b, b + 1], None),
        (vec![b + 1], Some(b + 2)),
        (vec![2 * b + 3], Some(2 * b + 3)),
        (vec![N], None),
        (vec![], Some(640)),
    ];
    for (bad, forged) in scenarios {
        let mut headers = honest.clone();
        if let Some(f) = forged {
            headers[f as usize - 1].difficulty += 1;
        }
        let pow = BadPow::default();
        pow.bad
            .lock()
            .unwrap()
            .extend(bad.iter().map(|&h| headers[h as usize - 1].to_bytes()));
        let run = |threads: usize, deferred: bool| {
            // Every header's work is checked (samples = expected).
            let mut c = HeaderCheck::from_genesis(&params, &pow, N, N, u64::MAX / 2).unwrap();
            c.set_threads(threads);
            let mut verdict = Ok(());
            for h in &headers {
                verdict = if deferred {
                    c.check_deferred(h, false)
                } else {
                    c.check(h, false)
                };
                if verdict.is_err() {
                    break;
                }
            }
            if verdict.is_ok() {
                verdict = c.flush();
            }
            (verdict, c.refused_height(), c.pow_checked)
        };
        let reference = run(1, false);
        // The scenario bites where it should: the first failure in chain
        // order.
        let first = bad
            .iter()
            .copied()
            .filter(|&h| headers[h as usize - 1].difficulty > 1)
            .chain(forged)
            .min();
        assert_eq!(reference.1, first, "{bad:?} {forged:?}");
        if let Some(h) = first {
            let e = reference.0.as_ref().unwrap_err();
            assert!(e.contains(&format!("header {h}")), "{e}");
        }
        for threads in [1, 2, 4, 8] {
            let parallel = run(threads, true);
            assert_eq!(
                (&parallel.0, parallel.1),
                (&reference.0, reference.1),
                "{threads} threads, {bad:?} {forged:?}"
            );
            if threads == 1 {
                assert_eq!(parallel.2, reference.2, "the same hashes, one by one");
            }
        }
    }
}

/// W3-39c, through a restore (the check's threads: every available one): a
/// forged proof of work in the dense tail, in the header feed (below the
/// restore height) or in the scanned blocks, is refused at its block, as
/// the one-by-one check refused it: the blocks below it applied, none from
/// it on, whatever block of its batch of 100 it is.
#[test]
fn a_parallel_restore_refuses_at_the_forged_block() {
    let chain = fast_chain(22, 400);
    for bad in [150u64, 330, 399] {
        for restore in [100u64, 360] {
            let pow = Arc::new(BadPow::default());
            pow.bad
                .lock()
                .unwrap()
                .push(chain.blocks[bad as usize].header.to_bytes());
            let mut w = restored(Some(pow.clone()), restore);
            let e = w.sync(&chain).unwrap_err().to_string();
            assert!(e.contains(&format!("header {bad}'s proof of work")), "{e}");
            let want = if bad >= restore { bad - 1 } else { restore - 1 };
            assert_eq!(w.synced_height(), want, "bad {bad} restore {restore}");
        }
    }
}

/// W3-39c measurement (ignored; run with `--ignored --nocapture`): the
/// header check's 720-header dense tail with RandomX light mode (each hash
/// computed, then accepted: the chain is mined with the stand-in), on one
/// thread and on every available thread, the results compared.
#[test]
#[ignore]
fn dense_tail_pow_720_headers_sequential_and_parallel() {
    use crate::headers::HeaderCheck;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Measured(blacksilk_consensus::RandomXPow, AtomicU64);
    impl PowFunction for Measured {
        fn pow_hash(&self, seed: &Hash, header: &[u8]) -> Hash {
            self.1.fetch_add(1, Ordering::Relaxed);
            let _ = self.0.pow_hash(seed, header);
            [0; 32]
        }
    }
    const N: u64 = 720;
    let chain = fast_chain(23, N);
    let params = ChainParams::regtest();
    let pow = Measured(blacksilk_consensus::RandomXPow::new(), AtomicU64::new(0));
    // The light cache is built once, outside the measurement.
    let _ = pow
        .0
        .pow_hash(&params.genesis_id(), &[0; blacksilk_consensus::HEADER_SIZE]);
    let all = std::thread::available_parallelism().map_or(1, |n| n.get());
    for threads in [1, all] {
        let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
        c.set_threads(threads);
        let before = pow.1.load(Ordering::Relaxed);
        let t = std::time::Instant::now();
        for h in 1..=N {
            c.check_deferred(&chain.blocks[h as usize].header, true)
                .unwrap();
        }
        c.flush().unwrap();
        let elapsed = t.elapsed();
        let hashes = pow.1.load(Ordering::Relaxed) - before;
        eprintln!(
            "{threads} thread(s): {hashes} light hashes in {elapsed:?} ({:?} per hash)",
            elapsed / hashes.max(1) as u32
        );
    }
}

/// `HeaderCheck::resume` takes only consecutive, linked headers, at least
/// the context the difficulty rule needs (mutation run E: no test resumed
/// from a broken or short start). A header whose height or parent alone is
/// wrong is refused, as is one header too few.
#[test]
fn a_header_check_resumes_only_from_linked_headers_with_enough_context() {
    use crate::headers::HeaderCheck;
    let chain = fast_chain(31, 200);
    let params = ChainParams::regtest();
    let pow = ZeroPow;
    let seeds = [(0u64, params.genesis_id())];
    let n = HeaderCheck::context_len(&params);
    assert!(n < 150);
    let headers: Vec<BlockHeader> = (1..=200).map(|h| chain.blocks[h as usize].header).collect();
    let start = &headers[200 - n..];
    let resume =
        |s: &[BlockHeader]| HeaderCheck::resume(&params, &pow, s, &seeds, 10, 10, u64::MAX / 2);
    let mut c = resume(start).expect("a linked start with the context");
    assert_eq!(c.last().0, headers[199]);
    // The next header checks against it.
    let more = fast_chain(31, 201);
    assert_eq!(more.blocks[200].header, headers[199]);
    c.check(&more.blocks[201].header, true).unwrap();
    let e = resume(&start[1..]).err().expect("one header too few");
    assert!(e.contains("too few headers"), "{e}");
    let mut gap = start.to_vec();
    gap.remove(n / 2);
    gap.push(headers[0]); // keep the length
    let e = resume(&gap).err().expect("refused");
    assert!(e.contains("does not extend"), "{e}");
    // The last header at a wrong height (its parent is right).
    let mut height = start.to_vec();
    height.last_mut().unwrap().height += 1;
    let e = resume(&height).err().expect("refused");
    assert!(e.contains("does not extend"), "{e}");
    // The last header on another parent (its height is right).
    let mut parent = start.to_vec();
    parent.last_mut().unwrap().prev_id = [9; 32];
    let e = resume(&parent).err().expect("refused");
    assert!(e.contains("does not extend"), "{e}");
}

/// Below the forced headers, a check samples about `samples` of `expected`
/// headers for proof of work (mutation run E: the sampling rate had no
/// test). With half of 600 headers expected, the count of hashes computed
/// stays within six standard deviations of half the headers that need one
/// (difficulty above 1); forcing every header computes them all.
#[test]
fn the_header_check_samples_at_the_requested_rate() {
    use crate::headers::HeaderCheck;
    const N: u64 = 600;
    let chain = fast_chain(32, N);
    let params = ChainParams::regtest();
    let headers: Vec<BlockHeader> = (1..=N).map(|h| chain.blocks[h as usize].header).collect();
    let need = headers.iter().filter(|h| h.difficulty > 1).count() as f64;
    assert!(need > 500.0, "{need}");
    let run = |samples: u64, force: bool| {
        let pow = BadPow::default();
        let mut c = HeaderCheck::from_genesis(&params, &pow, N, samples, u64::MAX / 2).unwrap();
        for h in &headers {
            c.check_deferred(h, force).unwrap();
        }
        c.flush().unwrap();
        c.pow_checked as f64
    };
    let half = run(N / 2, false);
    let sd = (need / 4.0).sqrt();
    assert!((half - need / 2.0).abs() <= 6.0 * sd, "{half} of {need}");
    assert_eq!(run(0, true), need, "forced: every one");
    assert_eq!(run(N, false), need, "samples = expected: every one");
}

/// The check's thread count (at least 1) and its known key blocks.
#[test]
fn the_header_checks_threads_and_key_blocks() {
    use crate::headers::HeaderCheck;
    let params = ChainParams::regtest();
    let pow = ZeroPow;
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
    let all = std::thread::available_parallelism().map_or(1, |n| n.get());
    assert_eq!(c.threads(), all);
    c.set_threads(3);
    assert_eq!(c.threads(), 3);
    c.set_threads(0);
    assert_eq!(c.threads(), 1);
    assert!(c.has_seed(0), "the genesis is the first key block");
    assert!(!c.has_seed(1) && !c.has_seed(params.seed_epoch));
}

/// A check from the genesis hands its last headers and its key blocks to
/// the wallet, so the next check resumes from them, also when the restore
/// scanned fewer blocks than the context holds (mutation run E: in the
/// existing resume test the scanned blocks alone held the context and the
/// key block). The context is the last `context_len` headers checked, never
/// the genesis; a check keeps no more of them.
#[test]
fn a_restores_header_check_hands_its_context_and_keys_to_the_next() {
    use crate::headers::HeaderCheck;
    let params = ChainParams::regtest();
    let n = HeaderCheck::context_len(&params);
    // Past the key switch at 2 113 (key block 2 048), restored two blocks
    // below the tip; and a chain shorter than the context.
    for (len, restore, more) in [(2_150u64, 2_149u64, 2_200u64), (52, 50, 60)] {
        let mut chain = fast_chain(33, len);
        let mut w = restored(None, restore);
        assert_eq!(w.sync(&chain).unwrap(), len);
        assert_eq!(w.headers_checked_through(), Some(len));
        let to = wallet().primary();
        while chain.height() < more {
            chain.mine(&to, 0);
        }
        let mut w = Wallet::from_json(&w.to_json()).unwrap();
        w.set_header_pow(Arc::new(ZeroPow));
        w.set_verify_headers(true);
        chain.header_requests.borrow_mut().clear();
        assert_eq!(w.sync(&chain).unwrap(), more);
        assert_eq!(w.headers_checked_through(), Some(more));
        assert!(
            chain
                .header_requests
                .borrow()
                .iter()
                .all(|&(from, _)| from >= len),
            "{len}: {:?}",
            chain.header_requests.borrow()
        );
    }
    // The check's own context.
    let chain = fast_chain(34, 200);
    let pow = ZeroPow;
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
    for h in 1..=20 {
        c.check(&chain.blocks[h as usize].header, false).unwrap();
    }
    let heights: Vec<u64> = c.context().map(|h| h.height).collect();
    assert_eq!(heights, (1..=20).collect::<Vec<u64>>(), "no genesis");
    for h in 21..=200 {
        c.check(&chain.blocks[h as usize].header, false).unwrap();
    }
    let heights: Vec<u64> = c.context().map(|h| h.height).collect();
    assert_eq!(heights, (201 - n as u64..=200).collect::<Vec<u64>>());
    assert_eq!(
        c.seeds().collect::<Vec<_>>(),
        vec![(0, params.genesis_id())],
        "the only key block below 2 048"
    );
}

/// Deferred proof-of-work checks are computed in batches of `POW_BATCH`:
/// none while fewer are queued, all of them when the batch fills, the rest
/// at `flush` (mutation run E: the batch's edge had no test).
#[test]
fn deferred_proof_of_work_is_computed_in_batches_of_pow_batch() {
    use crate::headers::{HeaderCheck, POW_BATCH};
    use std::sync::atomic::Ordering;
    assert_eq!(POW_BATCH, 256);
    let n = POW_BATCH as u64 + 20;
    let chain = fast_chain(35, n);
    let params = ChainParams::regtest();
    let pow = BadPow::default();
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
    let headers: Vec<BlockHeader> = (1..=n).map(|h| chain.blocks[h as usize].header).collect();
    // Only headers above difficulty 1 queue a check; force every one.
    let mut queued = 0;
    for h in &headers {
        c.check_deferred(h, true).unwrap();
        queued += usize::from(h.difficulty > 1);
        let calls = pow.calls.load(Ordering::Relaxed) as usize;
        if queued < POW_BATCH {
            assert_eq!(calls, 0, "{queued} queued: none computed yet");
        } else if queued == POW_BATCH {
            assert_eq!(calls, POW_BATCH, "the batch is full: computed");
        }
    }
    assert!(queued > POW_BATCH, "{queued}");
    assert_eq!(pow.calls.load(Ordering::Relaxed) as usize, POW_BATCH);
    c.flush().unwrap();
    assert_eq!(pow.calls.load(Ordering::Relaxed) as usize, queued);
}

/// Each header must extend the last one checked, by height and by parent,
/// each on its own (mutation run E: the header feed's own linkage checks
/// had masked this one). The refusal names the expected height, and the
/// check is spent after it.
#[test]
fn a_header_check_refuses_a_header_off_its_parent_or_height() {
    use crate::headers::HeaderCheck;
    let chain = fast_chain(36, 12);
    let params = ChainParams::regtest();
    let pow = ZeroPow;
    let header = |h: u64| chain.blocks[h as usize].header;
    let fresh = || {
        let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
        for h in 1..=10 {
            c.check(&header(h), false).unwrap();
        }
        c
    };
    let mut c = fresh();
    let mut other_parent = header(11);
    other_parent.prev_id = header(9).id(params.network_id);
    let e = c.check(&other_parent, false).unwrap_err();
    assert!(e.contains("does not extend header 10"), "{e}");
    assert_eq!(c.refused_height(), Some(11));
    assert!(
        c.check(&header(11), false).is_err(),
        "spent after a refusal"
    );
    let mut c = fresh();
    let mut other_height = header(11);
    other_height.height = 12;
    let e = c.check(&other_height, false).unwrap_err();
    assert!(e.contains("does not extend header 10"), "{e}");
    let mut c = fresh();
    c.check(&header(11), false).unwrap();
    c.check(&header(12), false).unwrap();
}

/// The future time limit is inclusive: a header stamped exactly `now +
/// future_time_limit` is checked, one second later is refused (mutation run
/// E: the edge had no test).
#[test]
fn the_header_checks_future_time_limit_is_inclusive() {
    use crate::headers::HeaderCheck;
    let chain = fast_chain(37, 1);
    let params = ChainParams::regtest();
    let pow = ZeroPow;
    let header = chain.blocks[1].header;
    let edge = header.timestamp - params.future_time_limit;
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, edge).unwrap();
    c.check(&header, false).expect("exactly at the limit");
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, edge - 1).unwrap();
    let e = c.check(&header, false).unwrap_err();
    assert!(e.contains("in the future"), "{e}");
}

/// With more than one thread, the proof-of-work checks run on helper
/// threads too (W3-39c; mutation run E: no test saw which threads ran
/// them). The stand-in's first hash waits, up to 30 s, for a hash on another
/// thread: with helpers it comes at once; without, the check takes 30 s.
#[test]
fn deferred_proof_of_work_runs_on_helper_threads() {
    use crate::headers::HeaderCheck;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    #[derive(Default)]
    struct Threads {
        seen: Mutex<std::collections::HashSet<std::thread::ThreadId>>,
        more: Condvar,
        waited: std::sync::atomic::AtomicBool,
    }
    impl PowFunction for Threads {
        fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
            let mut seen = self.seen.lock().unwrap();
            seen.insert(std::thread::current().id());
            self.more.notify_all();
            // Only the first hash waits (once, not per hash, on one thread).
            if !self.waited.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let _ = self
                    .more
                    .wait_timeout_while(seen, Duration::from_secs(30), |s| s.len() < 2)
                    .unwrap();
            }
            [0; 32]
        }
    }
    let chain = fast_chain(38, 40);
    let params = ChainParams::regtest();
    let pow = Threads::default();
    let mut c = HeaderCheck::from_genesis(&params, &pow, 0, 0, u64::MAX / 2).unwrap();
    c.set_threads(4);
    for h in 1..=40 {
        c.check_deferred(&chain.blocks[h as usize].header, true)
            .unwrap();
    }
    let t = std::time::Instant::now();
    c.flush().unwrap();
    assert!(pow.seen.lock().unwrap().len() >= 2, "helpers computed some");
    assert!(t.elapsed() < Duration::from_secs(30));
}

/// The dense tail is exactly the node's last `DENSE_POW_TAIL` headers, plus
/// the first block scanned: with sampling off, a restore hashes those and
/// nothing else (mutation run E: the tail's lower edge had no exact test).
#[test]
fn the_dense_tail_is_exactly_the_last_720_headers_and_the_first() {
    use std::sync::atomic::Ordering;
    const N: u64 = 1_000;
    let chain = fast_chain(39, N);
    let tail = super::DENSE_POW_TAIL;
    assert_eq!(tail, 720);
    let forced: Vec<u64> = std::iter::once(1)
        .chain(N - tail + 1..=N)
        .filter(|&h| chain.blocks[h as usize].header.difficulty > 1)
        .collect();
    assert!(forced.len() as u64 >= tail, "{}", forced.len());
    let pow = Arc::new(BadPow::default());
    let mut w = restored(Some(pow.clone()), 1);
    w.set_header_samples(0);
    assert_eq!(w.sync(&chain).unwrap(), N);
    assert_eq!(pow.calls.load(Ordering::Relaxed), forced.len() as u64);
    // The header just below the tail is not forced: a forgery there passes
    // an unsampled check, one at the tail's lowest header does not.
    for (h, refused) in [(N - tail, false), (N - tail + 1, true)] {
        let pow = Arc::new(BadPow::default());
        pow.bad
            .lock()
            .unwrap()
            .push(chain.blocks[h as usize].header.to_bytes());
        let mut w = restored(Some(pow), 1);
        w.set_header_samples(0);
        assert_eq!(w.sync(&chain).is_err(), refused, "{h}");
    }
}

/// The header feed's pages are checked before use: a page from another
/// height, an empty page, a page with a partial header and a page with more
/// headers than asked are each refused as malformed (mutation run E: no
/// test served a malformed page, each fault on its own).
#[test]
fn a_malformed_header_feed_page_is_refused() {
    use crate::node::NodeApi;
    use blacksilk_rpc as rpc;
    struct Feed<'a> {
        chain: &'a MockChain,
        lie: u8,
    }
    impl NodeApi for Feed<'_> {
        fn info(&self) -> Result<rpc::Info, String> {
            self.chain.info()
        }
        fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
            self.chain.blocks(from, count)
        }
        fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
            let mut r = self.chain.headers(from, count)?;
            if from == 1 {
                match self.lie {
                    0 => r.from += 1,
                    1 => r.headers.clear(),
                    2 => r.headers.push_str("00"),
                    3 => r.headers.push_str(&hex::encode(
                        self.chain.blocks[(from + count) as usize].header.to_bytes(),
                    )),
                    _ => {}
                }
            }
            Ok(r)
        }
        fn distribution(&self, to: u64) -> Result<rpc::Distribution, String> {
            self.chain.distribution(to)
        }
        fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
            self.chain.outputs(indices)
        }
        fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String> {
            self.chain.submit_tx(tx)
        }
        fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
            self.chain.px_commitments(from)
        }
        fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
            self.chain.px_contracts(from)
        }
    }
    let chain = fast_chain(40, 60);
    let mut honest = restored(None, 50);
    assert_eq!(
        honest
            .sync(&Feed {
                chain: &chain,
                lie: 9
            })
            .unwrap(),
        60
    );
    for lie in 0..4 {
        let mut w = restored(None, 50);
        let e = w
            .sync(&Feed { chain: &chain, lie })
            .unwrap_err()
            .to_string();
        assert!(e.contains("missing or malformed"), "lie {lie}: {e}");
        assert_eq!(w.synced_height(), 49, "lie {lie}: nothing scanned");
    }
}
