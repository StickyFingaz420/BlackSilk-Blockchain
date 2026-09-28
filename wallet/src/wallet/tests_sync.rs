//! Adversarial sync tests (dossier 39 W1, W5; CB-B2 rebroadcast note): a
//! scripted node (`mock_chain`) that lies about the PX commitment list, its
//! blocks or its headers, against the wallet's own tree and header check.

use super::mock_chain::{MockChain, ZeroPow};
use super::*;
use crate::px::digest_hex;
use blacksilk_consensus::{Hash, PowFunction};
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
    // Sampling: with the default rate, the tip is always checked, and far
    // fewer than all headers are hashed.
    let pow = Arc::new(BadPow::default());
    let long = fast_chain(9, 300);
    let mut w = restored(Some(pow.clone()), 1);
    w.sync(&long).unwrap();
    let calls = pow.calls.load(std::sync::atomic::Ordering::Relaxed);
    assert!((2..120).contains(&calls), "{calls} hashes for 300 headers");
}

/// W5: a restore from a height above the genesis recomputes the difficulty
/// from the node's headers before it (not anchored at the genesis), and a
/// routine sync checks only when asked.
#[test]
fn the_header_check_from_a_later_restore_and_opt_in() {
    let mut chain = fast_chain(10, 200);
    let mut w = restored(None, 150);
    assert_eq!(w.sync(&chain).unwrap(), 200);
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
