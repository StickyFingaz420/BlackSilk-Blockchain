//! Sync policy shared by every path that lets outside data make this node
//! compute RandomX: P2P header sync (`p2p/src/net/headers.rs`) and the RPC
//! `/block` gate (`node/src/lib.rs`). One rule, one place (R16-5; decisions
//! "Agent 07" W2 and "Agent 31" S1). Node policy, not consensus: nothing here
//! changes whether a header or block is valid, only whether this node spends
//! proof-of-work time and memory on it.
//!
//! - [`worth_verifying`], [`anti_dos_threshold`]: the anti-DoS work gate
//!   (R1-C1): RandomX is spent only on headers that can make a chain
//!   competitive with our best one (docs/p2p.md §6).
//! - [`seed_is_live`]: the RandomX keys an unknown-version header may be
//!   hashed under (RTW1-1 (c)).
//! - [`hot_seeds`]: the keys whose caches the node keeps built and prebuilds
//!   (`PowFunction::set_hot_seeds`, 07 W1).
//! - [`pow_chunk`]: the header proof-of-work chunk, capped so that no header
//!   is hashed under a key taken from an unverified header of its own chunk
//!   (F07-4, F31-8).
//! - [`caught_up`], [`template_ready`]: whether the node serves block
//!   templates (dossier 09 M9-2, RTW3-1): never mid-drain, and before the
//!   node's catch-up latch sets only once it has caught up (tip recent,
//!   bodies at most [`TEMPLATE_SYNC_SLACK`] blocks below the best header).
//! - [`next_seed_height`]: the next RandomX key announced with a template
//!   (Monero's `next_seed_hash`), for the miner's prebuild.

use blacksilk_consensus::pow::HOT_SEEDS;
use blacksilk_consensus::{seed_height, BlockHeader, ChainParams, Hash, HeaderChain, Network};

/// Blocks of main-chain work below our best that a competing branch may lack
/// and still be verified and stored (R1-C1; Bitcoin Core's anti-DoS work
/// threshold uses 144 blocks as well).
pub const ANTI_DOS_BLOCKS: u64 = 144;

/// Claimed cumulative work a branch must reach to be hashed and stored:
/// `best_work - work(last ANTI_DOS_BLOCKS main blocks)`, i.e. the work of our
/// best chain at `tip - ANTI_DOS_BLOCKS`. There is no hard-coded minimum
/// chain work (docs/p2p.md §12).
pub fn anti_dos_threshold(hc: &HeaderChain) -> u128 {
    let base = hc.height().saturating_sub(ANTI_DOS_BLOCKS);
    hc.main_id_at(base).and_then(|id| hc.work(&id)).unwrap_or(0)
}

/// Whether headers `fresh` (linked, not stored, every rule but PoW checked,
/// the first one's parent stored) are worth their proof of work: RandomX
/// hashes are spent only on headers that can make a chain competitive with
/// our best one (docs/p2p.md §6). The difficulties must be the required ones
/// (the pre-check passed, or the caller replaced an unchecked difficulty, of
/// an unknown-version header or of an RPC block, by the required one,
/// RTW1-1), so the sums below are the work this node would count for the
/// headers.
///
/// - The batch's claimed tip work reaches [`anti_dos_threshold`] (our best
///   work minus that of our last 144 blocks): verify. This covers every
///   extension of our best chain and near-tip competing branches.
/// - Otherwise, if the message was not a full batch (`full`), the peer's
///   branch ends here, far below our work: dropped.
/// - A full batch may be the start of a longer, heavier branch (a fork deeper
///   than one batch). It is verified only if its work per height is at least
///   half of our best chain's over the same heights (our tip's difficulty for
///   heights above our tip). Cheap branches (difficulty driven down with
///   spread-out timestamps) fail this; an honest competing branch, mined at
///   comparable difficulty, passes.
pub fn worth_verifying(hc: &HeaderChain, fresh: &[BlockHeader], full: bool) -> bool {
    let Some(first) = fresh.first() else {
        return true;
    };
    let Some(parent_work) = hc.work(&first.prev_id) else {
        return true; // not reached: the parent is stored
    };
    let batch: u128 = fresh.iter().map(|h| h.difficulty as u128).sum();
    if parent_work + batch >= anti_dos_threshold(hc) {
        return true;
    }
    if !full {
        return false;
    }
    let last = first.height + fresh.len() as u64 - 1;
    let tip = hc.height();
    let tip_difficulty = hc.tip().difficulty as u128;
    let ours = if first.height > tip {
        tip_difficulty * fresh.len() as u128
    } else {
        let top = last.min(tip);
        let work_at = |h: u64| hc.main_id_at(h).and_then(|id| hc.work(&id)).unwrap_or(0);
        work_at(top).saturating_sub(work_at(first.height - 1))
            + tip_difficulty * (last - top) as u128
    };
    batch.saturating_mul(2) >= ours
}

/// Whether `seed` is the RandomX key of the next block on our best chain, or
/// the key after it once the block holding it exists (the keys this node
/// keeps built). An unknown-version header under any other key is never
/// hashed, so it cannot make the node build (and evict) a cache (RTW1-1 (c)).
pub fn seed_is_live(hc: &HeaderChain, seed: &Hash) -> bool {
    let p = hc.params();
    let next = hc.height() + 1;
    [next, next + p.seed_epoch]
        .into_iter()
        .any(|h| hc.main_id_at(seed_height(h, p.seed_epoch, p.seed_lag)) == Some(*seed))
}

/// Heights of the blocks whose ids are the RandomX keys to keep built for a
/// best chain whose tip is at `tip`, most urgent first, at most
/// [`HOT_SEEDS`]: the next block's key, the key after it (from the moment
/// its block exists, `seed_lag` blocks before it is used: the prebuild
/// window), and the key a competing branch within [`ANTI_DOS_BLOCKS`] of the
/// tip may still use (dossier 07 §3.3: the pin window `[tip + 1 - 144,
/// tip + 1 + lag]`).
///
/// With the network parameters (epoch 2048, lag 64) the window spans 209 <
/// 2048 heights, so it holds at most one key switch and every key of the
/// window is returned (tested). With shorter test epochs the two most urgent
/// are kept.
pub fn hot_seed_heights(tip: u64, p: &ChainParams) -> Vec<u64> {
    let next = tip + 1;
    let lowest = next.saturating_sub(ANTI_DOS_BLOCKS).max(1);
    let mut out = Vec::with_capacity(HOT_SEEDS);
    for h in [next, next + p.seed_lag, lowest] {
        let s = seed_height(h, p.seed_epoch, p.seed_lag);
        if !out.contains(&s) && out.len() < HOT_SEEDS {
            out.push(s);
        }
    }
    out
}

/// The RandomX keys to keep built for our best header chain
/// ([`hot_seed_heights`], as block ids), for `PowFunction::set_hot_seeds`.
pub fn hot_seeds(hc: &HeaderChain) -> Vec<Hash> {
    hot_seed_heights(hc.height(), hc.params())
        .into_iter()
        .filter_map(|h| hc.main_id_at(h))
        .collect()
}

/// Headers hashed per proof-of-work chunk, from the configured `pow_threads`:
/// at most `seed_lag`. Each chunk is accepted before the next is hashed, and
/// a header's key is at least `seed_lag + 1` blocks below it, so a header's
/// key is never an unverified header of its own chunk: a batch with junk
/// proof of work cannot make the node build the cache of a key taken from it
/// (F07-4 / F31-8: with more than 65 threads, a chunk could hold both a fake
/// key block S and a header at S + 65).
pub fn pow_chunk(pow_threads: usize, p: &ChainParams) -> usize {
    let cap = usize::try_from(p.seed_lag).unwrap_or(usize::MAX).max(1);
    pow_threads.clamp(1, cap)
}

/// Blocks the best valid header chain may be ahead of the connected tip
/// while a node that has not latched yet counts as caught up
/// ([`caught_up`]). A header usually arrives a moment before its body (the
/// labnet shows `header_height = height + 1` most of the time), so 0 would
/// keep a node that is at the tip from latching; 2 also covers a body racing
/// a second header.
pub const TEMPLATE_SYNC_SLACK: u64 = 2;

/// The oldest the connected tip may be, in target block times, for a node
/// that has not latched yet to count as caught up ([`max_tip_age`]).
///
/// Why 24: the bound only has to tell "downloading old blocks" from "at the
/// network's tip".
/// - **Honest tips are younger.** At a steady hash rate the chance that no
///   block is found for 24 target times is `e^-24` (about `4e-11`). A tip's
///   timestamp may also trail the real time: a miner may stamp as low as the
///   median of the last 11 blocks plus one (about 6 target times back), and
///   clocks differ by seconds (docs/testnet.md §12.2). That leaves about 18
///   target times of margin.
/// - **Catch-up tips are older.** A node downloading history sees tips
///   stamped hours or days ago. Once its tip is within 24 target times of
///   the clock, about 24 blocks are left at most, and the header-gap rule
///   holds the gate for those whose headers are known.
/// - **A false "not caught up" only delays mining, and only before the
///   latch sets:** the next block from the network makes the tip recent. It
///   needs every miner to have been gone for 24 target times (48 minutes on
///   testnet) and this node to have restarted since. `--mine-from-stale-tip`
///   sets the latch for that case and for a network's first blocks on an
///   old genesis.
///
/// Bitcoin Core's initial-download latch uses 24 hours at 10-minute blocks
/// (144 target times, `DEFAULT_MAX_TIP_AGE`). Here the header-gap rule does
/// most of the work, so a shorter bound suffices.
pub const MAX_TIP_AGE_BLOCKS: u64 = 24;

/// The tip-age bound of [`caught_up`] in seconds: [`MAX_TIP_AGE_BLOCKS`]
/// target block times (48 minutes on testnet and mainnet). `None` on
/// regtest: its tests and lab networks mine at synthetic timestamps far
/// behind the real clock (Bitcoin Core likewise skips its initial-download
/// check for block templates on test chains), so only the drain and
/// header-gap rules apply there.
pub fn max_tip_age(p: &ChainParams) -> Option<u64> {
    (p.network != Network::Regtest).then(|| MAX_TIP_AGE_BLOCKS.saturating_mul(p.target_block_time))
}

/// Whether a node counts as caught up with its network at the local time
/// `now` (RTW3-1): what sets its catch-up latch ([`template_ready`]).
///
/// - **Not mid-drain** (`sync_pending`).
/// - **Headers:** bodies at most [`TEMPLATE_SYNC_SLACK`] blocks below the
///   best valid header.
/// - **Clock:** the connected tip's timestamp at most `max_tip_age` seconds
///   before `now` ([`max_tip_age`]; no bound when `None`). A tip stamped
///   ahead of `now` counts as recent.
pub fn caught_up(
    sync_pending: bool,
    height: u64,
    header_height: u64,
    tip_time: u64,
    now: u64,
    max_tip_age: Option<u64>,
) -> bool {
    !sync_pending
        && header_height.saturating_sub(height) <= TEMPLATE_SYNC_SLACK
        && max_tip_age.is_none_or(|age| tip_time.saturating_add(age) >= now)
}

/// Whether the node serves block templates (`/template`, docs/blocks.md
/// §9.4; dossier 09 M9-2, RTW3-1). Node policy, not consensus:
///
/// - **Never mid-drain** (`sync_pending`): between the steps of a bounded
///   drain the mempool is only partly revalidated, so a template could offer
///   transactions the next block cannot carry. A drain connects bodies the
///   node already holds and always ends; nobody can prolong it without
///   supplying real blocks.
/// - **Catch-up latch** (Bitcoin Core's initial-download latch): until the
///   node is first [`caught_up`], templates are refused, since a block mined
///   on a tip the network has passed is an orphan. Once caught up, the latch
///   (`latched`) sets and stays set for the life of the process: no header
///   lead closes the gate again. The W2-09b gate recomputed the header gap
///   on every request, so three bodiless headers on a synced node's tip (a
///   3-block private branch, at any minority hash rate) kept it from mining
///   until the bodies came or the headers were outworked (RT-W3).
/// - **No peer-count rule**: the first node of a network mines from genesis
///   alone (decisions "Agent 09"), once its genesis is recent or the
///   operator sets the latch (`--mine-from-stale-tip`).
pub fn template_ready(sync_pending: bool, latched: bool, caught_up: bool) -> bool {
    !sync_pending && (latched || caught_up)
}

/// The height of the block holding the RandomX key that templates at
/// `height` switch to next, while that block exists and the switch is ahead
/// (heights `S + 1 ..= S + lag` for the key block `S`), else `None`: Monero's
/// `next_seed_hash` window (`rx_seedheights`). The returned height is at
/// most `height - 1`, so the block is an ancestor of the template's parent.
pub fn next_seed_height(height: u64, epoch: u64, lag: u64) -> Option<u64> {
    let now = seed_height(height, epoch, lag);
    let next = seed_height(height + lag, epoch, lag);
    (next != now).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::merkle::tx_root;
    use blacksilk_consensus::PowFunction;
    use std::sync::Arc;

    /// Meets any difficulty: the tests here are about claimed work only.
    struct ZeroPow;
    impl PowFunction for ZeroPow {
        fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
            [0; 32]
        }
    }

    fn chain(n: usize) -> HeaderChain {
        let mut c = HeaderChain::new(ChainParams::regtest(), Arc::new(ZeroPow));
        let tip = c.tip_id();
        extend(&mut c, tip, n, 0);
        c
    }

    fn child(c: &HeaderChain, parent: Hash, tag: u8) -> BlockHeader {
        let t = c.template_on(parent).unwrap();
        let p = *c.header(&parent).unwrap();
        BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: parent,
            timestamp: t.min_timestamp.max(p.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: tx_root(&[[tag; 32]]),
            nonce: 0,
            ..Default::default()
        }
    }

    fn extend(c: &mut HeaderChain, parent: Hash, n: usize, tag: u8) -> Vec<Hash> {
        let mut p = parent;
        let mut ids = Vec::new();
        for _ in 0..n {
            let h = child(c, p, tag);
            p = c.accept(h, u64::MAX / 2).unwrap().id;
            ids.push(p);
        }
        ids
    }

    /// `n` linked, unstored headers after `parent`, each claiming
    /// `difficulty`.
    fn fresh(c: &HeaderChain, parent: Hash, n: usize, difficulty: u64) -> Vec<BlockHeader> {
        let nid = c.params().network_id;
        let mut out: Vec<BlockHeader> = Vec::new();
        let mut h = child(c, parent, 9);
        for _ in 0..n {
            h.difficulty = difficulty;
            out.push(h);
            let prev = h.id(nid);
            h.prev_id = prev;
            h.height += 1;
            h.timestamp += 1;
        }
        out
    }

    #[test]
    fn the_threshold_is_our_work_144_blocks_below_the_tip() {
        let c = chain(0);
        assert_eq!(anti_dos_threshold(&c), c.work(&c.tip_id()).unwrap());
        let c = chain(100);
        let genesis = c.main_id_at(0).unwrap();
        assert_eq!(
            anti_dos_threshold(&c),
            c.work(&genesis).unwrap(),
            "height <= 144"
        );
        let c = chain(300);
        let at = c.main_id_at(300 - ANTI_DOS_BLOCKS).unwrap();
        assert_eq!(anti_dos_threshold(&c), c.work(&at).unwrap());
    }

    /// The three cases of the gate (31 S1): an extension of the best chain,
    /// a near-tip rival, and a cheap branch forking deep below the tip.
    #[test]
    fn worth_verifying_covers_extensions_rivals_and_cheap_deep_branches() {
        let c = chain(300);
        let tip = c.tip_id();
        assert!(
            worth_verifying(&c, &fresh(&c, tip, 1, 1), false),
            "extends the best"
        );
        assert!(worth_verifying(&c, &[], false), "nothing to hash");
        let near = c.main_id_at(290).unwrap();
        assert!(
            worth_verifying(&c, &fresh(&c, near, 1, 1), false),
            "near-tip rival"
        );

        let deep = c.main_id_at(10).unwrap();
        assert!(
            !worth_verifying(&c, &fresh(&c, deep, 5, 1), false),
            "a short deep branch far below our work"
        );
        // A full batch forking deep: judged by its work per height.
        let ours = c.work(&c.main_id_at(210).unwrap()).unwrap()
            - c.work(&c.main_id_at(10).unwrap()).unwrap();
        let per_height = (ours / 200) as u64;
        assert!(
            !worth_verifying(&c, &fresh(&c, deep, 200, 0), true),
            "zero work per height"
        );
        assert!(
            worth_verifying(&c, &fresh(&c, deep, 200, per_height.max(1)), true),
            "comparable work per height"
        );
        // A genesis-only chain has nothing to protect.
        let g = chain(0);
        let gen = g.tip_id();
        assert!(worth_verifying(&g, &fresh(&g, gen, 3, 1), false));
    }

    /// The pin window (07 T5): with the network key schedule the window
    /// `[tip + 1 - 144, tip + 1 + lag]` holds at most two keys, and
    /// `hot_seed_heights` returns exactly that set, next block's key first.
    #[test]
    fn hot_seed_heights_are_exactly_the_pin_window() {
        let p = ChainParams::testnet();
        assert_eq!((p.seed_epoch, p.seed_lag), (2048, 64));
        let key = |h: u64| seed_height(h, p.seed_epoch, p.seed_lag);
        for tip in 0..20_000u64 {
            let next = tip + 1;
            let mut window: Vec<u64> = (next.saturating_sub(ANTI_DOS_BLOCKS).max(1)
                ..=next + p.seed_lag)
                .map(key)
                .collect();
            window.dedup();
            assert!(window.len() <= HOT_SEEDS, "tip {tip}: {window:?}");
            let hot = hot_seed_heights(tip, &p);
            assert_eq!(hot[0], key(next), "tip {tip}");
            assert!(hot.contains(&key(next + p.seed_lag)), "tip {tip}");
            let mut sorted = hot.clone();
            sorted.sort();
            assert_eq!(sorted, window, "tip {tip}");
            assert!(hot.iter().all(|&s| s <= tip), "every key block exists");
        }
        // Around the first switch (2113): the next key is pinned from the
        // moment its block (2048) exists, the old one for 144 blocks after.
        assert_eq!(hot_seed_heights(2047, &p), vec![0]);
        assert_eq!(hot_seed_heights(2048, &p), vec![0, 2048]);
        assert_eq!(hot_seed_heights(2112, &p), vec![2048, 0]);
        assert_eq!(hot_seed_heights(2112 + 143, &p), vec![2048, 0]);
        assert_eq!(hot_seed_heights(2112 + 144, &p), vec![2048]);
    }

    #[test]
    fn hot_seeds_are_main_chain_ids() {
        let mut p = ChainParams::regtest();
        p.seed_epoch = 16;
        p.seed_lag = 4;
        let mut c = HeaderChain::new(p, Arc::new(ZeroPow));
        let g = c.tip_id();
        let ids = extend(&mut c, g, 18, 0);
        // Tip 18: the next block (19) uses genesis, the one at 21 block 16.
        assert_eq!(hot_seeds(&c), vec![g, ids[15]]);
        assert!(seed_is_live(&c, &g));
        assert!(!seed_is_live(&c, &[3; 32]));
    }

    /// Monero's `rx_seedheight` / `rx_seedheights`, transcribed independently
    /// of `seed_height` (src/crypto/rx-slow-hash.c): the next key is
    /// announced exactly when it differs from the current one.
    fn monero_seedheight(height: u64) -> u64 {
        const EPOCH: u64 = 2048;
        const LAG: u64 = 64;
        if height <= EPOCH + LAG {
            0
        } else {
            (height - LAG - 1) & !(EPOCH - 1)
        }
    }

    #[test]
    fn next_seed_heights_follow_monero_next_seed_hash() {
        for h in 0..20_000u64 {
            let (seed, next) = (monero_seedheight(h), monero_seedheight(h + 64));
            let expected = (next != seed).then_some(next);
            assert_eq!(next_seed_height(h, 2048, 64), expected, "height {h}");
            if let Some(n) = expected {
                assert!(n < h, "the key block exists below the template");
            }
        }
        let window: Vec<u64> = (2000..2200)
            .filter(|&h| next_seed_height(h, 2048, 64).is_some())
            .collect();
        assert_eq!(window, (2049..=2112).collect::<Vec<_>>());
        for (h, n) in [(2048, None), (2049, Some(2048)), (2112, Some(2048))] {
            assert_eq!(next_seed_height(h, 2048, 64), n, "height {h}");
        }
        for (h, n) in [
            (2113, None),
            (4096, None),
            (4097, Some(4096)),
            (4160, Some(4096)),
        ] {
            assert_eq!(next_seed_height(h, 2048, 64), n, "height {h}");
        }
        assert_eq!(next_seed_height(4161, 2048, 64), None);
    }

    /// Slack 2 and the tip-age bound decide `caught_up`; a pending drain
    /// never serves templates, latched or not; the latch overrides the rest.
    #[test]
    fn caught_up_needs_no_drain_a_small_header_gap_and_a_recent_tip() {
        assert_eq!(TEMPLATE_SYNC_SLACK, 2);
        let age = Some(2880);
        let now = 1_000_000;
        assert!(caught_up(false, 10, 10, now, now, age));
        assert!(caught_up(false, 10, 12, now, now, age));
        assert!(
            !caught_up(false, 10, 13, now, now, age),
            "a header gap of 3"
        );
        assert!(!caught_up(true, 10, 10, now, now, age), "mid-drain");
        assert!(
            caught_up(false, 10, 10, now - 2880, now, age),
            "at the bound"
        );
        assert!(!caught_up(false, 10, 10, now - 2881, now, age), "older");
        assert!(
            caught_up(false, 10, 10, now + 300, now, age),
            "stamped ahead"
        );
        assert!(caught_up(false, 10, 10, 0, now, None), "no bound");
        assert!(caught_up(false, 0, 0, 0, u64::MAX, None), "regtest genesis");

        assert!(template_ready(false, false, true));
        assert!(!template_ready(false, false, false), "catching up");
        assert!(template_ready(false, true, false), "latched");
        assert!(!template_ready(true, true, true), "mid-drain");
    }

    /// 24 target block times on testnet and mainnet, none on regtest.
    #[test]
    fn the_tip_age_bound_is_24_target_times_except_on_regtest() {
        assert_eq!(max_tip_age(&ChainParams::testnet()), Some(24 * 120));
        assert_eq!(max_tip_age(&ChainParams::mainnet()), Some(24 * 120));
        assert_eq!(max_tip_age(&ChainParams::regtest()), None);
    }

    /// F07-4 / F31-8: the chunk never exceeds the key lag.
    #[test]
    fn the_pow_chunk_is_capped_by_the_key_lag() {
        let p = ChainParams::testnet();
        assert_eq!(pow_chunk(128, &p), 64);
        assert_eq!(pow_chunk(8, &p), 8);
        assert_eq!(pow_chunk(0, &p), 1);
        let mut short = ChainParams::regtest();
        short.seed_lag = 4;
        assert_eq!(pow_chunk(16, &short), 4);
    }
}
