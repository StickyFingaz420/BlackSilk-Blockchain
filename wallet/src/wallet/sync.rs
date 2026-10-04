//! Synchronization with a node: network checks, rewinds, block scanning and
//! balances.

use super::{
    network_name, Balance, HeldOutput, HeldRecord, Holdings, StoredOutput, Wallet, WalletError,
    KEPT_BLOCK_IDS, RING_RETENTION_BLOCKS,
};
use crate::headers::HeaderCheck;
use crate::node::NodeApi;
use crate::px::{deployed, listed_as, PxStore};
use blacksilk_chain::block::Block;
use blacksilk_consensus::pow::seed_height;
use blacksilk_consensus::{BlockHeader, Hash, PowFunction, RandomXPow, HEADER_SIZE};
use blacksilk_crypto::stealth::ReceivedOutput;
use blacksilk_px_core::Digest;
use blacksilk_rpc as rpc;
use blacksilk_tx::params::{COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::Transaction;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const _: () = assert!(rpc::HEADER_BYTES == HEADER_SIZE);

/// RandomX key-block ids the wallet keeps from a header check: the keys of
/// the next headers are among the last two.
const KEPT_KEY_IDS: usize = 3;

/// The header check computes the proof of work of every header among the
/// node's last this many (RTW3-5), besides the sample below them. A forged
/// block forces the node to forge every header after it, so a forgery is
/// always a suffix of the node's chain, and one within this depth is caught
/// for sure; a deeper one covers at least this many headers of the sampled
/// range too. 720 blocks is the wallet's reorganization window
/// (`KEPT_BLOCK_IDS`).
pub const DENSE_POW_TAIL: u64 = 720;
const _: () = assert!(DENSE_POW_TAIL as usize == KEPT_BLOCK_IDS);

/// A tip older than this many target block times plus the future time limit
/// (against the local clock) is reported as stale (RTW3-6).
pub const STALE_TIP_WARN_BLOCKS: u64 = 10;

/// A tip older than this many target block times plus the future time limit
/// makes the wallet refuse to build transactions (RTW3-6). With a steady
/// hash rate the chance that the network finds no block for `k` target
/// times is `e^-k`; the future time limit covers a tip stamped ahead.
pub const STALE_TIP_REFUSE_BLOCKS: u64 = 60;

/// A duration in seconds, for messages.
pub fn format_age(secs: u64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7_200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3_600),
        s => format!("{} days", s / 86_400),
    }
}

/// `(warn, refuse)` tip ages in seconds for `params` (RTW3-6).
pub fn stale_tip_limits(params: &blacksilk_consensus::ChainParams) -> (u64, u64) {
    let t = params.target_block_time;
    let ftl = params.future_time_limit;
    (
        STALE_TIP_WARN_BLOCKS * t + ftl,
        STALE_TIP_REFUSE_BLOCKS * t + ftl,
    )
}

/// Where a header check starts (`Wallet::header_start`).
enum HeaderStart {
    /// From the genesis: the headers of the blocks up to the wallet's are
    /// read from the node's header feed and checked first.
    Genesis,
    /// From the wallet's own last headers, checked from the genesis by an
    /// earlier sync (`Wallet::checked_through`), with the RandomX key-block
    /// ids below them.
    Resume {
        start: Vec<BlockHeader>,
        seeds: Vec<(u64, Hash)>,
    },
}

/// The node's lists below the first block the wallet scans (the backfill).
struct BackfillLists {
    /// `/px/commitments` up to the base block.
    commitments: Vec<(u64, Digest)>,
    /// `/px/contracts` up to the base block.
    contracts: Vec<rpc::PxContractEntry>,
}

impl BackfillLists {
    /// The blocks checked against the lists: the one of the last commitment
    /// listed, and every one the contract list names.
    fn blocks(&self) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = self.contracts.iter().map(|c| c.height).collect();
        out.extend(self.commitments.last().map(|e| e.0));
        out
    }
}

/// The local time, seconds since the Unix epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Decodes a block the node served.
fn decode_block(entry: &rpc::BlockEntry) -> Result<Block, WalletError> {
    let bytes =
        hex::decode(&entry.hex).map_err(|_| WalletError::BadNodeData("block hex".into()))?;
    Block::decode(&bytes).map_err(|e| WalletError::BadNodeData(format!("{e:?}")))
}

/// Checks the headers of a batch of blocks in order (`decoded`, as served in
/// `entries`), their proof of work computed together (W3-39c): the first
/// header, the last `DENSE_POW_TAIL` of the node's chain (above
/// `dense_from`) always, others sampled. Stops at the first block that does
/// not decode (the scan refuses it first). Returns the position in the
/// batch of the first header refused, in chain order, and why.
fn check_batch(
    c: &mut HeaderCheck<'_>,
    entries: &[rpc::BlockEntry],
    decoded: &[Result<Block, WalletError>],
    first: u64,
    dense_from: u64,
) -> Option<(usize, String)> {
    let base = c.last().0.height + 1;
    // The refused header's position in the batch (a proof-of-work refusal
    // may name an earlier header than the one being checked).
    let at = |c: &HeaderCheck<'_>, e: String| -> (usize, String) {
        let height = c.refused_height().expect("a refusal has a height");
        (height.saturating_sub(base) as usize, e)
    };
    for (entry, block) in entries.iter().zip(decoded) {
        let Ok(block) = block else {
            break;
        };
        let force = entry.height == first || entry.height > dense_from;
        if let Err(e) = c.check_deferred(&block.header, force) {
            return Some(at(c, e));
        }
    }
    c.flush().err().map(|e| at(c, e))
}

/// Reads the headers of blocks `lo..=hi` from the node's header feed
/// (`/headers`, in pages) and hands each to `f`, in order. Each must be the
/// header of its height; how they link is the caller's check.
fn for_each_header(
    node: &dyn NodeApi,
    lo: u64,
    hi: u64,
    mut f: impl FnMut(BlockHeader) -> Result<(), WalletError>,
) -> Result<(), WalletError> {
    let mut h = lo;
    while h <= hi {
        let count = (hi - h + 1).min(rpc::MAX_HEADERS_PER_REQUEST);
        let resp = node.headers(h, count).map_err(WalletError::Node)?;
        let bytes = hex::decode(&resp.headers)
            .map_err(|_| WalletError::BadNodeData("header hex".into()))?;
        let n = bytes.len() / HEADER_SIZE;
        if resp.from != h || n == 0 || bytes.len() % HEADER_SIZE != 0 || n as u64 > count {
            return Err(WalletError::BadNodeData(format!(
                "the node's header feed from block {h} is missing or malformed"
            )));
        }
        for chunk in bytes.chunks(HEADER_SIZE) {
            let header = BlockHeader::from_bytes(chunk)
                .ok_or_else(|| WalletError::BadNodeData("block header".into()))?;
            if header.height != h {
                return Err(WalletError::BadNodeData(format!(
                    "expected header {h}, got {}",
                    header.height
                )));
            }
            f(header)?;
            h += 1;
        }
    }
    Ok(())
}

/// The headers of blocks `lo..=hi` from the node, each extending the one
/// before it.
fn fetch_headers(
    node: &dyn NodeApi,
    lo: u64,
    hi: u64,
    network_id: u32,
) -> Result<Vec<BlockHeader>, WalletError> {
    let mut out: Vec<BlockHeader> = Vec::new();
    for_each_header(node, lo, hi, |h| {
        if let Some(p) = out.last() {
            if h.prev_id != p.id(network_id) {
                return Err(WalletError::BadNodeData(format!(
                    "header {} does not extend header {}",
                    h.height, p.height
                )));
            }
        }
        out.push(h);
        Ok(())
    })?;
    Ok(out)
}

/// The id of the node's block at `height` (computed from its header), or
/// `None` if the node has none there.
fn node_id_at(
    node: &dyn NodeApi,
    height: u64,
    network_id: u32,
) -> Result<Option<Hash>, WalletError> {
    let resp = node.headers(height, 1).map_err(WalletError::Node)?;
    if resp.headers.is_empty() {
        return Ok(None);
    }
    let bytes =
        hex::decode(&resp.headers).map_err(|_| WalletError::BadNodeData("header hex".into()))?;
    match BlockHeader::from_bytes(&bytes) {
        Some(h) if h.height == height && resp.from == height => Ok(Some(h.id(network_id))),
        _ => Err(WalletError::BadNodeData(format!(
            "the node's header {height} is malformed"
        ))),
    }
}

/// The node's block at `height`, which must be the block of header id `id`
/// (its id recomputed, and its transactions those its `tx_root` commits
/// to).
fn fetch_block(
    node: &dyn NodeApi,
    height: u64,
    id: &Hash,
    network_id: u32,
) -> Result<Block, WalletError> {
    let entry = node
        .blocks(height, 1)
        .map_err(WalletError::Node)?
        .blocks
        .into_iter()
        .next()
        .filter(|e| e.height == height)
        .ok_or_else(|| WalletError::BadNodeData(format!("block {height} is missing")))?;
    let bytes =
        hex::decode(&entry.hex).map_err(|_| WalletError::BadNodeData("block hex".into()))?;
    let block = Block::decode(&bytes).map_err(|e| WalletError::BadNodeData(format!("{e:?}")))?;
    if block.id(network_id) != *id || block.compute_tx_root() != block.header.tx_root {
        return Err(WalletError::BadNodeData(format!(
            "block {height} is not the block of the header chain at that height"
        )));
    }
    Ok(block)
}

impl Wallet {
    // ---- sync ----
    pub(super) fn check_network(
        &self,
        node: &dyn NodeApi,
    ) -> Result<blacksilk_rpc::Info, WalletError> {
        let info = node.info().map_err(WalletError::Node)?;
        if info.network != network_name(self.network) {
            return Err(WalletError::WrongNetwork {
                wallet: network_name(self.network).into(),
                node: info.network,
            });
        }
        // The same network name is not enough: a release candidate, a
        // rehearsal or a retired identity uses it too (R15-3).
        let ours = hex::encode(self.genesis_id);
        match &info.genesis_id {
            Some(g) if g.eq_ignore_ascii_case(&ours) => {}
            other => {
                return Err(WalletError::WrongGenesis {
                    wallet: ours,
                    node: other.clone().unwrap_or_default(),
                })
            }
        }
        Ok(info)
    }

    /// Removes everything learned from blocks above `height`. A record
    /// credited for its key image that goes with them hands the credit back
    /// to a duplicate below the fork (RTW1-4).
    fn rewind(&mut self, height: u64) {
        // Below the first scanned block the PX tree and the registrations
        // are rebuilt from a fresh backfill: the chain below the restore
        // height may have changed.
        if height < self.restore_height {
            self.px.tree = None;
        }
        self.outputs.retain(|o| o.height <= height);
        for o in &mut self.outputs {
            if o.spent_height.is_some_and(|h| h > height) {
                o.spent_height = None;
            }
        }
        self.elect_credited();
        self.block_ids.retain(|h, _| *h <= height);
        self.headers.retain(|h| h.height <= height);
        self.checked_through = self.checked_through.map(|c| c.min(height));
        self.key_ids.retain(|h, _| *h <= height);
        self.index.rewind(height);
        let rescan = self.px.rewind(height);
        self.synced_height = height;
        if rescan && height >= self.restore_height {
            // The PX tree cannot go back that far: rescan from the restore
            // height, as for a reorganization deeper than the kept window.
            self.rewind(self.restore_height.saturating_sub(1));
        }
    }

    /// Scans new blocks. Detects reorganizations by comparing stored block ids with
    /// the node's, and rewinds to the fork point. Returns the new synced height.
    ///
    /// Every block's PX anchors are checked against the wallet's own tree
    /// (`crate::tree`), registrations are derived from the deploys
    /// (`crate::px::deployed`), and, for a restored wallet until it has
    /// caught up or when enabled (`set_verify_headers`), the header chain is
    /// checked from the genesis (`crate::headers`). A refused block is not
    /// applied: the wallet stays at the block before it.
    ///
    /// Once caught up, it also completes the output index (the one-time
    /// `/outputs` backfill below the restore height, `complete_index`), so
    /// that a later spend requests nothing but `/tx` (D1, RT-D1 F2). A failed
    /// backfill is a warning: the next sync, or the spend, tries again.
    pub fn sync(&mut self, node: &dyn NodeApi) -> Result<u64, WalletError> {
        let (h, tip) = self.sync_chain(node)?;
        if h >= tip && self.index_needs_backfill() {
            if let Err(e) = self.complete_index(node) {
                self.warnings.push(format!(
                    "the output index below the restore height could not be completed ({e}); \
                     the next sync tries again"
                ));
            }
        }
        Ok(h)
    }

    /// Whether the output index lacks outputs the wallet has not scanned
    /// (below its restore height, or all of them for a wallet file written
    /// before the index existed): the work of the one-time backfill.
    pub(super) fn index_needs_backfill(&self) -> bool {
        self.index.start() > 0
            || (self.index.is_empty()
                && self.synced_height > 0
                && self.synced_height >= self.restore_height)
    }

    /// The scan of `sync`, without completing the output index: returns the
    /// synced height and the node's height.
    fn sync_chain(&mut self, node: &dyn NodeApi) -> Result<(u64, u64), WalletError> {
        let info = self.check_network(node)?;
        if info.header_height > info.height {
            return Err(WalletError::Node(format!(
                "the node is still synchronizing ({} of {} blocks); try again later",
                info.height, info.header_height
            )));
        }
        let nid = self.params.network_id;
        // Reorg detection: walk back from our tip until our block id matches
        // the node's (read from its header feed: 100 bytes per height).
        let fresh = self.block_ids.is_empty();
        while self.synced_height >= self.restore_height && self.synced_height > 0 {
            let Some(ours) = self.block_ids.get(&self.synced_height).copied() else {
                if fresh {
                    break;
                }
                // Fork deeper than the kept window: rescan from the restore height.
                let h = self.restore_height.saturating_sub(1);
                self.rewind(h);
                break;
            };
            let theirs = if self.synced_height <= info.height {
                node_id_at(node, self.synced_height, nid)?
            } else {
                None
            };
            if theirs == Some(ours) {
                break;
            }
            let h = self.synced_height - 1;
            self.rewind(h);
        }
        // The PX tree and the registrations below the first block scanned:
        // built once, from the node's lists checked against the blocks.
        let backfill = if self.px.tree.is_none() {
            if self.synced_height >= self.restore_height {
                self.rewind(self.restore_height.saturating_sub(1));
            }
            let base = self.synced_height;
            Some(if base == 0 {
                BackfillLists {
                    commitments: Vec::new(),
                    contracts: Vec::new(),
                }
            } else {
                BackfillLists {
                    commitments: PxStore::fetch_commitments(node, base)?,
                    contracts: PxStore::fetch_contract_list(node, base)?,
                }
            })
        } else {
            None
        };
        let mut backfill_ids: BTreeMap<u64, Hash> = BTreeMap::new();
        let mut want: BTreeSet<u64> = backfill.as_ref().map_or_else(BTreeSet::new, |b| b.blocks());
        if backfill.is_some() {
            want.insert(self.synced_height);
        }

        // The header check, with local copies so it can run beside the scan.
        let params = self.params.clone();
        let pow: std::sync::Arc<dyn PowFunction> = self
            .header_pow
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(RandomXPow::new()));
        let bad = |e: String| WalletError::BadNodeData(format!("header chain: {e}"));
        let synced = self.synced_height;
        // Headers above this have their work computed, all of them (RTW3-5);
        // the sample is spread over those below it.
        let dense_from = info.height.saturating_sub(DENSE_POW_TAIL);
        let mut check = match self.header_start(&info) {
            None => None,
            Some(HeaderStart::Resume { start, seeds }) => Some(
                HeaderCheck::resume(
                    &params,
                    pow.as_ref(),
                    &start,
                    &seeds,
                    dense_from.saturating_sub(synced),
                    self.header_samples,
                    unix_now(),
                )
                .map_err(bad)?,
            ),
            Some(HeaderStart::Genesis) => {
                let mut c = HeaderCheck::from_genesis(
                    &params,
                    pow.as_ref(),
                    dense_from,
                    self.header_samples,
                    unix_now(),
                )
                .map_err(bad)?;
                // Every header below the first block scanned, from the
                // genesis (W3-39b), streamed: the ids the backfill needs are
                // kept, the rest is dropped. Their proof of work is computed
                // in parallel batches (W3-39c), all of it before anything
                // relies on them.
                if synced > 0 {
                    for_each_header(node, 1, synced, |h| {
                        c.check_deferred(&h, h.height > dense_from).map_err(bad)?;
                        if want.contains(&h.height) {
                            backfill_ids.insert(h.height, c.last().1);
                        }
                        Ok(())
                    })?;
                    c.flush().map_err(bad)?;
                    let (_, last) = c.last();
                    if self
                        .block_ids
                        .get(&synced)
                        .is_some_and(|ours| *ours != last)
                    {
                        return Err(WalletError::BadNodeData(
                            "the node's headers do not end at the wallet's last block".into(),
                        ));
                    }
                    self.headers = c.context().collect();
                    self.checked_through = Some(synced);
                    self.keep_key_ids(c.seeds());
                }
                Some(c)
            }
        };
        if let Some(lists) = backfill {
            self.backfill(node, lists, backfill_ids)?;
        }

        let first = self.synced_height + 1;
        let mut from = first;
        let keep_headers = HeaderCheck::context_len(&self.params);
        while from <= info.height {
            let batch = node
                .blocks(from, blacksilk_rpc::MAX_BLOCKS_PER_REQUEST)
                .map_err(WalletError::Node)?;
            if batch.blocks.is_empty() {
                break;
            }
            let decoded: Vec<Result<Block, WalletError>> =
                batch.blocks.iter().map(decode_block).collect();
            // The batch's headers are checked before any of its blocks is
            // applied, their proof of work in parallel (W3-39c). A refusal
            // is reported at its block, after the blocks before it are
            // applied, as a check block by block would.
            let refused = match check.as_mut() {
                Some(c) => check_batch(c, &batch.blocks, &decoded, first, dense_from),
                None => None,
            };
            for (i, (entry, block)) in batch.blocks.into_iter().zip(decoded).enumerate() {
                if entry.height != from {
                    return Err(WalletError::BadNodeData(format!(
                        "expected block {from}, got {}",
                        entry.height
                    )));
                }
                let block = block?;
                let id = block.id(nid);
                if hex::encode(id) != entry.id || block.compute_tx_root() != block.header.tx_root {
                    return Err(WalletError::BadNodeData(format!(
                        "block {from} does not match its id"
                    )));
                }
                // Each block must extend the one before it (review F6), the
                // first one the backfill's base.
                if let Some(prev) = self.block_ids.get(&(entry.height - 1)) {
                    if block.header.prev_id != *prev {
                        return Err(WalletError::BadNodeData(format!(
                            "block {from} does not extend the previous block"
                        )));
                    }
                }
                // Proof of work: checked when the header check runs (the
                // first header, the tip and the last `DENSE_POW_TAIL`
                // always, others sampled), by `check_batch` above.
                if let Some((at, e)) = &refused {
                    if *at == i {
                        return Err(WalletError::BadNodeData(format!("header chain: {e}")));
                    }
                }
                if let Err(e) = self.apply_block(&block, entry.height, entry.first_output) {
                    if !self.px.tree.as_ref().is_some_and(|t| t.is_confirmed()) {
                        // The node's list below the restore height may be
                        // what is wrong (or stale after a reorganization
                        // below it): the next sync rebuilds the tree from a
                        // fresh one, from this node or another.
                        self.rewind(self.restore_height.saturating_sub(1));
                    }
                    return Err(e);
                }
                self.block_ids.insert(entry.height, id);
                self.headers.push_back(block.header);
                while self.headers.len() > keep_headers {
                    self.headers.pop_front();
                }
                if check.is_some() {
                    self.checked_through = Some(entry.height);
                    if entry.height.is_multiple_of(self.params.seed_epoch) {
                        self.keep_key_ids([(entry.height, id)]);
                    }
                } else {
                    self.checked_through = None;
                }
                self.synced_height = entry.height;
                from += 1;
            }
            while self.block_ids.len() > KEPT_BLOCK_IDS {
                let first = *self.block_ids.keys().next().expect("non-empty");
                self.block_ids.remove(&first);
            }
        }
        if check.is_some() && self.synced_height >= info.height {
            // Caught up with a checked header chain.
            self.restore_check = false;
        }
        let synced = self.synced_height;
        self.note_tip_age(node)?;
        self.refresh_pending(node);
        for cm in self.px.resolve_lookups()? {
            self.warnings.push(format!(
                "imported record {cm} is not in the blocks this wallet keeps and not yet on \
                 chain after them: it is placed when its block is scanned, or, if it is older, \
                 at a rescan (restore the seed at a height below its block and import it again)"
            ));
        }
        self.px.retain_witnesses(synced, RING_RETENTION_BLOCKS);
        Ok((self.synced_height, info.height))
    }

    /// Records the age of the synced tip against the local clock, with a
    /// warning when it is stale (RTW3-6): a node that withholds its newest
    /// blocks hides the payments and spends in them.
    fn note_tip_age(&mut self, node: &dyn NodeApi) -> Result<(), WalletError> {
        let h = self.synced_height;
        let nid = self.params.network_id;
        let header = match self.headers.back() {
            Some(t) if t.height == h => *t,
            _ if h == 0 => self.params.genesis,
            _ => {
                let t = fetch_headers(node, h, h, nid)?[0];
                if self.block_ids.get(&h).is_some_and(|id| *id != t.id(nid)) {
                    return Err(WalletError::BadNodeData(
                        "the node's header at the wallet's height is not the wallet's block".into(),
                    ));
                }
                t
            }
        };
        self.tip_time = Some((h, header.timestamp));
        let age = unix_now().saturating_sub(header.timestamp);
        let (warn, refuse) = stale_tip_limits(&self.params);
        if age > warn {
            self.warnings.push(format!(
                "the node's tip (block {h}) is {} old by this computer's clock: the node may be \
                 behind or withholding blocks (payments and spends in them are not shown), or \
                 the clock is wrong. Transactions are refused while it is older than {} \
                 (docs/blocks.md §10)",
                format_age(age),
                format_age(refuse)
            ));
        }
        Ok(())
    }

    /// The synced tip's height and its age in seconds by the local clock, as
    /// of the last sync.
    pub fn tip_age(&self) -> Option<(u64, u64)> {
        self.tip_time
            .map(|(h, ts)| (h, unix_now().saturating_sub(ts)))
    }

    /// The chain parameters the wallet checks and builds with.
    pub fn params(&self) -> &blacksilk_consensus::ChainParams {
        &self.params
    }

    /// Lets transactions be built on a tip older than the refusal bound
    /// (`stale_tip_limits`): for a network that really stalled, or tests on
    /// chains with old timestamps. Not persisted.
    pub fn set_allow_stale_tip(&mut self, allow: bool) {
        self.allow_stale_tip = allow;
    }

    /// Refuses to build or send a transaction on a stale tip (RTW3-6): the
    /// node may withhold newer blocks, in which the wallet's outputs may be
    /// spent already (a new ring for them would intersect the old one) and
    /// the anchor would lag the chain.
    pub(super) fn check_fresh_tip(&self) -> Result<(), WalletError> {
        if self.allow_stale_tip {
            return Ok(());
        }
        let (_, refuse) = stale_tip_limits(&self.params);
        match self.tip_age() {
            Some((height, age)) if age > refuse => Err(WalletError::StaleTip {
                height,
                age,
                limit: refuse,
            }),
            Some(_) => Ok(()),
            None => Err(WalletError::Node(
                "the wallet has not synced with the node yet".into(),
            )),
        }
    }

    /// The scan of `sync`, then `check_fresh_tip`: the start of every
    /// transaction. It does not complete the output index: a backfill here
    /// would come just before `/tx`. If an earlier sync has not done it (a
    /// spend straight after a restore, with no `sync` in between), the spend
    /// does, with a warning (`plans_for`).
    pub(super) fn sync_to_send(&mut self, node: &dyn NodeApi) -> Result<u64, WalletError> {
        let (h, _) = self.sync_chain(node)?;
        self.check_fresh_tip()?;
        Ok(h)
    }

    /// Adds RandomX key-block ids from a header check, keeping the last
    /// [`KEPT_KEY_IDS`].
    fn keep_key_ids(&mut self, ids: impl IntoIterator<Item = (u64, Hash)>) {
        self.key_ids.extend(ids);
        while self.key_ids.len() > KEPT_KEY_IDS {
            self.key_ids.pop_first();
        }
    }

    /// Where the header check of the next blocks starts, or `None` when no
    /// check runs (`restore_check`, `verify_headers`) or nothing is to be
    /// scanned. From the wallet's own last headers when an earlier check
    /// covered them from the genesis (`checked_through`) and they hold the
    /// context, with the key-block ids the next headers need; else from the
    /// genesis (W3-39b: every check is anchored there).
    fn header_start(&self, info: &blacksilk_rpc::Info) -> Option<HeaderStart> {
        if !(self.verify_headers || self.restore_check) || self.synced_height >= info.height {
            return None;
        }
        let p = &self.params;
        let synced = self.synced_height;
        if synced == 0 || self.checked_through != Some(synced) {
            return Some(HeaderStart::Genesis);
        }
        let ctx: Vec<BlockHeader> = self.headers.iter().copied().collect();
        let first = ctx.first().map_or(0, |h| h.height);
        let from_genesis = first == 1;
        let usable = ctx.last().map(|h| h.height) == Some(synced)
            && ctx.windows(2).all(|w| w[1].height == w[0].height + 1)
            && (from_genesis || ctx.len() >= HeaderCheck::context_len(p));
        if !usable {
            return Some(HeaderStart::Genesis);
        }
        // The key blocks of the next headers that lie below the context.
        let key = |h: u64| seed_height(h, p.seed_epoch, p.seed_lag);
        let mut seeds = Vec::new();
        let mut k = key(synced + 1);
        while k <= key(info.height) {
            if k < first {
                let id = if k == 0 {
                    p.genesis_id()
                } else {
                    match self.key_ids.get(&k) {
                        Some(id) => *id,
                        None => return Some(HeaderStart::Genesis),
                    }
                };
                seeds.push((k, id));
            }
            k += p.seed_epoch;
        }
        let mut start = ctx;
        if from_genesis {
            start.insert(0, p.genesis);
        }
        Some(HeaderStart::Resume { start, seeds })
    }

    /// Builds the PX tree and the registrations below the first block the
    /// wallet scans (block `base`, the synced height; dossier 39 W1,
    /// W3-39b). From the genesis nothing is fetched. Above it the node's two
    /// lists (fetched whole: they tell the node nothing) are checked against
    /// the blocks they name, each bound to the header chain (`ids`: the
    /// header check's own when it ran from the genesis, else the node's
    /// header feed, which must lead to the wallet's checked header at the
    /// base when it has one):
    /// - the block of the last commitment listed must hold exactly the
    ///   commitments listed at its height. A node that labels commitments of
    ///   later blocks as older ones (withheld blocks behind a stale tip, the
    ///   residual of W3-39) is caught here; a list that ends early gives a
    ///   root no block accepts once it is 100 blocks old (`crate::tree`);
    /// - every block the contract list names is read, and its deploys give
    ///   the registrations; the list must state exactly those. A node can
    ///   leave a deploy out of its list altogether: the wallet then does
    ///   not know that contract and refuses to use it.
    ///
    /// The first scanned block must then extend the base block.
    fn backfill(
        &mut self,
        node: &dyn NodeApi,
        lists: BackfillLists,
        mut ids: BTreeMap<u64, Hash>,
    ) -> Result<(), WalletError> {
        let base = self.synced_height;
        let nid = self.params.network_id;
        if base == 0 {
            self.px.set_base(0, &[], false, Vec::new())?;
            self.block_ids.insert(0, self.params.genesis_id());
            return Ok(());
        }
        let blocks = lists.blocks();
        if blocks.contains(&0) {
            return Err(WalletError::BadNodeData(
                "the node lists records in the genesis block".into(),
            ));
        }
        if !blocks.iter().chain([&base]).all(|h| ids.contains_key(h)) {
            let lo = blocks.first().copied().unwrap_or(base);
            let headers = fetch_headers(node, lo, base, nid)?;
            let top = headers.last().expect("lo <= base").id(nid);
            let checked = self
                .headers
                .back()
                .filter(|h| h.height == base && self.checked_through == Some(base));
            if checked.is_some_and(|h| h.id(nid) != top) {
                return Err(WalletError::BadNodeData(
                    "the node's headers do not end at the wallet's checked header".into(),
                ));
            }
            ids = headers.iter().map(|h| (h.height, h.id(nid))).collect();
        }
        let last = lists.commitments.last().map(|e| e.0);
        let mut contracts = Vec::new();
        for &h in &blocks {
            let block = fetch_block(node, h, &ids[&h], nid)?;
            if last == Some(h) {
                let listed: Vec<Digest> = lists
                    .commitments
                    .iter()
                    .filter(|e| e.0 == h)
                    .map(|e| e.1)
                    .collect();
                let held: Vec<Digest> = block
                    .txs
                    .iter()
                    .filter_map(|t| match t {
                        Transaction::Px(p) => Some(p.commitments),
                        _ => None,
                    })
                    .flatten()
                    .collect();
                if listed != held {
                    return Err(WalletError::BadNodeData(format!(
                        "the node's commitment list does not end like block {h}: it lists \
                         other commitments at that height than the block holds (commitments \
                         of later blocks labelled as older ones, or some left out)"
                    )));
                }
            }
            let derived = deployed(&block.txs, h)?;
            let listed: Vec<&rpc::PxContractEntry> =
                lists.contracts.iter().filter(|c| c.height == h).collect();
            if !listed_as(&listed, &derived) {
                return Err(WalletError::BadNodeData(format!(
                    "the node's contract list does not state the registrations of block {h}'s \
                     deploys"
                )));
            }
            contracts.extend(derived);
        }
        self.px
            .set_base(base, &lists.commitments, true, contracts)?;
        // Imported records older than the scanned blocks (RTW3-15).
        self.px.place_from_list(&lists.commitments)?;
        self.block_ids.insert(base, ids[&base]);
        Ok(())
    }

    /// Checks the header chain at every sync (dossier 39 W5; opt-in for
    /// routine syncs, on by default for the first sync of a restored
    /// wallet). Not persisted.
    pub fn set_verify_headers(&mut self, on: bool) {
        self.verify_headers = on;
    }

    /// Whether the next sync checks the header chain.
    pub fn verifies_headers(&self) -> bool {
        self.verify_headers || self.restore_check
    }

    /// The height up to which the wallet's header chain was checked from
    /// the genesis (`None` if its last block was scanned unchecked).
    pub fn headers_checked_through(&self) -> Option<u64> {
        self.checked_through
    }

    /// Replaces the header check's proof-of-work function (RandomX light
    /// mode by default): for regtest nodes that mine with a stand-in, and
    /// tests. Not persisted.
    pub fn set_header_pow(&mut self, pow: std::sync::Arc<dyn PowFunction>) {
        self.header_pow = Some(pow);
    }

    /// How many headers the check samples per sync (`HEADER_SAMPLES`).
    pub fn set_header_samples(&mut self, samples: u64) {
        self.header_samples = samples;
    }

    /// Applies block `height`: its PX part first, which checks the block's
    /// anchors against the wallet's tree and changes nothing on a refusal,
    /// then the v1 part.
    fn apply_block(
        &mut self,
        block: &Block,
        height: u64,
        first_output: u64,
    ) -> Result<(), WalletError> {
        self.check_first_output(height, first_output)?;
        self.px
            .apply_block(&mut self.px_keys, &self.px_account, &block.txs, height)?;
        self.apply_v1_block(block, height, first_output);
        Ok(())
    }

    /// Checks the node's global index of the first output of block `height`
    /// against what the wallet knows (RT-D1 F1). Once the output index holds
    /// outputs the wallet scanned (heights at or above the restore height),
    /// the next block must continue it exactly: a block that "restarts" the
    /// index would discard the scanned range and hand it to the next
    /// backfill, with node-chosen heights. Restarting stays allowed when the
    /// index is empty or holds only backfilled outputs (the rescan after a
    /// reorganization deeper than the kept window). Block 1 always starts
    /// at 0 (the genesis has no outputs), and no block starts below its
    /// height − 1 (every block from 1 on has at least one output).
    fn check_first_output(&self, height: u64, first_output: u64) -> Result<(), WalletError> {
        let scanned = self
            .index
            .last_height()
            .is_some_and(|h| h >= self.restore_height);
        let bad = if scanned {
            first_output != self.index.end()
        } else {
            first_output < height.saturating_sub(1) || (height == 1 && first_output != 0)
        };
        if bad {
            return Err(WalletError::BadNodeData(format!(
                "block {height}: the node places its first output at {first_output}, \
                 the wallet's output index ends at {}",
                self.index.end()
            )));
        }
        Ok(())
    }

    /// Adds every output of `block` to the output index, in the chain's
    /// global order (as `scan_block` counts).
    fn index_block(&mut self, block: &Block, height: u64, first_output: u64) {
        self.index.push_block(
            height,
            first_output,
            block.txs.iter().flat_map(|tx| {
                let coinbase = tx.is_coinbase();
                tx.output_keys()
                    .into_iter()
                    .map(move |k| (*k.one_time_key.bytes(), *k.commitment.bytes(), coinbase))
            }),
        );
    }

    /// Indexes the synced block again, from the block feed, checked against
    /// the wallet's own id for it: for an empty output index at a synced
    /// height above 0 (a wallet file written before the index existed, with
    /// no block synced since). Its `first_output` is where the backfill ends.
    /// One `/blocks` request for the wallet's own tip, once per such file.
    ///
    /// Its `first_output` is checked against the wallet's own outputs (their
    /// global indices were recorded at earlier scans): those of earlier
    /// blocks must lie below it, those of this block within it, and it must
    /// be at least `h − 1` (one output per block from 1 on).
    pub(super) fn index_synced_block(&mut self, node: &dyn NodeApi) -> Result<(), WalletError> {
        let h = self.synced_height;
        let Some(&ours) = self.block_ids.get(&h) else {
            return Err(WalletError::BadNodeData(format!(
                "no block id kept for the synced block {h}; sync again"
            )));
        };
        let entry = node
            .blocks(h, 1)
            .map_err(WalletError::Node)?
            .blocks
            .into_iter()
            .next()
            .filter(|e| e.height == h)
            .ok_or_else(|| WalletError::BadNodeData(format!("block {h} was not served")))?;
        let block = decode_block(&entry)?;
        if block.id(self.params.network_id) != ours
            || block.compute_tx_root() != block.header.tx_root
        {
            return Err(WalletError::BadNodeData(format!(
                "block {h} is not the wallet's"
            )));
        }
        let first = entry.first_output;
        let count = block
            .txs
            .iter()
            .map(|tx| tx.output_keys().len() as u64)
            .sum::<u64>();
        let consistent = first >= h.saturating_sub(1)
            && (h != 1 || first == 0)
            && self.outputs.iter().all(|o| match o.height.cmp(&h) {
                std::cmp::Ordering::Less => o.global_index < first,
                std::cmp::Ordering::Equal => {
                    o.global_index >= first && o.global_index - first < count
                }
                std::cmp::Ordering::Greater => true,
            });
        if !consistent {
            return Err(WalletError::BadNodeData(format!(
                "block {h}: the node places its first output at {first}, which the wallet's \
                 own outputs contradict"
            )));
        }
        self.index_block(&block, h, first);
        Ok(())
    }

    /// The v1 part of a block: the output index, owned outputs and spends.
    fn apply_v1_block(&mut self, block: &Block, height: u64, first_output: u64) {
        self.index_block(block, height, first_output);
        // Gap-limit scan (review M-2): an output found near the edge of the
        // window moves the window, and the block is scanned again with it, so
        // later outputs of the same block (and later blocks) are found too.
        loop {
            let report = scan_block(
                self.keys.view_keys(),
                &self.table,
                &block.txs,
                height,
                first_output,
            );
            let mut grew = false;
            for o in report.owned {
                if self
                    .outputs
                    .iter()
                    .any(|s| s.global_index == o.global_index)
                {
                    continue;
                }
                let ki = o.key_image(&self.keys);
                let ReceivedOutput {
                    subaddress,
                    amount,
                    mask,
                    output_key_offset,
                } = o.received;
                let key_image = hex::encode(ki.bytes());
                // One credited output per key image (docs/transactions.md
                // §12.5, D8 option B): two outputs with the same one-time
                // key share the key image, and only one of them can ever be
                // spent. The Janus check makes this unreachable on a valid
                // chain except for a hash collision (a copy in another
                // transaction has another input context), so this is defence
                // in depth, e.g. against a dishonest node. Every such output
                // is kept, unchanged, and one is credited: the LARGEST
                // amount, then the lowest global index (Monero's rule; a
                // small early copy never displaces a large genuine output;
                // `elect_credited`). Records are never rewritten in place,
                // so a rewind of the credited one's block credits the one
                // below the fork again (RTW1-4). The key image's spent and
                // reserved state is shared by all of them.
                let sibling = self.outputs.iter().find(|s| s.key_image == key_image);
                let (spent_height, pending, pending_height) = sibling
                    .map_or((None, false, 0), |s| {
                        (s.spent_height, s.pending, s.pending_height)
                    });
                let duplicate = sibling.map(|s| s.global_index);
                if let Some(held) = duplicate {
                    self.warnings.push(format!(
                        "outputs {held} and {} share a key image: only one of them is \
                         credited (docs/transactions.md §12.5)",
                        o.global_index,
                    ));
                }
                self.outputs.push(StoredOutput {
                    global_index: o.global_index,
                    height,
                    coinbase: o.coinbase,
                    account: subaddress.account,
                    index: subaddress.index,
                    amount,
                    one_time_key: hex::encode(o.key.one_time_key.bytes()),
                    commitment: hex::encode(o.key.commitment.bytes()),
                    mask: hex::encode(mask.as_bytes()),
                    offset: hex::encode(output_key_offset.as_bytes()),
                    key_image,
                    spent_height,
                    pending,
                    pending_height,
                    tx: Some(hex::encode(o.tx_hash)),
                    credited: duplicate.is_none(),
                });
                grew |= self.note_used(subaddress.account, subaddress.index);
            }
            if !grew {
                break;
            }
        }
        self.elect_credited();
        // Rejected outputs (Janus probes, bogus amounts) are deliberately ignored:
        // they must not be shown or spent (docs/transactions.md §12.5).
        // Every kind spends v1 outputs through key images: transfers, PX
        // transactions (bridge-in, fees) and deploys.
        let spent: HashSet<String> = block
            .txs
            .iter()
            .flat_map(|t| t.key_images())
            .map(|ki| hex::encode(ki.bytes()))
            .collect();
        for o in &mut self.outputs {
            if spent.contains(&o.key_image) {
                o.spent_height = Some(height);
                o.pending = false;
            }
        }
    }

    /// Elects, for every key image held more than once, the record that is
    /// credited: the largest amount, then the lowest global index (RTW1-4).
    /// The stored ring of such a key image (W-5) loses every member carrying
    /// its one-time key: the credited record may be one of them now, and a
    /// reused ring must never carry the same one-time key at two positions.
    pub(super) fn elect_credited(&mut self) {
        // key image -> (amount, global index) of the best record so far.
        let mut best: HashMap<&str, (u64, u64)> = HashMap::new();
        // key image -> one-time key, for key images held more than once.
        let mut duplicated: HashMap<&str, &str> = HashMap::new();
        for o in &self.outputs {
            let (amount, index) = (o.amount, o.global_index);
            match best.entry(&o.key_image) {
                Entry::Vacant(e) => {
                    e.insert((amount, index));
                }
                Entry::Occupied(mut e) => {
                    duplicated.insert(&o.key_image, &o.one_time_key);
                    let (held_amount, held_index) = *e.get();
                    if amount > held_amount || (amount == held_amount && index < held_index) {
                        e.insert((amount, index));
                    }
                }
            }
        }
        let credited: HashSet<(&str, u64)> =
            best.iter().map(|(k, &(_, index))| (*k, index)).collect();
        let credited: Vec<bool> = self
            .outputs
            .iter()
            .map(|o| credited.contains(&(o.key_image.as_str(), o.global_index)))
            .collect();
        let duplicated: Vec<(String, String)> = duplicated
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        for (o, c) in self.outputs.iter_mut().zip(credited) {
            o.credited = c;
        }
        for (key_image, one_time_key) in duplicated {
            if let Some(ring) = self.rings.get_mut(&key_image) {
                ring.retain(|m| m.one_time_key != one_time_key);
            }
        }
    }

    pub(super) fn spendable_at(o: &StoredOutput, next_height: u64) -> bool {
        let age = if o.coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        };
        o.credited && o.spent_height.is_none() && !o.pending && next_height >= o.height + age
    }

    pub fn balance(&self) -> Balance {
        let next = self.synced_height + 1;
        let mut b = Balance::default();
        for o in self
            .outputs
            .iter()
            .filter(|o| o.credited && o.spent_height.is_none() && !o.pending)
        {
            b.total += o.amount;
            if Self::spendable_at(o, next) {
                b.unlocked += o.amount;
            }
        }
        b
    }

    /// Everything this wallet holds, as of its synced height, for the supply
    /// audit (tools/supply-audit). Read-only: no secret material (masks,
    /// seeds, record openings) is included, only amounts and public ids.
    ///
    /// - v1: every owned output, spent or not, with its confirmation state;
    ///   of outputs sharing a key image, only the credited one.
    /// - PX: every plain record, and every contract record that is on chain
    ///   (`height` known). Contract records created or imported but never
    ///   confirmed are left out: they hold no value on chain.
    pub fn holdings(&self) -> Holdings {
        let outputs = self
            .outputs
            .iter()
            .filter(|o| o.credited)
            .map(|o| HeldOutput {
                global_index: o.global_index,
                height: o.height,
                amount: o.amount,
                coinbase: o.coinbase,
                spent_height: o.spent_height,
                pending: o.pending,
            })
            .collect();
        let mut px_records: Vec<HeldRecord> = self
            .px
            .records
            .iter()
            .map(|r| HeldRecord {
                commitment: r.commitment.clone(),
                height: r.height,
                value: r.value,
                spent_height: r.spent_height,
                pending: r.pending,
                contract: None,
            })
            .collect();
        px_records.extend(self.px.contract_records.iter().filter_map(|r| {
            Some(HeldRecord {
                commitment: r.commitment.clone(),
                height: r.height?,
                value: r.value,
                spent_height: r.spent_height,
                pending: r.pending,
                contract: Some(r.contract.clone()),
            })
        }));
        Holdings {
            height: self.synced_height,
            tip: self.block_ids.get(&self.synced_height).copied(),
            pending_txs: self.pending_txs.len(),
            outputs,
            px_records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::{BlockHeader, Network, HEADER_VERSION};
    use blacksilk_crypto::keys::SubaddressIndex;
    use blacksilk_crypto::Point;
    use blacksilk_tx::builder::{build_coinbase, Payment};
    use blacksilk_tx::types::{Coinbase, CoinbaseOutput, Input, Transaction, Transfer};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn wallet() -> Wallet {
        Wallet::from_seed(Network::Regtest, [7; 32], 1)
    }

    fn block(height: u64, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: HEADER_VERSION,
                height,
                prev_id: [0; 32],
                timestamp: 0,
                difficulty: 1,
                tx_root: [0; 32],
                nonce: 0,
            },
            txs,
        }
    }

    /// An honest coinbase at `height` paying `amount` to the wallet.
    fn pay_wallet(w: &Wallet, height: u64, amount: u64, rng: &mut ChaCha20Rng) -> Coinbase {
        build_coinbase(
            height,
            &[Payment {
                address: w.keys.address(SubaddressIndex::PRIMARY),
                amount,
            }],
            &[9; 32],
            rng,
        )
        .unwrap()
    }

    /// A transaction spending `key_image` (only its key images and outputs
    /// matter to `apply_block`).
    fn spend(key_image: Point) -> Transaction {
        Transaction::from(Transfer {
            inputs: vec![Input {
                key_image,
                ring: [0; blacksilk_tx::params::RING_SIZE],
            }],
            outputs: vec![],
            fee: 0,
            pseudo_outs: vec![],
            range_proof: blacksilk_crypto::bulletproofs_plus::BppProof {
                a: key_image,
                a1: key_image,
                b: key_image,
                r1: blacksilk_crypto::Scalar::ZERO,
                s1: blacksilk_crypto::Scalar::ZERO,
                d1: blacksilk_crypto::Scalar::ZERO,
                l: vec![],
                r: vec![],
            },
            signatures: vec![],
        })
    }

    fn stored_key_image(o: &StoredOutput) -> Point {
        let b: [u8; 32] = hex::decode(&o.key_image).unwrap().try_into().unwrap();
        Point::decode(&b).unwrap()
    }

    /// D8 option B (dossier 50 §5.1 test 3): a copy of the wallet's output,
    /// mined BEFORE the genuine output, with the same one-time key and a
    /// larger amount. The copy's input context differs, so the Janus check
    /// refuses it; the genuine output is credited, once, whatever the order
    /// and the amounts. The copy stays in the output index (it is a chain
    /// output, and may be a decoy: never filtered, F13-7).
    #[test]
    fn a_copy_mined_before_the_genuine_output_is_not_credited() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut w = wallet();
        let genuine = pay_wallet(&w, 2, 1_000, &mut rng);
        let copy = Coinbase {
            height: 1,
            outputs: vec![CoinbaseOutput {
                amount: 1_000_000,
                ..genuine.outputs[0].clone()
            }],
        };
        w.apply_v1_block(&block(1, vec![Transaction::Coinbase(copy)]), 1, 0);
        assert!(w.outputs.is_empty(), "the copy is not credited");
        w.apply_v1_block(&block(2, vec![Transaction::Coinbase(genuine)]), 2, 1);
        assert_eq!(w.outputs.len(), 1);
        assert_eq!(w.outputs[0].global_index, 1);
        assert_eq!(w.outputs[0].amount, 1_000);
        assert_eq!(w.balance().total, 1_000);
        // Both chain outputs are indexed (decoy candidates).
        assert!(w.index.get(0).is_some() && w.index.get(1).is_some());
        assert_eq!(
            w.index.get(0).unwrap().one_time_key,
            w.index.get(1).unwrap().one_time_key
        );
    }

    /// The records credited for their key image.
    fn credited(w: &Wallet) -> Vec<(u64, u64)> {
        w.outputs
            .iter()
            .filter(|o| o.credited)
            .map(|o| (o.global_index, o.amount))
            .collect()
    }

    /// Defence in depth (F13-6, F17-2, RT-10): outputs that pass the scan but
    /// share a key image (here two outputs of one transaction with the same
    /// one-time key and different amounts, which consensus rejects but a
    /// dishonest node can serve) are credited once: the LARGEST amount, then
    /// the lowest global index. Both are kept (RTW1-4). A spend of that key
    /// image spends it.
    #[test]
    fn one_output_is_credited_per_key_image_the_largest_then_the_lowest_index() {
        for (amounts, kept) in [
            ([500u64, 7_000u64], 1u64), // the larger comes second
            ([7_000, 500], 0),          // the larger comes first
            ([900, 900], 0),            // equal: the lowest index
        ] {
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            let mut w = wallet();
            let honest = pay_wallet(&w, 5, 1, &mut rng);
            let bad = Coinbase {
                height: 5,
                outputs: amounts
                    .iter()
                    .map(|&amount| CoinbaseOutput {
                        amount,
                        ..honest.outputs[0].clone()
                    })
                    .collect(),
            };
            w.apply_v1_block(&block(5, vec![Transaction::Coinbase(bad)]), 5, 0);
            assert_eq!(w.outputs.len(), 2, "{amounts:?}: both kept");
            assert_eq!(
                credited(&w),
                vec![(kept, amounts[kept as usize])],
                "{amounts:?}: credited once"
            );
            assert_eq!(w.balance().total, amounts[kept as usize]);
            assert_eq!(w.holdings().outputs.len(), 1, "audited once");
            assert_eq!(w.take_warnings().len(), 1, "a local diagnostic");
            // The key image is spent: nothing is left.
            let ki = stored_key_image(&w.outputs[0]);
            w.apply_v1_block(&block(6, vec![spend(ki)]), 6, 2);
            assert!(w.outputs.iter().all(|o| o.spent_height == Some(6)));
            assert_eq!(w.balance().total, 0);
        }
    }

    /// The same across two scans of the chain (a copy that somehow passes
    /// the scan in a later block, e.g. after a hash collision): a larger
    /// later output is credited instead, a smaller one is not; the spent and
    /// reserved state of the key image is shared by every record.
    #[test]
    fn a_later_duplicate_is_credited_only_if_larger() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        // The same block served twice at two positions (a dishonest node).
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(100))]), 5, 20);
        assert_eq!(credited(&w), vec![(10, 300)]);
        // Reserved by a submitted spend: a larger duplicate stays reserved.
        w.outputs[0].pending = true;
        w.outputs[0].pending_height = 5;
        w.outputs[1].pending = true;
        w.outputs[1].pending_height = 5;
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(800))]), 5, 30);
        assert_eq!(credited(&w), vec![(30, 800)]);
        assert!(w.outputs.iter().all(|o| o.pending && o.pending_height == 5));
        assert_eq!(w.balance().total, 0, "reserved");
        for o in &mut w.outputs {
            o.pending = false;
        }
        assert_eq!(w.balance().total, 800);
        // Only the credited record can be chosen to spend.
        let spendable: Vec<u64> = w
            .outputs
            .iter()
            .filter(|o| Wallet::spendable_at(o, 1_000))
            .map(|o| o.global_index)
            .collect();
        assert_eq!(spendable, vec![30]);
        // Every record and the credit survive a save and load; files written
        // before the flag (one record per key image) load as credited.
        let loaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(loaded.outputs.len(), 3);
        assert_eq!(credited(&loaded), vec![(30, 800)]);
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        let outputs = json["outputs"].as_array_mut().unwrap();
        outputs.retain(|o| o["global_index"] == 30);
        outputs[0].as_object_mut().unwrap().remove("credited");
        let old = Wallet::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(credited(&old), vec![(30, 800)]);
        let _ = w.take_warnings();
        // Spent, then a larger duplicate: still spent.
        let ki = stored_key_image(&w.outputs[0]);
        w.apply_v1_block(&block(6, vec![spend(ki)]), 6, 40);
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(900))]), 5, 50);
        assert_eq!(credited(&w), vec![(50, 900)]);
        assert!(w.outputs.iter().all(|o| o.spent_height == Some(6)));
        assert_eq!(w.balance().total, 0);
    }

    /// RTW1-4 (red team RT-W1): a larger duplicate in a later block is
    /// credited instead of the earlier output, and a rewind below the later
    /// block brings the earlier output back. Before the fix the duplicate
    /// replaced the held record in place (height and global index), so the
    /// rewind dropped the only record and the genuine output, still on chain
    /// below the fork, stayed invisible until a restore from the seed.
    #[test]
    fn a_rewind_below_a_replacing_duplicate_keeps_the_displaced_output() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        w.synced_height = 5;
        w.apply_v1_block(&block(7, vec![Transaction::Coinbase(with(800))]), 7, 30);
        w.synced_height = 7;
        assert_eq!(w.balance().total, 800, "the larger duplicate is credited");
        w.rewind(6);
        assert_eq!(
            w.balance().total,
            300,
            "output 10 at height 5 is still on chain"
        );
        assert_eq!(credited(&w), vec![(10, 300)]);
    }

    /// RTW1-4: once a key image is held twice, its stored ring (W-5, reused
    /// by the next spend of that key image) loses every member carrying the
    /// shared one-time key, so the real input's key never appears at a
    /// second position of the reused ring. Other members are kept.
    #[test]
    fn a_reused_ring_never_carries_the_credited_key_twice() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        w.apply_v1_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        let key = w.outputs[0].one_time_key.clone();
        let other = hex::encode([0x11; 32]);
        let member = |index: u64, k: &str| super::super::RingMember {
            index,
            one_time_key: k.to_owned(),
            commitment: other.clone(),
        };
        // A ring submitted for output 10 whose decoys include output 30,
        // which later turns out to carry the same one-time key.
        w.rings.insert(
            w.outputs[0].key_image.clone(),
            vec![member(3, &other), member(30, &key)],
        );
        w.apply_v1_block(&block(7, vec![Transaction::Coinbase(with(800))]), 7, 30);
        assert_eq!(credited(&w), vec![(30, 800)]);
        let ring = &w.rings[&w.outputs[0].key_image];
        assert_eq!(ring.iter().map(|m| m.index).collect::<Vec<_>>(), vec![3]);
    }
}

// The header feed's reading under the stable fuzz driver (W4-STATEFUL).
#[cfg(test)]
#[path = "fuzz_headers.rs"]
mod fuzz_headers;
