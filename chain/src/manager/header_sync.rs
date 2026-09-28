//! Header sync serving: locators, headers after a locator, missing bodies, PoW
//! jobs and header prechecks and acceptance.

use super::pow_cache::{CachedPow, PowJob};
use super::ChainManager;
use blacksilk_consensus::{seed_height, BlockHeader, Hash, HeaderError};
use std::collections::HashSet;
use std::sync::Arc;

impl ChainManager {
    /// Block locator over the best header chain: the tip, 10 predecessors one by
    /// one, then exponentially sparser back to genesis (at most 64 ids).
    pub fn locator(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut h = self.headers.height();
        let mut step = 1u64;
        loop {
            out.push(self.headers.main_id_at(h).expect("height on best chain"));
            if h == 0 || out.len() >= 63 {
                break;
            }
            if out.len() >= 10 {
                step *= 2;
            }
            h = h.saturating_sub(step);
        }
        if *out.last().expect("non-empty") != self.params.genesis_id() {
            out.push(self.params.genesis_id());
        }
        out
    }

    /// Headers of the best chain following the first locator id found on it, up to
    /// `max`, ending early at `stop`.
    pub fn headers_after(&self, locator: &[Hash], stop: &Hash, max: usize) -> Vec<BlockHeader> {
        let start = locator
            .iter()
            .find(|id| self.headers.is_on_main(id))
            .and_then(|id| self.headers.header(id))
            .map_or(1, |h| h.height + 1);
        let mut out = Vec::new();
        let mut h = start;
        while out.len() < max {
            let Some(id) = self.headers.main_id_at(h) else {
                break;
            };
            out.push(*self.headers.header(&id).expect("main header"));
            if id == *stop {
                break;
            }
            h += 1;
        }
        out
    }

    /// Blocks whose body is missing on the way to every valid header tip with
    /// more work than the connected tip, lowest height first (for download).
    /// The header-best chain is scanned forward from its fork with the
    /// connected chain; any other heavier tip (a competing branch, for example
    /// while the header-best one's bodies are withheld) is walked back to its
    /// last body-complete ancestor. Equal-work tips are not listed: they could
    /// not replace the connected tip (ties keep it).
    pub fn missing_bodies(&self, max: usize) -> Vec<(u64, Hash)> {
        let tip_work = self.work(&self.tip_id());
        let mut out = Vec::new();
        if self.headers.best_work() > tip_work {
            let mut h = self.fork_height() as u64 + 1;
            while out.len() < max {
                let Some(id) = self.headers.main_id_at(h) else {
                    break;
                };
                if !self.bodies.contains_key(&id) {
                    out.push((h, id));
                }
                h += 1;
            }
        }
        let main_tip = self.headers.tip_id();
        let mut seen: HashSet<Hash> = out.iter().map(|&(_, id)| id).collect();
        for &(_, leaf) in self.leaves.range((tip_work + 1, [0u8; 32])..) {
            if leaf == main_tip {
                continue;
            }
            let mut cur = leaf;
            while !self.complete.contains_key(&cur) {
                let header = self.headers.header(&cur).expect("valid header");
                if !self.bodies.contains_key(&cur) && seen.insert(cur) {
                    out.push((header.height, cur));
                }
                cur = header.prev_id;
            }
        }
        out.sort_by_key(|&(h, _)| h);
        out.truncate(max);
        out
    }

    /// Work to precompute the PoW of a batch of headers (docs/p2p.md §6): the seed
    /// and bytes of each header, taking seeds from the batch itself where needed.
    /// `None` if the batch does not extend a known header or is not a chain. Run
    /// the result with [`CachedPow::compute_parallel`] *without* holding a lock on
    /// the manager, then accept the headers cheaply.
    pub fn pow_jobs(&self, headers: &[BlockHeader]) -> Option<(Arc<CachedPow>, Vec<PowJob>)> {
        let first = headers.first()?;
        let parent = self.headers.header(&first.prev_id)?;
        // Seeds below the batch are looked up on the parent's branch, which is
        // only defined for heights up to the parent's (a height gap would walk
        // past genesis and panic).
        if first.height != parent.height + 1 {
            return None;
        }
        let nid = self.params.network_id;
        let ids: Vec<Hash> = headers.iter().map(|h| h.id(nid)).collect();
        for i in 1..headers.len() {
            if headers[i].prev_id != ids[i - 1] || headers[i].height != headers[i - 1].height + 1 {
                return None;
            }
        }
        let base = first.height;
        let jobs = headers
            .iter()
            .map(|h| {
                let sh = seed_height(h.height, self.params.seed_epoch, self.params.seed_lag);
                let seed = if sh >= base {
                    ids[(sh - base) as usize]
                } else {
                    self.headers.seed_id_for(first.prev_id, h.height)
                };
                (seed, h.to_bytes())
            })
            .collect();
        Some((self.pow.clone(), jobs))
    }

    /// Checks a linked batch of headers with every rule except proof of work,
    /// without storing anything (`HeaderChain::precheck_batch`). Run before
    /// any RandomX work on a peer's batch.
    pub fn precheck_headers(
        &self,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<(), (usize, HeaderError)> {
        self.headers.precheck_batch(headers, now)
    }

    /// Accepts a batch of headers in order. Known headers are skipped. Returns the
    /// number of new headers, or the index and error of the first rejected one.
    /// Headers before a rejected one stay accepted.
    pub fn accept_headers(
        &mut self,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<usize, (usize, HeaderError)> {
        let mut new = 0;
        let mut result = Ok(());
        for (i, h) in headers.iter().enumerate() {
            let id = h.id(self.params.network_id);
            if self.headers.header(&id).is_some() {
                if self.headers.is_valid(&id) == Some(false) {
                    result = Err((i, HeaderError::InvalidParent));
                    break;
                }
                continue;
            }
            if let Err(e) = self.headers.accept(*h, now) {
                result = Err((i, e));
                break;
            }
            self.header_added(id, h.prev_id);
            new += 1;
        }
        // Headers never change the connected chain: its target depends only on
        // bodies (module docs). New headers only add bodies to download.
        self.publish_summary();
        result.map(|()| new)
    }
}
