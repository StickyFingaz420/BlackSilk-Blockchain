//! Address manager (docs/p2p.md §9; dossier 32 W1), after Bitcoin Core's
//! `addrman` with test-before-evict.
//!
//! Two tables of fixed slots: *new* (256 buckets of 64: heard of) and
//! *tried* (64 buckets of 64: this node connected to it). Where an address
//! goes is a keyed hash, with a random `key` local to the node and saved
//! with the table, so an attacker cannot predict it:
//!
//! - *new* bucket: `h1 = H(key, 0, group(addr), group(src)) mod 16`, then
//!   `H(key, 2, group(src), h1) mod 256`. One source group reaches at most
//!   [`NEW_BUCKETS_PER_SOURCE_GROUP`] buckets, whatever addresses it
//!   announces (before v2 it reached all 256, R8-3);
//! - *tried* bucket: `h1 = H(key, 1, addr) mod 2`, then
//!   `H(key, 3, group(addr), h1) mod 64`: one group reaches at most
//!   [`TRIED_BUCKETS_PER_GROUP`];
//! - the slot in the bucket: `H(key, 4 + table, bucket, addr) mod 64`.
//!
//! An address has one slot. A new address whose slot is taken is dropped
//! unless the occupant is terrible ([`AddrMan::add`]): flooding cannot push
//! out entries that still work. An address that connected moves to *tried*;
//! if its slot there is taken, the occupant is tested first (a feeler) and
//! replaced only if it no longer answers (test-before-evict,
//! [`AddrMan::resolve_collisions`]). *tried* holds at most one address per IP
//! (F32-9). Selection ([`AddrMan::select`]) draws a table, then a non-empty
//! bucket uniformly, so entries crowded into few buckets (one source's) are
//! drawn no more often than one bucket's worth.
//!
//! Times are this node's clock (Unix seconds), passed in: nothing a peer
//! claims is used here. Everything random comes from the caller's RNG, so a
//! table under a fixed key and RNG seed behaves deterministically.

use crate::addr::{peer_key, NetAddr};
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_tx::codec::Writer;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

pub const NEW_BUCKETS: usize = 256;
pub const TRIED_BUCKETS: usize = 64;
pub const BUCKET_SIZE: usize = 64;
/// The *new* buckets one source group can reach (Bitcoin Core: 64 of 1024).
pub const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 16;
/// The *tried* buckets one address group can reach (Bitcoin Core: 8 of 256).
pub const TRIED_BUCKETS_PER_GROUP: u64 = 2;
/// An address not heard of (or connected to) for this long is terrible.
pub const HORIZON_SECS: u64 = 30 * DAY;
/// Failed attempts after which a never-connected address is terrible.
pub const RETRIES: u32 = 3;
/// Failed attempts after which an address without a success in
/// [`MIN_FAIL_SECS`] is terrible.
pub const MAX_FAILURES: u32 = 10;
pub const MIN_FAIL_SECS: u64 = 7 * DAY;
/// *tried* collisions waiting for a test, at most.
pub const MAX_COLLISIONS: usize = 10;
/// A *tried* occupant that connected this recently is kept.
pub const REPLACEMENT_SECS: u64 = 4 * 3600;
/// A collision not tested within this long evicts the occupant.
pub const TEST_WINDOW_SECS: u64 = 40 * 60;
/// Probability that [`AddrMan::select`] draws from *tried* when both tables
/// have entries (Bitcoin Core: 0.5; Monero draws 70 % of its connections
/// from its white list). Set from the eclipse simulator
/// (`p2p/tests/eclipse_sim.rs`): with a *tried* table, 0.7 roughly halves
/// the attacker's outbound share again compared with 0.5, since *tried*
/// holds only addresses this node connected to. A *tried* draw with nothing
/// eligible falls back to *new*, so a small *tried* table costs nothing.
/// Re-derived with feelers modelled (RTW3-10: answering attacker addresses
/// reach *tried*, one per IP): 0.7 is never worse than 0.5 in any scenario;
/// 0.8 and 0.9 lower the share further where the attacker holds few *tried*
/// entries but raise P(all 8) where it holds most of them, so it stays 0.7.
pub const TRIED_BIAS: f64 = 0.7;
/// The share of the table a `GetAddr` answer may reveal, in percent
/// (Bitcoin Core's `MAX_PCT_ADDR_TO_SEND`).
pub const GETADDR_MAX_PCT: usize = 23;

const DAY: u64 = 24 * 3600;
/// Random bucket draws in [`AddrMan::select`] before it falls back to a scan.
const SELECT_DRAWS: usize = 256;
/// Version of the saved format; another version starts a fresh table.
const FORMAT_VERSION: u32 = 2;

/// The two tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Table {
    New,
    Tried,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    addr: NetAddr,
    /// The bucketing group of the peer we heard it from.
    source_group: Vec<u8>,
    /// When this node last heard of the address or connected to it.
    time: u64,
    /// Our last connection attempt (0: never).
    last_try: u64,
    /// Our last successful connection (0: never).
    last_success: u64,
    /// Attempts since the last success.
    attempts: u32,
    tried: bool,
}

type Bucket = [Option<u64>; BUCKET_SIZE];

/// The saved form: the key and the entries; slots are recomputed at load.
#[derive(Serialize, Deserialize)]
struct Saved {
    version: u32,
    key: [u8; 32],
    entries: Vec<Entry>,
}

pub struct AddrMan {
    key: [u8; 32],
    entries: HashMap<u64, Entry>,
    index: HashMap<NetAddr, u64>,
    new: Vec<Bucket>,
    tried: Vec<Bucket>,
    new_len: Vec<u8>,
    tried_len: Vec<u8>,
    /// The *tried* entry of each IP (at most one, F32-9).
    tried_ips: HashMap<IpAddr, u64>,
    /// *new* entries that connected but whose *tried* slot is taken, waiting
    /// for the occupant to be tested.
    collisions: Vec<u64>,
    next_id: u64,
    /// Local networks (`allow_private`): unroutable addresses are grouped by
    /// the whole address, so a LAN's nodes spread over buckets instead of
    /// all landing in one (they share one /16).
    private_groups: bool,
}

impl AddrMan {
    /// An empty table with a random key.
    pub fn new(rng: &mut impl RngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self::with_key(key)
    }

    /// An empty table with `key` (tests, the simulator).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            entries: HashMap::new(),
            index: HashMap::new(),
            new: vec![[None; BUCKET_SIZE]; NEW_BUCKETS],
            tried: vec![[None; BUCKET_SIZE]; TRIED_BUCKETS],
            new_len: vec![0; NEW_BUCKETS],
            tried_len: vec![0; TRIED_BUCKETS],
            tried_ips: HashMap::new(),
            collisions: Vec::new(),
            next_id: 1,
            private_groups: false,
        }
    }

    /// Groups unroutable addresses by the whole address (local test and lab
    /// networks, `allow_private`). The table is re-placed under the new rule.
    pub fn set_private_groups(&mut self, on: bool) {
        if self.private_groups != on {
            self.private_groups = on;
            let entries = self.take_entries();
            self.place_all(entries);
        }
    }

    // ------------------------------------------------------------ hashing

    fn addr_key(a: &NetAddr) -> Vec<u8> {
        let mut w = Writer::new();
        a.encode(&mut w);
        w.into_bytes()
    }

    /// The group an address is bucketed by.
    pub fn bucket_group(&self, a: &NetAddr) -> Vec<u8> {
        if self.private_groups && !a.is_routable() {
            let mut g = vec![0xff];
            g.extend(Self::addr_key(a));
            g
        } else {
            a.group()
        }
    }

    /// `H32("p2p/addrman", key ‖ disc ‖ (len ‖ part)…)`, first 8 bytes LE.
    fn hash(&self, disc: u8, parts: &[&[u8]]) -> u64 {
        let mut buf = vec![disc];
        for p in parts {
            buf.push(p.len() as u8);
            buf.extend_from_slice(p);
        }
        let h = h32(tags::P2P_ADDRMAN, &[&self.key, &buf]);
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
    }

    fn new_bucket(&self, addr: &NetAddr, source_group: &[u8]) -> usize {
        let h1 =
            self.hash(0, &[&self.bucket_group(addr), source_group]) % NEW_BUCKETS_PER_SOURCE_GROUP;
        (self.hash(2, &[source_group, &h1.to_le_bytes()]) % NEW_BUCKETS as u64) as usize
    }

    fn tried_bucket(&self, addr: &NetAddr) -> usize {
        let h1 = self.hash(1, &[&Self::addr_key(addr)]) % TRIED_BUCKETS_PER_GROUP;
        (self.hash(3, &[&self.bucket_group(addr), &h1.to_le_bytes()]) % TRIED_BUCKETS as u64)
            as usize
    }

    fn slot(&self, table: Table, bucket: usize, addr: &NetAddr) -> usize {
        let disc = match table {
            Table::New => 4,
            Table::Tried => 5,
        };
        let b = (bucket as u64).to_le_bytes();
        (self.hash(disc, &[&b, &Self::addr_key(addr)]) % BUCKET_SIZE as u64) as usize
    }

    /// Where `e` belongs: its table, bucket and slot.
    fn home(&self, e: &Entry) -> (Table, usize, usize) {
        if e.tried {
            let b = self.tried_bucket(&e.addr);
            (Table::Tried, b, self.slot(Table::Tried, b, &e.addr))
        } else {
            let b = self.new_bucket(&e.addr, &e.source_group);
            (Table::New, b, self.slot(Table::New, b, &e.addr))
        }
    }

    /// A keyed hash of a network group, unpredictable to peers (inbound
    /// eviction protects peers by it, as Bitcoin Core's keyed netgroup).
    pub fn keyed_group(&self, group: &[u8]) -> u64 {
        self.hash(6, &[group])
    }

    // ------------------------------------------------------------ slots

    fn cell(&mut self, table: Table, b: usize, s: usize) -> &mut Option<u64> {
        match table {
            Table::New => &mut self.new[b][s],
            Table::Tried => &mut self.tried[b][s],
        }
    }

    fn put(&mut self, table: Table, b: usize, s: usize, id: u64) {
        debug_assert!(self.cell(table, b, s).is_none());
        *self.cell(table, b, s) = Some(id);
        match table {
            Table::New => self.new_len[b] += 1,
            Table::Tried => self.tried_len[b] += 1,
        }
    }

    fn clear(&mut self, table: Table, b: usize, s: usize) -> Option<u64> {
        let id = self.cell(table, b, s).take();
        if id.is_some() {
            match table {
                Table::New => self.new_len[b] -= 1,
                Table::Tried => self.tried_len[b] -= 1,
            }
        }
        id
    }

    /// Removes entry `id` from its slot, the index and every set.
    fn delete(&mut self, id: u64) {
        let Some(e) = self.entries.get(&id) else {
            return;
        };
        let (t, b, s) = self.home(e);
        if *self.cell(t, b, s) == Some(id) {
            self.clear(t, b, s);
        }
        let e = self.entries.remove(&id).expect("present");
        self.index.remove(&e.addr);
        if let Some(ip) = e.addr.ip() {
            if self.tried_ips.get(&ip) == Some(&id) {
                self.tried_ips.remove(&ip);
            }
        }
        self.collisions.retain(|&c| c != id);
    }

    fn insert_entry(&mut self, e: Entry) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.index.insert(e.addr.clone(), id);
        self.entries.insert(id, e);
        id
    }

    // ------------------------------------------------------------ queries

    pub fn contains(&self, addr: &NetAddr) -> bool {
        self.index.contains_key(addr)
    }

    /// Entries in *new* and in *tried*.
    pub fn len(&self) -> (usize, usize) {
        (
            self.new_len.iter().map(|&n| n as usize).sum(),
            self.tried_len.iter().map(|&n| n as usize).sum(),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The table, bucket and slot of `addr`, if present (diagnostics, the
    /// simulator).
    pub fn position(&self, addr: &NetAddr) -> Option<(Table, usize, usize)> {
        let e = self.entries.get(self.index.get(addr)?)?;
        Some(self.home(e))
    }

    /// Every address with its table, in slot order.
    pub fn addresses(&self) -> Vec<(NetAddr, Table)> {
        let mut out = Vec::new();
        for (table, buckets) in [(Table::New, &self.new), (Table::Tried, &self.tried)] {
            for id in buckets.iter().flatten().flatten() {
                out.push((self.entries[id].addr.clone(), table));
            }
        }
        out
    }

    /// Bitcoin Core's `IsTerrible`: an entry not worth keeping when its slot
    /// is wanted, nor worth sending to peers.
    fn is_terrible(e: &Entry, now: u64) -> bool {
        if e.last_try != 0 && now.saturating_sub(e.last_try) < 60 {
            return false; // tried in the last minute: give it a chance
        }
        e.time > now + 600
            || now.saturating_sub(e.time) > HORIZON_SECS
            || (e.last_success == 0 && e.attempts >= RETRIES)
            || (now.saturating_sub(e.last_success) > MIN_FAIL_SECS && e.attempts >= MAX_FAILURES)
    }

    /// Bitcoin Core's `GetChance`: the relative chance of being selected.
    fn chance(e: &Entry, now: u64) -> f64 {
        let mut c = 1.0;
        if now.saturating_sub(e.last_try) < 600 {
            c *= 0.01;
        }
        c * 0.66f64.powi(e.attempts.min(8) as i32)
    }

    // ------------------------------------------------------------ updates

    /// Records an address heard from `source`. Returns whether it was
    /// added: a known address only has its time refreshed, and a new address
    /// whose slot holds a non-terrible entry is dropped.
    pub fn add(&mut self, addr: NetAddr, source: &NetAddr, now: u64) -> bool {
        if let Some(&id) = self.index.get(&addr) {
            let e = self.entries.get_mut(&id).expect("indexed");
            e.time = e.time.max(now);
            return false;
        }
        let source_group = self.bucket_group(source);
        let b = self.new_bucket(&addr, &source_group);
        let s = self.slot(Table::New, b, &addr);
        if let Some(occupant) = self.new[b][s] {
            if !Self::is_terrible(&self.entries[&occupant], now) {
                return false;
            }
            self.delete(occupant);
        }
        let id = self.insert_entry(Entry {
            addr,
            source_group,
            time: now,
            last_try: 0,
            last_success: 0,
            attempts: 0,
            tried: false,
        });
        self.put(Table::New, b, s, id);
        true
    }

    /// Records a connection attempt to `addr` (made now).
    pub fn attempt(&mut self, addr: &NetAddr, now: u64) {
        if let Some(e) = self.index.get(addr).and_then(|id| self.entries.get_mut(id)) {
            e.last_try = now;
            e.attempts = e.attempts.saturating_add(1);
        }
    }

    /// Records that an outbound connection to `addr` is still up (the
    /// maintenance calls it every round): its time is refreshed, and a
    /// *tried* entry's last success, so test-before-evict never replaces an
    /// address this node is connected to.
    pub fn connected(&mut self, addr: &NetAddr, now: u64) {
        if let Some(e) = self.index.get(addr).and_then(|id| self.entries.get_mut(id)) {
            e.time = e.time.max(now);
            if e.tried {
                e.last_success = e.last_success.max(now);
            }
        }
    }

    /// Records a successful outbound connection to `addr` (an address of
    /// the table; others are ignored). It moves to *tried*, unless its slot
    /// there holds another address: then it waits in *new* as a collision
    /// until the occupant is tested ([`Self::select_tried_collision`],
    /// [`Self::resolve_collisions`]). Returns whether it is in *tried*.
    pub fn good(&mut self, addr: &NetAddr, now: u64) -> bool {
        let Some(&id) = self.index.get(addr) else {
            return false;
        };
        let e = self.entries.get_mut(&id).expect("indexed");
        e.last_success = now;
        e.last_try = now;
        e.attempts = 0;
        e.time = e.time.max(now);
        if e.tried {
            return true;
        }
        let b = self.tried_bucket(addr);
        let s = self.slot(Table::Tried, b, addr);
        let same_ip = addr.ip().and_then(|ip| self.tried_ips.get(&ip).copied());
        if let Some(occupant) = self.tried[b][s] {
            if Some(occupant) != same_ip {
                if self.collisions.len() < MAX_COLLISIONS && !self.collisions.contains(&id) {
                    self.collisions.push(id);
                }
                return false;
            }
        }
        self.make_tried(id);
        true
    }

    /// Moves *new* entry `id` to its *tried* slot. The IP's previous *tried*
    /// entry and the slot's occupant go back to *new* (dropping whatever
    /// holds their *new* slot).
    fn make_tried(&mut self, id: u64) {
        let e = self.entries[&id].clone();
        debug_assert!(!e.tried);
        let (t, b, s) = self.home(&e);
        if self.new[b][s] == Some(id) {
            self.clear(t, b, s);
        }
        self.collisions.retain(|&c| c != id);
        if let Some(old) = e.addr.ip().and_then(|ip| self.tried_ips.get(&ip).copied()) {
            self.demote(old);
        }
        let tb = self.tried_bucket(&e.addr);
        let ts = self.slot(Table::Tried, tb, &e.addr);
        if let Some(occupant) = self.tried[tb][ts] {
            self.demote(occupant);
        }
        self.entries.get_mut(&id).expect("present").tried = true;
        self.put(Table::Tried, tb, ts, id);
        if let Some(ip) = e.addr.ip() {
            self.tried_ips.insert(ip, id);
        }
    }

    /// Moves *tried* entry `id` back to its *new* slot, dropping the entry
    /// that holds it.
    fn demote(&mut self, id: u64) {
        let e = self.entries[&id].clone();
        let (t, b, s) = self.home(&e);
        if *self.cell(t, b, s) == Some(id) {
            self.clear(t, b, s);
        }
        if let Some(ip) = e.addr.ip() {
            if self.tried_ips.get(&ip) == Some(&id) {
                self.tried_ips.remove(&ip);
            }
        }
        self.entries.get_mut(&id).expect("present").tried = false;
        let (_, nb, ns) = self.home(&self.entries[&id]);
        if let Some(occupant) = self.new[nb][ns] {
            self.delete(occupant);
        }
        self.put(Table::New, nb, ns, id);
    }

    /// A *tried* occupant whose slot a newly connected address wants: the
    /// address a feeler should test (test-before-evict).
    pub fn select_tried_collision(&mut self, rng: &mut impl RngCore) -> Option<NetAddr> {
        if self.collisions.is_empty() {
            return None;
        }
        let i = (rng.next_u64() % self.collisions.len() as u64) as usize;
        let id = self.collisions[i];
        let Some(e) = self.entries.get(&id) else {
            self.collisions.swap_remove(i);
            return None;
        };
        let b = self.tried_bucket(&e.addr);
        let s = self.slot(Table::Tried, b, &e.addr);
        match self.tried[b][s] {
            Some(occupant) => Some(self.entries[&occupant].addr.clone()),
            None => None,
        }
    }

    /// Settles waiting collisions (Bitcoin Core's `ResolveCollisions`):
    /// - the occupant connected in the last [`REPLACEMENT_SECS`]: it stays,
    ///   and the newcomer stays in *new*;
    /// - it was tried in that time without success, at least a minute ago:
    ///   the newcomer replaces it;
    /// - it was not tested within [`TEST_WINDOW_SECS`] of the collision: it
    ///   stays, and the collision is dropped (the newcomer stays in *new*;
    ///   RTW3-9: an occupant that could not be tested is not evicted);
    /// - the slot became free, or the newcomer left *new*: settled.
    pub fn resolve_collisions(&mut self, now: u64) {
        for id in self.collisions.clone() {
            let Some(e) = self.entries.get(&id) else {
                self.collisions.retain(|&c| c != id);
                continue;
            };
            if e.tried {
                self.collisions.retain(|&c| c != id);
                continue;
            }
            let b = self.tried_bucket(&e.addr);
            let s = self.slot(Table::Tried, b, &e.addr);
            let promote = match self.tried[b][s] {
                None => Some(true),
                Some(occupant) => {
                    let old = &self.entries[&occupant];
                    if now.saturating_sub(old.last_success) < REPLACEMENT_SECS {
                        Some(false)
                    } else if now.saturating_sub(old.last_try) < REPLACEMENT_SECS {
                        (now.saturating_sub(old.last_try) > 60).then_some(true)
                    } else if now.saturating_sub(e.last_success) > TEST_WINDOW_SECS {
                        // Never tested within the window: the collision is
                        // dropped and the occupant kept (RTW3-9). Bitcoin
                        // Core evicts it here; a node that could not test it
                        // (no feeler ran, no route) has no evidence it is
                        // gone, and an attacker's answering address must not
                        // displace a working entry by default.
                        Some(false)
                    } else {
                        None
                    }
                }
            };
            match promote {
                Some(true) => self.make_tried(id),
                Some(false) => self.collisions.retain(|&c| c != id),
                None => {}
            }
        }
    }

    /// A candidate for an outbound connection, skipping addresses for which
    /// `skip` is true; from *new* only if `new_only` (feelers). A table is
    /// drawn (*tried* with probability [`TRIED_BIAS`]), then a non-empty
    /// bucket uniformly, then the first entry from a random slot; it is
    /// taken with probability `chance × 1.2^draws` (entries tried recently or
    /// failing often are drawn less). After [`SELECT_DRAWS`] draws, or if
    /// the table has nothing left to offer, a non-empty bucket with an
    /// eligible entry is chosen uniformly, then such an entry; then the
    /// other table.
    pub fn select(
        &self,
        rng: &mut impl RngCore,
        now: u64,
        new_only: bool,
        skip: impl Fn(&NetAddr) -> bool,
    ) -> Option<NetAddr> {
        self.select_biased(rng, now, new_only, TRIED_BIAS, skip)
    }

    /// [`Self::select`] drawing *tried* first with probability `tried_bias`
    /// (the simulator compares biases).
    pub fn select_biased(
        &self,
        rng: &mut impl RngCore,
        now: u64,
        new_only: bool,
        tried_bias: f64,
        skip: impl Fn(&NetAddr) -> bool,
    ) -> Option<NetAddr> {
        let (n_new, n_tried) = self.len();
        let first = if new_only || n_tried == 0 {
            Table::New
        } else if n_new == 0 || unit(rng) < tried_bias {
            Table::Tried
        } else {
            Table::New
        };
        let order: &[Table] = match (new_only, first) {
            (true, _) => &[Table::New],
            (false, Table::New) => &[Table::New, Table::Tried],
            (false, Table::Tried) => &[Table::Tried, Table::New],
        };
        for &table in order {
            if let Some(a) = self.select_in(table, rng, now, &skip) {
                return Some(a);
            }
        }
        None
    }

    fn select_in(
        &self,
        table: Table,
        rng: &mut impl RngCore,
        now: u64,
        skip: &impl Fn(&NetAddr) -> bool,
    ) -> Option<NetAddr> {
        let (buckets, lens) = match table {
            Table::New => (&self.new, &self.new_len),
            Table::Tried => (&self.tried, &self.tried_len),
        };
        let full: Vec<usize> = (0..buckets.len()).filter(|&b| lens[b] > 0).collect();
        if full.is_empty() {
            return None;
        }
        let mut factor = 1.0;
        for _ in 0..SELECT_DRAWS {
            let b = full[(rng.next_u64() % full.len() as u64) as usize];
            let start = (rng.next_u64() % BUCKET_SIZE as u64) as usize;
            let id = (0..BUCKET_SIZE)
                .find_map(|i| buckets[b][(start + i) % BUCKET_SIZE])
                .expect("non-empty bucket");
            let e = &self.entries[&id];
            if skip(&e.addr) {
                continue;
            }
            if unit(rng) < Self::chance(e, now) * factor {
                return Some(e.addr.clone());
            }
            factor *= 1.2;
        }
        // Few eligible entries: choose among them directly, still one
        // bucket's worth per bucket.
        let eligible: Vec<Vec<u64>> = full
            .iter()
            .map(|&b| {
                buckets[b]
                    .iter()
                    .flatten()
                    .copied()
                    .filter(|id| !skip(&self.entries[id].addr))
                    .collect::<Vec<u64>>()
            })
            .filter(|v| !v.is_empty())
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let v = &eligible[(rng.next_u64() % eligible.len() as u64) as usize];
        let id = v[(rng.next_u64() % v.len() as u64) as usize];
        Some(self.entries[&id].addr.clone())
    }

    /// Addresses for a `GetAddr` answer: at most `max`, and at most
    /// [`GETADDR_MAX_PCT`] percent of the table (rounded up), random, none
    /// terrible.
    pub fn get_addr(&self, max: usize, rng: &mut impl RngCore, now: u64) -> Vec<NetAddr> {
        let total = self.entries.len();
        let n = max.min((total * GETADDR_MAX_PCT).div_ceil(100));
        let mut all: Vec<&Entry> = [&self.new, &self.tried]
            .into_iter()
            .flat_map(|t| t.iter().flatten().flatten())
            .map(|id| &self.entries[id])
            .filter(|e| !Self::is_terrible(e, now))
            .collect();
        let n = n.min(all.len());
        for i in 0..n {
            let j = i + (rng.next_u64() % (all.len() - i) as u64) as usize;
            all.swap(i, j);
        }
        all.into_iter().take(n).map(|e| e.addr.clone()).collect()
    }

    // ------------------------------------------------------------ persistence

    fn take_entries(&mut self) -> Vec<Entry> {
        let mut out = Vec::with_capacity(self.entries.len());
        for table in [&self.tried, &self.new] {
            for id in table.iter().flatten().flatten() {
                out.push(self.entries[id].clone());
            }
        }
        let (key, private) = (self.key, self.private_groups);
        *self = Self::with_key(key);
        self.private_groups = private;
        out
    }

    /// Places saved entries into an empty table: *tried* ones first, each
    /// into its slot (to *new* if the slot or its IP is taken), then *new*
    /// ones (dropped if the slot is taken). Every invariant holds by
    /// construction, whatever the file said.
    fn place_all(&mut self, entries: Vec<Entry>) {
        let (tried, new): (Vec<Entry>, Vec<Entry>) = entries.into_iter().partition(|e| e.tried);
        for mut e in tried.into_iter().chain(new) {
            if self.index.contains_key(&e.addr) || e.addr.clone().canonical() != e.addr {
                continue;
            }
            if e.tried {
                let b = self.tried_bucket(&e.addr);
                let s = self.slot(Table::Tried, b, &e.addr);
                let ip_taken = e
                    .addr
                    .ip()
                    .is_some_and(|ip| self.tried_ips.contains_key(&ip));
                if self.tried[b][s].is_none() && !ip_taken {
                    let ip = e.addr.ip();
                    let id = self.insert_entry(e);
                    self.put(Table::Tried, b, s, id);
                    if let Some(ip) = ip {
                        self.tried_ips.insert(ip, id);
                    }
                    continue;
                }
                e.tried = false;
            }
            let b = self.new_bucket(&e.addr, &e.source_group);
            let s = self.slot(Table::New, b, &e.addr);
            if self.new[b][s].is_none() {
                let id = self.insert_entry(e);
                self.put(Table::New, b, s, id);
            }
        }
    }

    /// Written to a temporary file and renamed: a crash mid-write leaves the
    /// previous table.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for table in [&self.tried, &self.new] {
            for id in table.iter().flatten().flatten() {
                entries.push(self.entries[id].clone());
            }
        }
        let saved = Saved {
            version: FORMAT_VERSION,
            key: self.key,
            entries,
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(&saved).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(tmp, path)
    }

    /// Loads a saved table with its key; `None` if missing, unreadable or of
    /// another format version (a fresh table is used).
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let saved: Saved = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                log::warn!(
                    "{}: cannot parse ({e}); starting a fresh address table",
                    path.display()
                );
                return None;
            }
        };
        if saved.version != FORMAT_VERSION {
            log::warn!(
                "{}: format version {} (expected {FORMAT_VERSION}); starting a fresh address table",
                path.display(),
                saved.version
            );
            return None;
        }
        let mut m = Self::with_key(saved.key);
        m.place_all(saved.entries);
        Some(m)
    }

    /// Checks every internal invariant (tests).
    #[doc(hidden)]
    pub fn check(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for (table, buckets, lens) in [
            (Table::New, &self.new, &self.new_len),
            (Table::Tried, &self.tried, &self.tried_len),
        ] {
            for (b, bucket) in buckets.iter().enumerate() {
                let n = bucket.iter().flatten().count();
                if n != lens[b] as usize {
                    return Err(format!("{table:?} bucket {b}: count {} != {n}", lens[b]));
                }
                for (s, id) in bucket.iter().enumerate() {
                    let Some(id) = id else { continue };
                    if !seen.insert(*id) {
                        return Err(format!("entry {id} in two slots"));
                    }
                    let e = self.entries.get(id).ok_or("slot of a missing entry")?;
                    if self.home(e) != (table, b, s) {
                        return Err(format!("{} not in its home slot", e.addr));
                    }
                    if self.index.get(&e.addr) != Some(id) {
                        return Err(format!("{} not indexed", e.addr));
                    }
                }
            }
        }
        if seen.len() != self.entries.len() || self.index.len() != self.entries.len() {
            return Err("entries outside the tables".into());
        }
        let mut ips = std::collections::HashSet::new();
        for e in self.entries.values().filter(|e| e.tried) {
            if let Some(ip) = e.addr.ip() {
                if !ips.insert(ip) {
                    return Err(format!("two tried entries of {ip}"));
                }
            }
        }
        if ips.len() != self.tried_ips.len() {
            return Err("tried IP index out of date".into());
        }
        if self.collisions.len() > MAX_COLLISIONS {
            return Err("too many collisions".into());
        }
        Ok(())
    }
}

/// A uniform number in [0, 1).
fn unit(rng: &mut impl RngCore) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// Banned peers with expiry (docs/p2p.md §10), keyed by [`peer_key`]: an IPv4
/// address, or an IPv6 /64.
#[derive(Default, Serialize, Deserialize)]
pub struct BanList {
    until: HashMap<IpAddr, u64>,
}

impl BanList {
    pub fn ban(&mut self, ip: IpAddr, until: u64) {
        self.until.insert(peer_key(ip), until);
    }

    pub fn is_banned(&self, ip: &IpAddr, now: u64) -> bool {
        self.until.get(&peer_key(*ip)).is_some_and(|&t| t > now)
    }

    pub fn prune(&mut self, now: u64) {
        self.until.retain(|_, &mut t| t > now);
    }

    pub fn len(&self) -> usize {
        self.until.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }

    /// Written to a temporary file and renamed, as `peers.json`: a crash
    /// mid-write leaves the previous list, not an unreadable one (which would
    /// silently lift every ban).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(tmp, path)
    }

    /// A missing file is an empty list. An existing one that cannot be read
    /// or parsed is logged: starting without its bans is a visible event,
    /// not a silent one. Keys are brought to [`peer_key`] form.
    pub fn load(path: &Path) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                log::warn!(
                    "{}: cannot read ({e}); starting without bans",
                    path.display()
                );
                return Self::default();
            }
        };
        let saved: Self = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log::warn!(
                "{}: cannot parse ({e}); starting without bans",
                path.display()
            );
            Self::default()
        });
        let mut list = Self::default();
        for (ip, t) in saved.until {
            let k = peer_key(ip);
            let t = t.max(list.until.get(&k).copied().unwrap_or(0));
            list.until.insert(k, t);
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const NOW: u64 = 1_900_000_000;

    fn a(s: &str) -> NetAddr {
        NetAddr::parse(s).unwrap()
    }

    fn table(seed: u64) -> (AddrMan, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (AddrMan::new(&mut rng), rng)
    }

    /// A routable address in /16 number `g` (distinct for g < 50 000).
    fn in_group(g: u32, host: u32) -> NetAddr {
        a(&format!(
            "{}.{}.{}.{}:8333",
            20 + g / 256,
            g % 256,
            (host / 256) % 256,
            1 + host % 250
        ))
    }

    fn new_buckets_used(m: &AddrMan) -> usize {
        m.new_len.iter().filter(|&&n| n > 0).count()
    }

    #[test]
    fn add_select_and_promote() {
        let (mut m, mut rng) = table(1);
        let src = a("9.9.9.9:1");
        assert!(m.add(a("1.2.3.4:5"), &src, NOW));
        assert!(!m.add(a("1.2.3.4:5"), &src, NOW), "duplicate");
        assert_eq!(m.len(), (1, 0));
        assert!(m.good(&a("1.2.3.4:5"), NOW));
        assert_eq!(m.len(), (0, 1));
        assert_eq!(
            m.select(&mut rng, NOW, false, |_| false),
            Some(a("1.2.3.4:5"))
        );
        assert_eq!(m.select(&mut rng, NOW, true, |_| false), None, "new only");
        assert_eq!(m.select(&mut rng, NOW, false, |_| true), None);
        // An address never heard of does not enter by connecting.
        assert!(!m.good(&a("5.5.5.5:5"), NOW));
        assert!(!m.contains(&a("5.5.5.5:5")));
        m.check().unwrap();
    }

    /// R8-3 (W1): addresses of many groups announced by ONE source group
    /// reach at most 16 of the 256 *new* buckets. Before v2 they reached all
    /// 256 (`one source reached 256 of 256 new buckets` on bff3a62).
    #[test]
    fn one_source_group_reaches_at_most_16_new_buckets() {
        let (mut m, _) = table(7);
        let src = a("66.66.1.1:1");
        for i in 0..4000u32 {
            m.add(in_group(i % 2000, i), &src, NOW);
        }
        let used = new_buckets_used(&m);
        assert!(used <= 16, "one source reached {used} of 256 new buckets");
        assert!(m.len().0 <= 16 * BUCKET_SIZE);
        // Another source of the same /16 shares them; other groups do not.
        m.add(in_group(9999, 1), &a("66.66.200.1:1"), NOW);
        assert!(new_buckets_used(&m) <= 16);
        for g in 0..64 {
            m.add(in_group(5000 + g, 1), &in_group(9000 + g, 1), NOW);
        }
        assert!(new_buckets_used(&m) > 40, "{}", new_buckets_used(&m));
        m.check().unwrap();
    }

    /// Flooding cannot evict entries that work: a full bucket keeps its
    /// occupants unless they are terrible.
    #[test]
    fn flooding_never_evicts_a_working_entry() {
        let (mut m, _) = table(8);
        let src = a("7.7.1.1:1");
        let honest: Vec<NetAddr> = (0..300).map(|i| in_group(i, 1)).collect();
        let kept: Vec<NetAddr> = honest
            .iter()
            .filter(|h| m.add((*h).clone(), &src, NOW))
            .cloned()
            .collect();
        for i in 0..20_000u32 {
            m.add(in_group(1000 + i % 30_000, i), &src, NOW + 10);
        }
        for h in &kept {
            assert!(m.contains(h), "{h} was evicted");
        }
        // A terrible occupant (3 failures, never connected) gives way.
        let (mut m, _) = table(9);
        let victim = in_group(1, 1);
        assert!(m.add(victim.clone(), &src, NOW));
        let (_, b, s) = m.position(&victim).unwrap();
        for t in 0..3 {
            m.attempt(&victim, NOW + t * 100);
        }
        let later = NOW + 1000;
        let mut i = 0u32;
        while m.contains(&victim) {
            let x = in_group(2 + i % 40_000, i);
            if m.new_bucket(&x, &m.bucket_group(&src)) == b && m.slot(Table::New, b, &x) == s {
                assert!(m.add(x, &src, later));
            }
            i += 1;
            assert!(i < 5_000_000, "no colliding address found");
        }
        m.check().unwrap();
    }

    /// Test-before-evict: a newly connected address whose *tried* slot is
    /// taken waits; the occupant stays if it answers, and is replaced if it
    /// does not.
    #[test]
    fn test_before_evict_keeps_a_live_tried_entry() {
        let (mut m, mut rng) = table(10);
        let src = a("9.9.9.9:9");
        // Two addresses of one group, same tried slot.
        let old = in_group(3, 1);
        assert!(m.add(old.clone(), &src, NOW));
        assert!(m.good(&old, NOW));
        let (_, tb, ts) = m.position(&old).unwrap();
        let mut i = 2u32;
        let newer = loop {
            let x = in_group(3, i);
            if m.tried_bucket(&x) == tb
                && m.slot(Table::Tried, tb, &x) == ts
                && m.add(x.clone(), &src, NOW)
            {
                break x;
            }
            i += 1;
        };
        let t1 = NOW + 5 * 3600;
        assert!(!m.good(&newer, t1), "collision: waits in new");
        assert_eq!(m.select_tried_collision(&mut rng), Some(old.clone()));
        // The feeler reaches the occupant: it stays.
        assert!(m.good(&old, t1 + 10));
        m.resolve_collisions(t1 + 20);
        assert_eq!(m.position(&old).unwrap().0, Table::Tried);
        assert_eq!(m.position(&newer).unwrap().0, Table::New);
        assert_eq!(m.select_tried_collision(&mut rng), None, "settled");
        // Later the occupant stops answering: tried, failed, a minute passed.
        let t2 = t1 + 6 * 3600;
        assert!(!m.good(&newer, t2));
        m.attempt(&old, t2 + 5);
        m.resolve_collisions(t2 + 30);
        assert_eq!(
            m.position(&old).unwrap().0,
            Table::Tried,
            "less than a minute"
        );
        m.resolve_collisions(t2 + 70);
        assert_eq!(m.position(&newer).unwrap().0, Table::Tried);
        assert_eq!(m.position(&old).unwrap().0, Table::New, "demoted, not lost");
        // An occupant this node stays connected to is never replaced.
        let (mut m, _) = table(10);
        m.add(old.clone(), &src, NOW);
        m.good(&old, NOW);
        m.add(newer.clone(), &src, NOW);
        let t = NOW + 5 * 3600;
        assert!(!m.good(&newer, t));
        m.connected(&old, t + TEST_WINDOW_SECS);
        m.resolve_collisions(t + TEST_WINDOW_SECS + 1);
        assert_eq!(m.position(&old).unwrap().0, Table::Tried);
        // Never tested (RTW3-9): after the test window the collision is
        // dropped and the occupant kept; it was replaced before.
        let (mut m, mut rng) = table(10);
        m.add(old.clone(), &src, NOW);
        m.good(&old, NOW);
        m.add(newer.clone(), &src, NOW);
        let t = NOW + 5 * 3600;
        assert!(!m.good(&newer, t));
        m.resolve_collisions(t + TEST_WINDOW_SECS);
        assert_eq!(m.position(&newer).unwrap().0, Table::New);
        assert_eq!(m.select_tried_collision(&mut rng), Some(old.clone()));
        m.resolve_collisions(t + TEST_WINDOW_SECS + 1);
        assert_eq!(m.position(&old).unwrap().0, Table::Tried, "kept");
        assert_eq!(m.position(&newer).unwrap().0, Table::New);
        assert_eq!(m.select_tried_collision(&mut rng), None, "dropped");
        m.check().unwrap();
    }

    /// F32-9: *tried* holds one entry per IP; another port of the IP that
    /// connects replaces it.
    #[test]
    fn tried_holds_one_entry_per_ip() {
        let (mut m, _) = table(11);
        let src = a("9.9.9.9:9");
        let mut last = None;
        for port in 1000..1100u16 {
            let x = a(&format!("44.44.4.4:{port}"));
            if (m.add(x.clone(), &src, NOW) || m.contains(&x)) && m.good(&x, NOW) {
                last = Some(x);
            }
        }
        assert_eq!(m.len().1, 1, "{:?}", m.len());
        assert_eq!(m.position(&last.unwrap()).unwrap().0, Table::Tried);
        m.check().unwrap();
    }

    /// Selection draws a non-empty bucket uniformly: 1000 entries crowded
    /// into one source's 16 buckets are drawn about as often as 16 entries
    /// in 16 other buckets.
    #[test]
    fn selection_is_uniform_over_buckets_not_entries() {
        let (mut m, mut rng) = table(12);
        let flood_src = a("66.66.1.1:1");
        for i in 0..1000u32 {
            m.add(in_group(i, i), &flood_src, NOW);
        }
        let mut honest = Vec::new();
        let mut g = 20_000u32;
        while honest.len() < 16 {
            let h = in_group(g, 1);
            let src = in_group(g + 10_000, 1);
            let b = m.new_bucket(&h, &m.bucket_group(&src));
            let crowded = m.new_len[b] > 0;
            if !crowded && m.add(h.clone(), &src, NOW) {
                honest.push(h);
            }
            g += 1;
        }
        let draws = 4000;
        let hits = (0..draws)
            .filter(|_| {
                let x = m.select(&mut rng, NOW, true, |_| false).unwrap();
                honest.contains(&x)
            })
            .count();
        let share = hits as f64 / draws as f64;
        // 16 honest buckets of at most 32 non-empty: about one half.
        assert!(share > 0.35, "honest share {share}");
    }

    #[test]
    fn different_keys_give_different_buckets() {
        let (m1, _) = table(3);
        let (m2, _) = table(4);
        let g = a("7.7.7.7:7").group();
        let same = (0..32)
            .filter(|i| {
                let x = a(&format!("7.{i}.7.7:7"));
                m1.new_bucket(&x, &g) == m2.new_bucket(&x, &g)
            })
            .count();
        assert!(same < 4, "buckets must not be predictable across nodes");
    }

    /// Placement is a function of the key: the same key and the same inputs
    /// give the same table, slot for slot.
    #[test]
    fn deterministic_under_a_fixed_key() {
        let build = || {
            let mut m = AddrMan::with_key([5; 32]);
            for i in 0..500u32 {
                m.add(in_group(i % 97, i), &in_group(i % 7, 1), NOW);
            }
            for i in 0..50u32 {
                m.good(&in_group(i % 97, i), NOW);
            }
            m.addresses()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn terrible_entries() {
        let e = |time, last_try, last_success, attempts| Entry {
            addr: a("1.1.1.1:1"),
            source_group: vec![],
            time,
            last_try,
            last_success,
            attempts,
            tried: false,
        };
        assert!(!AddrMan::is_terrible(&e(NOW, 0, 0, 0), NOW));
        assert!(AddrMan::is_terrible(&e(NOW + 601, 0, 0, 0), NOW), "future");
        assert!(
            AddrMan::is_terrible(&e(NOW - HORIZON_SECS - 1, 0, 0, 0), NOW),
            "old"
        );
        assert!(
            AddrMan::is_terrible(&e(NOW, NOW - 100, 0, RETRIES), NOW),
            "never worked"
        );
        assert!(
            !AddrMan::is_terrible(&e(NOW, NOW - 10, 0, RETRIES), NOW),
            "just tried"
        );
        assert!(!AddrMan::is_terrible(&e(NOW, NOW - 100, NOW - 100, 5), NOW));
        assert!(AddrMan::is_terrible(
            &e(NOW, NOW - 100, NOW - MIN_FAIL_SECS - 1, MAX_FAILURES),
            NOW
        ));
    }

    /// Random operation sequences keep every invariant: the index matches the
    /// slots, counts match, no duplicates, one *tried* entry per IP, at most
    /// 16 *new* buckets per source group, and a save and load round-trip.
    #[test]
    fn random_operations_keep_the_invariants() {
        let dir = tempfile::tempdir().unwrap();
        for seed in 0..6u64 {
            let (mut m, mut rng) = table(100 + seed);
            let mut now = NOW;
            let mut sources: HashMap<Vec<u8>, std::collections::HashSet<usize>> = HashMap::new();
            for step in 0..6000u32 {
                now += rng.next_u64() % 120;
                let x = in_group(rng.next_u32() % 400, rng.next_u32() % 40);
                match rng.next_u32() % 10 {
                    0..=5 => {
                        let src = in_group(rng.next_u32() % 20, 1);
                        if m.add(x.clone(), &src, now) {
                            let (_, b, _) = m.position(&x).unwrap();
                            sources.entry(src.group()).or_default().insert(b);
                        }
                    }
                    6 => m.attempt(&x, now),
                    7 => {
                        m.good(&x, now);
                    }
                    8 => m.resolve_collisions(now),
                    _ => {
                        let _ = m.select_tried_collision(&mut rng);
                        let _ = m.select(&mut rng, now, false, |_| false);
                    }
                }
                if step % 500 == 0 {
                    m.check().unwrap();
                }
            }
            m.check().unwrap();
            for (g, buckets) in &sources {
                assert!(buckets.len() <= 16, "{g:?}: {}", buckets.len());
            }
            let p = dir.path().join(format!("peers-{seed}.json"));
            m.save(&p).unwrap();
            let l = AddrMan::load(&p).unwrap();
            l.check().unwrap();
            assert_eq!(l.addresses(), m.addresses());
            assert_eq!(l.key, m.key);
        }
    }

    #[test]
    fn persistence() {
        let (mut m, _) = table(5);
        m.add(a("1.1.1.1:1"), &a("2.2.2.2:2"), NOW);
        m.add(a("3.3.3.3:3"), &a("2.2.2.2:2"), NOW);
        m.good(&a("3.3.3.3:3"), NOW);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("peers.json");
        m.save(&p).unwrap();
        let l = AddrMan::load(&p).unwrap();
        assert_eq!(l.len(), (1, 1));
        assert_eq!(l.key, m.key, "the key is kept");
        assert!(AddrMan::load(&dir.path().join("missing.json")).is_none());
        std::fs::write(&p, b"{garbage").unwrap();
        assert!(AddrMan::load(&p).is_none());
        // The v1 format (before addrman v2) starts a fresh table.
        std::fs::write(&p, br#"{"secret":[0],"new":[],"tried":[]}"#).unwrap();
        assert!(AddrMan::load(&p).is_none());
        let other = Saved {
            version: FORMAT_VERSION + 1,
            key: [0; 32],
            entries: vec![],
        };
        std::fs::write(&p, serde_json::to_vec(&other).unwrap()).unwrap();
        assert!(AddrMan::load(&p).is_none());
    }

    /// A tampered file cannot break an invariant: duplicates, two *tried*
    /// entries of one IP and non-canonical addresses are dropped at load.
    #[test]
    fn a_tampered_file_is_placed_safely() {
        let e = |s: &str, tried| Entry {
            addr: NetAddr::Ip(s.parse().unwrap()),
            source_group: vec![4, 9, 9],
            time: NOW,
            last_try: 0,
            last_success: NOW,
            attempts: 0,
            tried,
        };
        let saved = Saved {
            version: FORMAT_VERSION,
            key: [1; 32],
            entries: vec![
                e("8.8.8.8:1", true),
                e("8.8.8.8:2", true),
                e("8.8.8.8:1", false),
                e("[::ffff:9.9.9.9]:1", false),
            ],
        };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("peers.json");
        std::fs::write(&p, serde_json::to_vec(&saved).unwrap()).unwrap();
        let m = AddrMan::load(&p).unwrap();
        m.check().unwrap();
        assert_eq!(m.len().1, 1);
        assert!(!m.contains(&NetAddr::Ip("[::ffff:9.9.9.9]:1".parse().unwrap())));
    }

    #[test]
    fn get_addr_is_bounded_and_skips_terrible_entries() {
        let (mut m, mut rng) = table(6);
        for i in 0..400u32 {
            m.add(in_group(i, 1), &in_group(1000 + i % 50, 1), NOW);
        }
        let total = m.len().0;
        let s = m.get_addr(1000, &mut rng, NOW);
        assert_eq!(s.len(), (total * GETADDR_MAX_PCT).div_ceil(100));
        let set: std::collections::HashSet<_> = s.iter().collect();
        assert_eq!(set.len(), s.len());
        assert_eq!(m.get_addr(10, &mut rng, NOW).len(), 10);
        // One entry: still answered (rounded up).
        let (mut one, _) = table(6);
        one.add(in_group(1, 1), &in_group(2, 1), NOW);
        assert_eq!(one.get_addr(1000, &mut rng, NOW).len(), 1);
        assert!(one
            .get_addr(1000, &mut rng, NOW + HORIZON_SECS + 1)
            .is_empty());
    }

    /// Local networks: with private groups, a LAN's addresses spread over
    /// buckets instead of sharing the one /16's.
    #[test]
    fn private_groups_spread_local_addresses() {
        let (mut m, _) = table(13);
        m.set_private_groups(true);
        let src = a("192.168.1.1:9000");
        let mut added = 0;
        for i in 0..40u32 {
            added += m.add(a(&format!("192.168.1.{}:{}", 2 + i, 9000)), &src, NOW) as usize;
        }
        assert!(added >= 38, "{added}");
        m.set_private_groups(false);
        m.check().unwrap();
        m.set_private_groups(true);
        m.check().unwrap();
    }

    #[test]
    fn bans_expire_and_cover_a_slash64() {
        let mut b = BanList::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        b.ban(ip, 100);
        assert!(b.is_banned(&ip, 50));
        assert!(!b.is_banned(&ip, 100));
        let v6: IpAddr = "2a00:1:2:3::1".parse().unwrap();
        b.ban(v6, 100);
        assert!(b.is_banned(&"2a00:1:2:3:ffff::9".parse().unwrap(), 50));
        assert!(!b.is_banned(&"2a00:1:2:4::1".parse().unwrap(), 50));
        b.prune(200);
        assert!(b.is_empty());
    }
}
