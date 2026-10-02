//! The originated set (docs/p2p.md §8.1; dossier 33 W2, F33-1): the
//! transactions this node originated (RPC `/tx`, `Network::submit_tx`), each
//! with the height it was relayed for and the height this node pooled it for
//! as every node does (at the fluff, or after a reorganization returned it),
//! persisted across restarts.
//!
//! An honest relay never stems, and never announces as new, a transaction the
//! network has held for a while; only its origin does that when its wallet
//! resubmits a transaction the origin forgot (a restart empties the pool; the
//! pool's own expiry comes first at the origin, which admitted it first). A
//! spy that still pools it then learns the origin with near certainty. So a
//! transaction in this set is never originated again while other nodes may
//! still pool it:
//! - before `relayed + MEMPOOL_EXPIRY_BLOCKS`, while honest pools hold it, a
//!   resubmission is **held**: pooled here, never stemmed or announced
//!   ([`Verdict::Held`]);
//! - until `relayed + NETWORK_EXPIRY_BLOCKS` (the recently-expired guard of
//!   every node that expired it, `RECENTLY_EXPIRED_BLOCKS`), it is refused as
//!   `Expired` ([`Verdict::Expired`]), the persisted form of the mempool's
//!   in-memory guard;
//! - after that the entry is dropped and the transaction may be originated
//!   again, as a new one ([`Verdict::Fresh`]).
//!
//! The relay height decides these windows only, never the pool
//! re-announcement schedule (docs/p2p.md §7; TM2-P1). Every node counts that
//! schedule from the height its pool entry was admitted for: at or after the
//! fluff, or the readmission after a reorganization. A block found while the
//! transaction is in the stem puts the fluff a block past the relay height,
//! and a reorganization moves every node's anchor but not the relay height.
//! The origin counts from its pool entry's height too, except for a **held**
//! copy (pooled by [`Verdict::Held`], typically after a restart), which was
//! pooled late: its anchor is the recorded pool height
//! ([`Originated::anchor`]), and without one it is not re-announced at all
//! (a relay that lost the transaction does not have it either).
//!
//! Heights are next-block heights (the height a transaction is admitted for),
//! as in the mempool. The file (`originated.json` in the data directory) is
//! written to a temporary file, synced and renamed, so a crash leaves the old
//! set or the new one, never a torn file. It holds at most
//! [`ORIGINATED_CAP`] entries; beyond that the oldest are dropped (a node
//! originating more than that within about three days loses the protection
//! for its oldest transactions, and logs it).

use blacksilk_chain::mempool::{MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS};
use blacksilk_consensus::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Blocks after its relay height during which other nodes may still hold a
/// transaction or refuse it as recently expired: the pool expiry plus the
/// recently-expired guard. Wallets must not re-originate a transaction the
/// node lacks before this (dossier 38 W4). Derived from the mempool's
/// constants, never copied.
pub const NETWORK_EXPIRY_BLOCKS: u64 = MEMPOOL_EXPIRY_BLOCKS + RECENTLY_EXPIRED_BLOCKS;

/// Most entries kept (oldest dropped first).
pub const ORIGINATED_CAP: usize = 10_000;

/// File format version of `originated.json` (2 added the pool height;
/// a version 1 file is read without it).
const FORMAT: u32 = 2;

/// What a resubmission of a transaction may do ([`Originated::verdict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not in the set (never originated here, or its window ended):
    /// originate it.
    Fresh,
    /// Originated here, and other nodes most likely still pool it: pool it
    /// here without stemming or announcing it.
    Held,
    /// Originated here, and other nodes expired it recently: refuse it
    /// (`Expired`), as the mempool's guard does.
    Expired,
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    /// `(transaction id (hex), relay height, pool height)`.
    entries: Vec<(String, u64, Option<u64>)>,
}

/// Format 1: `(transaction id (hex), relay height)`.
#[derive(Deserialize)]
struct FileV1 {
    entries: Vec<(String, u64)>,
}

#[derive(Deserialize)]
struct FormatVersion {
    version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    /// The height it was relayed for (the windows of [`Verdict`]).
    relayed: u64,
    /// The height this node last pooled it for as every node does (at the
    /// fluff, or readmitted after a reorganization): the re-announcement
    /// anchor of a later held copy. `None` until then.
    pooled: Option<u64>,
}

/// The originated set.
#[derive(Default)]
pub struct Originated {
    entries: HashMap<Hash, Entry>,
    /// Pool entries that are held copies ([`Verdict::Held`]), with the
    /// height each was pooled for. In memory only, as the pool is.
    held: HashMap<Hash, u64>,
    /// Changed since it was last written.
    dirty: bool,
}

impl Originated {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The height `id` was relayed for, if this node originated it.
    pub fn relayed(&self, id: &Hash) -> Option<u64> {
        self.entries.get(id).map(|e| e.relayed)
    }

    /// The height this node last pooled `id` for as every node does, if it
    /// originated it and pooled it so.
    pub fn pooled(&self, id: &Hash) -> Option<u64> {
        self.entries.get(id).and_then(|e| e.pooled)
    }

    /// What a resubmission of `id` for inclusion at `next` may do.
    pub fn verdict(&self, id: &Hash, next: u64) -> Verdict {
        match self.relayed(id) {
            None => Verdict::Fresh,
            Some(r) if next >= r.saturating_add(NETWORK_EXPIRY_BLOCKS) => Verdict::Fresh,
            Some(r) if next >= r.saturating_add(MEMPOOL_EXPIRY_BLOCKS) => Verdict::Expired,
            Some(_) => Verdict::Held,
        }
    }

    /// The pool re-announcement anchor of a transaction pooled here for
    /// `admitted` (docs/p2p.md §7): `admitted`, as on every node, unless
    /// the pool entry is a held copy of a transaction originated here; then
    /// the recorded pool height, and `None` (never re-announced) without
    /// one. Never the relay height.
    pub fn anchor(&self, id: &Hash, admitted: u64) -> Option<u64> {
        if self.held.get(id) == Some(&admitted) {
            self.pooled(id)
        } else {
            Some(admitted)
        }
    }

    /// Notes that `id` is pooled here for `admitted` as every node pools it
    /// (from a peer, at its own fluff, or readmitted after a
    /// reorganization), if this node originated it: the anchor a later held
    /// copy uses. The held copy itself (pooled for its held height) changes
    /// nothing. Returns whether the set changed (to be written).
    pub fn note_pooled(&mut self, id: &Hash, admitted: u64) -> bool {
        if self.held.get(id) == Some(&admitted) {
            return false;
        }
        let Some(e) = self.entries.get_mut(id) else {
            return false;
        };
        self.held.remove(id);
        if e.pooled == Some(admitted) {
            return false;
        }
        e.pooled = Some(admitted);
        self.dirty = true;
        true
    }

    /// Notes that a held copy of `id` ([`Verdict::Held`]) was pooled for
    /// `admitted`.
    pub fn note_held(&mut self, id: Hash, admitted: u64) {
        if self.entries.contains_key(&id) {
            self.held.insert(id, admitted);
        }
    }

    /// The held copies, with the heights they were pooled for.
    pub fn held(&self) -> Vec<(Hash, u64)> {
        self.held.iter().map(|(id, a)| (*id, *a)).collect()
    }

    /// Whether this node's pool entry for `id` is a held copy.
    pub fn is_held(&self, id: &Hash) -> bool {
        self.held.contains_key(id)
    }

    /// Drops the held-copy marks whose pool entry is gone or was replaced
    /// (`now`: each held id with its current pool height, if pooled). A held
    /// copy that is mined and returned by a reorganization is readmitted
    /// at the reorganization's height, as on every node, and anchored there.
    pub fn refresh_held(&mut self, now: &[(Hash, Option<u64>)]) {
        for (id, at) in now {
            if self.held.get(id).is_some_and(|a| Some(*a) != *at) {
                self.held.remove(id);
            }
        }
    }

    /// A peer announced `id` while this node holds a held copy of it with
    /// no recorded pool height (a restart came before the fluff): the
    /// anchor becomes `next`, the height a relay that lost the transaction
    /// pools it for on that announcement. Returns whether the set changed.
    pub fn held_announced(&mut self, id: &Hash, next: u64) -> bool {
        if !self.held.contains_key(id) {
            return false;
        }
        match self.entries.get_mut(id) {
            Some(e) if e.pooled.is_none() => {
                e.pooled = Some(next);
                self.dirty = true;
                true
            }
            _ => false,
        }
    }

    /// Records that `id` is originated here for inclusion at `next` (a
    /// window ended earlier starts again).
    pub fn record(&mut self, id: Hash, next: u64) {
        self.entries.insert(
            id,
            Entry {
                relayed: next,
                pooled: None,
            },
        );
        self.held.remove(&id);
        self.dirty = true;
        if self.entries.len() > ORIGINATED_CAP {
            self.prune(next);
        }
        while self.entries.len() > ORIGINATED_CAP {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(id, e)| (e.relayed, **id))
                .map(|(id, _)| *id)
                .expect("non-empty");
            self.entries.remove(&oldest);
            self.held.remove(&oldest);
            log::warn!(
                "originated set full ({ORIGINATED_CAP}): the oldest entry is dropped, and \
                 its transaction may be originated again before its window ends"
            );
        }
    }

    /// Forgets `id` (it was not originated after all).
    pub fn forget(&mut self, id: &Hash) {
        self.held.remove(id);
        if self.entries.remove(id).is_some() {
            self.dirty = true;
        }
    }

    /// Drops the entries whose window ended by `next`. Returns how many.
    pub fn prune(&mut self, next: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| next < e.relayed.saturating_add(NETWORK_EXPIRY_BLOCKS));
        let entries = &self.entries;
        self.held.retain(|id, _| entries.contains_key(id));
        let n = before - self.entries.len();
        self.dirty |= n > 0;
        n
    }

    /// Whether the set changed since [`Self::encode`] was last called.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Marks the set as changed (a write failed: write it again later).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// The file contents, clearing the dirty flag.
    pub fn encode(&mut self) -> Vec<u8> {
        self.dirty = false;
        let mut entries: Vec<(String, u64, Option<u64>)> = self
            .entries
            .iter()
            .map(|(id, e)| (hex::encode(id), e.relayed, e.pooled))
            .collect();
        entries.sort();
        serde_json::to_vec(&File {
            version: FORMAT,
            entries,
        })
        .expect("serializable")
    }

    /// Parses a saved set (format 2, or 1 without pool heights). Entries
    /// beyond [`ORIGINATED_CAP`] (oldest first) and malformed ids are
    /// dropped.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let v: FormatVersion = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let raw: Vec<(String, u64, Option<u64>)> = match v.version {
            FORMAT => {
                let f: File = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                f.entries
            }
            1 => {
                let f: FileV1 = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                f.entries.into_iter().map(|(id, r)| (id, r, None)).collect()
            }
            n => return Err(format!("unknown format version {n}")),
        };
        let mut entries: Vec<(Hash, Entry)> = raw
            .into_iter()
            .filter_map(|(id, relayed, pooled)| {
                let bytes = hex::decode(id).ok()?;
                Some((bytes.try_into().ok()?, Entry { relayed, pooled }))
            })
            .collect();
        entries.sort_by_key(|(id, e)| (std::cmp::Reverse(e.relayed), *id));
        entries.truncate(ORIGINATED_CAP);
        Ok(Self {
            entries: entries.into_iter().collect(),
            held: HashMap::new(),
            dirty: false,
        })
    }

    /// Loads the set saved at `path`. A missing file is an empty set. A file
    /// that cannot be read or parsed is logged as an error and an empty set
    /// is used: the node may then originate again a transaction it
    /// originated before, which is a visible event, not a silent one.
    pub fn load(path: &Path) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::new(),
            Err(e) => {
                log::error!(
                    "reading {}: {e}; starting with an empty originated set",
                    path.display()
                );
                return Self::new();
            }
        };
        Self::decode(&bytes).unwrap_or_else(|e| {
            log::error!(
                "{} is unreadable ({e}); starting with an empty originated set",
                path.display()
            );
            Self::new()
        })
    }
}

/// Writes `bytes` to `path` atomically: a temporary file in the same
/// directory, synced, then renamed over `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    /// The three windows, at both ends.
    #[test]
    fn verdicts_follow_the_windows() {
        let mut o = Originated::new();
        let r = 81;
        assert_eq!(o.verdict(&id(1), r), Verdict::Fresh);
        o.record(id(1), r);
        assert_eq!(o.verdict(&id(1), r), Verdict::Held);
        assert_eq!(
            o.verdict(&id(1), r + MEMPOOL_EXPIRY_BLOCKS - 1),
            Verdict::Held
        );
        assert_eq!(
            o.verdict(&id(1), r + MEMPOOL_EXPIRY_BLOCKS),
            Verdict::Expired
        );
        assert_eq!(
            o.verdict(&id(1), r + NETWORK_EXPIRY_BLOCKS - 1),
            Verdict::Expired
        );
        assert_eq!(o.verdict(&id(1), r + NETWORK_EXPIRY_BLOCKS), Verdict::Fresh);
        assert_eq!(o.verdict(&id(2), r), Verdict::Fresh, "only that id");
        assert_eq!(NETWORK_EXPIRY_BLOCKS, 2_160 + 30);
    }

    /// Entries are dropped exactly when their window ends.
    #[test]
    fn pruning_drops_ended_windows_only() {
        let mut o = Originated::new();
        o.record(id(1), 10);
        o.record(id(2), 20);
        let _ = o.encode();
        assert_eq!(o.prune(10 + NETWORK_EXPIRY_BLOCKS - 1), 0);
        assert!(!o.is_dirty());
        assert_eq!(o.prune(10 + NETWORK_EXPIRY_BLOCKS), 1);
        assert!(o.is_dirty());
        assert_eq!(o.relayed(&id(1)), None);
        assert_eq!(o.relayed(&id(2)), Some(20));
    }

    /// Saved and loaded through a file; a torn or foreign file is an empty
    /// set; the size is capped, oldest first.
    #[test]
    fn the_set_survives_a_save_and_load_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("originated.json");
        assert!(Originated::load(&path).is_empty(), "missing file");
        let mut o = Originated::new();
        o.record(id(1), 5);
        o.record(id(2), 7);
        assert!(o.is_dirty());
        write_atomic(&path, &o.encode()).unwrap();
        assert!(!o.is_dirty());
        assert!(!path.with_extension("tmp").exists());
        let back = Originated::load(&path);
        assert_eq!(back.len(), 2);
        assert_eq!(back.relayed(&id(1)), Some(5));
        assert_eq!(back.verdict(&id(2), 8), Verdict::Held);

        std::fs::write(&path, b"{\"version\":1,\"entr").unwrap();
        assert!(Originated::load(&path).is_empty(), "torn file");
        std::fs::write(&path, b"{\"version\":9,\"entries\":[]}").unwrap();
        assert!(Originated::load(&path).is_empty(), "unknown version");
        // A format 1 file: relay heights, no pool heights.
        let v1 = format!(
            "{{\"version\":1,\"entries\":[[\"{}\",5]]}}",
            hex::encode(id(1))
        );
        std::fs::write(&path, v1).unwrap();
        let back = Originated::load(&path);
        assert_eq!(back.relayed(&id(1)), Some(5));
        assert_eq!(back.pooled(&id(1)), None);

        let mut big = Originated::new();
        for n in 0..(ORIGINATED_CAP as u64 + 5) {
            // All inside one window: only the cap drops entries.
            big.record(id(n), 1_000 + n / 100);
        }
        assert_eq!(big.len(), ORIGINATED_CAP);
        assert_eq!(big.relayed(&id(0)), None, "oldest dropped");
        assert!(big.relayed(&id(ORIGINATED_CAP as u64 + 4)).is_some());
        let bytes = big.encode();
        assert_eq!(Originated::decode(&bytes).unwrap().len(), ORIGINATED_CAP);
    }

    /// TM2-P1: the re-announcement anchor is the pool entry's height, as on
    /// every node, never the relay height; a held copy (pooled late)
    /// anchors on the recorded pool height, which survives a save and load,
    /// and without one it is never re-announced. A reorganization's
    /// readmission moves the anchor, as everywhere.
    #[test]
    fn the_anchor_is_the_pool_height_never_the_relay_height() {
        let mut o = Originated::new();
        assert_eq!(o.anchor(&id(9), 50), Some(50), "not originated here");
        o.record(id(1), 81);
        // A block came during the stem: pooled at the fluff for 82.
        assert_eq!(o.anchor(&id(1), 82), Some(82));
        assert!(o.note_pooled(&id(1), 82));
        assert!(!o.note_pooled(&id(1), 82), "unchanged");
        // Mined, then returned by a reorganization and readmitted for 95.
        assert_eq!(o.anchor(&id(1), 95), Some(95));
        assert!(o.note_pooled(&id(1), 95));
        assert_eq!(o.pooled(&id(1)), Some(95));
        assert!(!o.note_pooled(&id(9), 1), "not originated here");

        // Saved and loaded (a restart): a held copy pooled for 97 anchors on
        // the pool height 95.
        let mut back = Originated::decode(&o.encode()).unwrap();
        assert_eq!(back.pooled(&id(1)), Some(95));
        assert_eq!(back.relayed(&id(1)), Some(81));
        back.note_held(id(1), 97);
        assert!(back.is_held(&id(1)));
        assert_eq!(back.anchor(&id(1), 97), Some(95));
        // The held copy mined and readmitted for 99: anchored there.
        back.refresh_held(&[(id(1), Some(99))]);
        assert!(!back.is_held(&id(1)));
        assert_eq!(back.anchor(&id(1), 99), Some(99));

        // No pool height (a restart before the fluff): a held copy is not
        // re-announced until a peer announces it.
        let mut o = Originated::new();
        o.record(id(2), 81);
        o.note_held(id(2), 84);
        assert_eq!(o.anchor(&id(2), 84), None);
        assert!(!o.held_announced(&id(3), 90), "not held");
        assert!(o.held_announced(&id(2), 90));
        assert_eq!(o.anchor(&id(2), 84), Some(90));
        assert!(!o.held_announced(&id(2), 91), "first announcement only");
        // The held copy itself is no pool height to record; a copy pooled
        // again (from a peer, or readmitted) replaces the held mark.
        o.note_held(id(2), 84);
        assert!(!o.note_pooled(&id(2), 84));
        assert!(o.is_held(&id(2)));
        assert!(o.note_pooled(&id(2), 92));
        assert!(!o.is_held(&id(2)));
        // Pruned with its entry.
        o.note_held(id(2), 92);
        o.prune(81 + NETWORK_EXPIRY_BLOCKS);
        assert!(!o.is_held(&id(2)) && o.is_empty());
        // Only originated transactions get a held mark.
        o.note_held(id(4), 5);
        assert!(!o.is_held(&id(4)));
    }
}
