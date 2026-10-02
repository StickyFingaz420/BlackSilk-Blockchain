//! The originated set (docs/p2p.md §8.1; dossier 33 W2, F33-1): the
//! transactions this node originated (RPC `/tx`, `Network::submit_tx`), each
//! with the height it was relayed for, persisted across restarts, and which
//! pool entries are held copies (in memory).
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
//! re-announcement schedule (docs/p2p.md §7; TM2-P1): the origin counts that
//! schedule from its pool entry's height, as every node does. A **held** copy
//! (pooled by [`Verdict::Held`], typically after a restart) is never
//! re-announced ([`Originated::anchor`]): the relays that still pool the
//! transaction re-announce it, and an origin announcing it on schedule after
//! a restart would show it held the transaction across the restart.
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

/// File format version of `originated.json`. Format 2 (a third, optional
/// pool height per entry, written by an unmerged development version) is
/// read too, its extra field ignored.
const FORMAT: u32 = 1;

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
    /// `(transaction id (hex), relay height)`.
    entries: Vec<(String, u64)>,
}

/// Format 2: `(transaction id (hex), relay height, pool height)`.
#[derive(Deserialize)]
struct FileV2 {
    entries: Vec<(String, u64, Option<u64>)>,
}

#[derive(Deserialize)]
struct FormatVersion {
    version: u32,
}

/// The originated set.
#[derive(Default)]
pub struct Originated {
    relayed: HashMap<Hash, u64>,
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
        self.relayed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relayed.is_empty()
    }

    /// The height `id` was relayed for, if this node originated it.
    pub fn relayed(&self, id: &Hash) -> Option<u64> {
        self.relayed.get(id).copied()
    }

    /// What a resubmission of `id` for inclusion at `next` may do.
    pub fn verdict(&self, id: &Hash, next: u64) -> Verdict {
        match self.relayed.get(id) {
            None => Verdict::Fresh,
            Some(&r) if next >= r.saturating_add(NETWORK_EXPIRY_BLOCKS) => Verdict::Fresh,
            Some(&r) if next >= r.saturating_add(MEMPOOL_EXPIRY_BLOCKS) => Verdict::Expired,
            Some(_) => Verdict::Held,
        }
    }

    /// The pool re-announcement anchor of a transaction pooled here for
    /// `admitted` (docs/p2p.md §7): `admitted`, as on every node, or `None`
    /// (never re-announced) if the pool entry is a held copy of a
    /// transaction originated here. Never the relay height.
    pub fn anchor(&self, id: &Hash, admitted: u64) -> Option<u64> {
        (self.held.get(id) != Some(&admitted)).then_some(admitted)
    }

    /// Notes that a held copy of `id` ([`Verdict::Held`]) was pooled for
    /// `admitted`.
    pub fn note_held(&mut self, id: Hash, admitted: u64) {
        if self.relayed.contains_key(&id) {
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
    /// copy that is mined and returned by a reorganization is readmitted at
    /// the reorganization's height, as on every node, and re-announced from
    /// there like everyone's copy.
    pub fn refresh_held(&mut self, now: &[(Hash, Option<u64>)]) {
        for (id, at) in now {
            if self.held.get(id).is_some_and(|a| Some(*a) != *at) {
                self.held.remove(id);
            }
        }
    }

    /// Records that `id` is originated here for inclusion at `next` (a
    /// window ended earlier starts again).
    pub fn record(&mut self, id: Hash, next: u64) {
        self.relayed.insert(id, next);
        self.held.remove(&id);
        self.dirty = true;
        if self.relayed.len() > ORIGINATED_CAP {
            self.prune(next);
        }
        while self.relayed.len() > ORIGINATED_CAP {
            let oldest = self
                .relayed
                .iter()
                .min_by_key(|(id, r)| (**r, **id))
                .map(|(id, _)| *id)
                .expect("non-empty");
            self.relayed.remove(&oldest);
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
        if self.relayed.remove(id).is_some() {
            self.dirty = true;
        }
    }

    /// Drops the entries whose window ended by `next`. Returns how many.
    pub fn prune(&mut self, next: u64) -> usize {
        let before = self.relayed.len();
        self.relayed
            .retain(|_, r| next < r.saturating_add(NETWORK_EXPIRY_BLOCKS));
        let relayed = &self.relayed;
        self.held.retain(|id, _| relayed.contains_key(id));
        let n = before - self.relayed.len();
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
        let mut entries: Vec<(String, u64)> = self
            .relayed
            .iter()
            .map(|(id, r)| (hex::encode(id), *r))
            .collect();
        entries.sort();
        serde_json::to_vec(&File {
            version: FORMAT,
            entries,
        })
        .expect("serializable")
    }

    /// Parses a saved set (format 1, or 2 with its pool heights ignored).
    /// Entries beyond [`ORIGINATED_CAP`] (oldest first) and malformed ids
    /// are dropped.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let v: FormatVersion = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let raw: Vec<(String, u64)> = match v.version {
            FORMAT => {
                let f: File = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                f.entries
            }
            2 => {
                let f: FileV2 = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                f.entries.into_iter().map(|(id, r, _)| (id, r)).collect()
            }
            n => return Err(format!("unknown format version {n}")),
        };
        let mut entries: Vec<(Hash, u64)> = raw
            .into_iter()
            .filter_map(|(id, r)| {
                let bytes = hex::decode(id).ok()?;
                Some((bytes.try_into().ok()?, r))
            })
            .collect();
        entries.sort_by_key(|(id, r)| (std::cmp::Reverse(*r), *id));
        entries.truncate(ORIGINATED_CAP);
        Ok(Self {
            relayed: entries.into_iter().collect(),
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
        // A format 2 file (pool heights, ignored).
        let v2 = format!(
            "{{\"version\":2,\"entries\":[[\"{}\",5,82],[\"{}\",6,null]]}}",
            hex::encode(id(1)),
            hex::encode(id(2))
        );
        std::fs::write(&path, v2).unwrap();
        let back = Originated::load(&path);
        assert_eq!(back.relayed(&id(1)), Some(5));
        assert_eq!(back.relayed(&id(2)), Some(6));

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
    /// every node, never the relay height; a held copy has none (never
    /// re-announced), until a reorganization readmits it like everyone's.
    #[test]
    fn the_anchor_is_the_pool_height_and_a_held_copy_has_none() {
        let mut o = Originated::new();
        assert_eq!(o.anchor(&id(9), 50), Some(50), "not originated here");
        o.record(id(1), 81);
        // A block came during the stem: pooled at the fluff for 82.
        assert_eq!(o.anchor(&id(1), 82), Some(82));
        // A held copy pooled for 97: never re-announced.
        o.note_held(id(1), 97);
        assert!(o.is_held(&id(1)));
        assert_eq!(o.anchor(&id(1), 97), None);
        assert_eq!(o.held(), vec![(id(1), 97)]);
        // Still pooled for 97: still held.
        o.refresh_held(&[(id(1), Some(97))]);
        assert!(o.is_held(&id(1)));
        // Mined, then readmitted for 99 by a reorganization: as everyone's.
        o.refresh_held(&[(id(1), Some(99))]);
        assert!(!o.is_held(&id(1)));
        assert_eq!(o.anchor(&id(1), 99), Some(99));
        // Gone from the pool: the mark goes too.
        o.note_held(id(1), 100);
        o.refresh_held(&[(id(1), None)]);
        assert!(!o.is_held(&id(1)));
        // The mark goes with its entry, and only originated ids get one.
        o.note_held(id(1), 100);
        o.forget(&id(1));
        assert!(!o.is_held(&id(1)));
        o.note_held(id(4), 5);
        assert!(!o.is_held(&id(4)));
        o.record(id(2), 81);
        o.note_held(id(2), 84);
        o.prune(81 + NETWORK_EXPIRY_BLOCKS);
        assert!(!o.is_held(&id(2)) && o.is_empty());
        // Not persisted: the pool is not either.
        o.record(id(3), 90);
        o.note_held(id(3), 91);
        assert!(!Originated::decode(&o.encode()).unwrap().is_held(&id(3)));
    }
}
