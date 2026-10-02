//! The originated set (docs/p2p.md §8.1; dossier 33 W2, F33-1): the
//! transactions this node originated (RPC `/tx`, `Network::submit_tx`), each
//! with the height it was relayed for, persisted across restarts.
//!
//! An honest relay never stems, and never announces as new, a transaction the
//! network has held for a while; only its origin does that when its wallet
//! resubmits a transaction the origin forgot (a restart empties the pool; the
//! pool's own expiry comes first at the origin, which admitted it first). A
//! spy that still pools it then learns the origin with near certainty. So a
//! transaction in this set is never originated again while other nodes may
//! still pool it:
//! - before `relayed + MEMPOOL_EXPIRY_BLOCKS`, while honest pools hold it, a
//!   resubmission is **held** ([`Verdict::Held`]): checked and accepted,
//!   but neither stemmed, announced nor pooled. The node then has it exactly
//!   as a restarted relay has it: not at all, until a peer announces it and
//!   it is fetched like any transaction (RT-TM2P2P: a pooled held copy
//!   answered an `InvTx` differently, and expired at its own height);
//! - until `relayed + NETWORK_EXPIRY_BLOCKS` (the recently-expired guard of
//!   every node that expired it, `RECENTLY_EXPIRED_BLOCKS`), it is refused as
//!   `Expired` ([`Verdict::Expired`]), the persisted form of the mempool's
//!   in-memory guard;
//! - after that the entry is dropped and the transaction may be originated
//!   again, as a new one ([`Verdict::Fresh`]).
//!
//! The relay height decides these windows only, never the pool
//! re-announcement schedule (docs/p2p.md §7; TM2-P1).
//!
//! Heights are next-block heights (the height a transaction is admitted for),
//! as in the mempool. The file (`originated.json` in the data directory) is
//! written to a temporary file, synced and renamed, so a crash leaves the old
//! set or the new one, never a torn file. A damaged file fails closed: every
//! entry that parses is kept, the rest is logged ([`Originated::decode`]).
//! It holds at most
//! [`ORIGINATED_CAP`] entries; beyond that the oldest are dropped (a node
//! originating more than that within about three days loses the protection
//! for its oldest transactions, and logs it).

use blacksilk_chain::mempool::{MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS};
use blacksilk_consensus::Hash;
use serde::Serialize;
use serde_json::Value;
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

/// File format version of `originated.json` (format 2, written by an
/// unmerged development version with a third field per entry, is read too).
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

#[derive(Serialize)]
struct File {
    version: u32,
    /// `(transaction id (hex), relay height)`.
    entries: Vec<(String, u64)>,
}

/// The originated set.
#[derive(Default)]
pub struct Originated {
    relayed: HashMap<Hash, u64>,
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

    /// Records that `id` is originated here for inclusion at `next` (a
    /// window ended earlier starts again).
    pub fn record(&mut self, id: Hash, next: u64) {
        self.relayed.insert(id, next);
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
            log::warn!(
                "originated set full ({ORIGINATED_CAP}): the oldest entry is dropped, and \
                 its transaction may be originated again before its window ends"
            );
        }
    }

    /// Forgets `id` (it was not originated after all).
    pub fn forget(&mut self, id: &Hash) {
        if self.relayed.remove(id).is_some() {
            self.dirty = true;
        }
    }

    /// Drops the entries whose window ended by `next`. Returns how many.
    pub fn prune(&mut self, next: u64) -> usize {
        let before = self.relayed.len();
        self.relayed
            .retain(|_, r| next < r.saturating_add(NETWORK_EXPIRY_BLOCKS));
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

    /// Parses a saved set, failing closed (RT-TM2P2P item 5): a forgotten
    /// entry lets the node originate a transaction again, so every entry
    /// that parses is kept, whatever is wrong elsewhere.
    /// - The file is read as JSON values, each entry on its own: an entry
    ///   is `[id (64 hex digits), relay height, ...]` (format 1 has two
    ///   fields, format 2 three; anything after the height is ignored). A
    ///   malformed entry is dropped alone. A missing or unknown version
    ///   does not stop the entries from being read.
    /// - A file that is not JSON (torn, corrupt) is scanned for entries.
    /// - A duplicate id keeps its highest height (the later window).
    /// - Beyond [`ORIGINATED_CAP`], the oldest are dropped.
    ///
    /// Returns the set and what was wrong (empty for a clean file); the set
    /// is marked changed if anything was, so it is written back clean.
    pub fn decode(bytes: &[u8]) -> (Self, Vec<String>) {
        let mut problems = Vec::new();
        let mut raw: Vec<(Hash, u64)> = Vec::new();
        match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(m)) => {
                match m.get("version").and_then(Value::as_u64) {
                    Some(1) | Some(2) => {}
                    Some(v) => problems.push(format!("unknown format version {v}")),
                    None => problems.push("no format version".into()),
                }
                match m.get("entries").and_then(Value::as_array) {
                    Some(list) => {
                        for (i, e) in list.iter().enumerate() {
                            match parse_entry(e) {
                                Some(x) => raw.push(x),
                                None => problems.push(format!("entry {i} is malformed")),
                            }
                        }
                    }
                    None => problems.push("no entry list".into()),
                }
            }
            Ok(_) => problems.push("not a JSON object".into()),
            Err(e) => {
                raw = salvage(bytes);
                problems.push(format!(
                    "not valid JSON ({e}); {} entries recovered by scanning",
                    raw.len()
                ));
            }
        }
        let mut relayed: HashMap<Hash, u64> = HashMap::new();
        for (id, r) in raw {
            let e = relayed.entry(id).or_insert(r);
            if r != *e {
                problems.push(format!(
                    "{} is listed twice; the highest height is kept",
                    hex::encode(id)
                ));
                *e = (*e).max(r);
            }
        }
        let mut entries: Vec<(Hash, u64)> = relayed.into_iter().collect();
        entries.sort_by_key(|(id, r)| (std::cmp::Reverse(*r), *id));
        if entries.len() > ORIGINATED_CAP {
            problems.push(format!(
                "{} entries, over the cap {ORIGINATED_CAP}: the oldest are dropped",
                entries.len()
            ));
            entries.truncate(ORIGINATED_CAP);
        }
        let dirty = !problems.is_empty();
        (
            Self {
                relayed: entries.into_iter().collect(),
                dirty,
            },
            problems,
        )
    }

    /// Loads the set saved at `path`. A missing file is an empty set. A file
    /// that cannot be read is logged as an error and an empty set is used:
    /// the node may then originate again a transaction it originated before,
    /// which is a visible event, not a silent one. A damaged file keeps
    /// every entry that parses ([`Self::decode`]), and every problem is
    /// logged as an error.
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
        let (set, problems) = Self::decode(&bytes);
        for p in &problems {
            log::error!("{}: {p}", path.display());
        }
        if !problems.is_empty() {
            log::error!(
                "{} is damaged: {} entries kept; a transaction whose entry was lost may \
                 be originated again by this node",
                path.display(),
                set.len()
            );
        }
        set
    }
}

/// One entry: `[id (64 hex digits), relay height, ...]`.
fn parse_entry(e: &Value) -> Option<(Hash, u64)> {
    let a = e.as_array()?;
    let id: Hash = hex::decode(a.first()?.as_str()?).ok()?.try_into().ok()?;
    Some((id, a.get(1)?.as_u64()?))
}

/// The entries a file that is not JSON still holds: every `["<64 hex
/// digits>", <height>` in it.
fn salvage(bytes: &[u8]) -> Vec<(Hash, u64)> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(i) = rest.find("[\"") {
        rest = &rest[i + 2..];
        let Some(hexed) = rest.get(..64) else { break };
        let Some(after) = rest.get(64..) else { break };
        let Some(after) = after.strip_prefix("\",") else {
            continue;
        };
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let id: Option<Hash> = hex::decode(hexed).ok().and_then(|b| b.try_into().ok());
        if let (Some(id), Ok(r)) = (id, digits.parse::<u64>()) {
            out.push((id, r));
        }
    }
    out
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

        let mut big = Originated::new();
        for n in 0..(ORIGINATED_CAP as u64 + 5) {
            // All inside one window: only the cap drops entries.
            big.record(id(n), 1_000 + n / 100);
        }
        assert_eq!(big.len(), ORIGINATED_CAP);
        assert_eq!(big.relayed(&id(0)), None, "oldest dropped");
        assert!(big.relayed(&id(ORIGINATED_CAP as u64 + 4)).is_some());
        let bytes = big.encode();
        let (back, problems) = Originated::decode(&bytes);
        assert_eq!(back.len(), ORIGINATED_CAP);
        assert!(problems.is_empty() && !back.is_dirty(), "a clean file");
    }

    /// RT-TM2P2P item 5: a damaged file fails closed. Each entry is read on
    /// its own and a bad one is dropped alone; a duplicate keeps the
    /// highest height; formats 1 and 2 and mixed entry shapes are read; a
    /// missing or unknown version does not stop the entries; a torn file
    /// keeps the entries before the tear. Every damage is reported and
    /// marks the set for a clean rewrite.
    #[test]
    fn a_damaged_file_keeps_every_entry_that_parses() {
        let h = |n: u64| hex::encode(id(n));
        let read = |json: String| Originated::decode(json.as_bytes());
        let (o, p) = read(format!(
            r#"{{"version":2,"entries":[["{}",5,7],["{}",6],["{}",-1],["zz",8],["{}",900],["{}",4]]}}"#,
            h(1),
            h(2),
            h(3),
            h(4),
            h(4)
        ));
        assert_eq!(o.relayed(&id(1)), Some(5), "format 2 entry");
        assert_eq!(
            o.relayed(&id(2)),
            Some(6),
            "format 1 entry in a format 2 file"
        );
        assert_eq!(o.relayed(&id(3)), None, "bad height dropped alone");
        assert_eq!(
            o.relayed(&id(4)),
            Some(900),
            "duplicate: the highest height"
        );
        assert_eq!(o.len(), 3);
        assert_eq!(p.len(), 3, "{p:?}");
        assert!(o.is_dirty());
        let (o, p) = read(format!(r#"{{"entries":[["{}",5]],"x":1}}"#, h(1)));
        assert_eq!((o.relayed(&id(1)), p.len()), (Some(5), 1), "no version");
        let (o, _) = read(format!(r#"{{"entries":[["{}",5]],"version":7}}"#, h(1)));
        assert_eq!(o.relayed(&id(1)), Some(5), "unknown version");
        let (o, p) = read(format!(
            r#"{{"version":1,"entries":[["{}",5],["{}", 6],["{}",7"#,
            h(1),
            h(2),
            &h(3)[..20]
        ));
        assert_eq!(o.relayed(&id(1)), Some(5), "torn file");
        assert_eq!(o.relayed(&id(2)), Some(6), "torn file");
        assert_eq!(o.len(), 2);
        assert_eq!(p.len(), 1, "{p:?}");
        let (o, p) = read("[1,2]".into());
        assert!(o.is_empty() && p.len() == 1);
        let (o, p) = read(format!(r#"{{"version":1,"entries":[["{}",5]]}}"#, h(1)));
        assert!(p.is_empty() && !o.is_dirty() && o.len() == 1, "clean");
    }
}
