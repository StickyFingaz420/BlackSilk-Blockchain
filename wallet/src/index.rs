//! The local output index (review I3 §3.9, SX2 C5).
//!
//! The wallet downloads every block anyway, so it records every v1 output it
//! sees: global index → (one-time key, commitment, height, coinbase). Ring
//! members are then resolved locally and the node is never asked about
//! them. The old `/outputs` query handed the node a superset of every future
//! ring with the real input in it; intersecting a few such queries with the
//! rings on chain finds the real input.
//!
//! Outputs older than the wallet's restore height were never scanned. They
//! are filled in once ("backfill") by fetching the **whole** missing range in
//! fixed-size pages, the same requests for every wallet with that restore
//! height, independent of what it later spends.
//!
//! The index is contiguous: it covers `start .. start + len` with no gap.
//! Reorganizations are undone by height, like the rest of the wallet.
//!
//! **Size.** 73 bytes per output in memory; 146 hex characters in the wallet
//! file (about 150 MB per million outputs). Adequate for the testnet; a
//! separate append-only file is the next step (docs/reviews/wallet-review.md).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One indexed output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedOutput {
    pub one_time_key: [u8; 32],
    pub commitment: [u8; 32],
    pub height: u64,
    pub coinbase: bool,
}

const RECORD: usize = 32 + 32 + 8 + 1;

impl IndexedOutput {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.one_time_key);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.push(self.coinbase as u8);
    }

    fn read(b: &[u8]) -> Option<Self> {
        let b: &[u8; RECORD] = b.try_into().ok()?;
        Some(Self {
            one_time_key: b[..32].try_into().ok()?,
            commitment: b[32..64].try_into().ok()?,
            height: u64::from_le_bytes(b[64..72].try_into().ok()?),
            coinbase: match b[72] {
                0 => false,
                1 => true,
                _ => return None,
            },
        })
    }
}

/// Every output with global index in `start .. start + entries.len()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputIndex {
    start: u64,
    entries: Vec<IndexedOutput>,
}

impl OutputIndex {
    /// The first indexed global index.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// One past the last indexed global index.
    pub fn end(&self) -> u64 {
        self.start + self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, index: u64) -> Option<&IndexedOutput> {
        let i = usize::try_from(index.checked_sub(self.start)?).ok()?;
        self.entries.get(i)
    }

    /// Whether every output in `0 .. total` is indexed, and nothing beyond.
    pub fn is_complete(&self, total: u64) -> bool {
        self.start == 0 && self.end() == total
    }

    /// Appends the outputs of the block at `height`, whose first output has
    /// global index `first`. A block that does not continue the index (it
    /// can only happen after an inconsistency) restarts the index at `first`;
    /// the missing part is then backfilled when needed.
    pub fn push_block(
        &mut self,
        height: u64,
        first: u64,
        outputs: impl IntoIterator<Item = ([u8; 32], [u8; 32], bool)>,
    ) {
        if self.entries.is_empty() || first != self.end() {
            self.entries.clear();
            self.start = first;
        }
        for (one_time_key, commitment, coinbase) in outputs {
            self.entries.push(IndexedOutput {
                one_time_key,
                commitment,
                height,
                coinbase,
            });
        }
    }

    /// Removes the outputs of blocks above `height`.
    pub fn rewind(&mut self, height: u64) {
        let keep = self.entries.partition_point(|e| e.height <= height);
        self.entries.truncate(keep);
    }

    /// Prepends `older`: the outputs `0 .. end`, where `end` must be where the
    /// index starts (any value for an empty index). They must lie at or below
    /// the index's first height.
    pub fn prepend(&mut self, older: Vec<IndexedOutput>, end: u64) -> Result<(), String> {
        if self.entries.is_empty() {
            self.start = end;
        }
        if end != self.start || older.len() as u64 != end {
            return Err("the backfill is not the range from 0 to the index's start".into());
        }
        let first_height = self.entries.first().map_or(u64::MAX, |e| e.height);
        if older.windows(2).any(|w| w[0].height > w[1].height)
            || older.last().is_some_and(|e| e.height > first_height)
        {
            return Err("backfilled outputs are out of height order".into());
        }
        self.start -= older.len() as u64;
        let mut all = older;
        all.append(&mut self.entries);
        self.entries = all;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    start: u64,
    /// The records, concatenated, in hex.
    data: String,
}

impl Serialize for OutputIndex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::with_capacity(self.entries.len() * RECORD);
        for e in &self.entries {
            e.write(&mut bytes);
        }
        Stored {
            start: self.start,
            data: hex::encode(bytes),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for OutputIndex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let s = Stored::deserialize(d)?;
        let bytes = hex::decode(&s.data).map_err(|_| D::Error::custom("output index hex"))?;
        if bytes.len() % RECORD != 0 {
            return Err(D::Error::custom("output index length"));
        }
        let entries = bytes
            .chunks(RECORD)
            .map(IndexedOutput::read)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| D::Error::custom("output index record"))?;
        if entries.windows(2).any(|w| w[0].height > w[1].height)
            || s.start.checked_add(entries.len() as u64).is_none()
        {
            return Err(D::Error::custom("output index order"));
        }
        Ok(Self {
            start: s.start,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(tag: u8) -> ([u8; 32], [u8; 32], bool) {
        ([tag; 32], [tag.wrapping_add(1); 32], tag.is_multiple_of(2))
    }

    #[test]
    fn blocks_append_rewind_and_backfill() {
        let mut ix = OutputIndex::default();
        ix.push_block(5, 100, [out(1), out(2)]);
        ix.push_block(6, 102, [out(3)]);
        assert_eq!((ix.start(), ix.end()), (100, 103));
        assert_eq!(ix.get(102).unwrap().height, 6);
        assert!(ix.get(99).is_none() && ix.get(103).is_none());
        ix.rewind(5);
        assert_eq!(ix.end(), 102);
        // Backfill 0..100.
        let older: Vec<IndexedOutput> = (0..100)
            .map(|i| IndexedOutput {
                one_time_key: [9; 32],
                commitment: [9; 32],
                height: i / 25,
                coinbase: true,
            })
            .collect();
        assert!(ix.prepend(older[..50].to_vec(), 100).is_err(), "gap");
        ix.prepend(older, 100).unwrap();
        assert!(ix.is_complete(102));
        assert_eq!(ix.get(0).unwrap().height, 0);
        // A block that does not continue the index restarts it.
        ix.push_block(9, 500, [out(4)]);
        assert_eq!((ix.start(), ix.end()), (500, 501));
    }

    #[test]
    fn it_round_trips_and_refuses_damage() {
        let mut ix = OutputIndex::default();
        ix.push_block(1, 0, [out(1), out(2)]);
        ix.push_block(2, 2, [out(3)]);
        let json = serde_json::to_string(&ix).unwrap();
        assert_eq!(serde_json::from_str::<OutputIndex>(&json).unwrap(), ix);
        let cut = json.replacen("\"data\":\"", "\"data\":\"00", 1);
        assert!(serde_json::from_str::<OutputIndex>(&cut).is_err());
    }
}
