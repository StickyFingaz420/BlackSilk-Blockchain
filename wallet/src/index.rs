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
//! **The output distribution** the decoy picker draws from (cumulative output
//! counts per block, `blacksilk_tx::decoy`) is derived from this index
//! ([`OutputIndex::cumulative`]), never asked of the node at spend time
//! (docs/transactions.md §11.3.1; dossier 38 F38-1, F38-6). A node-served
//! distribution could be skewed while staying monotone with the right total,
//! moving decoy ages away from a young real input, and the request itself
//! told the node that a spend was being built. The heights of the scanned
//! range come from blocks the wallet checked; those of the backfilled range
//! (below the restore height) are the node's `/outputs` answers, checked
//! only for shape (see `cumulative_of`), not verified (F38-2; 38 W11).
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

    /// The indexed outputs, in global-index order.
    pub fn iter(&self) -> std::slice::Iter<'_, IndexedOutput> {
        self.entries.iter()
    }

    /// The output distribution of blocks `0..=synced`: `cumulative[h]` is the
    /// number of outputs in blocks `0..=h` (what the node's `/distribution`
    /// serves), from the outputs' heights. The index must be complete (start
    /// at 0) and pass the shape check of [`cumulative_of`].
    pub fn cumulative(&self, synced: u64) -> Result<Vec<u64>, String> {
        if self.start != 0 {
            return Err(format!(
                "the output index starts at output {}, not 0",
                self.start
            ));
        }
        cumulative_of(self.entries.iter(), synced)
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

/// The output distribution of blocks `0..=synced` from `outputs`, every
/// output of those blocks from global index 0 on, in order: `cumulative[h]`
/// is the number of outputs in blocks `0..=h`.
///
/// A cheap sanity check of the heights, from consensus facts: the genesis
/// body is empty (docs/blocks.md §3), so no output has height 0; every other
/// block starts with a coinbase of at least one output (`MIN_COINBASE_OUTPUTS`
/// = 1, `validate_block_transactions_cached`), so every height `1..=synced`
/// appears, with a coinbase output; heights never decrease and none exceeds
/// `synced`. Anything else is refused. It catches a backfill with a gap, a
/// stale tail or relabelled coinbase flags; it cannot catch a consistent
/// fabrication (the backfill is not verified, F38-2).
pub fn cumulative_of<'a>(
    outputs: impl IntoIterator<Item = &'a IndexedOutput>,
    synced: u64,
) -> Result<Vec<u64>, String> {
    let outputs = outputs.into_iter();
    // Every height from 1 on has an output, so `synced` cannot exceed the
    // number of outputs; checked before anything is allocated from it.
    let hint = outputs.size_hint().1.unwrap_or(usize::MAX) as u64;
    if synced > hint {
        return Err(format!(
            "{hint} outputs cannot cover blocks 1 to {synced}, one coinbase output each"
        ));
    }
    let blocks = usize::try_from(synced + 1).map_err(|_| "too many blocks".to_string())?;
    let mut cumulative = Vec::with_capacity(blocks);
    // The genesis: no outputs.
    let (mut height, mut count, mut coinbase) = (0u64, 0u64, true);
    for e in outputs {
        if e.height == 0 {
            return Err(format!(
                "output {count} is in the genesis block, whose body is empty"
            ));
        }
        if e.height != height {
            if e.height < height {
                return Err(format!(
                    "output {count} (block {}) is out of height order",
                    e.height
                ));
            }
            if e.height > synced {
                return Err(format!(
                    "output {count} is in block {}, above the synced block {synced}",
                    e.height
                ));
            }
            if !coinbase {
                return Err(format!("block {height} has no coinbase output"));
            }
            if e.height != height + 1 {
                return Err(format!("block {} has no outputs", height + 1));
            }
            cumulative.push(count);
            height = e.height;
            coinbase = false;
        }
        coinbase |= e.coinbase;
        count += 1;
    }
    if !coinbase {
        return Err(format!("block {height} has no coinbase output"));
    }
    if height != synced {
        return Err(format!("block {} has no outputs", height + 1));
    }
    cumulative.push(count);
    Ok(cumulative)
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

    fn rec(height: u64, coinbase: bool) -> IndexedOutput {
        IndexedOutput {
            one_time_key: [height as u8; 32],
            commitment: [1; 32],
            height,
            coinbase,
        }
    }

    /// Blocks `1..=n`, block `h` with `1 + h % 3` outputs, the first a
    /// coinbase output.
    fn chain_index(n: u64) -> (OutputIndex, Vec<u64>) {
        let mut ix = OutputIndex::default();
        let mut cumulative = vec![0];
        let mut first = 0;
        for h in 1..=n {
            let k = 1 + h % 3;
            ix.push_block(h, first, (0..k).map(|j| ([h as u8; 32], [1; 32], j == 0)));
            first += k;
            cumulative.push(first);
        }
        (ix, cumulative)
    }

    #[test]
    fn cumulative_counts_outputs_per_block() {
        let (ix, want) = chain_index(30);
        assert_eq!(ix.cumulative(30).unwrap(), want);
        // The empty chain (only the genesis).
        assert_eq!(OutputIndex::default().cumulative(0).unwrap(), vec![0]);
        // A synced height the index does not reach, or exceeds.
        assert!(ix.cumulative(31).is_err());
        assert!(ix.cumulative(29).is_err());
    }

    #[test]
    fn cumulative_follows_a_reorganization() {
        let (mut ix, want) = chain_index(30);
        ix.rewind(20);
        assert_eq!(ix.cumulative(20).unwrap(), want[..=20]);
        // Another block 21, with two outputs.
        ix.push_block(21, want[20], [out(2), out(4)]);
        let c = ix.cumulative(21).unwrap();
        assert_eq!(c[..=20], want[..=20]);
        assert_eq!(c[21], want[20] + 2);
    }

    #[test]
    fn cumulative_after_a_backfill_prepend() {
        let (full, want) = chain_index(40);
        // The wallet scanned from block 25: blocks 1..=24 are backfilled.
        let start = want[24];
        let mut ix = OutputIndex::default();
        for h in 25..=40 {
            let from = want[h as usize - 1];
            ix.push_block(
                h,
                from,
                (from..want[h as usize]).map(|i| {
                    let e = full.get(i).unwrap();
                    (e.one_time_key, e.commitment, e.coinbase)
                }),
            );
        }
        assert!(ix.cumulative(40).is_err(), "incomplete: starts at {start}");
        let older: Vec<IndexedOutput> = (0..start).map(|i| *full.get(i).unwrap()).collect();
        assert_eq!(
            cumulative_of(older.iter().chain(ix.iter()), 40).unwrap(),
            want
        );
        ix.prepend(older, start).unwrap();
        assert_eq!(ix.cumulative(40).unwrap(), want);
    }

    /// The shape check: a backfill missing a block, a block without a
    /// coinbase output, an output in the genesis, out of order or above the
    /// synced block are refused.
    #[test]
    fn cumulative_refuses_a_malformed_index() {
        let good = vec![rec(1, true), rec(2, true), rec(2, false), rec(3, true)];
        assert_eq!(cumulative_of(&good, 3).unwrap(), vec![0, 1, 3, 4]);
        let bad: [(&str, Vec<IndexedOutput>); 6] = [
            ("a missing block", vec![rec(1, true), rec(3, true)]),
            (
                "no coinbase",
                vec![rec(1, true), rec(2, false), rec(3, true)],
            ),
            (
                "last without coinbase",
                vec![rec(1, true), rec(2, true), rec(3, false)],
            ),
            (
                "the genesis",
                vec![rec(0, true), rec(1, true), rec(2, true), rec(3, true)],
            ),
            (
                "out of order",
                vec![rec(1, true), rec(3, true), rec(2, true), rec(3, true)],
            ),
            (
                "above",
                vec![rec(1, true), rec(2, true), rec(3, true), rec(4, true)],
            ),
        ];
        for (what, outputs) in bad {
            assert!(cumulative_of(&outputs, 3).is_err(), "{what}");
        }
        // Too few outputs for the synced height: refused before allocating.
        assert!(cumulative_of(&good, u64::MAX).is_err());
    }

    /// 10^6 outputs over 250 000 blocks (the index's documented scale).
    /// Run with `cargo test --release -p blacksilk-wallet --lib -- --ignored
    /// cumulative_at_a_million_outputs --nocapture`.
    #[test]
    #[ignore = "timing"]
    fn cumulative_at_a_million_outputs() {
        let blocks = 250_000u64;
        let mut ix = OutputIndex::default();
        for h in 1..=blocks {
            let first = (h - 1) * 4;
            ix.push_block(h, first, (0..4).map(|j| ([7; 32], [7; 32], j == 0)));
        }
        let t = std::time::Instant::now();
        let c = ix.cumulative(blocks).unwrap();
        let took = t.elapsed();
        assert_eq!(c.len() as u64, blocks + 1);
        assert_eq!(c[blocks as usize], 1_000_000);
        println!("cumulative() over 10^6 outputs: {took:?}");
        assert!(took < std::time::Duration::from_secs(2), "{took:?}");
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
