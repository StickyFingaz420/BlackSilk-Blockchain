//! The wallet's private-execution (PX) state (docs/px.md §11.4): received
//! records, spends, and the commitment tree.
//!
//! **Privacy of scanning.** The wallet learns about its records only from
//! data every wallet downloads alike: whole blocks (records, nullifiers) and
//! the complete, ordered list of commitments (`/px/commitments`, fetched in
//! bulk). It never asks the node about a specific record, position or
//! nullifier, so the node cannot tell which records are the wallet's.
//!
//! **Keys.** PX keys derive from the same 24-word seed as the v1 keys
//! (domain-separated, `blacksilk_px::wallet::Account`).
//!
//! **Tree.** The wallet keeps every commitment in order to build
//! authentication paths, and checks its root against the node's.

use crate::node::NodeApi;
use crate::wallet::WalletError;
use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::Account;
use blacksilk_px_core::record::{nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, P};
use blacksilk_tx::px::digest_bytes;
use blacksilk_tx::types::Transaction;
use serde::{Deserialize, Serialize};

/// PX addresses scanned beyond the highest issued index.
pub const PX_LOOKAHEAD: u32 = 20;

/// Wallets anchor spends at the most recent height that is a multiple of
/// this, so every wallet transacting in the same window uses the same anchor
/// and the anchor does not reveal when a wallet last synced. Records become
/// spendable once the anchor height reaches them (at most this many blocks),
/// well inside the 100-block root window.
pub const ANCHOR_INTERVAL: u64 = 16;

/// The canonical anchor height for a wallet synced to `synced`.
pub fn anchor_height(synced: u64) -> u64 {
    synced - synced % ANCHOR_INTERVAL
}

pub(crate) fn digest_hex(d: &Digest) -> String {
    hex::encode(digest_bytes(d))
}

pub(crate) fn digest_from_hex(s: &str) -> Result<Digest, WalletError> {
    let b = hex::decode(s).map_err(|_| WalletError::Serialization("digest hex".into()))?;
    if b.len() != 32 {
        return Err(WalletError::Serialization("digest length".into()));
    }
    let mut d = [0u32; 8];
    for (i, x) in d.iter_mut().enumerate() {
        *x = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().expect("4 bytes"));
        if *x >= P {
            return Err(WalletError::Serialization("non-canonical digest".into()));
        }
    }
    Ok(d)
}

/// A received record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredRecord {
    /// The PX address index it was paid to.
    pub index: u32,
    pub height: u64,
    pub commitment: String,
    /// Tree position (resolved from the commitment list).
    pub position: Option<u64>,
    pub value: u64,
    pub data: String,
    pub rho: String,
    pub rcm: String,
    pub nullifier: String,
    pub spent_height: Option<u64>,
    /// Spent by a submitted, unconfirmed transaction.
    pub pending: bool,
    pub pending_height: u64,
}

impl StoredRecord {
    pub fn record(&self, owner: Digest) -> Result<Record, WalletError> {
        Ok(Record::plain(
            owner,
            self.value,
            digest_from_hex(&self.data)?,
            digest_from_hex(&self.rho)?,
            digest_from_hex(&self.rcm)?,
        ))
    }
}

/// The persisted PX state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PxStore {
    /// Every commitment of the chain, `(height, hex)`, in tree order.
    pub commitments: Vec<(u64, String)>,
    pub records: Vec<StoredRecord>,
    /// Highest PX address index handed out.
    pub issued: u32,
}

impl PxStore {
    /// Records the PX outputs paid to `account` and the spends of its
    /// records in a block at `height`.
    pub fn apply_block(&mut self, account: &Account, txs: &[Transaction], height: u64) {
        let mut perm = HostPerm::new();
        for tx in txs {
            let Transaction::Px(t) = tx else { continue };
            let nfs: Vec<String> = t.nullifiers.iter().map(digest_hex).collect();
            for r in &mut self.records {
                if nfs.contains(&r.nullifier) {
                    r.spent_height = Some(height);
                    r.pending = false;
                }
            }
            for (j, (cm, ct)) in t.commitments.iter().zip(&t.ciphertexts).enumerate() {
                let rho = output_rho(&mut perm, &t.nullifiers[0], j as u32);
                for index in 0..=self.issued.saturating_add(PX_LOOKAHEAD) {
                    let keys = account.delivery_keys(index);
                    let owner = account.owner(index);
                    let Some(rec) = delivery::open(&keys, &owner, ct, cm, &rho) else {
                        continue;
                    };
                    let hex_cm = digest_hex(cm);
                    if self.records.iter().any(|r| r.commitment == hex_cm) {
                        break;
                    }
                    let nf = nullifier(&mut perm, &account.keys().nk, &rec.rho, cm);
                    self.records.push(StoredRecord {
                        index,
                        height,
                        commitment: hex_cm,
                        position: None,
                        value: rec.value,
                        data: digest_hex(&rec.data),
                        rho: digest_hex(&rec.rho),
                        rcm: digest_hex(&rec.rcm),
                        nullifier: digest_hex(&nf),
                        spent_height: None,
                        pending: false,
                        pending_height: 0,
                    });
                    self.issued = self.issued.max(index);
                    break;
                }
            }
        }
    }

    /// Forgets everything learned above `height`.
    pub fn rewind(&mut self, height: u64) {
        self.records.retain(|r| r.height <= height);
        for r in &mut self.records {
            if r.spent_height.is_some_and(|h| h > height) {
                r.spent_height = None;
            }
        }
        self.commitments.retain(|(h, _)| *h <= height);
    }

    /// Fetches new commitments in bulk and resolves record positions. When
    /// the node is at the wallet's height, the tree root must equal the
    /// node's.
    pub fn sync_commitments(&mut self, node: &dyn NodeApi, synced: u64) -> Result<(), WalletError> {
        loop {
            let from = self.commitments.len() as u64;
            let resp = node.px_commitments(from).map_err(WalletError::Node)?;
            if resp.from != from {
                return Err(WalletError::BadNodeData("commitment range".into()));
            }
            // Only commitments of blocks the wallet has scanned.
            let mut added = 0;
            let mut ahead = false;
            for (h, c) in resp.commitments {
                if h > synced {
                    ahead = true;
                    break;
                }
                digest_from_hex(&c)?;
                self.commitments.push((h, c));
                added += 1;
            }
            let complete = self.commitments.len() as u64 == resp.total;
            if added == 0 || ahead || complete {
                if complete && resp.height == synced {
                    let root = digest_hex(&self.tree()?.root());
                    if root != resp.root {
                        return Err(WalletError::BadNodeData("PX tree root differs".into()));
                    }
                }
                break;
            }
        }
        for r in &mut self.records {
            if r.position.is_none() {
                r.position = self
                    .commitments
                    .iter()
                    .position(|(_, c)| *c == r.commitment)
                    .map(|p| p as u64);
            }
        }
        Ok(())
    }

    pub fn tree(&self) -> Result<Tree, WalletError> {
        self.tree_at(u64::MAX)
    }

    /// The tree as of the end of block `height`.
    pub fn tree_at(&self, height: u64) -> Result<Tree, WalletError> {
        let mut perm = HostPerm::new();
        let mut t = Tree::new(&mut perm);
        for (_, c) in self.commitments.iter().filter(|(h, _)| *h <= height) {
            t.append(&mut perm, digest_from_hex(c)?)
                .map_err(|_| WalletError::BadNodeData("tree full".into()))?;
        }
        Ok(t)
    }

    fn spendable(r: &StoredRecord) -> bool {
        r.spent_height.is_none() && !r.pending && r.position.is_some()
    }

    fn spendable_at(r: &StoredRecord, anchor: u64) -> bool {
        Self::spendable(r) && r.height <= anchor
    }

    /// `(total unspent, spendable now)` for a wallet synced to `synced`
    /// (spendable: confirmed at or below the canonical anchor height).
    pub fn balance(&self, synced: u64) -> (u64, u64) {
        let anchor = anchor_height(synced);
        let total = self
            .records
            .iter()
            .filter(|r| r.spent_height.is_none())
            .map(|r| r.value)
            .sum();
        let spendable = self
            .records
            .iter()
            .filter(|r| Self::spendable_at(r, anchor))
            .map(|r| r.value)
            .sum();
        (total, spendable)
    }

    /// Up to two records covering `needed` (the kernel spends two), all
    /// inside the tree as of the `anchor` height.
    pub fn select(&self, needed: u64, anchor: u64) -> Result<Vec<usize>, WalletError> {
        let mut idx: Vec<usize> = (0..self.records.len())
            .filter(|&i| Self::spendable_at(&self.records[i], anchor))
            .collect();
        idx.sort_by_key(|&i| self.records[i].value);
        if let Some(&i) = idx.iter().find(|&&i| self.records[i].value >= needed) {
            return Ok(vec![i]);
        }
        let n = idx.len();
        for a in 0..n {
            for b in a + 1..n {
                let (x, y) = (idx[a], idx[b]);
                if self.records[x].value as u128 + self.records[y].value as u128 >= needed as u128 {
                    return Ok(vec![x, y]);
                }
            }
        }
        let available = self
            .records
            .iter()
            .filter(|r| Self::spendable_at(r, anchor))
            .map(|r| r.value)
            .sum();
        Err(WalletError::InsufficientFunds { available, needed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(height: u64, value: u64, position: Option<u64>) -> StoredRecord {
        StoredRecord {
            index: 0,
            height,
            commitment: format!("{height:064x}"),
            position,
            value,
            data: String::new(),
            rho: String::new(),
            rcm: String::new(),
            nullifier: format!("{:064x}", height + 1_000),
            spent_height: None,
            pending: false,
            pending_height: 0,
        }
    }

    #[test]
    fn the_anchor_is_the_last_multiple_of_the_interval() {
        assert_eq!(anchor_height(0), 0);
        assert_eq!(anchor_height(15), 0);
        assert_eq!(anchor_height(16), 16);
        assert_eq!(anchor_height(47), 32);
        // Two wallets synced at different heights in one window share the anchor.
        assert_eq!(anchor_height(33), anchor_height(47));
    }

    #[test]
    fn only_records_under_the_anchor_are_spendable() {
        let mut s = PxStore::default();
        s.records.push(record(10, 5, Some(0))); // under anchor 16
        s.records.push(record(20, 7, Some(1))); // above anchor 16 at height 25
        s.records.push(record(12, 9, None)); // position not yet resolved
        assert_eq!(s.balance(25), (21, 5));
        assert_eq!(s.select(5, anchor_height(25)).unwrap(), vec![0]);
        assert!(matches!(
            s.select(6, anchor_height(25)),
            Err(WalletError::InsufficientFunds {
                available: 5,
                needed: 6
            })
        ));
        // At height 32 the second record is under the anchor too.
        assert_eq!(s.balance(32), (21, 12));
        assert_eq!(s.select(12, 32).unwrap(), vec![0, 1]);
        // Pending and spent records are never selected.
        s.records[0].pending = true;
        s.records[1].spent_height = Some(30);
        assert_eq!(s.balance(32), (14, 0));
    }

    #[test]
    fn selection_prefers_one_record_then_the_smallest_pair() {
        let mut s = PxStore::default();
        for (i, v) in [3u64, 10, 4, 6].into_iter().enumerate() {
            s.records.push(record(1 + i as u64, v, Some(i as u64)));
        }
        assert_eq!(
            s.select(8, 16).unwrap(),
            vec![1],
            "smallest single record that covers it"
        );
        // Nothing single covers 12: the first pair (in ascending value order) that does.
        let pick = s.select(12, 16).unwrap();
        assert_eq!(pick.len(), 2);
        assert!(pick.iter().map(|&i| s.records[i].value).sum::<u64>() >= 12);
        // More than two records' worth is refused (the kernel spends two).
        assert!(s.select(17, 16).is_err());
    }

    #[test]
    fn rewind_forgets_records_spends_and_commitments_above_the_height() {
        let mut s = PxStore::default();
        s.records.push(record(10, 5, Some(0)));
        s.records.push(record(20, 7, Some(1)));
        s.records[0].spent_height = Some(21);
        s.commitments = vec![(10, "a".into()), (20, "b".into()), (21, "c".into())];
        s.rewind(15);
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].spent_height, None, "the spend at 21 is undone");
        assert_eq!(s.commitments, vec![(10, "a".to_string())]);
    }
}
