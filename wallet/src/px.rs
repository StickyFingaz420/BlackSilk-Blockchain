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
//!
//! **Contracts** (docs/px.md §13). Deploys are public. The wallet downloads
//! the complete, ordered list of registrations (`/px/contracts`), like every
//! other wallet, so it knows contracts deployed before its restore height too,
//! and the node learns nothing about which contracts it uses. Contract
//! records are kept apart from the wallet's own funds: they are spent only
//! with a function of their contract, never selected to pay, and never
//! counted in the balance. The wallet learns a contract record in one of
//! three ways:
//! - **received:** its creator addressed the record's ciphertext to one of
//!   this wallet's PX addresses;
//! - **created:** this wallet built the transaction that creates it;
//! - **imported:** another holder shared the opening off chain
//!   (`blacksilk_px::share`).
//!
//! Created and imported records are confirmed by finding their commitment in
//! the chain's commitment list; received ones by the block they arrive in.

use crate::node::NodeApi;
use crate::wallet::WalletError;
use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::Account;
use blacksilk_px_core::record::{contract_nullifier, nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use blacksilk_tx::px::digest_bytes;
use blacksilk_tx::types::Transaction;
use blacksilk_zkvm::air::trace::Budget;
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

pub fn digest_hex(d: &Digest) -> String {
    hex::encode(digest_bytes(d))
}

pub fn digest_from_hex(s: &str) -> Result<Digest, WalletError> {
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

/// A program registered by a deploy: its id (hex) and row budget.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownProgram {
    pub id: String,
    /// `cycles, keys, add, bit, lt, shift, mul, poseidon`.
    pub budget: [usize; 8],
}

impl KnownProgram {
    pub fn budget(&self) -> Budget {
        let [cycles, keys, add, bit, lt, shift, mul, poseidon] = self.budget;
        Budget {
            cycles,
            keys,
            add,
            bit,
            lt,
            shift,
            mul,
            poseidon,
        }
    }
}

/// A deployed contract, from the chain's registration list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownContract {
    pub id: String,
    pub height: u64,
    pub programs: Vec<KnownProgram>,
}

/// How the wallet learned a contract record.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordSource {
    /// Its ciphertext was addressed to this PX address index.
    Received { index: u32 },
    /// This wallet created it.
    Created,
    /// Shared with this wallet off chain.
    Imported,
}

/// A contract record whose opening the wallet holds (docs/px.md §13).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractRecord {
    pub contract: String,
    pub commitment: String,
    pub value: u64,
    pub data: String,
    pub rho: String,
    pub rcm: String,
    /// The contract nullifier (`contract_nullifier`).
    pub nullifier: String,
    /// Height of the block that created it; `None` until seen on chain.
    pub height: Option<u64>,
    pub position: Option<u64>,
    pub spent_height: Option<u64>,
    /// Consumed by a submitted, unconfirmed transaction.
    pub pending: bool,
    pub pending_height: u64,
    pub source: RecordSource,
}

impl ContractRecord {
    pub fn new(record: &Record, cm: &Digest, source: RecordSource, height: Option<u64>) -> Self {
        let nf = contract_nullifier(&mut HostPerm::new(), &record.contract, &record.rcm, cm);
        ContractRecord {
            contract: digest_hex(&record.contract),
            commitment: digest_hex(cm),
            value: record.value,
            data: digest_hex(&record.data),
            rho: digest_hex(&record.rho),
            rcm: digest_hex(&record.rcm),
            nullifier: digest_hex(&nf),
            height,
            position: None,
            spent_height: None,
            pending: false,
            pending_height: 0,
            source,
        }
    }

    pub fn record(&self) -> Result<Record, WalletError> {
        Ok(Record {
            owner: ZERO_DIGEST,
            contract: digest_from_hex(&self.contract)?,
            asset: ZERO_DIGEST,
            value: self.value,
            data: digest_from_hex(&self.data)?,
            rho: digest_from_hex(&self.rho)?,
            rcm: digest_from_hex(&self.rcm)?,
        })
    }

    /// Unspent, not pending, and in the tree at or below the `anchor` height.
    pub fn spendable_at(&self, anchor: u64) -> bool {
        self.spent_height.is_none()
            && !self.pending
            && self.position.is_some()
            && self.height.is_some_and(|h| h <= anchor)
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
    /// Every contract deployed on chain.
    #[serde(default)]
    pub contracts: Vec<KnownContract>,
    /// Contract records whose openings the wallet holds.
    #[serde(default)]
    pub contract_records: Vec<ContractRecord>,
}

impl PxStore {
    /// Downloads new entries of the chain's registration list, up to the
    /// wallet's scanned height. Like the commitment list, the whole list is
    /// fetched in order, so the node learns nothing about the wallet.
    pub fn sync_contracts(&mut self, node: &dyn NodeApi, synced: u64) -> Result<(), WalletError> {
        loop {
            let from = self.contracts.len() as u64;
            let resp = node.px_contracts(from).map_err(WalletError::Node)?;
            if resp.from != from {
                return Err(WalletError::BadNodeData("contract range".into()));
            }
            let mut added = 0;
            for c in resp.contracts {
                if c.height > synced {
                    return Ok(());
                }
                digest_from_hex(&c.id)?;
                self.contracts.push(KnownContract {
                    id: c.id,
                    height: c.height,
                    programs: c
                        .programs
                        .into_iter()
                        .map(|p| KnownProgram {
                            id: p.id,
                            budget: p.budget,
                        })
                        .collect(),
                });
                added += 1;
            }
            if added == 0 || self.contracts.len() as u64 >= resp.total {
                return Ok(());
            }
        }
    }

    /// The budget of `program` if it is registered to `contract`.
    pub fn registered(&self, contract: &Digest, program: &[u8; 32]) -> Option<Budget> {
        let id = digest_hex(contract);
        let pid = hex::encode(program);
        self.contracts
            .iter()
            .find(|c| c.id == id)?
            .programs
            .iter()
            .find(|p| p.id == pid)
            .map(KnownProgram::budget)
    }

    /// Adds a contract record unless it is already known; a known one that
    /// was not yet confirmed takes `height`.
    pub fn add_contract_record(
        &mut self,
        record: &Record,
        cm: &Digest,
        source: RecordSource,
        height: Option<u64>,
    ) {
        let hex_cm = digest_hex(cm);
        if let Some(r) = self
            .contract_records
            .iter_mut()
            .find(|r| r.commitment == hex_cm)
        {
            if r.height.is_none() {
                r.height = height;
            }
            return;
        }
        self.contract_records
            .push(ContractRecord::new(record, cm, source, height));
    }

    /// The contract record with commitment `cm`.
    pub fn contract_record(&self, cm: &Digest) -> Option<usize> {
        let hex_cm = digest_hex(cm);
        self.contract_records
            .iter()
            .position(|r| r.commitment == hex_cm)
    }

    /// Records the PX outputs paid to `account`, the contract records
    /// addressed to it, and the spends of both, in a block at `height`.
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
            for r in &mut self.contract_records {
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
                    if rec.contract != ZERO_DIGEST {
                        // A contract record addressed to this wallet.
                        self.add_contract_record(
                            &rec,
                            cm,
                            RecordSource::Received { index },
                            Some(height),
                        );
                        self.issued = self.issued.max(index);
                        break;
                    }
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

    /// Forgets everything learned above `height`. Contract records the
    /// wallet created or imported are kept (it still holds their openings),
    /// as unconfirmed.
    pub fn rewind(&mut self, height: u64) {
        self.records.retain(|r| r.height <= height);
        for r in &mut self.records {
            if r.spent_height.is_some_and(|h| h > height) {
                r.spent_height = None;
            }
        }
        self.contracts.retain(|c| c.height <= height);
        self.contract_records.retain(|r| {
            !(matches!(r.source, RecordSource::Received { .. })
                && r.height.is_some_and(|h| h > height))
        });
        for r in &mut self.contract_records {
            if r.height.is_some_and(|h| h > height) {
                r.height = None;
                r.position = None;
            }
            if r.spent_height.is_some_and(|h| h > height) {
                r.spent_height = None;
            }
        }
        self.commitments.retain(|(h, _)| *h <= height);
    }

    /// Forgets unconfirmed spends. Contract-record openings are kept.
    pub fn clear_pending(&mut self) {
        for r in &mut self.records {
            r.pending = false;
        }
        for r in &mut self.contract_records {
            r.pending = false;
        }
        // Openings are never deleted, even of records whose transaction seems
        // never to have confirmed: it may have been relayed, and without the
        // opening its funds could not be recovered (review F14).
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
        // Contract records: a created or imported one is confirmed here, by
        // its commitment in the chain's list.
        for r in &mut self.contract_records {
            if r.position.is_none() {
                if let Some((p, (h, _))) = self
                    .commitments
                    .iter()
                    .enumerate()
                    .find(|(_, (_, c))| *c == r.commitment)
                {
                    r.position = Some(p as u64);
                    r.height.get_or_insert(*h);
                }
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

    fn contract_rec(source: RecordSource, height: Option<u64>, n: u64) -> ContractRecord {
        ContractRecord {
            contract: format!("{:064x}", 7),
            commitment: format!("{n:064x}"),
            value: 100 + n,
            data: String::new(),
            rho: String::new(),
            rcm: String::new(),
            nullifier: format!("{:064x}", n + 5_000),
            height,
            position: height.map(|h| h * 2),
            spent_height: None,
            pending: false,
            pending_height: 0,
            source,
        }
    }

    fn known(height: u64) -> KnownContract {
        KnownContract {
            id: format!("{height:064x}"),
            height,
            programs: vec![],
        }
    }

    #[test]
    fn a_rewind_keeps_the_contract_records_the_wallet_holds_openings_for() {
        let mut s = PxStore {
            contracts: vec![known(5), known(25)],
            contract_records: vec![
                contract_rec(RecordSource::Received { index: 0 }, Some(20), 1),
                contract_rec(RecordSource::Created, Some(20), 2),
                contract_rec(RecordSource::Imported, Some(10), 3),
                contract_rec(RecordSource::Created, None, 4),
            ],
            ..Default::default()
        };
        s.contract_records[2].spent_height = Some(18);
        s.rewind(15);
        // A received record leaves with its block (rescanning finds it again).
        let cms: Vec<&str> = s
            .contract_records
            .iter()
            .map(|r| &r.commitment[60..])
            .collect();
        assert_eq!(cms, ["0002", "0003", "0004"]);
        // A created one stays, unconfirmed, with no position.
        assert_eq!(
            (s.contract_records[0].height, s.contract_records[0].position),
            (None, None)
        );
        // An older one keeps its confirmation; a spend above the fork is undone.
        assert_eq!(s.contract_records[1].height, Some(10));
        assert_eq!(s.contract_records[1].spent_height, None);
        // Deploys above the fork are forgotten.
        assert_eq!(s.contracts, vec![known(5)]);
    }

    #[test]
    fn clearing_pending_keeps_every_contract_record_opening() {
        let mut s = PxStore {
            contract_records: vec![
                contract_rec(RecordSource::Created, None, 1),
                contract_rec(RecordSource::Imported, None, 2),
                contract_rec(RecordSource::Created, Some(3), 3),
            ],
            ..Default::default()
        };
        s.contract_records[2].pending = true;
        s.clear_pending();
        let cms: Vec<&str> = s
            .contract_records
            .iter()
            .map(|r| &r.commitment[60..])
            .collect();
        assert_eq!(cms, ["0001", "0002", "0003"]);
        assert!(s.contract_records.iter().all(|r| !r.pending));
    }

    #[test]
    fn contract_records_are_never_counted_or_selected_as_funds() {
        let s = PxStore {
            contract_records: vec![contract_rec(RecordSource::Created, Some(1), 1)],
            ..Default::default()
        };
        assert_eq!(s.balance(32), (0, 0));
        assert!(s.select(1, 32).is_err());
        assert!(s.contract_records[0].spendable_at(16));
        assert!(!s.contract_records[0].spendable_at(0), "above the anchor");
    }
}
