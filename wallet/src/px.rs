//! The wallet's private-execution (PX) state (docs/px.md §11.4): received
//! records, spends, and the commitment tree.
//!
//! **Privacy of scanning.** The wallet learns about its records only from
//! data every wallet downloads alike: whole blocks (records, nullifiers) and
//! the complete, ordered list of commitments (`/px/commitments`, fetched in
//! bulk). It never asks the node about a specific record, position or
//! nullifier, so the node cannot tell which records are the wallet's.
//!
//! **Keys.** PX keys derive from the same 27-word seed (format v1) as the v1 keys
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

/// PX addresses scanned beyond the highest issued index. The window grows as
/// records are found (a record at index `i` raises `issued` to `i`), so a
/// restored wallet finds addresses up to this far beyond the last one paid.
pub const PX_LOOKAHEAD: u32 = 20;

/// PX addresses handed out beyond the highest one that has received a record,
/// without an explicit override (docs/reviews/wallet-review.md M-1). Every
/// scanned address costs one scalar multiplication per PX output on chain.
pub const PX_GAP_LIMIT: u32 = 1_000;

/// Absolute ceiling above the highest PX address that has received a record,
/// even with the override. Wallet files holding more (written by older
/// versions) are clamped when loaded.
pub const PX_MAX_INDEX_AHEAD: u32 = 2_000;

/// Delivery keys and owner tags of PX addresses `0..n`, derived on first use
/// and kept in memory only, so scanning does not re-derive an ML-KEM key pair
/// per address and per output. Never persisted; the secret parts are
/// zeroized on drop (`DeliveryKeys`).
#[derive(Default)]
pub struct AddressKeys {
    keys: Vec<(delivery::DeliveryKeys, Digest)>,
}

impl AddressKeys {
    /// The keys and owner tag of address `index` of `account`. The cache must
    /// be used with one account only.
    pub fn get(&mut self, account: &Account, index: u32) -> (&delivery::DeliveryKeys, &Digest) {
        while self.keys.len() <= index as usize {
            let i = self.keys.len() as u32;
            self.keys.push((account.delivery_keys(i), account.owner(i)));
        }
        let (k, o) = &self.keys[index as usize];
        (k, o)
    }
}

/// Wallets anchor spends at a height that is a multiple of this, so every
/// wallet transacting in the same window uses the same anchor and the anchor
/// does not reveal when a wallet last synced.
pub const ANCHOR_INTERVAL: u64 = 16;

/// Wallet policy (dossier 21 F21-3; decisions, Agent 21): the anchor lies at
/// least this many blocks below the wallet's synced tip, for every record,
/// so a reorganization of up to this depth never removes the root a pending
/// spend proves against. Without it the anchor was the tip itself at every
/// multiple of [`ANCHOR_INTERVAL`]: a one-block reorganization made the
/// spend `PxUnknownAnchor`, and rebuilding it republished the same
/// nullifiers, linking both attempts (R5-12). ZIP 315 anchors at the same
/// depth (three trusted confirmations) for the same reason. Every wallet
/// must use the same value: the anchor is visible in each transaction.
pub const ANCHOR_MIN_DEPTH: u64 = 3;

/// The canonical anchor height for a wallet synced to `synced`: the highest
/// multiple of [`ANCHOR_INTERVAL`] at least [`ANCHOR_MIN_DEPTH`] blocks
/// below it (genesis while the chain is shorter). It lies 3 to 18 blocks
/// below the tip, well inside the 100-block root window, so a transaction
/// stays valid for at least 81 blocks after it is built. Records become
/// spendable once the anchor height reaches them, within
/// `ANCHOR_MIN_DEPTH + ANCHOR_INTERVAL - 1` blocks of their confirmation.
pub fn anchor_height(synced: u64) -> u64 {
    let deep = synced.saturating_sub(ANCHOR_MIN_DEPTH);
    deep - deep % ANCHOR_INTERVAL
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
    /// For a vault record this wallet locked: the secret (hex), stored in the
    /// encrypted wallet file before the lock is sent, so it survives a
    /// submission whose outcome is uncertain (review R11-W1). The record
    /// holds only `Hk(LOCK, secret)`; without the secret its value is locked
    /// for good (the demonstration vault has no refund).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
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
            secret: None,
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

    /// The budget to call the reference vault under `contract` with, if the
    /// contract is a vault the wallet can safely use (docs/px.md §13.4):
    /// - **its registered program set is exactly the vault.** A contract
    ///   record's nullifier depends only on its opening, and any program
    ///   registered to the contract can approve spending it. A contract that
    ///   registers the vault next to another program lets that program take
    ///   the vault's records without the secret, so a claimer who deploys
    ///   `{vault, backdoor}` and asks to be paid through it could take the
    ///   funds without the secret (review P-1);
    /// - **its budget is exactly `vault::BUDGET`.** A budget that fits LOCK but
    ///   not CLAIM would lock funds for good; any other budget would also
    ///   make its proofs stand out (review P-2).
    pub fn vault_budget(&self, contract: &Digest) -> Result<Budget, WalletError> {
        let id = digest_hex(contract);
        let c = self.contracts.iter().find(|c| c.id == id).ok_or_else(|| {
            WalletError::Contract(
                "unknown contract (wrong id, or its deploy is not yet confirmed)".into(),
            )
        })?;
        vault_check(c)
    }
}

/// Whether `c` is a vault contract the wallet can use: the vault program
/// alone, with the reference budget (`PxStore::vault_budget`).
pub fn vault_check(c: &KnownContract) -> Result<Budget, WalletError> {
    let vault_id = hex::encode(blacksilk_px::vault::program().id());
    let Some(p) = c.programs.iter().find(|p| p.id == vault_id) else {
        return Err(WalletError::Contract(
            "the vault program is not registered to this contract".into(),
        ));
    };
    if c.programs.len() != 1 {
        return Err(WalletError::Contract(format!(
            "this contract registers {} other program(s) besides the vault; any of them can \
             spend the contract's records without the secret, so the wallet refuses vault \
             operations on it (docs/px.md §13.4)",
            c.programs.len() - 1
        )));
    }
    let budget = p.budget();
    if budget != blacksilk_px::vault::BUDGET {
        return Err(WalletError::Contract(
            "this contract registers the vault with a non-standard budget; a budget that does \
             not cover CLAIM would lock funds for good, so the wallet refuses it"
                .into(),
        ));
    }
    Ok(budget)
}

impl PxStore {
    /// The highest PX address index that has received a record (a payment or
    /// a contract record addressed to it), if any.
    pub fn used_index(&self) -> Option<u32> {
        let paid = self.records.iter().map(|r| r.index);
        let received = self.contract_records.iter().filter_map(|r| match r.source {
            RecordSource::Received { index } => Some(index),
            _ => None,
        });
        paid.chain(received).max()
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

    /// Stores the vault secret of the known contract record `cm`.
    pub fn set_secret(&mut self, cm: &Digest, secret: &Digest) {
        if let Some(k) = self.contract_record(cm) {
            self.contract_records[k].secret = Some(digest_hex(secret));
        }
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
    pub fn apply_block(
        &mut self,
        keys: &mut AddressKeys,
        account: &Account,
        txs: &[Transaction],
        height: u64,
    ) {
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
                // The window is re-read for every output: a record found at
                // index `i` raises `issued`, extending it for the next one.
                for index in 0..=self.issued.saturating_add(PX_LOOKAHEAD) {
                    let (dk, owner) = keys.get(account, index);
                    let Some(rec) = delivery::open(dk, owner, ct, cm, &rho) else {
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
    fn the_anchor_is_the_last_multiple_of_the_interval_three_blocks_deep() {
        assert_eq!(anchor_height(0), 0);
        assert_eq!(anchor_height(2), 0);
        assert_eq!(anchor_height(15), 0);
        // The tip itself is never the anchor.
        assert_eq!(anchor_height(16), 0);
        assert_eq!(anchor_height(18), 0);
        assert_eq!(anchor_height(19), 16);
        assert_eq!(anchor_height(47), 32);
        // Two wallets synced at different heights in one window share the anchor.
        assert_eq!(anchor_height(35), anchor_height(50));
        for synced in 0..=1_000u64 {
            let a = anchor_height(synced);
            assert_eq!(a % ANCHOR_INTERVAL, 0);
            if synced >= ANCHOR_MIN_DEPTH {
                assert!(a + ANCHOR_MIN_DEPTH <= synced, "{synced}: {a} too shallow");
                assert!(
                    synced - a < ANCHOR_MIN_DEPTH + ANCHOR_INTERVAL,
                    "{synced}: {a}"
                );
            } else {
                assert_eq!(a, 0);
            }
        }
    }

    /// Dossier 21 F21-3 (decisions, Agent 21): a reorganization of up to
    /// three blocks never changes the root a wallet anchors to. Before the
    /// minimum depth the anchor was the tip itself at every multiple of 16,
    /// so a one-block reorganization that replaced the tip's commitments
    /// invalidated a fresh spend (`PxUnknownAnchor`), and rebuilding it
    /// republished the same nullifiers (R5-12). The depth is a literal here
    /// so that the test states the policy, not the constant.
    #[test]
    fn a_reorganization_of_up_to_three_blocks_keeps_the_anchor_root() {
        let commitment = |branch: u64, height: u64| format!("{:064x}", branch << 32 | height);
        for synced in 0..=100u64 {
            let mut s = PxStore::default();
            s.commitments = (1..=synced).map(|h| (h, commitment(1, h))).collect();
            let anchor = anchor_height(synced);
            let before = s.tree_at(anchor).unwrap().root();
            for depth in 1..=3u64.min(synced) {
                let mut other = PxStore {
                    commitments: s.commitments.clone(),
                    ..PxStore::default()
                };
                other.rewind(synced - depth);
                other
                    .commitments
                    .extend((synced - depth + 1..=synced).map(|h| (h, commitment(2, h))));
                assert_eq!(
                    other.tree_at(anchor).unwrap().root(),
                    before,
                    "synced {synced}: a {depth}-block reorganization moved anchor {anchor}"
                );
            }
        }
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
        // Synced to 32 the anchor is still 16 (three blocks deep); at 35 it
        // is 32, and the second record is under it too.
        assert_eq!(s.balance(32), (21, 5));
        assert_eq!(s.balance(35), (21, 12));
        assert_eq!(s.select(12, anchor_height(35)).unwrap(), vec![0, 1]);
        // Pending and spent records are never selected.
        s.records[0].pending = true;
        s.records[1].spent_height = Some(30);
        assert_eq!(s.balance(35), (14, 0));
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
            secret: None,
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

    fn vault_contract(programs: Vec<KnownProgram>) -> KnownContract {
        KnownContract {
            id: digest_hex(&[9, 0, 0, 0, 0, 0, 0, 0]),
            height: 1,
            programs,
        }
    }

    fn vault_program(budget: Budget) -> KnownProgram {
        let b = budget;
        KnownProgram {
            id: hex::encode(blacksilk_px::vault::program().id()),
            budget: [
                b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
            ],
        }
    }

    #[test]
    fn vault_operations_need_the_vault_alone_with_the_reference_budget() {
        use blacksilk_px::vault::BUDGET;
        let contract = [9, 0, 0, 0, 0, 0, 0, 0];
        let other = KnownProgram {
            id: "ab".repeat(32),
            budget: [1_000; 8],
        };
        let mut s = PxStore::default();
        // Unknown contract.
        assert!(s.vault_budget(&contract).is_err());
        // The vault alone, with the reference budget: accepted.
        s.contracts = vec![vault_contract(vec![vault_program(BUDGET)])];
        assert_eq!(s.vault_budget(&contract).unwrap(), BUDGET);
        // P-1: the vault next to another program (either order) is refused:
        // that program could spend the vault's records without the secret.
        for programs in [
            vec![vault_program(BUDGET), other.clone()],
            vec![other.clone(), vault_program(BUDGET)],
        ] {
            s.contracts = vec![vault_contract(programs)];
            let e = s.vault_budget(&contract).unwrap_err().to_string();
            assert!(e.contains("other program"), "{e}");
        }
        // No vault at all.
        s.contracts = vec![vault_contract(vec![other])];
        assert!(s
            .vault_budget(&contract)
            .unwrap_err()
            .to_string()
            .contains("not registered"));
        // P-2: any budget other than the reference one is refused, smaller
        // (CLAIM might not fit: funds locked for good) or larger (fingerprint).
        for budget in [
            Budget {
                cycles: BUDGET.cycles - 1,
                ..BUDGET
            },
            Budget {
                poseidon: BUDGET.poseidon + 1,
                ..BUDGET
            },
        ] {
            s.contracts = vec![vault_contract(vec![vault_program(budget)])];
            let e = s.vault_budget(&contract).unwrap_err().to_string();
            assert!(e.contains("non-standard budget"), "{e}");
        }
    }

    #[test]
    fn the_used_index_counts_payments_and_contract_records_received() {
        let mut s = PxStore::default();
        assert_eq!(s.used_index(), None);
        s.records.push(record(1, 1, None));
        s.records[0].index = 7;
        assert_eq!(s.used_index(), Some(7));
        // Created and imported records say nothing about the wallet's addresses.
        s.contract_records
            .push(contract_rec(RecordSource::Created, None, 1));
        s.contract_records
            .push(contract_rec(RecordSource::Imported, None, 2));
        assert_eq!(s.used_index(), Some(7));
        s.contract_records
            .push(contract_rec(RecordSource::Received { index: 12 }, None, 3));
        assert_eq!(s.used_index(), Some(12));
    }

    #[test]
    fn cached_address_keys_match_fresh_derivation() {
        let account = Account::from_seed(&[5; 32]);
        let mut cache = AddressKeys::default();
        for i in [3u32, 0, 7, 3] {
            let (dk, owner) = cache.get(&account, i);
            assert_eq!(*owner, account.owner(i));
            assert_eq!(dk.address(*owner), account.address(i));
        }
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
