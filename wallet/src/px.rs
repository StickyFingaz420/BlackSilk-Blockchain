//! The wallet's private-execution (PX) state (docs/px.md §11.4): received
//! records, spends, and the commitment tree.
//!
//! **Privacy of scanning.** The wallet learns about its records only from
//! data every wallet downloads alike: whole blocks (records, nullifiers,
//! commitments) and, below its restore height or for an imported record, the
//! complete, ordered list of commitments (`/px/commitments`, fetched in
//! bulk). It never asks the node about a specific record, position or
//! nullifier, so the node cannot tell which records are the wallet's.
//!
//! **Keys.** PX keys derive from the same 27-word seed (format v1) as the v1 keys
//! (domain-separated, `blacksilk_px::wallet::Account`).
//!
//! **Tree** (`crate::tree`, dossier 39 W1). The wallet builds the commitment
//! tree itself from the blocks it scans, keeps the consensus root window,
//! and refuses a block with a PX transaction whose anchor is not in it. It
//! keeps an incremental witness for every leaf it may spend, and anchors its
//! own spends at the root it computed: a node cannot choose the anchor
//! (F39-1).
//!
//! **Contracts** (docs/px.md §13). Deploys are public. The wallet derives
//! every registration from the deploy transactions themselves, as consensus
//! records them (contract id, and per program its id, budget, call ABI and
//! output words; [`deployed`]): from the blocks it scans, and below its
//! restore height from the blocks the node's registration list
//! (`/px/contracts`) names, fetched whole and checked against the header
//! chain (`Wallet::sync`). The node's list only says where deploys are; a
//! registration it misstates is refused, and the node learns nothing about
//! which contracts the wallet uses. Contract
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
//! Received and created records are confirmed by the block their commitment
//! appears in; an imported record already on chain by one bulk download of
//! the commitment list, checked against the wallet's own root.

use crate::node::NodeApi;
use crate::tree::{TreeError, WalletTree};
use crate::wallet::WalletError;
use blacksilk_px::delivery;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::state::ROOT_WINDOW;
use blacksilk_px::wallet::Account;
use blacksilk_px_core::call::ABI_VERSION;
use blacksilk_px_core::kernel::TREE_DEPTH;
use blacksilk_px_core::record::{contract_nullifier, nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use blacksilk_rpc as rpc;
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

/// A tree error as a wallet error: inconsistent node data, or a rescan.
fn tree_error(e: TreeError) -> WalletError {
    WalletError::BadNodeData(format!("PX tree: {e}"))
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
    /// Tree position (from the wallet's own tree, when the block is scanned).
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
    /// For output 1 of its transaction with nonzero data (the change of a
    /// vault lock with a timeout carries the claim lock there): the
    /// commitment (hex) and position of output 0, which may be the vault
    /// record this wallet locked (`Wallet::recover_vault_locks`). The wallet
    /// keeps a witness for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sibling: Option<(String, u64)>,
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

/// A program registered by a deploy: its id (hex), row budget, call ABI and
/// output words (`blacksilk_tx::px::Registration`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownProgram {
    pub id: String,
    /// `cycles, keys, add, bit, lt, shift, mul, poseidon`.
    pub budget: [usize; 8],
    #[serde(default)]
    pub abi: u32,
    /// The exact number of public output words every call publishes.
    #[serde(default)]
    pub out_words: u32,
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

/// A deployed contract, derived from its deploy transaction ([`deployed`]).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownContract {
    pub id: String,
    pub height: u64,
    pub programs: Vec<KnownProgram>,
    /// Derived from the deploy itself. `false` only in wallet files written
    /// when registrations came from the node's list: such a file rescans
    /// (`Wallet::from_json`).
    #[serde(default)]
    pub from_deploy: bool,
}

/// The registrations of the deploys among `txs` (block `height`), in block
/// order, exactly as consensus records them (`MemoryChain::apply_block`):
/// the contract id (`PxDeploy::contract_id`, which binds the key image, the
/// salt and every program's ELF, budget, ABI and output words) and each
/// program's id. A program that does not load cannot be in a valid block.
pub fn deployed(txs: &[Transaction], height: u64) -> Result<Vec<KnownContract>, WalletError> {
    txs.iter()
        .filter_map(|t| match t {
            Transaction::PxDeploy(d) => Some(d),
            _ => None,
        })
        .map(|d| {
            let programs = d
                .programs
                .iter()
                .map(|r| {
                    let program = blacksilk_zkvm::Program::from_elf(&r.elf).map_err(|_| {
                        WalletError::BadNodeData(format!(
                            "a program deployed in block {height} does not load"
                        ))
                    })?;
                    let b = r.budget;
                    Ok(KnownProgram {
                        id: hex::encode(program.id()),
                        budget: [
                            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                        ],
                        abi: r.abi,
                        out_words: r.out_words,
                    })
                })
                .collect::<Result<_, WalletError>>()?;
            Ok(KnownContract {
                id: digest_hex(&d.contract_id()),
                height,
                programs,
                from_deploy: true,
            })
        })
        .collect()
}

/// Whether the node's registration entries for one block say exactly what
/// its deploys register (ids, program ids and budgets, in order; the list
/// has no ABI or output words).
pub fn listed_as(listed: &[&rpc::PxContractEntry], derived: &[KnownContract]) -> bool {
    listed.len() == derived.len()
        && listed.iter().zip(derived).all(|(l, d)| {
            l.id == d.id
                && l.programs.len() == d.programs.len()
                && l.programs
                    .iter()
                    .zip(&d.programs)
                    .all(|(lp, dp)| lp.id == dp.id && lp.budget == dp.budget)
        })
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
    /// Imported and not yet found: the next sync looks for it once in the
    /// chain's whole commitment list (it may have been created before this
    /// wallet scanned), and later blocks find it otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lookup: bool,
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
            lookup: false,
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
    /// The wallet's own commitment tree (`crate::tree`), up to its synced
    /// height; `None` until the first sync builds it (or after a rewind
    /// below the restore height: it is rebuilt then).
    #[serde(default)]
    pub tree: Option<WalletTree>,
    /// Wallet files written before the wallet built its own tree kept the
    /// node's commitment list here. Read only to notice such a file: its
    /// PX state is rebuilt by a rescan (`Wallet::from_json`, `Wallet::sync`).
    #[serde(default, rename = "commitments", skip_serializing)]
    pub legacy_commitments: Option<Vec<(u64, String)>>,
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
    /// The node's registration list up to block `base` (`/px/contracts`,
    /// fetched whole and in order, like the commitment list): where the
    /// deploys below the restore height are. Its entries are claims, checked
    /// against those blocks by the caller (`Wallet::sync`).
    pub fn fetch_contract_list(
        node: &dyn NodeApi,
        base: u64,
    ) -> Result<Vec<rpc::PxContractEntry>, WalletError> {
        let mut list: Vec<rpc::PxContractEntry> = Vec::new();
        loop {
            let from = list.len() as u64;
            let resp = node.px_contracts(from).map_err(WalletError::Node)?;
            if resp.from != from {
                return Err(WalletError::BadNodeData("contract range".into()));
            }
            let n = resp.contracts.len();
            for c in resp.contracts {
                if c.height > base {
                    return Ok(list);
                }
                if c.height == 0 || list.last().is_some_and(|l| l.height > c.height) {
                    return Err(WalletError::BadNodeData(
                        "the contract list is out of height order".into(),
                    ));
                }
                list.push(c);
            }
            if n == 0 || list.len() as u64 >= resp.total {
                return Ok(list);
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
    let words = blacksilk_px::vault::OUT_WORDS;
    if p.abi != ABI_VERSION || p.out_words != words {
        return Err(WalletError::Contract(format!(
            "this contract registers the vault with call ABI {} and {} output word(s), where the \
             vault is called with ABI {ABI_VERSION} and publishes exactly {words} output word: \
             no call of it could ever be valid, so funds locked in it would be lost",
            p.abi, p.out_words
        )));
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

    /// The wallet's tree, which the first sync builds.
    fn tree_ref(&self) -> Result<&WalletTree, WalletError> {
        self.tree
            .as_ref()
            .ok_or_else(|| WalletError::Node("the wallet has not synced its PX tree yet".into()))
    }

    /// Checks the anchor of every PX transaction of block `height` against
    /// the wallet's root window, as consensus does, before anything of the
    /// block is applied. Returns whether one of them binds the backfill to
    /// the chain (`WalletTree::check_anchor`).
    fn check_block(&self, txs: &[Transaction], height: u64) -> Result<bool, WalletError> {
        let tree = self.tree_ref()?;
        if tree.height() + 1 != height {
            return Err(WalletError::BadNodeData(format!(
                "block {height} does not follow the wallet's PX tree (block {})",
                tree.height()
            )));
        }
        let mut confirms = false;
        for tx in txs {
            let Transaction::Px(t) = tx else { continue };
            match tree.check_anchor(&t.anchor) {
                Some(scanned) => confirms |= scanned,
                None => {
                    return Err(WalletError::BadNodeData(format!(
                        "block {height} holds a PX transaction whose anchor is not one of the \
                         last {ROOT_WINDOW} roots of the tree the wallet built from the chain: \
                         the node's blocks or its commitment list do not follow consensus"
                    )))
                }
            }
        }
        Ok(confirms)
    }

    /// Applies block `height` (the next after the tree's): checks every PX
    /// anchor first (`check_block`) and derives the block's registrations
    /// (`deployed`; nothing is changed on a refusal), then records the PX
    /// outputs paid to `account`, the contract records addressed to it, the
    /// spends of both and the registrations, and appends the block's
    /// commitments to the wallet's tree with a witness for every leaf the
    /// wallet may spend.
    pub fn apply_block(
        &mut self,
        keys: &mut AddressKeys,
        account: &Account,
        txs: &[Transaction],
        height: u64,
    ) -> Result<(), WalletError> {
        let confirms = self.check_block(txs, height)?;
        let contracts = deployed(txs, height)?;
        let mut tree = self.tree.take().expect("checked by check_block");
        let result = self.scan_block(&mut tree, keys, account, txs, height);
        match result {
            Ok(()) => {
                if confirms {
                    tree.confirm(height);
                }
                self.tree = Some(tree);
                self.contracts.extend(contracts);
                Ok(())
            }
            // Only a full tree fails here, which consensus never allows: the
            // tree is dropped and rebuilt by a rescan.
            Err(e) => Err(e),
        }
    }

    fn scan_block(
        &mut self,
        tree: &mut WalletTree,
        keys: &mut AddressKeys,
        account: &Account,
        txs: &[Transaction],
        height: u64,
    ) -> Result<(), WalletError> {
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
            // Both outputs are scanned before their commitments are
            // appended: a witness starts with its leaf's append.
            let first = tree.size();
            let mut witness = [false; 2];
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
                    // Output 1 with data: possibly the change of a vault lock
                    // with a timeout, whose vault record is output 0.
                    let sibling = (j == 1 && rec.data != ZERO_DIGEST)
                        .then(|| (digest_hex(&t.commitments[0]), first));
                    witness[0] |= sibling.is_some();
                    witness[j] = true;
                    self.records.push(StoredRecord {
                        index,
                        height,
                        commitment: hex_cm,
                        position: Some(first + j as u64),
                        value: rec.value,
                        data: digest_hex(&rec.data),
                        rho: digest_hex(&rec.rho),
                        rcm: digest_hex(&rec.rcm),
                        nullifier: digest_hex(&nf),
                        spent_height: None,
                        pending: false,
                        pending_height: 0,
                        sibling,
                    });
                    self.issued = self.issued.max(index);
                    break;
                }
            }
            for (j, cm) in t.commitments.iter().enumerate() {
                // A contract record held and not yet placed: received now,
                // created by this wallet, or imported.
                let hex_cm = digest_hex(cm);
                let held = self
                    .contract_records
                    .iter_mut()
                    .find(|r| r.commitment == hex_cm && r.position.is_none());
                let pos = tree.append(*cm).map_err(tree_error)?;
                debug_assert_eq!(pos, first + j as u64);
                if let Some(r) = held {
                    r.position = Some(pos);
                    r.height.get_or_insert(height);
                    r.lookup = false;
                    witness[j] = true;
                }
                if witness[j] {
                    tree.mark(pos).map_err(tree_error)?;
                }
            }
        }
        tree.end_block(height).map_err(tree_error)
    }

    /// Forgets everything learned above `height`. Contract records the
    /// wallet created or imported are kept (it still holds their openings),
    /// as unconfirmed. Returns `true` if the tree cannot be rewound that far
    /// (it is dropped): the caller rescans from the restore height.
    pub fn rewind(&mut self, height: u64) -> bool {
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
        match self.tree.as_mut().map(|t| t.rewind(height)) {
            Some(Err(_)) => {
                self.tree = None;
                true
            }
            _ => false,
        }
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

    /// Sets the state below the first block the wallet scans (block
    /// `base`): the tree from the chain's commitments up to it (`backfilled`
    /// unless the list is known exact, `crate::tree`) and the registrations
    /// derived from the deploys up to it. Replaces what was there.
    pub fn set_base(
        &mut self,
        base: u64,
        commitments: &[(u64, Digest)],
        backfilled: bool,
        contracts: Vec<KnownContract>,
    ) -> Result<(), WalletError> {
        self.tree = Some(WalletTree::new(base, commitments, backfilled).map_err(tree_error)?);
        self.contracts = contracts;
        Ok(())
    }

    /// The node's commitment list up to block `base` (`/px/commitments`,
    /// fetched whole: the backfill). Checked by the caller against the block
    /// of its last entry (`Wallet::sync`), and bound to the chain later
    /// (`crate::tree`).
    pub fn fetch_commitments(
        node: &dyn NodeApi,
        base: u64,
    ) -> Result<Vec<(u64, Digest)>, WalletError> {
        let mut list: Vec<(u64, Digest)> = Vec::new();
        loop {
            let from = list.len() as u64;
            let resp = node.px_commitments(from).map_err(WalletError::Node)?;
            if resp.from != from {
                return Err(WalletError::BadNodeData("commitment range".into()));
            }
            let n = resp.commitments.len();
            let mut done = false;
            for (h, c) in resp.commitments {
                if h > base {
                    done = true;
                    break;
                }
                list.push((h, digest_from_hex(&c)?));
            }
            if done || n == 0 || list.len() as u64 >= resp.total {
                break;
            }
        }
        Ok(list)
    }

    /// Places the imported contract records not found yet (`lookup`): one
    /// bulk download of the chain's commitment list, which must give the
    /// wallet's own root (`WalletTree::witness_from_list`), so nothing of it
    /// is trusted. A record not in it is found later by the block it
    /// confirms in.
    pub fn resolve_lookups(&mut self, node: &dyn NodeApi) -> Result<(), WalletError> {
        let wanted: Vec<usize> = (0..self.contract_records.len())
            .filter(|&i| {
                self.contract_records[i].lookup && self.contract_records[i].position.is_none()
            })
            .collect();
        if wanted.is_empty() {
            for r in &mut self.contract_records {
                r.lookup = false;
            }
            return Ok(());
        }
        let size = self.tree_ref()?.size();
        let mut list: Vec<Digest> = Vec::new();
        let mut heights: Vec<u64> = Vec::new();
        while (list.len() as u64) < size {
            let from = list.len() as u64;
            let resp = node.px_commitments(from).map_err(WalletError::Node)?;
            if resp.from != from || resp.commitments.is_empty() {
                return Err(WalletError::BadNodeData("commitment range".into()));
            }
            for (h, c) in resp.commitments {
                list.push(digest_from_hex(&c)?);
                heights.push(h);
            }
        }
        list.truncate(size as usize);
        let found: Vec<(usize, u64)> = wanted
            .iter()
            .filter_map(|&i| {
                let cm = digest_from_hex(&self.contract_records[i].commitment).ok()?;
                let p = list.iter().position(|c| *c == cm)?;
                Some((i, p as u64))
            })
            .collect();
        let tree = self.tree.as_mut().expect("checked above");
        let positions: Vec<u64> = found.iter().map(|&(_, p)| p).collect();
        tree.witness_from_list(&list, &positions)
            .map_err(tree_error)?;
        for (i, p) in found {
            // The block height: the wallet's own where it scanned the block,
            // else at most the node's (it only orders display and
            // spendability, and every path is checked against the root).
            let height = tree.height_of(p).unwrap_or_else(|| {
                let below = if p < tree.base_size() {
                    tree.base_height()
                } else {
                    tree.oldest_logged().map_or(tree.base_height(), |h| h - 1)
                };
                heights[p as usize].min(below)
            });
            let r = &mut self.contract_records[i];
            r.position = Some(p);
            r.height.get_or_insert(height);
        }
        for r in &mut self.contract_records {
            r.lookup = false;
        }
        Ok(())
    }

    /// The anchor of a PX transaction built by a wallet synced to `synced`
    /// (the canonical height, `anchor_height`) and the root there, from the
    /// wallet's own tree. Refused while that root could still be one the
    /// node chose (`WalletError::PxNotReady`):
    /// - an anchor below the restore height: the per-block roots there come
    ///   from the node's heights;
    /// - a root that holds only backfilled commitments before the backfill
    ///   is bound to the chain (`WalletTree::is_confirmed`), until the
    ///   backfill's end has left the root window: a shortened backfill then
    ///   gives a root no block accepts, never a valid root of the node's
    ///   choice.
    pub fn anchor_root(&self, synced: u64) -> Result<(u64, Digest), WalletError> {
        let tree = self.tree_ref()?;
        let anchor = anchor_height(synced);
        if tree.height() != synced {
            return Err(WalletError::BadNodeData(format!(
                "the wallet's PX tree is at block {}, not {synced}",
                tree.height()
            )));
        }
        let base = tree.base_height();
        if anchor < base {
            let from = base.div_ceil(ANCHOR_INTERVAL) * ANCHOR_INTERVAL + ANCHOR_MIN_DEPTH;
            return Err(WalletError::PxNotReady(format!(
                "the PX anchor (block {anchor}) lies below this wallet's restore height, where \
                 the tree's per-block roots come from the node; PX transactions can be built \
                 once the wallet is synced to block {from}"
            )));
        }
        let (root, size) = tree.root_at(anchor).ok_or_else(|| {
            WalletError::BadNodeData("the anchor is outside the root window".into())
        })?;
        if !tree.is_confirmed() && size <= tree.base_size() {
            let from = base + ROOT_WINDOW as u64;
            if synced < from {
                return Err(WalletError::PxNotReady(format!(
                    "the PX tree below this wallet's restore height came from the node and no \
                     later PX transaction has confirmed it yet, so the anchor could be a root \
                     the node chose; PX transactions without a record of this wallet can be \
                     built once a PX transaction confirms the tree or the wallet is synced to \
                     block {from} (restoring from height 1 builds the whole tree from blocks)"
                )));
            }
        }
        Ok((anchor, root))
    }

    /// The authentication path of leaf `pos` at `anchor`, checked against
    /// the wallet's root there (`root`).
    pub fn path(
        &self,
        pos: u64,
        anchor: u64,
        root: &Digest,
    ) -> Result<[Digest; TREE_DEPTH], WalletError> {
        let (path, at) = self.tree_ref()?.path(pos, anchor).map_err(tree_error)?;
        if at != *root {
            return Err(WalletError::BadNodeData(
                "the tree state at the anchor does not give the anchor's root".into(),
            ));
        }
        Ok(path)
    }

    /// Drops the witnesses no record needs: a leaf is kept while its record
    /// is unspent or its spend is within the wallet's reorganization window
    /// (`keep_spent` blocks), and the sibling a record points to.
    pub fn retain_witnesses(&mut self, synced: u64, keep_spent: u64) {
        let live = |spent: Option<u64>| spent.is_none_or(|h| synced < h + keep_spent);
        let mut keep: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for r in &self.records {
            if live(r.spent_height) {
                keep.extend(r.position);
            }
            if let Some((_, p)) = &r.sibling {
                keep.insert(*p);
            }
        }
        for r in &self.contract_records {
            if live(r.spent_height) {
                keep.extend(r.position);
            }
        }
        if let Some(t) = self.tree.as_mut() {
            t.retain_witnesses(|p| keep.contains(&p));
        }
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
            sibling: None,
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
        let commitment = |branch: u32, height: u64| [branch, height as u32, 0, 0, 0, 0, 0, 0];
        let grow = |t: &mut WalletTree, branch: u32, heights: std::ops::RangeInclusive<u64>| {
            for h in heights {
                t.append(commitment(branch, h)).unwrap();
                t.end_block(h).unwrap();
            }
        };
        for synced in 0..=100u64 {
            let mut t = WalletTree::new(0, &[], false).unwrap();
            grow(&mut t, 1, 1..=synced);
            let anchor = anchor_height(synced);
            let before = t.root_at(anchor).unwrap();
            for depth in 1..=3u64.min(synced) {
                let mut other = t.clone();
                other.rewind(synced - depth).unwrap();
                grow(&mut other, 2, synced - depth + 1..=synced);
                assert_eq!(
                    other.root_at(anchor).unwrap(),
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
        let mut t = WalletTree::new(0, &[], false).unwrap();
        for h in 1..=21u64 {
            if matches!(h, 10 | 20 | 21) {
                t.append([h as u32, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            }
            t.end_block(h).unwrap();
        }
        let at_15 = t.root_at(15).unwrap();
        s.tree = Some(t);
        assert!(!s.rewind(15));
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].spent_height, None, "the spend at 21 is undone");
        let t = s.tree.as_ref().unwrap();
        assert_eq!((t.height(), t.size()), (15, 1));
        assert_eq!(t.root_at(15), Some(at_15));
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
            lookup: false,
        }
    }

    fn known(height: u64) -> KnownContract {
        KnownContract {
            id: format!("{height:064x}"),
            height,
            programs: vec![],
            from_deploy: true,
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
            from_deploy: true,
        }
    }

    fn vault_program(budget: Budget) -> KnownProgram {
        let b = budget;
        KnownProgram {
            id: hex::encode(blacksilk_px::vault::program().id()),
            budget: [
                b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
            ],
            abi: ABI_VERSION,
            out_words: blacksilk_px::vault::OUT_WORDS,
        }
    }

    #[test]
    fn vault_operations_need_the_vault_alone_with_the_reference_budget() {
        use blacksilk_px::vault::BUDGET;
        let contract = [9, 0, 0, 0, 0, 0, 0, 0];
        let other = KnownProgram {
            id: "ab".repeat(32),
            budget: [1_000; 8],
            abi: ABI_VERSION,
            out_words: 0,
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
        // W3-39b: the vault registered with another call ABI or output-word
        // count is uncallable (every call must publish exactly the
        // registered words): refused.
        for (abi, out_words) in [
            (ABI_VERSION, blacksilk_px::vault::OUT_WORDS + 1),
            (ABI_VERSION, 0),
            (ABI_VERSION + 1, blacksilk_px::vault::OUT_WORDS),
        ] {
            let mut p = vault_program(BUDGET);
            (p.abi, p.out_words) = (abi, out_words);
            s.contracts = vec![vault_contract(vec![p])];
            let e = s.vault_budget(&contract).unwrap_err().to_string();
            assert!(e.contains("output word"), "{e}");
        }
    }

    /// W3-39b: registrations are derived from the deploy itself, as
    /// consensus records them; a program that does not load is node data
    /// no valid block holds.
    #[test]
    fn registrations_are_derived_from_the_deploy() {
        use blacksilk_px::vault;
        use blacksilk_tx::px::Registration;
        let mut chain = crate::wallet::mock_chain::MockChain::new(1);
        let mut odd = Registration::new(vault::VAULT_ELF.to_vec(), vault::BUDGET, 3);
        odd.abi = 7;
        let d = chain.deploy(vec![
            Registration::new(vault::VAULT_ELF.to_vec(), vault::BUDGET, vault::OUT_WORDS),
            odd,
        ]);
        let txs = vec![Transaction::PxDeploy(Box::new(d.clone()))];
        let got = deployed(&txs, 9).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, digest_hex(&d.contract_id()));
        assert_eq!((got[0].height, got[0].from_deploy), (9, true));
        let vault_id = hex::encode(vault::program().id());
        let b = vault::BUDGET;
        let budget = [
            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
        ];
        assert_eq!(
            got[0].programs,
            vec![
                KnownProgram {
                    id: vault_id.clone(),
                    budget,
                    abi: ABI_VERSION,
                    out_words: vault::OUT_WORDS,
                },
                KnownProgram {
                    id: vault_id,
                    budget,
                    abi: 7,
                    out_words: 3,
                },
            ]
        );
        let mut bad = d;
        bad.programs[0].elf = vec![0; 16];
        let txs = vec![Transaction::PxDeploy(Box::new(bad))];
        assert!(matches!(
            deployed(&txs, 9),
            Err(WalletError::BadNodeData(_))
        ));
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
