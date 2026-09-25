//! Wallet state, synchronization and transfers.
//!
//! The wallet trusts the node it syncs from for *availability* (which blocks
//! exist). It does not trust it for *correctness* of what it receives: block ids
//! are recomputed from headers and must match, every output is recognized with
//! the wallet's own keys (including the Janus anchor and commitment checks), and
//! the node validates every transaction the wallet submits. A dishonest node can
//! hide payments or lie about decoys; that is why wallets should use their own
//! node (docs/blocks.md §9).

use crate::node::NodeApi;
use crate::px::{ContractRecord, KnownContract, PxStore, RecordSource};

/// PX inputs chosen for a spend: the record indices, the kernel's two input
/// witnesses (dummies fill unused slots), their total value, and the anchor.
type PxInputs = (
    Vec<usize>,
    [blacksilk_px_core::kernel::InputWitness; 2],
    u64,
    [u32; 8],
);
use blacksilk_chain::address::encode_address;
use blacksilk_chain::block::Block;
use blacksilk_consensus::{ChainParams, Hash, Network};
use blacksilk_crypto::keys::{Address, SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::stealth::ReceivedOutput;
use blacksilk_crypto::{Point, Scalar};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_px::{delivery, share, vault};
use blacksilk_px_core::record::{output_rho, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::{
    build_transfer, standard_fee, BuildError, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, MAX_INPUTS, SPENDABLE_AGE};
use blacksilk_tx::px::{PxTx, Registration};
use blacksilk_tx::px_builder::{
    build_deploy, build_px, deploy_fee, px_standard_fee, FunctionRun, PxPlan,
};
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::{OutputKey, Transaction};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use zeroize::Zeroize;

/// Block ids kept for reorg detection.
const KEPT_BLOCK_IDS: usize = 720;
/// Subaddresses scanned beyond the highest one handed out, per account.
const LOOKAHEAD: u32 = 50;
/// How long the wallet keeps a submitted transaction (`PendingTx`):
/// - while it is unconfirmed, it is rebroadcast unchanged every this many
///   blocks, and its inputs stay reserved until the node rejects it for a
///   reason other than "already pooled";
/// - once confirmed, it is kept until its spend is this many blocks deep, so
///   that a reorganization re-reserves its inputs instead of freeing them.
///
/// The inputs are never simply released after a timeout. A transaction that
/// was relayed but not mined could still be in other nodes' pools, and spending
/// the same v1 output again with a new ring would let anyone intersect the two
/// rings and find the real input (docs/reviews/privacy-review.md §3c).
const PENDING_EXPIRY_BLOCKS: u64 = 20;

#[derive(Debug)]
pub enum WalletError {
    Node(String),
    WrongNetwork {
        wallet: String,
        node: String,
    },
    /// The node sent data inconsistent with itself (bad block encoding or id).
    BadNodeData(String),
    InsufficientFunds {
        available: u64,
        needed: u64,
    },
    TooManyInputs,
    Decoys(String),
    Build(BuildError),
    Rejected(String),
    /// The submission failed in transport, so the node may or may not have
    /// received the transaction. Its inputs stay reserved and it is
    /// rebroadcast unchanged on later syncs.
    Uncertain(String),
    Serialization(String),
    /// A contract operation that cannot be carried out (unknown contract,
    /// unregistered program, wrong secret, record not spendable).
    Contract(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Node(e) => write!(f, "node: {e}"),
            WalletError::WrongNetwork { wallet, node } => {
                write!(f, "wallet is for {wallet} but the node runs {node}")
            }
            WalletError::BadNodeData(e) => write!(f, "inconsistent data from node: {e}"),
            WalletError::InsufficientFunds { available, needed } => write!(
                f,
                "insufficient unlocked funds: {} available, {} needed (amount + fee)",
                blacksilk_chain::emission::format_amount(*available),
                blacksilk_chain::emission::format_amount(*needed)
            ),
            WalletError::TooManyInputs => write!(
                f,
                "amount needs more than {MAX_INPUTS} inputs; send in parts"
            ),
            WalletError::Decoys(e) => write!(f, "decoy selection: {e}"),
            WalletError::Build(e) => write!(f, "building the transaction: {e:?}"),
            WalletError::Rejected(e) => write!(f, "node rejected the transaction: {e}"),
            WalletError::Uncertain(e) => write!(
                f,
                "the node may or may not have received the transaction ({e}). Its funds \
                 stay reserved and `sync` rebroadcasts the same transaction. Do not run \
                 clear-pending unless you are sure it was never sent: a new transaction \
                 spending the same funds could reveal which ring member is the real input"
            ),
            WalletError::Serialization(e) => write!(f, "wallet data: {e}"),
            WalletError::Contract(e) => write!(f, "contract: {e}"),
        }
    }
}

impl std::error::Error for WalletError {}

/// An owned output, as persisted.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredOutput {
    global_index: u64,
    height: u64,
    coinbase: bool,
    account: u32,
    index: u32,
    amount: u64,
    one_time_key: String,
    commitment: String,
    mask: String,
    offset: String,
    key_image: String,
    /// Height at which it was spent on chain.
    spent_height: Option<u64>,
    /// Spent by a transaction we submitted that is not yet confirmed.
    pending: bool,
    /// Wallet height when that transaction was submitted.
    #[serde(default)]
    pending_height: u64,
}

/// A transaction this wallet submitted, kept until its spend is buried
/// (`PENDING_EXPIRY_BLOCKS`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingTx {
    /// The encoded transaction (hex), rebroadcast unchanged.
    tx: String,
    /// Wallet height of the last (re)broadcast.
    relayed_height: u64,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    network: String,
    seed: String,
    restore_height: u64,
    synced_height: u64,
    /// Recent block ids (height → id) for reorg detection.
    block_ids: BTreeMap<u64, String>,
    /// Highest subaddress index handed out, per account.
    issued: BTreeMap<u32, u32>,
    outputs: Vec<StoredOutput>,
    /// PX state (absent in wallets written before PX).
    #[serde(default)]
    px: PxStore,
    /// Submitted transactions (absent in wallets written before 2026-09-25).
    #[serde(default)]
    pending_txs: Vec<PendingTx>,
}

pub struct Wallet {
    network: Network,
    seed: [u8; 32],
    keys: WalletKeys,
    table: SubaddressTable,
    restore_height: u64,
    synced_height: u64,
    block_ids: BTreeMap<u64, Hash>,
    issued: BTreeMap<u32, u32>,
    outputs: Vec<StoredOutput>,
    px: PxStore,
    px_account: Account,
    pending_txs: Vec<PendingTx>,
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

pub fn parse_network(s: &str) -> Option<Network> {
    match s {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

fn h32(s: &str) -> Result<[u8; 32], WalletError> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| WalletError::Serialization(format!("bad hex field {s:?}")))
}

fn point(s: &str) -> Result<Point, WalletError> {
    Point::decode(&h32(s)?).ok_or_else(|| WalletError::Serialization("bad point".into()))
}

fn scalar(s: &str) -> Result<Scalar, WalletError> {
    blacksilk_crypto::point::decode_scalar(&h32(s)?)
        .ok_or_else(|| WalletError::Serialization("bad scalar".into()))
}

/// Balance summary in atomic units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// All unspent outputs (including those not yet spendable and pending change).
    pub total: u64,
    /// Spendable in the next block.
    pub unlocked: u64,
}

impl Wallet {
    /// A wallet from a 32-byte seed. `restore_height` is where scanning starts.
    pub fn from_seed(network: Network, seed: [u8; 32], restore_height: u64) -> Self {
        let keys = WalletKeys::from_seed(&seed);
        let mut w = Self {
            network,
            seed,
            table: SubaddressTable::default(),
            keys,
            restore_height,
            synced_height: restore_height.saturating_sub(1),
            block_ids: BTreeMap::new(),
            issued: BTreeMap::from([(0, 0)]),
            outputs: Vec::new(),
            px: PxStore::default(),
            px_account: Account::from_seed(&seed),
            pending_txs: Vec::new(),
        };
        w.rebuild_table();
        w
    }

    /// A new wallet from the OS CSPRNG. Scanning starts at `restore_height`
    /// (the current chain height for a brand new wallet).
    pub fn generate(network: Network, restore_height: u64) -> Result<Self, WalletError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| WalletError::Serialization(format!("OS RNG: {e}")))?;
        let w = Self::from_seed(network, seed, restore_height);
        seed.zeroize();
        Ok(w)
    }

    /// The seed as a 24-word BIP-39 mnemonic (the words encode the 32-byte seed
    /// directly; see docs/blocks.md §10).
    pub fn mnemonic(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.seed)
            .expect("32 bytes is valid BIP-39 entropy")
            .to_string()
    }

    pub fn from_mnemonic(
        network: Network,
        words: &str,
        restore_height: u64,
    ) -> Result<Self, WalletError> {
        let m = bip39::Mnemonic::parse_normalized(words.trim())
            .map_err(|e| WalletError::Serialization(format!("mnemonic: {e}")))?;
        let mut entropy = m.to_entropy();
        let seed: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::Serialization("mnemonic must have 24 words".into()))?;
        entropy.zeroize();
        Ok(Self::from_seed(network, seed, restore_height))
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn synced_height(&self) -> u64 {
        self.synced_height
    }

    fn rebuild_table(&mut self) {
        let mut table = SubaddressTable::default();
        for (&account, &issued) in &self.issued {
            for i in 0..=issued.saturating_add(LOOKAHEAD) {
                table.insert(self.keys.view_keys(), SubaddressIndex::new(account, i));
            }
        }
        self.table = table;
    }

    /// Address string for `(account, index)`, extending the scan window as needed.
    pub fn address(&mut self, account: u32, index: u32) -> String {
        let issued = self.issued.entry(account).or_insert(0);
        if index > *issued {
            *issued = index;
            self.rebuild_table();
        }
        encode_address(
            self.network,
            &self.keys.address(SubaddressIndex::new(account, index)),
        )
    }

    pub fn primary(&self) -> Address {
        self.keys.address(SubaddressIndex::PRIMARY)
    }

    // ---- persistence ----

    pub fn to_json(&self) -> Vec<u8> {
        let p = Persisted {
            version: 1,
            network: network_name(self.network).into(),
            seed: hex::encode(self.seed),
            restore_height: self.restore_height,
            synced_height: self.synced_height,
            block_ids: self
                .block_ids
                .iter()
                .map(|(h, id)| (*h, hex::encode(id)))
                .collect(),
            issued: self.issued.clone(),
            outputs: self.outputs.clone(),
            px: self.px.clone(),
            pending_txs: self.pending_txs.clone(),
        };
        serde_json::to_vec(&p).expect("serializable")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, WalletError> {
        let p: Persisted =
            serde_json::from_slice(bytes).map_err(|e| WalletError::Serialization(e.to_string()))?;
        if p.version != 1 {
            return Err(WalletError::Serialization(format!(
                "unsupported version {}",
                p.version
            )));
        }
        let network = parse_network(&p.network)
            .ok_or_else(|| WalletError::Serialization("network".into()))?;
        let mut seed = h32(&p.seed)?;
        let mut w = Self::from_seed(network, seed, p.restore_height);
        seed.zeroize();
        w.synced_height = p.synced_height;
        w.block_ids = p
            .block_ids
            .iter()
            .map(|(h, id)| Ok((*h, h32(id)?)))
            .collect::<Result<_, WalletError>>()?;
        w.issued = p.issued;
        w.outputs = p.outputs;
        w.px = p.px;
        w.pending_txs = p.pending_txs;
        w.rebuild_table();
        Ok(w)
    }

    // ---- sync ----

    fn check_network(&self, node: &dyn NodeApi) -> Result<blacksilk_rpc::Info, WalletError> {
        let info = node.info().map_err(WalletError::Node)?;
        if info.network != network_name(self.network) {
            return Err(WalletError::WrongNetwork {
                wallet: network_name(self.network).into(),
                node: info.network,
            });
        }
        Ok(info)
    }

    /// Removes everything learned from blocks above `height`.
    fn rewind(&mut self, height: u64) {
        self.outputs.retain(|o| o.height <= height);
        for o in &mut self.outputs {
            if o.spent_height.is_some_and(|h| h > height) {
                o.spent_height = None;
            }
        }
        self.block_ids.retain(|h, _| *h <= height);
        self.px.rewind(height);
        self.synced_height = height;
    }

    /// Scans new blocks. Detects reorganizations by comparing stored block ids with
    /// the node's, and rewinds to the fork point. Returns the new synced height.
    pub fn sync(&mut self, node: &dyn NodeApi) -> Result<u64, WalletError> {
        let info = self.check_network(node)?;
        // Reorg detection: walk back from our tip until our block id matches the node's.
        while self.synced_height >= self.restore_height && self.synced_height > 0 {
            let Some(ours) = self.block_ids.get(&self.synced_height).copied() else {
                if self.block_ids.is_empty() {
                    break; // fresh wallet
                }
                // Fork deeper than the kept window: rescan from the restore height.
                let h = self.restore_height.saturating_sub(1);
                self.rewind(h);
                break;
            };
            let theirs = if self.synced_height <= info.height {
                node.blocks(self.synced_height, 1)
                    .map_err(WalletError::Node)?
                    .blocks
                    .first()
                    .and_then(|b| blacksilk_rpc::parse_hash(&b.id))
            } else {
                None
            };
            if theirs == Some(ours) {
                break;
            }
            let h = self.synced_height - 1;
            self.rewind(h);
        }

        let mut from = self.synced_height + 1;
        while from <= info.height {
            let batch = node
                .blocks(from, blacksilk_rpc::MAX_BLOCKS_PER_REQUEST)
                .map_err(WalletError::Node)?;
            if batch.blocks.is_empty() {
                break;
            }
            for entry in batch.blocks {
                if entry.height != from {
                    return Err(WalletError::BadNodeData(format!(
                        "expected block {from}, got {}",
                        entry.height
                    )));
                }
                let bytes = hex::decode(&entry.hex)
                    .map_err(|_| WalletError::BadNodeData("block hex".into()))?;
                let block = Block::decode(&bytes)
                    .map_err(|e| WalletError::BadNodeData(format!("{e:?}")))?;
                let id = block.id(info.network_id);
                if hex::encode(id) != entry.id || block.compute_tx_root() != block.header.tx_root {
                    return Err(WalletError::BadNodeData(format!(
                        "block {from} does not match its id"
                    )));
                }
                self.apply_block(&block, entry.height, entry.first_output);
                self.block_ids.insert(entry.height, id);
                self.synced_height = entry.height;
                from += 1;
            }
            while self.block_ids.len() > KEPT_BLOCK_IDS {
                let first = *self.block_ids.keys().next().expect("non-empty");
                self.block_ids.remove(&first);
            }
        }
        let synced = self.synced_height;
        self.refresh_pending(node);
        self.px.sync_commitments(node, synced)?;
        self.px.sync_contracts(node, synced)?;
        Ok(self.synced_height)
    }

    fn apply_block(&mut self, block: &Block, height: u64, first_output: u64) {
        self.px.apply_block(&self.px_account, &block.txs, height);
        let report = scan_block(
            self.keys.view_keys(),
            &self.table,
            &block.txs,
            height,
            first_output,
        );
        for o in report.owned {
            let ki = o.key_image(&self.keys);
            if self
                .outputs
                .iter()
                .any(|s| s.global_index == o.global_index)
            {
                continue;
            }
            let ReceivedOutput {
                subaddress,
                amount,
                mask,
                output_key_offset,
            } = o.received;
            self.outputs.push(StoredOutput {
                global_index: o.global_index,
                height,
                coinbase: o.coinbase,
                account: subaddress.account,
                index: subaddress.index,
                amount,
                one_time_key: hex::encode(o.key.one_time_key.bytes()),
                commitment: hex::encode(o.key.commitment.bytes()),
                mask: hex::encode(mask.as_bytes()),
                offset: hex::encode(output_key_offset.as_bytes()),
                key_image: hex::encode(ki.bytes()),
                spent_height: None,
                pending: false,
                pending_height: 0,
            });
        }
        // Rejected outputs (Janus probes, bogus amounts) are deliberately ignored:
        // they must not be shown or spent (docs/transactions.md §12.5).
        // Every kind spends v1 outputs through key images: transfers, PX
        // transactions (bridge-in, fees) and deploys.
        let spent: HashSet<String> = block
            .txs
            .iter()
            .flat_map(|t| t.key_images())
            .map(|ki| hex::encode(ki.bytes()))
            .collect();
        for o in &mut self.outputs {
            if spent.contains(&o.key_image) {
                o.spent_height = Some(height);
                o.pending = false;
            }
        }
    }

    fn spendable_at(o: &StoredOutput, next_height: u64) -> bool {
        let age = if o.coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        };
        o.spent_height.is_none() && !o.pending && next_height >= o.height + age
    }

    pub fn balance(&self) -> Balance {
        let next = self.synced_height + 1;
        let mut b = Balance::default();
        for o in self
            .outputs
            .iter()
            .filter(|o| o.spent_height.is_none() && !o.pending)
        {
            b.total += o.amount;
            if Self::spendable_at(o, next) {
                b.unlocked += o.amount;
            }
        }
        b
    }

    /// Whether a submitted transaction is still unconfirmed.
    pub fn has_pending(&self) -> bool {
        self.outputs.iter().any(|o| o.pending)
    }

    /// Forgets unconfirmed spends and the stored transactions, v1 and PX alike.
    ///
    /// Only for a transaction that certainly never left this wallet. If it was
    /// relayed, spending its v1 inputs again with new rings links the two
    /// transactions by key image and lets observers intersect the rings.
    pub fn clear_pending(&mut self) {
        for o in &mut self.outputs {
            o.pending = false;
        }
        self.px.clear_pending();
        self.pending_txs.clear();
    }

    /// Calls `f(spent_height, pending, pending_height)` for every input of
    /// `tx` this wallet owns: v1 outputs by key image, PX and contract records
    /// by nullifier.
    fn for_each_input(
        &mut self,
        tx: &Transaction,
        mut f: impl FnMut(Option<u64>, &mut bool, &mut u64),
    ) {
        let kis: HashSet<String> = tx
            .key_images()
            .iter()
            .map(|k| hex::encode(k.bytes()))
            .collect();
        for o in &mut self.outputs {
            if kis.contains(&o.key_image) {
                f(o.spent_height, &mut o.pending, &mut o.pending_height);
            }
        }
        if let Transaction::Px(t) = tx {
            let nfs: HashSet<String> = t.nullifiers.iter().map(crate::px::digest_hex).collect();
            for r in &mut self.px.records {
                if nfs.contains(&r.nullifier) {
                    f(r.spent_height, &mut r.pending, &mut r.pending_height);
                }
            }
            for r in &mut self.px.contract_records {
                if nfs.contains(&r.nullifier) {
                    f(r.spent_height, &mut r.pending, &mut r.pending_height);
                }
            }
        }
    }

    /// Submits `tx`. Its inputs are reserved and the transaction stored
    /// *before* the request, so a transport failure leaves them reserved
    /// (`WalletError::Uncertain`). Only a definite refusal releases them.
    fn submit(&mut self, node: &dyn NodeApi, tx: Transaction) -> Result<Hash, WalletError> {
        let id = tx.hash();
        let bytes = tx.encode();
        let at = self.synced_height;
        self.for_each_input(&tx, |_, pending, h| {
            *pending = true;
            *h = at;
        });
        self.pending_txs.push(PendingTx {
            tx: hex::encode(&bytes),
            relayed_height: at,
        });
        match node.submit_tx(&bytes) {
            Err(e) => Err(WalletError::Uncertain(e)),
            Ok(r)
                if r.accepted
                    || r.error
                        .as_deref()
                        .is_some_and(|e| e.starts_with("AlreadyKnown")) =>
            {
                Ok(id)
            }
            // Refused by the only node that saw it: nothing was relayed.
            Ok(r) => {
                self.forget(&tx);
                Err(WalletError::Rejected(r.error.unwrap_or_default()))
            }
        }
    }

    /// Drops the stored copy of `tx` and releases its unspent inputs.
    fn forget(&mut self, tx: &Transaction) {
        let hex_tx = hex::encode(tx.encode());
        self.pending_txs.retain(|p| p.tx != hex_tx);
        self.for_each_input(tx, |spent, pending, _| {
            if spent.is_none() {
                *pending = false;
            }
        });
    }

    /// Maintains the stored transactions after a sync (`PENDING_EXPIRY_BLOCKS`).
    /// Transport errors are ignored here; the next sync retries.
    fn refresh_pending(&mut self, node: &dyn NodeApi) {
        let synced = self.synced_height;
        let mut kept = Vec::new();
        let mut covered_kis = HashSet::new();
        let mut covered_nfs = HashSet::new();
        for mut p in std::mem::take(&mut self.pending_txs) {
            let Some(tx) = hex::decode(&p.tx)
                .ok()
                .and_then(|b| Transaction::decode(&b).ok())
            else {
                continue; // unreadable entry: nothing to rebroadcast
            };
            let (mut unspent, mut buried) = (false, true);
            self.for_each_input(&tx, |spent, _, _| match spent {
                None => {
                    unspent = true;
                    buried = false;
                }
                Some(h) => buried &= synced >= h + PENDING_EXPIRY_BLOCKS,
            });
            if buried {
                continue;
            }
            if unspent {
                // Re-reserve inputs whose confirmation a reorganization undid.
                let at = p.relayed_height;
                self.for_each_input(&tx, |spent, pending, h| {
                    if spent.is_none() && !*pending {
                        *pending = true;
                        *h = at;
                    }
                });
                if synced >= p.relayed_height + PENDING_EXPIRY_BLOCKS {
                    match node.submit_tx(&tx.encode()) {
                        Ok(r) if r.accepted || r.already_pooled() => p.relayed_height = synced,
                        // It can never be mined on this chain: release the inputs.
                        Ok(r) if r.error.as_deref().is_some_and(|e| e.starts_with("Invalid")) => {
                            self.for_each_input(&tx, |spent, pending, _| {
                                if spent.is_none() {
                                    *pending = false;
                                }
                            });
                            continue;
                        }
                        // A full pool or a transport error: retry on a later sync.
                        _ => {}
                    }
                }
            }
            covered_kis.extend(tx.key_images().iter().map(|k| hex::encode(k.bytes())));
            if let Transaction::Px(t) = &tx {
                covered_nfs.extend(t.nullifiers.iter().map(crate::px::digest_hex));
            }
            kept.push(p);
        }
        self.pending_txs = kept;
        // Reservations without a stored transaction come from wallet files
        // written before transactions were stored: they keep the old expiry.
        for o in &mut self.outputs {
            if o.pending
                && !covered_kis.contains(&o.key_image)
                && synced >= o.pending_height + PENDING_EXPIRY_BLOCKS
            {
                o.pending = false;
            }
        }
        for r in &mut self.px.records {
            if r.pending
                && !covered_nfs.contains(&r.nullifier)
                && synced >= r.pending_height + PENDING_EXPIRY_BLOCKS
            {
                r.pending = false;
            }
        }
    }

    // ---- transfers ----

    fn to_spendable(o: &StoredOutput) -> Result<SpendableOutput, WalletError> {
        Ok(SpendableOutput {
            global_index: o.global_index,
            key: OutputKey {
                one_time_key: point(&o.one_time_key)?,
                commitment: point(&o.commitment)?,
            },
            subaddress: SubaddressIndex::new(o.account, o.index),
            output_key_offset: scalar(&o.offset)?,
            amount: o.amount,
            mask: scalar(&o.mask)?,
        })
    }

    /// Chooses inputs: the smallest single output that covers everything if one
    /// exists (fewest inputs, least change linkage), otherwise largest-first.
    fn select_inputs(
        &self,
        amount: u64,
        payments: usize,
        rules: &TxRules,
    ) -> Result<(Vec<usize>, u64), WalletError> {
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        let available: u64 = candidates.iter().map(|&i| self.outputs[i].amount).sum();
        let fee1 = standard_fee(1, payments + 1, rules);
        candidates.sort_by_key(|&i| self.outputs[i].amount);
        if let Some(&i) = candidates
            .iter()
            .find(|&&i| self.outputs[i].amount as u128 >= amount as u128 + fee1 as u128)
        {
            return Ok((vec![i], fee1));
        }
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in candidates.iter().rev() {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            if chosen.len() > MAX_INPUTS {
                return Err(WalletError::TooManyInputs);
            }
            let fee = standard_fee(chosen.len(), payments + 1, rules);
            if sum >= amount as u128 + fee as u128 {
                return Ok((chosen, fee));
            }
        }
        Err(WalletError::InsufficientFunds {
            available,
            needed: amount.saturating_add(standard_fee(
                candidates.len().max(1),
                payments + 1,
                rules,
            )),
        })
    }

    /// Picks 15 decoys for `real` and fetches their keys. Candidates that turn out
    /// to be coinbase outputs younger than the coinbase maturity are excluded and
    /// the selection is repeated.
    fn ring_for<R: RngCore + CryptoRng>(
        node: &dyn NodeApi,
        target_block_time: u64,
        cumulative: &[u64],
        next_height: u64,
        real: u64,
        rng: &mut R,
    ) -> Result<Vec<Decoy>, WalletError> {
        let mut excluded: HashSet<u64> = HashSet::new();
        let coinbase_limit = next_height
            .checked_sub(COINBASE_MATURITY)
            .and_then(|h| cumulative.get(h as usize).copied())
            .unwrap_or(0);
        // Young chains have many too-young coinbase outputs; each round excludes
        // the ones it hit.
        for _ in 0..100 {
            let ring = select_ring(rng, cumulative, next_height, target_block_time, real, |i| {
                !excluded.contains(&i)
            })
            .map_err(|e| WalletError::Decoys(format!("{e:?}")))?;
            let decoy_indices: Vec<u64> = ring.iter().copied().filter(|&i| i != real).collect();
            let fetched = node
                .outputs(&decoy_indices)
                .map_err(WalletError::Node)?
                .outputs;
            if fetched.len() != decoy_indices.len() {
                return Err(WalletError::BadNodeData("wrong number of outputs".into()));
            }
            let mut ok = true;
            let mut decoys = Vec::with_capacity(15);
            for (o, &i) in fetched.iter().zip(&decoy_indices) {
                if o.index != i {
                    return Err(WalletError::BadNodeData("output index mismatch".into()));
                }
                if o.coinbase && i >= coinbase_limit {
                    excluded.insert(i);
                    ok = false;
                }
                decoys.push(Decoy {
                    global_index: i,
                    key: OutputKey {
                        one_time_key: point(&o.one_time_key)?,
                        commitment: point(&o.commitment)?,
                    },
                });
            }
            if ok {
                return Ok(decoys);
            }
        }
        Err(WalletError::Decoys("could not find eligible decoys".into()))
    }

    /// Builds, submits and records a transfer of `amount` to `to`. Change goes to
    /// the primary address. Returns the transaction id and the fee.
    pub fn transfer<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let next = self.synced_height + 1;
        let (inputs, fee) = self.select_inputs(amount, 1, rules)?;
        let dist = node
            .distribution(self.synced_height)
            .map_err(WalletError::Node)?;
        let mut plans = Vec::with_capacity(inputs.len());
        for &i in &inputs {
            let o = &self.outputs[i];
            let target = ChainParams::for_network(self.network).target_block_time;
            let decoys = Self::ring_for(node, target, &dist.cumulative, next, o.global_index, rng)?;
            plans.push(InputPlan {
                real: Self::to_spendable(o)?,
                decoys,
            });
        }
        let tx = build_transfer(
            &self.keys,
            plans,
            &[Payment {
                address: *to,
                amount,
            }],
            &self.primary(),
            fee,
            rules,
            rng,
        )
        .map_err(WalletError::Build)?;
        let id = self.submit(node, Transaction::from(tx))?;
        debug_assert!(inputs.iter().all(|&i| self.outputs[i].pending));
        Ok((id, fee))
    }

    // ---- private execution (docs/px.md §11) ----

    /// The PX address `index`, as a string.
    pub fn px_address(&mut self, index: u32) -> String {
        self.px.issued = self.px.issued.max(index);
        blacksilk_chain::address::encode_px_address(self.network, &self.px_account.address(index))
    }

    /// PX balance: `(total unspent, spendable now)`.
    pub fn px_balance(&self) -> (u64, u64) {
        self.px.balance(self.synced_height)
    }

    fn submit_px(&mut self, node: &dyn NodeApi, tx: PxTx) -> Result<Hash, WalletError> {
        self.submit(node, Transaction::Px(Box::new(tx)))
    }

    /// v1 inputs covering `needed` (largest first), with their rings.
    fn v1_plans<R: RngCore + CryptoRng>(
        &self,
        node: &dyn NodeApi,
        needed: u64,
        rng: &mut R,
    ) -> Result<(Vec<usize>, Vec<InputPlan>), WalletError> {
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.outputs[i].amount));
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in &candidates {
            if sum >= needed as u128 {
                break;
            }
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
        }
        if sum < needed as u128 || chosen.len() > MAX_INPUTS {
            return Err(WalletError::InsufficientFunds {
                available: candidates.iter().map(|&i| self.outputs[i].amount).sum(),
                needed,
            });
        }
        let plans = self.plans_for(node, &chosen, rng)?;
        Ok((chosen, plans))
    }

    /// Rings for the v1 outputs `chosen`.
    fn plans_for<R: RngCore + CryptoRng>(
        &self,
        node: &dyn NodeApi,
        chosen: &[usize],
        rng: &mut R,
    ) -> Result<Vec<InputPlan>, WalletError> {
        let next = self.synced_height + 1;
        let dist = node
            .distribution(self.synced_height)
            .map_err(WalletError::Node)?;
        let target = ChainParams::for_network(self.network).target_block_time;
        let mut plans = Vec::with_capacity(chosen.len());
        for &i in chosen {
            let o = &self.outputs[i];
            let decoys = Self::ring_for(node, target, &dist.cumulative, next, o.global_index, rng)?;
            plans.push(InputPlan {
                real: Self::to_spendable(o)?,
                decoys,
            });
        }
        Ok(plans)
    }

    /// Moves `amount` of v1 funds into PX, to PX address 0. The v1 inputs pay
    /// the amount and the standard PX fee. Returns the transaction id and the fee.
    pub fn px_deposit<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let fee = px_standard_fee();
        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds {
                available: 0,
                needed: u64::MAX,
            })?;
        let (chosen, plans) = self.v1_plans(node, needed, rng)?;
        let root = self
            .px
            .tree_at(crate::px::anchor_height(self.synced_height))?
            .root();
        let owner = self.px_account.owner(0);
        let witness = pxw::witness(
            root,
            amount,
            0,
            [pxw::dummy_input(rng), pxw::dummy_input(rng)],
            [pxw::output(rng, owner, amount), pxw::empty_output(rng)],
        );
        let tx = build_px(
            PxPlan {
                keys: Some(&self.keys),
                inputs: plans,
                change: Some(self.primary()),
                payouts: vec![],
                witness,
                recipients: [Some(self.px_account.address(0)), None],
                functions: vec![],
                fee,
            },
            rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        let id = self.submit_px(node, tx)?;
        debug_assert!(chosen.iter().all(|&i| self.outputs[i].pending));
        Ok((id, fee))
    }

    /// The PX inputs for spending `needed`: one or two records, plus a
    /// dummy when only one is used.
    fn px_inputs<R: RngCore + CryptoRng>(
        &mut self,
        needed: u64,
        rng: &mut R,
    ) -> Result<PxInputs, WalletError> {
        // The canonical anchor (see `px::anchor_height`).
        let anchor = crate::px::anchor_height(self.synced_height);
        let chosen = self.px.select(needed, anchor)?;
        let tree = self.px.tree_at(anchor)?;
        let mut inputs = Vec::with_capacity(2);
        let mut total = 0u64;
        for &i in &chosen {
            let r = &self.px.records[i];
            let pos = r.position.expect("spendable records have positions");
            let owner = self.px_account.owner(r.index);
            let rec = r.record(owner)?;
            let path = tree
                .path(pos)
                .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
            inputs.push(self.px_account.spend(r.index, &rec, pos, path));
            total += r.value;
        }
        while inputs.len() < 2 {
            inputs.push(pxw::dummy_input(rng));
        }
        let inputs: [_; 2] = inputs.try_into().expect("two inputs");
        Ok((chosen, inputs, total, tree.root()))
    }

    /// Pays `amount` privately to a PX address; the fee is paid from PX.
    pub fn px_send<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &blacksilk_px::delivery::Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let fee = px_standard_fee();
        let (chosen, inputs, total, root) = self.px_inputs(amount.saturating_add(fee), rng)?;
        let change = total - amount - fee;
        let witness = pxw::witness(
            root,
            0,
            fee,
            inputs,
            [
                pxw::output(rng, to.owner, amount),
                pxw::output(rng, self.px_account.owner(1), change),
            ],
        );
        let tx = build_px(
            PxPlan {
                keys: None,
                inputs: vec![],
                change: None,
                payouts: vec![],
                witness,
                recipients: [Some(to.clone()), Some(self.px_account.address(1))],
                functions: vec![],
                fee,
            },
            rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let id = self.submit_px(node, tx)?;
        debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
        Ok((id, fee))
    }

    /// Moves `amount` out of PX to a v1 address (a clear-amount payout); the
    /// fee is paid from PX.
    pub fn px_withdraw<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let fee = px_standard_fee();
        let out = amount.saturating_add(fee);
        let (chosen, inputs, total, root) = self.px_inputs(out, rng)?;
        let change = total - out;
        let witness = pxw::witness(
            root,
            0,
            out,
            inputs,
            [
                pxw::output(rng, self.px_account.owner(1), change),
                pxw::empty_output(rng),
            ],
        );
        let tx = build_px(
            PxPlan {
                keys: None,
                inputs: vec![],
                change: None,
                payouts: vec![Payment {
                    address: *to,
                    amount,
                }],
                witness,
                recipients: [Some(self.px_account.address(1)), None],
                functions: vec![],
                fee,
            },
            rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let id = self.submit_px(node, tx)?;
        debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
        Ok((id, fee))
    }

    // ---- private contracts (docs/px.md §13) ----

    /// Contracts deployed on chain, as indexed while scanning.
    pub fn px_contracts(&self) -> &[KnownContract] {
        &self.px.contracts
    }

    /// Contract records whose openings this wallet holds.
    pub fn px_contract_records(&self) -> &[ContractRecord] {
        &self.px.contract_records
    }

    /// Registers `programs` as a new private contract, paid with v1 funds (the
    /// deployer is hidden behind ring signatures). Returns the transaction id,
    /// the contract id and the fee. The contract is usable from the block
    /// after the deploy confirms.
    pub fn px_deploy<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        programs: Vec<Registration>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest, u64), WalletError> {
        self.sync(node)?;
        // Two outputs (the transfer minimum): change, and a zero-value output
        // to this wallet.
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.outputs[i].amount));
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        let mut fee = deploy_fee(1, 2, &programs);
        for &i in &candidates {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            fee = deploy_fee(chosen.len(), 2, &programs);
            if sum >= fee as u128 || chosen.len() >= MAX_INPUTS {
                break;
            }
        }
        if sum < fee as u128 {
            return Err(WalletError::InsufficientFunds {
                available: candidates.iter().map(|&i| self.outputs[i].amount).sum(),
                needed: fee,
            });
        }
        let plans = self.plans_for(node, &chosen, rng)?;
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let deploy = build_deploy(
            &self.keys,
            plans,
            &[Payment {
                address: self.primary(),
                amount: 0,
            }],
            &self.primary(),
            salt,
            programs,
            rules,
            rng,
        )
        .map_err(WalletError::Build)?;
        let contract = deploy.contract_id();
        let fee = deploy.fee;
        let id = self.submit(node, Transaction::PxDeploy(Box::new(deploy)))?;
        debug_assert!(chosen.iter().all(|&i| self.outputs[i].pending));
        Ok((id, contract, fee))
    }

    /// The registered budget of the reference vault program under `contract`.
    fn vault_budget(
        &self,
        contract: &Digest,
    ) -> Result<blacksilk_zkvm::air::trace::Budget, WalletError> {
        self.px
            .registered(contract, &vault::program().id())
            .ok_or_else(|| {
                WalletError::Contract(
                    "not a known vault contract (unknown id, not yet confirmed, or the vault program is not registered to it)".into(),
                )
            })
    }

    /// Locks `amount` of this wallet's PX funds in a new record of the vault
    /// `contract`, under `Hk(LOCK, secret)`. The record's ciphertext goes to
    /// `deliver_to` (the party that will claim it) or to this wallet; this
    /// wallet keeps its own copy either way. The fee is paid from PX. Returns
    /// the transaction id and the vault record's commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_lock<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        contract: &Digest,
        amount: u64,
        secret: &Digest,
        deliver_to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest), WalletError> {
        self.sync(node)?;
        let budget = self.vault_budget(contract)?;
        let fee = px_standard_fee();
        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds {
                available: 0,
                needed: u64::MAX,
            })?;
        let (chosen, inputs, total, root) = self.px_inputs(needed, rng)?;
        let lock = vault::lock_of(secret);
        let blind = pxw::random_digest(rng);
        let (input, fw) = vault::lock_call(contract, amount, &lock, 0, &blind);
        let vault_out = pxw::contract_output(rng, *contract, amount, lock);
        let mut witness = pxw::witness(
            root,
            0,
            fee,
            inputs,
            [
                vault_out.clone(),
                pxw::output(rng, self.px_account.owner(1), total - needed),
            ],
        );
        witness.n_fn = 1;
        witness.functions[0] = Some(fw);
        let to = deliver_to
            .cloned()
            .unwrap_or_else(|| self.px_account.address(0));
        let tx = build_px(
            PxPlan {
                keys: None,
                inputs: vec![],
                change: None,
                payouts: vec![],
                witness,
                recipients: [Some(to), Some(self.px_account.address(1))],
                functions: vec![FunctionRun {
                    program: vault::program(),
                    input,
                    budget,
                }],
                fee,
            },
            rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        // This wallet's copy of the new vault record.
        let rho = output_rho(&mut HostPerm::new(), &tx.nullifiers[0], 0);
        let record = Record {
            owner: ZERO_DIGEST,
            contract: *contract,
            asset: ZERO_DIGEST,
            value: amount,
            data: lock,
            rho,
            rcm: vault_out.rcm,
        };
        let cm = tx.commitments[0];
        if record.commit(&mut HostPerm::new()) != cm {
            return Err(WalletError::Contract(
                "vault record does not match its commitment".into(),
            ));
        }
        self.px.issued = self.px.issued.max(1);
        // Keep the creator's copy first: if the submission's outcome is
        // uncertain, the record may exist on chain and its opening must not
        // be lost.
        let known = self.px.contract_record(&cm).is_some();
        self.px
            .add_contract_record(&record, &cm, RecordSource::Created, None);
        match self.submit_px(node, tx) {
            Ok(id) => {
                debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
                Ok((id, cm))
            }
            Err(e) => {
                // A definite refusal: the record never existed.
                if matches!(e, WalletError::Rejected(_)) && !known {
                    let hex_cm = crate::px::digest_hex(&cm);
                    self.px.contract_records.retain(|r| r.commitment != hex_cm);
                }
                Err(e)
            }
        }
    }

    /// Claims the vault record with commitment `record` with `secret`, paying
    /// its value to `to` (a PX address) or to this wallet. The fee is paid
    /// from one of this wallet's PX records, or else from v1 funds. Returns
    /// the transaction id and the claimed value.
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_claim<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        record: &Digest,
        secret: &Digest,
        to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let anchor = crate::px::anchor_height(self.synced_height);
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown vault record".into()))?;
        let stored = &self.px.contract_records[k];
        if !stored.spendable_at(anchor) {
            return Err(WalletError::Contract(
                "vault record not spendable yet (unconfirmed, above the anchor, pending or spent)"
                    .into(),
            ));
        }
        let rec = stored.record()?;
        let pos = stored.position.expect("spendable records have positions");
        if vault::lock_of(secret) != rec.data {
            return Err(WalletError::Contract(
                "wrong secret for this vault record".into(),
            ));
        }
        let budget = self.vault_budget(&rec.contract)?;
        let fee = px_standard_fee();
        let tree = self.px.tree_at(anchor)?;
        let path = tree
            .path(pos)
            .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
        let vault_in = pxw::contract_input(rng, &rec, pos, path);
        let recipient = to.cloned().unwrap_or_else(|| self.px_account.address(0));
        let blind = pxw::random_digest(rng);
        let (input, fw) = vault::claim_call(&rec, secret, &recipient.owner, 0, 0, &blind);
        let payout = pxw::output(rng, recipient.owner, rec.value);

        // The fee: one PX record of this wallet if one covers it, else v1.
        let single = self
            .px
            .select(fee, anchor)
            .ok()
            .filter(|picked| picked.len() == 1);
        let (fee_input, second_out, second_to, bridge_out, fee_record, v1) = match single {
            Some(picked) => {
                let i = picked[0];
                let r = &self.px.records[i];
                let p = r.position.expect("spendable records have positions");
                let owner = self.px_account.owner(r.index);
                let user = r.record(owner)?;
                let path = tree
                    .path(p)
                    .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
                let change = pxw::output(rng, self.px_account.owner(1), r.value - fee);
                (
                    self.px_account.spend(r.index, &user, p, path),
                    change,
                    Some(self.px_account.address(1)),
                    fee,
                    Some(i),
                    None,
                )
            }
            None => {
                let (chosen, plans) = self.v1_plans(node, fee, rng)?;
                (
                    pxw::dummy_input(rng),
                    pxw::empty_output(rng),
                    None,
                    0,
                    None,
                    Some((chosen, plans)),
                )
            }
        };
        let mut witness = pxw::witness(
            tree.root(),
            0,
            bridge_out,
            [vault_in, fee_input],
            [payout, second_out],
        );
        witness.n_fn = 1;
        witness.functions[0] = Some(fw);
        let (v1_chosen, v1_plans) = v1.unwrap_or_default();
        let tx = build_px(
            PxPlan {
                keys: (!v1_plans.is_empty()).then_some(&self.keys),
                inputs: v1_plans,
                change: (!v1_chosen.is_empty()).then(|| self.primary()),
                payouts: vec![],
                witness,
                recipients: [Some(recipient), second_to],
                functions: vec![FunctionRun {
                    program: vault::program(),
                    input,
                    budget,
                }],
                fee,
            },
            rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let records: Vec<usize> = fee_record.into_iter().collect();
        let id = self.submit_px(node, tx)?;
        debug_assert!(records.iter().all(|&i| self.px.records[i].pending));
        debug_assert!(self.px.contract_records[k].pending);
        Ok((id, rec.value))
    }

    /// The opening of contract record `record`, sealed to `to` for sharing
    /// off chain (`blacksilk_px::share`).
    pub fn px_share<R: RngCore + CryptoRng>(
        &self,
        record: &Digest,
        to: &delivery::Address,
        rng: &mut R,
    ) -> Result<Vec<u8>, WalletError> {
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown contract record".into()))?;
        let rec = self.px.contract_records[k].record()?;
        share::seal_share(rng, to, &rec, record)
            .map_err(|_| WalletError::Contract("the recipient address does not decode".into()))
    }

    /// Imports a shared contract-record opening addressed to one of this
    /// wallet's PX addresses. It counts as confirmed once its commitment is
    /// found on chain (the next sync). Returns its commitment.
    pub fn px_import(&mut self, shared: &[u8]) -> Result<Digest, WalletError> {
        for index in 0..=self.px.issued.saturating_add(crate::px::PX_LOOKAHEAD) {
            let keys = self.px_account.delivery_keys(index);
            let owner = self.px_account.owner(index);
            let Some((rec, cm)) = share::open_share(&keys, &owner, shared) else {
                continue;
            };
            if rec.contract == ZERO_DIGEST {
                return Err(WalletError::Contract(
                    "only contract records can be imported".into(),
                ));
            }
            self.px
                .add_contract_record(&rec, &cm, RecordSource::Imported, None);
            return Ok(cm);
        }
        Err(WalletError::Contract(
            "not a share addressed to this wallet".into(),
        ))
    }
}
