//! Wallet state, synchronization and transfers.
//!
//! The wallet trusts the node it syncs from for *availability* (which blocks
//! exist). It does not trust it for *correctness* of what it receives: block ids
//! are recomputed from headers and must match, every output is recognized with
//! the wallet's own keys (including the Janus anchor and commitment checks), and
//! the node validates every transaction the wallet submits. A dishonest node can
//! hide payments or lie about decoys; that is why wallets should use their own
//! node (docs/blocks.md §9).

use crate::index::{IndexedOutput, OutputIndex};
use crate::node::NodeApi;
use crate::px::{
    AddressKeys, ContractRecord, KnownContract, PxStore, RecordSource, PX_GAP_LIMIT, PX_LOOKAHEAD,
    PX_MAX_INDEX_AHEAD,
};

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
use blacksilk_px::wallet::{self as pxw, Account, Derivation};
use blacksilk_px::{delivery, share, vault};
use blacksilk_px_core::record::{output_rho, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::{
    build_transfer, standard_fee, BuildError, Decoy, InputPlan, Payment, SpendableOutput,
};
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
use zeroize::{Zeroize, Zeroizing};

/// Block ids kept for reorg detection.
const KEPT_BLOCK_IDS: usize = 720;
/// Subaddresses scanned beyond the highest one handed out or found, per
/// account. The window grows while scanning: an output found at index `i`
/// raises the account's `issued` to `i` (a gap-limit scan), so a wallet
/// restored from its seed finds subaddresses up to this far beyond the last
/// one that was paid.
pub const LOOKAHEAD: u32 = 50;
/// Subaddress indexes handed out beyond the highest one that has received
/// funds (per account) without an explicit override (docs/reviews/wallet-review.md
/// M-1). Every index up to the highest handed out, plus `LOOKAHEAD`, is
/// derived at every load and scanned for.
pub const GAP_LIMIT: u32 = 1_000;
/// Absolute ceiling above the highest subaddress index that has received
/// funds, even with the override. Wallet files holding more (written by older
/// versions, which had no limit) are clamped when loaded.
pub const MAX_INDEX_AHEAD: u32 = 10_000;
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
/// Stored transactions and rings are kept until their spend is this deep: the
/// wallet's reorganization window (`KEPT_BLOCK_IDS`). K4 allows deeper
/// reorganizations, but beyond this window the wallet rescans anyway.
const RING_RETENTION_BLOCKS: u64 = KEPT_BLOCK_IDS as u64;

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
    /// An address index too far beyond the highest one that has received
    /// funds (`GAP_LIMIT`, `MAX_INDEX_AHEAD` and their PX counterparts).
    AddressIndex {
        index: u32,
        /// The highest index allowed now.
        limit: u32,
        /// Whether the override was given (then `limit` is the hard ceiling).
        forced: bool,
    },
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
                 spending the same funds would be linkable to it"
            ),
            WalletError::Serialization(e) => write!(f, "wallet data: {e}"),
            WalletError::Contract(e) => write!(f, "contract: {e}"),
            WalletError::AddressIndex {
                index,
                limit,
                forced: false,
            } => write!(
                f,
                "address index {index} is too far beyond the highest index that has received \
                 funds (at most {limit} now): every index up to it would be scanned for on \
                 every sync. Use a lower index, or --force if you really need it"
            ),
            WalletError::AddressIndex {
                index,
                limit,
                forced: true,
            } => write!(
                f,
                "address index {index} is beyond the hard limit ({limit}) even with --force"
            ),
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
    /// Hash of the transaction that created it (absent in wallet files
    /// written before 2026-09-27; the block height stands in for it then).
    #[serde(default)]
    tx: Option<String>,
}

impl StoredOutput {
    /// What identifies its source for merge avoidance (review R3-13): the
    /// creating transaction, or the block for outputs stored without it.
    fn source(&self) -> String {
        match &self.tx {
            Some(t) => t.clone(),
            None => format!("block {}", self.height),
        }
    }
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

/// A decoy of a ring this wallet used, as persisted: its index and, to detect
/// that a reorganization gave the index to another output, its keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RingMember {
    index: u64,
    one_time_key: String,
    commitment: String,
}

impl RingMember {
    fn of(d: &Decoy) -> Self {
        Self {
            index: d.global_index,
            one_time_key: hex::encode(d.key.one_time_key.bytes()),
            commitment: hex::encode(d.key.commitment.bytes()),
        }
    }
}

/// A secret string (the hex seed in the wallet JSON), wiped when dropped.
///
/// This covers the wallet's own copy only. Not covered: the JSON text itself
/// (zeroized by `crate::load`/`crate::save`, but `serde_json` may reallocate
/// its output buffer while writing, leaving earlier copies in freed memory),
/// and copies the allocator or the OS keep (swap, core dumps).
struct SecretString(Zeroizing<String>);

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| SecretString(Zeroizing::new(s)))
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    network: String,
    seed: SecretString,
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
    /// Decoys of the ring last submitted for each key image (W-5).
    #[serde(default)]
    rings: BTreeMap<String, Vec<RingMember>>,
    /// The PX key derivation (`blacksilk_px::wallet::Derivation`). Absent in
    /// files written before 2026-09-27, which are version 1: `1`.
    #[serde(default)]
    derivation: Option<u32>,
    /// Every v1 output seen, for local ring-member resolution (absent in
    /// older files: rebuilt by the next sync and a backfill).
    #[serde(default)]
    output_index: OutputIndex,
}

/// The wallet-file format version for a wallet with PX derivation `d`.
/// Version 2 adds the PX key derivation (`derivation`); version 1 files are
/// read as derivation 1, and derivation-1 wallets are still written as
/// version 1. A version-2 file is refused by older wallets, which would
/// otherwise derive the wrong PX addresses from it.
fn file_version(d: Derivation) -> u32 {
    match d {
        Derivation::V1 => 1,
        Derivation::V2 => 2,
    }
}

pub struct Wallet {
    network: Network,
    seed: [u8; 32],
    /// PX key derivation of this wallet (docs/px.md §3.1).
    derivation: Derivation,
    /// Every v1 output seen (`crate::index`).
    index: OutputIndex,
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
    /// Decoys of the ring last submitted for each key image: reused when the
    /// output is spent again (docs/reviews/wallet-review.md W-5).
    rings: BTreeMap<String, Vec<RingMember>>,
    /// Rings of the transaction being built, recorded in `rings` when it is
    /// submitted.
    staged_rings: Vec<(String, Vec<RingMember>)>,
    /// Where `submit` saves the wallet before a transaction leaves it
    /// (`set_autosave`).
    autosave: Option<AutoSave>,
    /// PX delivery keys derived so far (memory only).
    px_keys: AddressKeys,
    /// Problems found and repaired when loading (`take_warnings`).
    warnings: Vec<String>,
}

/// The wallet file to save to before a submission (docs/reviews/wallet-review.md F1).
struct AutoSave {
    path: std::path::PathBuf,
    password: zeroize::Zeroizing<Vec<u8>>,
    kdf: crate::file::KdfParams,
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
        // The value is not echoed: the field may be secret (the seed, masks).
        .ok_or_else(|| WalletError::Serialization("bad 32-byte hex field".into()))
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
    /// A wallet from a 32-byte seed, with the latest PX key derivation.
    /// `restore_height` is where scanning starts.
    pub fn from_seed(network: Network, seed: [u8; 32], restore_height: u64) -> Self {
        Self::from_seed_with(network, seed, restore_height, Derivation::LATEST)
    }

    /// A wallet from a 32-byte seed with PX key derivation `derivation`
    /// (docs/px.md §3.1). The v1 keys do not depend on it.
    pub fn from_seed_with(
        network: Network,
        seed: [u8; 32],
        restore_height: u64,
        derivation: Derivation,
    ) -> Self {
        let keys = WalletKeys::from_seed(&seed);
        let mut w = Self {
            network,
            seed,
            derivation,
            index: OutputIndex::default(),
            table: SubaddressTable::default(),
            keys,
            restore_height,
            synced_height: restore_height.saturating_sub(1),
            block_ids: BTreeMap::new(),
            issued: BTreeMap::from([(0, 0)]),
            outputs: Vec::new(),
            px: PxStore::default(),
            px_account: Account::from_seed_with(&seed, derivation),
            pending_txs: Vec::new(),
            rings: BTreeMap::new(),
            staged_rings: Vec::new(),
            autosave: None,
            px_keys: AddressKeys::default(),
            warnings: Vec::new(),
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
    ///
    /// The result is wiped when dropped, and written into a buffer large
    /// enough that it is never reallocated (no stray partial copies). The
    /// intermediate `bip39::Mnemonic` (word indices) is not zeroized: the
    /// crate's `zeroize` feature is not enabled in this build.
    pub fn mnemonic(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let m =
            bip39::Mnemonic::from_entropy(&self.seed).expect("32 bytes is valid BIP-39 entropy");
        // 24 words of at most 8 letters and 23 spaces: 215 bytes.
        let mut s = Zeroizing::new(String::with_capacity(256));
        write!(s, "{m}").expect("writing to a String cannot fail");
        s
    }

    /// A wallet from its 24-word seed, with the latest PX key derivation.
    pub fn from_mnemonic(
        network: Network,
        words: &str,
        restore_height: u64,
    ) -> Result<Self, WalletError> {
        Self::from_mnemonic_with(network, words, restore_height, Derivation::LATEST)
    }

    /// A wallet from its 24-word seed with PX key derivation `derivation`.
    /// The words do not record the derivation (docs/px.md §3.1): a seed from
    /// a wallet created before derivation 2 must be restored with 1, or its
    /// PX records are not found. The v1 funds are found either way.
    pub fn from_mnemonic_with(
        network: Network,
        words: &str,
        restore_height: u64,
        derivation: Derivation,
    ) -> Result<Self, WalletError> {
        let m = bip39::Mnemonic::parse_normalized(words.trim())
            .map_err(|e| WalletError::Serialization(format!("mnemonic: {e}")))?;
        let mut entropy = m.to_entropy();
        let seed: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::Serialization("mnemonic must have 24 words".into()))?;
        entropy.zeroize();
        Ok(Self::from_seed_with(
            network,
            seed,
            restore_height,
            derivation,
        ))
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The PX key derivation of this wallet.
    pub fn derivation(&self) -> Derivation {
        self.derivation
    }

    /// The full viewing key of PX address range `range` (addresses
    /// `range·2^16 ..`), for an auditor or a watch-only service: it sees the
    /// records received in that range and their spends, and cannot spend.
    /// `None` under derivation 1. Sensitive; there is no CLI export yet.
    pub fn px_range_view(&self, range: u32) -> Option<pxw::RangeViewKey> {
        self.px_account.range_view(range)
    }

    pub fn synced_height(&self) -> u64 {
        self.synced_height
    }

    fn rebuild_table(&mut self) {
        self.table = SubaddressTable::default();
        let issued: Vec<(u32, u32)> = self.issued.iter().map(|(&a, &i)| (a, i)).collect();
        for (account, i) in issued {
            self.extend_window(account, None, i);
        }
    }

    /// Adds to the scan table the indexes that raising `account`'s issued
    /// index from `from` (`None`: a new account) to `to` brings into the
    /// window `0..=issued + LOOKAHEAD`.
    fn extend_window(&mut self, account: u32, from: Option<u32>, to: u32) {
        let start = match from {
            None => 0,
            Some(f) => match f.saturating_add(LOOKAHEAD).checked_add(1) {
                Some(s) => s,
                None => return,
            },
        };
        for i in start..=to.saturating_add(LOOKAHEAD) {
            self.table
                .insert(self.keys.view_keys(), SubaddressIndex::new(account, i));
        }
    }

    /// The highest subaddress index of `account` that has received funds.
    fn used_index(&self, account: u32) -> Option<u32> {
        self.outputs
            .iter()
            .filter(|o| o.account == account)
            .map(|o| o.index)
            .max()
    }

    /// Records that `(account, index)` received funds: the account's window
    /// moves so that it stays `LOOKAHEAD` ahead of it (gap-limit scan, review
    /// M-2). Returns whether the window grew.
    fn note_used(&mut self, account: u32, index: u32) -> bool {
        let current = self.issued.get(&account).copied();
        if current.is_some_and(|c| c >= index) {
            return false;
        }
        self.issued.insert(account, index);
        self.extend_window(account, current, index);
        true
    }

    /// The highest index allowed to be handed out now, relative to the highest
    /// used one (`base`).
    fn index_limit(base: Option<u32>, gap: u32, hard: u32, force: bool) -> u32 {
        base.unwrap_or(0)
            .saturating_add(if force { hard } else { gap })
    }

    /// The address string for `(account, index)`, extending the scan window
    /// to cover it (a new account included).
    ///
    /// Refused (`WalletError::AddressIndex`) when `index` is more than
    /// `GAP_LIMIT` beyond the highest index of the account that has received
    /// funds, unless `force`; and beyond `MAX_INDEX_AHEAD` in any case. Each
    /// index in the window costs a derivation at every load and a table entry,
    /// so an unbounded index would make the wallet file unusable (review M-1).
    /// Indexes up to the highest already handed out are always allowed.
    ///
    /// A wallet restored from the seed scans account 0 only, `LOOKAHEAD`
    /// beyond the last index found (`found_by_restore`).
    pub fn try_address(
        &mut self,
        account: u32,
        index: u32,
        force: bool,
    ) -> Result<String, WalletError> {
        let current = self.issued.get(&account).copied();
        if current.is_none_or(|c| index > c) {
            let base = self.used_index(account);
            let limit = Self::index_limit(base, GAP_LIMIT, MAX_INDEX_AHEAD, force);
            if index > limit {
                return Err(WalletError::AddressIndex {
                    index,
                    limit,
                    forced: force,
                });
            }
            self.issued
                .insert(account, current.map_or(index, |c| c.max(index)));
            self.extend_window(account, current, index);
        }
        Ok(encode_address(
            self.network,
            &self.keys.address(SubaddressIndex::new(account, index)),
        ))
    }

    /// `try_address` without the override.
    ///
    /// # Panics
    /// If `index` is beyond the gap limit (see `try_address`).
    pub fn address(&mut self, account: u32, index: u32) -> String {
        self.try_address(account, index, false)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// Whether a wallet restored from the seed now would find payments to
    /// `(account, index)` by itself: it scans account 0 only, and only
    /// `LOOKAHEAD` beyond the highest index found.
    pub fn found_by_restore(&self, account: u32, index: u32) -> bool {
        account == 0 && index <= self.used_index(0).unwrap_or(0).saturating_add(LOOKAHEAD)
    }

    /// Problems found and repaired when the wallet was loaded, for the user.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    pub fn primary(&self) -> Address {
        self.keys.address(SubaddressIndex::PRIMARY)
    }

    // ---- persistence ----

    pub fn to_json(&self) -> Vec<u8> {
        let p = Persisted {
            version: file_version(self.derivation),
            derivation: Some(self.derivation.number()),
            output_index: self.index.clone(),
            network: network_name(self.network).into(),
            seed: SecretString(Zeroizing::new(hex::encode(self.seed))),
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
            rings: self.rings.clone(),
        };
        serde_json::to_vec(&p).expect("serializable")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, WalletError> {
        let p: Persisted =
            serde_json::from_slice(bytes).map_err(|e| WalletError::Serialization(e.to_string()))?;
        // Files without a derivation predate it: derivation 1.
        let derivation = Derivation::from_number(p.derivation.unwrap_or(1));
        let derivation = match (p.version, derivation) {
            (1 | 2, Some(d)) if file_version(d) == p.version => d,
            (1 | 2, _) => {
                return Err(WalletError::Serialization(format!(
                    "wallet file version {} with PX key derivation {:?}",
                    p.version, p.derivation
                )))
            }
            _ => {
                return Err(WalletError::Serialization(format!(
                    "unsupported version {}",
                    p.version
                )))
            }
        };
        let network = parse_network(&p.network)
            .ok_or_else(|| WalletError::Serialization("network".into()))?;
        let mut seed = h32(&p.seed.0)?;
        let mut w = Self::from_seed_with(network, seed, p.restore_height, derivation);
        seed.zeroize();
        w.index = p.output_index;
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
        w.rings = p.rings;
        w.repair_windows();
        w.rebuild_table();
        Ok(w)
    }

    /// Brings loaded scan windows within the limits (review M-1, M-2):
    /// - an issued index beyond `MAX_INDEX_AHEAD` above the highest used one
    ///   (possible in files of older versions, which had no limit) is clamped,
    ///   with a warning, instead of deriving billions of keys at every load;
    /// - an index that received funds but lies above `issued` (older versions
    ///   did not move the window when scanning) raises `issued`.
    fn repair_windows(&mut self) {
        let mut used: BTreeMap<u32, u32> = BTreeMap::new();
        for o in &self.outputs {
            let u = used.entry(o.account).or_insert(o.index);
            *u = (*u).max(o.index);
        }
        for (&account, issued) in self.issued.iter_mut() {
            let base = used.get(&account).copied();
            let cap = Self::index_limit(base, GAP_LIMIT, MAX_INDEX_AHEAD, true);
            if *issued > cap {
                self.warnings.push(format!(
                    "account {account}: the scan window reached subaddress {issued}, beyond the \
                     limit of {cap}; it was reduced to {cap}. Payments to subaddresses above \
                     {cap} will not be found"
                ));
                *issued = cap;
            }
        }
        for (account, u) in used {
            let issued = self.issued.entry(account).or_insert(u);
            *issued = (*issued).max(u);
        }
        let base = self.px.used_index();
        let cap = Self::index_limit(base, PX_GAP_LIMIT, PX_MAX_INDEX_AHEAD, true);
        if self.px.issued > cap {
            self.warnings.push(format!(
                "the PX scan window reached address {}, beyond the limit of {cap}; it was \
                 reduced to {cap}. Records sent to PX addresses above {cap} will not be found",
                self.px.issued
            ));
            self.px.issued = cap;
        }
        if let Some(u) = base {
            self.px.issued = self.px.issued.max(u);
        }
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
        self.index.rewind(height);
        self.px.rewind(height);
        self.synced_height = height;
    }

    /// Scans new blocks. Detects reorganizations by comparing stored block ids with
    /// the node's, and rewinds to the fork point. Returns the new synced height.
    pub fn sync(&mut self, node: &dyn NodeApi) -> Result<u64, WalletError> {
        let info = self.check_network(node)?;
        if info.header_height > info.height {
            return Err(WalletError::Node(format!(
                "the node is still synchronizing ({} of {} blocks); try again later",
                info.height, info.header_height
            )));
        }
        // Reorg detection: walk back from our tip until our block id matches the node's.
        let fresh = self.block_ids.is_empty();
        while self.synced_height >= self.restore_height && self.synced_height > 0 {
            let Some(ours) = self.block_ids.get(&self.synced_height).copied() else {
                if fresh {
                    break;
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
                // Each block must extend the one before it (review F6). Proof of
                // work is not checked here: a wallet must trust its node for that.
                if let Some(prev) = self.block_ids.get(&(entry.height - 1)) {
                    if block.header.prev_id != *prev {
                        return Err(WalletError::BadNodeData(format!(
                            "block {from} does not extend the previous block"
                        )));
                    }
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
        // Every output, in the chain's global order (as `scan_block` counts).
        self.index.push_block(
            height,
            first_output,
            block.txs.iter().flat_map(|tx| {
                let coinbase = tx.is_coinbase();
                tx.output_keys()
                    .into_iter()
                    .map(move |k| (*k.one_time_key.bytes(), *k.commitment.bytes(), coinbase))
            }),
        );
        self.px
            .apply_block(&mut self.px_keys, &self.px_account, &block.txs, height);
        // Gap-limit scan (review M-2): an output found near the edge of the
        // window moves the window, and the block is scanned again with it, so
        // later outputs of the same block (and later blocks) are found too.
        loop {
            let report = scan_block(
                self.keys.view_keys(),
                &self.table,
                &block.txs,
                height,
                first_output,
            );
            let mut grew = false;
            for o in report.owned {
                if self
                    .outputs
                    .iter()
                    .any(|s| s.global_index == o.global_index)
                {
                    continue;
                }
                let ki = o.key_image(&self.keys);
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
                    tx: Some(hex::encode(o.tx_hash)),
                });
                grew |= self.note_used(subaddress.account, subaddress.index);
            }
            if !grew {
                break;
            }
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
    /// Meant for a transaction that certainly never left this wallet. The rings
    /// of submitted transactions are kept (`rings`), so a new spend of the same
    /// inputs reuses them; but the new transaction still shares the key images,
    /// so observers can link the two spends.
    pub fn clear_pending(&mut self) {
        for o in &mut self.outputs {
            o.pending = false;
        }
        self.px.clear_pending();
        self.pending_txs.clear();
    }

    /// Makes every submission save the wallet to `path` **before** the
    /// transaction is sent, and again after the node's answer. If the first save
    /// fails, nothing is sent. Without it, a crash between sending and the
    /// caller's save would lose the reservation, the stored transaction and
    /// its rings.
    pub fn set_autosave(
        &mut self,
        path: &std::path::Path,
        password: &[u8],
        kdf: crate::file::KdfParams,
    ) {
        self.autosave = Some(AutoSave {
            path: path.to_path_buf(),
            password: zeroize::Zeroizing::new(password.to_vec()),
            kdf,
        });
    }

    fn persist(&self) -> Result<(), WalletError> {
        match &self.autosave {
            Some(a) => crate::save(self, &a.path, &a.password, a.kdf)
                .map_err(|e| WalletError::Serialization(format!("saving the wallet: {e}"))),
            None => Ok(()),
        }
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
        // Record everything before the transaction can leave: its reservation,
        // the stored copy, and its rings. Rings are kept even if the node then
        // refuses: reusing a ring that never became public costs nothing, and
        // the node's answer cannot be verified (review F5).
        self.for_each_input(&tx, |_, pending, h| {
            *pending = true;
            *h = at;
        });
        self.pending_txs.push(PendingTx {
            tx: hex::encode(&bytes),
            relayed_height: at,
        });
        let kis: HashSet<String> = tx
            .key_images()
            .iter()
            .map(|k| hex::encode(k.bytes()))
            .collect();
        for (ki, ring) in std::mem::take(&mut self.staged_rings) {
            if kis.contains(&ki) {
                self.rings.insert(ki, ring);
            }
        }
        if let Err(e) = self.persist() {
            // Not sent: undo the reservation.
            self.forget(&tx);
            return Err(e);
        }
        let result = match node.submit_tx(&bytes) {
            Err(e) => Err(WalletError::Uncertain(e)),
            Ok(r)
                if r.accepted
                    || r.error
                        .as_deref()
                        .is_some_and(|e| e.starts_with("AlreadyKnown")) =>
            {
                Ok(id)
            }
            // Refused by the only node that saw it (as far as we can tell).
            Ok(r) => {
                self.forget(&tx);
                Err(WalletError::Rejected(r.error.unwrap_or_default()))
            }
        };
        // Best effort: the state that matters was saved before sending.
        let _ = self.persist();
        result
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
            // Kept until every input is known spent and buried. Inputs the
            // wallet does not currently see (a node behind the wallet, a
            // rewind) do not count as buried (review F3).
            let (mut found, mut unspent, mut buried) = (false, false, true);
            self.for_each_input(&tx, |spent, _, _| {
                found = true;
                match spent {
                    None => {
                        unspent = true;
                        buried = false;
                    }
                    Some(h) => buried &= synced >= h + RING_RETENTION_BLOCKS,
                }
            });
            if found && buried {
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
        // A ring is needed while its output may still be spent again: until the
        // spend is buried, or while a stored transaction still spends it.
        // Only rings of outputs known to be spent and buried beyond the
        // wallet's reorganization window are dropped (review F3, F9).
        let outputs = &self.outputs;
        self.rings.retain(|ki, _| {
            covered_kis.contains(ki)
                || !outputs.iter().any(|o| {
                    o.key_image == *ki
                        && o.spent_height
                            .is_some_and(|h| synced >= h + RING_RETENTION_BLOCKS)
                })
        });
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

    /// Adds inputs from `order` (largest first) until `enough(count, sum)`.
    ///
    /// Merge avoidance (review R3-13): spending two outputs of one transaction
    /// together tells observers that both real inputs came from it (Kumar et
    /// al. 2017; Möser et al. 2018). So the first pass takes at most one output
    /// per source transaction; only if that cannot cover the amount does a
    /// plain largest-first pass run. Returns the inputs and whether they
    /// include two outputs of one source, or `None` if everything is not
    /// enough. The result may exceed `MAX_INPUTS`; callers refuse that.
    fn gather(
        &self,
        order: &[usize],
        enough: impl Fn(usize, u128) -> bool,
    ) -> Option<(Vec<usize>, bool)> {
        let mut sources = HashSet::new();
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in order {
            if chosen.len() == MAX_INPUTS {
                break;
            }
            if sources.insert(self.outputs[i].source()) {
                chosen.push(i);
                sum += self.outputs[i].amount as u128;
                if enough(chosen.len(), sum) {
                    return Some((chosen, false));
                }
            }
        }
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in order {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            if chosen.len() > MAX_INPUTS {
                return Some((chosen, false));
            }
            if enough(chosen.len(), sum) {
                let distinct: HashSet<String> =
                    chosen.iter().map(|&i| self.outputs[i].source()).collect();
                let merged = distinct.len() < chosen.len();
                return Some((chosen, merged));
            }
        }
        None
    }

    /// The warning for inputs that include outputs of one source transaction.
    fn merge_warning(&mut self) {
        self.warnings.push(
            "this transaction spends two or more outputs that were created by the same \
             transaction; observers can link them and guess the real inputs of its rings \
             (there was no other way to cover the amount)"
                .into(),
        );
    }

    /// Chooses inputs: the smallest single output that covers everything if one
    /// exists (fewest inputs, least change linkage), otherwise largest-first,
    /// avoiding outputs of one source transaction together (`gather`).
    fn select_inputs(
        &mut self,
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
        candidates.reverse();
        let fee = |n: usize| standard_fee(n, payments + 1, rules);
        match self.gather(&candidates, |n, sum| sum >= amount as u128 + fee(n) as u128) {
            Some((chosen, _)) if chosen.len() > MAX_INPUTS => Err(WalletError::TooManyInputs),
            Some((chosen, merged)) => {
                if merged {
                    self.merge_warning();
                }
                let f = fee(chosen.len());
                Ok((chosen, f))
            }
            None => Err(WalletError::InsufficientFunds {
                available,
                needed: amount.saturating_add(fee(candidates.len().max(1))),
            }),
        }
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
        let (inputs, fee) = self.select_inputs(amount, 1, rules)?;
        let plans = self.plans_for(node, &inputs, rng)?;
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

    /// The PX address `index`, as a string, extending the scan window to it.
    ///
    /// Refused (`WalletError::AddressIndex`) beyond `PX_GAP_LIMIT` above the
    /// highest PX address that has received a record, unless `force`, and
    /// beyond `PX_MAX_INDEX_AHEAD` in any case: every scanned PX address costs
    /// a scalar multiplication for every PX output on chain (review M-1).
    pub fn try_px_address(&mut self, index: u32, force: bool) -> Result<String, WalletError> {
        if index > self.px.issued {
            let limit = Self::index_limit(
                self.px.used_index(),
                PX_GAP_LIMIT,
                PX_MAX_INDEX_AHEAD,
                force,
            );
            if index > limit {
                return Err(WalletError::AddressIndex {
                    index,
                    limit,
                    forced: force,
                });
            }
            self.px.issued = index;
        }
        Ok(blacksilk_chain::address::encode_px_address(
            self.network,
            &self.px_account.address(index),
        ))
    }

    /// `try_px_address` without the override.
    ///
    /// # Panics
    /// If `index` is beyond the gap limit (see `try_px_address`).
    pub fn px_address(&mut self, index: u32) -> String {
        self.try_px_address(index, false)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// Whether a wallet restored from the seed now would find records sent to
    /// PX address `index` by itself (`PX_LOOKAHEAD` beyond the highest found).
    pub fn px_found_by_restore(&self, index: u32) -> bool {
        index
            <= self
                .px
                .used_index()
                .unwrap_or(0)
                .saturating_add(PX_LOOKAHEAD)
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
        &mut self,
        node: &dyn NodeApi,
        needed: u64,
        rng: &mut R,
    ) -> Result<(Vec<usize>, Vec<InputPlan>), WalletError> {
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.outputs[i].amount));
        let chosen = match self.gather(&candidates, |_, sum| sum >= needed as u128) {
            Some((chosen, _)) if chosen.len() > MAX_INPUTS => {
                return Err(WalletError::TooManyInputs)
            }
            Some((chosen, merged)) => {
                if merged {
                    self.merge_warning();
                }
                chosen
            }
            None => {
                return Err(WalletError::InsufficientFunds {
                    available: candidates.iter().map(|&i| self.outputs[i].amount).sum(),
                    needed,
                })
            }
        };
        let plans = self.plans_for(node, &chosen, rng)?;
        Ok((chosen, plans))
    }

    /// Makes the local output index (`crate::index`) cover every output up to
    /// `total` (the node's count through the synced height).
    ///
    /// Outputs the wallet never scanned (below its restore height, or all of
    /// them for a wallet file written before the index existed) are fetched
    /// with `/outputs` **once**, as the whole missing range in fixed pages of
    /// `MAX_OUTPUTS_PER_REQUEST` consecutive indices. The requests depend only
    /// on the index's extent, never on which outputs the wallet spends, so
    /// they reveal nothing about rings (review I3 §3.9; F2 is thereby moot).
    fn complete_index(&mut self, node: &dyn NodeApi, total: u64) -> Result<(), WalletError> {
        // Nothing indexed (an older wallet file with no block synced since):
        // everything through the synced height is missing.
        let end = if self.index.is_empty() {
            total
        } else if self.index.end() != total {
            return Err(WalletError::BadNodeData(format!(
                "the node counts {total} outputs through block {}, the blocks it sent {}",
                self.synced_height,
                self.index.end()
            )));
        } else {
            self.index.start()
        };
        if end == 0 {
            return Ok(());
        }
        let page = blacksilk_rpc::MAX_OUTPUTS_PER_REQUEST as u64;
        // Not pre-allocated: `end` comes from the node.
        let mut older: Vec<IndexedOutput> = Vec::new();
        let mut from = 0u64;
        while from < end {
            let to = (from + page).min(end);
            let query: Vec<u64> = (from..to).collect();
            let fetched = node.outputs(&query).map_err(WalletError::Node)?.outputs;
            if fetched.len() != query.len()
                || fetched.iter().zip(&query).any(|(f, i)| f.index != *i)
            {
                return Err(WalletError::BadNodeData(
                    "outputs do not match the request".into(),
                ));
            }
            for f in fetched {
                let key = h32(&f.one_time_key)?;
                let commitment = h32(&f.commitment)?;
                if Point::decode(&key).is_none() || Point::decode(&commitment).is_none() {
                    return Err(WalletError::BadNodeData(
                        "an output key is not a point".into(),
                    ));
                }
                older.push(IndexedOutput {
                    one_time_key: key,
                    commitment,
                    height: f.height,
                    coinbase: f.coinbase,
                });
            }
            from = to;
        }
        self.index
            .prepend(older, end)
            .map_err(WalletError::BadNodeData)?;
        if !self.index.is_complete(total) {
            return Err(WalletError::BadNodeData(
                "the output index does not match the node's distribution".into(),
            ));
        }
        Ok(())
    }

    /// Rings for the v1 outputs `chosen`, staged for `submit`.
    ///
    /// Privacy of ring construction (review I3 §3.9, docs/reviews/wallet-review.md
    /// F2): ring members are resolved from the local output index, so the node
    /// is not asked about any of them. Only the output distribution (one
    /// request, for the synced height) and, once, a backfill of outputs older
    /// than the restore height (`complete_index`) come from the node.
    ///
    /// Decoys follow the gamma picker with coinbase maturity applied inside the
    /// draw (`blacksilk_tx::decoy`, review R3-1). An output spent before in a
    /// submitted transaction gets that ring again (W-5), as far as its members
    /// still exist unchanged and are eligible.
    fn plans_for<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        chosen: &[usize],
        rng: &mut R,
    ) -> Result<Vec<InputPlan>, WalletError> {
        let next = self.synced_height + 1;
        let dist = node
            .distribution(self.synced_height)
            .map_err(WalletError::Node)?;
        let cumulative = &dist.cumulative;
        let total = *cumulative
            .get(self.synced_height as usize)
            .ok_or_else(|| WalletError::BadNodeData("short output distribution".into()))?;
        self.complete_index(node, total)?;
        let target = ChainParams::for_network(self.network).target_block_time;
        let decoy_err = |e| WalletError::Decoys(format!("{e:?}"));
        let usable = blacksilk_tx::decoy::usable_outputs(cumulative, next).map_err(decoy_err)?;
        // Coinbase outputs of blocks `0..=next − 60` are mature.
        let coinbase_limit = next
            .checked_sub(COINBASE_MATURITY)
            .and_then(|h| cumulative.get(h as usize).copied())
            .unwrap_or(0);
        let index = &self.index;
        let eligible = |i: u64| {
            i < usable
                && index
                    .get(i)
                    .is_some_and(|e| !(e.coinbase && i >= coinbase_limit))
        };
        let member = |i: u64| -> Result<Decoy, WalletError> {
            let e = index
                .get(i)
                .ok_or_else(|| WalletError::Decoys(format!("output {i} is not indexed")))?;
            let bad = || WalletError::BadNodeData(format!("output {i} is not a point"));
            Ok(Decoy {
                global_index: i,
                key: OutputKey {
                    one_time_key: Point::decode(&e.one_time_key).ok_or_else(bad)?,
                    commitment: Point::decode(&e.commitment).ok_or_else(bad)?,
                },
            })
        };
        let mut plans = Vec::with_capacity(chosen.len());
        let mut staged = Vec::with_capacity(chosen.len());
        for &i in chosen {
            let o = &self.outputs[i];
            let real = o.global_index;
            if real >= usable {
                return Err(WalletError::Decoys("output not yet usable".into()));
            }
            // Our own output, as scanned, must be what the index holds.
            let own = index
                .get(real)
                .ok_or_else(|| WalletError::Decoys("own output not indexed".into()))?;
            if hex::encode(own.one_time_key) != o.one_time_key
                || hex::encode(own.commitment) != o.commitment
            {
                return Err(WalletError::BadNodeData(
                    "the output index disagrees on our output".into(),
                ));
            }
            // Stored members are kept only if the index still holds the same
            // output at that position (a reorganization may have moved it).
            let keep: Vec<u64> = self
                .rings
                .get(&o.key_image)
                .map(|m| {
                    m.iter()
                        .filter(|m| {
                            index.get(m.index).is_some_and(|e| {
                                hex::encode(e.one_time_key) == m.one_time_key
                                    && hex::encode(e.commitment) == m.commitment
                            })
                        })
                        .map(|m| m.index)
                        .collect()
                })
                .unwrap_or_default();
            let ring = blacksilk_tx::decoy::select_ring_keeping(
                rng, cumulative, next, target, real, &keep, eligible,
            )
            .map_err(decoy_err)?;
            let decoys = ring
                .iter()
                .filter(|&&m| m != real)
                .map(|&m| member(m))
                .collect::<Result<Vec<Decoy>, WalletError>>()?;
            staged.push((
                o.key_image.clone(),
                decoys.iter().map(RingMember::of).collect(),
            ));
            plans.push(InputPlan {
                real: Self::to_spendable(o)?,
                decoys,
            });
        }
        self.staged_rings = staged;
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
                hedge_secret: self.px_account.hedge_secret(),
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
                hedge_secret: self.px_account.hedge_secret(),
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
                hedge_secret: self.px_account.hedge_secret(),
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
        check_vault_deploy(&programs)?;
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

    /// The budget of the reference vault under `contract`, if the contract is
    /// a vault this wallet can safely use: the vault program alone, with the
    /// reference budget (`PxStore::vault_budget`, reviews P-1 and P-2).
    fn vault_budget(
        &self,
        contract: &Digest,
    ) -> Result<blacksilk_zkvm::air::trace::Budget, WalletError> {
        self.px.vault_budget(contract)
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
                hedge_secret: self.px_account.hedge_secret(),
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
        // And the secret: `submit` saves the wallet before sending, so it is
        // on disk before the lock can exist on chain (review R11-W1).
        self.px.set_secret(&cm, secret);
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
                hedge_secret: self.px_account.hedge_secret(),
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

    /// The secret of vault record `record`, if this wallet locked it (stored
    /// before the lock was sent). Checked against the record's lock.
    pub fn px_vault_secret(&self, record: &Digest) -> Result<Zeroizing<Digest>, WalletError> {
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown contract record".into()))?;
        let r = &self.px.contract_records[k];
        let hex = r.secret.as_deref().ok_or_else(|| {
            WalletError::Contract(
                "no secret stored for this record (not locked by this wallet)".into(),
            )
        })?;
        let secret = Zeroizing::new(crate::px::digest_from_hex(hex)?);
        if vault::lock_of(&secret) != r.record()?.data {
            return Err(WalletError::Contract(
                "the stored secret does not open this record".into(),
            ));
        }
        Ok(secret)
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
        let secret = zeroize::Zeroizing::new(self.px_account.hedge_secret());
        share::seal_share(rng, secret.as_slice(), to, &rec, record)
            .map_err(|_| WalletError::Contract("the recipient address does not decode".into()))
    }

    /// Imports a shared contract-record opening addressed to one of this
    /// wallet's PX addresses. It counts as confirmed once its commitment is
    /// found on chain (the next sync). Returns its commitment.
    pub fn px_import(&mut self, shared: &[u8]) -> Result<Digest, WalletError> {
        for index in 0..=self.px.issued.saturating_add(PX_LOOKAHEAD) {
            let (keys, owner) = self.px_keys.get(&self.px_account, index);
            let Some((rec, cm)) = share::open_share(keys, owner, shared) else {
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

/// Refuses a deploy that registers the reference vault next to other programs,
/// or with a budget other than `vault::BUDGET`: the wallet would refuse to use
/// such a contract as a vault (`PxStore::vault_budget`, reviews P-1, P-2), and
/// a contract's records can be spent by any of its programs.
pub fn check_vault_deploy(programs: &[Registration]) -> Result<(), WalletError> {
    let vault_id = vault::program().id();
    let mut has_vault = false;
    for r in programs {
        let id = blacksilk_zkvm::Program::from_elf(&r.elf)
            .map_err(|e| WalletError::Contract(format!("a program does not load: {e:?}")))?
            .id();
        if id == vault_id {
            has_vault = true;
            if r.budget != vault::BUDGET {
                return Err(WalletError::Contract(
                    "the vault must be registered with its reference budget (vault::BUDGET)".into(),
                ));
            }
        }
    }
    if has_vault && programs.len() > 1 {
        return Err(WalletError::Contract(
            "the vault must be deployed alone: any other program of the same contract could \
             spend the vault's records without the secret (docs/px.md §13.4)"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::px::{digest_hex, KnownProgram};
    use blacksilk_rpc as rpc;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn wallet() -> Wallet {
        Wallet::from_seed(Network::Regtest, [7; 32], 1)
    }

    fn scanned(w: &Wallet, account: u32, index: u32) -> bool {
        let a = w.keys.address(SubaddressIndex::new(account, index));
        w.table.lookup(a.spend().bytes()).is_some()
    }

    #[test]
    fn subaddress_indexes_beyond_the_gap_limit_need_the_override() {
        let mut w = wallet();
        assert!(w.try_address(0, GAP_LIMIT, false).is_ok());
        // Nothing has been received: the base stays 0, whatever was issued.
        assert!(matches!(
            w.try_address(0, GAP_LIMIT + 1, false),
            Err(WalletError::AddressIndex {
                limit: GAP_LIMIT,
                forced: false,
                ..
            })
        ));
        // Anything up to the highest handed out stays available.
        assert!(w.try_address(0, 17, false).is_ok());
        // The override reaches the hard ceiling, never beyond.
        assert!(w.try_address(0, MAX_INDEX_AHEAD, true).is_ok());
        assert!(scanned(&w, 0, MAX_INDEX_AHEAD + LOOKAHEAD));
        assert!(!scanned(&w, 0, MAX_INDEX_AHEAD + LOOKAHEAD + 1));
        assert!(matches!(
            w.try_address(0, MAX_INDEX_AHEAD + 1, true),
            Err(WalletError::AddressIndex { forced: true, .. })
        ));
        assert!(w.try_address(0, u32::MAX, true).is_err());
        // The window is extended incrementally: exactly issued + LOOKAHEAD + 1.
        assert_eq!(w.table.len(), (MAX_INDEX_AHEAD + LOOKAHEAD + 1) as usize);
    }

    #[test]
    fn the_limit_follows_the_highest_index_that_received_funds() {
        let mut w = wallet();
        w.outputs.push(StoredOutput {
            global_index: 0,
            height: 1,
            coinbase: false,
            account: 0,
            index: 4_000,
            amount: 1,
            one_time_key: String::new(),
            commitment: String::new(),
            mask: String::new(),
            offset: String::new(),
            key_image: String::new(),
            spent_height: None,
            pending: false,
            pending_height: 0,
            tx: None,
        });
        assert!(w.try_address(0, 4_000 + GAP_LIMIT, false).is_ok());
        assert!(w.try_address(0, 4_001 + GAP_LIMIT, false).is_err());
        // Another account has its own base.
        assert!(w.try_address(1, GAP_LIMIT + 1, false).is_err());
    }

    #[test]
    fn a_new_account_is_scanned_from_index_zero_at_once() {
        // L-1: the first address of a new account used to be added to
        // `issued` without extending the scan table until the next load.
        let mut w = wallet();
        assert!(!scanned(&w, 3, 0));
        w.try_address(3, 0, false).unwrap();
        assert!(scanned(&w, 3, 0));
        assert!(scanned(&w, 3, LOOKAHEAD));
        assert!(!scanned(&w, 3, LOOKAHEAD + 1));
        // The same as a freshly loaded wallet.
        let loaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(loaded.table.len(), w.table.len());
    }

    #[test]
    fn finding_funds_moves_the_window() {
        let mut w = wallet();
        assert!(!scanned(&w, 0, 95));
        assert!(w.note_used(0, 45));
        assert_eq!(w.issued[&0], 45);
        assert!(scanned(&w, 0, 95));
        assert!(!scanned(&w, 0, 96));
        assert!(!w.note_used(0, 30), "below the window's issued index");
    }

    #[test]
    fn absurd_scan_windows_in_old_files_are_clamped_on_load() {
        // M-1: a file whose issued index is huge must load quickly, not derive
        // billions of keys.
        let mut w = wallet();
        w.issued.insert(0, u32::MAX);
        w.issued.insert(2, 3_000_000_000);
        w.px.issued = u32::MAX;
        let json = w.to_json();
        let t = std::time::Instant::now();
        let mut loaded = Wallet::from_json(&json).unwrap();
        let took = t.elapsed();
        eprintln!("load with two clamped accounts: {took:?}");
        assert_eq!(loaded.issued[&0], MAX_INDEX_AHEAD);
        assert_eq!(loaded.issued[&2], MAX_INDEX_AHEAD);
        assert_eq!(loaded.px.issued, PX_MAX_INDEX_AHEAD);
        let warnings = loaded.take_warnings();
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(loaded.take_warnings().is_empty());
        assert!(took < std::time::Duration::from_secs(60));
    }

    #[test]
    fn old_files_with_funds_above_the_window_raise_it_on_load() {
        // M-2 migration: older versions never moved `issued` when scanning.
        let mut w = wallet();
        w.outputs.push(StoredOutput {
            global_index: 0,
            height: 1,
            coinbase: false,
            account: 0,
            index: 40,
            amount: 1,
            one_time_key: String::new(),
            commitment: String::new(),
            mask: String::new(),
            offset: String::new(),
            key_image: String::new(),
            spent_height: None,
            pending: false,
            pending_height: 0,
            tx: None,
        });
        let loaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(loaded.issued[&0], 40);
        assert!(scanned(&loaded, 0, 90));
    }

    #[test]
    fn px_address_indexes_beyond_the_gap_limit_need_the_override() {
        let mut w = wallet();
        assert!(w.try_px_address(PX_GAP_LIMIT, false).is_ok());
        assert!(w.try_px_address(PX_GAP_LIMIT + 1, false).is_err());
        assert!(w.try_px_address(PX_MAX_INDEX_AHEAD, true).is_ok());
        assert_eq!(w.px.issued, PX_MAX_INDEX_AHEAD);
        assert!(w.try_px_address(PX_MAX_INDEX_AHEAD + 1, true).is_err());
        assert!(w.try_px_address(3, false).is_ok());
        assert_eq!(w.px.issued, PX_MAX_INDEX_AHEAD);
    }

    #[test]
    fn secrets_stay_out_of_error_messages() {
        let secret = "5ec2e7".repeat(10);
        let e = h32(&secret).unwrap_err().to_string();
        assert!(!e.contains("5ec2e7"), "{e}");
        let mut json: serde_json::Value = serde_json::from_slice(&wallet().to_json()).unwrap();
        json["seed"] = serde_json::Value::String(secret.clone());
        let e = Wallet::from_json(&serde_json::to_vec(&json).unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(!e.contains("5ec2e7"), "{e}");
    }

    #[test]
    fn the_mnemonic_round_trips_without_reallocating() {
        let w = wallet();
        let m = w.mnemonic();
        assert_eq!(m.split(' ').count(), 24);
        assert!(m.capacity() == 256, "written into the preallocated buffer");
        let r = Wallet::from_mnemonic(Network::Regtest, &m, 1).unwrap();
        assert_eq!(r.seed, w.seed);
    }

    #[test]
    fn deploys_mixing_the_vault_with_other_programs_are_refused() {
        let vault = Registration {
            elf: vault::VAULT_ELF.to_vec(),
            budget: vault::BUDGET,
        };
        let other = Registration {
            elf: include_bytes!("../../zkvm/tests/fixtures/guest-sum.elf").to_vec(),
            budget: vault::BUDGET,
        };
        assert!(check_vault_deploy(std::slice::from_ref(&vault)).is_ok());
        assert!(check_vault_deploy(std::slice::from_ref(&other)).is_ok());
        assert!(check_vault_deploy(&[vault.clone(), other.clone()]).is_err());
        assert!(check_vault_deploy(&[other, vault.clone()]).is_err());
        let odd = Registration {
            budget: blacksilk_zkvm::air::trace::Budget {
                cycles: vault::BUDGET.cycles * 2,
                ..vault::BUDGET
            },
            ..vault
        };
        assert!(check_vault_deploy(&[odd]).is_err());
    }

    #[test]
    fn a_stored_vault_secret_survives_a_save_and_load() {
        // R11-W1: the secret of a lock this wallet created is kept in the
        // encrypted file (px_vault_lock stores it before `submit` saves).
        let secret = [21, 22, 23, 24, 25, 26, 27, 28];
        let record = Record {
            owner: ZERO_DIGEST,
            contract: [1, 0, 0, 0, 0, 0, 0, 0],
            asset: ZERO_DIGEST,
            value: 10,
            data: vault::lock_of(&secret),
            rho: [2, 0, 0, 0, 0, 0, 0, 0],
            rcm: [3, 0, 0, 0, 0, 0, 0, 0],
        };
        let cm = record.commit(&mut HostPerm::new());
        let mut w = wallet();
        w.px.add_contract_record(&record, &cm, RecordSource::Created, None);
        assert!(w.px_vault_secret(&cm).is_err(), "nothing stored yet");
        w.px.set_secret(&cm, &secret);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.wallet");
        let fast = crate::file::KdfParams {
            m_kib: 256,
            t: 1,
            p: 1,
        };
        crate::save(&w, &path, b"pw", fast).unwrap();
        drop(w);
        let loaded = crate::load(&path, b"pw").unwrap();
        assert_eq!(*loaded.px_vault_secret(&cm).unwrap(), secret);
        assert!(loaded.px_vault_secret(&[9; 8]).is_err(), "unknown record");
        // A stored secret that does not open the record is reported.
        let mut bad = loaded;
        bad.px.contract_records[0].secret = Some(digest_hex(&[1; 8]));
        assert!(bad.px_vault_secret(&cm).is_err());
    }

    /// A node at height 0 with an empty PX tree and the given registrations.
    struct Registry(Vec<rpc::PxContractEntry>);

    impl NodeApi for Registry {
        fn info(&self) -> Result<rpc::Info, String> {
            Ok(rpc::Info {
                network: "regtest".into(),
                network_id: 0,
                height: 0,
                tip: String::new(),
                difficulty: 1,
                generated: 0,
                mempool_txs: 0,
                mempool_bytes: 0,
                outputs: 0,
                peers: 0,
                header_height: 0,
                deepest_reorg: 0,
                misbehaving_disconnects: 0,
                genesis_id: None,
                consensus_fingerprint: None,
                build_commit: None,
                version: None,
            })
        }
        fn blocks(&self, _: u64, _: u64) -> Result<rpc::Blocks, String> {
            Ok(rpc::Blocks { blocks: vec![] })
        }
        fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
            Err("not used".into())
        }
        fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
            Err("not used".into())
        }
        fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
            Err("must not be reached".into())
        }
        fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
            Ok(rpc::PxCommitments {
                from,
                commitments: vec![],
                total: 0,
                root: digest_hex(&PxStore::default().tree().unwrap().root()),
                height: 0,
                next: None,
            })
        }
        fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
            Ok(rpc::PxContracts {
                from,
                contracts: self.0.iter().skip(from as usize).cloned().collect(),
                total: self.0.len() as u64,
                height: 0,
            })
        }
    }

    fn entry(
        contract: &Digest,
        programs: &[(String, blacksilk_zkvm::air::trace::Budget)],
    ) -> rpc::PxContractEntry {
        rpc::PxContractEntry {
            height: 0,
            id: digest_hex(contract),
            programs: programs
                .iter()
                .map(|(id, b)| {
                    let p = KnownProgram {
                        id: id.clone(),
                        budget: [
                            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                        ],
                    };
                    rpc::PxProgramEntry {
                        id: p.id,
                        budget: p.budget,
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn vault_lock_and_claim_refuse_unsafe_contracts_before_proving() {
        let vault_id = hex::encode(vault::program().id());
        let good = [1, 0, 0, 0, 0, 0, 0, 0];
        let mixed = [2, 0, 0, 0, 0, 0, 0, 0];
        let odd = [3, 0, 0, 0, 0, 0, 0, 0];
        let node = Registry(vec![
            entry(&good, &[(vault_id.clone(), vault::BUDGET)]),
            // P-1: Bob's contract: the vault and a backdoor.
            entry(
                &mixed,
                &[
                    (vault_id.clone(), vault::BUDGET),
                    ("ab".repeat(32), vault::BUDGET),
                ],
            ),
            // P-2: the vault alone with a budget too small for CLAIM.
            entry(
                &odd,
                &[(
                    vault_id,
                    blacksilk_zkvm::air::trace::Budget {
                        cycles: 64,
                        ..vault::BUDGET
                    },
                )],
            ),
        ]);
        let rules = TxRules::for_chain(&ChainParams::regtest());
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let secret = [5, 6, 7, 8, 9, 10, 11, 12];
        let mut w = wallet();
        // Lock: the safe vault passes the check and stops at the funds (this
        // wallet has none); the others are refused as contracts.
        let lock = |w: &mut Wallet, c: &Digest, rng: &mut ChaCha20Rng| {
            w.px_vault_lock(&node, c, 1, &secret, None, &rules, rng)
        };
        assert!(matches!(
            lock(&mut w, &good, &mut rng),
            Err(WalletError::InsufficientFunds { .. })
        ));
        for c in [&mixed, &odd] {
            assert!(matches!(
                lock(&mut w, c, &mut rng),
                Err(WalletError::Contract(_))
            ));
        }
        // Claim: a record of each contract, delivered to this wallet.
        let mut perm = HostPerm::new();
        let mut cms = Vec::new();
        for (i, c) in [good, mixed, odd].iter().enumerate() {
            let record = Record {
                owner: ZERO_DIGEST,
                contract: *c,
                asset: ZERO_DIGEST,
                value: 10,
                data: vault::lock_of(&secret),
                rho: [i as u32 + 1, 0, 0, 0, 0, 0, 0, 0],
                rcm: [i as u32 + 7, 0, 0, 0, 0, 0, 0, 0],
            };
            let cm = record.commit(&mut perm);
            w.px.add_contract_record(&record, &cm, RecordSource::Received { index: 0 }, Some(0));
            w.px.contract_records.last_mut().unwrap().position = Some(i as u64);
            cms.push(cm);
        }
        let claim = |w: &mut Wallet, cm: &Digest, rng: &mut ChaCha20Rng| {
            w.px_vault_claim(&node, cm, &secret, None, &rules, rng)
        };
        // The safe vault passes the check and stops later (this fake record
        // is not in the node's empty tree).
        assert!(matches!(
            claim(&mut w, &cms[0], &mut rng),
            Err(WalletError::BadNodeData(_))
        ));
        for cm in &cms[1..] {
            assert!(matches!(
                claim(&mut w, cm, &mut rng),
                Err(WalletError::Contract(_))
            ));
        }
    }

    /// Serves `/outputs` for any index (identity keys, 10 outputs per block,
    /// all coinbase) and records every request.
    #[derive(Default)]
    struct Pages(std::cell::RefCell<Vec<Vec<u64>>>);

    impl NodeApi for Pages {
        fn info(&self) -> Result<rpc::Info, String> {
            Err("not used".into())
        }
        fn blocks(&self, _: u64, _: u64) -> Result<rpc::Blocks, String> {
            Err("not used".into())
        }
        fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
            Err("not used".into())
        }
        fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
            self.0.borrow_mut().push(indices.to_vec());
            Ok(rpc::Outputs {
                outputs: indices
                    .iter()
                    .map(|&index| rpc::OutputEntry {
                        index,
                        one_time_key: "00".repeat(32),
                        commitment: "00".repeat(32),
                        height: index / 10,
                        coinbase: true,
                    })
                    .collect(),
            })
        }
        fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
            Err("not used".into())
        }
        fn px_commitments(&self, _: u64) -> Result<rpc::PxCommitments, String> {
            Err("not used".into())
        }
        fn px_contracts(&self, _: u64) -> Result<rpc::PxContracts, String> {
            Err("not used".into())
        }
    }

    /// Review I3 §3.9: outputs below the restore height are fetched once, as
    /// the whole missing range in fixed pages, whatever the wallet spends.
    #[test]
    fn the_backfill_fetches_the_whole_missing_range_in_fixed_pages() {
        let mut w = wallet();
        w.index
            .push_block(250, 2_500, [([0; 32], [0; 32], true); 3]);
        w.synced_height = 250;
        let node = Pages::default();
        w.complete_index(&node, 2_503).unwrap();
        {
            let q = node.0.borrow();
            let pages: Vec<(u64, u64)> = q.iter().map(|p| (p[0], p.len() as u64)).collect();
            assert_eq!(pages, [(0, 1_024), (1_024, 1_024), (2_048, 452)]);
            assert!(q.iter().all(|p| p.windows(2).all(|w| w[1] == w[0] + 1)));
        }
        assert!(w.index.is_complete(2_503));
        assert_eq!(w.index.get(1_234).unwrap().height, 123);
        // Complete: nothing more is fetched.
        w.complete_index(&node, 2_503).unwrap();
        assert_eq!(node.0.borrow().len(), 3);
        // A distribution that disagrees with the blocks is refused.
        assert!(matches!(
            w.complete_index(&node, 2_504),
            Err(WalletError::BadNodeData(_))
        ));
        // The index survives a save and load.
        let reloaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(reloaded.index, w.index);
    }

    fn owned(w: &mut Wallet, global_index: u64, amount: u64, tx: Option<&str>, height: u64) {
        let zero = hex::encode([0u8; 32]);
        w.outputs.push(StoredOutput {
            global_index,
            height,
            coinbase: false,
            account: 0,
            index: 0,
            amount,
            one_time_key: zero.clone(),
            commitment: zero.clone(),
            mask: zero.clone(),
            offset: zero.clone(),
            key_image: format!("{global_index:064x}"),
            spent_height: None,
            pending: false,
            pending_height: 0,
            tx: tx.map(String::from),
        });
    }

    /// Review R3-13: two outputs of one transaction are spent together only
    /// when nothing else covers the amount, and then with a warning.
    #[test]
    fn outputs_of_one_transaction_are_not_spent_together_unless_needed() {
        use blacksilk_chain::emission::COIN;
        let rules = TxRules::for_chain(&ChainParams::regtest());
        let mut w = wallet();
        w.synced_height = 100;
        owned(&mut w, 1, 10 * COIN, Some("aa"), 50);
        owned(&mut w, 2, 9 * COIN, Some("aa"), 50);
        owned(&mut w, 3, 8 * COIN, Some("bb"), 60);
        let amounts = |w: &Wallet, chosen: &[usize]| {
            let mut a: Vec<u64> = chosen.iter().map(|&i| w.outputs[i].amount / COIN).collect();
            a.sort_unstable();
            a
        };
        // Largest-first would take 10 + 9, both from "aa".
        let (chosen, _) = w.select_inputs(15 * COIN, 1, &rules).unwrap();
        assert_eq!(amounts(&w, &chosen), [8, 10]);
        assert!(w.take_warnings().is_empty());
        // 25 needs all three: allowed, with a warning.
        let (chosen, _) = w.select_inputs(25 * COIN, 1, &rules).unwrap();
        assert_eq!(chosen.len(), 3);
        assert_eq!(w.take_warnings().len(), 1);
        // Outputs stored without their transaction (older files) are grouped
        // by block.
        let mut w = wallet();
        w.synced_height = 100;
        owned(&mut w, 1, 10 * COIN, None, 50);
        owned(&mut w, 2, 9 * COIN, None, 50);
        owned(&mut w, 3, 8 * COIN, None, 60);
        let (chosen, _) = w.select_inputs(15 * COIN, 1, &rules).unwrap();
        assert_eq!(amounts(&w, &chosen), [8, 10]);
    }

    /// Existing wallet files keep their PX addresses (derivation 1); new
    /// wallets use derivation 2, recorded in a version-2 file.
    #[test]
    fn wallet_files_keep_their_px_key_derivation() {
        let mut new = wallet();
        assert_eq!(new.derivation(), Derivation::V2);
        assert!(new.px_range_view(0).is_some());
        let mut old = Wallet::from_seed_with(Network::Regtest, [7; 32], 1, Derivation::V1);
        assert!(old.px_range_view(0).is_none());
        let (new_px, old_px) = (new.px_address(0), old.px_address(0));
        assert_ne!(new_px, old_px, "the derivation changes PX addresses");
        assert_eq!(new.primary(), old.primary(), "but not the v1 keys");

        // A file written before the derivation and the index existed.
        let mut json: serde_json::Value = serde_json::from_slice(&old.to_json()).unwrap();
        assert_eq!(json["version"], 1);
        let fields = json.as_object_mut().unwrap();
        fields.remove("derivation");
        fields.remove("output_index");
        let bytes = serde_json::to_vec(&json).unwrap();
        let mut loaded = Wallet::from_json(&bytes).unwrap();
        assert_eq!(loaded.derivation(), Derivation::V1);
        assert_eq!(loaded.px_address(0), old_px);

        let json: serde_json::Value = serde_json::from_slice(&new.to_json()).unwrap();
        assert_eq!(json["version"], 2);
        let mut loaded = Wallet::from_json(&new.to_json()).unwrap();
        assert_eq!(loaded.derivation(), Derivation::V2);
        assert_eq!(loaded.px_address(0), new_px);

        // Inconsistent or unknown versions are refused.
        for (version, derivation) in [(1, 2), (2, 1), (3, 2), (2, 9)] {
            let mut json: serde_json::Value = serde_json::from_slice(&new.to_json()).unwrap();
            json["version"] = version.into();
            json["derivation"] = derivation.into();
            let bytes = serde_json::to_vec(&json).unwrap();
            assert!(
                Wallet::from_json(&bytes).is_err(),
                "version {version}, derivation {derivation}"
            );
        }
    }
}
