//! Wallet state, synchronization and transfers.
//!
//! The wallet trusts the node it syncs from for *availability* (which blocks
//! exist). It does not trust it for *correctness* of what it receives: block ids
//! are recomputed from headers and must match, every output is recognized with
//! the wallet's own keys (including the Janus anchor and commitment checks), the
//! PX commitment tree is built from the blocks and every PX anchor checked
//! against it (`crate::tree`), contract registrations are derived from the
//! deploys themselves (`crate::px::deployed`), the header chain is checked
//! from the genesis on restores and on request (`crate::headers`), and the
//! node validates every transaction the wallet submits. A dishonest node can
//! still withhold blocks, and hide payments from a wallet that does not check
//! the header chain; that is why wallets should use their own node
//! (docs/blocks.md §9.3, §10).

mod contracts;
mod keys;
#[cfg(test)]
pub(crate) mod mock_chain;
mod persistence;
mod px_flows;
mod rebroadcast;
mod sync;
#[cfg(test)]
mod tests_sync;
mod transfer;

use crate::index::OutputIndex;
use crate::px::{AddressKeys, PxStore};
use crate::seed::{Seed, SeedError};
use blacksilk_consensus::{ChainParams, Hash, Network};
use blacksilk_crypto::keys::{SubaddressTable, WalletKeys};
use blacksilk_px::wallet::Account;
use blacksilk_tx::builder::{BuildError, Decoy};
use blacksilk_tx::params::MAX_INPUTS;
pub use contracts::{
    check_vault_deploy, vault_claim_window, vault_refund_window, MAX_VAULT_TIMEOUT_AHEAD,
    VAULT_TIMEOUT_GRANULE,
};
pub use rebroadcast::{
    PendingInfo, RebroadcastState, NETWORK_EXPIRY_BLOCKS, REBROADCAST_PROBE_BLOCKS,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub use sync::{
    format_age, stale_tip_limits, DENSE_POW_TAIL, STALE_TIP_REFUSE_BLOCKS, STALE_TIP_WARN_BLOCKS,
};

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

/// Reservations without a stored transaction (wallet files written before
/// transactions were stored) are released after this many blocks. A stored
/// transaction (`PendingTx`) keeps its inputs reserved while it is
/// unconfirmed, until the node finds it invalid; it is checked on with
/// `/tx/status` and sent again only as `rebroadcast.rs` allows
/// (`REBROADCAST_PROBE_BLOCKS`, `NETWORK_EXPIRY_BLOCKS`).
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

/// The PX account this wallet uses (docs/px.md §3.1). Accounts are hardened
/// children of the seed's PX root (`blacksilk_px::wallet::Account::account`);
/// the scanner and the record store hold one account today.
pub const PX_ACCOUNT: u32 = 0;

#[derive(Debug)]
pub enum WalletError {
    Node(String),
    WrongNetwork {
        wallet: String,
        node: String,
    },
    /// The node runs the wallet's network (same name) on another chain: its
    /// genesis id differs from the one recorded in the wallet file, or it does
    /// not report one (R15-3). Hex ids; `node` is empty when not reported.
    WrongGenesis {
        wallet: String,
        node: String,
    },
    /// The node sent data inconsistent with itself or with consensus (bad
    /// block encoding or id, a PX anchor outside the wallet's own root
    /// window, a header chain that fails the checks of `crate::headers`).
    BadNodeData(String),
    /// A PX transaction cannot be built yet without letting the node choose
    /// its anchor (`crate::px::PxStore::anchor_root`); the message says
    /// from when it can.
    PxNotReady(String),
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
    /// A consensus upgrade activated while the transaction was being built:
    /// it is signed (or proven) for branch `built_for`, and the node's next
    /// block, `height`, needs branch `needed`. Nothing was sent and no funds
    /// were reserved (docs/reviews/v3-upgrade-mechanism.md §10).
    EpochChanged {
        built_for: u32,
        needed: u32,
        height: u64,
    },
    /// Seed words that were refused (never echoed), or a seed of another
    /// network than the one asked for.
    Seed(SeedError),
    /// An address index too far beyond the highest one that has received
    /// funds (`GAP_LIMIT`, `MAX_INDEX_AHEAD` and their PX counterparts).
    AddressIndex {
        index: u32,
        /// The highest index allowed now.
        limit: u32,
        /// Whether the override was given (then `limit` is the hard ceiling).
        forced: bool,
    },
    /// The node's tip (block `height`) is `age` seconds old by the local
    /// clock, beyond `limit` (`sync::stale_tip_limits`, RTW3-6): no
    /// transaction is built on it.
    StaleTip {
        height: u64,
        age: u64,
        limit: u64,
    },
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Node(e) => write!(f, "node: {e}"),
            WalletError::WrongNetwork { wallet, node } => {
                write!(f, "wallet is for {wallet} but the node runs {node}")
            }
            WalletError::WrongGenesis { wallet, node } if node.is_empty() => write!(
                f,
                "the node does not report its genesis id; this wallet belongs to the chain \
                 with genesis {wallet} and cannot check that the node follows it"
            ),
            WalletError::WrongGenesis { wallet, node } => write!(
                f,
                "the node follows another chain (genesis {node}) than this wallet \
                 (genesis {wallet}); use a node of this wallet's chain, or restore the \
                 seed into a new wallet file for that chain"
            ),
            WalletError::BadNodeData(e) => write!(f, "inconsistent data from node: {e}"),
            WalletError::PxNotReady(e) => write!(f, "not yet: {e}"),
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
            WalletError::Seed(e) => write!(f, "seed: {e}"),
            WalletError::StaleTip { height, age, limit } => write!(
                f,
                "the node's tip (block {height}) is {} old by this computer's clock, more than \
                 {}: the node may be withholding newer blocks, in which this wallet's funds may \
                 already be spent. No transaction was built. Use another node, check the \
                 clock, or, if the network has really stalled, pass --allow-stale-tip",
                sync::format_age(*age),
                sync::format_age(*limit)
            ),
            WalletError::EpochChanged {
                built_for,
                needed,
                height,
            } => write!(
                f,
                "a consensus upgrade activated while the transaction was being built: it was signed for branch {built_for:#010x}, and block {height} needs branch {needed:#010x}. Nothing was sent and no funds were reserved; run the command again"
            ),
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
    /// Whether this record is the one credited for its key image (RTW1-4).
    /// Outputs sharing a key image are all kept, and exactly one of them is
    /// credited (balance, spending, holdings): the largest amount, then the
    /// lowest global index, elected again after every scan and rewind
    /// (`Wallet::elect_credited`). Absent in older files, which kept one
    /// record per key image: credited.
    #[serde(default = "credited_by_default")]
    credited: bool,
}

fn credited_by_default() -> bool {
    true
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
    /// The branch id its signatures and PX proof commit to: the epoch of the
    /// height it was built for (`TxRules::at_height(params, synced + 1)`).
    /// It is rebroadcast only while the next block is in that epoch. Absent
    /// in files written before 2026-09-27 (every network then had a single
    /// epoch): the epoch of `relayed_height + 1` stands in for it.
    #[serde(default)]
    branch_id: Option<u32>,
    /// What the wallet knows and did about it (`rebroadcast.rs`). Absent in
    /// files written before 2026-09-28: `Sent`.
    #[serde(default)]
    state: RebroadcastState,
    /// Wallet height it was last checked on (`/tx/status`); absent in older
    /// files: 0, so it is checked at the next sync.
    #[serde(default)]
    checked_height: u64,
}

/// A stored transaction dropped because a consensus upgrade made it invalid
/// before it was mined (`refresh_pending`): its funds were released, and the
/// payment must be sent again. Kept only as a notice for the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleTx {
    /// Transaction id (hex).
    pub id: String,
    /// The branch id it was built for.
    pub built_for: u32,
    /// The branch id of the next block when it was dropped.
    pub needed: u32,
    /// Wallet height when it was dropped.
    pub height: u64,
}

/// A decoy of a ring this wallet used, as persisted: its index and, to detect
/// that a reorganization gave the index to another output, its keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RingMember {
    index: u64,
    one_time_key: String,
    commitment: String,
}

/// The terms of a vault record this wallet locked with a timeout
/// (docs/contracts.md §8), kept in the wallet file so the refund needs no
/// argument (RTW1C-3): the claim lock and the timeout. The refund lock is
/// re-derived from the seed. After a restore from the seed the same terms
/// are found again from the chain (`Wallet::recover_vault_locks`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTerms {
    /// `Hk(LOCK, contract ‖ secret)` (hex digest).
    pub claim_lock: String,
    /// The first height at which a refund may be included (a multiple of
    /// `VAULT_TIMEOUT_GRANULE`).
    pub timeout: u64,
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

pub struct Wallet {
    network: Network,
    /// The chain's parameters: `ChainParams::for_network`, unless replaced
    /// by `set_chain_params` (regtest schedules in tests). Transactions are
    /// built with the rules of the epoch of the next block
    /// (`TxRules::at_height`).
    params: ChainParams,
    /// Transactions dropped by an upgrade (`StaleTx`).
    stale_txs: Vec<StaleTx>,
    /// The genesis id of the wallet's chain: recorded in the file and
    /// compared with the node's at every sync (R15-3). A node of the same
    /// network name on another genesis (a release candidate, a rehearsal, a
    /// retired identity) is refused.
    genesis_id: Hash,
    /// The seed (format v1, docs/blocks.md §10): every key derives from its
    /// `master`. Wiped when dropped.
    seed: Seed,
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
    /// PX account `PX_ACCOUNT` of the seed (docs/px.md §3.1).
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
    /// Terms of the vault records this wallet locked with a timeout, by
    /// commitment (hex): stored before the lock is sent.
    vault_terms: BTreeMap<String, StoredTerms>,
    /// Problems found and repaired when loading (`take_warnings`).
    warnings: Vec<String>,
    /// Check the header chain of the blocks scanned (`crate::headers`) at
    /// the next syncs until the wallet reaches the node's tip: set by a
    /// restore from the seed (dossier 39 W5, on by default for restores).
    restore_check: bool,
    /// Check the header chain at every sync (opt-in, not persisted).
    verify_headers: bool,
    /// The proof-of-work function of the header check: RandomX light mode
    /// unless replaced (`set_header_pow`). Not persisted.
    header_pow: Option<std::sync::Arc<dyn blacksilk_consensus::PowFunction>>,
    /// Headers whose work the check samples per sync (`HEADER_SAMPLES`).
    header_samples: u64,
    /// The headers of the last scanned blocks, oldest first: the context of
    /// a later header check (`HeaderCheck::context_len` of them).
    headers: std::collections::VecDeque<blacksilk_consensus::BlockHeader>,
    /// The height up to which every header, from the genesis, passed the
    /// header check (`crate::headers`), when `headers` end there: a later
    /// check continues from them instead of reading the chain from the
    /// genesis again. `None` once a block is scanned unchecked.
    checked_through: Option<u64>,
    /// Ids of the last RandomX key blocks among the checked headers (the
    /// keys of the next ones).
    key_ids: BTreeMap<u64, Hash>,
    /// The synced tip's height and timestamp, as of the last sync (memory
    /// only; RTW3-6).
    tip_time: Option<(u64, u64)>,
    /// Build transactions on a stale tip anyway (`set_allow_stale_tip`;
    /// memory only).
    allow_stale_tip: bool,
}

/// The wallet file to save to before a submission (docs/reviews/wallet-review.md F1).
struct AutoSave {
    path: std::path::PathBuf,
    password: zeroize::Zeroizing<Vec<u8>>,
    kdf: crate::file::KdfParams,
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

/// Balance summary in atomic units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// All unspent outputs (including those not yet spendable and pending change).
    pub total: u64,
    /// Spendable in the next block.
    pub unlocked: u64,
}

/// What a wallet holds at its synced height (`Wallet::holdings`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holdings {
    /// The wallet's synced height.
    pub height: u64,
    /// The id of the block at `height`, if the wallet has scanned it.
    pub tip: Option<Hash>,
    /// Transactions submitted by this wallet and still stored (unconfirmed,
    /// or confirmed but not yet buried).
    pub pending_txs: usize,
    pub outputs: Vec<HeldOutput>,
    pub px_records: Vec<HeldRecord>,
}

/// An owned v1 output (`Holdings`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldOutput {
    pub global_index: u64,
    /// Height of the block that created it.
    pub height: u64,
    pub amount: u64,
    pub coinbase: bool,
    /// Height of the block that spent it, if spent on chain.
    pub spent_height: Option<u64>,
    /// Reserved by a transaction this wallet submitted that is not confirmed.
    pub pending: bool,
}

/// An owned PX record (`Holdings`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRecord {
    /// The record commitment (hex), unique on chain.
    pub commitment: String,
    /// Height of the block that created it.
    pub height: u64,
    pub value: u64,
    /// Height of the block that spent it, if spent on chain.
    pub spent_height: Option<u64>,
    /// Reserved by a transaction this wallet submitted that is not confirmed.
    pub pending: bool,
    /// The contract (hex) for a contract record, `None` for a plain record.
    pub contract: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeApi;
    use crate::px::{digest_hex, KnownProgram};
    use crate::px::{RecordSource, PX_GAP_LIMIT, PX_MAX_INDEX_AHEAD};
    use crate::wallet::persistence::h32;
    use blacksilk_crypto::keys::SubaddressIndex;
    use blacksilk_px::perm::HostPerm;
    use blacksilk_px::vault;
    use blacksilk_px_core::record::Record;
    use blacksilk_px_core::{Digest, ZERO_DIGEST};
    use blacksilk_rpc as rpc;
    use blacksilk_tx::params::TxRules;
    use blacksilk_tx::px::Registration;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn wallet() -> Wallet {
        Wallet::from_seed(Network::Regtest, [7; 32], 1)
    }

    /// A regtest node that reports `genesis` and nothing else (R15-3 tests).
    struct GenesisNode(Option<String>);

    impl NodeApi for GenesisNode {
        fn info(&self) -> Result<rpc::Info, String> {
            Ok(rpc::Info {
                network: "regtest".into(),
                network_id: ChainParams::regtest().network_id,
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
                template_ready: None,
                genesis_id: self.0.clone(),
                consensus_fingerprint: None,
                rules_fingerprint: None,
                identity_fingerprint: None,
                build_commit: None,
                version: None,
                build_flags: None,
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
            Err("not used".into())
        }
        fn px_commitments(&self, _: u64) -> Result<rpc::PxCommitments, String> {
            Err("not used".into())
        }
        fn px_contracts(&self, _: u64) -> Result<rpc::PxContracts, String> {
            Err("not used".into())
        }
    }

    /// R15-3: the wallet file records the genesis id of its chain, and a node
    /// of the same network name on another genesis (or reporting none) is
    /// refused before anything is read from it.
    #[test]
    fn the_wallet_is_bound_to_its_genesis() {
        let ours = ChainParams::regtest().genesis_id();
        let w = wallet();
        assert_eq!(w.genesis_id(), ours);
        // Recorded in the file and restored from it.
        let json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        assert_eq!(json["genesis_id"], hex::encode(ours));
        assert_eq!(Wallet::from_json(&w.to_json()).unwrap().genesis_id(), ours);

        // The node of the wallet's chain: accepted.
        let mut w = wallet();
        assert!(w
            .check_network(&GenesisNode(Some(hex::encode(ours))))
            .is_ok());
        // Same network name and id, another genesis: refused.
        let other = hex::encode([0xAB; 32]);
        match w.sync(&GenesisNode(Some(other.clone()))) {
            Err(WalletError::WrongGenesis { wallet, node }) => {
                assert_eq!(wallet, hex::encode(ours));
                assert_eq!(node, other);
            }
            r => panic!("expected WrongGenesis, got {r:?}"),
        }
        // A node that does not report a genesis id: refused.
        assert!(matches!(
            w.sync(&GenesisNode(None)),
            Err(WalletError::WrongGenesis { node, .. }) if node.is_empty()
        ));

        // A file written for another genesis is refused by this build
        // (RTW1-5; `persistence::tests`).
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        json["genesis_id"] = serde_json::Value::String(other.clone());
        assert!(Wallet::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    /// Files without a genesis id (written before the binding) are refused,
    /// not silently bound to this build's genesis.
    #[test]
    fn files_without_a_genesis_id_are_refused() {
        let w = wallet();
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        json.as_object_mut().unwrap().remove("genesis_id");
        let e = Wallet::from_json(&serde_json::to_vec(&json).unwrap())
            .err()
            .unwrap();
        assert!(
            e.to_string().contains("predates the genesis binding"),
            "{e}"
        );
        // Also with the older file version and derivation (a pre-v3 file).
        json["version"] = 1.into();
        json["derivation"] = 1.into();
        assert!(Wallet::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
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
            credited: true,
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
            credited: true,
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
        assert_eq!(m.split(' ').count(), crate::seed::SEED_WORDS);
        assert!(m.capacity() == 256, "written into the preallocated buffer");
        let r = Wallet::from_mnemonic(Network::Regtest, &m, 1).unwrap();
        assert_eq!(*r.seed.master(), *w.seed.master());
        assert_eq!(r.mnemonic(), m);
    }

    #[test]
    fn deploys_mixing_the_vault_with_other_programs_are_refused() {
        let vault = Registration {
            elf: vault::VAULT_ELF.to_vec(),
            budget: vault::BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
        };
        let other = Registration {
            elf: include_bytes!("../../zkvm/tests/fixtures/guest-sum.elf").to_vec(),
            budget: vault::BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
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
            data: vault::record_data(&[1, 0, 0, 0, 0, 0, 0, 0], &secret),
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

    /// A node at height 0 with an empty PX tree; the registrations are the
    /// wallet's, as if derived from scanned deploys.
    struct Registry(Vec<crate::px::KnownContract>);

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
                template_ready: None,
                genesis_id: Some(hex::encode(ChainParams::regtest().genesis_id())),
                consensus_fingerprint: None,
                rules_fingerprint: None,
                identity_fingerprint: None,
                build_commit: None,
                version: None,
                build_flags: None,
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
                root: digest_hex(&blacksilk_px::state::State::new().root()),
                height: 0,
                next: None,
            })
        }
        fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
            Ok(rpc::PxContracts {
                from,
                contracts: vec![],
                total: 0,
                height: 0,
            })
        }
    }

    /// A registration as the wallet derives it from a deploy (current ABI,
    /// the vault's output words).
    fn entry(
        contract: &Digest,
        programs: &[(String, blacksilk_zkvm::air::trace::Budget)],
    ) -> crate::px::KnownContract {
        crate::px::KnownContract {
            height: 0,
            id: digest_hex(contract),
            programs: programs
                .iter()
                .map(|(id, b)| KnownProgram {
                    id: id.clone(),
                    budget: [
                        b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                    ],
                    abi: blacksilk_px_core::call::ABI_VERSION,
                    out_words: vault::OUT_WORDS,
                })
                .collect(),
            from_deploy: true,
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
        let rules = TxRules::at_height(&ChainParams::regtest(), 0);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let secret = [5, 6, 7, 8, 9, 10, 11, 12];
        let mut w = wallet();
        w.sync(&node).unwrap();
        w.px.contracts = node.0.clone();
        // The node's tip is the regtest genesis (2023): stale (RTW3-6).
        w.set_allow_stale_tip(true);
        // Lock: the safe vault passes the check and stops at the funds (this
        // wallet has none); the others are refused as contracts.
        let lock = |w: &mut Wallet, c: &Digest, rng: &mut ChaCha20Rng| {
            w.px_vault_lock(&node, c, 1, Some(&secret), None, &rules, rng)
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
                data: vault::record_data(c, &secret),
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
            credited: true,
        });
    }

    /// Review R3-13: two outputs of one transaction are spent together only
    /// when nothing else covers the amount, and then with a warning.
    #[test]
    fn outputs_of_one_transaction_are_not_spent_together_unless_needed() {
        use blacksilk_chain::emission::COIN;
        let rules = TxRules::at_height(&ChainParams::regtest(), 101);
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

    /// Stored transactions record the branch id they were built for; files
    /// written before (no `branch_id`, no `stale_txs`) still load
    /// (docs/reviews/v3-upgrade-mechanism.md §10).
    #[test]
    fn stored_transactions_keep_their_branch_id_and_older_files_load() {
        let mut w = wallet();
        w.pending_txs.push(PendingTx {
            tx: "00".into(),
            relayed_height: 5,
            branch_id: Some(7),
            state: RebroadcastState::Resent { height: 9 },
            checked_height: 9,
        });
        w.stale_txs.push(StaleTx {
            id: "ab".into(),
            built_for: 1,
            needed: 2,
            height: 9,
        });
        let back = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(back.pending_txs[0].branch_id, Some(7));
        assert_eq!(
            back.pending_txs[0].state,
            RebroadcastState::Resent { height: 9 }
        );
        assert_eq!(back.stale_transactions(), w.stale_transactions());
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        for field in ["branch_id", "state", "checked_height"] {
            json["pending_txs"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        json.as_object_mut().unwrap().remove("stale_txs");
        let old = Wallet::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(old.pending_txs[0].branch_id, None);
        assert_eq!(old.pending_txs[0].state, RebroadcastState::Sent);
        assert_eq!(old.pending_txs[0].checked_height, 0);
        assert_eq!(old.pending_txs[0].relayed_height, 5);
        assert!(old.stale_transactions().is_empty());
        // Rules and parameters of another chain are refused.
        let mut w = wallet();
        let testnet = TxRules::at_height(&ChainParams::testnet(), 0);
        assert!(matches!(
            w.next_rules(&testnet),
            Err(WalletError::WrongNetwork { .. })
        ));
        assert_eq!(
            w.next_rules(&TxRules::at_height(&ChainParams::regtest(), 0))
                .unwrap(),
            w.next_block_rules()
        );
        assert!(w.set_chain_params(ChainParams::testnet()).is_err());
        assert!(w.set_chain_params(ChainParams::regtest()).is_ok());
    }

    /// Wallet files are version 3 (seed format v1). Files of versions 1 and
    /// 2 (24-word seeds, PX derivation 1) and unknown versions are refused;
    /// the seed's birthday survives a save and load.
    #[test]
    fn wallet_files_are_version_3_and_older_ones_are_refused() {
        let mut w = Wallet::from_seed(Network::Regtest, [7; 32], (5 << 14) + 1);
        let json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        assert_eq!(json["version"], 3);
        assert_eq!(json["seed_version"], 1);
        assert_eq!(json["birthday"], 5);
        assert!(json.get("derivation").is_none());
        let mut loaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(loaded.birthday(), 5);
        assert_eq!(loaded.mnemonic(), w.mnemonic());
        assert_eq!(loaded.px_address(0), w.px_address(0));

        for version in [1, 2] {
            let mut json = json.clone();
            json["version"] = version.into();
            json["derivation"] = version.into();
            let e = Wallet::from_json(&serde_json::to_vec(&json).unwrap())
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("no longer supported"), "{e}");
        }
        let mut other = json.clone();
        other["version"] = 4.into();
        assert!(Wallet::from_json(&serde_json::to_vec(&other).unwrap()).is_err());
        let mut other = json.clone();
        other["seed_version"] = 2.into();
        assert!(Wallet::from_json(&serde_json::to_vec(&other).unwrap()).is_err());
        let mut other = json;
        other.as_object_mut().unwrap().remove("birthday");
        assert!(Wallet::from_json(&serde_json::to_vec(&other).unwrap()).is_err());
    }
}
