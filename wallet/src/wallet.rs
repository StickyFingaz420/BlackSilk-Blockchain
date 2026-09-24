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
use crate::px::PxStore;

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
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_tx::builder::{
    build_transfer, standard_fee, BuildError, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, MAX_INPUTS, SPENDABLE_AGE};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::px_builder::{build_px, px_standard_fee, PxPlan};
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
/// A submitted transaction still unconfirmed after this many blocks is presumed
/// dropped (e.g. its ring members were reorganized away) and its inputs become
/// spendable again. Safe: if it confirms later, the spend is still detected from
/// the chain, and reusing an input it spent is rejected by consensus.
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
    Serialization(String),
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
            WalletError::Serialization(e) => write!(f, "wallet data: {e}"),
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
        for o in &mut self.outputs {
            if o.pending && synced >= o.pending_height + PENDING_EXPIRY_BLOCKS {
                o.pending = false;
            }
        }
        for r in &mut self.px.records {
            if r.pending && synced >= r.pending_height + PENDING_EXPIRY_BLOCKS {
                r.pending = false;
            }
        }
        self.px.sync_commitments(node, synced)?;
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

    /// Forgets unconfirmed spends (use if a submitted transaction was dropped).
    pub fn clear_pending(&mut self) {
        for o in &mut self.outputs {
            o.pending = false;
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
        let tx = Transaction::from(tx);
        let result = node.submit_tx(&tx.encode()).map_err(WalletError::Node)?;
        if !result.accepted {
            return Err(WalletError::Rejected(result.error.unwrap_or_default()));
        }
        for &i in &inputs {
            self.outputs[i].pending = true;
            self.outputs[i].pending_height = self.synced_height;
        }
        // Sanity: the key images we marked are the ones in the transaction.
        if let Transaction::Transfer(t) = &tx {
            debug_assert!(t.inputs.iter().all(|inp| self
                .outputs
                .iter()
                .any(|o| o.pending && o.key_image == hex::encode(inp.key_image.bytes()))));
        }
        Ok((tx.hash(), fee))
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

    fn submit_px(
        &mut self,
        node: &dyn NodeApi,
        tx: PxTx,
        v1_inputs: &[usize],
        records: &[usize],
    ) -> Result<Hash, WalletError> {
        let tx = Transaction::Px(Box::new(tx));
        let result = node.submit_tx(&tx.encode()).map_err(WalletError::Node)?;
        if !result.accepted {
            return Err(WalletError::Rejected(result.error.unwrap_or_default()));
        }
        for &i in v1_inputs {
            self.outputs[i].pending = true;
            self.outputs[i].pending_height = self.synced_height;
        }
        for &i in records {
            self.px.records[i].pending = true;
            self.px.records[i].pending_height = self.synced_height;
        }
        Ok(tx.hash())
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
        let dist = node
            .distribution(self.synced_height)
            .map_err(WalletError::Node)?;
        let target = ChainParams::for_network(self.network).target_block_time;
        let mut plans = Vec::with_capacity(chosen.len());
        for &i in &chosen {
            let o = &self.outputs[i];
            let decoys = Self::ring_for(node, target, &dist.cumulative, next, o.global_index, rng)?;
            plans.push(InputPlan {
                real: Self::to_spendable(o)?,
                decoys,
            });
        }
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
        let id = self.submit_px(node, tx, &chosen, &[])?;
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
        let id = self.submit_px(node, tx, &[], &chosen)?;
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
        let id = self.submit_px(node, tx, &[], &chosen)?;
        Ok((id, fee))
    }
}
