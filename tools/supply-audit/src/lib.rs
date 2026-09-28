//! Closed-set supply audit (docs/testnet.md, "Supply audit"; review R15-7).
//!
//! v1 amounts are hidden in Pedersen commitments and spends are hidden behind
//! key images, so nobody can compute the circulating supply from the chain.
//! In a closed trial where **every** wallet is kept (miners' payout wallets
//! included), the sum of all wallets can be compared with what the chain
//! says exists. That is an end-to-end inflation check.
//!
//! # The equation
//!
//! At the audit height `H` (one block id, the same for the node and every
//! wallet):
//!
//! ```text
//! generated(H) = Σ reward(h), h = 1..=H          (fees excluded: blocks.md §2)
//! px_pool(H)   = Σ bridge_in − Σ bridge_out       (every PX transaction, px.md §8)
//!
//! generated(H) = V1 + PX + unaccounted
//!   V1 = Σ amounts of the distinct v1 outputs held by the wallets and unspent
//!        on chain at H
//!   PX = Σ values of the distinct PX records (plain and contract) held by the
//!        wallets and unspent on chain at H
//!
//! v1_difference = generated(H) − px_pool(H) − V1
//! px_difference = px_pool(H) − PX
//! ```
//!
//! Fees are not burned: the coinbase of each block pays exactly its reward
//! plus its fees (blocks.md §2), so a fee moves value from the payer to the
//! miner and `generated` counts only rewards. The tool checks that on the
//! chain itself (`Σ coinbase = generated + Σ fees`, coinbase amounts are
//! public).
//!
//! # Definitions (what is counted)
//!
//! - **On-chain state only.** An output counts while no block at or below `H`
//!   spends it. An output reserved by an unconfirmed transaction of the wallet
//!   (`pending`) still counts: the chain has not spent it. The change of an
//!   unconfirmed transaction does not exist on chain and does not count.
//!   Mempool contents play no role.
//! - **Immature coinbase and young outputs count.** They exist on chain; they
//!   are only not spendable yet. They are reported separately.
//! - **PX contract records** count once they are on chain (their commitment is
//!   in the tree), and are deduplicated by commitment across wallets (a shared
//!   vault record is known to two wallets).
//! - **Duplicates** (the same wallet listed twice, shared records) are counted
//!   once and reported.
//!
//! A positive difference means value held outside the audited set: a wallet
//! missing from the list, a payment to an address nobody in the set owns, an
//! output to a subaddress beyond a wallet's scan window, or an output the
//! wallet rejects (a malformed amount or anchor). The protocol has no burn
//! mechanism, so in a complete set the difference must be exactly zero. A
//! negative difference means the wallets hold more than the chain created:
//! inflation, or a wallet bug that keeps a spent output.

#![forbid(unsafe_code)]

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::{block_reward, format_amount};
use blacksilk_consensus::{ChainParams, Hash};
use blacksilk_rpc as rpc;
use blacksilk_tx::params::{COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::types::Transaction;
use blacksilk_wallet::node::NodeApi;
use blacksilk_wallet::wallet::{parse_network, Holdings};
use blacksilk_wallet::Wallet;
use serde::Serialize;
use std::collections::BTreeMap;

/// The node as the wallets see it during the audit: pinned at the audit
/// height, and unable to submit anything.
///
/// Pinning lets wallets sync to exactly `H` while the node keeps going, and
/// the refusal of `submit_tx` keeps the audit read-only: a wallet sync
/// rebroadcasts its stored transactions otherwise.
pub struct Pinned<'a> {
    inner: &'a dyn NodeApi,
    height: u64,
    tip: String,
}

impl<'a> Pinned<'a> {
    pub fn new(inner: &'a dyn NodeApi, height: u64, tip: String) -> Self {
        Self { inner, height, tip }
    }
}

impl NodeApi for Pinned<'_> {
    fn info(&self) -> Result<rpc::Info, String> {
        let mut i = self.inner.info()?;
        if i.height < self.height {
            return Err(format!(
                "the node is now at height {}, below the audit height {} (a reorganization?)",
                i.height, self.height
            ));
        }
        i.height = self.height;
        i.header_height = i.header_height.min(self.height);
        i.tip = self.tip.clone();
        Ok(i)
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        if from > self.height || count == 0 {
            return Ok(rpc::Blocks { blocks: vec![] });
        }
        let mut b = self.inner.blocks(from, count.min(self.height - from + 1))?;
        b.blocks.retain(|e| e.height <= self.height);
        Ok(b)
    }
    /// The header feed (the wallets' genesis-anchored header check, W3-39b),
    /// pinned like `blocks`: nothing above the audit height, and the node's
    /// height reported as the audit height.
    fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
        let pinned = |from| rpc::Headers {
            from,
            headers: String::new(),
            height: self.height,
        };
        if from > self.height || count == 0 {
            return Ok(pinned(from));
        }
        let mut h = self
            .inner
            .headers(from, count.min(self.height - from + 1))?;
        let keep = ((self.height - from + 1) as usize) * rpc::HEADER_BYTES * 2;
        h.headers.truncate(keep.min(h.headers.len()));
        h.height = self.height;
        Ok(h)
    }
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String> {
        self.inner.distribution(to)
    }
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
        self.inner.outputs(indices)
    }
    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        Err("the supply audit never submits transactions".into())
    }
    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
        self.inner.px_commitments(from)
    }
    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
        self.inner.px_contracts(from)
    }
}

/// What the chain itself says, from blocks `1..=H`.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ChainSummary {
    /// `Σ reward(h)` for `h = 1..=H`, from the emission formula.
    pub generated: u64,
    /// Σ of every coinbase output amount (public).
    pub coinbase_paid: u128,
    /// Σ of every transaction fee (public).
    pub fees: u128,
    pub bridge_in: u128,
    pub bridge_out: u128,
    /// `bridge_in − bridge_out`, applied in block order.
    pub px_pool: u128,
    pub blocks: u64,
    pub transfers: u64,
    pub px_txs: u64,
    pub px_deploys: u64,
}

/// One wallet's holdings at `H`, in atomic units.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct WalletSummary {
    pub name: String,
    /// v1 outputs unspent on chain (counted).
    pub v1_unspent: u128,
    pub v1_outputs: usize,
    /// Of `v1_unspent`: coinbase outputs younger than the coinbase maturity.
    pub v1_immature_coinbase: u128,
    /// Of `v1_unspent`: other outputs younger than the spendable age.
    pub v1_locked: u128,
    /// Of `v1_unspent`: reserved by an unconfirmed transaction of this wallet.
    pub v1_reserved: u128,
    /// PX records (plain and contract) unspent on chain (counted).
    pub px_unspent: u128,
    pub px_records: usize,
    /// Of `px_unspent`: contract records.
    pub px_contract: u128,
    /// Of `px_unspent`: reserved by an unconfirmed transaction of this wallet.
    pub px_reserved: u128,
    /// Transactions this wallet submitted and still stores.
    pub pending_txs: usize,
    /// The wallet's own `balance` total (excludes reserved outputs), for
    /// comparison with what its user sees.
    pub wallet_balance: u64,
    /// The wallet's own PX balance total.
    pub wallet_px_balance: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Totals {
    /// Σ of distinct v1 outputs unspent on chain.
    pub v1: u128,
    /// Σ of distinct PX records unspent on chain.
    pub px: u128,
    /// v1 outputs held by more than one listed wallet (counted once).
    pub v1_duplicates: usize,
    /// PX records held by more than one listed wallet (counted once).
    pub px_duplicates: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Report {
    pub network: String,
    /// The audit height `H` and its block id.
    pub height: u64,
    pub tip: String,
    /// The node's height and `generated` when the audit started.
    pub node_height: u64,
    pub node_generated: u64,
    pub chain: ChainSummary,
    pub wallets: Vec<WalletSummary>,
    pub totals: Totals,
    /// `generated − px_pool − V1`.
    pub v1_difference: i128,
    /// `px_pool − PX`.
    pub px_difference: i128,
    /// `generated − V1 − PX` (the sum of the two).
    pub total_difference: i128,
    /// Chain-level checks that failed (independent of the wallets).
    pub chain_failures: Vec<String>,
}

impl Report {
    /// Every check passed and the wallets account for every coin.
    pub fn complete(&self) -> bool {
        self.chain_failures.is_empty() && self.v1_difference == 0 && self.px_difference == 0
    }

    /// Whether something is wrong whatever the set of wallets: a chain check
    /// failed, or the wallets hold more than the chain created.
    pub fn alarm(&self) -> bool {
        !self.chain_failures.is_empty() || self.v1_difference < 0 || self.px_difference < 0
    }

    /// 0: consistent. 2: alarm (see [`Report::alarm`]). 3: a positive
    /// difference while the set is declared complete.
    pub fn exit_code(&self, expect_complete: bool) -> i32 {
        if self.alarm() {
            2
        } else if expect_complete && !self.complete() {
            3
        } else {
            0
        }
    }

    /// The report as human-readable text.
    pub fn text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let w = &mut s;
        let _ = writeln!(w, "BlackSilk supply audit ({})", self.network);
        let _ = writeln!(w, "  audit height     {}", self.height);
        let _ = writeln!(w, "  block id         {}", self.tip);
        let _ = writeln!(
            w,
            "  node             height {}, generated {}",
            self.node_height,
            amt(self.node_generated as i128)
        );
        let c = &self.chain;
        let _ = writeln!(
            w,
            "Chain (blocks 1..={}, {} scanned)",
            self.height, c.blocks
        );
        let _ = writeln!(w, "  generated        {}", amt(c.generated as i128));
        let _ = writeln!(w, "  coinbase paid    {}", amt(c.coinbase_paid as i128));
        let _ = writeln!(w, "  fees             {}", amt(c.fees as i128));
        let _ = writeln!(
            w,
            "  px_pool          {}  (in {}, out {})",
            amt(c.px_pool as i128),
            amt(c.bridge_in as i128),
            amt(c.bridge_out as i128)
        );
        let _ = writeln!(
            w,
            "  transactions     {} transfers, {} PX, {} deploys",
            c.transfers, c.px_txs, c.px_deploys
        );
        let _ = writeln!(w, "Wallets");
        for x in &self.wallets {
            let _ = writeln!(w, "  {}", x.name);
            let _ = writeln!(
                w,
                "    v1  {} in {} outputs (immature coinbase {}, locked {}, reserved {})",
                amt(x.v1_unspent as i128),
                x.v1_outputs,
                amt(x.v1_immature_coinbase as i128),
                amt(x.v1_locked as i128),
                amt(x.v1_reserved as i128)
            );
            let _ = writeln!(
                w,
                "    PX  {} in {} records (contract {}, reserved {})",
                amt(x.px_unspent as i128),
                x.px_records,
                amt(x.px_contract as i128),
                amt(x.px_reserved as i128)
            );
            let _ = writeln!(
                w,
                "    pending transactions {}; wallet shows {} v1, {} PX",
                x.pending_txs,
                amt(x.wallet_balance as i128),
                amt(x.wallet_px_balance as i128)
            );
        }
        let t = &self.totals;
        let _ = writeln!(w, "Totals (distinct outputs and records)");
        let _ = writeln!(w, "  v1               {}", amt(t.v1 as i128));
        let _ = writeln!(w, "  PX               {}", amt(t.px as i128));
        if t.v1_duplicates + t.px_duplicates > 0 {
            let _ = writeln!(
                w,
                "  duplicates       {} v1 outputs, {} PX records held by more than one wallet (counted once)",
                t.v1_duplicates, t.px_duplicates
            );
        }
        let _ = writeln!(w, "Differences");
        let _ = writeln!(
            w,
            "  v1  generated − px_pool − Σv1 = {}",
            amt(self.v1_difference)
        );
        let _ = writeln!(
            w,
            "  PX  px_pool − ΣPX             = {}",
            amt(self.px_difference)
        );
        let _ = writeln!(
            w,
            "  all generated − Σv1 − ΣPX     = {}",
            amt(self.total_difference)
        );
        for f in &self.chain_failures {
            let _ = writeln!(w, "CHAIN CHECK FAILED: {f}");
        }
        let verdict = if self.alarm() {
            "ALARM: a chain check failed or the wallets hold more than the chain created"
        } else if self.complete() {
            "COMPLETE: the listed wallets account for every coin"
        } else {
            "INCOMPLETE: value is held outside the listed wallets (a missing wallet, \
             a payment to an address outside the set, or an output a wallet rejects)"
        };
        let _ = writeln!(w, "{verdict}");
        s
    }
}

/// An amount in BLK with sign.
fn amt(v: i128) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let a = v.unsigned_abs();
    match u64::try_from(a) {
        Ok(x) => format!("{sign}{} BLK ({sign}{x})", format_amount(x)),
        Err(_) => format!("{sign}{a} atomic"),
    }
}

/// Scans blocks `1..=height` and checks their linkage to `genesis` and `tip`.
pub fn scan_chain(
    node: &dyn NodeApi,
    network_id: u32,
    genesis: Hash,
    height: u64,
    tip: &Hash,
) -> Result<(ChainSummary, Vec<String>), String> {
    let mut c = ChainSummary::default();
    let mut failures = Vec::new();
    let mut prev = genesis;
    let mut generated: u64 = 0;
    let mut pool: u128 = 0;
    let mut from = 1;
    while from <= height {
        let count = rpc::MAX_BLOCKS_PER_REQUEST.min(height - from + 1);
        let batch = node.blocks(from, count)?;
        if batch.blocks.is_empty() {
            return Err(format!("the node returned no block at height {from}"));
        }
        for e in batch.blocks {
            if e.height != from {
                return Err(format!("expected block {from}, got {}", e.height));
            }
            let bytes = hex::decode(&e.hex).map_err(|_| format!("block {from}: bad hex"))?;
            let b = Block::decode(&bytes).map_err(|err| format!("block {from}: {err:?}"))?;
            let id = b.id(network_id);
            if hex::encode(id) != e.id || b.compute_tx_root() != b.header.tx_root {
                return Err(format!("block {from} does not match its id"));
            }
            if b.header.prev_id != prev {
                return Err(format!("block {from} does not extend the previous block"));
            }
            let reward = block_reward(from, generated);
            generated = generated
                .checked_add(reward)
                .ok_or("emission overflows u64")?;
            let (mut paid, mut fees) = (0u128, 0u128);
            for tx in &b.txs {
                match tx {
                    Transaction::Coinbase(cb) => {
                        paid += cb.outputs.iter().map(|o| o.amount as u128).sum::<u128>();
                    }
                    Transaction::Transfer(t) => {
                        c.transfers += 1;
                        fees += t.fee as u128;
                    }
                    Transaction::Px(t) => {
                        c.px_txs += 1;
                        fees += t.fee as u128;
                        c.bridge_in += t.bridge_in as u128;
                        c.bridge_out += t.bridge_out as u128;
                        pool += t.bridge_in as u128;
                        match pool.checked_sub(t.bridge_out as u128) {
                            Some(p) => pool = p,
                            None => {
                                failures.push(format!("PX pool below zero in block {from}"));
                                pool = 0;
                            }
                        }
                    }
                    Transaction::PxDeploy(d) => {
                        c.px_deploys += 1;
                        fees += d.fee as u128;
                    }
                }
            }
            if paid != reward as u128 + fees {
                failures.push(format!(
                    "block {from}: coinbase pays {paid}, reward {reward} + fees {fees}"
                ));
            }
            c.coinbase_paid += paid;
            c.fees += fees;
            c.blocks += 1;
            prev = id;
            from += 1;
        }
    }
    if &prev != tip {
        return Err(format!(
            "the scanned chain ends at {}, not at the audit block {}",
            hex::encode(prev),
            hex::encode(tip)
        ));
    }
    c.generated = generated;
    c.px_pool = pool;
    Ok((c, failures))
}

/// The id of the node's block at `height`.
fn block_id(node: &dyn NodeApi, height: u64) -> Result<Hash, String> {
    let b = node.blocks(height, 1)?;
    let e = b
        .blocks
        .first()
        .filter(|e| e.height == height)
        .ok_or_else(|| format!("the node has no block at height {height}"))?;
    rpc::parse_hash(&e.id).ok_or_else(|| format!("bad block id at height {height}"))
}

/// Summarizes one wallet's holdings at `height`.
pub fn summarize(name: &str, h: &Holdings, height: u64) -> WalletSummary {
    let next = height + 1;
    let mut s = WalletSummary {
        name: name.to_string(),
        pending_txs: h.pending_txs,
        ..Default::default()
    };
    for o in h.outputs.iter().filter(|o| o.spent_height.is_none()) {
        let a = o.amount as u128;
        s.v1_unspent += a;
        s.v1_outputs += 1;
        if o.coinbase && next < o.height + COINBASE_MATURITY {
            s.v1_immature_coinbase += a;
        } else if !o.coinbase && next < o.height + SPENDABLE_AGE {
            s.v1_locked += a;
        }
        if o.pending {
            s.v1_reserved += a;
        }
    }
    for r in h.px_records.iter().filter(|r| r.spent_height.is_none()) {
        let v = r.value as u128;
        s.px_unspent += v;
        s.px_records += 1;
        if r.contract.is_some() {
            s.px_contract += v;
        }
        if r.pending {
            s.px_reserved += v;
        }
    }
    s
}

/// A wallet to audit: a display name and the loaded wallet.
pub struct Entry {
    pub name: String,
    pub wallet: Wallet,
}

/// Syncs every wallet to the audit height through [`Pinned`] and compares
/// their holdings with the chain.
///
/// `height`: the audit height (default: the node's height). The node must be
/// fully synchronized and at or above it. The audit is refused unless every
/// wallet ends at the same block id as the node, and that block is still on
/// the node's chain at the end.
/// This build's parameters for the node's network. Refused: an unknown
/// network, a network whose genesis is not final
/// (`ChainParams::genesis_is_final`; the node and the wallet refuse those
/// too; regtest always is), and a network id that differs from this build's.
fn node_params(info: &rpc::Info) -> Result<ChainParams, String> {
    let network = parse_network(&info.network)
        .ok_or_else(|| format!("unknown network {:?}", info.network))?;
    let params = ChainParams::for_network(network);
    if !params.genesis_is_final() {
        return Err(format!(
            "the {} genesis is not final yet (the network is disabled until its v3 genesis \
             is final); use regtest",
            info.network
        ));
    }
    if params.network_id != info.network_id {
        return Err(format!(
            "the node's network id {:#x} is not {}'s {:#x}",
            info.network_id, info.network, params.network_id
        ));
    }
    Ok(params)
}

pub fn audit(
    node: &dyn NodeApi,
    wallets: &mut [Entry],
    height: Option<u64>,
) -> Result<Report, String> {
    if wallets.is_empty() {
        return Err("no wallets to audit".into());
    }
    let info = node.info()?;
    if info.header_height > info.height {
        return Err(format!(
            "the node is still synchronizing ({} of {} blocks)",
            info.height, info.header_height
        ));
    }
    let params = node_params(&info)?;
    let network = params.network;
    let genesis = params.genesis_id();
    if let Some(g) = &info.genesis_id {
        if *g != hex::encode(genesis) {
            return Err(format!("the node's genesis {g} is not this build's"));
        }
    }
    let h = height.unwrap_or(info.height);
    if h > info.height {
        return Err(format!(
            "the audit height {h} is above the node's height {}",
            info.height
        ));
    }
    let tip = if h == 0 { genesis } else { block_id(node, h)? };

    let (chain, mut failures) = scan_chain(node, info.network_id, genesis, h, &tip)?;
    if h == info.height && chain.generated != info.generated {
        failures.push(format!(
            "the node reports generated {} at height {h}; the emission formula gives {}",
            info.generated, chain.generated
        ));
    }
    if chain.coinbase_paid != chain.generated as u128 + chain.fees {
        failures.push(format!(
            "Σ coinbase {} ≠ generated {} + fees {}",
            chain.coinbase_paid, chain.generated, chain.fees
        ));
    }

    let pinned = Pinned::new(node, h, hex::encode(tip));
    let mut summaries = Vec::new();
    let mut v1: BTreeMap<u64, u64> = BTreeMap::new();
    let mut px: BTreeMap<String, u64> = BTreeMap::new();
    let mut totals = Totals::default();
    for e in wallets.iter_mut() {
        if e.wallet.network() != network {
            return Err(format!("{}: not a {} wallet", e.name, info.network));
        }
        // A wallet that starts scanning above the audit block never reaches
        // it: refused before any sync (its header check would otherwise fail
        // first, with a misleading message about the node's feed).
        if e.wallet.restore_height() > h.max(1) {
            return Err(format!(
                "{}: scanning starts at height {}, above the audit block {h}; refusing to compare",
                e.name,
                e.wallet.restore_height()
            ));
        }
        let synced = e
            .wallet
            .sync(&pinned)
            .map_err(|err| format!("{}: sync: {err}", e.name))?;
        let hold = e.wallet.holdings();
        if synced != h || hold.height != h || (h > 0 && hold.tip != Some(tip)) {
            return Err(format!(
                "{}: synced to height {} ({}), not to the audit block {h} ({}); refusing to compare",
                e.name,
                hold.height,
                hold.tip.map(hex::encode).unwrap_or_else(|| "unknown".into()),
                hex::encode(tip)
            ));
        }
        let mut s = summarize(&e.name, &hold, h);
        s.wallet_balance = e.wallet.balance().total;
        s.wallet_px_balance = e.wallet.px_balance().0;
        for o in hold.outputs.iter().filter(|o| o.spent_height.is_none()) {
            if v1.insert(o.global_index, o.amount).is_some() {
                totals.v1_duplicates += 1;
            }
        }
        for r in hold.px_records.iter().filter(|r| r.spent_height.is_none()) {
            if px.insert(r.commitment.clone(), r.value).is_some() {
                totals.px_duplicates += 1;
            }
        }
        summaries.push(s);
    }
    // The audit block must still be on the node's chain.
    let after = if h == 0 { genesis } else { block_id(node, h)? };
    if after != tip {
        return Err(format!(
            "the node reorganized below the audit height during the audit (block {h} is now {}); rerun",
            hex::encode(after)
        ));
    }

    totals.v1 = v1.values().map(|&a| a as u128).sum();
    totals.px = px.values().map(|&a| a as u128).sum();
    let generated = chain.generated as i128;
    let pool = chain.px_pool as i128;
    let v1_difference = generated - pool - totals.v1 as i128;
    let px_difference = pool - totals.px as i128;
    Ok(Report {
        network: info.network,
        height: h,
        tip: hex::encode(tip),
        node_height: info.height,
        node_generated: info.generated,
        chain,
        wallets: summaries,
        totals,
        v1_difference,
        px_difference,
        total_difference: v1_difference + px_difference,
        chain_failures: failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_wallet::wallet::{HeldOutput, HeldRecord};

    fn out(
        height: u64,
        amount: u64,
        coinbase: bool,
        spent: Option<u64>,
        pending: bool,
    ) -> HeldOutput {
        HeldOutput {
            global_index: height * 10 + amount,
            height,
            amount,
            coinbase,
            spent_height: spent,
            pending,
        }
    }

    fn rec(c: &str, value: u64, spent: Option<u64>, pending: bool, contract: bool) -> HeldRecord {
        HeldRecord {
            commitment: c.into(),
            height: 40,
            value,
            spent_height: spent,
            pending,
            contract: contract.then(|| "c".into()),
        }
    }

    #[test]
    fn summary_counts_on_chain_state_and_classifies_it() {
        let h = Holdings {
            height: 100,
            tip: None,
            pending_txs: 1,
            outputs: vec![
                out(10, 1, true, None, false),       // mature coinbase
                out(50, 2, true, None, false),       // immature: 101 < 50 + 60
                out(95, 4, false, None, false),      // locked: 101 < 95 + 10
                out(20, 8, false, None, true),       // reserved, still unspent on chain
                out(30, 16, false, Some(90), false), // spent: not counted
            ],
            px_records: vec![
                rec("a", 32, None, true, false),
                rec("b", 64, None, false, true),
                rec("d", 128, Some(99), false, false),
            ],
        };
        let s = summarize("w", &h, 100);
        assert_eq!(s.v1_unspent, 15);
        assert_eq!(s.v1_outputs, 4);
        assert_eq!(s.v1_immature_coinbase, 2);
        assert_eq!(s.v1_locked, 4);
        assert_eq!(s.v1_reserved, 8);
        assert_eq!(s.px_unspent, 96);
        assert_eq!(s.px_records, 2);
        assert_eq!(s.px_contract, 64);
        assert_eq!(s.px_reserved, 32);
        assert_eq!(s.pending_txs, 1);
    }

    fn report(v1: i128, px: i128, failures: Vec<String>) -> Report {
        Report {
            network: "regtest".into(),
            height: 1,
            tip: String::new(),
            node_height: 1,
            node_generated: 0,
            chain: ChainSummary::default(),
            wallets: vec![],
            totals: Totals::default(),
            v1_difference: v1,
            px_difference: px,
            total_difference: v1 + px,
            chain_failures: failures,
        }
    }

    fn info(network: &str, network_id: u32) -> rpc::Info {
        serde_json::from_value(serde_json::json!({
            "network": network,
            "network_id": network_id,
            "height": 0,
            "tip": "",
            "difficulty": 1,
            "generated": 0,
            "mempool_txs": 0,
            "mempool_bytes": 0,
            "outputs": 0,
        }))
        .unwrap()
    }

    /// The audit builds rules only for a network whose genesis is final, as
    /// the node and the wallet do. Regtest is exempt.
    #[test]
    fn only_a_final_genesis_is_audited() {
        use blacksilk_consensus::Network;
        for (name, n) in [
            ("regtest", Network::Regtest),
            ("testnet", Network::Testnet),
            ("mainnet", Network::Mainnet),
        ] {
            let p = ChainParams::for_network(n);
            let r = node_params(&info(name, p.network_id));
            assert_eq!(r.is_ok(), p.genesis_is_final(), "{name}");
            if let Err(e) = r {
                assert!(e.contains("not final"), "{e}");
            }
        }
        assert!(node_params(&info("regtest", 1)).is_err(), "wrong id");
    }

    #[test]
    fn exit_codes() {
        assert_eq!(report(0, 0, vec![]).exit_code(true), 0);
        assert_eq!(report(5, 0, vec![]).exit_code(false), 0);
        assert_eq!(report(5, 0, vec![]).exit_code(true), 3);
        assert_eq!(report(0, 5, vec![]).exit_code(true), 3);
        // Wallets holding more than the chain created: an alarm in any mode.
        assert_eq!(report(-1, 0, vec![]).exit_code(false), 2);
        assert_eq!(report(0, -1, vec![]).exit_code(false), 2);
        assert_eq!(report(0, 0, vec!["x".into()]).exit_code(false), 2);
        assert!(report(-1, 0, vec![]).text().contains("ALARM"));
        assert_eq!(amt(-150_000_000), "-1.50000000 BLK (-150000000)");
    }
}
