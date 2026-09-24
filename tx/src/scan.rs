//! Wallet-side scanning of transactions (spec §3.3). Needs only view keys.

use crate::types::{Hash, OutputKey, Transaction};
use blacksilk_crypto::clsag::key_image;
use blacksilk_crypto::keys::{SubaddressTable, ViewKeys, WalletKeys};
use blacksilk_crypto::stealth::{
    coinbase_context, scan_output, transfer_context, ReceivedOutput, ScanOutcome, ScanRejection,
};
use blacksilk_crypto::Point;

/// An output that belongs to the wallet.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    pub global_index: u64,
    pub height: u64,
    pub tx_hash: Hash,
    pub index_in_tx: usize,
    pub key: OutputKey,
    pub coinbase: bool,
    pub received: ReceivedOutput,
}

impl OwnedOutput {
    /// The key image, which identifies the spend of this output. Needs the spend key.
    pub fn key_image(&self, keys: &WalletKeys) -> Point {
        let p = keys.one_time_secret(self.received.subaddress, &self.received.output_key_offset);
        key_image(&p, &self.key.one_time_key)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    pub owned: Vec<OwnedOutput>,
    /// Outputs recognized but refused (Janus probes, bogus amounts). A wallet must
    /// treat them as not received; they are reported for local diagnostics only.
    pub rejected: Vec<(usize, ScanRejection)>,
}

/// Scans `tx`, included at `height`, whose first output has global index
/// `first_global_index`.
pub fn scan_transaction(
    view: &ViewKeys,
    table: &SubaddressTable,
    tx: &Transaction,
    height: u64,
    first_global_index: u64,
) -> ScanReport {
    let (ctx, fields): (_, Vec<_>) = match tx {
        Transaction::Coinbase(c) => (
            coinbase_context(c.height),
            c.outputs.iter().map(|o| o.fields()).collect(),
        ),
        Transaction::Transfer(t) => {
            let images: Vec<Point> = t.inputs.iter().map(|i| i.key_image).collect();
            (
                transfer_context(&images),
                t.outputs.iter().map(|o| o.fields()).collect(),
            )
        }
        // Hidden change outputs, then clear-amount payouts (as `output_keys`).
        Transaction::Px(t) => (
            t.output_context(),
            t.outputs
                .iter()
                .map(|o| o.fields())
                .chain(t.payouts.iter().map(|o| o.fields()))
                .collect(),
        ),
        Transaction::PxDeploy(t) => {
            let images: Vec<Point> = t.inputs.iter().map(|i| i.key_image).collect();
            (
                transfer_context(&images),
                t.outputs.iter().map(|o| o.fields()).collect(),
            )
        }
    };
    let keys = tx.output_keys();
    let tx_hash = tx.hash();
    let mut report = ScanReport::default();
    for (i, f) in fields.iter().enumerate() {
        match scan_output(view, table, &ctx, f) {
            ScanOutcome::NotOwned => {}
            ScanOutcome::Rejected { reason, .. } => report.rejected.push((i, reason)),
            ScanOutcome::Owned(received) => report.owned.push(OwnedOutput {
                global_index: first_global_index + i as u64,
                height,
                tx_hash,
                index_in_tx: i,
                key: keys[i],
                coinbase: tx.is_coinbase(),
                received,
            }),
        }
    }
    report
}

/// Scans a block's transactions, whose first output has global index `first_global_index`.
pub fn scan_block(
    view: &ViewKeys,
    table: &SubaddressTable,
    txs: &[Transaction],
    height: u64,
    first_global_index: u64,
) -> ScanReport {
    let mut report = ScanReport::default();
    let mut next = first_global_index;
    for tx in txs {
        let r = scan_transaction(view, table, tx, height, next);
        next += tx.output_keys().len() as u64;
        report.owned.extend(r.owned);
        report.rejected.extend(r.rejected);
    }
    report
}
