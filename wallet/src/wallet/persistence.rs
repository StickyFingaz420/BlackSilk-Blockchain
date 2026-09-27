//! The wallet file format: serialization, loading, window repair and autosave.

use super::{
    network_name, parse_network, AutoSave, PendingTx, RingMember, StaleTx, StoredOutput, Wallet,
    WalletError, GAP_LIMIT, MAX_INDEX_AHEAD,
};
use crate::index::OutputIndex;
use crate::px::{PxStore, PX_GAP_LIMIT, PX_MAX_INDEX_AHEAD};
use blacksilk_crypto::{Point, Scalar};
use blacksilk_px::wallet::Derivation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

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
    /// The genesis id (hex) of the chain the wallet was created for (R15-3,
    /// testnet v3). Required: files without it (written before the binding)
    /// are refused.
    #[serde(default)]
    genesis_id: Option<String>,
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
    /// Transactions dropped by an upgrade, still to be sent again (absent in
    /// files written before 2026-09-27).
    #[serde(default)]
    stale_txs: Vec<StaleTx>,
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

pub(super) fn h32(s: &str) -> Result<[u8; 32], WalletError> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        // The value is not echoed: the field may be secret (the seed, masks).
        .ok_or_else(|| WalletError::Serialization("bad 32-byte hex field".into()))
}

pub(super) fn point(s: &str) -> Result<Point, WalletError> {
    Point::decode(&h32(s)?).ok_or_else(|| WalletError::Serialization("bad point".into()))
}

pub(super) fn scalar(s: &str) -> Result<Scalar, WalletError> {
    blacksilk_crypto::point::decode_scalar(&h32(s)?)
        .ok_or_else(|| WalletError::Serialization("bad scalar".into()))
}

impl Wallet {
    // ---- persistence ----
    pub fn to_json(&self) -> Vec<u8> {
        let p = Persisted {
            version: file_version(self.derivation),
            derivation: Some(self.derivation.number()),
            output_index: self.index.clone(),
            network: network_name(self.network).into(),
            genesis_id: Some(hex::encode(self.genesis_id)),
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
            stale_txs: self.stale_txs.clone(),
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
        // Files without a genesis id predate the binding (R15-3) and belong
        // to a retired chain: refused, not silently bound to this build's
        // genesis. Their seed is restored into a new file instead.
        let genesis_id = h32(p.genesis_id.as_deref().ok_or_else(|| {
            WalletError::Serialization(
                "the wallet file predates the genesis binding and belongs to a retired chain; \
                 restore its seed (mnemonic) into a new wallet file"
                    .into(),
            )
        })?)?;
        let mut seed = h32(&p.seed.0)?;
        let mut w = Self::from_seed_with(network, seed, p.restore_height, derivation);
        seed.zeroize();
        // The recorded id, not this build's: a file written for another
        // genesis stays bound to it, and the node check refuses the mismatch.
        w.genesis_id = genesis_id;
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
        w.stale_txs = p.stale_txs;
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

    pub(super) fn persist(&self) -> Result<(), WalletError> {
        match &self.autosave {
            Some(a) => crate::save(self, &a.path, &a.password, a.kdf)
                .map_err(|e| WalletError::Serialization(format!("saving the wallet: {e}"))),
            None => Ok(()),
        }
    }
}
