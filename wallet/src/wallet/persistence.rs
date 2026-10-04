//! The wallet file format: serialization, loading, window repair and autosave.

use super::{
    network_name, parse_network, AutoSave, PendingTx, RestorePoint, RingMember, StaleTx,
    StoredOutput, StoredTerms, Wallet, WalletError, GAP_LIMIT, MAX_INDEX_AHEAD,
};
use crate::index::OutputIndex;
use crate::px::{PxStore, PX_GAP_LIMIT, PX_MAX_INDEX_AHEAD};
use crate::seed::{Seed, SEED_VERSION};
use blacksilk_consensus::ChainParams;
use blacksilk_crypto::{Point, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// The wallet-file format version. Version 3 stores a format-v1 seed
/// (docs/blocks.md §10). Versions 1 and 2 held a raw 32-byte seed (the
/// 24-word format) and a PX derivation; they were removed at the v3 reset
/// and are refused.
const FILE_VERSION: u32 = 3;

/// A secret string (the hex seed entropy in the wallet JSON), wiped when dropped.
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
    /// The seed's entropy (hex).
    seed: SecretString,
    /// The seed format version (`crate::seed::SEED_VERSION`).
    seed_version: u8,
    /// The seed's birthday (docs/blocks.md §10), so the words can be shown
    /// again.
    birthday: u16,
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
    /// Every v1 output seen, for local ring-member resolution (absent in
    /// older files: rebuilt by the next sync and a backfill).
    #[serde(default)]
    output_index: OutputIndex,
    /// Transactions dropped by an upgrade, still to be sent again (absent in
    /// files written before 2026-09-27).
    #[serde(default)]
    stale_txs: Vec<StaleTx>,
    /// Terms of the vault records locked with a timeout, by commitment
    /// (absent in files written before RTW1C-3).
    #[serde(default)]
    vault_terms: BTreeMap<String, StoredTerms>,
    /// A restored wallet checks the header chain until it has caught up
    /// (dossier 39 W5; absent in older files: no check).
    #[serde(default)]
    restore_check: bool,
    /// The headers of the last scanned blocks (hex), the context of a later
    /// header check (absent in older files: fetched when needed).
    #[serde(default)]
    headers: Vec<String>,
    /// Where the header chain checked from the genesis ends
    /// (`Wallet::checked_through`; absent in older files: the next check
    /// starts from the genesis).
    #[serde(default)]
    checked_through: Option<u64>,
    /// The pinned restore point (RT-D1b N1; absent in older files: pinned
    /// at the next scan of the restore point).
    #[serde(default)]
    restore_point: Option<RestorePoint>,
    /// Ids (hex) of the last RandomX key blocks among the checked headers.
    #[serde(default)]
    key_ids: BTreeMap<u64, String>,
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
            version: FILE_VERSION,
            output_index: self.index.clone(),
            network: network_name(self.network).into(),
            genesis_id: Some(hex::encode(self.genesis_id)),
            seed: SecretString(Zeroizing::new(hex::encode(self.seed().entropy()))),
            seed_version: SEED_VERSION,
            birthday: self.seed().birthday(),
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
            vault_terms: self.vault_terms.clone(),
            restore_check: self.restore_check,
            headers: self
                .headers
                .iter()
                .map(|h| hex::encode(h.to_bytes()))
                .collect(),
            checked_through: self.checked_through,
            restore_point: self.restore_point,
            key_ids: self
                .key_ids
                .iter()
                .map(|(h, id)| (*h, hex::encode(id)))
                .collect(),
        };
        serde_json::to_vec(&p).expect("serializable")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, WalletError> {
        // The version first: older files lack the seed fields.
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let v: Version =
            serde_json::from_slice(bytes).map_err(|e| WalletError::Serialization(e.to_string()))?;
        match v.version {
            FILE_VERSION => {}
            1 | 2 => {
                return Err(WalletError::Serialization(format!(
                    "wallet file version {} (24-word seed) is no longer supported: the 24-word \
                     format and PX derivation 1 were removed at the v3 reset. Create a new wallet",
                    v.version
                )))
            }
            n => {
                return Err(WalletError::Serialization(format!(
                    "unsupported wallet file version {n}"
                )))
            }
        }
        let p: Persisted =
            serde_json::from_slice(bytes).map_err(|e| WalletError::Serialization(e.to_string()))?;
        if p.seed_version != SEED_VERSION {
            return Err(WalletError::Serialization(format!(
                "unsupported seed version {}",
                p.seed_version
            )));
        }
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
        // A file written for another genesis of the same network (a release
        // candidate, a rehearsal, a retired identity) is refused: this build
        // would sign for its own genesis while the file names another, and a
        // node of either chain would see the key images and rings of
        // transactions built for the wrong chain (RTW1-5).
        let ours = ChainParams::for_network(network).genesis_id();
        if genesis_id != ours {
            return Err(WalletError::Serialization(format!(
                "the wallet file belongs to another genesis ({}) than this build's {} ({}); \
                 use a build of that chain, or restore the seed (mnemonic) into a new \
                 wallet file",
                hex::encode(genesis_id),
                network_name(network),
                hex::encode(ours)
            )));
        }
        let mut entropy = h32(&p.seed.0)?;
        let seed = Seed::new(entropy, network, p.birthday);
        entropy.zeroize();
        let mut w = Self::from_file_seed(seed, p.restore_height);
        debug_assert_eq!(w.genesis_id, genesis_id);
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
        w.vault_terms = p.vault_terms;
        w.restore_check = p.restore_check;
        w.headers = p
            .headers
            .iter()
            .map(|h| {
                hex::decode(h)
                    .ok()
                    .and_then(|b| blacksilk_consensus::BlockHeader::from_bytes(&b))
                    .ok_or_else(|| WalletError::Serialization("bad stored header".into()))
            })
            .collect::<Result<_, _>>()?;
        w.checked_through = p.checked_through;
        w.restore_point = p.restore_point;
        w.key_ids = p
            .key_ids
            .iter()
            .map(|(h, id)| Ok((*h, h32(id)?)))
            .collect::<Result<_, WalletError>>()?;
        if w.px.contracts.iter().any(|c| !c.from_deploy) {
            // Written when registrations came from the node's list (before
            // W3-39b): they are derived again from the deploys by a rescan.
            w.px.contracts.clear();
            w.px.tree = None;
            w.warnings.push(format!(
                "this wallet file holds contract registrations taken from the node's list; the \
                 next sync rescans from block {} to derive them from the deploys",
                w.restore_height
            ));
        }
        if w.px.legacy_commitments.take().is_some() {
            // Written before the wallet built its own PX tree (dossier 39
            // W1): the next sync rescans from the restore height to build it.
            w.warnings.push(format!(
                "this wallet file predates the wallet's own PX tree; the next sync rescans \
                 from block {} to build it",
                w.restore_height
            ));
        }
        // Files written before RTW1-4 hold one record per key image, all
        // credited: a no-op for them.
        w.elect_credited();
        w.repair_windows();
        w.rebuild_table();
        // Derived vault secrets of held records the file does not have yet
        // (a restored wallet that found its own locks, docs/px.md §13.4).
        w.recover_vault_secrets();
        // And the openings and terms of its vault locks with a timeout,
        // delivered to someone else (RTW1C-3); a no-op once they are stored.
        w.recover_vault_locks();
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

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::Network;

    /// RTW1-5 (red team RT-W1): a wallet file bound to another genesis than
    /// this build's (same network name and id: a release candidate, a
    /// rehearsal or a retired identity) is refused at load, before any
    /// transaction can be built for it. Before the fix it loaded with the
    /// file's genesis id and this build's parameters, and would sign for
    /// this build's genesis after checking only the network id.
    #[test]
    fn a_file_bound_to_another_genesis_is_refused_at_load() {
        let w = Wallet::from_seed(Network::Regtest, [7; 32], 1);
        assert_eq!(w.genesis_id(), ChainParams::regtest().genesis_id());
        assert!(Wallet::from_json(&w.to_json()).is_ok());
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        json["genesis_id"] = serde_json::Value::String(hex::encode([0xAB; 32]));
        let e = Wallet::from_json(&serde_json::to_vec(&json).unwrap())
            .err()
            .expect("refused");
        let msg = e.to_string();
        assert!(msg.contains("another genesis"), "{msg}");
        assert!(msg.contains(&hex::encode([0xAB; 32])), "{msg}");
    }
}
