//! Construction from a seed or its words, network and rule parameters, the
//! derived vault secrets, and the subaddress scan windows and addresses.

use super::{
    network_name, StaleTx, Wallet, WalletError, GAP_LIMIT, LOOKAHEAD, MAX_INDEX_AHEAD, PX_ACCOUNT,
};
use crate::index::OutputIndex;
use crate::px::{digest_from_hex, AddressKeys, PxStore};
use crate::seed::{Seed, SeedError};
use blacksilk_chain::address::encode_address;
use blacksilk_consensus::{ChainParams, Hash, Network};
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::keys::{Address, SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self as pxw, Account, Derivation};
use blacksilk_px_core::kernel::InputWitness;
use blacksilk_px_core::record::{nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::validate::ACTIVATION_GRACE_BLOCKS;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// A digest as 32 bytes: its eight limbs, little-endian.
fn digest_bytes(d: &Digest) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    b
}

impl Wallet {
    /// A wallet from 32 bytes of seed entropy: a format-v1 seed for `network`
    /// born at `restore_height`, scanning from `restore_height`. The wallet
    /// belongs to the chain whose genesis this build defines for `network`.
    /// For tests and tools: users create with [`Wallet::generate`] and restore
    /// with [`Wallet::restore`].
    pub fn from_seed(network: Network, entropy: [u8; 32], restore_height: u64) -> Self {
        Self::from_parts(
            Seed::new(entropy, network, Seed::birthday_of(restore_height)),
            restore_height,
        )
    }

    /// A wallet of `seed`, scanning from `restore_height`. Every key derives
    /// from the seed's `master` (docs/blocks.md §10): the v1 keys
    /// (transactions.md §2.1) and PX account [`PX_ACCOUNT`] (docs/px.md §3.1).
    fn from_parts(seed: Seed, restore_height: u64) -> Self {
        let network = seed.network();
        let master = seed.master();
        let keys = WalletKeys::from_seed(&master);
        let px_account = Account::from_seed_with(&master, Derivation::V2).account(PX_ACCOUNT);
        drop(master);
        let params = ChainParams::for_network(network);
        let mut w = Self {
            network,
            genesis_id: params.genesis_id(),
            params,
            stale_txs: Vec::new(),
            seed,
            index: OutputIndex::default(),
            table: SubaddressTable::default(),
            keys,
            restore_height,
            synced_height: restore_height.saturating_sub(1),
            block_ids: BTreeMap::new(),
            issued: BTreeMap::from([(0, 0)]),
            outputs: Vec::new(),
            px: PxStore::default(),
            px_account,
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

    /// Refuses a network whose genesis is not final
    /// (`ChainParams::genesis_is_final`), as the node refuses to run one: a
    /// wallet created or restored for it would belong to no chain that can
    /// launch. Regtest always is final.
    fn check_network_enabled(network: Network) -> Result<(), WalletError> {
        if ChainParams::for_network(network).genesis_is_final() {
            Ok(())
        } else {
            Err(WalletError::Serialization(format!(
                "the {} genesis is not final yet (the network is disabled until its v3 genesis \
                 is final); use regtest",
                network_name(network)
            )))
        }
    }

    /// A new wallet from the OS CSPRNG. Scanning starts at `restore_height`
    /// (the next block for a brand new wallet), and the seed's birthday is
    /// its epoch. Refused for a network whose genesis is not final.
    pub fn generate(network: Network, restore_height: u64) -> Result<Self, WalletError> {
        Self::check_network_enabled(network)?;
        let seed = Seed::generate(network, restore_height)
            .map_err(|e| WalletError::Serialization(format!("OS RNG: {e}")))?;
        Ok(Self::from_parts(seed, restore_height))
    }

    /// The 27 seed words (docs/blocks.md §10). The result is wiped when
    /// dropped, and written into a buffer large enough that it is never
    /// reallocated (no stray partial copies).
    pub fn mnemonic(&self) -> Zeroizing<String> {
        self.seed.words()
    }

    /// The seed's birthday: the 2^14-block epoch the wallet was created in.
    pub fn birthday(&self) -> u16 {
        self.seed.birthday()
    }

    /// A wallet from its seed words, for `network`, scanning from
    /// `restore_height`. Refused when the words do not check, name another
    /// network, or `network`'s genesis is not final.
    pub fn from_mnemonic(
        network: Network,
        words: &str,
        restore_height: u64,
    ) -> Result<Self, WalletError> {
        Self::restore(words, Some(network), Some(restore_height))
    }

    /// A wallet from its seed words. `network`, if given, must be the seed's
    /// own (a seed is never restored on another network). Scanning starts at
    /// `restore_height`, by default at the start of the seed's birthday
    /// epoch. Refused when the words do not check or the network's genesis
    /// is not final.
    pub fn restore(
        words: &str,
        network: Option<Network>,
        restore_height: Option<u64>,
    ) -> Result<Self, WalletError> {
        let seed = Seed::parse(words).map_err(WalletError::Seed)?;
        if let Some(n) = network {
            if n != seed.network() {
                return Err(WalletError::Seed(SeedError::WrongNetwork {
                    seed: network_name(seed.network()),
                    wanted: network_name(n),
                }));
            }
        }
        Self::check_network_enabled(seed.network())?;
        let start = restore_height.unwrap_or_else(|| seed.scan_start());
        Ok(Self::from_parts(seed, start))
    }

    /// The seed, for the wallet file.
    pub(super) fn seed(&self) -> &Seed {
        &self.seed
    }

    /// A wallet file's seed and scan start (`persistence`).
    pub(super) fn from_file_seed(seed: Seed, restore_height: u64) -> Self {
        Self::from_parts(seed, restore_height)
    }

    /// The vault secret this wallet derives for a vault record of `contract`
    /// whose `rho` is `rho` (docs/px.md §13.4, dossier 37 K6):
    /// `H32("px/wallet/vault-secret/v1", hk_px ‖ u8 network ‖ contract ‖ rho)`,
    /// read as eight LE32 limbs reduced to 30 bits (canonical, 240 bits).
    /// Deterministic and seed-recoverable; unique on chain because `rho` is.
    pub fn px_vault_secret_for(&self, contract: &Digest, rho: &Digest) -> Zeroizing<Digest> {
        let hk = Zeroizing::new(self.px_account.hedge_secret());
        let net = [crate::seed::network_code(self.network)];
        let h = Zeroizing::new(h32(
            tags::PX_WALLET_VAULT_SECRET,
            &[
                hk.as_slice(),
                &net,
                &digest_bytes(contract),
                &digest_bytes(rho),
            ],
        ));
        let mut secret = Zeroizing::new([0u32; 8]);
        for (i, x) in secret.iter_mut().enumerate() {
            let w = u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().expect("4 bytes"));
            *x = w & ((1 << 30) - 1);
        }
        secret
    }

    /// The derived secret of a vault lock of `contract` whose first input is
    /// `first`: the vault record is output 0, so its `rho` is
    /// `Hk(RHO, nf_0 ‖ 0)` with `nf_0` the nullifier of `first`. Refused when
    /// `first` is not a real record of this wallet (a dummy's nullifier is
    /// re-drawn by the builder, so the secret would not be recoverable).
    pub(super) fn px_vault_secret_for_lock(
        &self,
        contract: &Digest,
        first: &InputWitness,
    ) -> Result<Zeroizing<Digest>, WalletError> {
        if first.dummy || first.contract != ZERO_DIGEST {
            return Err(WalletError::Contract(
                "a derived vault secret needs a funded first input".into(),
            ));
        }
        let mut perm = HostPerm::new();
        let keys = self.px_account.keys();
        let owner = keys.owner(&mut perm, &first.d);
        let cm =
            Record::plain(owner, first.value, first.data, first.rho, first.rcm).commit(&mut perm);
        let nf0 = nullifier(&mut perm, &keys.nk, &first.rho, &cm);
        let rho = output_rho(&mut perm, &nf0, 0);
        Ok(self.px_vault_secret_for(contract, &rho))
    }

    /// Stores the derived secret of every held vault record that has none
    /// and opens with it (a lock this wallet made, found again after a
    /// restore). Returns how many were recovered.
    pub fn recover_vault_secrets(&mut self) -> usize {
        let mut found = Vec::new();
        for r in self
            .px
            .contract_records
            .iter()
            .filter(|r| r.secret.is_none())
        {
            let (Ok(rec), Ok(cm)) = (r.record(), digest_from_hex(&r.commitment)) else {
                continue;
            };
            let candidate = self.px_vault_secret_for(&rec.contract, &rec.rho);
            if vault::record_data(&rec.contract, &candidate) == rec.data {
                found.push((cm, candidate));
            }
        }
        for (cm, secret) in &found {
            self.px.set_secret(cm, secret);
        }
        found.len()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The genesis id of the wallet's chain.
    pub fn genesis_id(&self) -> Hash {
        self.genesis_id
    }

    /// The full viewing key of PX address range `range` (addresses
    /// `range·2^16 ..`) of the wallet's PX account, for an auditor or a
    /// watch-only service: it sees the records received in that range and
    /// their spends, and cannot spend (docs/px.md §3.1). Sensitive; there is
    /// no CLI export yet.
    pub fn px_range_view(&self, range: u32) -> pxw::RangeViewKey {
        self.px_account
            .range_view(range)
            .expect("PX accounts use derivation 2")
    }

    pub fn synced_height(&self) -> u64 {
        self.synced_height
    }

    /// Replaces the chain parameters (by default `ChainParams::for_network`),
    /// for a chain whose activation schedule differs from the built-in one:
    /// a regtest upgrade in tests. Not persisted. Refused unless `params`
    /// belongs to the wallet's network and genesis.
    pub fn set_chain_params(&mut self, params: ChainParams) -> Result<(), WalletError> {
        if params.network != self.network || params.genesis_id() != self.genesis_id {
            return Err(WalletError::WrongGenesis {
                wallet: hex::encode(self.genesis_id),
                node: hex::encode(params.genesis_id()),
            });
        }
        self.params = params;
        Ok(())
    }

    /// The rules of the block after the synced height, the one a transaction
    /// built now is meant for (`TxRules::at_height`,
    /// docs/reviews/v3-upgrade-mechanism.md §2.4). Every transaction this
    /// wallet builds uses them.
    pub fn next_block_rules(&self) -> TxRules {
        TxRules::at_height(&self.params, self.synced_height + 1)
    }

    /// `next_block_rules`, for a build that was given `given`: those must be
    /// rules of this wallet's chain (any epoch; the network and genesis ids are
    /// checked). Warns when an upgrade activates within
    /// `ACTIVATION_GRACE_BLOCKS` of the next block: the transaction is then
    /// valid only if it is mined before the upgrade.
    pub(super) fn next_rules(&mut self, given: &TxRules) -> Result<TxRules, WalletError> {
        let rules = self.next_block_rules();
        if given.network_id != rules.network_id {
            return Err(WalletError::WrongNetwork {
                wallet: network_name(self.network).into(),
                node: format!("network id {:#010x}", given.network_id),
            });
        }
        // The network id is not enough: rules of another genesis of the same
        // network would sign for a chain this wallet does not follow
        // (RTW1-5).
        if given.genesis_id != rules.genesis_id || rules.genesis_id != self.genesis_id {
            return Err(WalletError::WrongGenesis {
                wallet: hex::encode(self.genesis_id),
                node: hex::encode(given.genesis_id),
            });
        }
        self.warn_near_activation(self.synced_height + 1, "this transaction");
        Ok(rules)
    }

    /// Warns that `what` becomes invalid if an upgrade activates within
    /// `ACTIVATION_GRACE_BLOCKS` blocks after `next` before it is mined.
    pub(super) fn warn_near_activation(&mut self, next: u64, what: &str) {
        let horizon = next.saturating_add(ACTIVATION_GRACE_BLOCKS);
        if let Some(e) = self.params.schedule.activation_in(next, horizon) {
            self.warnings.push(format!(
                "a consensus upgrade ({}) activates at block {}, {} blocks from now. {what} is valid only if it is mined before then; otherwise it can never be mined, the wallet releases its funds at a later sync, and you must send it again",
                e.name,
                e.activation_height,
                e.activation_height - next
            ));
        }
    }

    /// Transactions dropped because an upgrade made them invalid before they
    /// were mined: their funds are released, and the payments must be sent
    /// again. Kept for `RING_RETENTION_BLOCKS` blocks or until
    /// `clear_pending`.
    pub fn stale_transactions(&self) -> &[StaleTx] {
        &self.stale_txs
    }

    pub(super) fn rebuild_table(&mut self) {
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
    pub(super) fn used_index(&self, account: u32) -> Option<u32> {
        self.outputs
            .iter()
            .filter(|o| o.account == account)
            .map(|o| o.index)
            .max()
    }

    /// Records that `(account, index)` received funds: the account's window
    /// moves so that it stays `LOOKAHEAD` ahead of it (gap-limit scan, review
    /// M-2). Returns whether the window grew.
    pub(super) fn note_used(&mut self, account: u32, index: u32) -> bool {
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
    pub(super) fn index_limit(base: Option<u32>, gap: u32, hard: u32, force: bool) -> u32 {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::px::RecordSource;
    use blacksilk_px_core::kernel::TREE_DEPTH;
    use rand_chacha::rand_core::SeedableRng;

    fn wallet() -> Wallet {
        Wallet::from_seed(Network::Regtest, [7; 32], 1)
    }

    /// RTW1-5: rules handed to a build must be those of the wallet's chain,
    /// its genesis included, not only its network id.
    #[test]
    fn rules_of_another_genesis_are_refused() {
        let mut w = wallet();
        let ours = w.next_block_rules();
        assert!(w.next_rules(&ours).is_ok());
        let mut other = ours;
        other.genesis_id = [0xAB; 32];
        assert!(matches!(
            w.next_rules(&other),
            Err(WalletError::WrongGenesis { .. })
        ));
    }

    /// A wallet is created or restored only for a network whose genesis is
    /// final (`ChainParams::genesis_is_final`), as the node refuses to run
    /// one that is not. Regtest always is.
    #[test]
    fn create_and_restore_need_a_final_genesis() {
        for n in [Network::Regtest, Network::Testnet, Network::Mainnet] {
            let words = Wallet::from_seed(n, [7; 32], 1).mnemonic();
            let fin = ChainParams::for_network(n).genesis_is_final();
            assert_eq!(Wallet::generate(n, 1).is_ok(), fin, "{n:?}");
            assert_eq!(Wallet::from_mnemonic(n, &words, 1).is_ok(), fin, "{n:?}");
            assert_eq!(Wallet::restore(&words, None, None).is_ok(), fin, "{n:?}");
            if !fin {
                let e = Wallet::generate(n, 1).err().unwrap().to_string();
                assert!(e.contains("not final"), "{e}");
            }
        }
    }

    /// F37-1a: the same entropy gives unrelated keys on each network (the
    /// network enters `master`), so a testnet address does not link to the
    /// mainnet one. Failed on the base (2a69556): same primary address.
    #[test]
    fn a_seed_gives_unrelated_keys_on_each_network() {
        let a = Wallet::from_seed(Network::Regtest, [7; 32], 1);
        let b = Wallet::from_seed(Network::Testnet, [7; 32], 1);
        assert_ne!(a.primary(), b.primary());
        assert_ne!(a.px_account.keys().ak, b.px_account.keys().ak);
        assert_ne!(a.keys.hedge_secret(), b.keys.hedge_secret());
    }

    /// Restore finds the seed's network and birthday in the words, starts at
    /// the birthday unless told otherwise, and refuses another network.
    #[test]
    fn restore_uses_the_birthday_and_refuses_another_network() {
        let height = (3 << 14) + 5;
        let w = Wallet::from_seed(Network::Regtest, [7; 32], height);
        assert_eq!(w.birthday(), 3);
        let words = w.mnemonic();
        let r = Wallet::restore(&words, None, None).unwrap();
        assert_eq!(r.network(), Network::Regtest);
        assert_eq!(r.birthday(), 3);
        assert_eq!(r.restore_height, 3 << 14);
        assert!(r.restore_height <= height);
        let r = Wallet::restore(&words, Some(Network::Regtest), Some(10)).unwrap();
        assert_eq!(r.restore_height, 10);
        assert_eq!(r.primary(), w.primary());
        for (asked, words) in [
            (Network::Testnet, words.clone()),
            (Network::Mainnet, words.clone()),
            (
                Network::Regtest,
                Wallet::from_seed(Network::Testnet, [7; 32], 1).mnemonic(),
            ),
        ] {
            let e = Wallet::restore(&words, Some(asked), None).err().unwrap();
            assert!(
                matches!(e, WalletError::Seed(SeedError::WrongNetwork { .. })),
                "{e}"
            );
            assert!(e.to_string().contains("belongs to"), "{e}");
        }
        // A refused seed is never echoed.
        let e = Wallet::restore("abandon zoo", None, None).err().unwrap();
        assert!(!e.to_string().contains("zoo"), "{e}");
    }

    /// Restoring from the words reproduces every key: v1 keys and hedge key,
    /// PX keys, addresses, range view, hedge key and vault secrets.
    #[test]
    fn restore_reproduces_every_key() {
        let mut w = wallet();
        let mut r = Wallet::from_mnemonic(Network::Regtest, &w.mnemonic(), 1).unwrap();
        assert_eq!(r.mnemonic(), w.mnemonic());
        assert_eq!(r.primary(), w.primary());
        assert_eq!(r.address(2, 9), w.address(2, 9));
        assert_eq!(r.keys.hedge_secret(), w.keys.hedge_secret());
        assert_eq!(r.px_account.keys(), w.px_account.keys());
        assert_eq!(r.px_account.hedge_secret(), w.px_account.hedge_secret());
        for i in [0, 1, 77] {
            assert_eq!(r.px_address(i), w.px_address(i));
        }
        assert_eq!(r.px_range_view(0).nk(), w.px_range_view(0).nk());
        assert_eq!(
            r.px_range_view(1).owner(70_001),
            w.px_range_view(1).owner(70_001)
        );
        let (c, rho) = ([5; 8], [6; 8]);
        assert_eq!(
            *r.px_vault_secret_for(&c, &rho),
            *w.px_vault_secret_for(&c, &rho)
        );
        // The same through the wallet file.
        let mut l = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(l.mnemonic(), w.mnemonic());
        assert_eq!(l.px_address(1), w.px_address(1));
        assert_eq!(l.keys.hedge_secret(), w.keys.hedge_secret());
        // The PX account is a hardened child, not the root.
        let master = w.seed.master();
        let root = Account::from_seed_with(&master, Derivation::V2);
        assert_ne!(root.keys(), w.px_account.keys());
        assert_eq!(root.account(PX_ACCOUNT).keys(), w.px_account.keys());
    }

    fn vault_record(secret: &Digest, contract: Digest, rho: Digest) -> (Record, Digest) {
        let record = Record {
            owner: ZERO_DIGEST,
            contract,
            asset: ZERO_DIGEST,
            value: 10,
            data: vault::record_data(&contract, secret),
            rho,
            rcm: [3, 0, 0, 0, 0, 0, 0, 0],
        };
        let cm = record.commit(&mut HostPerm::new());
        (record, cm)
    }

    /// K6: a wallet restored from the seed recovers the secret of a vault
    /// lock it made and holds (the record delivered to itself). On the base
    /// (2a69556) the secret was random and this failed: the restored wallet
    /// had no way to find it.
    #[test]
    fn a_restored_wallet_recovers_its_vault_secret() {
        let w = wallet();
        let (contract, rho) = ([1, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]);
        let secret = w.px_vault_secret_for(&contract, &rho);
        let (record, cm) = vault_record(&secret, contract, rho);
        let mut restored = Wallet::from_mnemonic(Network::Regtest, &w.mnemonic(), 1).unwrap();
        restored
            .px
            .add_contract_record(&record, &cm, RecordSource::Received { index: 0 }, Some(0));
        // Re-derived at once, and stored at the next load.
        assert_eq!(*restored.px_vault_secret(&cm).unwrap(), *secret);
        assert!(restored.px.contract_records[0].secret.is_none());
        let loaded = Wallet::from_json(&restored.to_json()).unwrap();
        assert!(loaded.px.contract_records[0].secret.is_some());
        assert_eq!(*loaded.px_vault_secret(&cm).unwrap(), *secret);
        // Another wallet cannot.
        let mut other = Wallet::from_seed(Network::Regtest, [8; 32], 1);
        other
            .px
            .add_contract_record(&record, &cm, RecordSource::Received { index: 0 }, Some(0));
        assert_eq!(other.recover_vault_secrets(), 0);
        assert!(other.px_vault_secret(&cm).is_err());
        // Nor does a random secret come back (what locks with an explicit
        // secret keep in the file only).
        let random = pxw::random_digest(&mut rand_chacha::ChaCha20Rng::seed_from_u64(9));
        let (record, cm) = vault_record(&random, contract, rho);
        let mut w = wallet();
        w.px.add_contract_record(&record, &cm, RecordSource::Received { index: 0 }, Some(0));
        assert_eq!(w.recover_vault_secrets(), 0);
    }

    /// K6: the derived secret is a function of the wallet, the network, the
    /// contract and the vault record's `rho`, and nothing else; its limbs
    /// are canonical.
    #[test]
    fn vault_secrets_are_deterministic_and_bound_to_the_record() {
        let w = wallet();
        let s = |w: &Wallet, c: Digest, r: Digest| *w.px_vault_secret_for(&c, &r);
        let (c, r) = ([1; 8], [2; 8]);
        let base = s(&w, c, r);
        assert_eq!(base, s(&w, c, r));
        assert!(base.iter().all(|&x| x < 1 << 30));
        // The birthday is not an input.
        let late = Wallet::from_seed(Network::Regtest, [7; 32], 1 << 20);
        assert_eq!(base, s(&late, c, r));
        assert_ne!(base, s(&w, [3; 8], r));
        assert_ne!(base, s(&w, c, [3; 8]));
        let testnet = Wallet::from_seed(Network::Testnet, [7; 32], 1);
        assert_ne!(base, s(&testnet, c, r));
        let other = Wallet::from_seed(Network::Regtest, [8; 32], 1);
        assert_ne!(base, s(&other, c, r));
    }

    /// K6: the lock's derived secret uses the vault record's `rho`, which
    /// follows from the first input's nullifier; a dummy or contract first
    /// input is refused.
    #[test]
    fn a_derived_vault_secret_needs_a_funded_first_input() {
        let w = wallet();
        let c = [4; 8];
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let dummy = pxw::dummy_input(&mut rng);
        assert!(matches!(
            w.px_vault_secret_for_lock(&c, &dummy),
            Err(WalletError::Contract(_))
        ));
        let rec = Record::plain(w.px_account.owner(0), 50, [0; 8], [4; 8], [5; 8]);
        let input = w.px_account.spend(0, &rec, 7, [ZERO_DIGEST; TREE_DEPTH]);
        let mut perm = HostPerm::new();
        let cm = rec.commit(&mut perm);
        let nf = nullifier(&mut perm, &w.px_account.keys().nk, &rec.rho, &cm);
        let rho = output_rho(&mut perm, &nf, 0);
        assert_eq!(
            *w.px_vault_secret_for_lock(&c, &input).unwrap(),
            *w.px_vault_secret_for(&c, &rho)
        );
        let mut contract_input = input;
        contract_input.contract = c;
        assert!(w.px_vault_secret_for_lock(&c, &contract_input).is_err());
    }
}
