//! Construction from a seed or mnemonic, network and rule parameters, and the
//! subaddress scan windows and addresses.

use super::{network_name, StaleTx, Wallet, WalletError, GAP_LIMIT, LOOKAHEAD, MAX_INDEX_AHEAD};
use crate::index::OutputIndex;
use crate::px::{AddressKeys, PxStore};
use blacksilk_chain::address::encode_address;
use blacksilk_consensus::{ChainParams, Hash, Network};
use blacksilk_crypto::keys::{Address, SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_px::wallet::{self as pxw, Account, Derivation};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::validate::ACTIVATION_GRACE_BLOCKS;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

impl Wallet {
    /// A wallet from a 32-byte seed, with the latest PX key derivation.
    /// `restore_height` is where scanning starts. The wallet belongs to the
    /// chain whose genesis this build defines for `network`.
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
        let params = ChainParams::for_network(network);
        let mut w = Self {
            network,
            genesis_id: params.genesis_id(),
            params,
            stale_txs: Vec::new(),
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

    /// The genesis id of the wallet's chain.
    pub fn genesis_id(&self) -> Hash {
        self.genesis_id
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
    /// rules of this wallet's network (any epoch; only the network is
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
        self.warn_near_activation(self.synced_height + 1, "this transaction");
        Ok(rules)
    }

    /// Warns that `what` becomes invalid if an upgrade activates within
    /// `ACTIVATION_GRACE_BLOCKS` blocks after `next` before it is mined.
    pub(super) fn warn_near_activation(&mut self, next: u64, what: &str) {
        let horizon = next.saturating_add(ACTIVATION_GRACE_BLOCKS);
        if let Some(e) = self.params.schedule.activation_in(next, horizon) {
            self.warnings.push(format!(
                "a consensus upgrade ({}) activates at block {}, {} blocks from now. {what} is                  valid only if it is mined before then; otherwise it can never be mined, the                  wallet releases its funds at a later sync, and you must send it again",
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
