//! Private contracts (docs/contracts.md): deploys, vault lock, claim and
//! refund, vault secrets, and record sharing and import.

use super::{StoredTerms, Wallet, WalletError};
use crate::node::NodeApi;
use crate::px::{ContractRecord, KnownContract, RecordSource, PX_LOOKAHEAD};
use blacksilk_consensus::Hash;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet as pxw;
use blacksilk_px::{delivery, share, vault};
use blacksilk_px_core::call::{function_prefix, Call, Window, ABI_VERSION, PREFIX_WORDS};
use blacksilk_px_core::kernel::FunctionWitness;
use blacksilk_px_core::kernel::InputWitness;
use blacksilk_px_core::record::{nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::{TxRules, MAX_INPUTS};
use blacksilk_tx::px::digest_bytes;
use blacksilk_tx::px::Registration;
use blacksilk_tx::px_builder::{
    build_deploy, build_px, deploy_fee, px_standard_fee, FunctionRun, PxPlan,
};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::PX_EXPIRING_SOON_BLOCKS;
use blacksilk_zkvm::air::trace::Budget;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

impl Wallet {
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
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    pub fn px_deploy<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        programs: Vec<Registration>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest, u64), WalletError> {
        check_vault_deploy(&programs)?;
        self.sync_to_send(node)?;
        let rules = self.next_rules(rules)?;
        // Two outputs (the transfer minimum): change, and a zero-value output
        // to this wallet.
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.outputs[i].amount));
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        let mut fee = deploy_fee(1, 2, &programs, &rules);
        for &i in &candidates {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            fee = deploy_fee(chosen.len(), 2, &programs, &rules);
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
            &rules,
            rng,
        )
        .map_err(WalletError::Build)?;
        let contract = deploy.contract_id();
        let fee = deploy.fee;
        let id = self.submit(node, Transaction::PxDeploy(Box::new(deploy)), &rules)?;
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
    /// `contract`, claimable with `secret` and never refundable
    /// ([`Self::px_vault_lock_until`] without a timeout). Without a `secret`,
    /// the wallet derives one from its keys and the vault record's `rho`
    /// (`px_vault_secret_for`, docs/contracts.md §8), recoverable from the
    /// seed. Either way the secret is stored with the record before sending
    /// (`px_vault_secret`). The record's ciphertext goes to `deliver_to` (the
    /// party that will claim it) or to this wallet; this wallet keeps its own
    /// copy either way. The fee is paid from PX. Returns the transaction id
    /// and the vault record's commitment.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_lock<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        contract: &Digest,
        amount: u64,
        secret: Option<&Digest>,
        deliver_to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest), WalletError> {
        self.px_vault_lock_until(node, contract, amount, secret, deliver_to, 0, rules, rng)
            .map(|(id, cm, _)| (id, cm))
    }

    /// As [`Self::px_vault_lock`], with a `timeout` height (0 for none):
    /// before it, the record is claimable with the secret; from it on, only
    /// this wallet can take the value back ([`Self::px_vault_refund_stored`]),
    /// with a refund secret it derives from its keys and the record's `rho`
    /// ([`Self::px_vault_refund_secret_for`]).
    ///
    /// The timeout must be a multiple of [`VAULT_TIMEOUT_GRANULE`] (16), so
    /// claim and refund windows reveal only a 16-block interval (RTW1C-2);
    /// more than `PX_EXPIRING_SOON_BLOCKS` above the next block, so a claim
    /// can be built at all; and at most [`MAX_VAULT_TIMEOUT_AHEAD`] above it.
    /// Leave a margin for a claim to confirm: a miner can delay it.
    ///
    /// Recoverable from the seed (RTW1C-3): the record's `rcm` is derived
    /// ([`Self::px_vault_rcm_for`]) and the change output (to this wallet)
    /// carries the claim lock in its data, so a restored wallet rebuilds the
    /// record and its terms from the chain ([`Self::recover_vault_locks`]).
    /// The terms are also stored in the wallet file before the lock is sent.
    /// Every way out of the record is dry-run first (RTW1C-8). Returns the
    /// transaction id, the record's commitment and its [`vault::Terms`],
    /// which the claimer needs (with the secret).
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_lock_until<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        contract: &Digest,
        amount: u64,
        secret: Option<&Digest>,
        deliver_to: Option<&delivery::Address>,
        timeout: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest, vault::Terms), WalletError> {
        self.sync_to_send(node)?;
        let rules = self.next_rules(rules)?;
        let next = self.synced_height + 1;
        if timeout != 0 {
            check_vault_timeout(next, timeout)?;
        }
        let budget = self.vault_budget(contract)?;
        let fee = px_standard_fee();
        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds {
                available: 0,
                needed: u64::MAX,
            })?;
        let (chosen, inputs, total, root) = self.px_inputs(needed, rng)?;
        let derived = match secret {
            Some(_) => None,
            None => Some(self.px_vault_secret_for_lock(contract, &inputs[0])?),
        };
        let secret = secret.or(derived.as_deref()).expect("given or derived");
        // The vault record is output 0: its `rho` follows from the first
        // input's nullifier, so the refund secret and the `rcm` of a lock
        // with a timeout are derivable again later.
        let timed_rho = if timeout == 0 {
            None
        } else {
            Some(self.vault_lock_rho(&inputs[0])?)
        };
        let terms = match &timed_rho {
            None => vault::Terms::claim_only(contract, secret),
            Some(rho) => {
                let refund = self.px_vault_refund_secret_for(contract, rho);
                vault::Terms {
                    claim_lock: vault::lock_of(contract, secret),
                    refund_lock: vault::refund_lock_of(contract, &refund),
                    timeout,
                }
            }
        };
        let data = terms.data(contract);
        // The caller's own random values, hedged (W28-4): the function's
        // blind and, without a timeout, the vault record's `rcm` (the opening
        // this wallet keeps). With a timeout the `rcm` is derived from the
        // seed instead (RTW1C-3).
        let window = Window::UNBOUNDED;
        let hk = Zeroizing::new(self.px_account.hedge_secret());
        let context = lock_context(contract, amount, &data, &inputs);
        let items: Vec<&[u8]> = context.iter().map(|v| v.as_slice()).collect();
        let blind =
            pxw::hedged_digest(&[hk.as_slice()], pxw::witness_labels::FN_BLIND, &items, rng);
        let mut vault_out = pxw::contract_output(rng, *contract, amount, data);
        vault_out.rcm = match &timed_rho {
            None => pxw::hedged_digest(
                &[hk.as_slice()],
                pxw::witness_labels::CONTRACT_RCM,
                &items,
                rng,
            ),
            Some(rho) => *self.px_vault_rcm_for(contract, rho),
        };
        drop(hk);
        let (input, fw) = vault::lock_call(contract, amount, &terms, 0, &blind, &window);
        // The change goes to this wallet (address 1). With a timeout it
        // carries the claim lock in its data: private (inside the commitment
        // and the ciphertext to this wallet), and what a restore needs to
        // rebuild the terms when the claim secret was chosen by the
        // counterparty (RTW1C-3).
        let mut change = pxw::output(rng, self.px_account.owner(1), total - needed);
        if timeout != 0 {
            change.data = terms.claim_lock;
        }
        let mut witness = pxw::witness(root, 0, fee, inputs, [vault_out.clone(), change]);
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
                window,
                hedge_secret: self.px_account.hedge_secret(),
            },
            &rules,
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
            data,
            rho,
            rcm: vault_out.rcm,
        };
        let cm = tx.commitments[0];
        if record.commit(&mut HostPerm::new()) != cm {
            return Err(WalletError::Contract(
                "vault record does not match its commitment".into(),
            ));
        }
        // A derived secret must be the one a restore re-derives from the
        // record (its `rho` follows from the first nullifier).
        if derived.is_some() && *self.px_vault_secret_for(contract, &rho) != *secret {
            return Err(WalletError::Contract(
                "the derived vault secret does not match the vault record".into(),
            ));
        }
        let refund = (timeout != 0).then(|| self.px_vault_refund_secret_for(contract, &rho));
        if let Some(refund) = &refund {
            if vault::refund_lock_of(contract, refund) != terms.refund_lock {
                return Err(WalletError::Contract(
                    "the derived refund secret does not match the vault record".into(),
                ));
            }
        }
        // Every way out of the record, dry-run with its real opening before
        // any value is locked (RTW1C-8).
        dry_run_vault_exits(&record, secret, refund.as_deref(), &terms, &budget, next)?;
        self.px.issued = self.px.issued.max(1);
        // Keep the creator's copy first: if the submission's outcome is
        // uncertain, the record may exist on chain and its opening must not
        // be lost.
        let known = self.px.contract_record(&cm).is_some();
        self.px
            .add_contract_record(&record, &cm, RecordSource::Created, None);
        // And the secret and the terms: `submit` saves the wallet before
        // sending, so they are on disk before the lock can exist on chain
        // (review R11-W1, RTW1C-3).
        self.px.set_secret(&cm, secret);
        if timeout != 0 {
            self.store_vault_terms(&cm, &terms);
        }
        match self.submit_px(node, tx, &rules) {
            Ok(id) => {
                debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
                Ok((id, cm, terms))
            }
            Err(e) => {
                // A definite refusal, or nothing sent: the record never
                // existed.
                if matches!(
                    e,
                    WalletError::Rejected(_) | WalletError::EpochChanged { .. }
                ) && !known
                {
                    let hex_cm = crate::px::digest_hex(&cm);
                    self.px.contract_records.retain(|r| r.commitment != hex_cm);
                    self.vault_terms.remove(&hex_cm);
                }
                Err(e)
            }
        }
    }

    /// Claims the vault record with commitment `record` with `secret`, paying
    /// its value to `to` (a PX address) or to this wallet. For a record
    /// locked without a timeout ([`Self::px_vault_lock`]); a record with a
    /// timeout needs its terms ([`Self::px_vault_claim_with_terms`]). The fee
    /// is paid from one of this wallet's PX records, or else from v1 funds.
    /// Returns the transaction id and the claimed value.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
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
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown vault record".into()))?;
        let rec = self.px.contract_records[k].record()?;
        if vault::record_data(&rec.contract, secret) != rec.data {
            return Err(WalletError::Contract(
                "wrong secret for this vault record (or it was locked with a timeout: claim with                  its terms)"
                    .into(),
            ));
        }
        let terms = vault::Terms::claim_only(&rec.contract, secret);
        self.px_vault_claim_with_terms(node, record, secret, &terms, to, rules, rng)
    }

    /// Claims the vault record `record` with `secret` under its `terms` (as
    /// returned by [`Self::px_vault_lock_until`]). With a timeout `T`, the
    /// claim's validity window ends before `T` ([`vault_claim_window`]): a
    /// block at `T` or later can no longer include it, and from `T` on the
    /// locker can refund. Refused when the window would end within
    /// `PX_EXPIRING_SOON_BLOCKS` of the next block (pools refuse it).
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_claim_with_terms<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        record: &Digest,
        secret: &Digest,
        terms: &vault::Terms,
        to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        let contract = self.contract_of(record)?;
        if terms.claim_lock != vault::lock_of(&contract, secret) {
            return Err(WalletError::Contract(
                "wrong secret for this vault record".into(),
            ));
        }
        self.px_vault_release(node, vault::CLAIM, record, secret, terms, to, rules, rng)
    }

    /// Takes back the value of vault record `record`, locked by this wallet
    /// with `timeout` ([`Self::px_vault_lock_until`]), once the next block's
    /// height has reached the timeout. The refund secret is re-derived from
    /// this wallet's keys; the claim lock comes from the stored terms, else
    /// from the stored (or derived) claim secret. Pays to `to` or to this
    /// wallet. Returns the transaction id and the refunded value.
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_refund<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        record: &Digest,
        timeout: u64,
        to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        if timeout == 0 {
            return Err(WalletError::Contract(
                "a vault record without a timeout cannot be refunded".into(),
            ));
        }
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown vault record".into()))?;
        let rec = self.px.contract_records[k].record()?;
        let claim_lock = match self.px_vault_terms(record) {
            Some(stored) => stored.claim_lock,
            None => {
                let claim_secret = match self.px.contract_records[k].secret.as_deref() {
                    Some(hex) => Zeroizing::new(crate::px::digest_from_hex(hex)?),
                    None => self.px_vault_secret_for(&rec.contract, &rec.rho),
                };
                vault::lock_of(&rec.contract, &claim_secret)
            }
        };
        let refund = self.px_vault_refund_secret_for(&rec.contract, &rec.rho);
        let terms = vault::Terms {
            claim_lock,
            refund_lock: vault::refund_lock_of(&rec.contract, &refund),
            timeout,
        };
        if terms.data(&rec.contract) != rec.data {
            return Err(WalletError::Contract(
                "this wallet did not lock this record with this timeout".into(),
            ));
        }
        self.px_vault_release(node, vault::REFUND, record, &refund, &terms, to, rules, rng)
    }

    /// [`Self::px_vault_refund`] with the terms stored in the wallet file at
    /// lock time, or recovered from the chain after a restore from the seed
    /// ([`Self::recover_vault_locks`], run first if the record is unknown).
    #[allow(clippy::too_many_arguments)]
    pub fn px_vault_refund_stored<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        record: &Digest,
        to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        if self.px_vault_terms(record).is_none() {
            self.sync_to_send(node)?;
            self.recover_vault_locks();
        }
        let terms = self.px_vault_terms(record).ok_or_else(|| {
            WalletError::Contract(
                "no stored terms for this record (not locked by this wallet with a timeout)".into(),
            )
        })?;
        self.px_vault_refund(node, record, terms.timeout, to, rules, rng)
    }

    /// The terms of vault record `record` if this wallet locked it with a
    /// timeout (stored at lock time or recovered after a restore).
    pub fn px_vault_terms(&self, record: &Digest) -> Option<vault::Terms> {
        let stored = self.vault_terms.get(&crate::px::digest_hex(record))?;
        let claim_lock = crate::px::digest_from_hex(&stored.claim_lock).ok()?;
        let k = self.px.contract_record(record)?;
        let rec = self.px.contract_records[k].record().ok()?;
        let refund = self.px_vault_refund_secret_for(&rec.contract, &rec.rho);
        Some(vault::Terms {
            claim_lock,
            refund_lock: vault::refund_lock_of(&rec.contract, &refund),
            timeout: stored.timeout,
        })
    }

    /// Commitments of the vault records this wallet locked with a timeout
    /// and holds the terms of.
    pub fn px_vault_timed_locks(&self) -> Vec<(Digest, u64)> {
        self.vault_terms
            .iter()
            .filter_map(|(cm, t)| Some((crate::px::digest_from_hex(cm).ok()?, t.timeout)))
            .collect()
    }

    fn store_vault_terms(&mut self, cm: &Digest, terms: &vault::Terms) {
        self.vault_terms.insert(
            crate::px::digest_hex(cm),
            StoredTerms {
                claim_lock: crate::px::digest_hex(&terms.claim_lock),
                timeout: terms.timeout,
            },
        );
    }

    /// Finds, after a restore from the seed, the vault records this wallet
    /// locked with a timeout and delivered to someone else (RTW1C-3), and
    /// stores their openings and terms so they can be refunded. Returns how
    /// many were found.
    ///
    /// A lock with a timeout spends a record of this wallet as input 0 and
    /// pays its change (output 1) to this wallet's address 1, with the claim
    /// lock as the change's data. For each held record with nonzero data and
    /// such an input (`output_rho(nf_input, 1) = rho_change`, so only this
    /// wallet's own transactions qualify), the vault record's opening is
    /// rebuilt: `rho = output_rho(nf_input, 0)`, the derived `rcm` and
    /// refund lock, the value from the balance (the inputs of this wallet
    /// spent in that block, minus the standard fee and the change), for every
    /// vault contract deployed by then and every timeout that is a multiple
    /// of 16 in a bounded range around the lock's block. A candidate is kept
    /// only if its commitment is that of the transaction's output 0, which
    /// the scan kept with its position and a witness
    /// (`StoredRecord::sibling`). A record that was claimed or refunded
    /// before the restore is found too; the node refuses its refund (its
    /// nullifier is spent).
    pub fn recover_vault_locks(&mut self) -> usize {
        let mut perm = HostPerm::new();
        let fee = px_standard_fee();
        let vaults: Vec<(Digest, u64)> = self
            .px
            .contracts
            .iter()
            .filter(|c| crate::px::vault_check(c).is_ok())
            .filter_map(|c| Some((crate::px::digest_from_hex(&c.id).ok()?, c.height)))
            .collect();
        if vaults.is_empty() {
            return 0;
        }
        let mut found = Vec::new();
        for ch in self.px.records.iter().filter(|r| r.index == 1) {
            let Ok(claim_lock) = crate::px::digest_from_hex(&ch.data) else {
                continue;
            };
            let Ok(change_rho) = crate::px::digest_from_hex(&ch.rho) else {
                continue;
            };
            if claim_lock == ZERO_DIGEST {
                continue;
            }
            let h = ch.height;
            let spent: Vec<&crate::px::StoredRecord> = self
                .px
                .records
                .iter()
                .filter(|r| r.spent_height == Some(h))
                .collect();
            let Some(first) = spent.iter().find(|r| {
                crate::px::digest_from_hex(&r.nullifier)
                    .is_ok_and(|nf| output_rho(&mut perm, &nf, 1) == change_rho)
            }) else {
                continue;
            };
            let nf0 = crate::px::digest_from_hex(&first.nullifier).expect("checked above");
            let rho = output_rho(&mut perm, &nf0, 0);
            // The transaction's output 0, where the vault record must be (the
            // wallet keeps its commitment, position and witness from the
            // scan).
            let Some((sibling, sibling_pos)) = ch.sibling.clone() else {
                continue;
            };
            // Already known (the wallet file has its terms): no search.
            if self.vault_terms.contains_key(&sibling) {
                continue;
            }
            // The second input: a dummy, or another record spent in the block.
            let mut values: Vec<u64> = std::iter::once(0)
                .chain(
                    spent
                        .iter()
                        .filter(|r| r.nullifier != first.nullifier)
                        .map(|r| r.value),
                )
                .filter_map(|second| {
                    first
                        .value
                        .checked_add(second)?
                        .checked_sub(fee)?
                        .checked_sub(ch.value)
                })
                .collect();
            values.sort_unstable();
            values.dedup();
            let low =
                round_down(h.saturating_sub(RESTORE_TIMEOUT_LOOKBACK)).max(VAULT_TIMEOUT_GRANULE);
            let high = h.saturating_add(MAX_VAULT_TIMEOUT_AHEAD);
            'contracts: for (contract, deployed) in &vaults {
                if *deployed > h {
                    continue;
                }
                let rcm = self.px_vault_rcm_for(contract, &rho);
                let refund = self.px_vault_refund_secret_for(contract, &rho);
                let refund_lock = vault::refund_lock_of(contract, &refund);
                let mut timeout = low;
                while timeout <= high {
                    let terms = vault::Terms {
                        claim_lock,
                        refund_lock,
                        timeout,
                    };
                    let data = terms.data(contract);
                    for &value in &values {
                        let record = Record {
                            owner: ZERO_DIGEST,
                            contract: *contract,
                            asset: ZERO_DIGEST,
                            value,
                            data,
                            rho,
                            rcm: *rcm,
                        };
                        let cm = record.commit(&mut perm);
                        if crate::px::digest_hex(&cm) == sibling {
                            found.push((record, cm, h, sibling_pos, terms));
                            break 'contracts;
                        }
                    }
                    timeout += VAULT_TIMEOUT_GRANULE;
                }
            }
        }
        let mut n = 0;
        for (record, cm, h, pos, terms) in found {
            let hex_cm = crate::px::digest_hex(&cm);
            if self.vault_terms.contains_key(&hex_cm) {
                continue;
            }
            self.px
                .add_contract_record(&record, &cm, RecordSource::Created, Some(h));
            if let Some(k) = self.px.contract_record(&cm) {
                if self.px.contract_records[k].position.is_none() {
                    self.px.contract_records[k].position = Some(pos);
                }
            }
            // A derived claim secret opens it too (a lock without an
            // explicit secret).
            let derived = self.px_vault_secret_for(&record.contract, &record.rho);
            if vault::lock_of(&record.contract, &derived) == terms.claim_lock {
                self.px.set_secret(&cm, &derived);
            }
            self.store_vault_terms(&cm, &terms);
            n += 1;
        }
        n
    }

    /// The contract of a held contract record.
    fn contract_of(&self, record: &Digest) -> Result<Digest, WalletError> {
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown vault record".into()))?;
        Ok(self.px.contract_records[k].record()?.contract)
    }

    /// CLAIM or REFUND (`selector`) of vault record `record` with `secret`
    /// (the claim or the refund secret) under `terms`.
    #[allow(clippy::too_many_arguments)]
    fn px_vault_release<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        selector: u32,
        record: &Digest,
        secret: &Digest,
        terms: &vault::Terms,
        to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync_to_send(node)?;
        let rules = self.next_rules(rules)?;
        let next = self.synced_height + 1;
        // The anchor's root and the paths come from the wallet's own tree
        // (F39-1).
        let (anchor, root) = self.px.anchor_root(self.synced_height)?;
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
        if terms.data(&rec.contract) != rec.data {
            return Err(WalletError::Contract(
                "these terms do not open this vault record".into(),
            ));
        }
        // The validity window (PX6) the vault checks: a claim must be
        // included before the timeout, a refund from it on. Both are rounded
        // to 16-block boundaries so they do not reveal the timeout
        // (RTW1C-2), and a claim is not built within the expiring-soon margin
        // of the timeout, which pools refuse (RTW1C-4).
        let window = match (selector, terms.timeout) {
            (_, 0) => Window::UNBOUNDED,
            (vault::CLAIM, t) => vault_claim_window(next, t).ok_or_else(|| {
                WalletError::Contract(format!(
                    "the vault's timeout {t} is too close (next block: {next}; a claim must end \
                     at least {PX_EXPIRING_SOON_BLOCKS} blocks ahead) or has passed: it can \
                     only be refunded from {t} on"
                ))
            })?,
            (_, t) => vault_refund_window(next, t).ok_or_else(|| {
                WalletError::Contract(format!(
                    "the vault can be refunded from height {t} on (next block: {next})"
                ))
            })?,
        };
        let budget = self.vault_budget(&rec.contract)?;
        let fee = px_standard_fee();
        let path = self.px.path(pos, anchor, &root)?;
        let vault_in = pxw::contract_input(rng, &rec, pos, path);
        let recipient = to.cloned().unwrap_or_else(|| self.px_account.address(0));
        // The function's blind, hedged (W28-4), bound to the record (whose
        // `rho` is unique), the recipient and the window.
        let blind = {
            let hk = Zeroizing::new(self.px_account.hedge_secret());
            let window_bytes: Vec<u8> = window
                .words()
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            let rec_bytes = [digest_bytes(&rec.rho), digest_bytes(&rec.rcm)].concat();
            let recipient_bytes = digest_bytes(&recipient.owner);
            pxw::hedged_digest(
                &[hk.as_slice()],
                pxw::witness_labels::FN_BLIND,
                &[
                    &[selector as u8],
                    &rec_bytes,
                    &recipient_bytes,
                    &window_bytes,
                ],
                rng,
            )
        };
        let (input, fw) = if selector == vault::CLAIM {
            vault::claim_call(&rec, secret, terms, &recipient.owner, 0, 0, &blind, &window)
        } else {
            vault::refund_call(&rec, secret, terms, &recipient.owner, 0, 0, &blind, &window)
        };
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
                let path = self.px.path(p, anchor, &root)?;
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
            root,
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
                window,
                hedge_secret: self.px_account.hedge_secret(),
            },
            &rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let records: Vec<usize> = fee_record.into_iter().collect();
        let id = self.submit_px(node, tx, &rules)?;
        debug_assert!(records.iter().all(|&i| self.px.records[i].pending));
        debug_assert!(self.px.contract_records[k].pending);
        Ok((id, rec.value))
    }

    /// The secret of vault record `record`, if this wallet locked it (stored
    /// before the lock was sent), for a record locked without a timeout:
    /// checked against the record's data. A record locked with a timeout
    /// opens only with its terms ([`Self::px_vault_claim_with_terms`]).
    pub fn px_vault_secret(&self, record: &Digest) -> Result<Zeroizing<Digest>, WalletError> {
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown contract record".into()))?;
        let r = &self.px.contract_records[k];
        let Some(hex) = r.secret.as_deref() else {
            // A lock of this wallet found again after a restore: its derived
            // secret (docs/contracts.md §8).
            let rec = r.record()?;
            let derived = self.px_vault_secret_for(&rec.contract, &rec.rho);
            if vault::record_data(&rec.contract, &derived) == rec.data {
                return Ok(derived);
            }
            return Err(WalletError::Contract(
                "no secret stored for this record (not locked by this wallet)".into(),
            ));
        };
        let secret = Zeroizing::new(crate::px::digest_from_hex(hex)?);
        let rec = r.record()?;
        if vault::record_data(&rec.contract, &secret) != rec.data {
            return Err(WalletError::Contract(
                "the stored secret does not open this record without its terms (a timeout)".into(),
            ));
        }
        Ok(secret)
    }

    /// The refund secret this wallet derives for a vault record of
    /// `contract` whose `rho` is `rho`:
    /// `H32("px/wallet/vault-refund/v1", hk_px ‖ u8 network ‖ contract ‖
    /// rho)`, read as eight LE32 limbs reduced to 30 bits (RTW1C-7: a
    /// dedicated tag, distinct from the claim secret's). Wallet side,
    /// seed-recoverable.
    pub fn px_vault_refund_secret_for(&self, contract: &Digest, rho: &Digest) -> Zeroizing<Digest> {
        self.vault_derivation(
            blacksilk_crypto::hash::tags::PX_WALLET_VAULT_REFUND,
            contract,
            rho,
        )
    }

    /// The `rcm` of a vault record with a timeout that this wallet locks,
    /// for `contract` and the record's `rho` (unique on chain):
    /// `H32("px/wallet/vault-rcm/v1", hk_px ‖ u8 network ‖ contract ‖ rho)`
    /// as eight 30-bit limbs (RTW1C-3). Deterministic from the seed, so a
    /// locker restored from the seed rebuilds the record's opening and can
    /// refund it; unknown to anyone without `hk_px`, so the commitment stays
    /// hiding.
    pub fn px_vault_rcm_for(&self, contract: &Digest, rho: &Digest) -> Zeroizing<Digest> {
        self.vault_derivation(
            blacksilk_crypto::hash::tags::PX_WALLET_VAULT_RCM,
            contract,
            rho,
        )
    }

    /// `H32(tag, hk_px ‖ u8 network ‖ contract ‖ rho)` as eight LE32 limbs
    /// reduced to 30 bits (canonical).
    fn vault_derivation(&self, tag: &str, contract: &Digest, rho: &Digest) -> Zeroizing<Digest> {
        let hk = Zeroizing::new(self.px_account.hedge_secret());
        let net = [crate::seed::network_code(self.network)];
        let h = Zeroizing::new(blacksilk_crypto::hash::h32(
            tag,
            &[
                hk.as_slice(),
                &net,
                &digest_bytes(contract),
                &digest_bytes(rho),
            ],
        ));
        let mut out = Zeroizing::new([0u32; 8]);
        for (i, x) in out.iter_mut().enumerate() {
            let w = u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().expect("4 bytes"));
            *x = w & ((1 << 30) - 1);
        }
        out
    }

    /// The `rho` of the vault record a lock with first input `first` creates
    /// (output 0: `Hk(RHO, nf_0 ‖ 0)`). Refused for a dummy or contract first
    /// input, as for a derived secret.
    fn vault_lock_rho(&self, first: &InputWitness) -> Result<Digest, WalletError> {
        if first.dummy || first.contract != ZERO_DIGEST {
            return Err(WalletError::Contract(
                "a vault lock with a timeout needs a funded first input".into(),
            ));
        }
        let mut perm = HostPerm::new();
        let keys = self.px_account.keys();
        let owner = keys.owner(&mut perm, &first.d);
        let cm =
            Record::plain(owner, first.value, first.data, first.rho, first.rcm).commit(&mut perm);
        let nf0 = nullifier(&mut perm, &keys.nk, &first.rho, &cm);
        Ok(output_rho(&mut perm, &nf0, 0))
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
    /// found on chain: at the next sync among the commitments of the recent
    /// blocks the wallet's tree keeps, else in the block it confirms in, else
    /// (a record older than those blocks) from the backfill list of a rescan.
    /// No download is made for it (RTW3-15). Returns its commitment.
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
            if let Some(k) = self.px.contract_record(&cm) {
                let r = &mut self.px.contract_records[k];
                r.lookup = r.position.is_none();
            }
            return Ok(cm);
        }
        Err(WalletError::Contract(
            "not a share addressed to this wallet".into(),
        ))
    }
}

/// Vault timeouts are multiples of this (RTW1C-2), as anchors are: claim
/// and refund windows then reveal only a 16-block interval, never the exact
/// timeout (`vault_claim_window`, `vault_refund_window`).
pub const VAULT_TIMEOUT_GRANULE: u64 = 16;

/// The furthest a vault timeout may be above the next block (2^20 blocks,
/// about four years at 120 s). It bounds the search a wallet restored from
/// the seed runs to find the timeout of its locks
/// ([`Wallet::recover_vault_locks`]).
pub const MAX_VAULT_TIMEOUT_AHEAD: u64 = 1 << 20;

/// Blocks a claim window spans beyond the expiring-soon margin, at least
/// (`vault_claim_window`): two granules.
const CLAIM_WINDOW_SPAN: u64 = 2 * VAULT_TIMEOUT_GRANULE;

/// How far below the lock's block a timeout is searched on restore: a lock
/// can confirm long after it was built (the pool keeps it for
/// `MEMPOOL_EXPIRY_BLOCKS`, 2 160 blocks), and its timeout is only above the
/// height it was built for.
const RESTORE_TIMEOUT_LOOKBACK: u64 = 4_096;

fn round_down(x: u64) -> u64 {
    x - x % VAULT_TIMEOUT_GRANULE
}

fn round_up(x: u64) -> u64 {
    round_down(x.saturating_add(VAULT_TIMEOUT_GRANULE - 1))
}

/// The wallet's rules for a vault timeout set at next height `next`: a
/// multiple of [`VAULT_TIMEOUT_GRANULE`], far enough ahead for a claim to be
/// built ([`vault_claim_window`]) and at most [`MAX_VAULT_TIMEOUT_AHEAD`]
/// ahead.
fn check_vault_timeout(next: u64, timeout: u64) -> Result<(), WalletError> {
    if !timeout.is_multiple_of(VAULT_TIMEOUT_GRANULE) {
        return Err(WalletError::Contract(format!(
            "the vault timeout must be a multiple of {VAULT_TIMEOUT_GRANULE}, so the claim and \
             refund windows do not reveal it (e.g. {})",
            round_up(timeout)
        )));
    }
    if vault_claim_window(next, timeout).is_none() {
        return Err(WalletError::Contract(format!(
            "the vault timeout must be more than {PX_EXPIRING_SOON_BLOCKS} blocks above the \
             next block's height ({next}), or no claim could be built"
        )));
    }
    if timeout > next.saturating_add(MAX_VAULT_TIMEOUT_AHEAD) {
        return Err(WalletError::Contract(format!(
            "the vault timeout must be at most {MAX_VAULT_TIMEOUT_AHEAD} blocks ahead"
        )));
    }
    Ok(())
}

/// The validity window of a CLAIM built for the next block `next` of a vault
/// record with timeout `timeout` (a multiple of [`VAULT_TIMEOUT_GRANULE`]),
/// or `None` when the claim would end within the expiring-soon margin of the
/// timeout (`timeout − 1 < next + PX_EXPIRING_SOON_BLOCKS`: pools refuse it,
/// RTW1C-4). The window is `[0, min(T − 1, round_up16(next + 3) + 31)]`
/// (RTW1C-2): its end is always one below a multiple of 16 and at least
/// `next + 3` blocks ahead, and it reveals `T` only when the claim is made
/// within about 50 blocks of it, where `T − 1` is also the rounded bound.
pub fn vault_claim_window(next: u64, timeout: u64) -> Option<Window> {
    let last = timeout.checked_sub(1)?;
    let margin = next.saturating_add(PX_EXPIRING_SOON_BLOCKS);
    if last < margin {
        return None;
    }
    let rounded = round_up(margin).saturating_add(CLAIM_WINDOW_SPAN - 1);
    Some(Window {
        not_before: 0,
        not_after: last.min(rounded),
    })
}

/// The validity window of a REFUND built for the next block `next` of a
/// vault record with timeout `timeout`, or `None` before the timeout:
/// `[max(T, round_down16(next)), ∞)` (RTW1C-2). Its start is always a
/// multiple of 16 and reveals `T` only within 16 blocks after it.
pub fn vault_refund_window(next: u64, timeout: u64) -> Option<Window> {
    if timeout == 0 || next < timeout {
        return None;
    }
    Some(Window {
        not_before: round_down(next).max(timeout),
        not_after: 0,
    })
}

/// Runs a vault call (`input`, with the kernel's view `fw` of it, releasing
/// the record with commitment `cm`) as a dry run and checks that it would be
/// provable and accepted: exit code 0, the prefix the kernel requires
/// (`abi ‖ io_hash ‖ contract ‖ window`: a wrong secret or other terms give
/// another transcript), exactly `vault::OUT_WORDS` output words after it
/// (PX3, F-28-5) and every table within `budget`.
fn dry_run_vault_call(
    what: &str,
    input: &[u32],
    fw: &FunctionWitness,
    cm: &Digest,
    window: &Window,
    budget: &Budget,
) -> Result<(), WalletError> {
    let program = vault::program();
    let exec = blacksilk_zkvm::run(&program, input, blacksilk_zkvm::MAX_CYCLES)
        .map_err(|t| WalletError::Contract(format!("vault {what} dry run traps: {t:?}")))?;
    if exec.exit_code != 0 {
        return Err(WalletError::Contract(format!(
            "vault {what} dry run halts with {}",
            exec.exit_code
        )));
    }
    let call = Call {
        contract: fw.contract,
        approve: fw.approve.map(|a| a.then_some(*cm)),
        spec: fw.spec,
        blind: fw.blind,
    };
    let io_hash = call.io_hash(&mut HostPerm::new());
    let prefix = function_prefix(ABI_VERSION, &io_hash, &fw.contract, window);
    if exec.output.len() < PREFIX_WORDS || exec.output[..PREFIX_WORDS] != prefix {
        return Err(WalletError::Contract(format!(
            "vault {what} dry run does not match the record (wrong secret or terms)"
        )));
    }
    let words = exec.output.len().checked_sub(PREFIX_WORDS);
    if words != Some(vault::OUT_WORDS as usize) {
        return Err(WalletError::Contract(format!(
            "vault {what} dry run publishes {} output words, not the registered {}",
            exec.output.len(),
            vault::OUT_WORDS
        )));
    }
    let used = blacksilk_zkvm::air::trace::usage(&program, &exec);
    if let Some((table, used, limit)) = blacksilk_px::prove::over_budget(&used, budget) {
        return Err(WalletError::Contract(format!(
            "vault {what} dry run needs {used} rows of {table}, above the budget's {limit}"
        )));
    }
    Ok(())
}

/// The wallet policy before locking funds in a vault record (RTW1C-8,
/// docs/contracts.md §9): every way out of the record is dry-run first,
/// with the record's own opening. CLAIM with `secret` (inside the claim
/// window of a timeout), and with a timeout REFUND with this wallet's refund
/// secret (at the timeout): each must halt with 0, publish the registered
/// output words and fit the registered budget. A lock whose value could not
/// be released again is refused before it is sent.
fn dry_run_vault_exits(
    rec: &Record,
    secret: &Digest,
    refund_secret: Option<&Digest>,
    terms: &vault::Terms,
    budget: &Budget,
    next: u64,
) -> Result<(), WalletError> {
    let recipient = [1, 0, 0, 0, 0, 0, 0, 0];
    let blind = ZERO_DIGEST;
    let cm = rec.commit(&mut HostPerm::new());
    let claim_window = if terms.timeout == 0 {
        Window::UNBOUNDED
    } else {
        vault_claim_window(next, terms.timeout).ok_or_else(|| {
            WalletError::Contract("the vault's timeout leaves no claim window".into())
        })?
    };
    let (claim, fw) =
        vault::claim_call(rec, secret, terms, &recipient, 0, 0, &blind, &claim_window);
    dry_run_vault_call("CLAIM", &claim, &fw, &cm, &claim_window, budget)?;
    if let Some(refund_secret) = refund_secret {
        let window = vault_refund_window(terms.timeout, terms.timeout)
            .ok_or_else(|| WalletError::Contract("a refund needs a timeout".into()))?;
        let (refund, fw) =
            vault::refund_call(rec, refund_secret, terms, &recipient, 0, 0, &blind, &window);
        dry_run_vault_call("REFUND", &refund, &fw, &cm, &window, budget)?;
    }
    Ok(())
}

/// The context a vault lock's hedged values are bound to: the contract, the
/// amount, the record data (the terms) and the spent inputs' openings (a real
/// record's `rho` is unique on chain).
fn lock_context(
    contract: &Digest,
    amount: u64,
    data: &Digest,
    inputs: &[InputWitness; 2],
) -> Vec<Zeroizing<Vec<u8>>> {
    let mut v = vec![
        Zeroizing::new(b"px/vault/lock".to_vec()),
        Zeroizing::new(digest_bytes(contract).to_vec()),
        Zeroizing::new(amount.to_le_bytes().to_vec()),
        Zeroizing::new(digest_bytes(data).to_vec()),
    ];
    for i in inputs {
        let mut item = Vec::with_capacity(69);
        item.push(i.dummy as u8);
        item.extend_from_slice(&digest_bytes(&i.rho));
        item.extend_from_slice(&digest_bytes(&i.rcm));
        item.extend_from_slice(&i.position.to_le_bytes());
        v.push(Zeroizing::new(item));
    }
    v
}

/// Refuses a deploy that registers the reference vault next to other programs,
/// or with a budget, ABI or output-word count other than the reference ones
/// (`vault::BUDGET`, `ABI_VERSION`, `vault::OUT_WORDS`): the wallet would
/// refuse to use such a contract as a vault (`PxStore::vault_budget`, reviews
/// P-1, P-2), and a contract's records can be spent by any of its programs.
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
            if r.abi != ABI_VERSION || r.out_words != vault::OUT_WORDS {
                return Err(WalletError::Contract(
                    "the vault must be registered with the current call ABI and its one output \
                     word (vault::OUT_WORDS)"
                        .into(),
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
    use blacksilk_consensus::Network;
    use rand_chacha::rand_core::SeedableRng;

    fn wallet(entropy: u8) -> Wallet {
        Wallet::from_seed(Network::Regtest, [entropy; 32], 1)
    }

    /// The refund secret (W28-4) is derived like the claim secret (dossier
    /// 37 K6) with a suffix: deterministic from the seed, distinct from the
    /// claim secret for the same record, bound to the contract and `rho`,
    /// and canonical (30-bit limbs).
    #[test]
    fn the_refund_secret_is_seed_recoverable_and_distinct_from_the_claim_secret() {
        let w = wallet(7);
        let (c, rho) = ([1, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]);
        let refund = w.px_vault_refund_secret_for(&c, &rho);
        assert_eq!(
            *refund,
            *wallet(7).px_vault_refund_secret_for(&c, &rho),
            "a restored wallet derives it again"
        );
        assert_ne!(*refund, *w.px_vault_secret_for(&c, &rho));
        assert_ne!(
            *refund,
            *w.px_vault_refund_secret_for(&[3, 0, 0, 0, 0, 0, 0, 0], &rho)
        );
        assert_ne!(
            *refund,
            *w.px_vault_refund_secret_for(&c, &[4, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_ne!(*refund, *wallet(8).px_vault_refund_secret_for(&c, &rho));
        assert!(refund.iter().all(|&x| x < 1 << 30));
    }

    /// A record locked without a timeout opens with its (derived or stored)
    /// secret through `px_vault_secret`; one locked with a timeout needs its
    /// terms, and `px_vault_secret` refuses it rather than returning a
    /// secret that does not open it alone.
    #[test]
    fn px_vault_secret_opens_only_records_without_a_timeout() {
        let mut w = wallet(9);
        let c = [5, 0, 0, 0, 0, 0, 0, 0];
        let rho = [6, 0, 0, 0, 0, 0, 0, 0];
        let secret = w.px_vault_secret_for(&c, &rho);
        let refund = w.px_vault_refund_secret_for(&c, &rho);
        let timed = vault::Terms {
            claim_lock: vault::lock_of(&c, &secret),
            refund_lock: vault::refund_lock_of(&c, &refund),
            timeout: 640,
        };
        for (data, opens) in [
            (vault::record_data(&c, &secret), true),
            (timed.data(&c), false),
        ] {
            let record = Record {
                owner: ZERO_DIGEST,
                contract: c,
                asset: ZERO_DIGEST,
                value: 10,
                data,
                rho,
                rcm: [3, 0, 0, 0, 0, 0, 0, 0],
            };
            let cm = record.commit(&mut HostPerm::new());
            w.px.add_contract_record(&record, &cm, RecordSource::Created, None);
            assert_eq!(w.px_vault_secret(&cm).is_ok(), opens);
            // Stored, the claim secret is returned under the same rule.
            w.px.set_secret(&cm, &secret);
            assert_eq!(w.px_vault_secret(&cm).is_ok(), opens);
        }
    }

    /// RTW1C-2: claim and refund windows never publish the exact timeout
    /// `T` (a multiple of 16) or `T − 1`, except where the rounded window is
    /// itself `T − 1` (a claim within about 50 blocks of `T`) or `T` (a
    /// refund within 16 blocks after it). A claim window always ends at
    /// `16k − 1`, at least 3 blocks ahead and before `T`; a refund window
    /// always starts at a multiple of 16, at `T` or later and no later than
    /// the next block. Before the base (e986250) the claim ended at `T − 1`
    /// and the refund started at `T`, always.
    #[test]
    fn vault_windows_do_not_reveal_the_timeout() {
        let mut claims = 0;
        let mut refunds = 0;
        for t in (16..=2_000u64).step_by(16) {
            for next in 1..t + 100 {
                if let Some(w) = vault_claim_window(next, t) {
                    claims += 1;
                    assert_eq!(w.not_before, 0);
                    assert!(
                        w.not_after < t && w.not_after >= next + 3,
                        "{next} {t} {w:?}"
                    );
                    assert_eq!(w.not_after % 16, 15, "{next} {t} {w:?}");
                    assert!(w.contains(next));
                    let forced = round_up(next + 3) + CLAIM_WINDOW_SPAN > t - 1;
                    assert_eq!(w.not_after == t - 1, forced, "{next} {t} {w:?}");
                } else {
                    assert!(t - 1 < next + 3, "{next} {t}");
                }
                match vault_refund_window(next, t) {
                    Some(w) => {
                        refunds += 1;
                        assert!(next >= t);
                        assert_eq!(w.not_after, 0);
                        assert_eq!(w.not_before % 16, 0);
                        assert!(w.not_before >= t && w.not_before <= next);
                        assert!(w.contains(next));
                        assert_ne!(w.not_before, t - 1);
                        assert_eq!(w.not_before == t, round_down(next) <= t, "{next} {t}");
                    }
                    None => assert!(next < t),
                }
            }
        }
        assert!(claims > 0 && refunds > 0);
        // Far from the timeout the windows are independent of it.
        assert_eq!(
            vault_claim_window(1_000, 6_400),
            vault_claim_window(1_000, 64_000)
        );
        assert_eq!(
            vault_refund_window(9_000, 6_400),
            vault_refund_window(9_000, 8_000)
        );
        // No timeout: nothing to refund.
        assert_eq!(vault_refund_window(100, 0), None);
    }

    /// The wallet's timeout rules: a multiple of 16, far enough ahead for a
    /// claim outside the expiring-soon margin (RTW1C-4), and bounded (the
    /// restore search).
    #[test]
    fn vault_timeouts_are_rounded_and_bounded() {
        let next = 100;
        assert!(check_vault_timeout(next, 112).is_ok());
        assert!(
            check_vault_timeout(next, 113).is_err(),
            "not a multiple of 16"
        );
        assert!(check_vault_timeout(next, 96).is_err(), "passed");
        // T − 1 < next + 3: no claim could be built.
        assert!(check_vault_timeout(108, 112).is_ok());
        assert!(check_vault_timeout(109, 112).is_err());
        let far = round_down(next + MAX_VAULT_TIMEOUT_AHEAD);
        assert!(check_vault_timeout(next, far).is_ok());
        assert!(check_vault_timeout(next, far + 16).is_err());
    }

    /// A vault record of `contract` locked by `locker` with a timeout, with
    /// a claim secret chosen by the counterparty (the swap case): the lock's
    /// first input `a` (a record of the locker, value 5 000 000 plus the fee),
    /// the vault record and the change, as they appear on chain at height
    /// `h`. Returns (the input's stored record, the vault record, its
    /// commitment, the change's stored record, the terms, the secret).
    #[allow(clippy::type_complexity)]
    fn timed_lock(
        locker: &Wallet,
        contract: Digest,
        h: u64,
        timeout: u64,
    ) -> (
        crate::px::StoredRecord,
        Record,
        Digest,
        crate::px::StoredRecord,
        vault::Terms,
        Digest,
    ) {
        use crate::px::{digest_hex, StoredRecord};
        let mut perm = HostPerm::new();
        let keys = locker.px_account.keys();
        let amount = 4_000_000;
        let fee = px_standard_fee();
        let a = Record::plain(
            locker.px_account.owner(0),
            5_000_000 + fee,
            [0; 8],
            [11, 0, 0, 0, 0, 0, 0, 0],
            [12, 0, 0, 0, 0, 0, 0, 0],
        );
        let cm_a = a.commit(&mut perm);
        let nf_a = nullifier(&mut perm, &keys.nk, &a.rho, &cm_a);
        let rho = output_rho(&mut perm, &nf_a, 0);
        let secret = [77, 1, 2, 3, 4, 5, 6, 7];
        let refund = locker.px_vault_refund_secret_for(&contract, &rho);
        let terms = vault::Terms {
            claim_lock: vault::lock_of(&contract, &secret),
            refund_lock: vault::refund_lock_of(&contract, &refund),
            timeout,
        };
        let vault_rec = Record {
            owner: ZERO_DIGEST,
            contract,
            asset: ZERO_DIGEST,
            value: amount,
            data: terms.data(&contract),
            rho,
            rcm: *locker.px_vault_rcm_for(&contract, &rho),
        };
        let cm_v = vault_rec.commit(&mut perm);
        let change = Record::plain(
            locker.px_account.owner(1),
            5_000_000 - amount,
            terms.claim_lock,
            output_rho(&mut perm, &nf_a, 1),
            [13, 0, 0, 0, 0, 0, 0, 0],
        );
        let cm_ch = change.commit(&mut perm);
        let stored = |r: &Record, cm: &Digest, index: u32, height: u64| StoredRecord {
            index,
            height,
            commitment: digest_hex(cm),
            position: None,
            value: r.value,
            data: digest_hex(&r.data),
            rho: digest_hex(&r.rho),
            rcm: digest_hex(&r.rcm),
            nullifier: digest_hex(&nullifier(&mut HostPerm::new(), &keys.nk, &r.rho, cm)),
            spent_height: None,
            pending: false,
            pending_height: 0,
            sibling: None,
        };
        let mut input = stored(&a, &cm_a, 0, h - 5);
        input.spent_height = Some(h);
        input.position = Some(0);
        let mut ch = stored(&change, &cm_ch, 1, h);
        ch.position = Some(2);
        // The scan keeps output 0 of the change's transaction (the vault
        // record) with its position.
        ch.sibling = Some((digest_hex(&cm_v), 1));
        (input, vault_rec, cm_v, ch, terms, secret)
    }

    /// What a wallet restored from `words` knows after scanning the chain of
    /// `timed_lock`: its own input (spent) and change (with the commitment
    /// and position of its transaction's output 0), and the vault contract;
    /// not the vault record (delivered to the counterparty) nor the terms.
    fn restored_after_scan(
        words: &str,
        contract: Digest,
        lock: &(
            crate::px::StoredRecord,
            Record,
            Digest,
            crate::px::StoredRecord,
            vault::Terms,
            Digest,
        ),
    ) -> Wallet {
        use crate::px::{digest_hex, KnownProgram};
        let mut r = Wallet::from_mnemonic(Network::Regtest, words, 1).unwrap();
        let (input, _, _, ch, _, _) = lock;
        r.px.records = vec![input.clone(), ch.clone()];
        let b = vault::BUDGET;
        r.px.contracts = vec![KnownContract {
            id: digest_hex(&contract),
            height: 3,
            programs: vec![KnownProgram {
                id: hex::encode(vault::program().id()),
                budget: [
                    b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                ],
                abi: ABI_VERSION,
                out_words: vault::OUT_WORDS,
            }],
            from_deploy: true,
        }];
        r
    }

    /// RTW1C-3: a locker restored from the seed recovers a vault lock with a
    /// timeout whose record was delivered to the counterparty, with a claim
    /// secret it never knew: the record's opening (derived `rcm`), its value
    /// and position, and its terms (the claim lock from the change's data,
    /// the timeout by search). The recovered opening refunds: the pinned
    /// vault guest accepts a REFUND with it at the timeout, within the
    /// registered budget, and the kernel accepts spending the record. The
    /// terms survive the wallet file. Another seed recovers nothing. On the
    /// base (e986250) the `rcm` was random and delivered only to the
    /// counterparty: nothing could be recovered.
    #[test]
    fn a_restored_locker_recovers_its_timed_lock_and_can_refund() {
        let contract = [0x300, 1, 2, 3, 4, 5, 6, 7];
        let locker = wallet(21);
        let h = 50;
        let timeout = 1_024;
        let lock = timed_lock(&locker, contract, h, timeout);
        let (_, vault_rec, cm_v, _, terms, secret) = lock.clone();
        let words = locker.mnemonic();
        let mut r = restored_after_scan(&words, contract, &lock);
        assert!(r.px_vault_terms(&cm_v).is_none());
        assert_eq!(r.recover_vault_locks(), 1);
        assert_eq!(r.recover_vault_locks(), 0, "a no-op once stored");
        assert_eq!(r.px_vault_terms(&cm_v), Some(terms));
        assert_eq!(r.px_vault_timed_locks(), vec![(cm_v, timeout)]);
        let k =
            r.px.contract_record(&cm_v)
                .expect("the vault record is held");
        let held = &r.px.contract_records[k];
        assert_eq!(held.record().unwrap(), vault_rec);
        assert_eq!(held.position, Some(1));
        assert_eq!(held.height, Some(h));
        // The claim secret was the counterparty's: not stored.
        assert!(held.secret.is_none());
        // The refund with the recovered opening, at the timeout.
        let refund = r.px_vault_refund_secret_for(&contract, &vault_rec.rho);
        let window = vault_refund_window(timeout, timeout).unwrap();
        let (input, fw) = vault::refund_call(
            &vault_rec,
            &refund,
            &terms,
            &r.px_account.owner(0),
            0,
            0,
            &ZERO_DIGEST,
            &window,
        );
        dry_run_vault_call("REFUND", &input, &fw, &cm_v, &window, &vault::BUDGET).unwrap();
        // The kernel accepts consuming the recovered record (its opening
        // matches the commitment in the tree) with this approval.
        let mut perm = HostPerm::new();
        let mut tree = blacksilk_px::tree::Tree::new(&mut perm);
        let pos = tree.append(&mut perm, cm_v).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let vault_in = pxw::contract_input(&mut rng, &vault_rec, pos, tree.path(pos).unwrap());
        let payout = pxw::output(&mut rng, r.px_account.owner(0), vault_rec.value);
        let mut w = pxw::witness(
            tree.root(),
            0,
            0,
            [vault_in, pxw::dummy_input(&mut rng)],
            [payout, pxw::empty_output(&mut rng)],
        );
        w.n_fn = 1;
        w.functions[0] = Some(fw);
        let words_in = blacksilk_px::prove::witness_words(&w);
        blacksilk_px_core::kernel::transfer(
            &mut HostPerm::new(),
            &mut blacksilk_px_core::kernel::SliceSource::new(&words_in),
        )
        .expect("the kernel accepts the recovered record's refund");
        // The counterparty's claim also still opens it (the terms are the
        // real ones).
        assert_eq!(terms.claim_lock, vault::lock_of(&contract, &secret));
        // Through the wallet file.
        let loaded = Wallet::from_json(&r.to_json()).unwrap();
        assert_eq!(loaded.px_vault_terms(&cm_v), Some(terms));
        // A wallet file of the restored wallet before the recovery recovers
        // at load.
        let fresh = restored_after_scan(&words, contract, &lock);
        let loaded = Wallet::from_json(&fresh.to_json()).unwrap();
        assert_eq!(loaded.px_vault_terms(&cm_v), Some(terms));
        // Another seed with the same (foreign) view recovers nothing.
        let other = wallet(22).mnemonic();
        let mut o = restored_after_scan(&other, contract, &lock);
        assert_eq!(o.recover_vault_locks(), 0);
        // Nor does a lock without the claim lock in its change (a lock
        // without a timeout, or an ordinary change).
        let mut plain = lock.clone();
        plain.3.data = crate::px::digest_hex(&ZERO_DIGEST);
        let mut p = restored_after_scan(&words, contract, &plain);
        assert_eq!(p.recover_vault_locks(), 0);
        // The worst case: a candidate whose vault contract the wallet does
        // not know is searched over the whole timeout range and not found.
        let mut u = restored_after_scan(&words, [0x400, 1, 2, 3, 4, 5, 6, 7], &lock);
        let start = std::time::Instant::now();
        assert_eq!(u.recover_vault_locks(), 0);
        println!(
            "full timeout search ({} candidates): {:?}",
            (RESTORE_TIMEOUT_LOOKBACK + MAX_VAULT_TIMEOUT_AHEAD) / VAULT_TIMEOUT_GRANULE,
            start.elapsed()
        );
    }

    /// RTW1C-8: the lock's dry run of every way out of the record. With the
    /// registered budget, the right secret and a timeout both CLAIM and
    /// REFUND pass; a budget one row short, or a wrong secret (CLAIM halts
    /// with an error), refuses the lock before it is sent.
    #[test]
    fn a_lock_dry_runs_every_way_out_of_the_record() {
        let contract = [0x300, 1, 2, 3, 4, 5, 6, 7];
        let locker = wallet(23);
        let (_, rec, _, _, terms, secret) = timed_lock(&locker, contract, 50, 1_024);
        let refund = locker.px_vault_refund_secret_for(&contract, &rec.rho);
        let ok = |s: &Digest, b: &Budget| {
            dry_run_vault_exits(&rec, s, Some(&refund), &terms, b, 60).is_ok()
        };
        assert!(ok(&secret, &vault::BUDGET));
        assert!(!ok(&[1; 8], &vault::BUDGET), "wrong secret");
        let mut short = vault::BUDGET;
        short.cycles = 1_000;
        assert!(!ok(&secret, &short), "budget too small");
        // Without a timeout: CLAIM only.
        let plain_terms = vault::Terms::claim_only(&contract, &secret);
        let plain = Record {
            data: plain_terms.data(&contract),
            ..rec
        };
        assert!(
            dry_run_vault_exits(&plain, &secret, None, &plain_terms, &vault::BUDGET, 60).is_ok()
        );
        // A timeout too close for a claim.
        assert!(
            dry_run_vault_exits(&rec, &secret, Some(&refund), &terms, &vault::BUDGET, 1_022)
                .is_err()
        );
    }

    /// RTW1C-7: the refund secret uses its own tag, and differs from the
    /// claim secret and the derived `rcm` of the same record.
    #[test]
    fn the_refund_secret_and_rcm_have_their_own_tags() {
        let w = wallet(7);
        let (c, rho) = ([1, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]);
        let hk = w.px_account.hedge_secret();
        let net = [crate::seed::network_code(w.network)];
        let expect = |tag: &str| {
            let h = blacksilk_crypto::hash::h32(
                tag,
                &[hk.as_slice(), &net, &digest_bytes(&c), &digest_bytes(&rho)],
            );
            let mut d = [0u32; 8];
            for (i, x) in d.iter_mut().enumerate() {
                *x = u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().unwrap()) & ((1 << 30) - 1);
            }
            d
        };
        use blacksilk_crypto::hash::tags;
        assert_eq!(
            *w.px_vault_refund_secret_for(&c, &rho),
            expect(tags::PX_WALLET_VAULT_REFUND)
        );
        assert_eq!(
            *w.px_vault_rcm_for(&c, &rho),
            expect(tags::PX_WALLET_VAULT_RCM)
        );
        assert_eq!(
            *w.px_vault_secret_for(&c, &rho),
            expect(tags::PX_WALLET_VAULT_SECRET)
        );
        let all = [
            *w.px_vault_refund_secret_for(&c, &rho),
            *w.px_vault_rcm_for(&c, &rho),
            *w.px_vault_secret_for(&c, &rho),
        ];
        assert!(all[0] != all[1] && all[1] != all[2] && all[0] != all[2]);
    }

    /// The vault must be registered with the current call ABI and its one
    /// output word; any other registration would be uncallable.
    #[test]
    fn a_vault_deploy_needs_the_current_abi_and_one_output_word() {
        let good = Registration::new(vault::VAULT_ELF.to_vec(), vault::BUDGET, vault::OUT_WORDS);
        assert!(check_vault_deploy(std::slice::from_ref(&good)).is_ok());
        let mut abi = good.clone();
        abi.abi = ABI_VERSION + 1;
        assert!(check_vault_deploy(&[abi]).is_err());
        let mut words = good;
        words.out_words = 2;
        assert!(check_vault_deploy(&[words]).is_err());
    }
}
