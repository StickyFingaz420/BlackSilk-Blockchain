//! Private contracts (docs/contracts.md): deploys, vault lock, claim and
//! refund, vault secrets, and record sharing and import.

use super::{Wallet, WalletError};
use crate::node::NodeApi;
use crate::px::{ContractRecord, KnownContract, RecordSource, PX_LOOKAHEAD};
use blacksilk_consensus::Hash;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet as pxw;
use blacksilk_px::{delivery, share, vault};
use blacksilk_px_core::call::{Window, ABI_VERSION};
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
        self.sync(node)?;
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
    /// this wallet can take the value back ([`Self::px_vault_refund`]), with
    /// a refund secret it derives from its keys and the record's `rho`
    /// ([`Self::px_vault_refund_secret_for`]). The timeout is public once
    /// the record is claimed or refunded (the transaction's validity window,
    /// PX6), so round it (to a multiple of 16, as anchors are), and leave a
    /// margin for a claim to confirm: a miner can delay it. Returns the
    /// transaction id, the record's commitment and its [`vault::Terms`],
    /// which the claimer needs (with the secret) and the refund needs (the
    /// timeout); the wallet does not store the timeout.
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
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        if timeout != 0 && timeout <= self.synced_height + 1 {
            return Err(WalletError::Contract(
                "the vault timeout must be above the next block's height".into(),
            ));
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
        // input's nullifier, so the refund secret is derivable again later.
        let terms = if timeout == 0 {
            vault::Terms::claim_only(contract, secret)
        } else {
            let rho = self.vault_lock_rho(&inputs[0])?;
            let refund = self.px_vault_refund_secret_for(contract, &rho);
            vault::Terms {
                claim_lock: vault::lock_of(contract, secret),
                refund_lock: vault::refund_lock_of(contract, &refund),
                timeout,
            }
        };
        let data = terms.data(contract);
        // The caller's own random values, hedged (W28-4): the function's
        // blind and the vault record's `rcm` (the opening this wallet keeps).
        let window = Window::UNBOUNDED;
        let hk = Zeroizing::new(self.px_account.hedge_secret());
        let context = lock_context(contract, amount, &data, &inputs);
        let items: Vec<&[u8]> = context.iter().map(|v| v.as_slice()).collect();
        let blind =
            pxw::hedged_digest(&[hk.as_slice()], pxw::witness_labels::FN_BLIND, &items, rng);
        let mut vault_out = pxw::contract_output(rng, *contract, amount, data);
        vault_out.rcm = pxw::hedged_digest(
            &[hk.as_slice()],
            pxw::witness_labels::CONTRACT_RCM,
            &items,
            rng,
        );
        drop(hk);
        let (input, fw) = vault::lock_call(contract, amount, &terms, 0, &blind, &window);
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
        if timeout != 0 {
            let refund = self.px_vault_refund_secret_for(contract, &rho);
            if vault::refund_lock_of(contract, &refund) != terms.refund_lock {
                return Err(WalletError::Contract(
                    "the derived refund secret does not match the vault record".into(),
                ));
            }
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
    /// claim's validity window ends at `T − 1`: a block at `T` or later can
    /// no longer include it, and from `T` on the locker can refund.
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
    /// this wallet's keys; the claim lock comes from the stored (or derived)
    /// claim secret. Pays to `to` or to this wallet. Returns the transaction
    /// id and the refunded value.
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
        let claim_secret = match self.px.contract_records[k].secret.as_deref() {
            Some(hex) => Zeroizing::new(crate::px::digest_from_hex(hex)?),
            None => self.px_vault_secret_for(&rec.contract, &rec.rho),
        };
        let refund = self.px_vault_refund_secret_for(&rec.contract, &rec.rho);
        let terms = vault::Terms {
            claim_lock: vault::lock_of(&rec.contract, &claim_secret),
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
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        let next = self.synced_height + 1;
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
        if terms.data(&rec.contract) != rec.data {
            return Err(WalletError::Contract(
                "these terms do not open this vault record".into(),
            ));
        }
        // The validity window (PX6) the vault checks: a claim must be
        // included before the timeout, a refund from it on.
        let window = match (selector, terms.timeout) {
            (_, 0) => Window::UNBOUNDED,
            (vault::CLAIM, t) => {
                if next >= t {
                    return Err(WalletError::Contract(
                        "the vault's timeout has passed: it can only be refunded".into(),
                    ));
                }
                Window {
                    not_before: 0,
                    not_after: t - 1,
                }
            }
            (_, t) => {
                if next < t {
                    return Err(WalletError::Contract(format!(
                        "the vault can be refunded from height {t} on (next block: {next})"
                    )));
                }
                Window {
                    not_before: t,
                    not_after: 0,
                }
            }
        };
        let budget = self.vault_budget(&rec.contract)?;
        let fee = px_standard_fee();
        let tree = self.px.tree_at(anchor)?;
        let path = tree
            .path(pos)
            .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
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
    /// `contract` whose `rho` is `rho`: the vault-secret derivation
    /// (`px_vault_secret_for`, dossier 37 K6) with the suffix `"refund"`,
    /// `H32("px/wallet/vault-secret/v1", hk_px ‖ u8 network ‖ contract ‖ rho
    /// ‖ "refund")`, read as eight LE32 limbs reduced to 30 bits. Every part
    /// before the suffix has a fixed length, so it never equals a claim
    /// secret's input. Wallet side, seed-recoverable.
    pub fn px_vault_refund_secret_for(&self, contract: &Digest, rho: &Digest) -> Zeroizing<Digest> {
        let hk = Zeroizing::new(self.px_account.hedge_secret());
        let net = [crate::seed::network_code(self.network)];
        let h = Zeroizing::new(blacksilk_crypto::hash::h32(
            blacksilk_crypto::hash::tags::PX_WALLET_VAULT_SECRET,
            &[
                hk.as_slice(),
                &net,
                &digest_bytes(contract),
                &digest_bytes(rho),
                REFUND_SECRET_SUFFIX,
            ],
        ));
        let mut secret = Zeroizing::new([0u32; 8]);
        for (i, x) in secret.iter_mut().enumerate() {
            let w = u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().expect("4 bytes"));
            *x = w & ((1 << 30) - 1);
        }
        secret
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

/// Suffix of the refund-secret derivation input
/// ([`Wallet::px_vault_refund_secret_for`]).
const REFUND_SECRET_SUFFIX: &[u8] = b"refund";

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
                    "the vault must be registered with the current call ABI and its one output                      word (vault::OUT_WORDS)"
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
