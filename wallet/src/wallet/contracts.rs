//! Private contracts (docs/px.md §13): deploys, vault lock and claim, vault
//! secrets, and record sharing and import.

use super::{Wallet, WalletError};
use crate::node::NodeApi;
use crate::px::{ContractRecord, KnownContract, RecordSource, PX_LOOKAHEAD};
use blacksilk_consensus::Hash;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::wallet as pxw;
use blacksilk_px::{delivery, share, vault};
use blacksilk_px_core::record::{output_rho, Record};
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::{TxRules, MAX_INPUTS};
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
        let mut fee = deploy_fee(1, 2, &programs);
        for &i in &candidates {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            fee = deploy_fee(chosen.len(), 2, &programs);
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
    /// `contract`, under `Hk(LOCK, secret)`. The record's ciphertext goes to
    /// `deliver_to` (the party that will claim it) or to this wallet; this
    /// wallet keeps its own copy either way. The fee is paid from PX. Returns
    /// the transaction id and the vault record's commitment.
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
        secret: &Digest,
        deliver_to: Option<&delivery::Address>,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, Digest), WalletError> {
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        let budget = self.vault_budget(contract)?;
        let fee = px_standard_fee();
        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds {
                available: 0,
                needed: u64::MAX,
            })?;
        let (chosen, inputs, total, root) = self.px_inputs(needed, rng)?;
        let lock = vault::lock_of(secret);
        let blind = pxw::random_digest(rng);
        let (input, fw) = vault::lock_call(contract, amount, &lock, 0, &blind);
        let vault_out = pxw::contract_output(rng, *contract, amount, lock);
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
            data: lock,
            rho,
            rcm: vault_out.rcm,
        };
        let cm = tx.commitments[0];
        if record.commit(&mut HostPerm::new()) != cm {
            return Err(WalletError::Contract(
                "vault record does not match its commitment".into(),
            ));
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
                Ok((id, cm))
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
    /// its value to `to` (a PX address) or to this wallet. The fee is paid
    /// from one of this wallet's PX records, or else from v1 funds. Returns
    /// the transaction id and the claimed value.
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
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
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
        if vault::lock_of(secret) != rec.data {
            return Err(WalletError::Contract(
                "wrong secret for this vault record".into(),
            ));
        }
        let budget = self.vault_budget(&rec.contract)?;
        let fee = px_standard_fee();
        let tree = self.px.tree_at(anchor)?;
        let path = tree
            .path(pos)
            .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
        let vault_in = pxw::contract_input(rng, &rec, pos, path);
        let recipient = to.cloned().unwrap_or_else(|| self.px_account.address(0));
        let blind = pxw::random_digest(rng);
        let (input, fw) = vault::claim_call(&rec, secret, &recipient.owner, 0, 0, &blind);
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
    /// before the lock was sent). Checked against the record's lock.
    pub fn px_vault_secret(&self, record: &Digest) -> Result<Zeroizing<Digest>, WalletError> {
        let k = self
            .px
            .contract_record(record)
            .ok_or_else(|| WalletError::Contract("unknown contract record".into()))?;
        let r = &self.px.contract_records[k];
        let hex = r.secret.as_deref().ok_or_else(|| {
            WalletError::Contract(
                "no secret stored for this record (not locked by this wallet)".into(),
            )
        })?;
        let secret = Zeroizing::new(crate::px::digest_from_hex(hex)?);
        if vault::lock_of(&secret) != r.record()?.data {
            return Err(WalletError::Contract(
                "the stored secret does not open this record".into(),
            ));
        }
        Ok(secret)
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

/// Refuses a deploy that registers the reference vault next to other programs,
/// or with a budget other than `vault::BUDGET`: the wallet would refuse to use
/// such a contract as a vault (`PxStore::vault_budget`, reviews P-1, P-2), and
/// a contract's records can be spent by any of its programs.
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
