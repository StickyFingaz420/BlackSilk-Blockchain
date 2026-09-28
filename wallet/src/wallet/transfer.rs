//! Transparent transfers: input gathering and selection, and building.

use super::persistence::{point, scalar};
use super::{StoredOutput, Wallet, WalletError};
use crate::node::NodeApi;
use blacksilk_consensus::Hash;
use blacksilk_crypto::keys::{Address, SubaddressIndex};
use blacksilk_tx::builder::{build_transfer, standard_fee, Payment, SpendableOutput};
use blacksilk_tx::params::{TxRules, MAX_INPUTS};
use blacksilk_tx::types::{OutputKey, Transaction};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashSet;

impl Wallet {
    // ---- transfers ----
    pub(super) fn to_spendable(o: &StoredOutput) -> Result<SpendableOutput, WalletError> {
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

    /// Adds inputs from `order` (largest first) until `enough(count, sum)`.
    ///
    /// Merge avoidance (review R3-13): spending two outputs of one transaction
    /// together tells observers that both real inputs came from it (Kumar et
    /// al. 2017; Möser et al. 2018). So the first pass takes at most one output
    /// per source transaction; only if that cannot cover the amount does a
    /// plain largest-first pass run. Returns the inputs and whether they
    /// include two outputs of one source, or `None` if everything is not
    /// enough. The result may exceed `MAX_INPUTS`; callers refuse that.
    pub(super) fn gather(
        &self,
        order: &[usize],
        enough: impl Fn(usize, u128) -> bool,
    ) -> Option<(Vec<usize>, bool)> {
        let mut sources = HashSet::new();
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in order {
            if chosen.len() == MAX_INPUTS {
                break;
            }
            if sources.insert(self.outputs[i].source()) {
                chosen.push(i);
                sum += self.outputs[i].amount as u128;
                if enough(chosen.len(), sum) {
                    return Some((chosen, false));
                }
            }
        }
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for &i in order {
            chosen.push(i);
            sum += self.outputs[i].amount as u128;
            if chosen.len() > MAX_INPUTS {
                return Some((chosen, false));
            }
            if enough(chosen.len(), sum) {
                let distinct: HashSet<String> =
                    chosen.iter().map(|&i| self.outputs[i].source()).collect();
                let merged = distinct.len() < chosen.len();
                return Some((chosen, merged));
            }
        }
        None
    }

    /// The warning for inputs that include outputs of one source transaction.
    pub(super) fn merge_warning(&mut self) {
        self.warnings.push(
            "this transaction spends two or more outputs that were created by the same \
             transaction; observers can link them and guess the real inputs of its rings \
             (there was no other way to cover the amount)"
                .into(),
        );
    }

    /// Chooses inputs: the smallest single output that covers everything if one
    /// exists (fewest inputs, least change linkage), otherwise largest-first,
    /// avoiding outputs of one source transaction together (`gather`).
    pub(super) fn select_inputs(
        &mut self,
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
        candidates.reverse();
        let fee = |n: usize| standard_fee(n, payments + 1, rules);
        match self.gather(&candidates, |n, sum| sum >= amount as u128 + fee(n) as u128) {
            Some((chosen, _)) if chosen.len() > MAX_INPUTS => Err(WalletError::TooManyInputs),
            Some((chosen, merged)) => {
                if merged {
                    self.merge_warning();
                }
                let f = fee(chosen.len());
                Ok((chosen, f))
            }
            None => Err(WalletError::InsufficientFunds {
                available,
                needed: amount.saturating_add(fee(candidates.len().max(1))),
            }),
        }
    }

    /// Builds, submits and records a transfer of `amount` to `to`. Change goes to
    /// the primary address. Returns the transaction id and the fee.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    pub fn transfer<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync_to_send(node)?;
        let rules = self.next_rules(rules)?;
        let (inputs, fee) = self.select_inputs(amount, 1, &rules)?;
        let plans = self.plans_for(node, &inputs, rng)?;
        let tx = build_transfer(
            &self.keys,
            plans,
            &[Payment {
                address: *to,
                amount,
            }],
            &self.primary(),
            fee,
            &rules,
            rng,
        )
        .map_err(WalletError::Build)?;
        let id = self.submit(node, Transaction::from(tx), &rules)?;
        debug_assert!(inputs.iter().all(|&i| self.outputs[i].pending));
        Ok((id, fee))
    }
}
