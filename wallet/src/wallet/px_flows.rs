//! Private execution (docs/px.md §11): PX addresses, balances, the output
//! index backfill, planning, deposits, sends and withdrawals.

use super::persistence::h32;
use super::{RingMember, Wallet, WalletError};
use crate::index::IndexedOutput;
use crate::node::NodeApi;
use crate::px::{PX_GAP_LIMIT, PX_LOOKAHEAD, PX_MAX_INDEX_AHEAD};
use blacksilk_consensus::Hash;
use blacksilk_crypto::keys::Address;
use blacksilk_crypto::Point;
use blacksilk_px::wallet as pxw;
use blacksilk_tx::builder::{Decoy, InputPlan, Payment};
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, MAX_INPUTS};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::px_builder::{build_px, px_standard_fee, PxPlan};
use blacksilk_tx::types::{OutputKey, Transaction};
use rand_core::{CryptoRng, RngCore};

/// PX inputs chosen for a spend: the record indices, the kernel's two input
/// witnesses (dummies fill unused slots), their total value, and the anchor.
type PxInputs = (
    Vec<usize>,
    [blacksilk_px_core::kernel::InputWitness; 2],
    u64,
    [u32; 8],
);

impl Wallet {
    // ---- private execution (docs/px.md §11) ----

    /// The PX address `index`, as a string, extending the scan window to it.
    ///
    /// Refused (`WalletError::AddressIndex`) beyond `PX_GAP_LIMIT` above the
    /// highest PX address that has received a record, unless `force`, and
    /// beyond `PX_MAX_INDEX_AHEAD` in any case: every scanned PX address costs
    /// a scalar multiplication for every PX output on chain (review M-1).
    pub fn try_px_address(&mut self, index: u32, force: bool) -> Result<String, WalletError> {
        if index > self.px.issued {
            let limit = Self::index_limit(
                self.px.used_index(),
                PX_GAP_LIMIT,
                PX_MAX_INDEX_AHEAD,
                force,
            );
            if index > limit {
                return Err(WalletError::AddressIndex {
                    index,
                    limit,
                    forced: force,
                });
            }
            self.px.issued = index;
        }
        Ok(blacksilk_chain::address::encode_px_address(
            self.network,
            &self.px_account.address(index),
        ))
    }

    /// `try_px_address` without the override.
    ///
    /// # Panics
    /// If `index` is beyond the gap limit (see `try_px_address`).
    pub fn px_address(&mut self, index: u32) -> String {
        self.try_px_address(index, false)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// Whether a wallet restored from the seed now would find records sent to
    /// PX address `index` by itself (`PX_LOOKAHEAD` beyond the highest found).
    pub fn px_found_by_restore(&self, index: u32) -> bool {
        index
            <= self
                .px
                .used_index()
                .unwrap_or(0)
                .saturating_add(PX_LOOKAHEAD)
    }

    /// PX balance: `(total unspent, spendable now)`.
    pub fn px_balance(&self) -> (u64, u64) {
        self.px.balance(self.synced_height)
    }

    pub(super) fn submit_px(
        &mut self,
        node: &dyn NodeApi,
        tx: PxTx,
        rules: &TxRules,
    ) -> Result<Hash, WalletError> {
        self.submit(node, Transaction::Px(Box::new(tx)), rules)
    }

    /// v1 inputs covering `needed` (largest first), with their rings.
    pub(super) fn v1_plans<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        needed: u64,
        rng: &mut R,
    ) -> Result<(Vec<usize>, Vec<InputPlan>), WalletError> {
        let next = self.synced_height + 1;
        let mut candidates: Vec<usize> = (0..self.outputs.len())
            .filter(|&i| Self::spendable_at(&self.outputs[i], next))
            .collect();
        candidates.sort_by_key(|&i| std::cmp::Reverse(self.outputs[i].amount));
        let chosen = match self.gather(&candidates, |_, sum| sum >= needed as u128) {
            Some((chosen, _)) if chosen.len() > MAX_INPUTS => {
                return Err(WalletError::TooManyInputs)
            }
            Some((chosen, merged)) => {
                if merged {
                    self.merge_warning();
                }
                chosen
            }
            None => {
                return Err(WalletError::InsufficientFunds {
                    available: candidates.iter().map(|&i| self.outputs[i].amount).sum(),
                    needed,
                })
            }
        };
        let plans = self.plans_for(node, &chosen, rng)?;
        Ok((chosen, plans))
    }

    /// Makes the local output index (`crate::index`) cover every output up to
    /// `total` (the node's count through the synced height).
    ///
    /// Outputs the wallet never scanned (below its restore height, or all of
    /// them for a wallet file written before the index existed) are fetched
    /// with `/outputs` **once**, as the whole missing range in fixed pages of
    /// `MAX_OUTPUTS_PER_REQUEST` consecutive indices. The requests depend only
    /// on the index's extent, never on which outputs the wallet spends, so
    /// they reveal nothing about rings (review I3 §3.9; F2 is thereby moot).
    pub(super) fn complete_index(
        &mut self,
        node: &dyn NodeApi,
        total: u64,
    ) -> Result<(), WalletError> {
        // Nothing indexed (an older wallet file with no block synced since):
        // everything through the synced height is missing.
        let end = if self.index.is_empty() {
            total
        } else if self.index.end() != total {
            return Err(WalletError::BadNodeData(format!(
                "the node counts {total} outputs through block {}, the blocks it sent {}",
                self.synced_height,
                self.index.end()
            )));
        } else {
            self.index.start()
        };
        if end == 0 {
            return Ok(());
        }
        let page = blacksilk_rpc::MAX_OUTPUTS_PER_REQUEST as u64;
        // Not pre-allocated: `end` comes from the node.
        let mut older: Vec<IndexedOutput> = Vec::new();
        let mut from = 0u64;
        while from < end {
            let to = (from + page).min(end);
            let query: Vec<u64> = (from..to).collect();
            let fetched = node.outputs(&query).map_err(WalletError::Node)?.outputs;
            if fetched.len() != query.len()
                || fetched.iter().zip(&query).any(|(f, i)| f.index != *i)
            {
                return Err(WalletError::BadNodeData(
                    "outputs do not match the request".into(),
                ));
            }
            for f in fetched {
                let key = h32(&f.one_time_key)?;
                let commitment = h32(&f.commitment)?;
                if Point::decode(&key).is_none() || Point::decode(&commitment).is_none() {
                    return Err(WalletError::BadNodeData(
                        "an output key is not a point".into(),
                    ));
                }
                older.push(IndexedOutput {
                    one_time_key: key,
                    commitment,
                    height: f.height,
                    coinbase: f.coinbase,
                });
            }
            from = to;
        }
        self.index
            .prepend(older, end)
            .map_err(WalletError::BadNodeData)?;
        if !self.index.is_complete(total) {
            return Err(WalletError::BadNodeData(
                "the output index does not match the node's distribution".into(),
            ));
        }
        Ok(())
    }

    /// Rings for the v1 outputs `chosen`, staged for `submit`.
    ///
    /// Privacy of ring construction (review I3 §3.9, docs/reviews/wallet-review.md
    /// F2): ring members are resolved from the local output index, so the node
    /// is not asked about any of them. Only the output distribution (one
    /// request, for the synced height) and, once, a backfill of outputs older
    /// than the restore height (`complete_index`) come from the node.
    ///
    /// Decoys follow the gamma picker with coinbase maturity applied inside the
    /// draw (`blacksilk_tx::decoy`, review R3-1). An output spent before in a
    /// submitted transaction gets that ring again (W-5), as far as its members
    /// still exist unchanged and are eligible.
    pub(super) fn plans_for<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        chosen: &[usize],
        rng: &mut R,
    ) -> Result<Vec<InputPlan>, WalletError> {
        let next = self.synced_height + 1;
        let dist = node
            .distribution(self.synced_height)
            .map_err(WalletError::Node)?;
        let cumulative = &dist.cumulative;
        let total = *cumulative
            .get(self.synced_height as usize)
            .ok_or_else(|| WalletError::BadNodeData("short output distribution".into()))?;
        self.complete_index(node, total)?;
        let target = self.params.target_block_time;
        let decoy_err = |e| WalletError::Decoys(format!("{e:?}"));
        let usable = blacksilk_tx::decoy::usable_outputs(cumulative, next).map_err(decoy_err)?;
        // Coinbase outputs of blocks `0..=next − 60` are mature.
        let coinbase_limit = next
            .checked_sub(COINBASE_MATURITY)
            .and_then(|h| cumulative.get(h as usize).copied())
            .unwrap_or(0);
        let index = &self.index;
        // Eligibility depends on position and maturity only. Outputs sharing
        // a one-time key with another output (allowed since D8 option B) are
        // NOT filtered out (dossier 13 F13-7): the wallet cannot tell a copy
        // from the genuine output, and excluding both would make the genuine
        // one a never-decoy whose later spend is then identified.
        let eligible = |i: u64| {
            i < usable
                && index
                    .get(i)
                    .is_some_and(|e| !(e.coinbase && i >= coinbase_limit))
        };
        let member = |i: u64| -> Result<Decoy, WalletError> {
            let e = index
                .get(i)
                .ok_or_else(|| WalletError::Decoys(format!("output {i} is not indexed")))?;
            let bad = || WalletError::BadNodeData(format!("output {i} is not a point"));
            Ok(Decoy {
                global_index: i,
                key: OutputKey {
                    one_time_key: Point::decode(&e.one_time_key).ok_or_else(bad)?,
                    commitment: Point::decode(&e.commitment).ok_or_else(bad)?,
                },
            })
        };
        let mut plans = Vec::with_capacity(chosen.len());
        let mut staged = Vec::with_capacity(chosen.len());
        for &i in chosen {
            let o = &self.outputs[i];
            let real = o.global_index;
            if real >= usable {
                return Err(WalletError::Decoys("output not yet usable".into()));
            }
            // Our own output, as scanned, must be what the index holds.
            let own = index
                .get(real)
                .ok_or_else(|| WalletError::Decoys("own output not indexed".into()))?;
            if hex::encode(own.one_time_key) != o.one_time_key
                || hex::encode(own.commitment) != o.commitment
            {
                return Err(WalletError::BadNodeData(
                    "the output index disagrees on our output".into(),
                ));
            }
            // Stored members are kept only if the index still holds the same
            // output at that position (a reorganization may have moved it).
            let keep: Vec<u64> = self
                .rings
                .get(&o.key_image)
                .map(|m| {
                    m.iter()
                        .filter(|m| {
                            index.get(m.index).is_some_and(|e| {
                                hex::encode(e.one_time_key) == m.one_time_key
                                    && hex::encode(e.commitment) == m.commitment
                            })
                        })
                        .map(|m| m.index)
                        .collect()
                })
                .unwrap_or_default();
            let ring = blacksilk_tx::decoy::select_ring_keeping(
                rng, cumulative, next, target, real, &keep, eligible,
            )
            .map_err(decoy_err)?;
            let decoys = ring
                .iter()
                .filter(|&&m| m != real)
                .map(|&m| member(m))
                .collect::<Result<Vec<Decoy>, WalletError>>()?;
            staged.push((
                o.key_image.clone(),
                decoys.iter().map(RingMember::of).collect(),
            ));
            plans.push(InputPlan {
                real: Self::to_spendable(o)?,
                decoys,
            });
        }
        self.staged_rings = staged;
        Ok(plans)
    }

    /// Moves `amount` of v1 funds into PX, to PX address 0. The v1 inputs pay
    /// the amount and the standard PX fee. Returns the transaction id and the fee.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    pub fn px_deposit<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        let fee = px_standard_fee();
        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds {
                available: 0,
                needed: u64::MAX,
            })?;
        let (chosen, plans) = self.v1_plans(node, needed, rng)?;
        let root = self
            .px
            .tree_at(crate::px::anchor_height(self.synced_height))?
            .root();
        let owner = self.px_account.owner(0);
        let witness = pxw::witness(
            root,
            amount,
            0,
            [pxw::dummy_input(rng), pxw::dummy_input(rng)],
            [pxw::output(rng, owner, amount), pxw::empty_output(rng)],
        );
        let tx = build_px(
            PxPlan {
                keys: Some(&self.keys),
                inputs: plans,
                change: Some(self.primary()),
                payouts: vec![],
                witness,
                recipients: [Some(self.px_account.address(0)), None],
                functions: vec![],
                fee,
                hedge_secret: self.px_account.hedge_secret(),
            },
            &rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        let id = self.submit_px(node, tx, &rules)?;
        debug_assert!(chosen.iter().all(|&i| self.outputs[i].pending));
        Ok((id, fee))
    }

    /// The PX inputs for spending `needed`: one or two records, plus a
    /// dummy when only one is used.
    pub(super) fn px_inputs<R: RngCore + CryptoRng>(
        &mut self,
        needed: u64,
        rng: &mut R,
    ) -> Result<PxInputs, WalletError> {
        // The canonical anchor (see `px::anchor_height`).
        let anchor = crate::px::anchor_height(self.synced_height);
        let chosen = self.px.select(needed, anchor)?;
        let tree = self.px.tree_at(anchor)?;
        let mut inputs = Vec::with_capacity(2);
        let mut total = 0u64;
        for &i in &chosen {
            let r = &self.px.records[i];
            let pos = r.position.expect("spendable records have positions");
            let owner = self.px_account.owner(r.index);
            let rec = r.record(owner)?;
            let path = tree
                .path(pos)
                .ok_or_else(|| WalletError::BadNodeData("record outside the tree".into()))?;
            inputs.push(self.px_account.spend(r.index, &rec, pos, path));
            total += r.value;
        }
        while inputs.len() < 2 {
            inputs.push(pxw::dummy_input(rng));
        }
        let inputs: [_; 2] = inputs.try_into().expect("two inputs");
        Ok((chosen, inputs, total, tree.root()))
    }

    /// Pays `amount` privately to a PX address; the fee is paid from PX.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    pub fn px_send<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &blacksilk_px::delivery::Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        let fee = px_standard_fee();
        let (chosen, inputs, total, root) = self.px_inputs(amount.saturating_add(fee), rng)?;
        let change = total - amount - fee;
        let witness = pxw::witness(
            root,
            0,
            fee,
            inputs,
            [
                pxw::output(rng, to.owner, amount),
                pxw::output(rng, self.px_account.owner(1), change),
            ],
        );
        let tx = build_px(
            PxPlan {
                keys: None,
                inputs: vec![],
                change: None,
                payouts: vec![],
                witness,
                recipients: [Some(to.clone()), Some(self.px_account.address(1))],
                functions: vec![],
                fee,
                hedge_secret: self.px_account.hedge_secret(),
            },
            &rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let id = self.submit_px(node, tx, &rules)?;
        debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
        Ok((id, fee))
    }

    /// Moves `amount` out of PX to a v1 address (a clear-amount payout); the
    /// fee is paid from PX.
    ///
    /// `rules` only has to belong to this wallet's network: the transaction
    /// is always built with the rules of the block after the synced height
    /// (`next_block_rules`), whatever epoch `rules` is for.
    pub fn px_withdraw<R: RngCore + CryptoRng>(
        &mut self,
        node: &dyn NodeApi,
        to: &Address,
        amount: u64,
        rules: &TxRules,
        rng: &mut R,
    ) -> Result<(Hash, u64), WalletError> {
        self.sync(node)?;
        let rules = self.next_rules(rules)?;
        let fee = px_standard_fee();
        let out = amount.saturating_add(fee);
        let (chosen, inputs, total, root) = self.px_inputs(out, rng)?;
        let change = total - out;
        let witness = pxw::witness(
            root,
            0,
            out,
            inputs,
            [
                pxw::output(rng, self.px_account.owner(1), change),
                pxw::empty_output(rng),
            ],
        );
        let tx = build_px(
            PxPlan {
                keys: None,
                inputs: vec![],
                change: None,
                payouts: vec![Payment {
                    address: *to,
                    amount,
                }],
                witness,
                recipients: [Some(self.px_account.address(1)), None],
                functions: vec![],
                fee,
                hedge_secret: self.px_account.hedge_secret(),
            },
            &rules,
            rng,
        )
        .map_err(|e| WalletError::Rejected(format!("PX build: {e:?}")))?;
        self.px.issued = self.px.issued.max(1);
        let id = self.submit_px(node, tx, &rules)?;
        debug_assert!(chosen.iter().all(|&i| self.px.records[i].pending));
        Ok((id, fee))
    }
}
