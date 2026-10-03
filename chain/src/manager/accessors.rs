//! Read-only accessors: parameters, rules, the connected tip, state, mempool,
//! headers and stored blocks.

use super::pow_cache::CachedPow;
use super::{ChainManager, OperatorFork};
use crate::block::Block;
use crate::mempool::Mempool;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::validate::BlockError;
use std::cmp::Reverse;
use std::sync::Arc;

impl ChainManager {
    /// The PoW cache shared with the header chain (tests and diagnostics).
    pub fn pow_cache(&self) -> &Arc<CachedPow> {
        &self.pow
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The rules passed to [`Self::open`]: the first epoch's. Blocks and pool
    /// transactions are validated with [`Self::rules_at`] their height, which
    /// differs from these after an activation (docs/consensus.md §11).
    pub fn rules(&self) -> &TxRules {
        &self.rules
    }

    /// The transaction rules of a block at `height`: `TxRules::at_height`
    /// (the epoch's network and branch ids), with the fee and weight limits
    /// given to [`Self::open`].
    pub fn rules_at(&self, height: u64) -> TxRules {
        TxRules {
            fee_per_weight: self.rules.fee_per_weight,
            max_block_weight: self.rules.max_block_weight,
            ..TxRules::at_height(&self.params, height)
        }
    }

    /// The rules a transaction is admitted under now: those of the next block.
    pub fn next_rules(&self) -> TxRules {
        self.rules_at(self.height() + 1)
    }

    /// Height of the connected tip.
    pub fn height(&self) -> u64 {
        (self.connected.len() - 1) as u64
    }

    pub fn tip_id(&self) -> Hash {
        *self.connected.last().expect("genesis is always connected")
    }

    pub fn tip_header(&self) -> &BlockHeader {
        self.headers
            .header(&self.tip_id())
            .expect("connected blocks have headers")
    }

    /// Coins generated so far on the connected chain (fees excluded).
    pub fn generated(&self) -> u64 {
        *self.generated.last().expect("non-empty")
    }

    pub fn state(&self) -> &MemoryChain {
        &self.state
    }

    /// The deepest reorganization (blocks disconnected) since opening.
    pub fn deepest_reorg(&self) -> usize {
        self.deepest_reorg
    }

    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    pub fn headers(&self) -> &HeaderChain {
        &self.headers
    }

    /// The connected block at `height`.
    pub fn block_at(&self, height: u64) -> Option<Block> {
        let id = self.connected.get(height as usize)?;
        let header = *self.headers.header(id)?;
        let txs = if height == 0 {
            Vec::new()
        } else {
            self.bodies.get(id)?.clone()
        };
        Some(Block { header, txs })
    }

    /// Why a block was rejected when connecting, if it was.
    pub fn invalid_reason(&self, id: &Hash) -> Option<&BlockError> {
        self.invalid.get(id)
    }

    /// Whether the operator invalidated the block
    /// ([`Self::invalidate_block`], `--invalidate-block`). Its descendants
    /// are refused too, but are not listed here.
    pub fn operator_invalidated(&self, id: &Hash) -> bool {
        self.operator_invalid.contains(id)
    }

    /// The operator's verdicts in force, sorted by id.
    pub fn operator_verdicts(&self) -> Vec<Hash> {
        let mut ids: Vec<Hash> = self.operator_invalid.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// [`Self::operator_verdicts`] with each block's height, `None` while
    /// its header is not known (the node's `/info`, F48-9). Allocates
    /// nothing while no verdict is in force.
    pub fn operator_verdict_heights(&self) -> Vec<(Hash, Option<u64>)> {
        if self.operator_invalid.is_empty() {
            return Vec::new();
        }
        self.operator_verdicts()
            .into_iter()
            .map(|id| (id, self.headers.header(&id).map(|h| h.height)))
            .collect()
    }

    /// A heavier chain this node refuses only because of the operator's
    /// verdicts (RTW3-8): the heaviest known header in the subtree of an
    /// operator-invalidated block, if it has more work than the connected
    /// tip. Blocks whose bodies broke a rule (`invalid_reason`) and their
    /// descendants do not count: the node would refuse them without the
    /// verdict. Headers under a verdict were fully checked (proof of work
    /// included) before it applied; later children are refused unverified
    /// (`HeaderError::InvalidParent`), so the refused chain's known work is
    /// a lower bound of the network's. Deterministic: ties go to the lowest
    /// branch tip id, then the lowest verdict id. Free while no verdict is
    /// in force; otherwise it walks the verdicts' subtrees.
    pub fn operator_fork(&self) -> Option<OperatorFork> {
        if self.operator_invalid.is_empty() {
            return None;
        }
        let tip_work = self.work(&self.tip_id());
        let mut best: Option<(u128, Reverse<Hash>, Reverse<Hash>)> = None;
        for root in self.operator_verdicts() {
            let mut stack = vec![root];
            while let Some(x) = stack.pop() {
                if self.invalid.contains_key(&x) {
                    continue;
                }
                let Some(w) = self.headers.work(&x) else {
                    continue;
                };
                let key = (w, Reverse(x), Reverse(root));
                if best.is_none_or(|b| key > b) {
                    best = Some(key);
                }
                if let Some(kids) = self.children.get(&x) {
                    stack.extend_from_slice(kids);
                }
            }
        }
        let (w, Reverse(branch_tip), Reverse(block)) = best?;
        if w <= tip_work {
            return None;
        }
        let height_of = |id: &Hash| self.headers.header(id).map_or(0, |h| h.height);
        Some(OperatorFork {
            block,
            height: height_of(&block),
            branch_tip,
            branch_height: height_of(&branch_tip),
            excess_work: w - tip_work,
        })
    }

    // ---- header-first sync (docs/p2p.md §6) ----

    /// Height of the best valid header chain (may exceed [`Self::height`] while
    /// bodies are downloading).
    pub fn header_height(&self) -> u64 {
        self.headers.height()
    }

    pub fn best_header_id(&self) -> Hash {
        self.headers.tip_id()
    }

    pub fn header(&self, id: &Hash) -> Option<&BlockHeader> {
        self.headers.header(id)
    }

    /// Whether the header is known and not invalid.
    pub fn knows_valid_header(&self, id: &Hash) -> bool {
        self.headers.is_valid(id) == Some(true)
    }

    pub fn has_body(&self, id: &Hash) -> bool {
        *id == self.params.genesis_id() || self.bodies.contains_key(id)
    }

    /// Any stored block (main chain or side branch) with its body.
    pub fn block(&self, id: &Hash) -> Option<Block> {
        let header = *self.headers.header(id)?;
        if *id == self.params.genesis_id() {
            return Some(Block {
                header,
                txs: Vec::new(),
            });
        }
        let txs = self.bodies.get(id)?.clone();
        Some(Block { header, txs })
    }
}
