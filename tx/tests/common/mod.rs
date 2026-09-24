//! Test harness: an in-memory regtest chain with a miner and wallets that scan it.

#![allow(dead_code)]

use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::ChainParams;
use blacksilk_crypto::keys::{Address, SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::Point;
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_block_transactions, BlockContext, BlockError, ChainView};
use blacksilk_tx::Transfer;
use rand_chacha::rand_core::SeedableRng;
pub use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;

pub const REWARD: u64 = 1_000_000_000;

pub fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn rules() -> TxRules {
    TxRules::for_chain(&ChainParams::regtest())
}

#[derive(Clone)]
pub struct Wallet {
    pub keys: WalletKeys,
    pub table: SubaddressTable,
    pub owned: Vec<OwnedOutput>,
    pub spent: HashSet<Point>,
}

impl Wallet {
    pub fn new(rng: &mut ChaCha20Rng) -> Self {
        let (keys, _) = WalletKeys::generate(rng);
        let table = SubaddressTable::new(keys.view_keys(), 2, 10);
        Self {
            keys,
            table,
            owned: Vec::new(),
            spent: HashSet::new(),
        }
    }

    pub fn address(&self, account: u32, index: u32) -> Address {
        self.keys.address(SubaddressIndex::new(account, index))
    }

    pub fn primary(&self) -> Address {
        self.address(0, 0)
    }

    /// Unspent outputs spendable at `height`.
    pub fn spendable(&self, height: u64) -> Vec<&OwnedOutput> {
        self.owned
            .iter()
            .filter(|o| !self.spent.contains(&o.key_image(&self.keys)))
            .filter(|o| {
                let age = if o.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                height >= o.height + age
            })
            .collect()
    }

    pub fn balance(&self) -> u128 {
        self.owned
            .iter()
            .filter(|o| !self.spent.contains(&o.key_image(&self.keys)))
            .map(|o| o.received.amount as u128)
            .sum()
    }

    pub fn observe(&mut self, txs: &[Transaction], height: u64, first: u64) {
        let r = scan_block(self.keys.view_keys(), &self.table, txs, height, first);
        self.owned.extend(r.owned);
        let mine: HashSet<Point> = self.owned.iter().map(|o| o.key_image(&self.keys)).collect();
        for tx in txs {
            for ki in tx.key_images() {
                if mine.contains(&ki) {
                    self.spent.insert(ki);
                }
            }
        }
    }
}

pub struct TestNet {
    pub chain: MemoryChain,
    pub rules: TxRules,
    pub miner: Wallet,
    pub rng: ChaCha20Rng,
}

impl TestNet {
    /// A chain with `blocks` mined blocks (coinbase only) paying the miner.
    pub fn new(seed: u64, blocks: u64) -> Self {
        let mut rng = rng(seed);
        let miner = Wallet::new(&mut rng);
        let mut net = Self {
            chain: MemoryChain::new(),
            rules: rules(),
            miner,
            rng,
        };
        for _ in 0..blocks {
            net.mine(vec![], &mut []).unwrap();
        }
        net
    }

    pub fn height(&self) -> u64 {
        self.chain.next_height()
    }

    /// A snapshot of the miner's wallet (so it can be passed to `pay`).
    pub fn miner_clone(&self) -> Wallet {
        self.miner.clone()
    }

    pub fn coinbase(&mut self, fees: u64) -> Transaction {
        let h = self.height();
        let secret = self.miner.keys.hedge_secret();
        Transaction::Coinbase(
            build_coinbase(
                h,
                &[Payment {
                    address: self.miner.primary(),
                    amount: REWARD + fees,
                }],
                &secret,
                &mut self.rng,
            )
            .unwrap(),
        )
    }

    pub fn context(&self, txs: &[Transaction]) -> BlockContext {
        let ids: Vec<_> = txs.iter().map(Transaction::hash).collect();
        BlockContext {
            height: self.height(),
            reward: REWARD,
            tx_root: tx_root(&ids),
        }
    }

    /// Validates and applies a block with the given transfers (plus a correct
    /// coinbase); every wallet in `watchers` and the miner scan it.
    pub fn mine(
        &mut self,
        transfers: Vec<Transfer>,
        watchers: &mut [&mut Wallet],
    ) -> Result<(), BlockError> {
        let fees: u64 = transfers.iter().map(|t| t.fee).sum();
        let mut txs = vec![self.coinbase(fees)];
        txs.extend(transfers.into_iter().map(Transaction::from));
        self.submit(txs, watchers)
    }

    /// Validates and applies an arbitrary block body.
    pub fn submit(
        &mut self,
        txs: Vec<Transaction>,
        watchers: &mut [&mut Wallet],
    ) -> Result<(), BlockError> {
        let ctx = self.context(&txs);
        validate_block_transactions(&txs, &ctx, &self.chain, &self.rules, &mut self.rng)?;
        let height = self.height();
        let first = self.chain.apply_block(&txs);
        self.miner.observe(&txs, height, first);
        for w in watchers.iter_mut() {
            w.observe(&txs, height, first);
        }
        Ok(())
    }

    /// An input plan for `real` with 15 decoys from the gamma picker.
    pub fn plan(&mut self, real: &OwnedOutput) -> InputPlan {
        let height = self.height();
        let cumulative = self.chain.cumulative_outputs();
        let chain = &self.chain;
        let eligible = |i: u64| {
            chain.output(i).is_some_and(|r| {
                let age = if r.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                height >= r.height + age
            })
        };
        let ring = select_ring(
            &mut self.rng,
            &cumulative,
            height,
            120,
            real.global_index,
            eligible,
        )
        .expect("enough decoys");
        let decoys = ring
            .iter()
            .filter(|&&i| i != real.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: self.chain.output(i).unwrap().key,
            })
            .collect();
        InputPlan {
            real: SpendableOutput::from(real),
            decoys,
        }
    }

    /// `from` pays `amount` to each address, spending its first spendable outputs.
    pub fn pay(&mut self, from: &Wallet, to: &[(Address, u64)]) -> Transfer {
        let height = self.height();
        let total: u64 = to.iter().map(|p| p.1).sum();
        let spendable: Vec<OwnedOutput> = from.spendable(height).into_iter().cloned().collect();
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for o in spendable {
            chosen.push(o.clone());
            sum += o.received.amount as u128;
            let fee = standard_fee(chosen.len(), to.len() + 1, &self.rules) as u128;
            if sum >= total as u128 + fee {
                break;
            }
        }
        let fee = standard_fee(chosen.len(), to.len() + 1, &self.rules);
        let plans: Vec<InputPlan> = chosen.iter().map(|o| self.plan(o)).collect();
        let payments: Vec<Payment> = to
            .iter()
            .map(|&(address, amount)| Payment { address, amount })
            .collect();
        build_transfer(
            &from.keys,
            plans,
            &payments,
            &from.primary(),
            fee,
            &self.rules,
            &mut self.rng,
        )
        .expect("build")
    }
}
