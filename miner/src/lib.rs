//! Miner library: builds a block from a node template and searches nonces with
//! RandomX. The PoW rules are the consensus crate's (`check_hash`, header layout),
//! so a block this miner finds is exactly what the node verifies.

#![forbid(unsafe_code)]

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{check_hash, BlockHeader, Hash, HEADER_VERSION, NONCE_OFFSET};
use blacksilk_crypto::keys::Address;
use blacksilk_randomx::{Cache, Dataset, Vm};
use blacksilk_rpc as rpc;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::types::Transaction;
use rand_core::{CryptoRng, RngCore};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug)]
pub enum TemplateError {
    Hex(&'static str),
    Tx(usize),
    Coinbase,
}

/// Builds the block for `template`, paying `reward + fees` to `payout`.
/// The header timestamp is `max(min_timestamp, now)`; the nonce starts at 0.
pub fn build_block<R: RngCore + CryptoRng>(
    template: &rpc::Template,
    payout: &Address,
    hedge_secret: &[u8],
    now: u64,
    rng: &mut R,
) -> Result<Block, TemplateError> {
    let prev_id = rpc::parse_hash(&template.prev_id).ok_or(TemplateError::Hex("prev_id"))?;
    let mut txs = Vec::with_capacity(template.txs.len() + 1);
    let coinbase = build_coinbase(
        template.height,
        &[Payment {
            address: *payout,
            amount: template.reward + template.fees,
        }],
        hedge_secret,
        rng,
    )
    .map_err(|_| TemplateError::Coinbase)?;
    txs.push(Transaction::Coinbase(coinbase));
    for (i, h) in template.txs.iter().enumerate() {
        let bytes = hex::decode(h).map_err(|_| TemplateError::Tx(i))?;
        txs.push(Transaction::decode(&bytes).map_err(|_| TemplateError::Tx(i))?);
    }
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        version: HEADER_VERSION,
        height: template.height,
        prev_id,
        timestamp: now.max(template.min_timestamp),
        difficulty: template.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
    };
    log::debug!(
        "template {}: {} txs, payout {}",
        template.height,
        txs.len() - 1,
        format_amount(template.reward + template.fees)
    );
    Ok(Block { header, txs })
}

/// RandomX state for one seed: light (256 MiB cache, slow) or full (2 GiB
/// dataset, fast).
pub enum PowContext {
    Light { seed: Hash, cache: Cache },
    Full { seed: Hash, dataset: Dataset },
}

impl PowContext {
    pub fn new(seed: Hash, full: bool, threads: usize) -> Self {
        let cache = Cache::new(&seed);
        if full {
            let dataset = Dataset::new(&cache, threads.max(1));
            PowContext::Full { seed, dataset }
        } else {
            PowContext::Light { seed, cache }
        }
    }

    pub fn seed(&self) -> &Hash {
        match self {
            PowContext::Light { seed, .. } | PowContext::Full { seed, .. } => seed,
        }
    }

    fn vm(&self) -> Vm<'_> {
        match self {
            PowContext::Light { cache, .. } => Vm::light(cache),
            PowContext::Full { dataset, .. } => Vm::full(dataset),
        }
    }
}

/// Result of a nonce search.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub nonce: u64,
    pub pow_hash: Hash,
}

/// Searches nonces `start, start+1, …` across `threads` threads until one meets
/// the header's difficulty, `stop` is set, or `max_hashes` hashes were tried.
/// Returns the found nonce and the number of hashes computed.
pub fn search(
    pow: &PowContext,
    header: &BlockHeader,
    start: u64,
    threads: usize,
    max_hashes: u64,
    stop: &AtomicBool,
) -> (Option<Found>, u64) {
    let threads = threads.max(1) as u64;
    let found: Mutex<Option<Found>> = Mutex::new(None);
    let hashes = AtomicU64::new(0);
    let base = header.to_bytes();
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, hashes, base) = (&found, &hashes, base);
            s.spawn(move || {
                let mut vm = pow.vm();
                let mut bytes = base;
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let k = i * threads + t;
                    if k >= max_hashes {
                        break;
                    }
                    let nonce = start.wrapping_add(k);
                    bytes[NONCE_OFFSET..NONCE_OFFSET + 8].copy_from_slice(&nonce.to_le_bytes());
                    let h = vm.hash(&bytes);
                    hashes.fetch_add(1, Ordering::Relaxed);
                    if check_hash(&h, header.difficulty) {
                        let mut f = found.lock().unwrap_or_else(|e| e.into_inner());
                        if f.is_none() {
                            *f = Some(Found { nonce, pow_hash: h });
                        }
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    i += 1;
                }
            });
        }
    });
    (
        found.into_inner().unwrap_or_else(|e| e.into_inner()),
        hashes.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::{ChainParams, HeaderChain, RandomXPow};
    use std::sync::Arc;

    #[test]
    fn found_nonce_verifies_with_consensus() {
        let params = ChainParams::regtest();
        let chain = HeaderChain::new(params.clone(), Arc::new(RandomXPow::new()));
        let t = chain.template();
        let mut header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(params.genesis.timestamp + 120),
            difficulty: 3,
            tx_root: [5; 32],
            nonce: 0,
        };
        let pow = PowContext::new(t.seed_id, false, 2);
        let stop = AtomicBool::new(false);
        let (found, n) = search(&pow, &header, 1000, 2, 200, &stop);
        let found = found.expect("difficulty 3 is found within 200 hashes");
        assert!(n >= 1);
        header.nonce = found.nonce;
        let h = blacksilk_randomx::hash_light(&t.seed_id, &header.to_bytes());
        assert_eq!(h, found.pow_hash);
        assert!(check_hash(&h, 3));
    }

    #[test]
    fn stop_flag_and_limit_end_the_search() {
        let pow = PowContext::new([1; 32], false, 1);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: 1,
            prev_id: [0; 32],
            timestamp: 0,
            difficulty: u64::MAX,
            tx_root: [0; 32],
            nonce: 0,
        };
        let stop = AtomicBool::new(false);
        let (found, n) = search(&pow, &header, 0, 2, 4, &stop);
        assert_eq!(found, None);
        assert_eq!(n, 4);
        stop.store(true, Ordering::Relaxed);
        let (found, n) = search(&pow, &header, 0, 2, 1000, &stop);
        assert_eq!((found, n), (None, 0));
    }
}
