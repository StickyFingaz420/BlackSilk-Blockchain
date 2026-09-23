use super::transaction::{Transaction, TransactionValidationError};
use std::collections::HashMap;
use parking_lot::RwLock;

#[derive(Debug)]
pub enum MempoolError {
    ValidationError(TransactionValidationError),
    DuplicateTransaction,
    MempoolFull,
    ExceedsMaxAncestors,
}

pub struct MemPool {
    transactions: RwLock<HashMap<Vec<u8>, Transaction>>,
    max_size: usize,
    max_ancestors: usize,
}

impl MemPool {
    pub fn new(max_size: usize, max_ancestors: usize) -> Self {
        Self {
            transactions: RwLock::new(HashMap::new()),
            max_size,
            max_ancestors,
        }
    }

    pub fn add_transaction(&self, tx: Transaction) -> Result<(), MempoolError> {
        // Validate transaction
        tx.validate().map_err(MempoolError::ValidationError)?;

        let tx_hash = tx.hash();
        let mut mempool = self.transactions.write();

        // Check if transaction already exists
        if mempool.contains_key(&tx_hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        // Check mempool size
        if mempool.len() >= self.max_size {
            return Err(MempoolError::MempoolFull);
        }

        // Check ancestor count for inputs
        let ancestor_count = self.count_ancestors(&tx, &mempool);
        if ancestor_count > self.max_ancestors {
            return Err(MempoolError::ExceedsMaxAncestors);
        }

        // Add to mempool
        mempool.insert(tx_hash, tx);
        Ok(())
    }

    fn count_ancestors(&self, tx: &Transaction, mempool: &HashMap<Vec<u8>, Transaction>) -> usize {
        let mut count = 0;
        let mut visited = HashMap::new();

        for input in &tx.inputs {
            if let Some(parent_tx) = mempool.get(&input.prev_tx) {
                count += 1 + self.count_ancestors_recursive(parent_tx, mempool, &mut visited);
            }
        }

        count
    }

    fn count_ancestors_recursive(
        &self,
        tx: &Transaction,
        mempool: &HashMap<Vec<u8>, Transaction>,
        visited: &mut HashMap<Vec<u8>, bool>,
    ) -> usize {
        let mut count = 0;
        let tx_hash = tx.hash();

        if visited.contains_key(&tx_hash) {
            return 0;
        }

        visited.insert(tx_hash, true);

        for input in &tx.inputs {
            if let Some(parent_tx) = mempool.get(&input.prev_tx) {
                count += 1 + self.count_ancestors_recursive(parent_tx, mempool, visited);
            }
        }

        count
    }

    pub fn remove_transaction(&self, tx_hash: &[u8]) -> Option<Transaction> {
        self.transactions.write().remove(tx_hash)
    }

    pub fn get_transaction(&self, tx_hash: &[u8]) -> Option<Transaction> {
        self.transactions.read().get(tx_hash).cloned()
    }

    pub fn clear(&self) {
        self.transactions.write().clear();
    }

    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.transactions.read().values().cloned().collect()
    }
}
