use super::quantum::{QuantumScheme, QuantumSignature, QuantumValidationError};
use super::ring_signature::QuantumRingSignature;

#[derive(Debug)]
pub enum TransactionValidationError {
    InvalidSignature(QuantumValidationError),
    InvalidRingSignature(QuantumValidationError),
    InvalidFormat,
    InvalidAmount,
    InsufficientFunds,
    InvalidFee,
    DoubleSpend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u64,
    pub signature: Option<QuantumSignature>,
    pub ring_signature: Option<QuantumRingSignature>,
}

impl Transaction {
    pub fn validate(&self) -> Result<bool, TransactionValidationError> {
        // Basic validation
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(TransactionValidationError::InvalidFormat);
        }

        // Calculate transaction hash
        let tx_hash = self.hash();

        // Validate quantum signatures if present
        if let Some(ref sig) = self.signature {
            sig.verify(&tx_hash)
                .map_err(TransactionValidationError::InvalidSignature)?;
        }

        // Validate ring signatures if present
        if let Some(ref ring_sig) = self.ring_signature {
            ring_sig.verify(&tx_hash)
                .map_err(TransactionValidationError::InvalidRingSignature)?;
        }

        // Validate amounts and fees
        self.validate_amounts()?;

        Ok(true)
    }

    fn validate_amounts(&self) -> Result<bool, TransactionValidationError> {
        let total_input: u64 = self.inputs.iter()
            .map(|input| input.amount)
            .sum();

        let total_output: u64 = self.outputs.iter()
            .map(|output| output.amount)
            .sum();

        if total_input < total_output {
            return Err(TransactionValidationError::InsufficientFunds);
        }

        let fee = total_input - total_output;
        if fee < self.calculate_min_fee() {
            return Err(TransactionValidationError::InvalidFee);
        }

        Ok(true)
    }

    fn calculate_min_fee(&self) -> u64 {
        // Calculate minimum fee based on transaction size and current network parameters
        let tx_size = self.get_size();
        let base_fee = 1000; // Base fee in atomic units
        let size_multiplier = 100; // Fee per byte in atomic units
        
        base_fee + (tx_size as u64 * size_multiplier)
    }

    pub fn get_size(&self) -> usize {
        // Calculate transaction size including signatures
        let mut size = std::mem::size_of::<u32>() // version
            + std::mem::size_of::<u64>() // lock_time
            + self.inputs.len() * std::mem::size_of::<TransactionInput>()
            + self.outputs.len() * std::mem::size_of::<TransactionOutput>();

        if let Some(ref sig) = self.signature {
            size += sig.signature.len() + sig.public_key.len();
        }

        if let Some(ref ring_sig) = self.ring_signature {
            size += ring_sig.signature.len() 
                + ring_sig.public_keys.iter().map(|pk| pk.len()).sum::<usize>();
        }

        size
    }

    pub fn hash(&self) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        
        // Hash transaction data excluding signatures
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.lock_time.to_le_bytes());
        
        for input in &self.inputs {
            hasher.update(&input.prev_tx);
            hasher.update(&input.prev_index.to_le_bytes());
            hasher.update(&input.amount.to_le_bytes());
        }
        
        for output in &self.outputs {
            hasher.update(&output.amount.to_le_bytes());
            hasher.update(&output.script);
        }

        hasher.finalize().to_vec()
    }
}
