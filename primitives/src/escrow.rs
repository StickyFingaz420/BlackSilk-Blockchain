//! Escrow smart contract for BlackSilk blockchain

use crate::types::Hash;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowStatus {
    Created,
    Funded,
    Completed,
    Disputed,
    Refunded,
}

#[derive(Debug, Clone)]
pub struct EscrowContract {
    pub contract_id: Hash,
    pub buyer: Hash,    // Public key hash
    pub seller: Hash,   // Public key hash
    pub arbiter: Hash,  // Public key hash
    pub amount: u64,
    pub status: EscrowStatus,
    pub signatures: HashSet<Hash>, // Set of signers (for multisig)
}

impl EscrowContract {
    /// Create a new escrow contract
    pub fn new(contract_id: Hash, buyer: Hash, seller: Hash, arbiter: Hash, amount: u64) -> Self {
        Self {
            contract_id,
            buyer,
            seller,
            arbiter,
            amount,
            status: EscrowStatus::Created,
            signatures: HashSet::new(),
        }
    }

    /// Fund the contract (buyer locks funds)
    pub fn fund(&mut self, buyer_sig: Hash) {
        if self.status == EscrowStatus::Created {
            self.signatures.insert(buyer_sig);
            self.status = EscrowStatus::Funded;
        }
    }

    /// Sign for release (multisig: any 2 of 3)
    pub fn sign_release(&mut self, signer: Hash) {
        if self.status == EscrowStatus::Funded || self.status == EscrowStatus::Disputed {
            self.signatures.insert(signer);
        }
    }

    /// Check if contract can be released (2 of 3 signatures)
    pub fn can_release(&self) -> bool {
        self.signatures.len() >= 2
    }

    /// Release funds to seller
    pub fn release(&mut self) -> bool {
        if self.can_release() && (self.status == EscrowStatus::Funded || self.status == EscrowStatus::Disputed) {
            self.status = EscrowStatus::Completed;
            true
        } else {
            false
        }
    }

    /// Refund to buyer (2 of 3 signatures)
    pub fn refund(&mut self) -> bool {
        if self.can_release() && (self.status == EscrowStatus::Funded || self.status == EscrowStatus::Disputed) {
            self.status = EscrowStatus::Refunded;
            true
        } else {
            false
        }
    }

    /// Raise a dispute (by buyer or seller)
    pub fn dispute(&mut self, by: Hash) {
        if self.status == EscrowStatus::Funded && (by == self.buyer || by == self.seller) {
            self.status = EscrowStatus::Disputed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fake_hash(val: u8) -> Hash { [val; 32] }

    #[test]
    fn test_escrow_flow() {
        let buyer = fake_hash(1);
        let seller = fake_hash(2);
        let arbiter = fake_hash(3);
        let contract_id = fake_hash(9);
        let mut contract = EscrowContract::new(contract_id, buyer, seller, arbiter, 1000);
        assert_eq!(contract.status, EscrowStatus::Created);
        contract.fund(buyer);
        assert_eq!(contract.status, EscrowStatus::Funded);
        // Buyer and seller sign to release
        contract.sign_release(buyer);
        contract.sign_release(seller);
        assert!(contract.can_release());
        assert!(contract.release());
        assert_eq!(contract.status, EscrowStatus::Completed);
    }

    #[test]
    fn test_escrow_dispute_and_refund() {
        let buyer = fake_hash(1);
        let seller = fake_hash(2);
        let arbiter = fake_hash(3);
        let contract_id = fake_hash(8);
        let mut contract = EscrowContract::new(contract_id, buyer, seller, arbiter, 1000);
        contract.fund(buyer);
        contract.dispute(buyer);
        assert_eq!(contract.status, EscrowStatus::Disputed);
        // Buyer and arbiter sign to refund
        contract.sign_release(buyer);
        contract.sign_release(arbiter);
        assert!(contract.can_release());
        assert!(contract.refund());
        assert_eq!(contract.status, EscrowStatus::Refunded);
    }
} 