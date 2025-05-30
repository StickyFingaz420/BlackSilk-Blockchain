//! Escrow smart contract for BlackSilk blockchain

use crate::types::Hash;
use sha2::{Sha256, Digest};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowStatus {
    Created,
    Funded,
    Completed,
    Disputed,
    Refunded,
    Voting, // New: voting in progress
    Resolved,
}

#[derive(Debug, Clone)]
pub struct DisputeVote {
    pub voter: Hash, // public key hash
    pub vote: bool, // true = favor buyer, false = favor seller
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
    pub votes: Vec<DisputeVote>, // New: votes for dispute resolution
}

impl EscrowContract {
    /// Create a new escrow contract with real cryptographic hashes
    pub fn new(buyer_pubkey: &[u8], seller_pubkey: &[u8], arbiter_pubkey: &[u8], amount: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(buyer_pubkey);
        let buyer = hasher.finalize_reset().into();

        hasher.update(seller_pubkey);
        let seller = hasher.finalize_reset().into();

        hasher.update(arbiter_pubkey);
        let arbiter = hasher.finalize_reset().into();

        hasher.update(&[buyer, seller, arbiter].concat());
        let contract_id = hasher.finalize().into();

        Self {
            contract_id,
            buyer,
            seller,
            arbiter,
            amount,
            status: EscrowStatus::Created,
            signatures: HashSet::new(),
            votes: Vec::new(),
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

    /// Start a DAO/Community vote for dispute resolution
    pub fn start_voting(&mut self) {
        if self.status == EscrowStatus::Disputed {
            self.status = EscrowStatus::Voting;
            self.votes.clear();
        }
    }

    /// Submit a vote (true = favor buyer, false = favor seller)
    pub fn submit_vote(&mut self, voter: Hash, vote: bool) {
        if self.status == EscrowStatus::Voting && !self.votes.iter().any(|v| v.voter == voter) {
            self.votes.push(DisputeVote { voter, vote });
        }
    }

    /// Tally votes and resolve dispute
    pub fn tally_votes(&mut self) -> Option<bool> {
        if self.status == EscrowStatus::Voting {
            let total = self.votes.len();
            let favor_buyer = self.votes.iter().filter(|v| v.vote).count();
            let favor_seller = total - favor_buyer;
            if total >= 3 { // Example: require at least 3 votes
                self.status = EscrowStatus::Resolved;
                return Some(favor_buyer > favor_seller);
            }
        }
        None
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
        let _contract_id = fake_hash(9);
        let mut contract = EscrowContract::new(&buyer, &seller, &arbiter, 1000);
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
        let _contract_id = fake_hash(8);
        let mut contract = EscrowContract::new(&buyer, &seller, &arbiter, 1000);
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

    #[test]
    fn test_escrow_dispute_voting() {
        let buyer = fake_hash(1);
        let seller = fake_hash(2);
        let arbiter = fake_hash(3);
        let _contract_id = fake_hash(7);
        let mut contract = EscrowContract::new(&buyer, &seller, &arbiter, 1000);
        contract.fund(buyer);
        contract.dispute(buyer);
        contract.start_voting();
        assert_eq!(contract.status, EscrowStatus::Voting);
        // Voters
        let voter1 = fake_hash(4);
        let voter2 = fake_hash(5);
        let voter3 = fake_hash(6);
        // Submit votes
        contract.submit_vote(voter1, true);
        contract.submit_vote(voter2, false);
        contract.submit_vote(voter3, true);
        // Tally votes
        let result = contract.tally_votes();
        assert_eq!(contract.status, EscrowStatus::Resolved);
        assert_eq!(result, Some(true)); // Buyer favored
    }
}