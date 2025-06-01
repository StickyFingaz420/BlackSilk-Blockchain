//! Escrow smart contract for BlackSilk blockchain

use crate::types::Hash;
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowStatus {
    Created,
    Funded,
    Completed,
    Disputed,
    Refunded,
    Voting, // New: voting in progress
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeVote {
    pub voter: Hash, // public key hash
    pub vote: bool, // true = favor buyer, false = favor seller
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        println!("Dispute called by: {:?}", by);
        println!("Buyer: {:?}, Seller: {:?}", self.buyer, self.seller);
        if self.status == EscrowStatus::Funded && (by == self.buyer || by == self.seller) {
            self.status = EscrowStatus::Disputed;
            println!("Status changed to Disputed");
        } else {
            println!("Dispute conditions not met");
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
    use sha2::{Sha256, Digest};

    // Replace fake_hash with a professional hash generation method
    fn generate_hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    #[test]
    fn test_escrow_flow() {
        let buyer = generate_hash(b"buyer");
        let seller = generate_hash(b"seller");
        let arbiter = generate_hash(b"arbiter");
        let _contract_id = generate_hash(b"contract_id");
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
        let buyer = generate_hash(b"buyer");
        let seller = generate_hash(b"seller");
        let arbiter = generate_hash(b"arbiter");
        let _contract_id = generate_hash(b"contract_id");
        let mut contract = EscrowContract::new(&buyer, &seller, &arbiter, 1000);

        println!("Initial status: {:?}", contract.status);
        contract.fund(buyer);
        println!("After funding: {:?}", contract.status);

        contract.dispute(buyer);
        println!("After dispute: {:?}", contract.status);

        // Buyer and arbiter sign to refund
        contract.sign_release(buyer);
        println!("After buyer signs: {:?}", contract.signatures);

        contract.sign_release(arbiter);
        println!("After arbiter signs: {:?}", contract.signatures);

        assert!(contract.can_release());
        assert!(contract.refund());
        println!("After refund: {:?}", contract.status);

        assert_eq!(contract.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_escrow_dispute_voting() {
        let buyer_pubkey = generate_hash(b"buyer");
        let seller_pubkey = generate_hash(b"seller");
        let arbiter_pubkey = generate_hash(b"arbiter");
        let _contract_id = generate_hash(b"contract_id");
        let mut contract = EscrowContract::new(&buyer_pubkey, &seller_pubkey, &arbiter_pubkey, 1000);

        println!("Initial status: {:?}", contract.status);
        contract.fund(generate_hash(b"fund"));
        println!("After funding: {:?}", contract.status);

        // Ensure the dispute is raised by the buyer
        contract.dispute(buyer_pubkey);
        println!("After dispute by buyer: {:?}", contract.status);
        assert_eq!(contract.status, EscrowStatus::Disputed);

        // Start voting
        contract.start_voting();
        println!("After starting voting: {:?}", contract.status);
        assert_eq!(contract.status, EscrowStatus::Voting);

        // Debugging buyer's hash
        println!("Buyer hash: {:?}", buyer_pubkey);

        assert_eq!(contract.status, EscrowStatus::Voting);

        // Voters
        let voter1 = generate_hash(b"voter1");
        let voter2 = generate_hash(b"voter2");
        let voter3 = generate_hash(b"voter3");

        // Submit votes
        contract.submit_vote(voter1, true);
        println!("After voter1 votes: {:?}", contract.votes);

        contract.submit_vote(voter2, false);
        println!("After voter2 votes: {:?}", contract.votes);

        contract.submit_vote(voter3, true);
        println!("After voter3 votes: {:?}", contract.votes);

        // Tally votes
        let result = contract.tally_votes();
        assert_eq!(contract.status, EscrowStatus::Resolved);
        assert_eq!(result, Some(true)); // Buyer favored
    }
}