//! Escrow Integration for BlackSilk Marketplace
//! Connects marketplace orders with the blockchain escrow system

use primitives::escrow::{EscrowContract, EscrowStatus};
use primitives::types::Hash;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct MarketplaceEscrow {
    pub marketplace_order_id: Uuid,
    pub blockchain_contract: EscrowContract,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct EscrowManager {
    contracts: Arc<RwLock<HashMap<Hash, MarketplaceEscrow>>>,
    node_client: Option<crate::node_client::NodeClient>,
}

impl EscrowManager {
    pub fn new() -> Self {
        Self {
            contracts: Arc::new(RwLock::new(HashMap::new())),
            node_client: None,
        }
    }

    pub async fn with_node_client(mut self, client: crate::node_client::NodeClient) -> Self {
        self.node_client = Some(client);
        self
    }

    /// Create a new escrow contract for marketplace order
    pub async fn create_escrow(
        &self,
        buyer_pubkey: &[u8],
        seller_pubkey: &[u8],
        arbiter_pubkey: &[u8],
        amount: u64,
    ) -> Result<EscrowContract> {
        // Create the escrow contract using primitives
        let contract = EscrowContract::new(
            buyer_pubkey,
            seller_pubkey,
            arbiter_pubkey,
            amount,
        );

        let marketplace_escrow = MarketplaceEscrow {
            marketplace_order_id: Uuid::new_v4(),
            blockchain_contract: contract.clone(),
            created_at: chrono::Utc::now(),
            last_updated: chrono::Utc::now(),
        };

        // Store in our tracking system
        {
            let mut contracts = self.contracts.write().await;
            contracts.insert(contract.contract_id, marketplace_escrow);
        }

        // If we have a node client, submit to blockchain
        if let Some(client) = &self.node_client {
            match client.submit_escrow_contract(&contract).await {
                Ok(_) => {
                    println!("✅ Escrow contract {} submitted to blockchain", 
                        hex::encode(&contract.contract_id[..8]));
                }
                Err(e) => {
                    println!("⚠️ Failed to submit escrow to blockchain: {}", e);
                    // Continue anyway - we can retry later
                }
            }
        }

        Ok(contract)
    }

    /// Fund an escrow contract (buyer action)
    pub async fn fund_escrow(
        &self,
        contract_id: Hash,
        buyer_signature: Hash,
    ) -> Result<()> {
        let mut contracts = self.contracts.write().await;
        
        if let Some(marketplace_escrow) = contracts.get_mut(&contract_id) {
            // Update the contract
            marketplace_escrow.blockchain_contract.fund(buyer_signature);
            marketplace_escrow.last_updated = chrono::Utc::now();

            println!("💰 Escrow {} funded by buyer", 
                hex::encode(&contract_id[..8]));

            // Submit to blockchain if we have a client
            if let Some(client) = &self.node_client {
                client.update_escrow_status(&marketplace_escrow.blockchain_contract).await?;
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Escrow contract not found"))
        }
    }

    /// Release funds to seller (requires 2 of 3 signatures)
    pub async fn release_funds(
        &self,
        contract_id: Hash,
        signer: Hash,
    ) -> Result<bool> {
        let mut contracts = self.contracts.write().await;
        
        if let Some(marketplace_escrow) = contracts.get_mut(&contract_id) {
            // Sign for release
            marketplace_escrow.blockchain_contract.sign_release(signer);
            marketplace_escrow.last_updated = chrono::Utc::now();

            let can_release = marketplace_escrow.blockchain_contract.can_release();
            
            if can_release {
                let released = marketplace_escrow.blockchain_contract.release();
                if released {
                    println!("✅ Funds released to seller for escrow {}", 
                        hex::encode(&contract_id[..8]));

                    // Submit to blockchain
                    if let Some(client) = &self.node_client {
                        client.finalize_escrow(&marketplace_escrow.blockchain_contract).await?;
                    }
                }
                Ok(released)
            } else {
                println!("📝 Signature added to escrow {} ({} of 2 required)", 
                    hex::encode(&contract_id[..8]),
                    marketplace_escrow.blockchain_contract.signatures.len());
                Ok(false)
            }
        } else {
            Err(anyhow::anyhow!("Escrow contract not found"))
        }
    }

    /// Initiate dispute resolution
    pub async fn raise_dispute(
        &self,
        contract_id: Hash,
        disputer: Hash,
        reason: String,
    ) -> Result<()> {
        let mut contracts = self.contracts.write().await;
        
        if let Some(marketplace_escrow) = contracts.get_mut(&contract_id) {
            marketplace_escrow.blockchain_contract.dispute(disputer);
            marketplace_escrow.last_updated = chrono::Utc::now();

            println!("⚠️ Dispute raised for escrow {}: {}", 
                hex::encode(&contract_id[..8]), reason);

            // Start DAO voting process
            marketplace_escrow.blockchain_contract.start_voting();

            // Submit to blockchain
            if let Some(client) = &self.node_client {
                client.submit_dispute(&marketplace_escrow.blockchain_contract, &reason).await?;
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Escrow contract not found"))
        }
    }

    /// Submit a vote for dispute resolution
    pub async fn submit_vote(
        &self,
        contract_id: Hash,
        voter: Hash,
        vote_for_buyer: bool,
    ) -> Result<()> {
        let mut contracts = self.contracts.write().await;
        
        if let Some(marketplace_escrow) = contracts.get_mut(&contract_id) {
            marketplace_escrow.blockchain_contract.submit_vote(voter, vote_for_buyer);
            marketplace_escrow.last_updated = chrono::Utc::now();

            println!("🗳️ Vote submitted for escrow {}: {}", 
                hex::encode(&contract_id[..8]),
                if vote_for_buyer { "Favor Buyer" } else { "Favor Seller" });

            // Submit to blockchain
            if let Some(client) = &self.node_client {
                client.submit_escrow_vote(&marketplace_escrow.blockchain_contract, voter, vote_for_buyer).await?;
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Escrow contract not found"))
        }
    }

    /// Check if dispute voting is complete and tally results
    pub async fn check_dispute_resolution(
        &self,
        contract_id: Hash,
    ) -> Result<Option<bool>> {
        let mut contracts = self.contracts.write().await;
        
        if let Some(marketplace_escrow) = contracts.get_mut(&contract_id) {
            if let Some(buyer_wins) = marketplace_escrow.blockchain_contract.tally_votes() {
                marketplace_escrow.last_updated = chrono::Utc::now();

                if buyer_wins {
                    println!("🏆 Dispute resolved in favor of buyer for escrow {}", 
                        hex::encode(&contract_id[..8]));
                    // Refund to buyer
                    marketplace_escrow.blockchain_contract.refund();
                } else {
                    println!("🏆 Dispute resolved in favor of seller for escrow {}", 
                        hex::encode(&contract_id[..8]));
                    // Release to seller
                    marketplace_escrow.blockchain_contract.release();
                }

                // Submit final resolution to blockchain
                if let Some(client) = &self.node_client {
                    client.finalize_dispute_resolution(&marketplace_escrow.blockchain_contract).await?;
                }

                Ok(Some(buyer_wins))
            } else {
                Ok(None) // Voting still in progress
            }
        } else {
            Err(anyhow::anyhow!("Escrow contract not found"))
        }
    }

    /// Get escrow status for marketplace order
    pub async fn get_escrow_status(&self, contract_id: Hash) -> Option<EscrowStatus> {
        let contracts = self.contracts.read().await;
        contracts.get(&contract_id).map(|e| e.blockchain_contract.status.clone())
    }

    /// Get all active escrows (for admin/monitoring)
    pub async fn get_active_escrows(&self) -> Vec<MarketplaceEscrow> {
        let contracts = self.contracts.read().await;
        contracts.values()
            .filter(|e| matches!(
                e.blockchain_contract.status, 
                EscrowStatus::Created | EscrowStatus::Funded | EscrowStatus::Disputed | EscrowStatus::Voting
            ))
            .cloned()
            .collect()
    }

    /// Get escrow statistics for marketplace dashboard
    pub async fn get_escrow_stats(&self) -> EscrowStats {
        let contracts = self.contracts.read().await;
        
        let mut stats = EscrowStats::default();
        
        for escrow in contracts.values() {
            match escrow.blockchain_contract.status {
                EscrowStatus::Created => stats.created += 1,
                EscrowStatus::Funded => stats.funded += 1,
                EscrowStatus::Completed => stats.completed += 1,
                EscrowStatus::Disputed => stats.disputed += 1,
                EscrowStatus::Refunded => stats.refunded += 1,
                EscrowStatus::Voting => stats.voting += 1,
                EscrowStatus::Resolved => stats.resolved += 1,
            }
            stats.total_value += escrow.blockchain_contract.amount;
        }

        stats.total_contracts = contracts.len() as u64;
        stats
    }

    /// Automatic escrow monitoring (should be called periodically)
    pub async fn monitor_escrows(&self) -> Result<()> {
        let contracts = self.contracts.read().await;
        
        for (contract_id, escrow) in contracts.iter() {
            // Check for timeouts, stuck transactions, etc.
            let age = chrono::Utc::now() - escrow.created_at;
            
            match escrow.blockchain_contract.status {
                EscrowStatus::Created => {
                    if age.num_hours() > 24 {
                        println!("⏰ Escrow {} unfunded for >24h", hex::encode(&contract_id[..8]));
                        // Could automatically cancel or notify
                    }
                }
                EscrowStatus::Funded => {
                    if age.num_days() > 30 {
                        println!("⏰ Escrow {} funded but not completed for >30 days", 
                            hex::encode(&contract_id[..8]));
                        // Could automatically dispute or escalate
                    }
                }
                EscrowStatus::Disputed => {
                    if age.num_days() > 7 {
                        println!("⏰ Dispute for escrow {} unresolved for >7 days", 
                            hex::encode(&contract_id[..8]));
                        // Could escalate to higher authority
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct EscrowStats {
    pub total_contracts: u64,
    pub total_value: u64,
    pub created: u64,
    pub funded: u64,
    pub completed: u64,
    pub disputed: u64,
    pub refunded: u64,
    pub voting: u64,
    pub resolved: u64,
}

impl EscrowStats {
    pub fn success_rate(&self) -> f64 {
        if self.total_contracts == 0 {
            return 0.0;
        }
        (self.completed as f64) / (self.total_contracts as f64) * 100.0
    }

    pub fn dispute_rate(&self) -> f64 {
        if self.total_contracts == 0 {
            return 0.0;
        }
        (self.disputed as f64) / (self.total_contracts as f64) * 100.0
    }
}
