//! Node Client for BlackSilk Marketplace
//! Handles communication with the BlackSilk blockchain node

use primitives::{Block, Transaction, escrow::EscrowContract};
use primitives::types::{Hash, BlkAmount};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use anyhow::{Result, anyhow};
use reqwest::Client;

#[derive(Debug, Clone)]
pub struct NodeClient {
    base_url: String,
    client: Client,
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub chain_height: u64,
    pub difficulty: u64,
    pub hashrate: f64,
    pub peers: u32,
    pub mempool_size: u32,
    pub network: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub txid: String,
    pub confirmations: u32,
    pub block_height: Option<u64>,
    pub fee: BlkAmount,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: BlkAmount,
    pub unconfirmed: BlkAmount,
    pub locked_in_escrow: BlkAmount,
}

impl NodeClient {
    pub async fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let node_client = Self {
            base_url: base_url.to_string(),
            client,
            api_key: std::env::var("BLACKSILK_API_KEY").ok(),
        };

        // Test connection
        node_client.get_node_info().await?;
        
        Ok(node_client)
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Get basic node information
    pub async fn get_node_info(&self) -> Result<NodeInfo> {
        let url = format!("{}/api/info", self.base_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let info: NodeInfo = response.json().await?;
            Ok(info)
        } else {
            Err(anyhow!("Failed to get node info: {}", response.status()))
        }
    }

    /// Get balance for a public key
    pub async fn get_balance(&self, public_key: &[u8]) -> Result<Balance> {
        let url = format!("{}/api/balance/{}", self.base_url, hex::encode(public_key));
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let balance: Balance = response.json().await?;
            Ok(balance)
        } else {
            Err(anyhow!("Failed to get balance: {}", response.status()))
        }
    }

    /// Submit a transaction to the network
    pub async fn submit_transaction(&self, tx: &Transaction) -> Result<String> {
        let url = format!("{}/api/submit_tx", self.base_url);
        let response = self.client
            .post(&url)
            .json(tx)
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            Ok(result["txid"].as_str().unwrap_or("unknown").to_string())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to submit transaction: {}", error_text))
        }
    }

    /// Get transaction status
    pub async fn get_transaction_status(&self, txid: &str) -> Result<TransactionStatus> {
        let url = format!("{}/api/tx/{}", self.base_url, txid);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let status: TransactionStatus = response.json().await?;
            Ok(status)
        } else {
            Err(anyhow!("Transaction not found or node error"))
        }
    }

    /// Submit escrow contract to blockchain
    pub async fn submit_escrow_contract(&self, contract: &EscrowContract) -> Result<String> {
        let url = format!("{}/api/escrow/create", self.base_url);
        
        #[derive(Serialize)]
        struct EscrowRequest {
            contract: EscrowContract,
        }

        let request = EscrowRequest {
            contract: contract.clone(),
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            Ok(result["contract_id"].as_str().unwrap_or("unknown").to_string())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to submit escrow contract: {}", error_text))
        }
    }

    /// Update escrow status (funding, signing, etc.)
    pub async fn update_escrow_status(&self, contract: &EscrowContract) -> Result<()> {
        let url = format!("{}/api/escrow/update", self.base_url);
        
        let response = self.client
            .put(&url)
            .json(contract)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to update escrow: {}", error_text))
        }
    }

    /// Finalize escrow (release or refund)
    pub async fn finalize_escrow(&self, contract: &EscrowContract) -> Result<String> {
        let url = format!("{}/api/escrow/finalize", self.base_url);
        
        let response = self.client
            .post(&url)
            .json(contract)
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            Ok(result["txid"].as_str().unwrap_or("unknown").to_string())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to finalize escrow: {}", error_text))
        }
    }

    /// Submit dispute for DAO voting
    pub async fn submit_dispute(&self, contract: &EscrowContract, reason: &str) -> Result<()> {
        let url = format!("{}/api/escrow/dispute", self.base_url);
        
        #[derive(Serialize)]
        struct DisputeRequest {
            contract_id: Hash,
            reason: String,
            contract: EscrowContract,
        }

        let request = DisputeRequest {
            contract_id: contract.contract_id,
            reason: reason.to_string(),
            contract: contract.clone(),
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to submit dispute: {}", error_text))
        }
    }

    /// Submit vote for escrow dispute
    pub async fn submit_escrow_vote(
        &self, 
        contract: &EscrowContract, 
        voter: Hash, 
        vote_for_buyer: bool
    ) -> Result<()> {
        let url = format!("{}/api/escrow/vote", self.base_url);
        
        #[derive(Serialize)]
        struct VoteRequest {
            contract_id: Hash,
            voter: Hash,
            vote_for_buyer: bool,
        }

        let request = VoteRequest {
            contract_id: contract.contract_id,
            voter,
            vote_for_buyer,
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to submit vote: {}", error_text))
        }
    }

    /// Finalize dispute resolution
    pub async fn finalize_dispute_resolution(&self, contract: &EscrowContract) -> Result<String> {
        let url = format!("{}/api/escrow/resolve", self.base_url);
        
        let response = self.client
            .post(&url)
            .json(contract)
            .send()
            .await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            Ok(result["txid"].as_str().unwrap_or("unknown").to_string())
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("Failed to resolve dispute: {}", error_text))
        }
    }

    /// Get current mempool transactions
    pub async fn get_mempool(&self) -> Result<Vec<Transaction>> {
        let url = format!("{}/api/mempool", self.base_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let transactions: Vec<Transaction> = response.json().await?;
            Ok(transactions)
        } else {
            Err(anyhow!("Failed to get mempool: {}", response.status()))
        }
    }

    /// Get block by height
    pub async fn get_block(&self, height: u64) -> Result<Block> {
        let url = format!("{}/api/block/{}", self.base_url, height);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let block: Block = response.json().await?;
            Ok(block)
        } else {
            Err(anyhow!("Block not found: {}", height))
        }
    }

    /// Get recent transactions for address
    pub async fn get_address_transactions(&self, address: &str, limit: u32) -> Result<Vec<Transaction>> {
        let url = format!("{}/api/address/{}/transactions?limit={}", self.base_url, address, limit);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let transactions: Vec<Transaction> = response.json().await?;
            Ok(transactions)
        } else {
            Err(anyhow!("Failed to get address transactions: {}", response.status()))
        }
    }

    /// Estimate transaction fee
    pub async fn estimate_fee(&self, tx_size: u32, priority: &str) -> Result<BlkAmount> {
        let url = format!("{}/api/estimate_fee?size={}&priority={}", self.base_url, tx_size, priority);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            let fee = result["fee"].as_u64().unwrap_or(1000); // Default 0.001 BLK
            Ok(fee)
        } else {
            Err(anyhow!("Failed to estimate fee: {}", response.status()))
        }
    }

    /// Health check
    pub async fn health_check(&self) -> bool {
        match self.get_node_info().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Get mining statistics
    pub async fn get_mining_stats(&self) -> Result<serde_json::Value> {
        let url = format!("{}/api/mining/stats", self.base_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let stats = response.json().await?;
            Ok(stats)
        } else {
            Err(anyhow!("Failed to get mining stats: {}", response.status()))
        }
    }

    /// Subscribe to real-time updates via WebSocket
    pub async fn subscribe_to_updates(&self) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
        let ws_url = self.base_url.replace("http", "ws") + "/ws";
        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url).await?;
        Ok(ws_stream)
    }

    /// Batch request multiple operations
    pub async fn batch_request(&self, requests: Vec<serde_json::Value>) -> Result<Vec<serde_json::Value>> {
        let url = format!("{}/api/batch", self.base_url);
        let response = self.client
            .post(&url)
            .json(&requests)
            .send()
            .await?;
        
        if response.status().is_success() {
            let results: Vec<serde_json::Value> = response.json().await?;
            Ok(results)
        } else {
            Err(anyhow!("Batch request failed: {}", response.status()))
        }
    }

    /// Submit marketplace data to the blockchain as a special transaction
    pub async fn submit_marketplace_data(&self, data: Vec<u8>) -> Result<Hash> {
        let url = format!("{}/api/marketplace/data", self.base_url);
        
        let payload = serde_json::json!({
            "data": base64::encode(&data),
            "timestamp": chrono::Utc::now().timestamp()
        });

        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            let tx_hash_str = result["tx_hash"].as_str()
                .ok_or_else(|| anyhow!("Invalid response format"))?;
            
            // Convert hex string to Hash
            let hash_bytes = hex::decode(tx_hash_str)?;
            if hash_bytes.len() != 32 {
                return Err(anyhow!("Invalid hash length"));
            }
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_bytes);
            Ok(Hash::from(hash_array))
        } else {
            Err(anyhow!("Failed to submit marketplace data: {}", response.status()))
        }
    }

    /// Get marketplace transaction data by hash
    pub async fn get_marketplace_transaction(&self, tx_hash: &Hash) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/api/marketplace/data/{:x}", self.base_url, tx_hash);
        
        let response = self.client
            .get(&url)
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(data_str) = result["data"].as_str() {
                let data = base64::decode(data_str)?;
                Ok(Some(data))
            } else {
                Ok(None)
            }
        } else {
            Err(anyhow!("Failed to get marketplace transaction: {}", response.status()))
        }
    }

    /// Get all marketplace transactions from the blockchain
    pub async fn get_all_marketplace_transactions(&self) -> Result<Vec<Vec<u8>>> {
        let url = format!("{}/api/marketplace/transactions", self.base_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            let mut transactions = Vec::new();
            
            if let Some(txs) = result["transactions"].as_array() {
                for tx in txs {
                    if let Some(data_str) = tx["data"].as_str() {
                        if let Ok(data) = base64::decode(data_str) {
                            transactions.push(data);
                        }
                    }
                }
            }
            
            Ok(transactions)
        } else {
            Err(anyhow!("Failed to get marketplace transactions: {}", response.status()))
        }
    }
}
