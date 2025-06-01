//! Decentralized Storage for BlackSilk Marketplace
//! Uses the BlackSilk blockchain node as the primary data layer
//! All marketplace data is stored on-chain with privacy preservations

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use primitives::{Transaction, Block};
use primitives::types::{Hash, BlkAmount};
use crate::node_client::NodeClient;
use crate::models::*;

/// Marketplace data types that can be stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarketplaceData {
    UserProfile(UserProfile),
    ProductListing(ProductListing),
    OrderData(OrderData),
    Review(ReviewData),
    VendorBond(VendorBondData),
    EscrowContract(EscrowContractData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub public_key: Vec<u8>,
    pub reputation_score: f64,
    pub total_sales: u32,
    pub total_purchases: u32,
    pub join_date: DateTime<Utc>,
    pub is_vendor: bool,
    pub pgp_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductListing {
    pub id: Uuid,
    pub vendor_id: Uuid,
    pub title: String,
    pub description: String,
    pub category: String,
    pub subcategory: Option<String>,
    pub price: BlkAmount,
    pub quantity_available: u32,
    pub ships_from: String,
    pub ships_to: Vec<String>,
    pub shipping_price: BlkAmount,
    pub processing_time: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub image_hashes: Vec<String>, // IPFS hashes
    pub stealth_required: bool,
    pub escrow_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderData {
    pub id: Uuid,
    pub buyer_id: Uuid,
    pub vendor_id: Uuid,
    pub product_id: Uuid,
    pub quantity: u32,
    pub total_price: BlkAmount,
    pub escrow_address: Option<String>,
    pub shipping_address_hash: String, // Encrypted shipping address hash
    pub status: OrderStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewData {
    pub id: Uuid,
    pub order_id: Uuid,
    pub reviewer_id: Uuid,
    pub vendor_id: Uuid,
    pub product_id: Uuid,
    pub rating: u8, // 1-5 stars
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorBondData {
    pub vendor_id: Uuid,
    pub bond_amount: BlkAmount,
    pub bond_tx_hash: Hash,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowContractData {
    pub id: Uuid,
    pub order_id: Uuid,
    pub buyer_id: Uuid,
    pub vendor_id: Uuid,
    pub amount: BlkAmount,
    pub contract_address: String,
    pub status: EscrowStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Decentralized storage manager using BlackSilk blockchain
#[derive(Clone)]
pub struct DecentralizedStorage {
    node_client: Arc<NodeClient>,
    cache: Arc<RwLock<HashMap<String, MarketplaceData>>>,
}

impl DecentralizedStorage {
    pub async fn new(node_url: &str) -> Result<Self> {
        let node_client = Arc::new(NodeClient::new(node_url).await?);
        let cache = Arc::new(RwLock::new(HashMap::new()));
        
        Ok(Self {
            node_client,
            cache,
        })
    }

    /// Store data on the blockchain by creating a special marketplace transaction
    pub async fn store_data(&self, data: MarketplaceData) -> Result<Hash> {
        // Serialize the marketplace data
        let data_bytes = bincode::serialize(&data)?;
        
        // Create a data hash for indexing
        let mut hasher = Sha256::new();
        hasher.update(&data_bytes);
        let data_hash = hasher.finalize().to_vec();
        
        // Create a special marketplace transaction with the data as metadata
        let tx_hash = self.node_client.submit_marketplace_data(data_bytes).await?;
        
        // Cache the data locally for faster access
        let cache_key = format!("{:x}", Hash::from(data_hash.try_into().unwrap()));
        self.cache.write().await.insert(cache_key, data);
        
        Ok(tx_hash)
    }

    /// Retrieve data from the blockchain by transaction hash
    pub async fn get_data_by_hash(&self, tx_hash: &Hash) -> Result<Option<MarketplaceData>> {
        // First check cache
        let cache_key = format!("{:x}", tx_hash);
        if let Some(data) = self.cache.read().await.get(&cache_key) {
            return Ok(Some(data.clone()));
        }

        // Fetch from blockchain if not in cache
        if let Some(tx_data) = self.node_client.get_marketplace_transaction(tx_hash).await? {
            let data: MarketplaceData = bincode::deserialize(&tx_data)?;
            
            // Update cache
            self.cache.write().await.insert(cache_key, data.clone());
            
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Query marketplace data by type and filters
    pub async fn query_data<F>(&self, filter: F) -> Result<Vec<MarketplaceData>>
    where
        F: Fn(&MarketplaceData) -> bool + Send + Sync,
    {
        // Get all marketplace transactions from the node
        let marketplace_txs = self.node_client.get_all_marketplace_transactions().await?;
        
        let mut results = Vec::new();
        for tx_data in marketplace_txs {
            if let Ok(data) = bincode::deserialize::<MarketplaceData>(&tx_data) {
                if filter(&data) {
                    results.push(data);
                }
            }
        }
        
        Ok(results)
    }

    // User operations
    pub async fn create_user(&self, username: &str, public_key: &[u8]) -> Result<UserProfile> {
        let user = UserProfile {
            id: Uuid::new_v4(),
            username: username.to_string(),
            public_key: public_key.to_vec(),
            reputation_score: 0.0,
            total_sales: 0,
            total_purchases: 0,
            join_date: Utc::now(),
            is_vendor: false,
            pgp_key: None,
        };

        let data = MarketplaceData::UserProfile(user.clone());
        self.store_data(data).await?;
        
        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<UserProfile>> {
        let users = self.query_data(|data| {
            matches!(data, MarketplaceData::UserProfile(user) if user.id == *user_id)
        }).await?;

        if let Some(MarketplaceData::UserProfile(user)) = users.first() {
            Ok(Some(user.clone()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserProfile>> {
        let users = self.query_data(|data| {
            matches!(data, MarketplaceData::UserProfile(user) if user.username == username)
        }).await?;

        if let Some(MarketplaceData::UserProfile(user)) = users.first() {
            Ok(Some(user.clone()))
        } else {
            Ok(None)
        }
    }

    // Product operations
    pub async fn create_product(&self, product: ProductListing) -> Result<()> {
        let data = MarketplaceData::ProductListing(product);
        self.store_data(data).await?;
        Ok(())
    }

    pub async fn get_products_by_category(&self, category: &str) -> Result<Vec<ProductListing>> {
        let products = self.query_data(|data| {
            matches!(data, MarketplaceData::ProductListing(product) 
                    if product.category == category && product.is_active)
        }).await?;

        let mut result = Vec::new();
        for data in products {
            if let MarketplaceData::ProductListing(product) = data {
                result.push(product);
            }
        }
        
        Ok(result)
    }

    pub async fn get_product_by_id(&self, product_id: &Uuid) -> Result<Option<ProductListing>> {
        let products = self.query_data(|data| {
            matches!(data, MarketplaceData::ProductListing(product) if product.id == *product_id)
        }).await?;

        if let Some(MarketplaceData::ProductListing(product)) = products.first() {
            Ok(Some(product.clone()))
        } else {
            Ok(None)
        }
    }

    // Order operations
    pub async fn create_order(&self, order: OrderData) -> Result<()> {
        let data = MarketplaceData::OrderData(order);
        self.store_data(data).await?;
        Ok(())
    }

    pub async fn get_orders_by_user(&self, user_id: &Uuid) -> Result<Vec<OrderData>> {
        let orders = self.query_data(|data| {
            matches!(data, MarketplaceData::OrderData(order) 
                    if order.buyer_id == *user_id || order.vendor_id == *user_id)
        }).await?;

        let mut result = Vec::new();
        for data in orders {
            if let MarketplaceData::OrderData(order) = data {
                result.push(order);
            }
        }
        
        Ok(result)
    }

    // Vendor operations
    pub async fn create_vendor_bond(&self, vendor_bond: VendorBondData) -> Result<()> {
        let data = MarketplaceData::VendorBond(vendor_bond);
        self.store_data(data).await?;
        Ok(())
    }

    pub async fn get_active_vendors(&self) -> Result<Vec<UserProfile>> {
        let vendor_bonds = self.query_data(|data| {
            matches!(data, MarketplaceData::VendorBond(bond) if bond.is_active)
        }).await?;

        let mut vendor_ids = Vec::new();
        for data in vendor_bonds {
            if let MarketplaceData::VendorBond(bond) = data {
                vendor_ids.push(bond.vendor_id);
            }
        }

        let mut vendors = Vec::new();
        for vendor_id in vendor_ids {
            if let Some(vendor) = self.get_user_by_id(&vendor_id).await? {
                vendors.push(vendor);
            }
        }

        Ok(vendors)
    }

    // Statistics and analytics
    pub async fn get_marketplace_stats(&self) -> Result<MarketplaceStats> {
        let all_products = self.query_data(|data| {
            matches!(data, MarketplaceData::ProductListing(product) if product.is_active)
        }).await?;

        let all_vendors = self.get_active_vendors().await?;
        
        let all_orders = self.query_data(|data| {
            matches!(data, MarketplaceData::OrderData(_))
        }).await?;

        Ok(MarketplaceStats {
            total_listings: all_products.len() as u64,
            online_vendors: all_vendors.len() as u64,
            total_orders: all_orders.len() as u64,
            total_volume: BlkAmount::from_atomic(0), // TODO: Calculate from orders
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceStats {
    pub total_listings: u64,
    pub online_vendors: u64,
    pub total_orders: u64,
    pub total_volume: BlkAmount,
}
