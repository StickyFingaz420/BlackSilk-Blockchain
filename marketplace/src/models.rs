use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use primitives::types::{Hash, BlkAmount};

/// User account in the marketplace - identified by cryptographic keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid, // Derived from public key hash
    pub public_key: Vec<u8>, // Ed25519 public key (32 bytes)
    pub stealth_address: Option<String>, // BlackSilk stealth address for payments
    pub reputation_score: f64,
    pub total_sales: u64,
    pub total_purchases: u64,
    pub join_date: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_vendor: bool,
    pub vendor_bond: Option<BlkAmount>, // Bond paid to become vendor
    pub pgp_key: Option<String>, // PGP public key for secure comms
    pub display_name: Option<String>, // Optional display name (not for auth)
}

/// Product listing in the marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub id: Uuid,
    pub vendor_id: Uuid,
    pub vendor_name: String, // Add vendor_name field for templates
    pub title: String,
    pub description: String,
    pub category: String,
    pub subcategory: Option<String>,
    pub price: f64, // Price in BLK (for template compatibility)
    pub currency: String, // "BLK"
    pub quantity_available: u32,
    pub ships_from: String,
    pub ships_to: Vec<String>, // JSON array of countries
    pub shipping_price: f64, // Shipping price in BLK
    pub processing_time: String, // e.g., "1-2 days"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub image_hashes: Vec<String>, // IPFS hashes of product images
    pub stealth_required: bool, // Requires stealth shipping
    pub escrow_required: bool, // Always true for security
}

/// Order in the marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: Uuid,
    pub buyer_id: Uuid,
    pub vendor_id: Uuid,
    pub product_id: Uuid,
    pub quantity: u32,
    pub total_price: BlkAmount,
    pub shipping_address_encrypted: Vec<u8>, // Encrypted with vendor's public key
    pub status: OrderStatus,
    pub escrow_contract_id: Option<Hash>, // Link to blockchain escrow
    pub created_at: DateTime<Utc>,
    pub shipped_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub dispute_reason: Option<String>,
    pub tracking_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrderStatus {
    Pending,     // Order placed, waiting for payment
    Paid,        // Payment received, escrow funded
    Processing,  // Vendor preparing order
    Shipped,     // Order shipped
    Delivered,   // Buyer confirmed receipt
    Disputed,    // Dispute opened
    Cancelled,   // Order cancelled
    Refunded,    // Money returned to buyer
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscrowStatus {
    Created,     // Escrow contract created
    Funded,      // Buyer has funded the escrow
    Released,    // Funds released to vendor
    Disputed,    // Dispute in progress
    Refunded,    // Funds returned to buyer
    Expired,     // Escrow expired
}

/// Review/feedback system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub id: Uuid,
    pub order_id: Uuid,
    pub reviewer_id: Uuid,
    pub reviewed_id: Uuid, // Vendor being reviewed
    pub rating: u8, // 1-5 stars
    pub review_text: String,
    pub product_quality: u8,
    pub shipping_speed: u8,
    pub communication: u8,
    pub created_at: DateTime<Utc>,
    pub is_anonymous: bool,
}

/// Message in the marketplace communication system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub order_id: Option<Uuid>, // Associated order if any
    pub subject: String,
    pub content_encrypted: Vec<u8>, // Encrypted message content
    pub created_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Order,      // Order-related communication
    Support,    // Customer support
    General,    // General inquiry
    Dispute,    // Dispute communication
}

/// Category structure for marketplace organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String, // Category identifier
    pub name: String,
    pub description: String,
    pub icon: String, // Emoji or icon for the category
    pub subcategories: Vec<Subcategory>,
    pub requires_vendor_verification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subcategory {
    pub name: String,
    pub description: String,
    pub product_count: u64,
}

/// Market statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStats {
    pub total_users: u64,
    pub total_vendors: u64,
    pub total_products: u64,
    pub total_orders: u64,
    pub total_volume_blk: BlkAmount,
    pub active_listings: u64,
    pub successful_transactions: u64,
    pub average_rating: f64,
}

/// Authentication request using private key
#[derive(Debug, Deserialize)]
pub struct PrivateKeyAuth {
    pub private_key: String, // Hex-encoded private key
}

/// Authentication request using seed phrase
#[derive(Debug, Deserialize)]
pub struct SeedPhraseAuth {
    pub seed_phrase: String, // Mnemonic seed phrase
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
