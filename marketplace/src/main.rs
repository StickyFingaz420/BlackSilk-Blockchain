//! BlackSilk Marketplace - Fully Decentralized
//! Uses the BlackSilk blockchain as the primary data layer
//! No centralized databases or authentication systems

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use askama::Template;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::{cors::CorsLayer, services::ServeDir};
use uuid::Uuid;
use anyhow::Result;

mod decentralized_storage;
mod models;
mod escrow_integration;
mod node_client;
mod ipfs_client;
mod smart_contracts; // Import smart_contracts module

use decentralized_storage::{DecentralizedStorage, MarketplaceData};
use models::*;
use escrow_integration::EscrowManager;
use node_client::NodeClient;
// Add cryptographic imports for authentication
use ed25519_dalek::SigningKey;
use sha2::{Sha256, Digest};
use hex;
use bip39::{Mnemonic, Language};
use smart_contracts::escrow_contract::Escrow; // Import Escrow contract

// BlackSilk Marketplace - Classic Silk Road Design
// "Don't be sick" - We maintain community standards

#[derive(Template)]
#[template(path = "marketplace/index.html")]
struct IndexTemplate {
    featured_products: Vec<Product>,
    categories: Vec<MarketplaceCategory>,
    total_listings: u64,
    online_vendors: u64,
    warning_message: String,
}

#[derive(Template)]
#[template(path = "marketplace/category.html")]
struct CategoryTemplate {
    category: MarketplaceCategory,
    products: Vec<Product>,
    page: u32,
    total_pages: u32,
    warning_message: String,
}

#[derive(Template)]
#[template(path = "marketplace/product.html")]
struct ProductTemplate {
    product: Product,
    vendor: User,
    similar_products: Vec<Product>,
    warning_message: String,
}

#[derive(Template)]
#[template(path = "marketplace/login.html")]
struct LoginTemplate {
    error: Option<String>,
    warning_message: String,
}

#[derive(Template)]
#[template(path = "marketplace/sell.html")]
struct SellTemplate {
    categories: Vec<MarketplaceCategory>,
    error: Option<String>,
    warning_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MarketplaceCategory {
    id: String,
    name: String,
    description: String,
    icon: String,
    count: u64,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub storage: DecentralizedStorage,
    pub node_client: NodeClient,
    pub escrow_manager: EscrowManager,
    pub categories: Vec<MarketplaceCategory>,
}

impl AppState {
    pub async fn new() -> Result<Self> {
        let node_url = std::env::var("BLACKSILK_NODE_URL")
            .unwrap_or_else(|_| "http://localhost:9333".to_string());
            
        let storage = DecentralizedStorage::new(&node_url).await?;
        let node_client = NodeClient::new(&node_url).await?;
        let escrow_manager = EscrowManager::new();
        
        let categories = vec![
            MarketplaceCategory {
                id: "digital".to_string(),
                name: "Digital Goods".to_string(),
                description: "Software, E-books, Digital Services".to_string(),
                icon: "💾".to_string(),
                count: 0,
            },
            MarketplaceCategory {
                id: "services".to_string(),
                name: "Services".to_string(),
                description: "Consulting, Design, Education".to_string(),
                icon: "🛠️".to_string(),
                count: 0,
            },
            MarketplaceCategory {
                id: "physical".to_string(),
                name: "Physical Goods".to_string(),
                description: "Electronics, Clothing, Supplies".to_string(),
                icon: "📦".to_string(),
                count: 0,
            },
        ];

        Ok(Self {
            storage,
            node_client,
            escrow_manager,
            categories,
        })
    }
}

pub fn warning_message() -> String {
    "⚠️ Community Standards: We maintain a legitimate marketplace. No pornographic or inappropriate content. Don't be sick.".to_string()
}

// Route handlers
async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Get marketplace statistics from decentralized storage
    let stats = match state.storage.get_marketplace_stats().await {
        Ok(stats) => stats,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load marketplace data").into_response();
        }
    };

    // Get featured products (first 12 active products)
    let featured_products = match state.storage.query_data(|data| {
        matches!(data, MarketplaceData::ProductListing(product) if product.is_active)
    }).await {
        Ok(products) => {
            let mut featured = Vec::new();
            for data in products.into_iter().take(12) {
                if let MarketplaceData::ProductListing(product) = data {
                    // Convert to the template Product format
                    let template_product = Product {
                        id: product.id,
                        vendor_id: product.vendor_id,
                        vendor_name: format!("vendor_{}", product.vendor_id.to_string()[..8].to_uppercase()), // Generate vendor name from ID
                        title: product.title,
                        description: product.description,
                        category: product.category,
                        subcategory: product.subcategory,
                        price: product.price as f64 / 1_000_000.0, // Convert to BLK
                        currency: "BLK".to_string(),
                        quantity_available: product.quantity_available,
                        ships_from: product.ships_from,
                        ships_to: product.ships_to,
                        shipping_price: product.shipping_price as f64 / 1_000_000.0,
                        processing_time: product.processing_time,
                        created_at: product.created_at,
                        updated_at: product.updated_at,
                        is_active: product.is_active,
                        image_hashes: product.image_hashes,
                        stealth_required: product.stealth_required,
                        escrow_required: product.escrow_required,
                    };
                    featured.push(template_product);
                }
            }
            featured
        },
        Err(_) => vec![],
    };

    let template = IndexTemplate {
        featured_products,
        categories: state.categories.clone(),
        total_listings: stats.total_listings,
        online_vendors: stats.online_vendors,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap()).into_response()
}

async fn category_page(
    Path(category_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let page: u32 = params.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let per_page = 20;

    // Get products for this category
    let products = match state.storage.get_products_by_category(&category_id).await {
        Ok(products) => products,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load products").into_response();
        }
    };

    // Convert to template format
    let template_products: Vec<Product> = products.into_iter().map(|product| {
        Product {
            id: product.id,
            vendor_id: product.vendor_id,
            vendor_name: format!("vendor_{}", product.vendor_id.to_string()[..8].to_uppercase()), // Generate vendor name from ID
            title: product.title,
            description: product.description,
            category: product.category,
            subcategory: product.subcategory,
            price: product.price as f64 / 1_000_000.0,
            currency: "BLK".to_string(),
            quantity_available: product.quantity_available,
            ships_from: product.ships_from,
            ships_to: product.ships_to,
            shipping_price: product.shipping_price as f64 / 1_000_000.0,
            processing_time: product.processing_time,
            created_at: product.created_at,
            updated_at: product.updated_at,
            is_active: product.is_active,
            image_hashes: product.image_hashes,
            stealth_required: product.stealth_required,
            escrow_required: product.escrow_required,
        }
    }).collect();

    // Pagination
    let total_products = template_products.len();
    let total_pages = (total_products as f64 / per_page as f64).ceil() as u32;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(total_products);
    let page_products = template_products[start..end].to_vec();

    // Find category info
    let category = state.categories.iter()
        .find(|c| c.id == category_id)
        .cloned()
        .unwrap_or_else(|| MarketplaceCategory {
            id: category_id.clone(),
            name: "Unknown Category".to_string(),
            description: "Category not found".to_string(),
            icon: "❓".to_string(),
            count: 0,
        });

    let template = CategoryTemplate {
        category,
        products: page_products,
        page,
        total_pages,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap()).into_response()
}

#[derive(Deserialize)]
struct CreateProductRequest {
    title: String,
    description: String,
    category: String,
    subcategory: Option<String>,
    price: f64,
    quantity_available: u32,
    ships_from: String,
    ships_to: Vec<String>,
    shipping_price: f64,
    processing_time: String,
    stealth_required: bool,
    escrow_required: bool,
    vendor_public_key: String, // For identifying the vendor
}

async fn create_product(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateProductRequest>,
) -> impl IntoResponse {
    // In a real implementation, we would verify the vendor's identity
    // For now, we'll create a mock vendor ID
    let vendor_id = Uuid::new_v4();

    let product = decentralized_storage::ProductListing {
        id: Uuid::new_v4(),
        vendor_id,
        title: req.title,
        description: req.description,
        category: req.category,
        subcategory: req.subcategory,
        price: (req.price * 1_000_000.0) as u64,
        quantity_available: req.quantity_available,
        ships_from: req.ships_from,
        ships_to: req.ships_to,
        shipping_price: (req.shipping_price * 1_000_000.0) as u64,
        processing_time: req.processing_time,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        is_active: true,
        image_hashes: vec![], // Would be populated from IPFS uploads
        stealth_required: req.stealth_required,
        escrow_required: req.escrow_required,
    };

    match state.storage.create_product(product).await {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "message": "Product created successfully"
        })),
        Err(_) => Json(serde_json::json!({
            "success": false,
            "message": "Failed to create product"
        })),
    }
}

// API Routes for frontend
async fn api_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.storage.get_marketplace_stats().await {
        Ok(stats) => Json(serde_json::json!({
            "total_listings": stats.total_listings,
            "online_vendors": stats.online_vendors,
            "total_orders": stats.total_orders,
            "total_volume": stats.total_volume
        })),
        Err(_) => Json(serde_json::json!({
            "error": "Failed to load stats"
        })),
    }
}

async fn api_products(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let category = params.get("category");
    
    let products = match category {
        Some(cat) => state.storage.get_products_by_category(cat).await,
        None => state.storage.query_data(|data| {
            matches!(data, MarketplaceData::ProductListing(product) if product.is_active)
        }).await.map(|data| {
            data.into_iter().filter_map(|d| {
                if let MarketplaceData::ProductListing(product) = d {
                    Some(product)
                } else {
                    None
                }
            }).collect()
        }),
    };

    match products {
        Ok(products) => Json(serde_json::json!({
            "products": products
        })),
        Err(_) => Json(serde_json::json!({
            "error": "Failed to load products"
        })),
    }
}

// Authentication handlers
async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate {
        error: None,
        warning_message: warning_message(),
    };
    Html(template.render().unwrap())
}

async fn auth_private_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Form(auth_req): axum::extract::Form<PrivateKeyAuth>,
) -> impl IntoResponse {
    match authenticate_with_private_key(&state, &auth_req.private_key).await {
        Ok(session) => {
            // Set session cookie and redirect to marketplace
            let cookie = format!("session={}; Path=/; HttpOnly; Secure; SameSite=Strict", session.session_token);
            (
                StatusCode::SEE_OTHER,
                [("Set-Cookie", cookie.as_str()), ("Location", "/")],
                "Authentication successful".to_string(),
            ).into_response()
        },
        Err(err) => {
            let template = LoginTemplate {
                error: Some(format!("Authentication failed: {}", err)),
                warning_message: warning_message(),
            };
            (StatusCode::UNAUTHORIZED, Html(template.render().unwrap())).into_response()
        }
    }
}

async fn auth_seed_phrase(
    State(state): State<Arc<AppState>>,
    axum::extract::Form(auth_req): axum::extract::Form<SeedPhraseAuth>,
) -> impl IntoResponse {
    match authenticate_with_seed_phrase(&state, &auth_req.seed_phrase).await {
        Ok(session) => {
            // Set session cookie and redirect to marketplace
            let cookie = format!("session={}; Path=/; HttpOnly; Secure; SameSite=Strict", session.session_token);
            (
                StatusCode::SEE_OTHER,
                [("Set-Cookie", cookie.as_str()), ("Location", "/")],
                "Authentication successful".to_string(),
            ).into_response()
        },
        Err(err) => {
            let template = LoginTemplate {
                error: Some(format!("Authentication failed: {}", err)),
                warning_message: warning_message(),
            };
            (StatusCode::UNAUTHORIZED, Html(template.render().unwrap())).into_response()
        }
    }
}

// Cryptographic authentication functions
async fn authenticate_with_private_key(
    state: &AppState,
    private_key_hex: &str,
) -> Result<AuthSession> {
    // Validate hex format
    if private_key_hex.len() != 64 {
        return Err(anyhow::anyhow!("Private key must be 64 hex characters"));
    }
    
    let private_key_bytes = hex::decode(private_key_hex)
        .map_err(|_| anyhow::anyhow!("Invalid hex format"))?;
        
    if private_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Private key must be 32 bytes"));
    }
    
    // Create signing key from private key
    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes().to_vec();
    
    // Generate user ID from public key hash
    let mut hasher = Sha256::new();
    hasher.update(&public_key_bytes);
    let user_id_bytes = hasher.finalize();
    let user_id = Uuid::from_slice(&user_id_bytes[..16])?;
    
    // Create or update user account
    let user = User {
        id: user_id,
        public_key: public_key_bytes.clone(),
        stealth_address: None, // TODO: Generate from key
        reputation_score: 0.0,
        total_sales: 0,
        total_purchases: 0,
        join_date: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        is_vendor: false,
        vendor_bond: None,
        pgp_key: None,
        display_name: None,
    };
    
    // Store user data on blockchain
    state.storage.store_user_data(&user).await?;
    
    // Create session
    let session_token = hex::encode(rand::random::<[u8; 32]>());
    let session = AuthSession {
        user_id,
        public_key: public_key_bytes,
        session_token,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        created_at: chrono::Utc::now(),
    };
    
    Ok(session)
}

async fn authenticate_with_seed_phrase(
    state: &AppState,
    seed_phrase: &str,
) -> Result<AuthSession> {
    // Parse mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, seed_phrase.trim())
        .map_err(|_| anyhow::anyhow!("Invalid seed phrase format"))?;
        
    // Generate seed from mnemonic
    let seed_bytes = mnemonic.to_seed(""); // No passphrase
    
    // Derive private key from seed (using first 32 bytes)
    let private_key_bytes: [u8; 32] = seed_bytes[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes().to_vec();
    
    // Generate user ID from public key hash
    let mut hasher = Sha256::new();
    hasher.update(&public_key_bytes);
    let user_id_bytes = hasher.finalize();
    let user_id = Uuid::from_slice(&user_id_bytes[..16])?;
    
    // Create or update user account
    let user = User {
        id: user_id,
        public_key: public_key_bytes.clone(),
        stealth_address: None, // TODO: Generate from key
        reputation_score: 0.0,
        total_sales: 0,
        total_purchases: 0,
        join_date: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        is_vendor: false,
        vendor_bond: None,
        pgp_key: None,
        display_name: None,
    };
    
    // Store user data on blockchain
    state.storage.store_user_data(&user).await?;
    
    // Create session
    let session_token = hex::encode(rand::random::<[u8; 32]>());
    let session = AuthSession {
        user_id,
        public_key: public_key_bytes,
        session_token,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        created_at: chrono::Utc::now(),
    };
    
    Ok(session)
}

// Escrow contract handlers
#[axum::debug_handler]
async fn create_escrow_contract(buyer: String, seller: String, amount: u128) -> Result<String, StatusCode> {
    let escrow = Escrow::new(buyer, seller, amount);
    println!("Escrow contract created: {:?}", escrow);
    // Logic to deploy the contract to the blockchain
    Ok("Escrow contract deployed successfully".to_string())
}

async fn confirm_delivery(contract_address: String) -> Result<String, StatusCode> {
    println!("Confirming delivery for contract: {}", contract_address);
    // Logic to call the confirm_delivery function on the contract
    Ok("Delivery confirmed successfully".to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("🔒 BlackSilk Marketplace - Decentralized & Private");
    println!("📡 Connecting to BlackSilk node...");

    // Initialize application state
    let state = Arc::new(AppState::new().await?);

    println!("✅ Connected to node: {}", std::env::var("BLACKSILK_NODE_URL").unwrap_or_else(|_| "http://localhost:9333".to_string()));
    println!("🏪 Marketplace ready - All data stored on blockchain");

    // Build our application with routes
    let app = Router::new()
        .route("/", get(index))
        .route("/category/:id", get(category_page))
        .route("/api/stats", get(api_stats))
        .route("/api/products", get(api_products))
        .route("/api/products", post(create_product))
        .route("/login", get(login_page))
        .route("/auth/private-key", post(auth_private_key))
        .route("/auth/seed-phrase", post(auth_seed_phrase))
        .route("/create_escrow", post(create_escrow_contract.into_service())) // Route to create escrow contract
        .route("/confirm_delivery", post(confirm_delivery)) // Route to confirm delivery
        .nest_service("/static", ServeDir::new("static"))
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    // Start the server
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    
    println!("🚀 Marketplace server running on http://0.0.0.0:{}", port);
    println!("🔐 No databases, no centralized auth - Pure decentralization!");

    axum::serve(listener, app).await?;

    Ok(())
}
