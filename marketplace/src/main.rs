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
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, services::ServeDir};
use uuid::Uuid;
use anyhow::Result;

mod decentralized_storage;
mod models;
mod escrow_integration;
mod node_client;
mod ipfs_client;

use decentralized_storage::{DecentralizedStorage, MarketplaceData};
use models::*;
use escrow_integration::EscrowManager;
use node_client::NodeClient;

// BlackSilk Marketplace - Classic Silk Road Design
// "Don't be sick" - We maintain community standards

#[derive(Template)]
#[template(path = "marketplace/index.html")]
struct IndexTemplate {
    featured_products: Vec<Product>,
    categories: Vec<Category>,
    total_listings: u64,
    online_vendors: u64,
    warning_message: String,
}

#[derive(Template)]
#[template(path = "marketplace/category.html")]
struct CategoryTemplate {
    category: Category,
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
                        title: product.title,
                        description: product.description,
                        category: product.category,
                        subcategory: product.subcategory,
                        price: product.price.to_atomic() as f64 / 1_000_000.0, // Convert to BLK
                        currency: "BLK".to_string(),
                        quantity_available: product.quantity_available,
                        ships_from: product.ships_from,
                        ships_to: product.ships_to,
                        shipping_price: product.shipping_price.to_atomic() as f64 / 1_000_000.0,
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

    Html(template.render().unwrap())
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
            title: product.title,
            description: product.description,
            category: product.category,
            subcategory: product.subcategory,
            price: product.price.to_atomic() as f64 / 1_000_000.0,
            currency: "BLK".to_string(),
            quantity_available: product.quantity_available,
            ships_from: product.ships_from,
            ships_to: product.ships_to,
            shipping_price: product.shipping_price.to_atomic() as f64 / 1_000_000.0,
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

    Html(template.render().unwrap())
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
        price: primitives::types::BlkAmount::from_atomic((req.price * 1_000_000.0) as u64),
        quantity_available: req.quantity_available,
        ships_from: req.ships_from,
        ships_to: req.ships_to,
        shipping_price: primitives::types::BlkAmount::from_atomic((req.shipping_price * 1_000_000.0) as u64),
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
            "total_volume": stats.total_volume.to_atomic()
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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::init();

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
