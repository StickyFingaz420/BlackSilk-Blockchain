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

mod database;
mod models;
mod escrow_integration;
mod node_client;
mod ipfs_client;
mod tor_service;

use database::Database;
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
    categories: Vec<Category>,
    error: Option<String>,
    warning_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Category {
    id: String,
    name: String,
    description: String,
    icon: String,
    count: u64,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Database,
    pub node_client: NodeClient,
    pub escrow_manager: EscrowManager,
    pub categories: Vec<Category>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let db = Database::new("marketplace.db").await?;
        let node_client = NodeClient::new("http://localhost:9333").await?;
        let escrow_manager = EscrowManager::new();
        
        let categories = vec![
            Category {
                id: "digital".to_string(),
                name: "Digital Goods".to_string(),
                description: "Software, E-books, Digital Services".to_string(),
                icon: "💾".to_string(),
                count: 0,
            },
            Category {
                id: "services".to_string(),
                name: "Services".to_string(),
                description: "Consulting, Design, Education".to_string(),
                icon: "🛠️".to_string(),
                count: 0,
            },
            Category {
                id: "physical".to_string(),
                name: "Physical Goods".to_string(),
                description: "Electronics, Clothing, Supplies".to_string(),
                icon: "📦".to_string(),
                count: 0,
            },
        ];

        Ok(Self {
            db,
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
    let featured_products = match state.db.get_featured_products(12).await {
        Ok(products) => products,
        Err(_) => vec![],
    };

    let total_listings = state.db.count_active_products().await.unwrap_or(0);
    let online_vendors = state.db.count_active_vendors().await.unwrap_or(0);

    let template = IndexTemplate {
        featured_products,
        categories: state.categories.clone(),
        total_listings,
        online_vendors,
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
    let limit = 20;
    let offset = (page - 1) * limit;

    let category = state.categories.iter()
        .find(|c| c.id == category_id)
        .cloned()
        .unwrap_or_else(|| Category {
            id: category_id.clone(),
            name: "Unknown Category".to_string(),
            description: "Category not found".to_string(),
            icon: "❓".to_string(),
            count: 0,
        });

    let products = match state.db.get_products_by_category(&category_id, limit, offset).await {
        Ok(products) => products,
        Err(_) => vec![],
    };

    let total_count = state.db.count_products_by_category(&category_id).await.unwrap_or(0);
    let total_pages = (total_count + limit as u64 - 1) / limit as u64;

    let template = CategoryTemplate {
        category,
        products,
        page,
        total_pages: total_pages as u32,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap())
}

async fn product_page(
    Path(product_id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let product = match state.db.get_product_by_id(product_id).await {
        Ok(Some(product)) => product,
        _ => return Html("<h1>Product not found</h1>".to_string()),
    };

    let vendor = match state.db.get_user_by_id(product.vendor_id).await {
        Ok(Some(vendor)) => vendor,
        _ => return Html("<h1>Vendor not found</h1>".to_string()),
    };

    let similar_products = state.db.get_similar_products(&product.category, product.id, 4).await.unwrap_or_default();

    let template = ProductTemplate {
        product,
        vendor,
        similar_products,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap())
}

async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate {
        error: None,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap())
}

async fn sell_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let template = SellTemplate {
        categories: state.categories.clone(),
        error: None,
        warning_message: warning_message(),
    };

    Html(template.render().unwrap())
}

// API endpoints
#[derive(Deserialize)]
struct LoginRequest {
    private_key: String,
    recovery_phrase: Option<String>,
}

async fn api_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // Validate private key format
    if payload.private_key.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid private key format"
        })));
    }

    // Generate public key from private key
    // In a real implementation, use proper Ed25519 key derivation
    let public_key = hex::decode(&payload.private_key).unwrap_or_default();
    
    // Check if user exists or create new user
    let user_id = match state.db.get_or_create_user_by_pubkey(&public_key).await {
        Ok(id) => id,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Database error"
        }))),
    };

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "user_id": user_id,
        "message": "Login successful"
    })))
}

#[derive(Deserialize)]
struct CreateProductRequest {
    title: String,
    description: String,
    category: String,
    subcategory: String,
    price: u64,
    quantity_available: u32,
    ships_from: String,
    ships_to: Vec<String>,
    shipping_price: u64,
    processing_time: String,
    image_files: Vec<String>, // Base64 encoded images
}

async fn api_create_product(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateProductRequest>,
) -> impl IntoResponse {
    // Content moderation check
    let forbidden_terms = vec!["porn", "sex", "adult", "xxx", "escort"];
    let content_check = format!("{} {}", payload.title.to_lowercase(), payload.description.to_lowercase());
    
    for term in forbidden_terms {
        if content_check.contains(term) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Content violates community standards. Don't be sick."
            })));
        }
    }

    // Upload images to IPFS (simulated)
    let mut image_hashes = Vec::new();
    for image_data in payload.image_files {
        // In real implementation, decode base64 and upload to IPFS
        let ipfs_hash = format!("Qm{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        image_hashes.push(ipfs_hash);
    }

    let product = Product {
        id: Uuid::new_v4(),
        vendor_id: Uuid::new_v4(), // Should come from authenticated session
        title: payload.title,
        description: payload.description,
        category: payload.category,
        subcategory: payload.subcategory,
        price: payload.price,
        currency: "BLK".to_string(),
        quantity_available: payload.quantity_available,
        ships_from: payload.ships_from,
        ships_to: payload.ships_to,
        shipping_price: payload.shipping_price,
        processing_time: payload.processing_time,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        is_active: true,
        image_hashes,
        stealth_required: true,
        escrow_required: true,
    };

    match state.db.create_product(product.clone()).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({
            "success": true,
            "product_id": product.id,
            "message": "Product created successfully"
        }))),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to create product"
        }))),
    }
}

#[derive(Deserialize)]
struct PurchaseRequest {
    product_id: Uuid,
    quantity: u32,
    shipping_address: String, // Encrypted
    buyer_public_key: String,
}

async fn api_purchase(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PurchaseRequest>,
) -> impl IntoResponse {
    let product = match state.db.get_product_by_id(payload.product_id).await {
        Ok(Some(product)) => product,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Product not found"
        }))),
    };

    let vendor = match state.db.get_user_by_id(product.vendor_id).await {
        Ok(Some(vendor)) => vendor,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Vendor not found"
        }))),
    };

    let total_amount = product.price * payload.quantity as u64 + product.shipping_price;

    // Create escrow contract
    let buyer_pubkey = hex::decode(&payload.buyer_public_key).unwrap_or_default();
    let escrow_contract = match state.escrow_manager.create_escrow(
        &buyer_pubkey,
        &vendor.public_key,
        &[], // Arbiter key - should be marketplace or community
        total_amount,
    ).await {
        Ok(contract) => contract,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to create escrow contract"
        }))),
    };

    // Create order
    let order = Order {
        id: Uuid::new_v4(),
        buyer_id: Uuid::new_v4(), // Should come from session
        vendor_id: product.vendor_id,
        product_id: payload.product_id,
        quantity: payload.quantity,
        total_amount,
        escrow_contract_id: escrow_contract.contract_id,
        status: OrderStatus::AwaitingPayment,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        shipping_address: payload.shipping_address,
        tracking_number: None,
        buyer_feedback: None,
        vendor_feedback: None,
        dispute_reason: None,
    };

    match state.db.create_order(order.clone()).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({
            "success": true,
            "order_id": order.id,
            "escrow_contract_id": escrow_contract.contract_id,
            "total_amount": total_amount,
            "message": "Order created. Please fund escrow to complete purchase."
        }))),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to create order"
        }))),
    }
}

async fn api_search(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let query = params.get("q").unwrap_or(&String::new()).clone();
    let category = params.get("category");
    let limit: u32 = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20);
    let offset: u32 = params.get("offset").and_then(|o| o.parse().ok()).unwrap_or(0);

    let products = match state.db.search_products(&query, category, limit, offset).await {
        Ok(products) => products,
        Err(_) => vec![],
    };

    Json(serde_json::json!({
        "products": products,
        "total": products.len(),
        "query": query
    }))
}

// WebSocket for real-time updates
async fn websocket_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: axum::extract::ws::WebSocket) {
    use axum::extract::ws::Message;
    
    while let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(text) => {
                    // Handle real-time updates (order status, new products, etc.)
                    println!("Received: {}", text);
                    
                    // Echo back for now
                    if socket.send(Message::Text(format!("Echo: {}", text))).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }
}

pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        // Web pages
        .route("/", get(index))
        .route("/category/:id", get(category_page))
        .route("/product/:id", get(product_page))
        .route("/login", get(login_page))
        .route("/sell", get(sell_page))
        
        // API endpoints
        .route("/api/login", post(api_login))
        .route("/api/products", post(api_create_product))
        .route("/api/purchase", post(api_purchase))
        .route("/api/search", get(api_search))
        .route("/ws", get(websocket_handler))
        
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::init();

    let state = Arc::new(AppState::new().await?);
    let app = create_router().with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("🕸️  BlackSilk Marketplace running on http://127.0.0.1:3000");
    println!("⚠️  Community Standards: Don't be sick.");
    
    axum::serve(listener, app).await?;

    Ok(())
}
