// Axum + sqlx + IPFS + BlackSilk Marketplace
use axum::{routing::{get, post}, Router, Json, extract::{State, Path, Multipart, FromRequestParts}, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use dotenvy::dotenv;
use std::{env, sync::Arc};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use hex::FromHex;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use serde_json;
use chrono;
use anyhow;
use async_trait::async_trait;
use axum::http::StatusCode;
use axum_macros::debug_handler;
use tokio::task;

// Types
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Listing {
    pub id: String,
    pub title: String,
    pub description: String,
    pub price: i64,
    pub seller: String,
    pub images: Vec<String>, // IPFS hashes
    pub category: String,
    pub created_at: i64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Order {
    pub id: String,
    pub listing_id: String,
    pub buyer: String,
    pub seller: String,
    pub amount: i64,
    pub escrow_address: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Escrow {
    pub contract_id: String,
    pub buyer: String,
    pub seller: String,
    pub arbiter: String,
    pub amount: i64,
    pub status: String,
}

#[derive(Clone)]
struct AppState {
    db: PgPool,
    ipfs: Arc<IpfsClient>,
}

// --- Wallet Auth Middleware ---
#[derive(Debug, Clone)]
pub struct WalletAuth {
    pub wallet_address: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for WalletAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let wallet_address = parts.headers.get("x-wallet-address").and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "Missing wallet address header"))?.to_string();
        let message = parts.headers.get("x-wallet-message").and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "Missing message header"))?;
        let signature = parts.headers.get("x-wallet-signature").and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "Missing signature header"))?;
        let sig_bytes = Vec::from_hex(signature).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature format"))?;
        let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length"))?;
        let signature = Signature::from_bytes(&sig_bytes);
        let pubkey_bytes = Vec::from_hex(&wallet_address).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid public key"))?;
        let pubkey_bytes: [u8; 32] = match pubkey_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid public key length")),
        };
        let public_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(pk) => pk,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid public key")),
        };
        if public_key.verify(message.as_bytes(), &signature).is_ok() {
            Ok(WalletAuth { wallet_address })
        } else {
            Err((StatusCode::UNAUTHORIZED, "Invalid signature"))
        }
    }
}

// --- IPFS Upload Endpoint ---
async fn ipfs_upload(State(_state): State<Arc<AppState>>, mut _multipart: Multipart) -> impl IntoResponse {
    // TODO: Implement IPFS upload using reqwest or a compatible REST client for Send compatibility.
    (StatusCode::NOT_IMPLEMENTED, "IPFS upload not implemented: use a REST client or web3.storage API.").into_response()
}

// Listings Endpoints
async fn get_listings(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let listings = sqlx::query_as::<_, Listing>("SELECT * FROM listings")
        .fetch_all(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    Ok(Json(listings))
}

async fn create_listing(
    State(state): State<Arc<AppState>>,
    WalletAuth { wallet_address }: WalletAuth,
    Json(listing): Json<Listing>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let _ = sqlx::query("INSERT INTO listings (id, title, description, price, seller, images, category, created_at, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&listing.id)
        .bind(&listing.title)
        .bind(&listing.description)
        .bind(listing.price)
        .bind(&wallet_address)
        .bind(&listing.images)
        .bind(&listing.category)
        .bind(listing.created_at)
        .bind(&listing.status)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    Ok((StatusCode::CREATED, "Listing created"))
}

async fn get_listing(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let listing = sqlx::query_as::<_, Listing>("SELECT * FROM listings WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    match listing {
        Some(l) => Ok(Json(l).into_response()),
        None => Err((StatusCode::NOT_FOUND, "Listing not found")),
    }
}

// Orders Endpoints
async fn create_order(
    State(state): State<Arc<AppState>>,
    WalletAuth { wallet_address }: WalletAuth,
    Json(order): Json<Order>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let _ = sqlx::query("INSERT INTO orders (id, listing_id, buyer, seller, amount, escrow_address, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&order.id)
        .bind(&order.listing_id)
        .bind(&wallet_address)
        .bind(&order.seller)
        .bind(order.amount)
        .bind(&order.escrow_address)
        .bind(&order.status)
        .bind(order.created_at)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    Ok((StatusCode::CREATED, "Order created"))
}

async fn get_order(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let order = sqlx::query_as::<_, Order>("SELECT * FROM orders WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    match order {
        Some(o) => Ok(Json(o).into_response()),
        None => Err((StatusCode::NOT_FOUND, "Order not found")),
    }
}

// Escrow Endpoints (Stub, to be integrated with smart contracts)
#[derive(Debug, Deserialize)]
pub struct EscrowCreateRequest {
    pub contract_id: String,
    pub buyer: String,
    pub seller: String,
    pub arbiter: String,
    pub amount: i64,
}

async fn create_escrow(
    State(state): State<Arc<AppState>>,
    WalletAuth { wallet_address }: WalletAuth,
    Json(req): Json<EscrowCreateRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    // TODO: Call smart contract here and get tx hash/address
    let contract_address = format!("escrow-{}", req.contract_id);
    let _ = sqlx::query("INSERT INTO escrows (contract_id, buyer, seller, arbiter, amount, status) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(&req.contract_id)
        .bind(&wallet_address)
        .bind(&req.seller)
        .bind(&req.arbiter)
        .bind(req.amount)
        .bind("Created")
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;
    Ok(Json(serde_json::json!({"contract_address": contract_address})))
}

// Mining Endpoints (Stub)
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub header: Vec<u8>,
    pub difficulty: i64,
    pub seed: Vec<u8>,
    pub coinbase_address: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockTemplateRequest {
    pub address: String,
}

async fn get_block_template(Json(req): Json<BlockTemplateRequest>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let mut header = vec![0; 80];
    let addr_bytes = req.address.as_bytes();
    for (i, b) in addr_bytes.iter().enumerate().take(16) {
        header[i] = *b;
    }
    let difficulty = 1000000;
    let seed = vec![1; 32];
    Ok(Json(BlockTemplate {
        header,
        difficulty,
        seed,
        coinbase_address: req.address,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SubmitBlockRequest {
    pub header: Vec<u8>,
    pub nonce: i64,
    pub hash: Vec<u8>,
}

async fn submit_block(Json(_req): Json<SubmitBlockRequest>) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    Ok((StatusCode::OK, "Block submitted"))
}

// Auth Endpoints (already Axum)
#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

async fn auth_challenge() -> Result<Json<ChallengeResponse>, (StatusCode, &'static str)> {
    let nonce: String = format!(
        "login-nonce-{}-{}",
        chrono::Utc::now().timestamp(),
        thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect::<String>()
    );
    Ok(Json(ChallengeResponse { nonce }))
}

#[derive(Deserialize)]
struct AuthRequest {
    wallet_address: String,
    message: String,
    signature: String,
}

async fn auth_login(
    State(state): State<Arc<AppState>>,
    Json(auth): Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let sig_bytes = Vec::from_hex(&auth.signature).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature format"))?;
    let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let pubkey_bytes = Vec::from_hex(&auth.wallet_address).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid public key"))?;
    let pubkey_bytes: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid public key length")),
    };
    let public_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid public key")),
    };
    if public_key.verify(auth.message.as_bytes(), &signature).is_ok() {
        let _ = sqlx::query("INSERT INTO users (wallet_address) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&auth.wallet_address)
            .execute(&state.db)
            .await;
        Ok((StatusCode::OK, "✅ Login successful!"))
    } else {
        Err((StatusCode::UNAUTHORIZED, "❌ Invalid signature"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = PgPoolOptions::new().max_connections(5).connect(&db_url).await?;
    let ipfs = Arc::new(IpfsClient::default());
    let state = Arc::new(AppState { db, ipfs });
    let app = Router::new()
        .route("/ipfs/upload", post(ipfs_upload))
        .route("/listings", get(get_listings).post(create_listing))
        .route("/listings/:id", get(get_listing))
        .route("/orders", post(create_order))
        .route("/orders/:id", get(get_order))
        .route("/escrow/create", post(create_escrow))
        .route("/mining/get_block_template", post(get_block_template))
        .route("/mining/submit_block", post(submit_block))
        .route("/auth/challenge", get(auth_challenge))
        .route("/auth/login", post(auth_login))
        .with_state(state);
    println!("Axum server running on http://0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
} 