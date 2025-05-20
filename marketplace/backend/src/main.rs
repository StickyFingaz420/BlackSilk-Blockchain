#[macro_use]
extern crate rocket;

use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use rocket::http::Status;
use rocket::State;
use std::sync::Arc;
use tokio::sync::Mutex;
use node::escrow as node_escrow;
use primitives::escrow::{EscrowContract, EscrowStatus};
use primitives::types::Hash;

// Types
#[derive(Debug, Serialize, Deserialize)]
pub struct Listing {
    id: String,
    title: String,
    description: String,
    price: u64,
    seller: String,
    images: Vec<String>, // IPFS hashes
    category: String,
    created_at: u64,
    status: ListingStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ListingStatus {
    Active,
    Sold,
    Suspended,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Order {
    id: String,
    listing_id: String,
    buyer: String,
    seller: String,
    amount: u64,
    escrow_address: String,
    status: OrderStatus,
    created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OrderStatus {
    Created,
    PaidToEscrow,
    Shipped,
    Completed,
    Disputed,
    Refunded,
}

#[derive(Debug, Deserialize)]
pub struct EscrowCreateRequest {
    pub contract_id: [u8; 32],
    pub buyer: [u8; 32],
    pub seller: [u8; 32],
    pub arbiter: [u8; 32],
    pub amount: u64,
}

// State
struct AppState {
    ipfs: IpfsClient,
    listings: Arc<Mutex<Vec<Listing>>>,
    orders: Arc<Mutex<Vec<Order>>>,
}

// Routes

#[get("/")]
fn index() -> &'static str {
    "BlackSilk Marketplace API"
}

// Listings
#[get("/listings")]
async fn get_listings(state: &State<AppState>) -> Json<Vec<Listing>> {
    let listings = state.listings.lock().await;
    Json(listings.clone())
}

#[post("/listings", format = "json", data = "<listing>")]
async fn create_listing(listing: Json<Listing>, state: &State<AppState>) -> Status {
    let mut listings = state.listings.lock().await;
    listings.push(listing.into_inner());
    Status::Created
}

#[get("/listings/<id>")]
async fn get_listing(id: String, state: &State<AppState>) -> Option<Json<Listing>> {
    let listings = state.listings.lock().await;
    listings.iter()
        .find(|l| l.id == id)
        .map(|l| Json(l.clone()))
}

// Orders
#[post("/orders", format = "json", data = "<order>")]
async fn create_order(order: Json<Order>, state: &State<AppState>) -> Status {
    let mut orders = state.orders.lock().await;
    orders.push(order.into_inner());
    Status::Created
}

#[get("/orders/<id>")]
async fn get_order(id: String, state: &State<AppState>) -> Option<Json<Order>> {
    let orders = state.orders.lock().await;
    orders.iter()
        .find(|o| o.id == id)
        .map(|o| Json(o.clone()))
}

// IPFS Integration
async fn upload_to_ipfs(data: &[u8], state: &State<AppState>) -> Result<String, Box<dyn std::error::Error>> {
    let ipfs = &state.ipfs;
    let res = ipfs.add(data).await?;
    Ok(res.hash)
}

// Escrow Functions
async fn create_escrow(amount: u64, buyer: &str, seller: &str) -> Result<String, Box<dyn std::error::Error>> {
    // TODO: Implement multisig escrow creation
    Ok("escrow_address_placeholder".to_string())
}

async fn release_escrow(escrow_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Implement escrow release
    Ok(())
}

// Escrow API
#[post("/escrow/create", format = "json", data = "<req>")]
fn create_escrow_endpoint(req: Json<EscrowCreateRequest>) -> Status {
    let contract = EscrowContract::new(
        req.contract_id,
        req.buyer,
        req.seller,
        req.arbiter,
        req.amount,
    );
    node_escrow::create_escrow(contract);
    Status::Created
}

#[derive(Debug, Deserialize)]
pub struct EscrowActionRequest {
    pub contract_id: [u8; 32],
    pub signer: [u8; 32],
}

#[post("/escrow/fund", format = "json", data = "<req>")]
fn fund_escrow_endpoint(req: Json<EscrowActionRequest>) -> Status {
    if node_escrow::fund_escrow(&req.contract_id, req.signer) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

#[post("/escrow/sign", format = "json", data = "<req>")]
fn sign_escrow_endpoint(req: Json<EscrowActionRequest>) -> Status {
    if node_escrow::sign_escrow(&req.contract_id, req.signer) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

#[post("/escrow/release", format = "json", data = "<req>")]
fn release_escrow_endpoint(req: Json<EscrowActionRequest>) -> Status {
    if node_escrow::release_escrow(&req.contract_id) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

#[post("/escrow/refund", format = "json", data = "<req>")]
fn refund_escrow_endpoint(req: Json<EscrowActionRequest>) -> Status {
    if node_escrow::refund_escrow(&req.contract_id) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

#[post("/escrow/dispute", format = "json", data = "<req>")]
fn dispute_escrow_endpoint(req: Json<EscrowActionRequest>) -> Status {
    if node_escrow::dispute_escrow(&req.contract_id, req.signer) {
        println!("[Escrow] Dispute raised for contract {:?} by {:?}", req.contract_id, req.signer);
        Status::Ok
    } else {
        Status::NotFound
    }
}

#[launch]
fn rocket() -> _ {
    let state = AppState {
        ipfs: IpfsClient::default(),
        listings: Arc::new(Mutex::new(Vec::new())),
        orders: Arc::new(Mutex::new(Vec::new())),
    };

    rocket::build()
        .manage(state)
        .mount("/", routes![
            index,
            get_listings,
            create_listing,
            get_listing,
            create_order,
            get_order,
            // Escrow endpoints
            create_escrow_endpoint,
            fund_escrow_endpoint,
            sign_escrow_endpoint,
            release_escrow_endpoint,
            refund_escrow_endpoint,
            dispute_escrow_endpoint,
        ])
} 