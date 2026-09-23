//! BlackSilk node library: the RPC server over a [`ChainManager`]
//! (docs/blocks.md §9).
//!
//! The binary (`main.rs`) opens the block store, replays it, and serves this
//! router on a loopback address. Everything consensus-relevant happens in
//! `blacksilk-chain` and below; this layer only decodes requests and bounds their
//! size and cost.

#![forbid(unsafe_code)]

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError};
use blacksilk_consensus::Network;
use blacksilk_p2p::Network as P2p;
use blacksilk_rpc as rpc;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use serde::Deserialize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Shared = Arc<Mutex<ChainManager>>;

/// RPC state: the chain, and the P2P network when it runs.
#[derive(Clone)]
pub struct App {
    pub chain: Shared,
    pub net: Option<P2p>,
}

pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Default RPC port per network.
pub fn default_rpc_port(n: Network) -> u16 {
    match n {
        Network::Mainnet => 19333,
        Network::Testnet => 29333,
        Network::Regtest => 39333,
    }
}

fn lock(shared: &Shared) -> MutexGuard<'_, ChainManager> {
    // A panic while holding the lock leaves the manager in a state produced by
    // complete operations only (sync_state runs to completion or panics before
    // mutating); continuing is preferable to taking the node down.
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// RPC without networking (tests, isolated nodes).
pub fn router(shared: Shared) -> Router {
    router_with(App {
        chain: shared,
        net: None,
    })
}

pub fn router_with(app: App) -> Router {
    Router::new()
        .route("/info", get(info))
        .route("/template", get(template))
        .route("/block", post(submit_block))
        .route("/tx", post(submit_tx))
        .route("/blocks", get(blocks))
        .route("/distribution", get(distribution))
        .route("/outputs", post(outputs))
        .layer(DefaultBodyLimit::max(rpc::MAX_REQUEST_BYTES))
        .with_state(app)
}

async fn info(State(App { chain: s, net }): State<App>) -> Json<rpc::Info> {
    let peers = net.map_or(0, |n| n.stats().peers);
    let m = lock(&s);
    Json(rpc::Info {
        network: network_name(m.params().network).to_string(),
        network_id: m.params().network_id,
        height: m.height(),
        tip: hex::encode(m.tip_id()),
        difficulty: m.tip_header().difficulty,
        generated: m.generated(),
        mempool_txs: m.mempool().len(),
        mempool_bytes: m.mempool().bytes(),
        outputs: m.state().output_count(),
        peers,
        header_height: m.header_height(),
    })
}

async fn template(State(App { chain: s, .. }): State<App>) -> Json<rpc::Template> {
    let m = lock(&s);
    let t = m.template();
    Json(rpc::Template {
        height: t.height,
        prev_id: hex::encode(t.prev_id),
        difficulty: t.difficulty,
        seed_id: hex::encode(t.seed_id),
        min_timestamp: t.min_timestamp,
        reward: t.reward,
        fees: t.fees,
        txs: t
            .txs
            .into_iter()
            .map(|tx| hex::encode(Transaction::from(tx).encode()))
            .collect(),
    })
}

fn rejected(error: String) -> rpc::SubmitResult {
    rpc::SubmitResult {
        accepted: false,
        id: None,
        on_best_chain: None,
        error: Some(error),
    }
}

async fn submit_block(
    State(App { chain: s, .. }): State<App>,
    Json(p): Json<rpc::HexPayload>,
) -> Result<Json<rpc::SubmitResult>, ApiError> {
    let bytes = hex::decode(&p.hex).map_err(|_| bad_request("hex"))?;
    let block = Block::decode(&bytes).map_err(|e| bad_request(format!("block: {e:?}")))?;
    // Validation (RandomX, CLSAG, BP+) is CPU-bound: keep it off the async workers.
    let result = tokio::task::spawn_blocking(move || {
        let mut m = lock(&s);
        let r = m.submit_block(block, now());
        (r, m.height())
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(match result {
        (Ok(sub), height) => {
            log::info!(
                "block {} at height {} accepted (tip {height})",
                hex::encode(&sub.id[..8]),
                sub.height
            );
            rpc::SubmitResult {
                accepted: true,
                id: Some(hex::encode(sub.id)),
                on_best_chain: Some(sub.on_best_chain),
                error: None,
            }
        }
        (Err(e), _) => {
            if let SubmitError::Store(io) = &e {
                log::error!("block store write failed: {io}");
            } else {
                log::info!("block rejected: {e:?}");
            }
            rejected(format!("{e:?}"))
        }
    }))
}

async fn submit_tx(
    State(App { chain: s, net }): State<App>,
    Json(p): Json<rpc::HexPayload>,
) -> Result<Json<rpc::SubmitResult>, ApiError> {
    let bytes = hex::decode(&p.hex).map_err(|_| bad_request("hex"))?;
    let tx = Transaction::decode(&bytes).map_err(|e| bad_request(format!("transaction: {e:?}")))?;
    // With networking, local transactions enter the Dandelion++ stem (docs/p2p.md §8)
    // instead of being broadcast from this node directly.
    let result = match net {
        Some(n) => n.submit_tx(tx).await,
        None => tokio::task::spawn_blocking(move || lock(&s).submit_tx(tx))
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| format!("{e:?}")),
    };
    Ok(Json(match result {
        Ok(id) => rpc::SubmitResult {
            accepted: true,
            id: Some(hex::encode(id)),
            on_best_chain: None,
            error: None,
        },
        Err(e) => rejected(e),
    }))
}

#[derive(Deserialize)]
struct BlocksQuery {
    from: u64,
    count: u64,
}

async fn blocks(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<rpc::Blocks>, ApiError> {
    if q.count == 0 || q.count > rpc::MAX_BLOCKS_PER_REQUEST {
        return Err(bad_request(format!(
            "count must be 1..={}",
            rpc::MAX_BLOCKS_PER_REQUEST
        )));
    }
    let m = lock(&s);
    let end = q.from.saturating_add(q.count - 1).min(m.height());
    let mut out = Vec::new();
    for h in q.from..=end {
        let block = m.block_at(h).expect("connected height");
        out.push(rpc::BlockEntry {
            height: h,
            id: hex::encode(block.id(m.params().network_id)),
            first_output: m.state().first_output_at(h).expect("connected height"),
            hex: hex::encode(block.encode()),
        });
    }
    Ok(Json(rpc::Blocks { blocks: out }))
}

#[derive(Deserialize)]
struct DistributionQuery {
    to: u64,
}

async fn distribution(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<DistributionQuery>,
) -> Json<rpc::Distribution> {
    let m = lock(&s);
    let mut cumulative = m.state().cumulative_outputs();
    cumulative.truncate(q.to.saturating_add(1) as usize);
    Json(rpc::Distribution { cumulative })
}

async fn outputs(
    State(App { chain: s, .. }): State<App>,
    Json(req): Json<rpc::OutputsRequest>,
) -> Result<Json<rpc::Outputs>, ApiError> {
    if req.indices.len() > rpc::MAX_OUTPUTS_PER_REQUEST {
        return Err(bad_request(format!(
            "at most {} indices",
            rpc::MAX_OUTPUTS_PER_REQUEST
        )));
    }
    let m = lock(&s);
    let mut out = Vec::with_capacity(req.indices.len());
    for &i in &req.indices {
        let rec = m
            .state()
            .output(i)
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("output {i}")))?;
        out.push(rpc::OutputEntry {
            index: i,
            one_time_key: hex::encode(rec.key.one_time_key.bytes()),
            commitment: hex::encode(rec.key.commitment.bytes()),
            height: rec.height,
            coinbase: rec.coinbase,
        });
    }
    Ok(Json(rpc::Outputs { outputs: out }))
}
