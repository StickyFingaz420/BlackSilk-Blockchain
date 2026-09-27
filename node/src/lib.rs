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
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use serde::Deserialize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Exit status of a node whose chain lock was poisoned.
pub const POISONED_EXIT_CODE: i32 = 70;

fn lock(shared: &Shared) -> MutexGuard<'_, ChainManager> {
    // A panic while holding the lock can leave the manager half-updated (a block
    // applied to the state but not to the tip, for example). Continuing would
    // serve and build on that state, so the node stops instead: the block store
    // is append-only and a restart replays it deterministically.
    match shared.lock() {
        Ok(guard) => guard,
        Err(_) => {
            log::error!("chain state lock poisoned by a panic; stopping (restart to recover)");
            std::process::exit(POISONED_EXIT_CODE)
        }
    }
}

/// The message the node exits with when its block store failed.
pub const STORE_FAILED_EXIT: &str = "block store write failed: free disk space / check the disk, \
     then restart the node; it resumes from the last stored block (docs/testnet.md §9)";

/// Resolves once the chain's block store has failed persistently
/// ([`ChainManager::store_failed`]), checked every `period` on a plain thread.
/// A node whose store failed accepts no block but would keep downloading
/// bodies; the caller shuts it down so that a restart recovers
/// deterministically (the load truncates a torn tail).
pub fn watch_store(shared: Shared, period: Duration) -> tokio::sync::oneshot::Receiver<()> {
    poll_until(period, move || lock(&shared).store_failed())
}

/// Resolves the returned receiver once `check` returns true, polling every
/// `period`. The thread ends when the receiver is dropped.
fn poll_until(
    period: Duration,
    check: impl Fn() -> bool + Send + 'static,
) -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || loop {
        if tx.is_closed() {
            return;
        }
        if check() {
            let _ = tx.send(());
            return;
        }
        std::thread::sleep(period);
    });
    rx
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

// The RPC body limit covers the largest block, hex-encoded.
const _: () = assert!(rpc::MAX_REQUEST_BYTES >= 2 * blacksilk_chain::block::MAX_BLOCK_BYTES + 1024);

pub fn router_with(app: App) -> Router {
    Router::new()
        .route("/info", get(info))
        .route("/template", get(template))
        .route("/block", post(submit_block))
        .route("/tx", post(submit_tx))
        .route("/blocks", get(blocks))
        .route("/distribution", get(distribution))
        .route("/outputs", post(outputs))
        .route("/px/commitments", get(px_commitments))
        .route("/px/contracts", get(px_contracts))
        .layer(DefaultBodyLimit::max(rpc::MAX_REQUEST_BYTES))
        .with_state(app)
}

async fn info(State(App { chain: s, net }): State<App>) -> Json<rpc::Info> {
    let stats = net.map(|n| n.stats());
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
        peers: stats.as_ref().map_or(0, |s| s.peers),
        header_height: m.header_height(),
        deepest_reorg: m.deepest_reorg() as u64,
        misbehaving_disconnects: stats.as_ref().map_or(0, |s| s.misbehaving_disconnects),
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
            .map(|tx| hex::encode(tx.encode()))
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
    let mut bytes = 0usize;
    for h in q.from..=end {
        let block = m.block_at(h).expect("connected height");
        let hex = hex::encode(block.encode());
        if !out.is_empty() && bytes + hex.len() > rpc::MAX_BLOCKS_RESPONSE_BYTES {
            break; // the client continues from the next height
        }
        bytes += hex.len();
        out.push(rpc::BlockEntry {
            height: h,
            id: hex::encode(block.id(m.params().network_id)),
            first_output: m.state().first_output_at(h).expect("connected height"),
            hex,
        });
    }
    Ok(Json(rpc::Blocks { blocks: out }))
}

#[derive(Deserialize)]
struct FromQuery {
    from: u64,
}

fn digest_hex(d: &[u32; 8]) -> String {
    hex::encode(blacksilk_tx::px::digest_bytes(d))
}

#[derive(Deserialize)]
struct PxCommitmentsQuery {
    from: Option<u64>,
    limit: Option<u64>,
}

/// A page of the PX commitment list, copied out of the state: only the
/// requested entries (height and 32-byte digest each), never the record log
/// or its ciphertexts.
struct PxPage {
    from: u64,
    /// `(height, commitment)`; a PX digest is eight field words.
    entries: Vec<(u64, [u32; 8])>,
    total: u64,
    root: [u32; 8],
    height: u64,
}

impl PxPage {
    /// Validates the query and copies the page. Cost is proportional to the
    /// page, so the caller may hold the chain lock around it.
    fn take(
        state: &MemoryChain,
        height: u64,
        from: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Self, String> {
        let from = from.unwrap_or(0);
        let limit = limit.unwrap_or(rpc::DEFAULT_PX_COMMITMENTS_PER_REQUEST);
        if limit == 0 || limit > rpc::MAX_PX_COMMITMENTS_PER_REQUEST {
            return Err(format!(
                "limit must be 1..={}",
                rpc::MAX_PX_COMMITMENTS_PER_REQUEST
            ));
        }
        let entries = state
            .px_record_slice(from, limit as usize)
            .iter()
            .map(|r| (r.height, r.commitment))
            .collect();
        Ok(Self {
            from,
            entries,
            total: state.px_record_count(),
            root: state.px().root(),
            height,
        })
    }

    fn render(self) -> rpc::PxCommitments {
        let end = self.from.saturating_add(self.entries.len() as u64);
        rpc::PxCommitments {
            from: self.from,
            commitments: self
                .entries
                .iter()
                .map(|(h, c)| (*h, digest_hex(c)))
                .collect(),
            total: self.total,
            root: digest_hex(&self.root),
            height: self.height,
            next: (end < self.total).then_some(end),
        }
    }
}

/// The `/px/commitments` answer for `from` and `limit` (both optional, as in
/// the query string) on `state` at tip `height`; `Err` is the HTTP 400
/// message. Exposed for tests: the RPC handler is exactly this.
pub fn px_commitments_page(
    state: &MemoryChain,
    height: u64,
    from: Option<u64>,
    limit: Option<u64>,
) -> Result<rpc::PxCommitments, String> {
    PxPage::take(state, height, from, limit).map(PxPage::render)
}

async fn px_commitments(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<PxCommitmentsQuery>,
) -> Result<Json<rpc::PxCommitments>, ApiError> {
    // The lock is held only to copy the requested page; hex encoding and
    // serialization happen after it is released.
    let page = {
        let m = lock(&s);
        PxPage::take(m.state(), m.height(), q.from, q.limit)
    };
    Ok(Json(page.map_err(bad_request)?.render()))
}

async fn px_contracts(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<FromQuery>,
) -> Json<rpc::PxContracts> {
    let m = lock(&s);
    let state = m.state();
    let log = state.px_contract_log();
    let total = log.len() as u64;
    let contracts = log
        .iter()
        .skip(q.from.min(total) as usize)
        .take(rpc::MAX_PX_CONTRACTS_PER_REQUEST as usize)
        .map(|(height, id)| rpc::PxContractEntry {
            height: *height,
            id: digest_hex(id),
            programs: state
                .px_contract(id)
                .unwrap_or(&[])
                .iter()
                .map(|f| {
                    let b = f.budget;
                    rpc::PxProgramEntry {
                        id: hex::encode(f.program_id),
                        budget: [
                            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                        ],
                    }
                })
                .collect(),
        })
        .collect();
    Json(rpc::PxContracts {
        from: q.from,
        contracts,
        total,
        height: m.height(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The store watcher fires once the check turns true, not before.
    #[test]
    fn poll_until_fires_when_the_check_turns_true() {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let mut rx = poll_until(Duration::from_millis(5), move || f.load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err(), "not fired while the check is false");
        flag.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match rx.try_recv() {
                Ok(()) => break,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("watcher did not fire: {e:?}"),
            }
        }
    }
}
