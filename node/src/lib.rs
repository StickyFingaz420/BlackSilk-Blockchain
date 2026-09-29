//! BlackSilk node library: the RPC server over a [`ChainManager`]
//! (docs/blocks.md §9).
//!
//! The binary (`main.rs`) opens the block store, replays it, starts the chain
//! actor (`blacksilk_chain::actor`) and serves this router on a loopback
//! address. Every chain access of a handler is one command on the actor's
//! lanes (`/block` on the Blocks lane, local `/tx` on the Tx lane, the other
//! reads on the Query lane); `/info`, `/tip` and the halt watcher read the
//! published snapshot. Everything consensus-relevant happens in `blacksilk-chain` and
//! below; this layer only decodes requests and bounds their size and cost.

#![forbid(unsafe_code)]

pub mod cookie;
pub mod fingerprint;
pub mod guard;
pub mod serve;

use axum::extract::{DefaultBodyLimit, Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use blacksilk_chain::actor::{self, ActorConfig, ChainHandle, Lane};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{
    ChainManager, ChainSummary, OperatorFork, SubmitError, SummaryCell,
};
use blacksilk_chain::sync_policy::{self, worth_verifying};
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, Network};
use blacksilk_p2p::{chain_access, Network as P2p};
use blacksilk_rpc as rpc;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A manager behind a lock the caller keeps (tests and embedders): the input
/// of [`router`], which starts a chain actor over it
/// (`blacksilk_chain::actor::spawn_shared`). The node binary shares one
/// actor between RPC and P2P instead ([`App`]).
pub type Shared = Arc<Mutex<ChainManager>>;

/// RPC state: the chain actor, the P2P network when it runs, and the
/// operator's mining policy.
#[derive(Clone)]
pub struct App {
    pub chain: ChainHandle,
    pub net: Option<P2p>,
    pub mining: MiningPolicy,
}

impl App {
    /// An `App` over a chain actor started on `shared` (tests and
    /// embedders; see [`Shared`]), with the default mining policy.
    pub fn shared(shared: Shared, net: Option<P2p>) -> Self {
        let (chain, _thread) = actor::spawn_shared(shared, ActorConfig::default());
        Self {
            chain,
            net,
            mining: MiningPolicy::default(),
        }
    }
}

/// The operator's overrides of the template gate (docs/blocks.md §9.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MiningPolicy {
    /// `--mine-despite-operator-fork`: serve templates although a heavier
    /// chain is refused only because of the operator's verdicts
    /// ([`ChainManager::operator_fork`], RTW3-8). Off by default: blocks
    /// mined then extend a chain the rest of the network does not follow.
    pub despite_operator_fork: bool,
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

/// Exit status of a node whose chain actor panicked (a panic while running
/// a chain operation can leave the manager half-updated; the node stops and
/// a restart replays the append-only store deterministically).
pub const POISONED_EXIT_CODE: i32 = 70;
// The chain actor and the P2P layer stop the node the same way (they cannot
// depend on this crate).
const _: () = assert!(POISONED_EXIT_CODE == blacksilk_p2p::POISONED_EXIT_CODE);
const _: () = assert!(POISONED_EXIT_CODE == actor::POISONED_EXIT_CODE);

/// The message the node exits with when its block store failed.
pub const STORE_FAILED_EXIT: &str = "block store write failed: free disk space / check the disk, \
     then restart the node; it resumes from the last stored block (docs/testnet.md §9)";

/// Exit status of a node that stopped because a block that passed
/// validation failed to apply ([`ChainManager::apply_halted`]): a bug in this
/// node, and deterministic, so a restart replays into the same failure. The
/// systemd unit lists it in `RestartPreventExitStatus` so that the node is
/// not restarted in a loop (docs/testnet.md, RTW1B-4). 65 is `EX_DATAERR`
/// (sysexits.h); other failures exit 1, a configuration error 2, a poisoned
/// chain lock [`POISONED_EXIT_CODE`].
pub const HALT_EXIT_CODE: i32 = 65;
const _: () = assert!(HALT_EXIT_CODE != POISONED_EXIT_CODE && HALT_EXIT_CODE > 2);

/// The exit status of a node stopped by [`watch_store`]:
/// [`HALT_EXIT_CODE`] for an apply failure, 1 for a failed block store
/// (which a restart may recover from once the disk is fixed). Read from the
/// published snapshot (the actor publishes the halt with the command that
/// caused it).
pub fn halt_exit_code(chain: &ChainHandle) -> i32 {
    if chain.summary().apply_halted {
        HALT_EXIT_CODE
    } else {
        1
    }
}

/// The exit status for an error from [`ChainManager::open`]:
/// [`HALT_EXIT_CODE`] when replay hit the same deterministic apply failure
/// ([`blacksilk_chain::manager::ApplyHalt`]), so that a restart loop stops at
/// start-up too; 1 otherwise.
pub fn open_exit_code(e: &std::io::Error) -> i32 {
    match e.get_ref() {
        Some(inner) if inner.is::<blacksilk_chain::manager::ApplyHalt>() => HALT_EXIT_CODE,
        _ => 1,
    }
}

/// Resolves once the chain manager has halted ([`ChainManager::halted`]):
/// its block store failed persistently, or a block that passed validation
/// failed to apply. Checked every `period` on a plain thread, on the
/// published chain snapshot (the actor publishes the halt with the command
/// that caused it), so the check never queues behind a long command. A
/// halted node accepts no block but would keep downloading bodies; the
/// caller shuts it down so that a restart recovers deterministically (the
/// load truncates a torn tail and replays the store).
pub fn watch_store(chain: &ChainHandle, period: Duration) -> tokio::sync::oneshot::Receiver<()> {
    let summary = chain.summary_cell();
    poll_until(period, move || summary.load().halted())
}

/// Why the node stopped, once [`watch_store`] resolved: the manager's
/// reason, with the operator instructions for a failed store (from the
/// published snapshot).
pub fn halt_message(chain: &ChainHandle) -> String {
    let s = chain.summary();
    if s.store_failed {
        STORE_FAILED_EXIT.to_string()
    } else {
        s.halt_reason
            .clone()
            .unwrap_or_else(|| STORE_FAILED_EXIT.to_string())
    }
}

/// How often [`watch_operator_fork`] repeats its warning while an operator
/// fork lasts.
pub const OPERATOR_FORK_WARN_INTERVAL: Duration = Duration::from_secs(600);

/// The periodic warning of an operator fork (RTW3-8): a message when one
/// starts, then every `interval` while it lasts, and one when it ends.
#[derive(Debug)]
pub struct ForkWarner {
    interval: Duration,
    last: Option<(OperatorFork, std::time::Instant)>,
}

impl ForkWarner {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// The message to log for the fork state `fork` at `at`, if any:
    /// `(true, _)` for a warning, `(false, _)` for the all-clear.
    pub fn poll(
        &mut self,
        fork: Option<OperatorFork>,
        mining: MiningPolicy,
        at: std::time::Instant,
    ) -> Option<(bool, String)> {
        match (fork, self.last) {
            (None, None) => None,
            (None, Some(_)) => {
                self.last = None;
                Some((
                    false,
                    "operator fork ended: no heavier chain is refused because of the \
                     operator's verdicts any more"
                        .into(),
                ))
            }
            (Some(f), last) => {
                let due = match last {
                    None => true,
                    Some((prev, t)) => {
                        prev.block != f.block || at.duration_since(t) >= self.interval
                    }
                };
                if !due {
                    return None;
                }
                self.last = Some((f, at));
                Some((true, operator_fork_warning(&f, mining)))
            }
        }
    }
}

/// The text of the operator-fork warning.
pub fn operator_fork_warning(f: &OperatorFork, mining: MiningPolicy) -> String {
    format!(
        "operator fork: a heavier chain (known up to height {}) is refused only because the \
         operator invalidated block {} at height {}. This node is off the network's chain: \
         its view, its wallets' balances and any block mined here differ from the network. \
         Verify the incident through a second channel; --reconsider-block {} undoes the \
         verdict (for example after upgrading to a fixed build). Templates are {}",
        f.branch_height,
        hex::encode(f.block),
        f.height,
        hex::encode(f.block),
        if mining.despite_operator_fork {
            "still served (--mine-despite-operator-fork)"
        } else {
            "refused (--mine-despite-operator-fork overrides)"
        }
    )
}

/// Logs [`ForkWarner`]'s messages for the published snapshot, checked
/// every `period` on a plain thread (never a chain command), until the
/// returned sender is dropped.
pub fn watch_operator_fork(
    chain: &ChainHandle,
    period: Duration,
    mining: MiningPolicy,
) -> std::sync::mpsc::Sender<()> {
    let summary = chain.summary_cell();
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut warner = ForkWarner::new(OPERATOR_FORK_WARN_INTERVAL);
        loop {
            let fork = summary.load().operator_fork;
            match warner.poll(fork, mining, std::time::Instant::now()) {
                Some((true, msg)) => log::warn!("{msg}"),
                Some((false, msg)) => log::info!("{msg}"),
                None => {}
            }
            match stopped.recv_timeout(period) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                _ => return,
            }
        }
    });
    stop
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

/// The system clock in seconds since the Unix epoch, or `None` when it reads
/// before the epoch (unusable: every block would be in its future).
pub fn system_clock() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The start-up clock check (dossier 04 W4; decisions, "Agent 04"). The
/// local clock is the only clock consensus reads (the future time limit,
/// consensus.md §5), and nothing corrects it. A node refuses to start on a
/// clock that it cannot read or that is before the genesis block, since it
/// could accept no new block. It warns (the returned message) when the
/// stored best block is stamped more than the future time limit ahead of
/// the clock: the chain is in this clock's future, so the clock is probably
/// behind, and new blocks are refused until it is set. `now` is
/// [`system_clock`].
pub fn clock_check(
    now: Option<u64>,
    params: &ChainParams,
    tip_timestamp: u64,
) -> Result<Option<String>, String> {
    let Some(now) = now else {
        return Err(
            "the system clock reads before 1970: set it (docs/testnet.md §12.2); \
                    consensus checks every new block's timestamp against it"
                .into(),
        );
    };
    let genesis = params.genesis.timestamp;
    if now < genesis {
        return Err(format!(
            "the system clock ({now}) is before this network's genesis block ({genesis}): \
             set it (docs/testnet.md §12.2); this node could accept no new block"
        ));
    }
    let ftl = params.future_time_limit;
    Ok((tip_timestamp > now.saturating_add(ftl)).then(|| {
        format!(
            "the stored best block is stamped {} s ahead of the system clock, more than the \
             future time limit ({ftl} s): the clock is probably behind, and new blocks are \
             refused until it is set (docs/testnet.md §12.2)",
            tip_timestamp - now
        )
    }))
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

fn internal(e: tokio::task::JoinError) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// The answer when the chain actor stopped (the node is shutting down).
fn stopping() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "the node is shutting down".into(),
    )
}

/// Runs `f` as one command on the chain actor's Query lane: an RPC handler
/// never waits on an async worker or a blocking thread, which the P2P tasks
/// share (R10-5), and its answer reflects the chain state at one point of
/// the actor's command order (docs/blocks.md §9).
async fn with_chain<T: Send + 'static>(
    chain: &ChainHandle,
    f: impl FnOnce(&ChainManager) -> T + Send + 'static,
) -> Result<T, ApiError> {
    on_lane(chain, Lane::Query, move |m| f(m)).await
}

/// [`with_chain`] on `lane`, with the manager mutable.
async fn on_lane<T: Send + 'static>(
    chain: &ChainHandle,
    lane: Lane,
    f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
) -> Result<T, ApiError> {
    chain_access::call(chain, lane, f)
        .await
        .ok_or_else(stopping)
}

/// RPC without networking (tests, isolated nodes) over a chain actor started
/// on `shared`. Guarded, without a credential: see [`router_with`].
pub fn router(shared: Shared) -> Router {
    router_with(App::shared(shared, None))
}

// The RPC body limit covers the largest block, hex-encoded.
const _: () = assert!(rpc::MAX_REQUEST_BYTES >= 2 * blacksilk_chain::block::MAX_BLOCK_BYTES + 1024);

/// Every route, with its method (docs/blocks.md §9). The guard runs in front
/// of all of them, and of unknown paths (tests enumerate this list).
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/info"),
    ("GET", "/template"),
    ("GET", "/tip"),
    ("POST", "/block"),
    ("POST", "/tx"),
    ("GET", "/blocks"),
    ("GET", "/headers"),
    ("GET", "/distribution"),
    ("POST", "/outputs"),
    ("GET", "/px/commitments"),
    ("GET", "/px/contracts"),
    ("GET", "/tx/status"),
];

/// The router behind the guard's host, browser, body and admission checks
/// (docs/blocks.md §9.1), without a credential. Embedders and tests use
/// this; the node binary serves [`serve::run`], which always requires the
/// cookie.
pub fn router_with(app: App) -> Router {
    router_secured(app, guard::Policy::default())
}

/// The router behind the guard with `policy` (docs/blocks.md §9.1). The guard
/// is the outermost layer, so it covers every route and unknown paths.
/// `/info` and `/tip` read the chain actor's published snapshot
/// (`ChainHandle::summary_cell`), never a command.
pub fn router_secured(app: App, policy: guard::Policy) -> Router {
    let guard = Arc::new(guard::Guard::new(policy));
    let summary = app.chain.summary_cell();
    Router::new()
        .route("/info", get(info))
        .route("/template", get(template))
        .route("/tip", get(tip))
        .route("/block", post(submit_block))
        .route("/tx", post(submit_tx))
        .route("/blocks", get(blocks))
        .route("/headers", get(headers))
        .route("/distribution", get(distribution))
        .route("/outputs", post(outputs))
        .route("/px/commitments", get(px_commitments))
        .route("/px/contracts", get(px_contracts))
        .route("/tx/status", get(tx_status_route))
        // The guard has already read the body within its per-route limit;
        // this only lets the extractors take a body of that size.
        .layer(DefaultBodyLimit::max(rpc::MAX_REQUEST_BYTES))
        .layer(Extension(summary))
        .with_state(app)
        .layer(axum::middleware::from_fn_with_state(guard, guard::guard))
}

/// `/info` answers from the published chain snapshot, never a command: it
/// stays prompt during any long command (F34-4), and its chain fields are
/// those of the last publication (at most one command or drain step old,
/// mutually consistent).
async fn info(
    State(App { net, mining, .. }): State<App>,
    Extension(summary): Extension<Arc<SummaryCell>>,
) -> Json<NodeInfo> {
    let stats = net.map(|n| n.stats());
    Json(node_info(&summary.load(), stats, mining, now()))
}

/// `/info`'s answer: the [`rpc::Info`] fields plus the template gate's state
/// (docs/blocks.md §9.4). A client that decodes only [`rpc::Info`] ignores
/// the extra fields.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NodeInfo {
    #[serde(flatten)]
    pub info: rpc::Info,
    /// The catch-up latch (RTW3-1): set once the node was caught up; from
    /// then on only a drain in progress or an operator fork refuses
    /// templates.
    pub template_latched: bool,
    /// Present while a heavier chain is refused only because of the
    /// operator's verdicts (RTW3-8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_fork: Option<OperatorForkInfo>,
}

/// [`OperatorFork`] as `/info` reports it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorForkInfo {
    /// The operator-invalidated block (full hex id) and its height.
    pub block: String,
    pub height: u64,
    /// The refused branch's heaviest known header height (a lower bound of
    /// the network's chain).
    pub branch_height: u64,
    /// Whether `/template` refuses because of it (no
    /// `--mine-despite-operator-fork`).
    pub templates_refused: bool,
}

/// The `/info` answer for the published snapshot `s` at the local time
/// `now`.
pub fn node_info(
    s: &ChainSummary,
    stats: Option<blacksilk_p2p::NetStats>,
    mining: MiningPolicy,
    now: u64,
) -> NodeInfo {
    NodeInfo {
        info: info_of(s, stats, summary_template_ready(s, mining, now)),
        template_latched: s.template_latched,
        operator_fork: s.operator_fork.map(|f| OperatorForkInfo {
            block: hex::encode(f.block),
            height: f.height,
            branch_height: f.branch_height,
            templates_refused: !mining.despite_operator_fork,
        }),
    }
}

fn info_of(
    s: &ChainSummary,
    stats: Option<blacksilk_p2p::NetStats>,
    template_ready: bool,
) -> rpc::Info {
    rpc::Info {
        network: network_name(s.network).to_string(),
        network_id: s.network_id,
        height: s.height,
        tip: hex::encode(s.tip_id),
        difficulty: s.tip_header.difficulty,
        generated: s.generated,
        mempool_txs: s.mempool_txs,
        mempool_bytes: s.mempool_bytes,
        outputs: s.outputs,
        peers: stats.as_ref().map_or(0, |s| s.peers),
        header_height: s.header_height,
        deepest_reorg: s.deepest_reorg as u64,
        misbehaving_disconnects: stats.as_ref().map_or(0, |s| s.misbehaving_disconnects),
        genesis_id: Some(fingerprint::hex(&s.genesis_id)),
        consensus_fingerprint: Some(fingerprint::hex(&fingerprint::consensus_fingerprint(
            s.network,
        ))),
        rules_fingerprint: Some(fingerprint::hex(&fingerprint::rules_fingerprint(s.network))),
        identity_fingerprint: Some(fingerprint::hex(&fingerprint::identity_fingerprint(
            s.network,
        ))),
        build_commit: Some(fingerprint::BUILD_COMMIT.to_string()),
        version: Some(fingerprint::VERSION.to_string()),
        template_ready: Some(template_ready),
    }
}

/// Whether `/template` would serve a template, as of a published snapshot
/// at the local time `now`: [`ChainManager::template_ready`], and no
/// operator fork unless the policy overrides it (the checks of
/// [`template_refusal`]).
fn summary_template_ready(s: &ChainSummary, mining: MiningPolicy, now: u64) -> bool {
    s.template_ready(now) && (s.operator_fork.is_none() || mining.despite_operator_fork)
}

/// Why `/template` refuses (`503`), or `None` if it serves: the checks run
/// in one chain command, after the catch-up latch is updated at `now`.
/// - **Operator fork** (RTW3-8): a heavier chain is refused only because of
///   the operator's verdicts, so a block mined here extends a chain the
///   network does not follow. Refused unless the operator passed
///   `--mine-despite-operator-fork`.
/// - **Syncing** ([`ChainManager::template_ready`], RTW3-1): a bounded drain
///   is in progress (the mempool is not yet revalidated), or the node has
///   not yet caught up since it started (its blocks would be orphans). Once
///   caught up, a header lead never refuses templates.
///
/// The miner retries after a `503`.
pub fn template_refusal(m: &ChainManager, mining: MiningPolicy, now: u64) -> Option<String> {
    if let Some(f) = m.operator_fork().filter(|_| !mining.despite_operator_fork) {
        return Some(operator_fork_refusal(&f));
    }
    if m.template_ready(now) {
        return None;
    }
    let (h, hh) = (m.height(), m.header_height());
    Some(if m.sync_pending() {
        format!("syncing: height {h}, headers {hh}: connecting downloaded blocks")
    } else {
        let age = now.saturating_sub(m.tip_header().timestamp);
        format!(
            "syncing: height {h}, headers {hh}, tip {age} s old: catching up since the node \
             started; templates are served once the tip is recent and at most {} blocks \
             below the best header (if every miner of the network has stopped, restart with \
             --mine-from-stale-tip)",
            sync_policy::TEMPLATE_SYNC_SLACK
        )
    })
}

/// The `503` body of `/template` during an operator fork (RTW3-8).
fn operator_fork_refusal(f: &OperatorFork) -> String {
    format!(
        "operator fork: a heavier chain (known up to height {}) is refused only because the \
         operator invalidated block {} at height {} (--invalidate-block); a block mined here \
         extends a chain the rest of the network does not follow. Verify the incident through \
         a second channel. --reconsider-block {} returns to the network's chain; \
         --mine-despite-operator-fork mines anyway",
        f.branch_height,
        hex::encode(f.block),
        f.height,
        hex::encode(f.block)
    )
}

/// `/template`: one Query command updates the catch-up latch, checks
/// readiness ([`template_refusal`]) and builds the template and its next
/// RandomX key (one point of the command order); hex encoding follows
/// outside the actor.
async fn template(
    State(App {
        chain: s, mining, ..
    }): State<App>,
) -> Result<Json<rpc::MiningTemplate>, ApiError> {
    let now = now();
    let (t, next) = on_lane(&s, Lane::Query, move |m| {
        m.update_template_latch(now);
        if let Some(why) = template_refusal(m, mining, now) {
            return Err(why);
        }
        let t = m.template();
        let next = m.next_seed_id(t.height, &t.prev_id);
        Ok((t, next))
    })
    .await?
    .map_err(|why| ApiError(StatusCode::SERVICE_UNAVAILABLE, why))?;
    Ok(Json(rpc::MiningTemplate {
        template: rpc::Template {
            height: t.height,
            prev_id: hex::encode(t.prev_id),
            difficulty: t.difficulty,
            seed_id: hex::encode(t.seed_id),
            min_timestamp: t.min_timestamp,
            version: t.version,
            reward: t.reward,
            fees: t.fees,
            txs: t
                .txs
                .into_iter()
                .map(|tx| hex::encode(tx.encode()))
                .collect(),
        },
        next_seed_id: next.map(hex::encode),
    }))
}

#[derive(Deserialize)]
struct TipQuery {
    after: Option<String>,
    wait: Option<u64>,
}

/// How often a held `/tip` request re-reads the published snapshot: a
/// pointer copy under a read lock, so a new tip is answered within this
/// delay without any chain command.
pub const TIP_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn tip_of(s: &ChainSummary, mining: MiningPolicy) -> rpc::Tip {
    rpc::Tip {
        height: s.height,
        tip: hex::encode(s.tip_id),
        header_height: s.header_height,
        template_ready: summary_template_ready(s, mining, now()),
    }
}

/// `/tip` (dossier 09 I1): the connected tip from the published snapshot.
/// With `after=<tip id>` the request is held until the tip differs from it,
/// at most `wait` seconds (clamped to `rpc::MAX_TIP_WAIT_SECS`), then
/// answered with the current tip either way. It never runs a chain command;
/// its admission class (`guard::Class::LongPoll`) bounds how many are held.
async fn tip(
    State(App { mining, .. }): State<App>,
    Extension(summary): Extension<Arc<SummaryCell>>,
    Query(q): Query<TipQuery>,
) -> Result<Json<rpc::Tip>, ApiError> {
    let after = match q.after.as_deref() {
        Some(a) => Some(rpc::parse_hash(a).ok_or_else(|| bad_request("after: 32 bytes of hex"))?),
        None => None,
    };
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(rpc::MAX_TIP_WAIT_SECS));
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let s = summary.load();
        if after != Some(s.tip_id) || tokio::time::Instant::now() >= deadline {
            return Ok(Json(tip_of(&s, mining)));
        }
        drop(s);
        tokio::time::sleep(TIP_POLL_INTERVAL).await;
    }
}

fn rejected(error: String) -> rpc::SubmitResult {
    rpc::SubmitResult {
        accepted: false,
        id: None,
        on_best_chain: None,
        error: Some(error),
    }
}

/// How far below the connected tip the parent of an RPC-submitted block may
/// be (docs/blocks.md §9.2). The local miner builds on the tip; a template a
/// few blocks old is still accepted.
pub const RPC_BLOCK_MAX_DEPTH: u64 = 8;

// Within this depth the block's RandomX seed lies on the connected chain
// (the seed height is at least `seed_lag` below the block), and the parent's
// work is above the P2P low-work threshold (144 blocks below the tip).
const _: () = assert!(RPC_BLOCK_MAX_DEPTH < 64 && RPC_BLOCK_MAX_DEPTH < 144);

/// The RPC admission rule for `/block` (docs/blocks.md §9.2; F07-3, F36-8),
/// checked by one chain command before any proof of work or storage:
/// - the parent is the connected tip or one of its last
///   [`RPC_BLOCK_MAX_DEPTH`] ancestors, and the height follows it;
/// - the block's RandomX seed is the tip's or the next block's, so an RPC
///   client can never make the node build the cache of another seed;
/// - it passes the P2P header gate, `sync_policy::worth_verifying` (one rule
///   for both paths, R16-5), charged the difficulty this node requires at
///   its position, not the one it claims (`LowWork`; only while our best
///   header chain is 144 blocks of work ahead of the connected tip, as
///   during initial sync).
///
/// Stronger than the P2P gate alone: only the local miner legitimately
/// submits here. Blocks of other shapes arrive over P2P, under that gate.
pub fn rpc_block_admissible(m: &ChainManager, header: &BlockHeader) -> Result<(), String> {
    let tip = m.height();
    let mut id = m.tip_id();
    let mut near = false;
    for _ in 0..=RPC_BLOCK_MAX_DEPTH {
        if id == header.prev_id {
            near = true;
            break;
        }
        match m.header(&id) {
            Some(h) if h.height > 0 => id = h.prev_id,
            _ => break,
        }
    }
    let parent = m.header(&header.prev_id);
    if !near || parent.is_none_or(|p| p.height + 1 != header.height) {
        return Err(format!(
            "NotNearTip: the parent must be the tip ({tip}) or one of its last \
             {RPC_BLOCK_MAX_DEPTH} ancestors on the connected chain"
        ));
    }
    let hc = m.headers();
    let seed = hc.seed_id_for(header.prev_id, header.height);
    let next = hc.seed_id_for(m.tip_id(), tip + 1);
    let current = (tip > 0).then(|| hc.seed_id_for(m.tip_header().prev_id, tip));
    if seed != next && Some(seed) != current {
        return Err("StaleSeed: the block's RandomX seed is not the tip's or the next".into());
    }
    // The claimed difficulty is not checked yet (validation comes after the
    // proof of work): the gate counts the required one (RTW1-1 (a)).
    let mut charged = *header;
    charged.difficulty = hc.template_on(header.prev_id).map_or(0, |t| t.difficulty);
    if !worth_verifying(hc, std::slice::from_ref(&charged), false) {
        return Err(
            "LowWork: the block's chain is below the anti-DoS work threshold of our best \
             header chain"
                .into(),
        );
    }
    Ok(())
}

async fn submit_block(
    State(App { chain: s, .. }): State<App>,
    Json(p): Json<rpc::HexPayload>,
) -> Result<Json<rpc::SubmitResult>, ApiError> {
    // Decoding and RandomX are CPU-bound: on a blocking thread, never on an
    // async worker. Block validation (CLSAG, BP+) runs in the chain actor.
    let block = tokio::task::spawn_blocking(move || {
        let bytes = hex::decode(&p.hex).map_err(|_| bad_request("hex"))?;
        Block::decode(&bytes).map_err(|e| bad_request(format!("block: {e:?}")))
    })
    .await
    .map_err(internal)??;
    // One Blocks-lane command: the admission rule, then the PoW job (one
    // former lock hold). Local mining submissions are served above queries
    // and transactions.
    let header = block.header;
    let admitted = on_lane(&s, Lane::Blocks, move |m| {
        rpc_block_admissible(m, &header).map(|()| m.pow_jobs(std::slice::from_ref(&header)))
    })
    .await?;
    let jobs = match admitted {
        Ok(jobs) => jobs,
        Err(gate) => {
            log::info!("block refused at the RPC: {gate}");
            return Ok(Json(rejected(gate)));
        }
    };
    // RandomX outside the actor (the submission below hits the cache).
    if let Some((pow, jobs)) = jobs {
        tokio::task::spawn_blocking(move || pow.compute_parallel(&jobs, 1))
            .await
            .map_err(internal)?;
    }
    // The actor connects in bounded steps (a block that releases many
    // waiting descendants does not stop other commands for all of them)
    // and answers with the final verdict.
    let r = match chain_access::submit_block(&s, block, now(), false).await {
        Some(Some(r)) => r,
        Some(None) => unreachable!("only_if_header_known is false"),
        None => return Err(stopping()),
    };
    let result = (r, s.summary().height);
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
    State(App { chain: s, net, .. }): State<App>,
    Json(p): Json<rpc::HexPayload>,
) -> Result<Json<rpc::SubmitResult>, ApiError> {
    // Decoding a transaction of several MiB is kept off the async workers.
    let tx = tokio::task::spawn_blocking(move || {
        let bytes = hex::decode(&p.hex).map_err(|_| bad_request("hex"))?;
        Transaction::decode(&bytes).map_err(|e| bad_request(format!("transaction: {e:?}")))
    })
    .await
    .map_err(internal)??;
    // With networking, local transactions enter the Dandelion++ stem (docs/p2p.md §8)
    // instead of being broadcast from this node directly.
    let result = match net {
        Some(n) => n.submit_tx(tx).await,
        // Local origination: the recently-expired guard applies (RTW1B-1).
        None => on_lane(&s, Lane::Tx, move |m| m.submit_local_tx(tx))
            .await?
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
    let out = with_chain(&s, move |m| {
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
        out
    })
    .await?;
    Ok(Json(rpc::Blocks { blocks: out }))
}

const _: () = assert!(rpc::HEADER_BYTES == blacksilk_consensus::HEADER_SIZE);

#[derive(Deserialize)]
struct HeadersQuery {
    from: u64,
    count: u64,
}

/// The headers of the connected blocks `from..from + count` (fewer at the
/// connected tip, none above it), oldest first: the answer of `/headers`
/// (docs/blocks.md §9). Exposed for tests: the handler is exactly this.
///
/// Cost: one lookup per header. The connected chain is read from the
/// header chain's height index, except for connected blocks off the best
/// header chain (a heavier header branch whose bodies are missing), which
/// are found by walking back from the connected tip to that branch.
pub fn connected_headers(m: &ChainManager, from: u64, count: u64) -> Vec<BlockHeader> {
    let tip = m.height();
    if count == 0 || from > tip {
        return Vec::new();
    }
    let end = from.saturating_add(count - 1).min(tip);
    let hc = m.headers();
    // Connected blocks above the fork point with the best header chain,
    // newest first (none while the connected tip is on it).
    let mut off_main = Vec::new();
    let mut id = m.tip_id();
    let mut h = tip;
    while !hc.is_on_main(&id) {
        let header = *hc.header(&id).expect("connected blocks have headers");
        if h <= end {
            off_main.push(header);
        }
        if h == from {
            // Every requested header is off the best header chain.
            off_main.reverse();
            return off_main;
        }
        id = header.prev_id;
        h -= 1;
    }
    // Heights `from..=h` are on the best header chain (the genesis always is).
    let mut out: Vec<BlockHeader> = (from..=h.min(end))
        .map(|x| {
            let id = hc.main_id_at(x).expect("below a block on the best chain");
            *hc.header(&id).expect("known header")
        })
        .collect();
    out.extend(off_main.into_iter().rev());
    out
}

/// `/headers`: one Query command copies the headers (100 bytes each, at
/// most `rpc::MAX_HEADERS_PER_REQUEST`); hex encoding follows outside it.
async fn headers(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<HeadersQuery>,
) -> Result<Json<rpc::Headers>, ApiError> {
    if q.count == 0 || q.count > rpc::MAX_HEADERS_PER_REQUEST {
        return Err(bad_request(format!(
            "count must be 1..={}",
            rpc::MAX_HEADERS_PER_REQUEST
        )));
    }
    let (headers, height) = with_chain(&s, move |m| {
        (connected_headers(m, q.from, q.count), m.height())
    })
    .await?;
    let mut bytes = Vec::with_capacity(headers.len() * rpc::HEADER_BYTES);
    for h in &headers {
        bytes.extend_from_slice(&h.to_bytes());
    }
    Ok(Json(rpc::Headers {
        from: q.from,
        headers: hex::encode(bytes),
        height,
    }))
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
    /// page, so the caller may run it as one chain command.
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
    // The command only copies the requested page; hex encoding and
    // serialization happen after it.
    let page = with_chain(&s, move |m| {
        PxPage::take(m.state(), m.height(), q.from, q.limit)
    })
    .await?;
    Ok(Json(page.map_err(bad_request)?.render()))
}

async fn px_contracts(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<FromQuery>,
) -> Result<Json<rpc::PxContracts>, ApiError> {
    with_chain(&s, move |m| px_contracts_page(m, q.from))
        .await
        .map(Json)
}

fn px_contracts_page(m: &ChainManager, from: u64) -> rpc::PxContracts {
    let state = m.state();
    let log = state.px_contract_log();
    let total = log.len() as u64;
    let contracts = log
        .iter()
        .skip(from.min(total) as usize)
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
    rpc::PxContracts {
        from,
        contracts,
        total,
        height: m.height(),
    }
}

#[derive(Deserialize)]
struct TxStatusQuery {
    id: String,
}

/// The `/tx/status` answer for `id` (docs/blocks.md §9): `pooled` if it is
/// in the mempool, `confirmed` with its height if a connected block contains
/// it, else `unknown`.
///
/// Only the chain manager is consulted, never the P2P stempool: a
/// transaction in this node's Dandelion++ stem, its own or relayed, answers
/// `unknown`, exactly like one the node has never seen (F36-11). Reporting
/// it would let anyone who can query the node learn what it originated or
/// stems.
///
/// Cost: a scan of the connected blocks' transaction ids, newest first, in
/// one chain command; `unknown` scans the whole chain (there is no
/// transaction index, docs/blocks.md §8).
pub fn tx_status(m: &ChainManager, id: &Hash) -> rpc::TxStatus {
    if m.mempool().contains(id) {
        return rpc::TxStatus::Pooled;
    }
    let state = m.state();
    (1..=m.height())
        .rev()
        .find(|&h| state.block_tx_hashes(h).is_some_and(|ids| ids.contains(id)))
        .map_or(rpc::TxStatus::Unknown, |height| rpc::TxStatus::Confirmed {
            height,
        })
}

async fn tx_status_route(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<TxStatusQuery>,
) -> Result<Json<rpc::TxStatus>, ApiError> {
    let id = rpc::parse_hash(&q.id).ok_or_else(|| bad_request("id: 32 bytes of hex"))?;
    with_chain(&s, move |m| tx_status(m, &id)).await.map(Json)
}

#[derive(Deserialize)]
struct DistributionQuery {
    to: u64,
}

async fn distribution(
    State(App { chain: s, .. }): State<App>,
    Query(q): Query<DistributionQuery>,
) -> Result<Json<rpc::Distribution>, ApiError> {
    let cumulative = with_chain(&s, move |m| {
        let mut cumulative = m.state().cumulative_outputs();
        cumulative.truncate(q.to.saturating_add(1) as usize);
        cumulative
    })
    .await?;
    Ok(Json(rpc::Distribution { cumulative }))
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
    let out = with_chain(&s, move |m| {
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
        Ok(out)
    })
    .await??;
    Ok(Json(rpc::Outputs { outputs: out }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn fork(block: u8) -> OperatorFork {
        OperatorFork {
            block: [block; 32],
            height: 4,
            branch_tip: [9; 32],
            branch_height: 7,
            excess_work: 3,
        }
    }

    /// RTW3-8: warned at once, repeated every interval while it lasts, again
    /// at once for another verdict, and an all-clear when it ends.
    #[test]
    fn the_operator_fork_warning_repeats_while_the_fork_lasts() {
        let policy = MiningPolicy::default();
        let t0 = std::time::Instant::now();
        let every = Duration::from_secs(600);
        let mut w = ForkWarner::new(every);
        assert_eq!(w.poll(None, policy, t0), None);
        let (warn, msg) = w.poll(Some(fork(1)), policy, t0).unwrap();
        assert!(warn);
        assert!(msg.contains(&hex::encode([1u8; 32])), "{msg}");
        assert!(msg.contains("known up to height 7"), "{msg}");
        assert!(msg.contains("second channel"), "{msg}");
        assert!(msg.contains("--reconsider-block"), "{msg}");
        assert!(msg.contains("refused (--mine-despite-operator-fork overrides)"));
        assert_eq!(w.poll(Some(fork(1)), policy, t0 + every / 2), None);
        assert!(w.poll(Some(fork(1)), policy, t0 + every).unwrap().0);
        assert!(
            w.poll(Some(fork(2)), policy, t0 + every).unwrap().0,
            "another verdict"
        );
        let (warn, msg) = w.poll(None, policy, t0 + every).unwrap();
        assert!(!warn, "{msg}");
        assert_eq!(w.poll(None, policy, t0 + every * 3), None);
        let despite = MiningPolicy {
            despite_operator_fork: true,
        };
        assert!(operator_fork_warning(&fork(1), despite).contains("still served"));
    }

    /// Dossier 04 W4: the start-up clock check refuses an unreadable clock
    /// and one before the genesis, and warns when the stored tip is more
    /// than the future time limit ahead of the clock.
    #[test]
    fn the_start_up_clock_check() {
        let p = ChainParams::testnet();
        let g = p.genesis.timestamp;
        let ftl = p.future_time_limit;
        let e = clock_check(None, &p, g).unwrap_err();
        assert!(e.contains("before 1970"), "{e}");
        let e = clock_check(Some(g - 1), &p, g).unwrap_err();
        assert!(e.contains("before this network's genesis"), "{e}");
        assert_eq!(clock_check(Some(g), &p, g), Ok(None));
        let now = g + 1_000_000;
        assert_eq!(
            clock_check(Some(now), &p, now + ftl),
            Ok(None),
            "at the limit"
        );
        let w = clock_check(Some(now), &p, now + ftl + 1).unwrap().unwrap();
        assert!(w.contains(&format!("{} s ahead", ftl + 1)), "{w}");
        assert!(clock_check(system_clock(), &p, g).is_ok());
    }

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
