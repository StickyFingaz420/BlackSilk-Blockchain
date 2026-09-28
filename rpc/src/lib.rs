//! Node RPC (docs/blocks.md §9): JSON over HTTP, binary objects as hex.
//!
//! The node implements the server side; the miner and wallet use [`Client`].
//! Everything here is interface, not consensus: the node validates every submitted
//! block and transaction with the consensus crates.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Largest request body the node accepts (a maximum-size block in hex, plus JSON).
/// Largest request body: a hex-encoded block with a full PX budget (the node
/// asserts this covers `blacksilk_chain::block::MAX_BLOCK_BYTES`).
pub const MAX_REQUEST_BYTES: usize = 2 * (1_000_000 + 8 * 1024 * 1024 + 64 * 1024) + 4096;
/// A `/blocks` response stops adding blocks beyond this many hex bytes (at
/// least one block is always returned), so PX-heavy ranges stay bounded.
pub const MAX_BLOCKS_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum blocks per `/blocks` request.
pub const MAX_BLOCKS_PER_REQUEST: u64 = 100;
/// Maximum indices per `/outputs` request.
pub const MAX_OUTPUTS_PER_REQUEST: usize = 1024;
/// Maximum headers per `/headers` request (Bitcoin's `headers` message
/// carries as many).
pub const MAX_HEADERS_PER_REQUEST: u64 = 2_000;
/// Bytes of one encoded block header (`blacksilk_consensus::HEADER_SIZE`,
/// which the node and the wallet assert equal).
pub const HEADER_BYTES: usize = 100;

// ---- authentication (docs/blocks.md §9.1) ----

/// The file in the node's data directory that holds the RPC credential. The
/// node writes a fresh one at every start and removes it at a clean shutdown;
/// clients read it (`Client::with_cookie_file`).
pub const COOKIE_FILE: &str = "rpc.cookie";

/// Environment variable naming a cookie file, for command-line tools run
/// without `--rpc-cookie` (`Client::with_cookie_option`).
pub const COOKIE_ENV: &str = "BLACKSILK_RPC_COOKIE";

/// Length of the credential: 32 random bytes as lowercase hex.
pub const TOKEN_HEX_LEN: usize = 64;

/// Whether `s` has the form of an RPC credential: exactly
/// [`TOKEN_HEX_LEN`] lowercase hex digits.
pub fn is_token(s: &str) -> bool {
    s.len() == TOKEN_HEX_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Reads the credential from a node's cookie file (surrounding whitespace is
/// ignored).
pub fn read_cookie(path: &std::path::Path) -> Result<String, RpcError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        RpcError::Config(format!(
            "RPC cookie {}: {e} (the node writes it to its data directory at start)",
            path.display()
        ))
    })?;
    let token = text.trim();
    if !is_token(token) {
        return Err(RpcError::Config(format!(
            "RPC cookie {}: not a node credential",
            path.display()
        )));
    }
    Ok(token.to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Info {
    pub network: String,
    pub network_id: u32,
    pub height: u64,
    pub tip: String,
    pub difficulty: u64,
    /// Coins generated so far (atomic units, fees excluded).
    pub generated: u64,
    pub mempool_txs: usize,
    pub mempool_bytes: usize,
    pub outputs: u64,
    /// Connected P2P peers.
    #[serde(default)]
    pub peers: usize,
    /// Best known header height (ahead of `height` while syncing).
    #[serde(default)]
    pub header_height: u64,
    /// The deepest reorganization since the node started, in blocks
    /// (docs/reviews/k4-reorg-policy.md).
    #[serde(default)]
    pub deepest_reorg: u64,
    /// Peers disconnected for misbehaviour since the node started.
    #[serde(default)]
    pub misbehaving_disconnects: u64,
    /// The full genesis id (hex). Operators compare it across devices.
    /// Optional so that clients decode nodes that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_id: Option<String>,
    /// The node's consensus fingerprint for its network (hex; see
    /// `blacksilk_node::fingerprint`). Nodes with different fingerprints fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_fingerprint: Option<String>,
    /// The git commit the node was built from, or `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_commit: Option<String>,
    /// The node crate version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether the node serves block templates now (`/template` answers
    /// `503` otherwise; docs/blocks.md §9.4): no bounded drain in progress,
    /// and either the catch-up latch is set (the node has been synced once
    /// this run: a recent tip and a small header gap; a later bodiless header
    /// lead never clears it, RTW3-1) or the node is caught up now. An operator
    /// fork also refuses templates unless overridden. Optional so that
    /// clients decode nodes that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_ready: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Template {
    pub height: u64,
    pub prev_id: String,
    pub difficulty: u64,
    pub seed_id: String,
    pub min_timestamp: u64,
    /// The header version of the block (that of the epoch at `height`). A
    /// node that does not send it serves the first epoch's version, 1.
    #[serde(default = "first_header_version")]
    pub version: u32,
    pub reward: u64,
    pub fees: u64,
    /// Encoded transfers to include after the coinbase, in order.
    pub txs: Vec<String>,
}

fn first_header_version() -> u32 {
    1
}

/// `/template`'s answer: the [`Template`] fields plus `next_seed_id`, the
/// RandomX key blocks switch to after the template's height, announced
/// during the `seed_lag` (64) heights before the switch (Monero's
/// `next_seed_hash`). A miner may build that key's context in advance; the
/// template's own `seed_id` stays the only key its block is hashed with.
/// A client that decodes only [`Template`] ignores the field.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MiningTemplate {
    #[serde(flatten)]
    pub template: Template,
    /// The next key's block id (hex), inside the window only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_seed_id: Option<String>,
}

/// The extra field of a [`MiningTemplate`], decoded apart from the
/// template (a flattened decode would buffer every transaction twice).
#[derive(Deserialize)]
struct NextSeedField {
    #[serde(default)]
    next_seed_id: Option<String>,
}

/// `GET /tip` (docs/blocks.md §9): the node's connected tip, from its
/// published chain snapshot. With `after=<tip id>&wait=<secs>` the node
/// holds the request until its tip differs from `after`, at most
/// [`MAX_TIP_WAIT_SECS`], so a miner learns of a new block at once instead
/// of at its next template refresh (dossier 09 I1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tip {
    pub height: u64,
    /// The connected tip's id (hex).
    pub tip: String,
    pub header_height: u64,
    /// As [`Info::template_ready`].
    pub template_ready: bool,
}

/// The longest a `/tip` long poll is held; a larger `wait` is clamped.
pub const MAX_TIP_WAIT_SECS: u64 = 30;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HexPayload {
    pub hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitResult {
    pub accepted: bool,
    /// Block or transaction id (hex) when accepted.
    pub id: Option<String>,
    /// Block: whether it became part of the best chain.
    pub on_best_chain: Option<bool>,
    pub error: Option<String>,
}

impl SubmitResult {
    /// Whether a transaction was refused only because the node's pool already
    /// holds it (`AlreadyKnown`) or another transaction spending the same inputs
    /// (`Conflict`). Only the owner of the inputs can create either, so for a
    /// wallet resubmitting its own transaction this means "still pending", not
    /// "invalid". The node reports mempool errors by their `Debug` names.
    pub fn already_pooled(&self) -> bool {
        !self.accepted
            && self
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("AlreadyKnown") || e.starts_with("Conflict"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockEntry {
    pub height: u64,
    pub id: String,
    /// Global index of the block's first output.
    pub first_output: u64,
    pub hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blocks {
    pub blocks: Vec<BlockEntry>,
}

/// Headers of connected blocks by height, answering
/// `GET /headers?from=h&count=n` (`1 ≤ n ≤` [`MAX_HEADERS_PER_REQUEST`]):
/// the wallet's header check reads the chain from the genesis with it
/// (docs/blocks.md §9, §10). Like `/blocks` it names only a height range.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Headers {
    /// Height of the first header (the request's `from`).
    pub from: u64,
    /// The headers of blocks `from, from + 1, …` up to the request's count
    /// or the connected tip, [`HEADER_BYTES`] bytes each, concatenated, as
    /// hex. Empty when `from` is above the tip.
    pub headers: String,
    /// The node's connected tip height.
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Distribution {
    /// `cumulative[h]` = outputs in blocks `0..=h`.
    pub cumulative: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputsRequest {
    pub indices: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputEntry {
    pub index: u64,
    pub one_time_key: String,
    pub commitment: String,
    pub height: u64,
    pub coinbase: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outputs {
    pub outputs: Vec<OutputEntry>,
}

/// Most registrations per `/px/contracts` response.
pub const MAX_PX_CONTRACTS_PER_REQUEST: u64 = 1_024;

/// A registered function program: its id (hex) and row budget
/// (`cycles, keys, add, bit, lt, shift, mul, poseidon`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PxProgramEntry {
    pub id: String,
    pub budget: [usize; 8],
}

/// A private-contract registration (docs/px.md §13.4).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PxContractEntry {
    pub height: u64,
    pub id: String,
    pub programs: Vec<PxProgramEntry>,
}

/// Every contract registration, in block order. Wallets download the whole
/// list, never a single contract, so the node learns nothing about which
/// contracts a wallet uses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PxContracts {
    /// Index of the first entry.
    pub from: u64,
    pub contracts: Vec<PxContractEntry>,
    /// Total registrations on the node's chain.
    pub total: u64,
    /// The node's tip height.
    pub height: u64,
}

/// Largest `limit` a `/px/commitments` request may ask for.
pub const MAX_PX_COMMITMENTS_PER_REQUEST: u64 = 4096;

/// Page size of a `/px/commitments` request without `limit`.
pub const DEFAULT_PX_COMMITMENTS_PER_REQUEST: u64 = 1024;

/// A page of PX commitments in tree order (docs/px.md §11.4), answering
/// `GET /px/commitments?from=F&limit=L` (both optional: `from` defaults to 0,
/// `limit` to [`DEFAULT_PX_COMMITMENTS_PER_REQUEST`] and is at most
/// [`MAX_PX_COMMITMENTS_PER_REQUEST`]). Wallets fetch every page in order,
/// never individual commitments, so the node learns nothing about which
/// records a wallet owns.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PxCommitments {
    /// Tree position of the first entry (the request's `from`, echoed even
    /// when it is past the end and the page is empty).
    pub from: u64,
    /// `(height, commitment hex)` in position order.
    pub commitments: Vec<(u64, String)>,
    /// Total commitments on the node's chain.
    pub total: u64,
    /// The node's current tree root (hex).
    pub root: String,
    /// The node's tip height.
    pub height: u64,
    /// The `from` of the next page, or `None` when this page reaches `total`.
    /// Absent in responses of nodes older than this field.
    #[serde(default)]
    pub next: Option<u64>,
}

// ---- response-size caps (client side) ----
//
// A node must not be able to exhaust the memory of a wallet or miner by
// sending an endless or huge body. Every response is read up to a cap chosen
// per endpoint, above the largest response an honest node sends (derived from
// the node's own limits above; `tests::caps_cover_the_largest_honest_responses`);
// a larger body is refused before it is parsed.

/// `/info`, `/tx`, `/block` and error bodies: a few hundred bytes in practice.
pub const MAX_SMALL_RESPONSE_BYTES: usize = 64 * 1024;
/// `/template`: its transactions fit in one block, whose hex fits in a request.
pub const MAX_TEMPLATE_RESPONSE_BYTES: usize = MAX_REQUEST_BYTES + 64 * 1024;
/// `/blocks`: the node stops adding blocks at `MAX_BLOCKS_RESPONSE_BYTES` of hex
/// (a single block is far below it), plus JSON framing for at most
/// `MAX_BLOCKS_PER_REQUEST` entries.
pub const MAX_BLOCKS_RESPONSE_LIMIT: usize = MAX_BLOCKS_RESPONSE_BYTES + 1024 * 1024;
/// `/px/commitments`: at most `MAX_PX_COMMITMENTS_PER_REQUEST` entries of under
/// 96 bytes (a height and 64 hex digits), with a 2x margin.
pub const MAX_PX_COMMITMENTS_RESPONSE_BYTES: usize =
    MAX_PX_COMMITMENTS_PER_REQUEST as usize * PX_COMMITMENT_ENTRY_RESPONSE_BYTES + 64 * 1024;
/// One `/px/commitments` entry, with a 2x margin.
pub const PX_COMMITMENT_ENTRY_RESPONSE_BYTES: usize = 192;

/// A page of at most `limit` entries (the node clamps `limit` to
/// `MAX_PX_COMMITMENTS_PER_REQUEST`; a larger page is refused either way).
fn px_commitments_cap(limit: u64) -> usize {
    limit.clamp(1, MAX_PX_COMMITMENTS_PER_REQUEST) as usize * PX_COMMITMENT_ENTRY_RESPONSE_BYTES
        + 64 * 1024
}
/// `/px/contracts`: at most `MAX_PX_CONTRACTS_PER_REQUEST` registrations of at
/// most 16 programs (`tx::params::MAX_DEPLOY_PROGRAMS`) of under 320 bytes
/// each, with a 2x margin.
pub const MAX_PX_CONTRACTS_RESPONSE_BYTES: usize =
    MAX_PX_CONTRACTS_PER_REQUEST as usize * (16 * 640 + 256) + 64 * 1024;
/// `/headers`: at most `MAX_HEADERS_PER_REQUEST` headers in hex, plus framing.
pub const MAX_HEADERS_RESPONSE_BYTES: usize =
    2 * MAX_HEADERS_PER_REQUEST as usize * HEADER_BYTES + 64 * 1024;
/// `/outputs`: one entry of about 250 bytes per requested index, with a 4x margin.
pub const OUTPUT_ENTRY_RESPONSE_BYTES: usize = 1024;
/// `/distribution?to=h`: `h + 1` numbers of at most 20 digits and a comma.
pub const DISTRIBUTION_ENTRY_RESPONSE_BYTES: usize = 32;

// The node's own hex budget plus framing for every entry; a template's
// transactions fit in a block, whose hex fits in a request.
const _: () = {
    assert!(
        MAX_BLOCKS_RESPONSE_LIMIT
            >= MAX_BLOCKS_RESPONSE_BYTES + MAX_BLOCKS_PER_REQUEST as usize * 256
    );
    assert!(MAX_TEMPLATE_RESPONSE_BYTES > MAX_REQUEST_BYTES);
};

fn distribution_cap(to: u64) -> usize {
    usize::try_from(to)
        .unwrap_or(usize::MAX)
        .saturating_add(2)
        .saturating_mul(DISTRIBUTION_ENTRY_RESPONSE_BYTES)
        .saturating_add(MAX_SMALL_RESPONSE_BYTES)
}

fn outputs_cap(n: usize) -> usize {
    n.saturating_mul(OUTPUT_ENTRY_RESPONSE_BYTES)
        .saturating_add(MAX_SMALL_RESPONSE_BYTES)
}

/// `GET /tx/status` (docs/blocks.md §9): `{"status":"pooled"}`,
/// `{"status":"confirmed","height":h}` or `{"status":"unknown"}`. A
/// transaction in the node's Dandelion++ stem is `unknown` (the stem state
/// is never reported).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum TxStatus {
    /// In the node's mempool.
    Pooled,
    /// In the connected block at `height`.
    Confirmed { height: u64 },
    /// Neither (or only in the stem).
    Unknown,
}

#[derive(Debug)]
pub enum RpcError {
    Http(String),
    Status(u16, String),
    Decode(String),
    /// The response body exceeded the cap for its endpoint.
    TooLarge {
        limit: usize,
    },
    /// The node address cannot be used (for example `https://`).
    Config(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Http(e) => write!(f, "cannot reach node: {e}"),
            RpcError::Status(c, m) => write!(f, "node returned HTTP {c}: {m}"),
            RpcError::Decode(e) => write!(f, "bad response from node: {e}"),
            RpcError::TooLarge { limit } => write!(
                f,
                "bad response from node: the body exceeds the {limit}-byte limit for this request"
            ),
            RpcError::Config(e) => write!(f, "node address: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// Normalizes a node address to `http://host:port` (no trailing slash).
///
/// Only plain HTTP is supported: no TLS stack is compiled in, so an
/// `https://` address is refused here, rather than failing later with an
/// obscure transport error or being mistaken for an encrypted connection.
fn normalize_base(base: &str) -> Result<String, RpcError> {
    let base = base.trim();
    let host = |s: &str| {
        let s = s.trim_end_matches('/');
        if s.is_empty() {
            Err(RpcError::Config("empty node address".into()))
        } else {
            Ok(format!("http://{s}"))
        }
    };
    match base.split_once("://") {
        None => host(base),
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => host(rest),
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => Err(RpcError::Config(
            "https:// is not supported: this client speaks plain HTTP only (no TLS). \
             Use your own node on this machine, or reach a remote node over an SSH \
             tunnel, a VPN or Tor, and give its http:// address"
                .into(),
        )),
        Some((scheme, _)) => Err(RpcError::Config(format!(
            "unsupported address {scheme:?}://...: use host:port or http://host:port"
        ))),
    }
}

/// Blocking client for the node RPC.
///
/// - **Plain HTTP only.** `https://` addresses are refused (`try_new`).
/// - **No implicit proxies.** Proxy environment variables (`HTTP_PROXY`,
///   `ALL_PROXY`, ...) are ignored, so traffic never silently goes through a
///   third party. To use Tor or a proxy, run a local forwarder and give its
///   address.
/// - **No redirects.** A node cannot send the client to another host.
/// - **Bounded responses.** Every body is read up to a per-endpoint cap
///   (the `MAX_*_RESPONSE_*` constants).
/// - **Authentication.** A node started by `blacksilk-node` requires its
///   credential on every request ([`Client::with_cookie_file`],
///   [`Client::with_token`]); it is sent as `Authorization: Bearer`.
pub struct Client {
    base: String,
    http: reqwest::blocking::Client,
    /// Set when the address was refused: every request fails with this.
    refused: Option<String>,
    /// The `Authorization` header value, when a credential is set.
    auth: Option<String>,
}

fn http_client() -> Result<reqwest::blocking::Client, RpcError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| RpcError::Config(e.to_string()))
}

impl Client {
    /// `base` is `host:port` or `http://host:port`. Refuses `https://` and
    /// other schemes.
    pub fn try_new(base: &str) -> Result<Self, RpcError> {
        Ok(Self {
            base: normalize_base(base)?,
            http: http_client()?,
            refused: None,
            auth: None,
        })
    }

    /// Sends `token` (a node credential, see [`is_token`]) with every request.
    pub fn with_token(mut self, token: &str) -> Result<Self, RpcError> {
        let token = token.trim();
        if !is_token(token) {
            return Err(RpcError::Config("not a node RPC credential".into()));
        }
        self.auth = Some(format!("Bearer {token}"));
        Ok(self)
    }

    /// Sends the credential read from the node's cookie file
    /// (`<data dir>/rpc.cookie`, see [`COOKIE_FILE`]) with every request.
    pub fn with_cookie_file(self, path: &std::path::Path) -> Result<Self, RpcError> {
        let token = read_cookie(path)?;
        self.with_token(&token)
    }

    /// For command-line tools: the cookie file given (`--rpc-cookie`), else
    /// the one named by the [`COOKIE_ENV`] environment variable, else none.
    pub fn with_cookie_option(self, path: Option<&std::path::Path>) -> Result<Self, RpcError> {
        match path {
            Some(p) => self.with_cookie_file(p),
            None => match std::env::var_os(COOKIE_ENV) {
                Some(p) if !p.is_empty() => self.with_cookie_file(std::path::Path::new(&p)),
                _ => Ok(self),
            },
        }
    }

    /// Like `try_new`, but an unusable address gives a client whose every
    /// request fails with the reason, without touching the network (for
    /// callers that report errors per request).
    pub fn new(base: &str) -> Self {
        match Self::try_new(base) {
            Ok(c) => c,
            Err(e) => Self {
                base: String::new(),
                http: http_client().expect("HTTP client without TLS"),
                refused: Some(e.to_string()),
                auth: None,
            },
        }
    }

    fn check(&self) -> Result<(), RpcError> {
        match &self.refused {
            Some(e) => Err(RpcError::Config(e.clone())),
            None => Ok(()),
        }
    }

    fn authorized(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match &self.auth {
            Some(v) => req.header(reqwest::header::AUTHORIZATION, v),
            None => req,
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str, cap: usize) -> Result<T, RpcError> {
        self.check()?;
        let resp = self
            .authorized(self.http.get(format!("{}{path}", self.base)))
            .send()
            .map_err(|e| RpcError::Http(e.to_string()))?;
        Self::parse(resp, cap)
    }

    fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        cap: usize,
    ) -> Result<T, RpcError> {
        self.check()?;
        let resp = self
            .authorized(self.http.post(format!("{}{path}", self.base)))
            .json(body)
            .send()
            .map_err(|e| RpcError::Http(e.to_string()))?;
        Self::parse(resp, cap)
    }

    /// Reads at most `cap` bytes of body; a longer one is an error.
    fn read_capped(mut resp: reqwest::blocking::Response, cap: usize) -> Result<Vec<u8>, RpcError> {
        use std::io::Read;
        if resp.content_length().is_some_and(|n| n > cap as u64) {
            return Err(RpcError::TooLarge { limit: cap });
        }
        let mut body = Vec::new();
        (&mut resp)
            .take(cap as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| RpcError::Http(e.to_string()))?;
        if body.len() > cap {
            return Err(RpcError::TooLarge { limit: cap });
        }
        Ok(body)
    }

    fn parse<T: for<'de> Deserialize<'de>>(
        resp: reqwest::blocking::Response,
        cap: usize,
    ) -> Result<T, RpcError> {
        let body = Self::body(resp, cap)?;
        serde_json::from_slice(&body).map_err(|e| RpcError::Decode(e.to_string()))
    }

    /// The body of a successful response, at most `cap` bytes; an error
    /// status is returned with its (capped) body.
    fn body(resp: reqwest::blocking::Response, cap: usize) -> Result<Vec<u8>, RpcError> {
        let status = resp.status();
        if !status.is_success() {
            let body = Self::read_capped(resp, MAX_SMALL_RESPONSE_BYTES)?;
            return Err(RpcError::Status(
                status.as_u16(),
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        Self::read_capped(resp, cap)
    }

    pub fn info(&self) -> Result<Info, RpcError> {
        self.get("/info", MAX_SMALL_RESPONSE_BYTES)
    }

    /// The block template. A node that is syncing answers `503`
    /// (`RpcError::Status(503, "syncing: ...")`): retry later.
    pub fn template(&self) -> Result<Template, RpcError> {
        self.get("/template", MAX_TEMPLATE_RESPONSE_BYTES)
    }

    /// The block template with the next RandomX key ([`MiningTemplate`]).
    pub fn mining_template(&self) -> Result<MiningTemplate, RpcError> {
        self.check()?;
        let resp = self
            .authorized(self.http.get(format!("{}/template", self.base)))
            .send()
            .map_err(|e| RpcError::Http(e.to_string()))?;
        let body = Self::body(resp, MAX_TEMPLATE_RESPONSE_BYTES)?;
        let template: Template =
            serde_json::from_slice(&body).map_err(|e| RpcError::Decode(e.to_string()))?;
        let next: NextSeedField =
            serde_json::from_slice(&body).map_err(|e| RpcError::Decode(e.to_string()))?;
        Ok(MiningTemplate {
            template,
            next_seed_id: next.next_seed_id,
        })
    }

    /// The node's connected tip (`GET /tip`). With `after`, the node answers
    /// once its tip differs from `after`, or after `wait_secs` (at most
    /// [`MAX_TIP_WAIT_SECS`]) with the unchanged tip.
    pub fn tip(&self, after: Option<&[u8; 32]>, wait_secs: u64) -> Result<Tip, RpcError> {
        let path = match after {
            Some(id) => format!(
                "/tip?after={}&wait={}",
                hex::encode(id),
                wait_secs.min(MAX_TIP_WAIT_SECS)
            ),
            None => "/tip".to_string(),
        };
        self.get(&path, MAX_SMALL_RESPONSE_BYTES)
    }

    pub fn submit_block(&self, block: &[u8]) -> Result<SubmitResult, RpcError> {
        self.post(
            "/block",
            &HexPayload {
                hex: hex::encode(block),
            },
            MAX_SMALL_RESPONSE_BYTES,
        )
    }

    pub fn submit_tx(&self, tx: &[u8]) -> Result<SubmitResult, RpcError> {
        self.post(
            "/tx",
            &HexPayload {
                hex: hex::encode(tx),
            },
            MAX_SMALL_RESPONSE_BYTES,
        )
    }

    pub fn blocks(&self, from: u64, count: u64) -> Result<Blocks, RpcError> {
        self.get(
            &format!("/blocks?from={from}&count={count}"),
            MAX_BLOCKS_RESPONSE_LIMIT,
        )
    }

    /// The headers of connected blocks `from..from + count` (fewer at the
    /// tip; `count` at most [`MAX_HEADERS_PER_REQUEST`]).
    pub fn headers(&self, from: u64, count: u64) -> Result<Headers, RpcError> {
        self.get(
            &format!("/headers?from={from}&count={count}"),
            MAX_HEADERS_RESPONSE_BYTES,
        )
    }

    pub fn distribution(&self, to: u64) -> Result<Distribution, RpcError> {
        self.get(&format!("/distribution?to={to}"), distribution_cap(to))
    }

    /// A page of the default size starting at `from`.
    pub fn px_commitments(&self, from: u64) -> Result<PxCommitments, RpcError> {
        self.get(
            &format!("/px/commitments?from={from}"),
            MAX_PX_COMMITMENTS_RESPONSE_BYTES,
        )
    }

    /// A page of at most `limit` commitments starting at `from`.
    pub fn px_commitments_page(&self, from: u64, limit: u64) -> Result<PxCommitments, RpcError> {
        self.get(
            &format!("/px/commitments?from={from}&limit={limit}"),
            px_commitments_cap(limit),
        )
    }

    pub fn px_contracts(&self, from: u64) -> Result<PxContracts, RpcError> {
        self.get(
            &format!("/px/contracts?from={from}"),
            MAX_PX_CONTRACTS_RESPONSE_BYTES,
        )
    }

    /// Whether the node has transaction `id` in its mempool or a connected
    /// block (`GET /tx/status`, docs/blocks.md §9).
    pub fn tx_status(&self, id: &[u8; 32]) -> Result<TxStatus, RpcError> {
        self.get(
            &format!("/tx/status?id={}", hex::encode(id)),
            MAX_SMALL_RESPONSE_BYTES,
        )
    }

    pub fn outputs(&self, indices: &[u64]) -> Result<Outputs, RpcError> {
        self.post(
            "/outputs",
            &OutputsRequest {
                indices: indices.to_vec(),
            },
            outputs_cap(indices.len()),
        )
    }
}

/// Parses a 32-byte hex id.
pub fn parse_hash(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

const _: () = assert!(
    DEFAULT_PX_COMMITMENTS_PER_REQUEST >= 1
        && DEFAULT_PX_COMMITMENTS_PER_REQUEST <= MAX_PX_COMMITMENTS_PER_REQUEST
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A response without `next` (from a node older than the field) decodes.
    #[test]
    fn px_commitments_without_next_decodes() {
        let json = r#"{"from":0,"commitments":[[1,"ab"]],"total":1,"root":"00","height":3}"#;
        let r: PxCommitments = serde_json::from_str(json).unwrap();
        assert_eq!(r.next, None);
        assert_eq!(r.commitments, vec![(1, "ab".to_string())]);
    }

    /// Serves one connection: reads the request head, then writes `head`
    /// followed by `body_len` bytes of `b'x'`, then closes.
    fn serve_once(head: String, body_len: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
            }
            if s.write_all(head.as_bytes()).is_err() {
                return;
            }
            let chunk = vec![b'x'; 64 * 1024];
            let mut left = body_len;
            while left > 0 {
                let n = left.min(chunk.len());
                // The client hangs up once it has seen enough.
                if s.write_all(&chunk[..n]).is_err() {
                    return;
                }
                left -= n;
            }
        });
        addr
    }

    #[test]
    fn https_and_unknown_schemes_are_refused() {
        for bad in [
            "https://node.example:29333",
            "HTTPS://x",
            "ftp://x",
            "",
            "http://",
        ] {
            assert!(
                matches!(Client::try_new(bad), Err(RpcError::Config(_))),
                "{bad:?}"
            );
        }
        let e = Client::try_new("https://node.example").err().unwrap();
        assert!(e.to_string().contains("plain HTTP only"), "{e}");
        // `new` never panics: the client refuses every request with the
        // reason, without touching the network.
        let c = Client::new("https://node.example:29333");
        assert!(matches!(c.info(), Err(RpcError::Config(m)) if m.contains("https")));
        for ok in [
            "127.0.0.1:29333",
            "http://127.0.0.1:29333/",
            "HTTP://localhost:1",
        ] {
            assert!(Client::try_new(ok).is_ok(), "{ok:?}");
        }
        assert_eq!(
            normalize_base("127.0.0.1:1/").unwrap(),
            "http://127.0.0.1:1"
        );
    }

    #[test]
    fn an_oversized_body_with_a_length_is_refused_before_reading() {
        let len = MAX_SMALL_RESPONSE_BYTES + 1;
        let addr = serve_once(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"),
            len,
        );
        let c = Client::try_new(&addr).unwrap();
        assert!(matches!(
            c.info(),
            Err(RpcError::TooLarge {
                limit: MAX_SMALL_RESPONSE_BYTES
            })
        ));
    }

    #[test]
    fn an_endless_body_without_a_length_is_cut_at_the_cap() {
        // No Content-Length: the body runs until the connection closes, far
        // beyond the cap. The client stops reading at the cap.
        let addr = serve_once(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string(),
            64 * 1024 * 1024,
        );
        let c = Client::try_new(&addr).unwrap();
        assert!(matches!(
            c.info(),
            Err(RpcError::TooLarge {
                limit: MAX_SMALL_RESPONSE_BYTES
            })
        ));
    }

    #[test]
    fn error_bodies_are_capped_too() {
        let len = 10 * 1024 * 1024;
        let addr = serve_once(
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
            ),
            len,
        );
        let c = Client::try_new(&addr).unwrap();
        assert!(matches!(c.info(), Err(RpcError::TooLarge { .. })));
    }

    #[test]
    fn a_body_within_the_cap_is_parsed_and_redirects_are_not_followed() {
        let body = r#"{"cumulative":[1,2,3]}"#;
        let addr = serve_once(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            0,
        );
        let c = Client::try_new(&addr).unwrap();
        assert_eq!(c.distribution(2).unwrap().cumulative, vec![1, 2, 3]);
        // A redirect is reported as a status, never followed to another host.
        let addr = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1:9/info\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
            0,
        );
        let c = Client::try_new(&addr).unwrap();
        assert!(matches!(c.info(), Err(RpcError::Status(302, _))));
    }

    /// Answers one request with an empty 401 and returns its head.
    fn capture_head() -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let _ = s.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            String::from_utf8_lossy(&req).to_ascii_lowercase()
        });
        (addr, h)
    }

    #[test]
    fn the_credential_is_sent_as_a_bearer_token() {
        let token = "0123456789abcdef".repeat(4);
        let (addr, h) = capture_head();
        let c = Client::try_new(&addr).unwrap().with_token(&token).unwrap();
        assert!(matches!(c.info(), Err(RpcError::Status(401, _))));
        assert!(h
            .join()
            .unwrap()
            .contains(&format!("authorization: bearer {token}\r\n")));
        let (addr, h) = capture_head();
        let _ = Client::try_new(&addr).unwrap().info();
        assert!(!h.join().unwrap().contains("authorization"));
        for bad in [
            "",
            "abc",
            &token.to_uppercase(),
            &token[1..],
            &format!("{token}0"),
        ] {
            assert!(
                Client::try_new(&addr).unwrap().with_token(bad).is_err(),
                "{bad:?}"
            );
        }
    }

    /// The `/tx/status` wire form (docs/blocks.md §9).
    #[test]
    fn tx_status_json() {
        let cases = [
            (TxStatus::Pooled, r#"{"status":"pooled"}"#),
            (
                TxStatus::Confirmed { height: 7 },
                r#"{"status":"confirmed","height":7}"#,
            ),
            (TxStatus::Unknown, r#"{"status":"unknown"}"#),
        ];
        for (s, json) in cases {
            assert_eq!(serde_json::to_string(&s).unwrap(), json);
            assert_eq!(serde_json::from_str::<TxStatus>(json).unwrap(), s);
        }
        assert!(serde_json::from_str::<TxStatus>(r#"{"status":"stem"}"#).is_err());
    }

    #[test]
    fn a_cookie_file_is_read_and_checked() {
        let dir = std::env::temp_dir().join(format!("bs-rpc-cookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(COOKIE_FILE);
        let token = "a".repeat(TOKEN_HEX_LEN);
        std::fs::write(&path, format!("{token}\n")).unwrap();
        assert_eq!(read_cookie(&path).unwrap(), token);
        assert!(Client::try_new("127.0.0.1:1")
            .unwrap()
            .with_cookie_option(Some(&path))
            .is_ok());
        std::fs::write(&path, "not a token").unwrap();
        assert!(matches!(read_cookie(&path), Err(RpcError::Config(_))));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(read_cookie(&path), Err(RpcError::Config(_))));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn caps_cover_the_largest_honest_responses() {
        // A full /distribution for ten million blocks, each count at its widest.
        let entry = format!("{},", u64::MAX);
        assert!(entry.len() <= DISTRIBUTION_ENTRY_RESPONSE_BYTES);
        assert!(distribution_cap(10_000_000) > 10_000_001 * entry.len());
        // A full /outputs entry.
        let e = OutputEntry {
            index: u64::MAX,
            one_time_key: "f".repeat(64),
            commitment: "f".repeat(64),
            height: u64::MAX,
            coinbase: false,
        };
        assert!(4 * serde_json::to_vec(&e).unwrap().len() <= OUTPUT_ENTRY_RESPONSE_BYTES);
        // A full /px/commitments page.
        let page = PxCommitments {
            from: u64::MAX,
            commitments: vec![(u64::MAX, "f".repeat(64)); MAX_PX_COMMITMENTS_PER_REQUEST as usize],
            total: u64::MAX,
            root: "f".repeat(64),
            height: u64::MAX,
            next: Some(u64::MAX),
        };
        assert!(2 * serde_json::to_vec(&page).unwrap().len() <= MAX_PX_COMMITMENTS_RESPONSE_BYTES);
        assert_eq!(
            px_commitments_cap(u64::MAX),
            MAX_PX_COMMITMENTS_RESPONSE_BYTES
        );
        let small = PxCommitments {
            commitments: vec![(u64::MAX, "f".repeat(64)); 16],
            ..page
        };
        assert!(2 * serde_json::to_vec(&small).unwrap().len() <= px_commitments_cap(16));
        // A full /px/contracts page: 16 programs per contract.
        let program = PxProgramEntry {
            id: "f".repeat(64),
            budget: [usize::MAX; 8],
        };
        let page = PxContracts {
            from: u64::MAX,
            contracts: vec![
                PxContractEntry {
                    height: u64::MAX,
                    id: "f".repeat(64),
                    programs: vec![program; 16],
                };
                MAX_PX_CONTRACTS_PER_REQUEST as usize
            ],
            total: u64::MAX,
            height: u64::MAX,
        };
        assert!(2 * serde_json::to_vec(&page).unwrap().len() <= MAX_PX_CONTRACTS_RESPONSE_BYTES);
        // A full /headers page.
        let headers = Headers {
            from: u64::MAX,
            headers: "f".repeat(2 * HEADER_BYTES * MAX_HEADERS_PER_REQUEST as usize),
            height: u64::MAX,
        };
        assert!(serde_json::to_vec(&headers).unwrap().len() + 1024 <= MAX_HEADERS_RESPONSE_BYTES);
        // /blocks and /template: checked at compile time (next to the caps).
    }

    /// `/info` from a node older than the identity fields decodes, and the
    /// fields round-trip when present.
    #[test]
    fn info_identity_fields_are_optional() {
        let old = r#"{"network":"testnet","network_id":1,"height":2,"tip":"00","difficulty":3,
            "generated":4,"mempool_txs":0,"mempool_bytes":0,"outputs":5}"#;
        let i: Info = serde_json::from_str(old).unwrap();
        assert_eq!(i.genesis_id, None);
        assert_eq!(i.consensus_fingerprint, None);
        assert_eq!(i.build_commit, None);
        assert_eq!(i.version, None);
        // Absent fields are not serialized as null.
        assert!(!serde_json::to_string(&i).unwrap().contains("genesis_id"));

        let new = Info {
            genesis_id: Some("aa".into()),
            consensus_fingerprint: Some("bb".into()),
            build_commit: Some("cc".into()),
            version: Some("0.1.0".into()),
            ..i
        };
        let back: Info = serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
        assert_eq!(back, new);
        assert_eq!(i.template_ready, None, "a node older than the field");
    }

    fn template() -> Template {
        Template {
            height: 2049,
            prev_id: "aa".repeat(32),
            difficulty: 5,
            seed_id: "00".repeat(32),
            min_timestamp: 7,
            version: 2,
            reward: 9,
            fees: 1,
            txs: vec!["abcd".into()],
        }
    }

    /// `/template` with `next_seed_id` still decodes as a [`Template`] (an
    /// older miner), and the field is left out outside the window.
    #[test]
    fn the_next_seed_id_extends_the_template_compatibly() {
        let with = MiningTemplate {
            template: template(),
            next_seed_id: Some("bb".repeat(32)),
        };
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.contains("\"next_seed_id\""), "{json}");
        let old: Template = serde_json::from_str(&json).unwrap();
        assert_eq!(old, template());
        let next: NextSeedField = serde_json::from_str(&json).unwrap();
        assert_eq!(next.next_seed_id, with.next_seed_id);
        let without = MiningTemplate {
            next_seed_id: None,
            ..with
        };
        let json = serde_json::to_string(&without).unwrap();
        assert!(!json.contains("next_seed_id"), "{json}");
        let next: NextSeedField = serde_json::from_str(&json).unwrap();
        assert_eq!(next.next_seed_id, None);
    }

    /// The miner's template request: both parts decoded from one body.
    #[test]
    fn a_mining_template_is_read_from_one_response() {
        let with = MiningTemplate {
            template: template(),
            next_seed_id: Some("cc".repeat(32)),
        };
        let body = serde_json::to_string(&with).unwrap();
        let (head, served) = capture_response(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        let got = Client::new(&head).mining_template().unwrap();
        assert_eq!(got, with);
        assert!(served.join().unwrap().starts_with("GET /template "));
    }

    /// `/tip` requests: a long poll names the tip and a clamped wait.
    #[test]
    fn a_tip_long_poll_names_the_tip_and_a_clamped_wait() {
        let tip = Tip {
            height: 3,
            tip: "dd".repeat(32),
            header_height: 4,
            template_ready: true,
        };
        let body = serde_json::to_string(&tip).unwrap();
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (addr, served) = capture_response(reply.clone());
        assert_eq!(Client::new(&addr).tip(Some(&[0xab; 32]), 999).unwrap(), tip);
        let head = served.join().unwrap();
        let expected = format!(
            "GET /tip?after={}&wait={MAX_TIP_WAIT_SECS} ",
            "ab".repeat(32)
        );
        assert!(head.starts_with(&expected), "{head}");
        let (addr, served) = capture_response(reply);
        Client::new(&addr).tip(None, 5).unwrap();
        assert!(served.join().unwrap().starts_with("GET /tip "));
    }

    /// Serves `reply` to one request; the thread returns the request head.
    fn capture_response(reply: String) -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            s.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });
        (addr, t)
    }
}
