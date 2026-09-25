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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Template {
    pub height: u64,
    pub prev_id: String,
    pub difficulty: u64,
    pub seed_id: String,
    pub min_timestamp: u64,
    pub reward: u64,
    pub fees: u64,
    /// Encoded transfers to include after the coinbase, in order.
    pub txs: Vec<String>,
}

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

/// Most PX commitments per `/px/commitments` response.
pub const MAX_PX_COMMITMENTS_PER_REQUEST: u64 = 65_536;

/// PX commitments in tree order (docs/px.md §11.4). Wallets fetch them in
/// bulk, never individually, so the node learns nothing about which records
/// a wallet owns.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PxCommitments {
    /// Tree position of the first entry.
    pub from: u64,
    /// `(height, commitment hex)` in position order.
    pub commitments: Vec<(u64, String)>,
    /// Total commitments on the node's chain.
    pub total: u64,
    /// The node's current tree root (hex).
    pub root: String,
    /// The node's tip height.
    pub height: u64,
}

#[derive(Debug)]
pub enum RpcError {
    Http(String),
    Status(u16, String),
    Decode(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Http(e) => write!(f, "cannot reach node: {e}"),
            RpcError::Status(c, m) => write!(f, "node returned HTTP {c}: {m}"),
            RpcError::Decode(e) => write!(f, "bad response from node: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// Blocking client for the node RPC.
pub struct Client {
    base: String,
    http: reqwest::blocking::Client,
}

impl Client {
    /// `base` is e.g. `http://127.0.0.1:29333`.
    pub fn new(base: &str) -> Self {
        let base = if base.starts_with("http://") || base.starts_with("https://") {
            base.trim_end_matches('/').to_string()
        } else {
            format!("http://{}", base.trim_end_matches('/'))
        };
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("HTTP client");
        Self { base, http }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, RpcError> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .map_err(|e| RpcError::Http(e.to_string()))?;
        Self::parse(resp)
    }

    fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, RpcError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .map_err(|e| RpcError::Http(e.to_string()))?;
        Self::parse(resp)
    }

    fn parse<T: for<'de> Deserialize<'de>>(
        resp: reqwest::blocking::Response,
    ) -> Result<T, RpcError> {
        let status = resp.status();
        let text = resp.text().map_err(|e| RpcError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(RpcError::Status(status.as_u16(), text));
        }
        serde_json::from_str(&text).map_err(|e| RpcError::Decode(e.to_string()))
    }

    pub fn info(&self) -> Result<Info, RpcError> {
        self.get("/info")
    }

    pub fn template(&self) -> Result<Template, RpcError> {
        self.get("/template")
    }

    pub fn submit_block(&self, block: &[u8]) -> Result<SubmitResult, RpcError> {
        self.post(
            "/block",
            &HexPayload {
                hex: hex::encode(block),
            },
        )
    }

    pub fn submit_tx(&self, tx: &[u8]) -> Result<SubmitResult, RpcError> {
        self.post(
            "/tx",
            &HexPayload {
                hex: hex::encode(tx),
            },
        )
    }

    pub fn blocks(&self, from: u64, count: u64) -> Result<Blocks, RpcError> {
        self.get(&format!("/blocks?from={from}&count={count}"))
    }

    pub fn distribution(&self, to: u64) -> Result<Distribution, RpcError> {
        self.get(&format!("/distribution?to={to}"))
    }

    pub fn px_commitments(&self, from: u64) -> Result<PxCommitments, RpcError> {
        self.get(&format!("/px/commitments?from={from}"))
    }

    pub fn px_contracts(&self, from: u64) -> Result<PxContracts, RpcError> {
        self.get(&format!("/px/contracts?from={from}"))
    }

    pub fn outputs(&self, indices: &[u64]) -> Result<Outputs, RpcError> {
        self.post(
            "/outputs",
            &OutputsRequest {
                indices: indices.to_vec(),
            },
        )
    }
}

/// Parses a 32-byte hex id.
pub fn parse_hash(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}
