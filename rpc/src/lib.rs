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

    /// A page of the default size starting at `from`.
    pub fn px_commitments(&self, from: u64) -> Result<PxCommitments, RpcError> {
        self.get(&format!("/px/commitments?from={from}"))
    }

    /// A page of at most `limit` commitments starting at `from`.
    pub fn px_commitments_page(&self, from: u64, limit: u64) -> Result<PxCommitments, RpcError> {
        self.get(&format!("/px/commitments?from={from}&limit={limit}"))
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

const _: () = assert!(
    DEFAULT_PX_COMMITMENTS_PER_REQUEST >= 1
        && DEFAULT_PX_COMMITMENTS_PER_REQUEST <= MAX_PX_COMMITMENTS_PER_REQUEST
);

#[cfg(test)]
mod tests {
    use super::*;

    /// A response without `next` (from a node older than the field) decodes.
    #[test]
    fn px_commitments_without_next_decodes() {
        let json = r#"{"from":0,"commitments":[[1,"ab"]],"total":1,"root":"00","height":3}"#;
        let r: PxCommitments = serde_json::from_str(json).unwrap();
        assert_eq!(r.next, None);
        assert_eq!(r.commitments, vec![(1, "ab".to_string())]);
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
    }
}
