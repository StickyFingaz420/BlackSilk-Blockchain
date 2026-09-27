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
pub struct Client {
    base: String,
    http: reqwest::blocking::Client,
    /// Set when the address was refused: every request fails with this.
    refused: Option<String>,
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
        })
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
            },
        }
    }

    fn check(&self) -> Result<(), RpcError> {
        match &self.refused {
            Some(e) => Err(RpcError::Config(e.clone())),
            None => Ok(()),
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str, cap: usize) -> Result<T, RpcError> {
        self.check()?;
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
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
            .http
            .post(format!("{}{path}", self.base))
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
        let status = resp.status();
        if !status.is_success() {
            let body = Self::read_capped(resp, MAX_SMALL_RESPONSE_BYTES)?;
            return Err(RpcError::Status(
                status.as_u16(),
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        let body = Self::read_capped(resp, cap)?;
        serde_json::from_slice(&body).map_err(|e| RpcError::Decode(e.to_string()))
    }

    pub fn info(&self) -> Result<Info, RpcError> {
        self.get("/info", MAX_SMALL_RESPONSE_BYTES)
    }

    pub fn template(&self) -> Result<Template, RpcError> {
        self.get("/template", MAX_TEMPLATE_RESPONSE_BYTES)
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
    }
}
