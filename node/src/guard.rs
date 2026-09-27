//! The request guard in front of every RPC route (docs/blocks.md §9.1).
//!
//! It runs before routing, so it also covers routes added later and unknown
//! paths. In order:
//!
//! 1. **Host allowlist** (DNS rebinding): the `Host` header, and the authority
//!    of an absolute-form request target, must name loopback (`localhost`,
//!    `127.0.0.0/8`, `[::1]`), the exact address the RPC is bound to (a
//!    non-loopback bind), or a name the operator allowed. A rebinding page
//!    always sends its own host name, so it is refused. `0.0.0.0`, `[::]` and
//!    every other name or address are refused.
//! 2. **Browser requests are refused**: any `Origin` or `Sec-Fetch-*` header.
//!    Browsers send at least one of them on requests to loopback; the node's
//!    clients (the miner, the wallet, curl) send none. This also stops
//!    cross-site no-cors GETs, which need no rebinding (F36-2).
//! 3. **Authentication** when the router has a credential: exactly one
//!    `Authorization: Bearer <cookie>`, compared in constant time; a failure
//!    is answered after a fixed delay.
//! 4. **Content type and body size**: a POST must be `application/json` and
//!    its body is read here, up to the route's limit and within a deadline;
//!    other methods carry no body.
//! 5. **Admission**: each class of routes has a fixed number of slots
//!    ([`Limits`]); a request that finds its class full is answered `503`
//!    at once, instead of queueing a blocking thread on the chain lock.
//!
//! Everything here is policy, not consensus.

use crate::cookie::Token;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Largest `/tx` body: the largest transaction of any kind, hex-encoded,
/// plus JSON framing.
pub const MAX_TX_BODY_BYTES: usize = 2 * max_tx_bytes() + 4096;
/// Largest `/outputs` body: the most indices, each at most 20 digits and a
/// comma, plus JSON framing.
pub const MAX_OUTPUTS_BODY_BYTES: usize = blacksilk_rpc::MAX_OUTPUTS_PER_REQUEST * 21 + 1024;
/// Largest `/block` body: a maximum-size block, hex-encoded
/// (`blacksilk_rpc::MAX_REQUEST_BYTES`).
pub const MAX_BLOCK_BODY_BYTES: usize = blacksilk_rpc::MAX_REQUEST_BYTES;

const fn max_tx_bytes() -> usize {
    use blacksilk_tx::params::{MAX_DEPLOY_TX_SIZE, MAX_PX_TX_SIZE, MAX_TX_SIZE};
    let mut m = MAX_TX_SIZE;
    if MAX_PX_TX_SIZE > m {
        m = MAX_PX_TX_SIZE;
    }
    if MAX_DEPLOY_TX_SIZE > m {
        m = MAX_DEPLOY_TX_SIZE;
    }
    m
}

const _: () = assert!(MAX_TX_BODY_BYTES < MAX_BLOCK_BODY_BYTES);

/// Admission classes: routes of one class share its slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// `/info`, `/distribution`, `/outputs`, `/px/*`, and any other path.
    Read,
    /// `/blocks` and `/template`: large responses or template assembly.
    Bulk,
    /// `/tx`.
    Submit,
    /// `/block`.
    Block,
    /// `/tip` (a long poll that holds its request open).
    LongPoll,
}

impl Class {
    pub fn of(path: &str) -> Self {
        match path {
            "/blocks" | "/template" => Class::Bulk,
            "/tx" => Class::Submit,
            "/block" => Class::Block,
            "/tip" => Class::LongPoll,
            _ => Class::Read,
        }
    }
}

/// The body limit of a POST to `path` (0: no body).
pub fn body_limit(path: &str) -> usize {
    match path {
        "/block" => MAX_BLOCK_BODY_BYTES,
        "/tx" => MAX_TX_BODY_BYTES,
        "/outputs" => MAX_OUTPUTS_BODY_BYTES,
        _ => 0,
    }
}

/// Per-request limits of the guard.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Concurrent requests per [`Class`].
    pub reads: usize,
    pub bulk: usize,
    pub submits: usize,
    pub blocks: usize,
    pub long_polls: usize,
    /// Time to receive a request body.
    pub body_timeout: Duration,
    /// Delay before a failed authentication is answered.
    pub auth_failure_delay: Duration,
}

impl Default for Limits {
    /// Sized for one miner and a few wallets on the node's own machine: at
    /// most 9 RPC requests use the chain at once (the long-poll class waits
    /// for a new tip rather than holding the chain).
    fn default() -> Self {
        Self {
            reads: 4,
            bulk: 2,
            submits: 2,
            blocks: 1,
            long_polls: 16,
            body_timeout: Duration::from_secs(60),
            auth_failure_delay: Duration::from_millis(250),
        }
    }
}

/// What the guard enforces.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// The credential every request must carry; `None` only for routers
    /// built without one (tests, embedded use): see [`crate::router`].
    pub token: Option<Token>,
    /// Extra host names accepted in `Host` (lowercase, without port), e.g.
    /// an onion service name.
    pub allow_hosts: Vec<String>,
    /// The address the RPC is bound to, accepted in `Host` when it is not a
    /// loopback or unspecified address.
    pub bound_ip: Option<IpAddr>,
    pub limits: Limits,
}

/// The guard's state: the policy and one semaphore per class.
pub(crate) struct Guard {
    policy: Policy,
    reads: Arc<Semaphore>,
    bulk: Arc<Semaphore>,
    submits: Arc<Semaphore>,
    blocks: Arc<Semaphore>,
    long_polls: Arc<Semaphore>,
}

impl Guard {
    pub(crate) fn new(mut policy: Policy) -> Self {
        for h in &mut policy.allow_hosts {
            *h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        }
        let sem = |n: usize| Arc::new(Semaphore::new(n));
        let l = &policy.limits;
        Self {
            reads: sem(l.reads),
            bulk: sem(l.bulk),
            submits: sem(l.submits),
            blocks: sem(l.blocks),
            long_polls: sem(l.long_polls),
            policy,
        }
    }

    fn slots(&self, class: Class) -> &Arc<Semaphore> {
        match class {
            Class::Read => &self.reads,
            Class::Bulk => &self.bulk,
            Class::Submit => &self.submits,
            Class::Block => &self.blocks,
            Class::LongPoll => &self.long_polls,
        }
    }

    /// Whether `host` (a `Host` value or request authority: a name or
    /// address, with an optional port) is one the RPC answers to.
    pub(crate) fn host_allowed(&self, host: &str) -> bool {
        let Some(name) = host_name(host) else {
            return false;
        };
        let name = name.to_ascii_lowercase();
        if name == "localhost" {
            return true;
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            let loopback = match ip {
                IpAddr::V4(v4) => v4.is_loopback(),
                IpAddr::V6(v6) => v6.is_loopback(),
            };
            let bound = self
                .policy
                .bound_ip
                .is_some_and(|b| !b.is_unspecified() && !b.is_loopback() && b == ip);
            return loopback || bound;
        }
        self.policy.allow_hosts.contains(&name)
    }
}

/// The host part of `host[:port]` or `[v6]:port`, or `None` if malformed.
/// An IPv6 address must be bracketed; a port must be 1 to 5 digits.
fn host_name(host: &str) -> Option<&str> {
    let port_ok = |p: &str| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = host.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        if after.is_empty() {
            return Some(inner);
        }
        return after
            .strip_prefix(':')
            .filter(|p| port_ok(p))
            .map(|_| inner);
    }
    let (name, port) = match host.split_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host, None),
    };
    if port.is_some_and(|p| !port_ok(p)) {
        return None;
    }
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    valid.then_some(name)
}

/// Constant-time comparison of a presented credential with the expected one
/// (the length is public: every credential has
/// [`blacksilk_rpc::TOKEN_HEX_LEN`] characters).
pub fn token_matches(expected: &Token, presented: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(expected.as_str().as_bytes().ct_eq(presented))
}

fn refuse(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

/// Browser-only request headers (Fetch Metadata and CORS).
const BROWSER_HEADERS: [&str; 5] = [
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
];

fn is_json(v: Option<&HeaderValue>) -> bool {
    v.and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim())
        .is_some_and(|m| m.eq_ignore_ascii_case("application/json"))
}

/// The credential in `Authorization: Bearer <token>`, if the request has
/// exactly one such header.
fn bearer(req: &Request) -> Option<&[u8]> {
    let mut values = req.headers().get_all(header::AUTHORIZATION).iter();
    let v = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let v = v.as_bytes();
    let (scheme, rest) = v.split_at(v.iter().position(|&b| b == b' ')?);
    scheme
        .eq_ignore_ascii_case(b"bearer")
        .then(|| rest.trim_ascii())
}

pub(crate) async fn guard(State(g): State<Arc<Guard>>, req: Request, next: Next) -> Response {
    // 1. Host.
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = match (hosts.next(), hosts.next()) {
        (Some(h), None) => h.to_str().ok(),
        _ => return refuse(StatusCode::BAD_REQUEST, "exactly one Host header required"),
    };
    let authority_ok = req
        .uri()
        .authority()
        .is_none_or(|a| g.host_allowed(a.as_str()));
    if !(host.is_some_and(|h| g.host_allowed(h)) && authority_ok) {
        return refuse(
            StatusCode::FORBIDDEN,
            "host not allowed (rpc_allow_hosts, docs/blocks.md §9.1)",
        );
    }
    // 2. Browsers.
    if BROWSER_HEADERS
        .iter()
        .any(|h| req.headers().contains_key(*h))
    {
        return refuse(
            StatusCode::FORBIDDEN,
            "browser requests are not served (docs/blocks.md §9.1)",
        );
    }
    // 3. Authentication.
    if let Some(token) = &g.policy.token {
        if !bearer(&req).is_some_and(|t| token_matches(token, t)) {
            tokio::time::sleep(g.policy.limits.auth_failure_delay).await;
            let mut r = refuse(
                StatusCode::UNAUTHORIZED,
                "RPC credential missing or wrong: send the node's rpc.cookie as a Bearer token",
            );
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"blacksilk-node\""),
            );
            return r;
        }
    }
    // 4. Content type; no body outside POST.
    let path = req.uri().path().to_string();
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let chunked = req.headers().contains_key(header::TRANSFER_ENCODING);
    let post = req.method() == Method::POST;
    if post {
        if !is_json(req.headers().get(header::CONTENT_TYPE)) {
            return refuse(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            );
        }
    } else if chunked || declared.is_some_and(|n| n > 0) {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "this request takes no body");
    }
    // 5. Admission, before any body is read (the body is held in memory).
    let Ok(_slot) = g.slots(Class::of(&path)).clone().try_acquire_owned() else {
        let mut r = refuse(StatusCode::SERVICE_UNAVAILABLE, "busy: retry shortly");
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return r;
    };
    let req = if post {
        let limit = body_limit(&path);
        if declared.is_some_and(|n| n > limit as u64) {
            return refuse(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
        let (parts, body) = req.into_parts();
        match tokio::time::timeout(
            g.policy.limits.body_timeout,
            axum::body::to_bytes(body, limit),
        )
        .await
        {
            Ok(Ok(bytes)) => Request::from_parts(parts, Body::from(bytes)),
            Ok(Err(_)) => {
                return refuse(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large or cut off",
                )
            }
            Err(_) => return refuse(StatusCode::REQUEST_TIMEOUT, "request body too slow"),
        }
    } else {
        req
    };
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard_with(allow: &[&str], bound: Option<&str>) -> Guard {
        Guard::new(Policy {
            allow_hosts: allow.iter().map(|s| s.to_string()).collect(),
            bound_ip: bound.map(|b| b.parse().unwrap()),
            ..Policy::default()
        })
    }

    #[test]
    fn hosts_are_loopback_the_bound_address_or_allowed_names() {
        let g = guard_with(&["Node.Example.onion."], Some("192.168.1.5"));
        for ok in [
            "127.0.0.1",
            "127.0.0.1:29333",
            "127.1.2.3:1",
            "[::1]",
            "[::1]:29333",
            "localhost",
            "LOCALHOST:29333",
            "192.168.1.5:29333",
            "node.example.onion",
            "NODE.EXAMPLE.ONION:80",
        ] {
            assert!(g.host_allowed(ok), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:29333",
            "localhost.",
            "localhost.evil.example",
            "0.0.0.0:29333",
            "[::]:1",
            "[::ffff:127.0.0.1]",
            "192.168.1.6:29333",
            "::1",
            "127.0.0.1:",
            "127.0.0.1:abc",
            "127.0.0.1:123456",
            "[::1]x",
            "[::1",
            "",
            "127.0.0.1 evil",
            "user@127.0.0.1",
            "2130706433",
            "127.1",
        ] {
            assert!(!g.host_allowed(bad), "{bad}");
        }
        // A loopback or unspecified bind adds nothing.
        let g = guard_with(&[], Some("0.0.0.0"));
        assert!(!g.host_allowed("0.0.0.0:29333"));
    }

    #[test]
    fn classes_and_body_limits() {
        assert_eq!(Class::of("/block"), Class::Block);
        assert_eq!(Class::of("/tx"), Class::Submit);
        assert_eq!(Class::of("/blocks"), Class::Bulk);
        assert_eq!(Class::of("/template"), Class::Bulk);
        assert_eq!(Class::of("/tip"), Class::LongPoll);
        for p in [
            "/info",
            "/outputs",
            "/distribution",
            "/px/commitments",
            "/nope",
        ] {
            assert_eq!(Class::of(p), Class::Read, "{p}");
        }
        assert_eq!(body_limit("/info"), 0);
        assert!(body_limit("/tx") >= 2 * blacksilk_tx::params::MAX_PX_TX_SIZE);
        assert!(body_limit("/tx") >= 2 * blacksilk_tx::params::MAX_DEPLOY_TX_SIZE);
        assert!(body_limit("/block") >= 2 * blacksilk_chain::block::MAX_BLOCK_BYTES);
        // 1,024 indices of the largest value fit.
        let json = format!(
            "{{\"indices\":[{}]}}",
            vec![u64::MAX.to_string(); blacksilk_rpc::MAX_OUTPUTS_PER_REQUEST].join(",")
        );
        assert!(json.len() <= body_limit("/outputs"), "{}", json.len());
    }

    /// The comparison accepts exactly the credential: not a prefix, not a
    /// one-character change at either end, not another length. (Constant
    /// time comes from `subtle`; timing is not measured here.)
    #[test]
    fn the_credential_comparison_is_exact() {
        let t = Token::generate().unwrap();
        let s = t.as_str().as_bytes();
        assert!(token_matches(&t, s));
        let mut first = s.to_vec();
        first[0] = if first[0] == b'0' { b'1' } else { b'0' };
        let mut last = s.to_vec();
        last[63] = if last[63] == b'0' { b'1' } else { b'0' };
        for bad in [
            &first[..],
            &last[..],
            &s[..63],
            b"",
            &[s, b"0"].concat()[..],
        ] {
            assert!(!token_matches(&t, bad));
        }
    }
}
