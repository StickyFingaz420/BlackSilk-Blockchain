//! The Monero-style stratum xmrig speaks (v6.26.0): one JSON object per
//! line over plain TCP. Requests carry an integer `id`; replies echo it with
//! either `result` or `error`; new work is a `job` notification.
//!
//! Reply strings are fixed (the gate's PASS rules compare them exactly). None
//! starts with a prefix xmrig treats as critical ("Unauthenticated", "your IP
//! is banned", "IP Address currently banned", "Invalid job id": it then drops
//! the connection), except [`UNAUTHENTICATED`] for a wrong session id, where
//! closing is intended.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, Read};

/// The algorithm name of the local xmrig patch.
pub const ALGO_BLACKSILK: &str = "rx/blacksilk";
/// Monero's algorithm: only for the negative control.
pub const ALGO_RX0: &str = "rx/0";

/// Wrong session id in a submit; the session is closed.
pub const UNAUTHENTICATED: &str = "Unauthenticated";
/// An unknown job, a job of another session, or a job whose tip is no longer
/// the node's.
pub const STALE_JOB: &str = "Stale job";
/// The submit's `algo` is missing or not the job's.
pub const INVALID_ALGO: &str = "Invalid algo";
/// The nonce is not exactly 8 hex characters.
pub const INVALID_NONCE: &str = "Invalid nonce";
/// The result is not 64 hex characters, or not the hash of the share.
pub const INVALID_RESULT: &str = "Invalid result";
/// The hash does not meet the block's difficulty.
pub const LOW_DIFFICULTY: &str = "Low difficulty share";
/// The same (job, nonce) was already taken for verification.
pub const DUPLICATE: &str = "Duplicate share";
/// The verification queue is full; the share was not recorded and may be
/// sent again.
pub const BUSY: &str = "Busy";
/// Prefix of the reply when the node refused the block.
pub const BLOCK_REJECTED: &str = "Block rejected: ";
/// Login without the expected algorithm in `params.algo`.
pub const UNSUPPORTED_ALGO: &str = "Unsupported algo";
/// Login with `pass` `diff=N` while `--allow-session-diff` is off.
pub const SESSION_DIFF_REFUSED: &str = "Session difficulty not allowed";
/// Login while the bridge has no template (the node is syncing or down).
pub const NO_WORK: &str = "No work available";
/// Login while the session limit is reached.
pub const TOO_MANY_SESSIONS: &str = "Too many sessions";
/// A second login on one connection.
pub const ALREADY_LOGGED_IN: &str = "Already logged in";
/// Submit or keepalive before login.
pub const NOT_LOGGED_IN: &str = "Not logged in";
pub const UNSUPPORTED_METHOD: &str = "Unsupported method";
pub const MALFORMED: &str = "Malformed request";
/// A line longer than [`MAX_LINE`]; the session is closed.
pub const LINE_TOO_LONG: &str = "Line too long";

/// Success status of a share whose block the node accepted onto its best
/// chain.
pub const STATUS_OK: &str = "OK";
/// Success status of a share whose block the node accepted but not onto its
/// best chain (a side block): a valid share, not a rejection, counted apart.
pub const STATUS_OFF_BEST_CHAIN: &str = "OK_OFF_BEST_CHAIN";
pub const STATUS_KEEPALIVED: &str = "KEEPALIVED";

/// The longest line read; a longer one closes the session.
pub const MAX_LINE: usize = 16 * 1024;

/// A request line.
#[derive(Debug, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Default, Deserialize)]
pub struct LoginParams {
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub pass: String,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub algo: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubmitParams {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub job_id: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub algo: Option<String>,
}

/// The job object. There is deliberately no `sig_key`: xmrig would write a
/// miner signature at blob offset 43, over the extranonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobObject {
    pub job_id: String,
    pub blob: String,
    pub target: String,
    pub algo: String,
    pub height: u64,
    pub seed_hash: String,
}

/// `{"id":..,"jsonrpc":"2.0","error":null,"result":..}`.
pub fn result_line(id: &Value, result: Value) -> String {
    json!({"id": id, "jsonrpc": "2.0", "error": null, "result": result}).to_string()
}

/// `{"id":..,"jsonrpc":"2.0","error":{"code":-1,"message":..},"result":null}`.
pub fn error_line(id: &Value, message: &str) -> String {
    json!({
        "id": id,
        "jsonrpc": "2.0",
        "error": {"code": -1, "message": message},
        "result": null
    })
    .to_string()
}

/// `{"jsonrpc":"2.0","method":"job","params":<job>}`.
pub fn job_notification(job: &JobObject) -> String {
    json!({"jsonrpc": "2.0", "method": "job", "params": job}).to_string()
}

/// One read line.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A line without its end of line (`\n`, and a `\r` before it).
    Text(String),
    /// Longer than [`MAX_LINE`] before its end.
    TooLong,
    /// Not UTF-8.
    NotUtf8,
    /// The peer closed the connection.
    Eof,
}

/// Reads one line of at most [`MAX_LINE`] bytes. Never buffers more than
/// that: an over-long line is reported as soon as the cap is passed.
pub fn read_line<R: BufRead>(r: &mut R) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if buf.len() > MAX_LINE {
        return Ok(Line::TooLong);
    }
    if buf.len() > MAX_LINE {
        return Ok(Line::TooLong);
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(Line::Text(s)),
        Err(_) => Ok(Line::NotUtf8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn lines_are_capped() {
        let data = format!("{{\"a\":1}}\r\n{}\nrest", "x".repeat(MAX_LINE + 5));
        let mut r = BufReader::new(data.as_bytes());
        assert_eq!(read_line(&mut r).unwrap(), Line::Text("{\"a\":1}".into()));
        assert_eq!(read_line(&mut r).unwrap(), Line::TooLong);
        let exact = format!("{}\n", "y".repeat(MAX_LINE));
        let mut r = BufReader::new(exact.as_bytes());
        assert_eq!(read_line(&mut r).unwrap(), Line::Text("y".repeat(MAX_LINE)));
        assert_eq!(read_line(&mut r).unwrap(), Line::Eof);
    }

    #[test]
    fn reply_shapes() {
        let id = json!(4);
        let ok: Value = serde_json::from_str(&result_line(&id, json!({"status": "OK"}))).unwrap();
        assert_eq!(ok["id"], 4);
        assert!(ok["error"].is_null());
        assert_eq!(ok["result"]["status"], "OK");
        let err: Value = serde_json::from_str(&error_line(&id, INVALID_RESULT)).unwrap();
        assert_eq!(err["error"]["message"], "Invalid result");
        assert!(err["result"].is_null());
    }

    /// No session-keeping reply starts with a prefix xmrig treats as
    /// critical (`Client::isCriticalError`).
    #[test]
    fn rejections_keep_the_session() {
        let critical = [
            "Unauthenticated",
            "your IP is banned",
            "IP Address currently banned",
            "Invalid job id",
        ];
        for m in [
            STALE_JOB,
            INVALID_ALGO,
            INVALID_NONCE,
            INVALID_RESULT,
            LOW_DIFFICULTY,
            DUPLICATE,
            BUSY,
            BLOCK_REJECTED,
            UNSUPPORTED_METHOD,
            MALFORMED,
        ] {
            assert!(!critical.iter().any(|c| m.starts_with(c)), "{m}");
        }
    }
}
