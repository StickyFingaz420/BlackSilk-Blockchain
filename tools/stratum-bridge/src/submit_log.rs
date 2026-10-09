//! The submit log: one JSON line per `submit`, with its outcome and every
//! input needed to recompute it offline (gate rule H3: every xmrig
//! submission, stale, duplicate and `Busy` ones included, is recomputed after
//! the run, not only the ones the bridge hashed live).

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One submit and its outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRecord {
    /// Unix time in milliseconds.
    pub ts_ms: u64,
    /// The session id (the only identifier logged).
    pub session: String,
    /// The login `agent` string (xmrig: `XMRig/<version> ...`).
    pub agent: String,
    /// The fields as received.
    pub job_id: String,
    pub nonce: String,
    pub result: String,
    pub algo: Option<String>,
    /// The job's own data, when the job was found.
    pub job_algo: Option<String>,
    pub height: Option<u64>,
    /// The RandomX key (hex).
    pub seed: Option<String>,
    /// The 47-byte PoW input of the share (hex): `pow_blob` of the rebuilt
    /// header, when the job was found and the nonce decoded.
    pub blob: Option<String>,
    /// The rebuilt header nonce `(X << 32) | LE32(nonce)`.
    pub header_nonce: Option<u64>,
    pub block_diff: Option<u64>,
    pub share_diff: Option<u64>,
    /// Whether the bridge hashed it live, and the hash.
    pub hashed: bool,
    pub bridge_hash: Option<String>,
    /// The outcome label (`Outcome::label`).
    pub outcome: String,
    /// The reply: `OK`, `OK_OFF_BEST_CHAIN`, or the error message.
    pub reply: String,
    /// A result from xmrig that differs from the bridge's hash.
    pub gate_mismatch: bool,
    /// The block id, when the node accepted the block.
    pub block_id: Option<String>,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A line-oriented log file, flushed after every line.
pub struct LineLog {
    file: Mutex<BufWriter<File>>,
}

impl LineLog {
    /// Creates `path`, or appends to it.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(BufWriter::new(f)),
        })
    }

    pub fn line(&self, text: &str) {
        let mut f = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if writeln!(f, "{text}").and_then(|()| f.flush()).is_err() {
            log::error!("log write failed");
        }
    }
}

/// Reads a submit log; a line that does not decode is returned as its line
/// number.
pub fn read(path: &Path) -> std::io::Result<(Vec<SubmitRecord>, Vec<usize>)> {
    let text = std::fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(r) => records.push(r),
            Err(_) => bad.push(i + 1),
        }
    }
    Ok((records, bad))
}
