//! The probe: a tiny stratum client that sends the invalid shares real xmrig
//! never sends, and one block the node must refuse (gate cases H4, H5).
//!
//! It is a client: it encodes its nonces itself (the 4 raw bytes it writes
//! at blob 39..43, as hex) and hashes the served blob itself, never through
//! the bridge's helpers. Every case expects one exact reply string.

use crate::stratum::{self, JobObject};
use crate::target::xmrig_would_submit;
use blacksilk_chain::block::Block;
use blacksilk_consensus::{check_hash, Hash, PowBlob, POW_BLOB_SIZE, POW_NONCE_OFFSET};
use blacksilk_crypto::keys::Address;
use blacksilk_rpc::{self as rpc, parse_hash, Client};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The probe's login agent (not xmrig's, so its deliberate bad results are
/// never counted as a `GATE-MISMATCH`).
pub const PROBE_AGENT: &str = concat!("blacksilk-stratum-probe/", env!("CARGO_PKG_VERSION"));

/// A submit's answer: `Ok(status)` or `Err(error message)`.
pub type Reply = Result<String, String>;

/// A stratum client over one connection.
pub struct ProbeClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
    /// The session id from the login.
    pub session: String,
    /// Job notifications not yet taken.
    pending: VecDeque<JobObject>,
    /// The latest job.
    pub job: JobObject,
}

fn io_err(m: impl Into<String>) -> std::io::Error {
    std::io::Error::other(m.into())
}

impl ProbeClient {
    /// Connects and logs in with `algo` and `pass`.
    pub fn login(
        addr: SocketAddr,
        agent: &str,
        algo: &[&str],
        pass: &str,
    ) -> std::io::Result<Result<Self, String>> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        let writer = stream.try_clone()?;
        let mut c = Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 1,
            session: String::new(),
            pending: VecDeque::new(),
            job: JobObject {
                job_id: String::new(),
                blob: String::new(),
                target: String::new(),
                algo: String::new(),
                height: 0,
                seed_hash: String::new(),
            },
        };
        let r = c.request(
            "login",
            json!({"login": "x", "pass": pass, "agent": agent, "algo": algo}),
        )?;
        if let Some(m) = r["error"]["message"].as_str() {
            return Ok(Err(m.to_string()));
        }
        c.session = r["result"]["id"]
            .as_str()
            .ok_or_else(|| io_err("login reply without an id"))?
            .to_string();
        c.job = serde_json::from_value(r["result"]["job"].clone())
            .map_err(|e| io_err(format!("login job: {e}")))?;
        Ok(Ok(c))
    }

    /// Sends a raw line.
    pub fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Reads one line (job notifications are queued, not returned); `None`
    /// at the end of the connection.
    pub fn read_value(&mut self) -> std::io::Result<Option<Value>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        serde_json::from_str(line.trim_end())
            .map(Some)
            .map_err(|e| io_err(format!("bad line from the bridge: {e}: {line}")))
    }

    /// Sends a request and returns its reply; job notifications that arrive
    /// meanwhile are queued.
    pub fn request(&mut self, method: &str, params: Value) -> std::io::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params});
        self.send_line(&line.to_string())?;
        self.reply_to(id)
    }

    fn reply_to(&mut self, id: u64) -> std::io::Result<Value> {
        loop {
            let v = self
                .read_value()?
                .ok_or_else(|| io_err("the bridge closed the connection"))?;
            if v["method"] == "job" {
                let j: JobObject = serde_json::from_value(v["params"].clone())
                    .map_err(|e| io_err(format!("job notification: {e}")))?;
                self.pending.push_back(j);
                continue;
            }
            if v["id"] == json!(id) {
                return Ok(v);
            }
        }
    }

    /// The answer of a submit.
    pub fn submit(
        &mut self,
        job_id: &str,
        nonce: &str,
        result: &str,
        algo: Option<&str>,
    ) -> std::io::Result<Reply> {
        let mut p = json!({"id": self.session, "job_id": job_id, "nonce": nonce, "result": result});
        if let Some(a) = algo {
            p["algo"] = json!(a);
        }
        let r = self.request("submit", p)?;
        Ok(reply_of(&r))
    }

    /// Takes queued job notifications; the latest becomes [`Self::job`].
    /// Returns whether there was one.
    pub fn drain_jobs(&mut self) -> bool {
        let mut any = false;
        while let Some(j) = self.pending.pop_front() {
            self.job = j;
            any = true;
        }
        any
    }

    /// Waits up to `timeout` for a new job notification.
    pub fn wait_job(&mut self, timeout: Duration) -> std::io::Result<bool> {
        if self.drain_jobs() {
            return Ok(true);
        }
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            self.reader.get_ref().set_read_timeout(Some(left))?;
            let r = self.read_value();
            self.reader
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(120)))?;
            match r {
                Ok(Some(v)) if v["method"] == "job" => {
                    self.job = serde_json::from_value(v["params"].clone())
                        .map_err(|e| io_err(format!("job notification: {e}")))?;
                    self.drain_jobs();
                    return Ok(true);
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err(io_err("the bridge closed the connection")),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(false)
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// `Ok(status)` or `Err(message)` of a reply object.
pub fn reply_of(r: &Value) -> Reply {
    match r["error"]["message"].as_str() {
        Some(m) => Err(m.to_string()),
        None => Ok(r["result"]["status"].as_str().unwrap_or("").to_string()),
    }
}

/// A job's blob with `nonce` written at 39..43 as its 4 little-endian bytes,
/// and those bytes as hex: what xmrig hashes and sends.
pub fn client_blob(job: &JobObject, nonce: u32) -> Option<(PowBlob, String)> {
    let mut blob: PowBlob = hex::decode(&job.blob).ok()?.try_into().ok()?;
    let raw = nonce.to_le_bytes();
    blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 4].copy_from_slice(&raw);
    debug_assert_eq!(blob.len(), POW_BLOB_SIZE);
    Some((blob, hex::encode(raw)))
}

/// One case's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseResult {
    pub case: String,
    pub expect: String,
    pub got: String,
    /// Whether the node's tip was the same before and after (when known).
    pub tip_unchanged: Option<bool>,
}

impl CaseResult {
    pub fn passed(&self) -> bool {
        self.expect == self.got && self.tip_unchanged != Some(false)
    }

    pub fn render(&self) -> String {
        format!(
            "probe case={} expect={:?} got={:?} tip_unchanged={} result={}",
            self.case,
            self.expect,
            self.got,
            self.tip_unchanged
                .map_or("not-checked".to_string(), |b| b.to_string()),
            if self.passed() { "PASS" } else { "FAIL" }
        )
    }
}

fn shown(r: &Reply) -> String {
    match r {
        Ok(s) => s.clone(),
        Err(m) => m.clone(),
    }
}

/// The hash a probe computes for (seed, blob).
pub type Hasher<'a> = dyn FnMut(&Hash, &PowBlob) -> Hash + 'a;
/// The node's tip id, when the probe can see the node.
pub type TipFn<'a> = dyn FnMut() -> Option<String> + 'a;

/// The invalid-share cases on the client's current job (H4), each with its
/// exact expected reply:
/// - `c`: a 7-hex nonce: `Invalid nonce`;
/// - `a`: nonce `n+1` with the true hash of `n`: `Invalid result`;
/// - `b`: nonce `n'` with one bit of its true hash flipped: `Invalid result`;
/// - `e`: (b) again on the still-current job: `Duplicate share`;
/// - `d`: a share that passes the job's target, with its true hash: `OK`
///   (one block, the tip moves);
/// - `e2`: (d) again once the new job has arrived: `Stale job`.
///
/// `algo` is the label sent with each submit (the job's own). Rejections are
/// checked with the tip unchanged when `tip` knows it.
pub fn run_cases(
    c: &mut ProbeClient,
    hasher: &mut Hasher<'_>,
    tip: &mut TipFn<'_>,
    rng: &mut dyn RngCore,
) -> std::io::Result<Vec<CaseResult>> {
    c.drain_jobs();
    let job = c.job.clone();
    let algo = Some(job.algo.clone());
    let seed: Hash = parse_hash(&job.seed_hash).ok_or_else(|| io_err("job seed_hash"))?;
    let target = crate::target::xmrig_decode_target(&job.target);
    let mut out = Vec::new();
    let rejection = |c: &mut ProbeClient,
                     case: &str,
                     expect: &str,
                     nonce: &str,
                     result: &str,
                     tip: &mut TipFn<'_>|
     -> std::io::Result<CaseResult> {
        let before = tip();
        let got = c.submit(&job.job_id, nonce, result, algo.as_deref())?;
        let after = tip();
        Ok(CaseResult {
            case: case.into(),
            expect: expect.into(),
            got: shown(&got),
            tip_unchanged: before.zip(after).map(|(b, a)| a == b),
        })
    };
    let blob = |n: u32| client_blob(&job, n).ok_or_else(|| io_err("job blob"));
    // c
    out.push(rejection(
        c,
        "c",
        stratum::INVALID_NONCE,
        "0000000",
        &"00".repeat(32),
        tip,
    )?);
    // a
    let na = rng.next_u32() & 0x7fff_ffff;
    let (ba, _) = blob(na)?;
    let ha = hasher(&seed, &ba);
    let (_, hex_a1) = blob(na + 1)?;
    out.push(rejection(
        c,
        "a",
        stratum::INVALID_RESULT,
        &hex_a1,
        &hex::encode(ha),
        tip,
    )?);
    // b
    let nb = (rng.next_u32() & 0x7fff_ffff) | 0x8000_0000;
    let (bb, hex_b) = blob(nb)?;
    let mut hb = hasher(&seed, &bb);
    hb[0] ^= 1;
    out.push(rejection(
        c,
        "b",
        stratum::INVALID_RESULT,
        &hex_b,
        &hex::encode(hb),
        tip,
    )?);
    // e: the same share again, on the still-current job.
    out.push(rejection(
        c,
        "e",
        stratum::DUPLICATE,
        &hex_b,
        &hex::encode(hb),
        tip,
    )?);
    // d: search like xmrig (the job's target), then submit the true hash.
    let mut nd = rng.next_u32();
    let (hex_d, hd) = loop {
        let (bd, hex_d) = blob(nd)?;
        let h = hasher(&seed, &bd);
        if xmrig_would_submit(&h, target) {
            break (hex_d, h);
        }
        nd = nd.wrapping_add(1);
    };
    let got = c.submit(&job.job_id, &hex_d, &hex::encode(hd), algo.as_deref())?;
    out.push(CaseResult {
        case: "d".into(),
        expect: stratum::STATUS_OK.into(),
        got: shown(&got),
        tip_unchanged: None,
    });
    // e2: (d) again once the bridge has moved to the new tip.
    if c.wait_job(Duration::from_secs(60))? {
        out.push(rejection(
            c,
            "e2",
            stratum::STALE_JOB,
            &hex_d,
            &hex::encode(hd),
            tip,
        )?);
    } else {
        out.push(CaseResult {
            case: "e2".into(),
            expect: stratum::STALE_JOB.into(),
            got: "no new job within 60 s".into(),
            tip_unchanged: None,
        });
    }
    Ok(out)
}

/// Case `f`: another session's share replayed on this session: `Stale job`
/// (jobs are scoped to their session).
pub fn replay(
    c: &mut ProbeClient,
    job_id: &str,
    nonce: &str,
    result: &str,
    tip: &mut TipFn<'_>,
) -> std::io::Result<CaseResult> {
    let before = tip();
    let algo = c.job.algo.clone();
    let got = c.submit(job_id, nonce, result, Some(&algo))?;
    let after = tip();
    Ok(CaseResult {
        case: "f".into(),
        expect: stratum::STALE_JOB.into(),
        got: shown(&got),
        tip_unchanged: before.zip(after).map(|(b, a)| a == b),
    })
}

/// The substring the node's refusal of a block whose hash misses its
/// difficulty carries (`HeaderError::InsufficientWork`).
pub const INSUFFICIENT_WORK: &str = "InsufficientWork";

/// Case `direct-to-node` (H5): a block built from the node's template, with
/// a nonce whose hash fails the block's difficulty, sent straight to
/// `/block`. The node must refuse it with `InsufficientWork`, tip unchanged.
/// Needs a difficulty above 1.
pub fn direct_to_node<R: RngCore + CryptoRng>(
    client: &Client,
    payout: &Address,
    hasher: &mut Hasher<'_>,
    rng: &mut R,
) -> Result<CaseResult, String> {
    let info = client.info().map_err(|e| e.to_string())?;
    if info.network != "regtest" {
        return Err(format!("refusing {}: regtest only", info.network));
    }
    let t = client
        .mining_template()
        .map_err(|e| e.to_string())?
        .template;
    if t.difficulty < 2 {
        return Err(format!(
            "the template's difficulty is {}: every hash meets it, so no block can fail",
            t.difficulty
        ));
    }
    let seed = parse_hash(&t.seed_id).ok_or("template seed_id")?;
    let mut hedge = [0u8; 32];
    rng.fill_bytes(&mut hedge);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut block: Block = blacksilk_miner::build_block(&t, payout, &hedge, now, rng)
        .map_err(|e| format!("build_block: {e:?}"))?;
    block.header.nonce = rng.next_u64();
    loop {
        let h = hasher(&seed, &block.header.pow_blob(info.network_id));
        if !check_hash(&h, t.difficulty) {
            break;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    let before = client.tip(None, 0).map_err(|e| e.to_string())?.tip;
    let r: rpc::SubmitResult = client
        .submit_block(&block.encode())
        .map_err(|e| e.to_string())?;
    let after = client.tip(None, 0).map_err(|e| e.to_string())?.tip;
    let got = if r.accepted {
        "accepted".to_string()
    } else {
        let e = r.error.unwrap_or_default();
        if e.contains(INSUFFICIENT_WORK) {
            INSUFFICIENT_WORK.to_string()
        } else {
            e
        }
    };
    Ok(CaseResult {
        case: "direct-to-node".into(),
        expect: INSUFFICIENT_WORK.into(),
        got,
        tip_unchanged: Some(before == after),
    })
}
