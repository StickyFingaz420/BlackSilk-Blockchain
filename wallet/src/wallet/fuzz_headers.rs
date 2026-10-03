//! The wallet's reading of the node's header feed (`/headers`) under the
//! stable fuzz driver (fuzz/src/targets/driver.rs; W4-STATEFUL): paging in
//! `for_each_header` and the single-header read `node_id_at`, against a node
//! whose answers a script corrupts. The wallet crate is not in the fuzz
//! workspace's graph (reqwest, hyper), so this has no libFuzzer target; it
//! runs in `cargo test`, `BLACKSILK_FUZZ_ITERS` inputs.
//!
//! Input: the range's start and length (3 bytes), then one byte per node
//! call (honest once the script ends): an honest page, a short page, a page
//! from the wrong height, a header of the wrong height, hex cut short, a
//! character that is not hex, a page longer than asked, an empty page, a
//! failure, or a header whose bytes do not decode.
//!
//! Invariants, beyond "no panic":
//! - every request asks for 1 to `MAX_HEADERS_PER_REQUEST` headers, from the
//!   next height not yet delivered;
//! - the headers handed on have consecutive heights from the range's start,
//!   every one the node served at that position, and all of the range on
//!   success;
//! - an honest node delivers exactly its chain's headers, with the fewest
//!   requests;
//! - every request either fails the read or advances it: at most one per
//!   header, plus one;
//! - `node_id_at` returns the id of the header the node served at that
//!   height (`None` only for an empty answer), and an error otherwise.

use super::{for_each_header, node_id_at};
use crate::node::NodeApi;
use blacksilk_consensus::{BlockHeader, HEADER_SIZE, HEADER_VERSION};
use blacksilk_rpc as rpc;
use std::cell::{Cell, RefCell};

#[path = "../../../fuzz/src/targets/driver.rs"]
mod driver;

const NETWORK: u32 = 0x5eed;
/// Headers of heights `0..CHAIN`: enough for three full pages.
const CHAIN: u64 = 4_500;

fn header(height: u64) -> BlockHeader {
    BlockHeader {
        version: HEADER_VERSION,
        height,
        prev_id: [(height % 251) as u8; 32],
        timestamp: 1_700_000_000 + 120 * height,
        difficulty: 1 + height,
        tx_root: [(height % 241) as u8; 32],
        nonce: height.wrapping_mul(0x9e37_79b9),
    }
}

/// A node whose `/headers` answers follow a script.
struct Feed {
    script: Vec<u8>,
    next: Cell<usize>,
    /// Every request, and the headers each answer carried (decoded).
    requests: RefCell<Vec<(u64, u64)>>,
    served: RefCell<Vec<(u64, Vec<Option<BlockHeader>>)>>,
}

impl Feed {
    fn new(script: &[u8]) -> Self {
        Feed {
            script: script.to_vec(),
            next: Cell::new(0),
            requests: RefCell::default(),
            served: RefCell::default(),
        }
    }

    fn op(&self) -> u8 {
        let i = self.next.get();
        self.next.set(i + 1);
        self.script.get(i).copied().unwrap_or(0)
    }

    /// The headers served at `from..` (`count` of them, as far as the chain
    /// goes), as the honest node sends them.
    fn honest(from: u64, count: u64) -> Vec<u8> {
        (from..(from + count).min(CHAIN))
            .flat_map(|h| header(h).to_bytes())
            .collect()
    }
}

impl NodeApi for Feed {
    fn info(&self) -> Result<rpc::Info, String> {
        Err("not served".into())
    }
    fn blocks(&self, _: u64, _: u64) -> Result<rpc::Blocks, String> {
        Err("not served".into())
    }
    fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
        Err("not served".into())
    }
    fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
        Err("not served".into())
    }
    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        Err("not served".into())
    }
    fn px_commitments(&self, _: u64) -> Result<rpc::PxCommitments, String> {
        Err("not served".into())
    }
    fn px_contracts(&self, _: u64) -> Result<rpc::PxContracts, String> {
        Err("not served".into())
    }

    fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
        self.requests.borrow_mut().push((from, count));
        let op = self.op();
        let mut resp_from = from;
        let mut bytes = Feed::honest(from, count);
        let k = (op >> 4) as u64;
        match op % 12 {
            0..=2 => {}
            3 => bytes.truncate(HEADER_SIZE * (1 + k as usize) % (bytes.len() + 1)),
            4 => {
                resp_from = if k & 1 == 0 {
                    from + 1
                } else {
                    from.wrapping_sub(1)
                }
            }
            5 => {
                // One header of another height, at position k.
                let n = bytes.len() / HEADER_SIZE;
                if n > 0 {
                    let i = k as usize % n;
                    let mut h = header(from + i as u64);
                    h.height = h.height.wrapping_add(1 + (k & 1));
                    bytes[i * HEADER_SIZE..(i + 1) * HEADER_SIZE].copy_from_slice(&h.to_bytes());
                }
            }
            6 => bytes.extend(Feed::honest(from + count, 1 + k % 2)),
            7 => bytes.clear(),
            8 => return Err("the node failed".into()),
            9 => {
                // Bytes that do not decode as a header: a cut-short header.
                bytes.truncate(bytes.len().saturating_sub(1 + k as usize % HEADER_SIZE));
            }
            _ => {}
        }
        let mut hex = hex::encode(&bytes);
        match op % 12 {
            10 => {
                hex.pop();
            }
            11 if !hex.is_empty() => {
                let i = (k as usize * 7) % hex.len();
                hex.replace_range(i..i + 1, "g");
            }
            _ => {}
        }
        self.served.borrow_mut().push((
            resp_from,
            bytes
                .chunks(HEADER_SIZE)
                .map(BlockHeader::from_bytes)
                .collect(),
        ));
        Ok(rpc::Headers {
            from: resp_from,
            headers: hex,
            height: CHAIN - 1,
        })
    }
}

fn run(data: &[u8]) {
    let [a, b, c] = [0, 1, 2].map(|i| data.get(i).copied().unwrap_or(0));
    let script = data.get(3..).unwrap_or(&[]);
    let lo = (a as u64 * 37) % CHAIN;
    let hi = (lo + (u16::from_le_bytes([b, c]) as u64 % 4_200)).min(CHAIN - 1);
    let n = hi - lo + 1;

    // The paged read.
    let feed = Feed::new(script);
    let mut got: Vec<BlockHeader> = Vec::new();
    let r = for_each_header(&feed, lo, hi, |h| {
        got.push(h);
        Ok(())
    });
    let requests = feed.requests.borrow();
    let mut next = lo;
    for &(from, count) in requests.iter() {
        assert!(
            (1..=rpc::MAX_HEADERS_PER_REQUEST).contains(&count),
            "count {count}"
        );
        assert!(
            from <= hi && from + count <= hi + 1,
            "request {from}+{count} past {hi}"
        );
        assert!(from >= next, "request from {from} below {next}");
        next = from;
    }
    assert!(
        requests.len() as u64 <= n + 1,
        "{} requests for {n} headers",
        requests.len()
    );
    for (i, h) in got.iter().enumerate() {
        assert_eq!(h.height, lo + i as u64, "a delivered header's height");
    }
    // Every delivered header is one the node served at that height.
    let served: Vec<BlockHeader> = feed
        .served
        .borrow()
        .iter()
        .flat_map(|(_, hs)| hs.iter().flatten().copied())
        .collect();
    for h in &got {
        assert!(served.contains(h), "a header the node never served");
    }
    match r {
        Ok(()) => assert_eq!(got.len() as u64, n, "a successful read covers the range"),
        Err(_) => assert!((got.len() as u64) < n),
    }
    let honest = script.iter().all(|&op| op % 12 <= 2);
    if honest {
        assert!(
            r_ok(&got, lo, hi),
            "an honest node's headers are delivered exactly"
        );
        let pages = n.div_ceil(rpc::MAX_HEADERS_PER_REQUEST);
        assert_eq!(requests.len() as u64, pages, "requests to an honest node");
    }
    drop(requests);

    // The single-header read.
    let feed = Feed::new(script);
    let height = hi;
    let r = node_id_at(&feed, height, NETWORK);
    let served = feed.served.borrow();
    let Some((from, headers)) = served.first() else {
        // The node failed.
        assert!(r.is_err());
        return;
    };
    match r {
        Ok(Some(id)) => {
            let h = headers[0].expect("a decoded header");
            assert_eq!(headers.len(), 1);
            assert_eq!((h.height, *from), (height, height));
            assert_eq!(id, h.id(NETWORK));
        }
        Ok(None) => assert!(headers.is_empty(), "None for a non-empty answer"),
        Err(_) => {}
    }
}

fn r_ok(got: &[BlockHeader], lo: u64, hi: u64) -> bool {
    got.len() as u64 == hi - lo + 1 && got.iter().all(|h| *h == header(h.height))
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        vec![0, 0, 0],
        vec![3, 0xd0, 0x07],
        vec![1, 0x68, 0x10],
        vec![0, 0xa0, 0x0f, 3],
        vec![2, 0x10, 0x00, 0x14],
        vec![5, 0x20, 0x00, 5],
        vec![9, 0xd0, 0x07, 0, 6],
        vec![4, 0x05, 0x00, 7],
        vec![6, 0x05, 0x00, 8],
        vec![7, 0x05, 0x00, 0x29],
        vec![8, 0x05, 0x00, 10],
        vec![1, 0x05, 0x00, 11],
    ]
}

#[test]
fn the_header_feed_is_read_in_order_and_within_its_bounds() {
    driver::drive("wallet_headers", &seeds(), 64, run);
}
