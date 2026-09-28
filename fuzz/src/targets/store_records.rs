//! Target body: the `blocks.dat` v2 record decoder (chain/src/store.rs,
//! docs/blocks.md §8; W2-35), through the public `FileStore` API: `bind`,
//! `load` (frame parsing, `decode_body`, torn-tail truncation, the
//! damage-before-valid-data refusal) and `repair`.
//!
//! Input: a mode byte, then the file (after a valid file header, or raw).
//! Mode bits: 1 = raw (the input is the whole file, header included), 2 =
//! testnet instead of regtest (a headerless legacy store is refused there),
//! 4 = fix checksums (the target recomputes the header's and every frame's
//! CRC-32 first, so mutations reach the body decoder instead of stopping at
//! the checksum).
//!
//! Invariants, beyond "no panic":
//! - a store with a valid header always binds; a refused bind or load
//!   changes nothing on disk;
//! - `load` only ever truncates (the kept file is a prefix of the input);
//! - canonical round trip: every frame of the kept file checks under an
//!   independent CRC-32, and its body is byte for byte the spec encoding of
//!   the record `load` returned for it (an unknown advisory record is the
//!   only frame without a record); writing the records into a new store
//!   gives the kept file minus those advisory frames; loading again returns
//!   the same records and changes nothing;
//! - `repair` sets aside exactly the bytes it drops (kept ‖ set-aside =
//!   input); afterwards the store loads, or refuses only a checksum-valid
//!   malformed record, which a second repair leaves alone (returns 0).
//!
//! Bounded allocation: `load` reads the file once and copies record bodies
//! out of it; a frame's length is checked against the bytes present before
//! anything is allocated for it (`parse_frame` allocates nothing). The
//! campaign runs this target with `-malloc_limit_mb` (fuzz/run_campaign.sh).

use blacksilk_chain::store::{
    BlockStore, Checkpoint, FileStore, InvalidMarker, InvalidOrigin, Marker, Record, StoreIdentity,
    FILE_HEADER, FORMAT_VERSION, MAX_BUILD_COMMIT, MAX_REASON,
};
use blacksilk_consensus::Network;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const RAW: u8 = 1;
const TESTNET: u8 = 2;
const FIX_CRC: u8 = 4;

const NET: u32 = 0x0001_D672;
const GENESIS: [u8; 32] = [0x42; 32];
const TYPED: &[u8; 4] = b"BSR2";
const LEGACY: &[u8; 4] = b"BSB1";
/// Magic, length, checksum.
const FRAME_HEADER: usize = 12;

fn identity(mode: u8) -> StoreIdentity {
    StoreIdentity {
        network: if mode & TESTNET != 0 {
            Network::Testnet
        } else {
            Network::Regtest
        },
        network_id: NET,
        genesis_id: GENESIS,
    }
}

/// CRC-32 (IEEE 802.3, reflected, the checksum `crc32fast` computes),
/// written here from the definition as an independent oracle.
pub fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = !0u32;
    for part in parts {
        for &b in *part {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
    }
    !c
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().expect("4 bytes"))
}

/// The v2 file header of `(NET, GENESIS)`, from the spec.
pub fn file_header() -> Vec<u8> {
    let mut h = b"BSBH".to_vec();
    h.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    h.extend_from_slice(&NET.to_le_bytes());
    h.extend_from_slice(&GENESIS);
    let crc = crc32(&[&h]);
    h.extend_from_slice(&crc.to_le_bytes());
    assert_eq!(h.len(), FILE_HEADER);
    h
}

/// A frame of `body` in the typed (`BSR2`, checksum over length and body) or
/// the legacy (`BSB1`, checksum over the body) layout.
pub fn frame(typed: bool, body: &[u8]) -> Vec<u8> {
    let n = (body.len() as u32).to_le_bytes();
    let crc = if typed {
        crc32(&[&n, body])
    } else {
        crc32(&[body])
    };
    let mut f = if typed {
        TYPED.to_vec()
    } else {
        LEGACY.to_vec()
    };
    f.extend_from_slice(&n);
    f.extend_from_slice(&crc.to_le_bytes());
    f.extend_from_slice(body);
    f
}

/// Recomputes the header checksum (if `file` starts with one) and the
/// checksum of every whole frame from the start of the records on.
pub fn fix_checksums(file: &mut [u8]) {
    let mut pos = 0;
    if file.len() >= FILE_HEADER && file.starts_with(b"BSBH") {
        let crc = crc32(&[&file[..44]]);
        file[44..48].copy_from_slice(&crc.to_le_bytes());
        pos = FILE_HEADER;
    }
    while pos + FRAME_HEADER <= file.len() {
        let typed = match &file[pos..pos + 4] {
            m if m == TYPED => true,
            m if m == LEGACY => false,
            _ => return,
        };
        let n = le32(&file[pos + 4..]) as usize;
        let Some(end) = (pos + FRAME_HEADER).checked_add(n) else {
            return;
        };
        if end > file.len() {
            return;
        }
        let body = &file[pos + FRAME_HEADER..end];
        let crc = if typed {
            crc32(&[&file[pos + 4..pos + 8], body])
        } else {
            crc32(&[body])
        };
        file[pos + 8..pos + 12].copy_from_slice(&crc.to_le_bytes());
        pos = end;
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The body of `record` as docs/blocks.md §8 specifies it.
fn spec_body(typed: bool, record: &Record) -> Vec<u8> {
    let mut b = Vec::new();
    match record {
        Record::Block((pow, block)) => {
            if typed {
                b.push(0x01);
            }
            b.extend_from_slice(pow);
            b.extend_from_slice(block);
        }
        Record::Marker(Marker::Invalid(m)) => {
            assert!(typed, "a legacy store holds blocks only");
            assert!(m.reason.len() <= MAX_REASON);
            b.push(0x02);
            b.extend_from_slice(&m.id);
            b.push(match m.origin {
                InvalidOrigin::Verdict => 1,
                InvalidOrigin::Operator => 2,
            });
            text(&mut b, &m.reason);
        }
        Record::Marker(Marker::Checkpoint(c)) => {
            assert!(typed, "a legacy store holds blocks only");
            assert!(c.build_commit.len() <= MAX_BUILD_COMMIT);
            b.push(0x81);
            b.extend_from_slice(&c.tip_id);
            b.extend_from_slice(&c.height.to_le_bytes());
            b.extend_from_slice(&c.state_digest);
            b.extend_from_slice(&c.fingerprint);
            text(&mut b, &c.build_commit);
        }
    }
    b
}

/// Checks that `kept` (a file `load` accepted) consists of whole, checked
/// frames that are exactly the spec encodings of `records`, in order, plus
/// skipped advisory frames. Returns `kept` without those advisory frames.
fn check_kept(typed: bool, kept: &[u8], records: &[Record]) -> Vec<u8> {
    let mut pos = if typed { FILE_HEADER } else { 0 };
    let mut canonical = kept[..pos].to_vec();
    let mut next = records.iter();
    while pos < kept.len() {
        assert!(
            pos + FRAME_HEADER <= kept.len(),
            "a partial frame header was kept"
        );
        let magic = if typed { TYPED } else { LEGACY };
        assert_eq!(
            &kept[pos..pos + 4],
            magic,
            "a frame without its magic was kept"
        );
        let n = le32(&kept[pos + 4..]) as usize;
        let end = pos + FRAME_HEADER + n;
        assert!(end <= kept.len(), "a partial frame was kept");
        let body = &kept[pos + FRAME_HEADER..end];
        assert_eq!(
            &kept[pos..end],
            &frame(typed, body)[..],
            "a frame with a wrong checksum was kept"
        );
        let unknown_advisory = typed && body[0] & 0x80 != 0 && body[0] != 0x81;
        if !unknown_advisory {
            let r = next.next().expect("a kept frame without a record");
            assert_eq!(spec_body(typed, r), body, "not the canonical encoding");
            canonical.extend_from_slice(&kept[pos..end]);
        }
        pos = end;
    }
    assert!(next.next().is_none(), "a record without a frame");
    canonical
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A fresh directory of this process (fuzz workers and test threads each
/// get their own).
fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "blacksilk-fuzz-store-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read the store")
}

pub fn run(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let dir = scratch_dir();
    check(mode, rest, &dir);
    std::fs::remove_dir_all(&dir).ok();
}

fn check(mode: u8, rest: &[u8], dir: &Path) {
    let id = identity(mode);
    let mut file = if mode & RAW != 0 {
        Vec::new()
    } else {
        file_header()
    };
    file.extend_from_slice(rest);
    if mode & FIX_CRC != 0 {
        fix_checksums(&mut file);
    }
    let path = dir.join("blocks.dat");
    std::fs::write(&path, &file).expect("write the store");

    let mut store = FileStore::open(&path).expect("open the store");
    if let Err(e) = store.bind(&id) {
        drop(store);
        assert!(mode & RAW != 0, "a store with a valid header binds: {e}");
        assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
        assert_eq!(read(&path), file, "a refused bind changes nothing");
        return;
    }
    let typed = store.format_version() == FORMAT_VERSION;
    // `bind` rewrites a torn header (a prefix of the expected one).
    let before = read(&path);
    let loaded = store.load();
    drop(store);
    let kept = read(&path);
    match loaded {
        Ok(records) => {
            assert!(before.starts_with(&kept), "load only truncates");
            let canonical = check_kept(typed, &kept, &records);
            if kept.is_empty() {
                // A legacy store that was all torn tail is now empty: the
                // next bind makes it a new store (with a v2 header).
                assert!(!typed && records.is_empty());
                return;
            }
            // Loading again: the same records, and nothing else changes.
            let mut again = FileStore::open(&path).expect("open the store");
            again.bind(&id).expect("an accepted store binds again");
            assert_eq!(
                again.load().expect("an accepted store loads again"),
                records
            );
            drop(again);
            assert_eq!(read(&path), kept, "a second load changes nothing");
            if typed {
                // Re-encoding through the store's own writer.
                let copy = dir.join("copy.dat");
                let mut s = FileStore::open(&copy).expect("open the copy");
                s.bind(&id).expect("bind the copy");
                for r in &records {
                    match r {
                        Record::Block((pow, block)) => s.append(pow, block),
                        Record::Marker(m) => s.append_marker(m),
                    }
                    .expect("a loaded record is written again");
                }
                drop(s);
                assert_eq!(read(&copy), canonical, "re-encoding is canonical");
            }
        }
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
            assert_eq!(kept, before, "a refused load changes nothing");
            check_repair(&path, &id, &before);
        }
    }
}

fn check_repair(path: &Path, id: &StoreIdentity, before: &[u8]) {
    let dropped = FileStore::repair(path, 0).expect("a store that binds can be repaired");
    let kept = read(path);
    let aside = path.with_extension("dat.damaged-0");
    if dropped == 0 {
        assert_eq!(kept, before, "nothing to repair, nothing changed");
        assert!(!aside.exists(), "nothing set aside");
    } else {
        let set_aside = read(&aside);
        assert_eq!(set_aside.len() as u64, dropped);
        assert_eq!([&kept[..], &set_aside[..]].concat(), before, "no byte lost");
        std::fs::remove_file(&aside).expect("remove the set-aside file");
    }
    let mut s = FileStore::open(path).expect("open the repaired store");
    s.bind(id).expect("a repaired store binds");
    if let Err(e) = s.load() {
        // Left: a checksum-valid record that is not valid, which repair
        // never drops (the operator decides).
        assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
        drop(s);
        assert_eq!(FileStore::repair(path, 0).expect("repair again"), 0);
    }
}

fn record_file(dir: &Path, records: &[Record]) -> Vec<u8> {
    let path = dir.join("seed.dat");
    std::fs::remove_file(&path).ok();
    let mut s = FileStore::open(&path).expect("open");
    s.bind(&identity(0)).expect("bind");
    for r in records {
        match r {
            Record::Block((pow, block)) => s.append(pow, block),
            Record::Marker(m) => s.append_marker(m),
        }
        .expect("append");
    }
    drop(s);
    read(&path)
}

fn with_mode(mode: u8, bytes: &[u8]) -> Vec<u8> {
    [&[mode][..], bytes].concat()
}

/// Seed inputs (named), written by the store itself where it can.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let dir = scratch_dir();
    let records = vec![
        Record::Block(([1; 32], vec![1; 11])),
        Record::Marker(Marker::Checkpoint(Checkpoint {
            tip_id: [2; 32],
            height: 1_002,
            state_digest: [3; 32],
            fingerprint: [4; 32],
            build_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        })),
        Record::Block(([5; 32], vec![5; 300])),
        Record::Marker(Marker::Invalid(InvalidMarker {
            id: [6; 32],
            origin: InvalidOrigin::Verdict,
            reason: "bad proof of work".into(),
        })),
        Record::Marker(Marker::Invalid(InvalidMarker {
            id: [7; 32],
            origin: InvalidOrigin::Operator,
            reason: String::new(),
        })),
        Record::Block(([8; 32], Vec::new())),
    ];
    let file = record_file(&dir, &records);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        &file[..FILE_HEADER],
        &file_header()[..],
        "the header oracle"
    );
    let body = &file[FILE_HEADER..];
    let mut torn = body.to_vec();
    torn.truncate(torn.len() - 20);
    let mut damaged = body.to_vec();
    damaged[FRAME_HEADER + 5] ^= 1;
    // Frames the store never writes: an unknown advisory type (skipped), an
    // unknown critical type (refused), a short block record, a bad origin.
    let odd: Vec<u8> = [
        frame(true, &[0x90, 1, 2, 3]),
        frame(true, &[0x01; 40]),
        frame(true, &[0x03, 0]),
        frame(true, &[0x01; 20]),
        frame(true, &[&[0x02][..], &[9; 32], &[3, 0, 0]].concat()),
    ]
    .concat();
    let legacy: Vec<u8> = [
        frame(false, &[[1; 32].as_slice(), &[1; 10]].concat()),
        frame(false, &[2; 32]),
    ]
    .concat();
    let mut v1_header = file_header();
    v1_header[4] = 1;
    vec![
        ("typed", with_mode(0, body)),
        ("typed_fix", with_mode(FIX_CRC, body)),
        ("typed_testnet", with_mode(TESTNET, body)),
        ("raw_file", with_mode(RAW, &file)),
        ("torn_tail", with_mode(0, &torn)),
        ("damaged_middle", with_mode(0, &damaged)),
        ("odd_records", with_mode(FIX_CRC, &odd)),
        ("legacy", with_mode(RAW, &legacy)),
        ("legacy_testnet", with_mode(RAW | TESTNET, &legacy)),
        (
            "format1",
            with_mode(RAW | FIX_CRC, &[&v1_header[..], body].concat()),
        ),
        ("torn_header", with_mode(RAW, &file[..20])),
        ("empty", vec![0]),
    ]
}
