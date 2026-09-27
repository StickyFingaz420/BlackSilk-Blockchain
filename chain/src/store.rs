//! Block storage (docs/blocks.md §8): an append-only log of accepted blocks.
//!
//! ```text
//! file    = file header ‖ record*
//! header  = "BSBH" ‖ LE32 version (1) ‖ LE32 network_id ‖ genesis_id (32)
//!           ‖ LE32 crc32(the 44 bytes before)                        (48 bytes)
//! record  = "BSB1" ‖ LE32 length ‖ LE32 crc32(payload) ‖ payload
//! payload = pow_hash (32) ‖ block bytes
//! ```
//!
//! **Network identity** ([`BlockStore::bind`], called by the chain manager
//! before `load`): a new store is created with the file header; an existing
//! one is refused if it names another network or genesis ("wrong network data
//! directory"), so a store left over from an earlier testnet is detected
//! instead of being replayed into (and silently orphaned by) a new genesis.
//! Stores written before 2026-09-27 have no file header (format version 0,
//! records from offset 0). They are accepted as they are, with a warning, and
//! stay headerless (nothing is rewritten); their network cannot be verified.
//!
//! **Failure behaviour** (docs/blocks.md §8):
//! - A record is durable when `append` returns (`sync_data`).
//! - A failed append (disk full, I/O error) is undone: the file is truncated
//!   back to its previous length, so no record ever follows damaged bytes. If
//!   even that fails, the store refuses further appends until the node
//!   restarts; the damaged bytes are then the file's tail, which `load`
//!   truncates.
//! - `load` truncates a damaged **tail** (a crash mid-write) and refuses damage
//!   followed by any valid record, which is real corruption, not a crash (fail
//!   safe: valid data is never dropped silently). Such a file is repaired only
//!   on the operator's request ([`FileStore::repair`]), which keeps the
//!   damaged part aside.
//! - A store that failed permanently reports it ([`BlockStore::failed`]); the
//!   chain manager then stops accepting blocks and the node exits, so a
//!   restart recovers deterministically.

use blacksilk_consensus::Hash;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"BSB1";
const RECORD_HEADER: usize = 12;
const FILE_MAGIC: &[u8; 4] = b"BSBH";
/// Current `blocks.dat` format version (0 = legacy file without a header).
pub const FORMAT_VERSION: u32 = 1;
/// Length of the file header.
pub const FILE_HEADER: usize = 48;
/// Upper bound on a record payload (32-byte PoW hash plus a maximum-size block).
const MAX_PAYLOAD: usize = 32 + crate::block::MAX_BLOCK_BYTES;

/// A stored block: the PoW hash computed when its header was accepted, and the
/// block's bytes.
pub type StoredBlock = (Hash, Vec<u8>);

pub trait BlockStore: Send {
    /// Appends a block durably (returns only after the data is on disk).
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()>;
    /// All stored blocks in insertion order.
    fn load(&mut self) -> io::Result<Vec<StoredBlock>>;
    /// Binds the store to a network before `load`: a new store records the
    /// network id and genesis id; an existing store naming another network or
    /// genesis is refused (`InvalidData`). The default accepts anything (a
    /// store without an identity).
    fn bind(&mut self, network_id: u32, genesis_id: &Hash) -> io::Result<()> {
        let _ = (network_id, genesis_id);
        Ok(())
    }
    /// Whether the store has failed permanently (a failed append could not be
    /// undone): every further append fails until the node restarts.
    fn failed(&self) -> bool {
        false
    }
}

/// Volatile store for tests and regtest experiments.
#[derive(Default)]
pub struct MemoryStore {
    records: Vec<StoredBlock>,
    identity: Option<(u32, Hash)>,
}

impl BlockStore for MemoryStore {
    fn bind(&mut self, network_id: u32, genesis_id: &Hash) -> io::Result<()> {
        match self.identity {
            Some(id) if id != (network_id, *genesis_id) => Err(corrupt(
                "memory store belongs to another network or genesis".into(),
            )),
            _ => {
                self.identity = Some((network_id, *genesis_id));
                Ok(())
            }
        }
    }

    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        self.records.push((*pow_hash, block.to_vec()));
        Ok(())
    }

    fn load(&mut self) -> io::Result<Vec<StoredBlock>> {
        Ok(self.records.clone())
    }
}

/// `blocks.dat` in the node's data directory.
pub struct FileStore {
    path: PathBuf,
    file: File,
    /// A failed append could not be undone: refuse further appends.
    poisoned: bool,
    /// Format version found or written by `bind` (0: legacy or not bound).
    version: u32,
    /// Test hooks: fail the next append after writing this many bytes, and
    /// fail the truncation that undoes it.
    #[cfg(test)]
    fail_after: Option<usize>,
    #[cfg(test)]
    fail_undo: bool,
}

impl FileStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Read/write rather than append mode: truncating a damaged tail needs write
        // access to the file data (on Windows append-only handles cannot truncate).
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            poisoned: false,
            version: 0,
            #[cfg(test)]
            fail_after: None,
            #[cfg(test)]
            fail_undo: false,
        })
    }

    /// Operator repair of a store that `load` refuses because of damage
    /// followed by valid records. Everything from the first damaged record on
    /// is moved to `<path>.damaged-<unix time>` (synced to disk first) and the
    /// store is truncated there; the node then downloads the dropped blocks
    /// again. Every valid record before the first damaged one is kept.
    ///
    /// Returns the number of bytes set aside: 0 if the store is undamaged or
    /// does not exist yet (a fresh data directory).
    pub fn repair(path: impl AsRef<Path>, unix_time: u64) -> io::Result<u64> {
        let path = path.as_ref();
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let pos = valid_prefix(&data);
        if pos == data.len() {
            return Ok(0);
        }
        let aside = path.with_extension(format!("dat.damaged-{unix_time}"));
        {
            // `create_new`: never overwrite an earlier set-aside file.
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&aside)?;
            f.write_all(&data[pos..])?;
            // The set-aside copy must be durable before the store loses the bytes.
            f.sync_all()?;
        }
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(pos as u64)?;
        f.sync_all()?;
        log::warn!(
            "{}: {} damaged or unreadable bytes from offset {pos} moved to {}",
            path.display(),
            data.len() - pos,
            aside.display()
        );
        Ok((data.len() - pos) as u64)
    }

    /// Writes `record` at the end of the file and syncs it.
    fn write_record(&mut self, record: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(n) = self.fail_after.take() {
            self.file.write_all(&record[..n.min(record.len())])?;
            return Err(io::Error::other("injected write failure"));
        }
        self.file.write_all(record)?;
        self.file.sync_data()
    }

    /// Truncates the file back to `len` after a failed append.
    fn undo(&mut self, len: u64) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_undo {
            return Err(io::Error::other("injected truncation failure"));
        }
        self.file.set_len(len)?;
        self.file.sync_data()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The format version: [`FORMAT_VERSION`] for a store with a file header,
    /// 0 for a legacy headerless store (or before [`BlockStore::bind`]).
    pub fn format_version(&self) -> u32 {
        self.version
    }
}

/// The file header for a network.
fn encode_file_header(network_id: u32, genesis_id: &Hash) -> [u8; FILE_HEADER] {
    let mut h = [0u8; FILE_HEADER];
    h[..4].copy_from_slice(FILE_MAGIC);
    h[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h[8..12].copy_from_slice(&network_id.to_le_bytes());
    h[12..44].copy_from_slice(genesis_id);
    let crc = crc32fast::hash(&h[..44]);
    h[44..].copy_from_slice(&crc.to_le_bytes());
    h
}

/// Length of a valid file header at the start of `data` (0 if there is none:
/// a legacy store). Records start there.
fn header_len(data: &[u8]) -> usize {
    if data.len() >= FILE_HEADER
        && &data[..4] == FILE_MAGIC
        && crc32fast::hash(&data[..44]).to_le_bytes() == data[44..48]
    {
        FILE_HEADER
    } else {
        0
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn corrupt(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl BlockStore for FileStore {
    /// Writes the file header into a new (empty) store, or checks an existing
    /// one. A torn header (a crash while the store was created, so no record
    /// follows) is written again. A headerless store is a legacy store: it is
    /// accepted unchanged, with a warning.
    fn bind(&mut self, network_id: u32, genesis_id: &Hash) -> io::Result<()> {
        let expected = encode_file_header(network_id, genesis_id);
        let mut head = Vec::with_capacity(FILE_HEADER);
        self.file.seek(SeekFrom::Start(0))?;
        (&mut self.file)
            .take(FILE_HEADER as u64)
            .read_to_end(&mut head)?;
        if head.len() < FILE_HEADER && expected.starts_with(&head) {
            // New store, or its header write was torn: nothing else is in it.
            self.file.set_len(0)?;
            self.file.seek(SeekFrom::Start(0))?;
            self.file.write_all(&expected)?;
            self.file.sync_all()?;
            self.version = FORMAT_VERSION;
            return Ok(());
        }
        if !head.starts_with(FILE_MAGIC) {
            log::warn!(
                "{}: legacy block store without a file header (format 0); its network \
                 cannot be verified. It is used as it is",
                self.path.display()
            );
            self.version = 0;
            return Ok(());
        }
        if header_len(&head) != FILE_HEADER {
            return Err(corrupt(format!(
                "{}: damaged file header",
                self.path.display()
            )));
        }
        let version = u32::from_le_bytes(head[4..8].try_into().expect("4 bytes"));
        if version != FORMAT_VERSION {
            return Err(corrupt(format!(
                "{}: unsupported block store format version {version}",
                self.path.display()
            )));
        }
        let net = u32::from_le_bytes(head[8..12].try_into().expect("4 bytes"));
        if head[8..44] != expected[8..44] {
            return Err(corrupt(format!(
                "{}: wrong network data directory: this block store belongs to network \
                 id {net:#010x} with genesis {}, but the node runs network id \
                 {network_id:#010x} with genesis {}. Use a separate data directory \
                 for each network (or remove the store of an old network)",
                self.path.display(),
                hex(&head[12..44]),
                hex(genesis_id)
            )));
        }
        self.version = FORMAT_VERSION;
        Ok(())
    }

    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        let record = encode_record(pow_hash, block);
        if self.poisoned {
            return Err(io::Error::other(
                "block store refuses writes after a failed write that could not be undone; \
                 restart the node",
            ));
        }
        let len = self.file.seek(SeekFrom::End(0))?;
        if let Err(e) = self.write_record(&record) {
            // Undo the partial record: a later record after damaged bytes would
            // make the whole store refuse to load at the next start.
            if let Err(u) = self.undo(len) {
                self.poisoned = true;
                log::error!(
                    "{}: a failed write ({e}) could not be undone ({u}); no further blocks \
                     are stored until restart",
                    self.path.display()
                );
            }
            return Err(e);
        }
        Ok(())
    }

    /// Reads every record. A damaged final region (a crash mid-write) is
    /// truncated away with a warning. Damage followed by **any** later valid
    /// record is an error: silently dropping blocks in the middle would hide
    /// real corruption (the operator repairs it with [`FileStore::repair`]).
    ///
    /// Cost is linear: every record is parsed once, and after the first damage
    /// each later `MAGIC` position is parsed at most once.
    fn load(&mut self) -> io::Result<Vec<StoredBlock>> {
        let mut data = Vec::new();
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut data)?;
        let mut out = Vec::new();
        let mut pos = header_len(&data);
        while pos < data.len() {
            match parse_record(&data[pos..]) {
                Ok((payload, used)) => {
                    let mut pow = [0u8; 32];
                    pow.copy_from_slice(&payload[..32]);
                    out.push((pow, payload[32..].to_vec()));
                    pos += used;
                }
                Err(e) => {
                    // Fail safe: a valid record anywhere after the damage means
                    // this is not (only) a torn tail. This also refuses a torn
                    // last block whose data embeds a record-shaped byte string
                    // (block data is partly user-chosen); `repair` recovers such
                    // a file without losing any valid record, because there the
                    // damaged region is the tail.
                    if let Some(at) = next_valid_record(&data, pos + 1) {
                        return Err(corrupt(format!(
                            "{}: corrupt record at offset {pos} ({e}) followed by valid data \
                             (a record at offset {at})",
                            self.path.display()
                        )));
                    }
                    log::warn!(
                        "{}: truncating damaged tail at offset {pos} ({e}); {} bytes dropped",
                        self.path.display(),
                        data.len() - pos
                    );
                    self.file.set_len(pos as u64)?;
                    self.file.sync_all()?;
                    break;
                }
            }
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(out)
    }

    fn failed(&self) -> bool {
        self.poisoned
    }
}

fn encode_record(pow_hash: &Hash, block: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + block.len());
    payload.extend_from_slice(pow_hash);
    payload.extend_from_slice(block);
    let mut record = Vec::with_capacity(RECORD_HEADER + payload.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Length of the longest prefix of `data` made of valid records.
fn valid_prefix(data: &[u8]) -> usize {
    let mut pos = header_len(data);
    while pos < data.len() {
        match parse_record(&data[pos..]) {
            Ok((_, used)) => pos += used,
            Err(_) => break,
        }
    }
    pos
}

/// Offset of the first valid record starting at or after `from`. Each
/// position holding `MAGIC` is parsed once, so the scan is linear in the data
/// plus the checksummed payloads of the candidates.
fn next_valid_record(data: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at + MAGIC.len() <= data.len() {
        let off = data[at..].windows(MAGIC.len()).position(|w| w == MAGIC)?;
        at += off;
        if parse_record(&data[at..]).is_ok() {
            return Some(at);
        }
        at += 1;
    }
    None
}

fn parse_record(data: &[u8]) -> Result<(&[u8], usize), &'static str> {
    if data.len() < RECORD_HEADER {
        return Err("short header");
    }
    if &data[..4] != MAGIC {
        return Err("bad magic");
    }
    let len = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) as usize;
    if !(32..=MAX_PAYLOAD).contains(&len) {
        return Err("bad length");
    }
    let crc = u32::from_le_bytes(data[8..12].try_into().expect("4 bytes"));
    let end = RECORD_HEADER + len;
    if data.len() < end {
        return Err("short payload");
    }
    let payload = &data[RECORD_HEADER..end];
    if crc32fast::hash(payload) != crc {
        return Err("checksum mismatch");
    }
    Ok((payload, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(store: &mut dyn BlockStore, n: u8) {
        for i in 0..n {
            store.append(&[i; 32], &vec![i; 10 + i as usize]).unwrap();
        }
    }

    #[test]
    fn round_trip_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 5);
        }
        let mut s = FileStore::open(&path).unwrap();
        let recs = s.load().unwrap();
        assert_eq!(recs.len(), 5);
        assert_eq!(recs[3], ([3; 32], vec![3; 13]));
        // Appending after a load continues the log.
        s.append(&[9; 32], b"more").unwrap();
        assert_eq!(FileStore::open(&path).unwrap().load().unwrap().len(), 6);
    }

    #[test]
    fn torn_tail_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 3);
        }
        let full = std::fs::metadata(&path).unwrap().len();
        // Simulate a crash in the middle of writing the last record.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(full - 5).unwrap();
        drop(f);
        let mut s = FileStore::open(&path).unwrap();
        assert_eq!(s.load().unwrap().len(), 2);
        // The damaged bytes are gone; the log is appendable again.
        s.append(&[7; 32], b"x").unwrap();
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[2].1, b"x");
    }

    #[test]
    fn corruption_in_the_middle_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 3);
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[RECORD_HEADER + 40] ^= 0xff; // inside the first payload
        std::fs::write(&path, &bytes).unwrap();
        let err = FileStore::open(&path).unwrap().load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Nothing was truncated.
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    /// A failed append leaves no bytes behind: later appends and a restart work.
    /// Before 2026-09-27 the partial record stayed, the next block was appended
    /// after it, and the node refused to start ("corrupt record followed by
    /// valid data").
    #[test]
    fn a_failed_append_is_undone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = FileStore::open(&path).unwrap();
        fill(&mut s, 3);
        let len = std::fs::metadata(&path).unwrap().len();
        s.fail_after = Some(20);
        assert!(s.append(&[8; 32], &[8; 500]).is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "partial record removed"
        );
        s.append(&[9; 32], b"next").unwrap();
        drop(s);
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[3], ([9; 32], b"next".to_vec()));
    }

    /// If the partial record cannot be removed, no further record is written,
    /// so the damage stays the file's tail and a restart truncates it.
    #[test]
    fn a_failed_append_that_cannot_be_undone_stops_writes_until_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = FileStore::open(&path).unwrap();
        fill(&mut s, 3);
        s.fail_after = Some(20);
        s.fail_undo = true;
        assert!(s.append(&[8; 32], &[8; 500]).is_err());
        assert!(
            s.append(&[9; 32], b"next").is_err(),
            "refused while poisoned"
        );
        drop(s);
        let mut s = FileStore::open(&path).unwrap();
        assert_eq!(s.load().unwrap().len(), 3, "the damaged tail is truncated");
        s.append(&[9; 32], b"next").unwrap();
        assert_eq!(FileStore::open(&path).unwrap().load().unwrap().len(), 4);
    }

    /// A torn last record whose data contains a record-shaped byte string
    /// (block data is partly chosen by users) cannot be told apart from damage
    /// followed by valid data, so the fail-safe rule refuses it. `repair` then
    /// recovers it without losing any valid record: the damaged region is the
    /// tail. (Until 2026-09-27 such a file was truncated on load, but the rule
    /// that allowed it could also drop valid records silently.)
    #[test]
    fn a_record_embedded_in_a_torn_tail_is_refused_then_repaired_without_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut inner = Vec::new();
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 2);
            // A block whose data embeds a complete, valid record.
            let fake_payload = [5u8; 40];
            inner.extend_from_slice(MAGIC);
            inner.extend_from_slice(&(fake_payload.len() as u32).to_le_bytes());
            inner.extend_from_slice(&crc32fast::hash(&fake_payload).to_le_bytes());
            inner.extend_from_slice(&fake_payload);
            let mut data = vec![1u8; 100];
            data.extend_from_slice(&inner);
            data.extend_from_slice(&[2u8; 300]);
            s.append(&[7; 32], &data).unwrap();
        }
        // Tear the last record after the embedded record.
        let full = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(full - 150).unwrap();
        drop(f);
        let torn = std::fs::read(&path).unwrap();
        let err = FileStore::open(&path).unwrap().load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), torn, "nothing truncated");
        let aside = FileStore::repair(&path, 42).unwrap();
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        assert_eq!(recs.len(), 2, "both valid records kept");
        assert_eq!(recs[1], ([1; 32], vec![1; 11]));
        assert_eq!(aside as usize, torn.len() - valid_prefix(&torn));
        assert_eq!(
            std::fs::read(path.with_extension("dat.damaged-42")).unwrap(),
            torn[torn.len() - aside as usize..]
        );
    }

    /// The case the 2026-09-27 rule got wrong: a bit flip in the middle of
    /// the file plus a torn last record. Every record after the flip is valid,
    /// so the file is refused (not truncated), and quickly: the old rule
    /// re-parsed the rest of the file from every later byte (quadratic) and
    /// then truncated everything after the flip.
    #[test]
    fn mid_file_corruption_and_a_torn_tail_are_refused_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        const N: usize = 20_000;
        // Built in memory: 20 000 synced appends would only measure fsync.
        let mut bytes = Vec::new();
        for i in 0..N {
            bytes.extend(encode_record(
                &[(i % 251) as u8; 32],
                &(i as u64).to_le_bytes(),
            ));
        }
        let rec = RECORD_HEADER + 32 + 8;
        assert_eq!(bytes.len(), N * rec);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(FileStore::open(&path).unwrap().load().unwrap().len(), N);
        bytes[10 * rec + RECORD_HEADER + 3] ^= 0x01; // record 10's payload
        bytes.truncate(bytes.len() - 7); // torn last record
        std::fs::write(&path, &bytes).unwrap();

        let started = std::time::Instant::now();
        let err = FileStore::open(&path).unwrap().load().unwrap_err();
        let took = started.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(&format!("offset {}", 10 * rec)));
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing truncated");
        assert!(
            took < std::time::Duration::from_secs(2),
            "load took {took:?}"
        );

        // The operator's repair keeps the valid prefix (records 0..10).
        let started = std::time::Instant::now();
        let aside = FileStore::repair(&path, 7).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(aside as usize, bytes.len() - 10 * rec);
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        assert_eq!(recs.len(), 10);
        assert_eq!(recs[9].1, 9u64.to_le_bytes());
    }

    /// A long damaged tail full of record-shaped candidates (MAGIC with bad
    /// lengths or checksums) is truncated in linear time.
    #[test]
    fn a_long_damaged_tail_of_record_candidates_is_truncated_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 3);
        }
        let good = std::fs::metadata(&path).unwrap().len() as usize;
        let mut bytes = std::fs::read(&path).unwrap();
        // 4 MiB of candidates claiming 64-byte payloads with a wrong checksum.
        let mut cand = Vec::new();
        cand.extend_from_slice(MAGIC);
        cand.extend_from_slice(&64u32.to_le_bytes());
        cand.extend_from_slice(&0u32.to_le_bytes());
        while bytes.len() < good + (4 << 20) {
            bytes.extend_from_slice(&cand);
        }
        std::fs::write(&path, &bytes).unwrap();
        let started = std::time::Instant::now();
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        let took = started.elapsed();
        assert_eq!(recs.len(), 3);
        assert_eq!(std::fs::metadata(&path).unwrap().len() as usize, good);
        assert!(
            took < std::time::Duration::from_secs(2),
            "load took {took:?}"
        );
    }

    /// Repair on a fresh data directory (no store yet) has nothing to do.
    #[test]
    fn repair_of_a_missing_store_is_nothing_to_repair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        assert_eq!(FileStore::repair(&path, 1).unwrap(), 0);
        assert!(!path.exists(), "repair does not create the store");
    }

    /// A store whose failed append could not be undone reports it.
    #[test]
    fn a_poisoned_store_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = FileStore::open(&path).unwrap();
        fill(&mut s, 1);
        assert!(!s.failed());
        s.fail_after = Some(5);
        assert!(s.append(&[8; 32], b"x").is_err());
        assert!(!s.failed(), "undone: not failed");
        s.fail_after = Some(5);
        s.fail_undo = true;
        assert!(s.append(&[8; 32], b"x").is_err());
        assert!(s.failed());
    }

    /// Real corruption followed by valid records is refused, and repaired only
    /// on request, keeping the damaged part aside.
    #[test]
    fn corruption_in_the_middle_is_repaired_only_on_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 4);
        }
        let mut bytes = std::fs::read(&path).unwrap();
        let second = RECORD_HEADER + 32 + 10; // start of the second record
        bytes[second + RECORD_HEADER + 5] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(FileStore::open(&path).unwrap().load().is_err());
        let aside = FileStore::repair(&path, 1_234).unwrap();
        assert_eq!(aside as usize, bytes.len() - second);
        assert_eq!(
            std::fs::read(path.with_extension("dat.damaged-1234")).unwrap(),
            bytes[second..]
        );
        assert_eq!(FileStore::open(&path).unwrap().load().unwrap().len(), 1);
        assert_eq!(
            FileStore::repair(&path, 1_235).unwrap(),
            0,
            "nothing more to repair"
        );
    }

    // ------------------------------------------------------------ file header

    const NET: u32 = 0x0001_D672;
    const GENESIS: Hash = [0x42; 32];

    /// A new store starts with the file header; it reopens under the same
    /// network with every record, and refuses another network or genesis
    /// without touching the file.
    #[test]
    fn a_new_store_is_bound_to_its_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            s.bind(NET, &GENESIS).unwrap();
            assert_eq!(s.format_version(), FORMAT_VERSION);
            assert!(s.load().unwrap().is_empty());
            fill(&mut s, 3);
        }
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..FILE_HEADER], &encode_file_header(NET, &GENESIS));
        let mut s = FileStore::open(&path).unwrap();
        s.bind(NET, &GENESIS).unwrap();
        let recs = s.load().unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[2], ([2; 32], vec![2; 12]));

        for (net, genesis) in [(NET + 1, GENESIS), (NET, [0x43; 32])] {
            let err = FileStore::open(&path)
                .unwrap()
                .bind(net, &genesis)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("wrong network data directory"));
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
    }

    /// A store written before the file header existed (format 0) is accepted
    /// as it is and stays headerless: records load, appends continue.
    #[test]
    fn a_legacy_headerless_store_is_accepted_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            fill(&mut s, 3); // never bound: the legacy layout
        }
        let legacy = std::fs::read(&path).unwrap();
        assert_eq!(&legacy[..4], MAGIC);
        let mut s = FileStore::open(&path).unwrap();
        s.bind(NET, &GENESIS).unwrap();
        assert_eq!(s.format_version(), 0);
        assert_eq!(s.load().unwrap().len(), 3);
        s.append(&[9; 32], b"new").unwrap();
        let now = std::fs::read(&path).unwrap();
        assert_eq!(&now[..legacy.len()], &legacy[..], "nothing rewritten");
        let mut s = FileStore::open(&path).unwrap();
        s.bind(NET + 1, &GENESIS).unwrap(); // a legacy store cannot be checked
        assert_eq!(s.load().unwrap().len(), 4);
    }

    /// A damaged header is refused (fail safe); a header torn while the store
    /// was being created (no record after it) is written again; a torn record
    /// after a good header is truncated as usual; repair keeps the header.
    #[test]
    fn damaged_and_torn_file_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = FileStore::open(&path).unwrap();
            s.bind(NET, &GENESIS).unwrap();
            fill(&mut s, 2);
        }
        let good = std::fs::read(&path).unwrap();
        let mut bad = good.clone();
        bad[20] ^= 1; // inside the genesis id
        std::fs::write(&path, &bad).unwrap();
        let err = FileStore::open(&path)
            .unwrap()
            .bind(NET, &GENESIS)
            .unwrap_err();
        assert!(err.to_string().contains("damaged file header"));
        // Unsupported version (with a valid checksum).
        let mut v2 = good.clone();
        v2[4..8].copy_from_slice(&2u32.to_le_bytes());
        let crc = crc32fast::hash(&v2[..44]);
        v2[44..48].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, &v2).unwrap();
        let err = FileStore::open(&path)
            .unwrap()
            .bind(NET, &GENESIS)
            .unwrap_err();
        assert!(err.to_string().contains("version 2"));

        // Torn header on creation.
        for cut in [1, 4, 30, FILE_HEADER - 1] {
            std::fs::write(&path, &good[..cut]).unwrap();
            let mut s = FileStore::open(&path).unwrap();
            s.bind(NET, &GENESIS).unwrap();
            assert!(s.load().unwrap().is_empty());
            assert_eq!(std::fs::read(&path).unwrap(), &good[..FILE_HEADER]);
        }

        // A torn last record after the header.
        std::fs::write(&path, &good[..good.len() - 3]).unwrap();
        let mut s = FileStore::open(&path).unwrap();
        s.bind(NET, &GENESIS).unwrap();
        assert_eq!(s.load().unwrap().len(), 1);
        drop(s);

        // Mid-file corruption after the header: repair keeps header and prefix.
        std::fs::write(&path, &good).unwrap();
        let mut bytes = good.clone();
        bytes[FILE_HEADER + RECORD_HEADER + 3] ^= 0xff; // first record's payload
        std::fs::write(&path, &bytes).unwrap();
        assert!(FileStore::open(&path).unwrap().load().is_err());
        FileStore::repair(&path, 5).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), &good[..FILE_HEADER]);
        let mut s = FileStore::open(&path).unwrap();
        s.bind(NET, &GENESIS).unwrap();
        assert!(s.load().unwrap().is_empty());
    }

    #[test]
    fn a_memory_store_is_bound_too() {
        let mut s = MemoryStore::default();
        s.bind(NET, &GENESIS).unwrap();
        s.bind(NET, &GENESIS).unwrap();
        assert!(s.bind(NET, &[0; 32]).is_err());
    }
}
