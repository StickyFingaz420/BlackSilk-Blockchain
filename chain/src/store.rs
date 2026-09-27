//! Block storage (docs/blocks.md §8): an append-only log of accepted blocks.
//!
//! ```text
//! record  = "BSB1" ‖ LE32 length ‖ LE32 crc32(payload) ‖ payload
//! payload = pow_hash (32) ‖ block bytes
//! ```
//!
//! **Failure behaviour** (docs/blocks.md §8):
//! - A record is durable when `append` returns (`sync_data`).
//! - A failed append (disk full, I/O error) is undone: the file is truncated
//!   back to its previous length, so no record ever follows damaged bytes. If
//!   even that fails, the store refuses further appends until the node
//!   restarts; the damaged bytes are then the file's tail, which `load`
//!   truncates.
//! - `load` truncates a damaged **tail** (a crash mid-write) and refuses damage
//!   followed by valid records, which is real corruption, not a crash. Such a
//!   file is repaired only on the operator's request ([`FileStore::repair`]),
//!   which keeps the damaged part aside.

use blacksilk_consensus::Hash;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"BSB1";
const RECORD_HEADER: usize = 12;
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
}

/// Volatile store for tests and regtest experiments.
#[derive(Default)]
pub struct MemoryStore {
    records: Vec<StoredBlock>,
}

impl BlockStore for MemoryStore {
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
            #[cfg(test)]
            fail_after: None,
            #[cfg(test)]
            fail_undo: false,
        })
    }

    /// Operator repair of a store that `load` refuses because of damage
    /// followed by valid records. Everything from the first damaged record on
    /// is moved to `<path>.damaged-<unix time>` and the store is truncated
    /// there; the node then downloads the dropped blocks again.
    ///
    /// Returns the number of bytes set aside (0 if the store is undamaged).
    pub fn repair(path: impl AsRef<Path>, unix_time: u64) -> io::Result<u64> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        let mut pos = 0usize;
        while pos < data.len() {
            match parse_record(&data[pos..]) {
                Ok((_, used)) => pos += used,
                Err(_) => break,
            }
        }
        if pos == data.len() {
            return Ok(0);
        }
        let aside = path.with_extension(format!("dat.damaged-{unix_time}"));
        std::fs::write(&aside, &data[pos..])?;
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
}

fn corrupt(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl BlockStore for FileStore {
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        let mut payload = Vec::with_capacity(32 + block.len());
        payload.extend_from_slice(pow_hash);
        payload.extend_from_slice(block);
        let mut record = Vec::with_capacity(RECORD_HEADER + payload.len());
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        record.extend_from_slice(&payload);
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

    /// Reads every record. A damaged *last* record (a crash mid-write) is truncated
    /// away with a warning. Damage anywhere else is an error: silently dropping
    /// blocks in the middle would hide real corruption.
    fn load(&mut self) -> io::Result<Vec<StoredBlock>> {
        let mut data = Vec::new();
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut data)?;
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let parsed = parse_record(&data[pos..]);
            match parsed {
                Ok((payload, used)) => {
                    let mut pow = [0u8; 32];
                    pow.copy_from_slice(&payload[..32]);
                    out.push((pow, payload[32..].to_vec()));
                    pos += used;
                }
                Err(e) => {
                    // Is this the tail? Only if nothing after it is a run of valid
                    // records reaching the end of the file. Requiring the run to
                    // reach the end keeps a record-shaped byte string embedded in
                    // a torn block (block data is partly user-chosen) from
                    // passing for later data.
                    let rest = &data[pos + 1..];
                    let later_valid = (0..rest.len())
                        .any(|i| rest[i..].starts_with(MAGIC) && valid_to_end(&rest[i..]));
                    if later_valid {
                        return Err(corrupt(format!(
                            "{}: corrupt record at offset {pos} ({e}) followed by valid data",
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
}

/// Whether `data` is a sequence of valid records ending exactly at its end.
fn valid_to_end(mut data: &[u8]) -> bool {
    while !data.is_empty() {
        match parse_record(data) {
            Ok((_, used)) => data = &data[used..],
            Err(_) => return false,
        }
    }
    true
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

    /// A torn last record whose data contains a record-shaped byte string is
    /// still a torn tail (block data is partly chosen by users).
    #[test]
    fn a_record_embedded_in_a_torn_tail_does_not_block_restart() {
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
        let recs = FileStore::open(&path).unwrap().load().unwrap();
        assert_eq!(recs.len(), 2, "treated as a torn tail");
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
}
