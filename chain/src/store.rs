//! Block storage (docs/blocks.md §8): an append-only log of accepted blocks.
//!
//! ```text
//! record  = "BSB1" ‖ LE32 length ‖ LE32 crc32(payload) ‖ payload
//! payload = pow_hash (32) ‖ block bytes
//! ```

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
        Ok(Self { path, file })
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
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&record)?;
        self.file.sync_data()
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
                    // Is this the tail? Only if no valid record follows anywhere after it.
                    let rest = &data[pos + 1..];
                    let later_valid = (0..rest.len())
                        .any(|i| rest[i..].starts_with(MAGIC) && parse_record(&rest[i..]).is_ok());
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
}
