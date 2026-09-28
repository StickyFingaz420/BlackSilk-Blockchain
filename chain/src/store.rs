//! Block storage (docs/blocks.md §8): an append-only log of typed records.
//!
//! ```text
//! file    = file header ‖ record*
//! header  = "BSBH" ‖ LE32 version (2) ‖ LE32 network_id ‖ genesis_id (32)
//!           ‖ LE32 crc32(the 44 bytes before)                        (48 bytes)
//! record  = "BSR2" ‖ LE32 n ‖ LE32 crc32(LE32 n ‖ body) ‖ body       (n = |body|)
//! body    = type (1) ‖ payload
//!   0x01 block       payload = pow_hash (32) ‖ block bytes
//!   0x02 invalid     payload = block id (32) ‖ origin (1) ‖ LE16 k ‖ reason (k ≤ 256, UTF-8)
//!   0x03 reconsider  payload = block id (32)
//!   0x81 checkpoint  payload = tip id (32) ‖ LE64 height ‖ state digest (32)
//!                              ‖ consensus fingerprint (32) ‖ LE16 k ‖ build commit (k ≤ 64, UTF-8)
//! ```
//!
//! A type with bit 7 set is **advisory**: ignoring it never changes the chain
//! a replay reaches (a checkpoint only lets a later build skip work), so a
//! reader that does not know it skips it. Any other unknown type is refused:
//! the store was written by a newer build whose records this one cannot
//! honour. A record whose checksum holds but whose body is malformed is
//! refused too; it is never skipped.
//!
//! **Operator verdicts** (`--invalidate-block`, `--reconsider-block`): an
//! `invalid` record of origin "operator" rules a block out; a later
//! `reconsider` record for the same id cancels it (the last of the two for
//! an id wins). Both are critical: a build that ignored them would connect
//! a block the operator ruled out, or keep refusing one reconsidered.
//!
//! **Reserved:** type `0x82` for the F48-5 quarantine record ("validating
//! <block id>", written before a body is validated and cleared after, so a
//! start after a crash during validation halts naming the suspect block
//! instead of looping). It is advisory (ignoring it only means validating
//! the block again) and not written or read by this build.
//!
//! **Network identity** ([`BlockStore::bind`], called by the chain manager
//! before `load`): a new store is created with the file header; an existing
//! one is refused if it names another network or genesis ("wrong network data
//! directory"), so a store left over from an earlier testnet is detected
//! instead of being replayed into (and silently orphaned by) a new genesis.
//!
//! **Older formats** are never migrated (docs/blocks.md §8):
//! - format 0 (no file header, written before 2026-09-27): its network cannot
//!   be verified, and every such store belongs to a network from before the
//!   v3 reset. It is refused on testnet and mainnet (F35-1). On regtest it is
//!   still read and appended to as it is (blocks only, in its own record
//!   layout), with a warning;
//! - format 1 (file header, untyped `"BSB1"` block records; pre-freeze labnet
//!   stores): refused on every network with resync advice.
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
//!   damaged part aside and the operator's verdicts in the store.
//! - A store that failed permanently reports it ([`BlockStore::failed`]); the
//!   chain manager then stops accepting blocks and the node exits, so a
//!   restart recovers deterministically.

use blacksilk_consensus::{ChainParams, Hash, Network};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const FILE_MAGIC: &[u8; 4] = b"BSBH";
/// Current `blocks.dat` format version (0 = legacy file without a header,
/// 1 = untyped records).
pub const FORMAT_VERSION: u32 = 2;
/// Length of the file header.
pub const FILE_HEADER: usize = 48;
/// Length of a record's frame header (magic, length, checksum).
const RECORD_HEADER: usize = 12;
/// Largest block a record holds.
const MAX_BLOCK: usize = crate::block::MAX_BLOCK_BYTES;

/// Record type of a stored block (critical).
const TYPE_BLOCK: u8 = 0x01;
/// Record type of an invalid-block marker (critical).
const TYPE_INVALID: u8 = 0x02;
/// Record type of an operator's reconsider marker (critical).
const TYPE_RECONSIDER: u8 = 0x03;
/// Record type of a validation checkpoint (advisory).
const TYPE_CHECKPOINT: u8 = 0x81;
/// Reserved record type of the F48-5 quarantine marker (advisory; not
/// written by this build and skipped when read, see the module docs).
const TYPE_QUARANTINE_RESERVED: u8 = 0x82;
/// Bit set in the type of every advisory record.
const ADVISORY: u8 = 0x80;
/// Longest reason text of an invalid marker.
pub const MAX_REASON: usize = 256;
/// Longest build commit text of a checkpoint.
pub const MAX_BUILD_COMMIT: usize = 64;

/// A stored block: the PoW hash computed when its header was accepted, and the
/// block's bytes.
pub type StoredBlock = (Hash, Vec<u8>);

/// Who marked a block invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidOrigin {
    /// The node's own validation verdict: deterministic, so a replay that
    /// validates the block again reaches the same verdict.
    Verdict,
    /// The operator (a node flag): the block must not be connected even
    /// though it may be valid by the rules.
    Operator,
}

/// A marker that a stored block is invalid (docs/blocks.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidMarker {
    pub id: Hash,
    pub origin: InvalidOrigin,
    /// Human-readable reason, at most [`MAX_REASON`] bytes.
    pub reason: String,
}

/// A validation checkpoint: the node's own record that the chain up to
/// `tip_id` was fully validated by a given build (docs/blocks.md §8). This
/// build writes none and trusts none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub tip_id: Hash,
    pub height: u64,
    pub state_digest: Hash,
    pub fingerprint: Hash,
    /// At most [`MAX_BUILD_COMMIT`] bytes.
    pub build_commit: String,
}

/// A non-block record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Marker {
    Invalid(InvalidMarker),
    /// The operator reconsiders the block with this id: an earlier
    /// operator [`Marker::Invalid`] for it no longer applies
    /// (`--reconsider-block`). Rule verdicts are not affected.
    Reconsider(Hash),
    Checkpoint(Checkpoint),
}

/// One record of the log, as `load` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Block(StoredBlock),
    Marker(Marker),
}

/// The network a store belongs to ([`BlockStore::bind`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    pub network: Network,
    pub network_id: u32,
    pub genesis_id: Hash,
}

impl StoreIdentity {
    pub fn of(params: &ChainParams) -> Self {
        Self {
            network: params.network,
            network_id: params.network_id,
            genesis_id: params.genesis_id(),
        }
    }
}

pub trait BlockStore: Send {
    /// Appends a block durably (returns only after the data is on disk).
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()>;
    /// Appends a marker durably. The default refuses (a store without
    /// markers).
    fn append_marker(&mut self, marker: &Marker) -> io::Result<()> {
        let _ = marker;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this block store keeps no markers",
        ))
    }
    /// All stored records in insertion order.
    fn load(&mut self) -> io::Result<Vec<Record>>;
    /// Binds the store to a network before `load`: a new store records the
    /// network id and genesis id; an existing store naming another network or
    /// genesis, or of an unsupported format, is refused (`InvalidData`). The
    /// default accepts anything (a store without an identity).
    fn bind(&mut self, identity: &StoreIdentity) -> io::Result<()> {
        let _ = identity;
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
    records: Vec<Record>,
    identity: Option<(u32, Hash)>,
}

impl BlockStore for MemoryStore {
    fn bind(&mut self, identity: &StoreIdentity) -> io::Result<()> {
        let id = (identity.network_id, identity.genesis_id);
        match self.identity {
            Some(known) if known != id => Err(corrupt(
                "memory store belongs to another network or genesis".into(),
            )),
            _ => {
                self.identity = Some(id);
                Ok(())
            }
        }
    }

    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        self.records
            .push(Record::Block((*pow_hash, block.to_vec())));
        Ok(())
    }

    fn append_marker(&mut self, marker: &Marker) -> io::Result<()> {
        self.records.push(Record::Marker(marker.clone()));
        Ok(())
    }

    fn load(&mut self) -> io::Result<Vec<Record>> {
        Ok(self.records.clone())
    }
}

/// The record layout of a store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    /// Format 2: typed records ("BSR2").
    Typed,
    /// Format 0 on regtest only: untyped block records ("BSB1").
    Legacy,
}

impl Codec {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            Codec::Typed => b"BSR2",
            Codec::Legacy => b"BSB1",
        }
    }

    /// The accepted body lengths.
    fn lengths(self) -> std::ops::RangeInclusive<usize> {
        match self {
            // The type byte, then at most a block record's payload.
            Codec::Typed => 1..=1 + 32 + MAX_BLOCK,
            Codec::Legacy => 32..=32 + MAX_BLOCK,
        }
    }

    fn checksum(self, body: &[u8]) -> u32 {
        match self {
            // The length is covered too: a damaged length cannot select
            // another body that happens to check.
            Codec::Typed => {
                let mut h = crc32fast::Hasher::new();
                h.update(&(body.len() as u32).to_le_bytes());
                h.update(body);
                h.finalize()
            }
            Codec::Legacy => crc32fast::hash(body),
        }
    }

    /// Frames `body` as a record.
    fn frame(self, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(RECORD_HEADER + body.len());
        r.extend_from_slice(self.magic());
        r.extend_from_slice(&(body.len() as u32).to_le_bytes());
        r.extend_from_slice(&self.checksum(body).to_le_bytes());
        r.extend_from_slice(body);
        r
    }

    /// The record of a block.
    fn block_record(self, pow_hash: &Hash, block: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + 32 + block.len());
        if self == Codec::Typed {
            body.push(TYPE_BLOCK);
        }
        body.extend_from_slice(pow_hash);
        body.extend_from_slice(block);
        self.frame(&body)
    }

    /// Parses the record frame at the start of `data`: the body and the
    /// record's length. Allocates nothing; the body is a slice of `data`.
    fn parse_frame(self, data: &[u8]) -> Result<(&[u8], usize), &'static str> {
        if data.len() < RECORD_HEADER {
            return Err("short header");
        }
        if &data[..4] != self.magic() {
            return Err("bad magic");
        }
        let len = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) as usize;
        if !self.lengths().contains(&len) {
            return Err("bad length");
        }
        let crc = u32::from_le_bytes(data[8..12].try_into().expect("4 bytes"));
        let end = RECORD_HEADER + len;
        if data.len() < end {
            return Err("short payload");
        }
        let body = &data[RECORD_HEADER..end];
        if self.checksum(body) != crc {
            return Err("checksum mismatch");
        }
        Ok((body, end))
    }

    /// Decodes a checked record body. `Ok(None)`: an advisory record of a
    /// type this build does not know (skipped). `Err`: a body that is not a
    /// valid record of its type, or an unknown critical type (refused).
    fn decode_body(self, body: &[u8]) -> Result<Option<Record>, String> {
        if self == Codec::Legacy {
            return Ok(Some(block_record(body)));
        }
        let (&ty, p) = body.split_first().expect("typed bodies are not empty");
        match ty {
            TYPE_BLOCK => {
                if p.len() < 32 {
                    return Err(format!("block record of {} bytes", p.len()));
                }
                Ok(Some(block_record(p)))
            }
            TYPE_INVALID => decode_invalid(p).map(|m| Some(Record::Marker(Marker::Invalid(m)))),
            TYPE_RECONSIDER => {
                let id: Hash = p
                    .try_into()
                    .map_err(|_| format!("reconsider marker of {} bytes", p.len()))?;
                Ok(Some(Record::Marker(Marker::Reconsider(id))))
            }
            TYPE_CHECKPOINT => {
                decode_checkpoint(p).map(|c| Some(Record::Marker(Marker::Checkpoint(c))))
            }
            // Reserved (F48-5): no build writes it yet; skipped like any
            // advisory type this build does not know.
            TYPE_QUARANTINE_RESERVED => Ok(None),
            t if t & ADVISORY != 0 => Ok(None),
            t => Err(format!(
                "unknown record type {t:#04x} (written by a newer build?)"
            )),
        }
    }
}

fn block_record(p: &[u8]) -> Record {
    let mut pow = [0u8; 32];
    pow.copy_from_slice(&p[..32]);
    Record::Block((pow, p[32..].to_vec()))
}

/// Reads a length-prefixed UTF-8 text of at most `max` bytes that ends `p`.
fn decode_text(p: &[u8], max: usize, what: &str) -> Result<String, String> {
    if p.len() < 2 {
        return Err(format!("{what}: missing length"));
    }
    let k = u16::from_le_bytes([p[0], p[1]]) as usize;
    if k > max || p.len() != 2 + k {
        return Err(format!("{what}: bad length"));
    }
    String::from_utf8(p[2..].to_vec()).map_err(|_| format!("{what}: not UTF-8"))
}

fn encode_text(out: &mut Vec<u8>, text: &str, max: usize, what: &str) -> io::Result<()> {
    if text.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} longer than {max} bytes"),
        ));
    }
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn decode_invalid(p: &[u8]) -> Result<InvalidMarker, String> {
    if p.len() < 33 {
        return Err("invalid marker: too short".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&p[..32]);
    let origin = match p[32] {
        1 => InvalidOrigin::Verdict,
        2 => InvalidOrigin::Operator,
        o => return Err(format!("invalid marker: unknown origin {o}")),
    };
    let reason = decode_text(&p[33..], MAX_REASON, "invalid marker reason")?;
    Ok(InvalidMarker { id, origin, reason })
}

fn decode_checkpoint(p: &[u8]) -> Result<Checkpoint, String> {
    const FIXED: usize = 32 + 8 + 32 + 32;
    if p.len() < FIXED {
        return Err("checkpoint: too short".into());
    }
    let hash = |at: usize| -> Hash { p[at..at + 32].try_into().expect("32 bytes") };
    Ok(Checkpoint {
        tip_id: hash(0),
        height: u64::from_le_bytes(p[32..40].try_into().expect("8 bytes")),
        state_digest: hash(40),
        fingerprint: hash(72),
        build_commit: decode_text(&p[FIXED..], MAX_BUILD_COMMIT, "checkpoint build commit")?,
    })
}

/// The body of a typed marker record.
fn encode_marker(marker: &Marker) -> io::Result<Vec<u8>> {
    let mut b = Vec::new();
    match marker {
        Marker::Invalid(m) => {
            b.push(TYPE_INVALID);
            b.extend_from_slice(&m.id);
            b.push(match m.origin {
                InvalidOrigin::Verdict => 1,
                InvalidOrigin::Operator => 2,
            });
            encode_text(&mut b, &m.reason, MAX_REASON, "invalid marker reason")?;
        }
        Marker::Reconsider(id) => {
            b.push(TYPE_RECONSIDER);
            b.extend_from_slice(id);
        }
        Marker::Checkpoint(c) => {
            b.push(TYPE_CHECKPOINT);
            b.extend_from_slice(&c.tip_id);
            b.extend_from_slice(&c.height.to_le_bytes());
            b.extend_from_slice(&c.state_digest);
            b.extend_from_slice(&c.fingerprint);
            encode_text(
                &mut b,
                &c.build_commit,
                MAX_BUILD_COMMIT,
                "checkpoint build commit",
            )?;
        }
    }
    Ok(b)
}

/// `blocks.dat` in the node's data directory.
pub struct FileStore {
    path: PathBuf,
    file: File,
    /// A failed append could not be undone: refuse further appends.
    poisoned: bool,
    /// The record layout, set by `bind` (`None`: not bound yet).
    codec: Option<Codec>,
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
            codec: None,
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
    /// again. Every valid record before the first damaged one is kept, and
    /// so is every intact operator record (`invalid` of origin operator,
    /// `reconsider`) of the moved region: they are written back after the
    /// kept prefix, in their order, each logged with its block id (RTW3-7).
    /// Blocks are downloaded again, but a lost verdict would not come back.
    ///
    /// Only the current format and legacy headerless stores are repaired; a
    /// damaged file header or another format version is an error (the
    /// operator moves the store aside and resyncs), and nothing is changed.
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
        let (codec, start) = if !data.starts_with(FILE_MAGIC) {
            (Codec::Legacy, 0)
        } else if data.len() < FILE_HEADER {
            return Ok(0); // a torn header: `bind` writes it again
        } else if header_len(&data) != FILE_HEADER {
            return Err(corrupt(format!(
                "{}: damaged file header; repair cannot tell the format. Move the store \
                 aside and resync",
                path.display()
            )));
        } else {
            match header_version(&data) {
                FORMAT_VERSION => (Codec::Typed, FILE_HEADER),
                v => {
                    return Err(corrupt(format!(
                        "{}: block store format version {v} is not repaired by this build; \
                         move the store aside and resync",
                        path.display()
                    )))
                }
            }
        };
        let pos = valid_prefix(codec, &data, start);
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
        // The operator's verdicts in the moved region are kept (RTW3-7): an
        // `invalid` record of the operator or a `reconsider` record lost here
        // would silently undo a verdict. They are written over the start of
        // the moved region, in their order, before the store is cut behind
        // them, so a crash in between leaves them in the file (a second
        // repair finds them again; repeating the sequence changes no verdict,
        // the last record for an id wins).
        let kept = match codec {
            Codec::Typed => operator_records(&data[pos..]),
            Codec::Legacy => Vec::new(),
        };
        let mut f = OpenOptions::new().write(true).open(path)?;
        let mut end = pos;
        if !kept.is_empty() {
            f.seek(SeekFrom::Start(pos as u64))?;
            for (at, frame, what) in &kept {
                f.write_all(frame)?;
                end += frame.len();
                log::warn!(
                    "{}: operator record kept from the damaged region (offset {}): {what}",
                    path.display(),
                    pos + at
                );
            }
            f.sync_all()?;
        }
        f.set_len(end as u64)?;
        f.sync_all()?;
        log::warn!(
            "{}: {} damaged or unreadable bytes from offset {pos} moved to {}; {} operator \
             record(s) kept",
            path.display(),
            data.len() - pos,
            aside.display(),
            kept.len()
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

    /// Appends one framed record, undoing a failed write.
    fn append_framed(&mut self, record: &[u8]) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "block store refuses writes after a failed write that could not be undone; \
                 restart the node",
            ));
        }
        let len = self.file.seek(SeekFrom::End(0))?;
        if let Err(e) = self.write_record(record) {
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

    fn codec(&self) -> io::Result<Codec> {
        self.codec.ok_or_else(|| {
            io::Error::other(format!(
                "{}: block store used before it was bound to a network",
                self.path.display()
            ))
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The format version: [`FORMAT_VERSION`] for a store with a file header,
    /// 0 for a legacy headerless store (regtest only) or before
    /// [`BlockStore::bind`].
    pub fn format_version(&self) -> u32 {
        match self.codec {
            Some(Codec::Typed) => FORMAT_VERSION,
            _ => 0,
        }
    }
}

/// The file header for a network.
fn encode_file_header(identity: &StoreIdentity) -> [u8; FILE_HEADER] {
    let mut h = [0u8; FILE_HEADER];
    h[..4].copy_from_slice(FILE_MAGIC);
    h[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h[8..12].copy_from_slice(&identity.network_id.to_le_bytes());
    h[12..44].copy_from_slice(&identity.genesis_id);
    let crc = crc32fast::hash(&h[..44]);
    h[44..].copy_from_slice(&crc.to_le_bytes());
    h
}

/// Length of a checksum-valid file header at the start of `data` (0 if there
/// is none).
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

/// The version field of a checked file header.
fn header_version(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[4..8].try_into().expect("4 bytes"))
}

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
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
    /// follows) is written again. Refused, with nothing changed: another
    /// network or genesis, a damaged header, format 1, an unknown version,
    /// and a headerless (format 0) store except on regtest.
    fn bind(&mut self, identity: &StoreIdentity) -> io::Result<()> {
        self.codec = None;
        let expected = encode_file_header(identity);
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
            self.codec = Some(Codec::Typed);
            return Ok(());
        }
        let path = self.path.display();
        let net = network_name(identity.network);
        if !head.starts_with(FILE_MAGIC) {
            // A format 0 store starts with its first record. Anything else is
            // not a block store (or its header magic is damaged): refused, so
            // that a damaged header is never read as a legacy store whose
            // "torn tail" is the whole file.
            if !head.starts_with(Codec::Legacy.magic()) {
                return Err(corrupt(format!(
                    "{path}: not a block store, or its file header is damaged. Move {path} \
                     aside and start again to resync"
                )));
            }
            if identity.network != Network::Regtest {
                return Err(corrupt(format!(
                    "{path}: block store from before the v3 reset (format 0, no file \
                     header): its network and genesis cannot be verified, so it is not \
                     used on {net}. Stop the node, move {path} aside (or start with a \
                     fresh data directory) and start again; the node resyncs the chain \
                     from its peers (docs/testnet.md §4.5)"
                )));
            }
            log::warn!(
                "{path}: legacy block store without a file header (format 0); its network \
                 cannot be verified. Regtest only: it is used as it is"
            );
            self.codec = Some(Codec::Legacy);
            return Ok(());
        }
        if header_len(&head) != FILE_HEADER {
            return Err(corrupt(format!(
                "{path}: damaged file header. Move {path} aside and start again to resync"
            )));
        }
        match header_version(&head) {
            FORMAT_VERSION => {}
            1 => {
                return Err(corrupt(format!(
                    "{path}: block store format version 1 (written before the v3 store \
                     format); this build reads format {FORMAT_VERSION} only and never \
                     migrates old stores. Stop the node, move {path} aside (or start with a \
                     fresh data directory) and start again to resync the chain from its \
                     peers (docs/testnet.md §4.5)"
                )))
            }
            v => {
                return Err(corrupt(format!(
                    "{path}: unsupported block store format version {v} (this build reads \
                     version {FORMAT_VERSION}; was the store written by a newer build?)"
                )))
            }
        }
        if head[8..44] != expected[8..44] {
            let their = u32::from_le_bytes(head[8..12].try_into().expect("4 bytes"));
            return Err(corrupt(format!(
                "{path}: wrong network data directory: this block store belongs to network \
                 id {their:#010x} with genesis {}, but the node runs {net} (network id \
                 {:#010x}) with genesis {}. Use a separate data directory for each network \
                 (or remove the store of an old network)",
                hex(&head[12..44]),
                identity.network_id,
                hex(&identity.genesis_id)
            )));
        }
        self.codec = Some(Codec::Typed);
        Ok(())
    }

    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        let record = self.codec()?.block_record(pow_hash, block);
        self.append_framed(&record)
    }

    fn append_marker(&mut self, marker: &Marker) -> io::Result<()> {
        if self.codec()? != Codec::Typed {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a legacy (format 0) block store keeps blocks only",
            ));
        }
        let record = Codec::Typed.frame(&encode_marker(marker)?);
        self.append_framed(&record)
    }

    /// Reads every record. A damaged final region (a crash mid-write) is
    /// truncated away with a warning. Damage followed by **any** later valid
    /// record is an error: silently dropping blocks in the middle would hide
    /// real corruption (the operator repairs it with [`FileStore::repair`]).
    /// A record whose checksum holds but which is not a valid record of a
    /// known type is an error too, wherever it is (never skipped, never
    /// truncated), except an advisory type this build does not know.
    ///
    /// Cost is linear: every record is parsed once, and after the first damage
    /// each later magic position is parsed at most once.
    fn load(&mut self) -> io::Result<Vec<Record>> {
        let codec = self.codec()?;
        let mut data = Vec::new();
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut data)?;
        let mut out = Vec::new();
        let mut pos = match codec {
            Codec::Typed => FILE_HEADER,
            Codec::Legacy => 0,
        };
        while pos < data.len() {
            match codec.parse_frame(&data[pos..]) {
                Ok((body, used)) => {
                    match codec.decode_body(body) {
                        Ok(Some(r)) => out.push(r),
                        Ok(None) => log::debug!(
                            "{}: skipping advisory record of unknown type {:#04x} at offset \
                             {pos}",
                            self.path.display(),
                            body[0]
                        ),
                        Err(e) => {
                            return Err(corrupt(format!(
                                "{}: record at offset {pos} is not valid: {e}",
                                self.path.display()
                            )))
                        }
                    }
                    pos += used;
                }
                Err(e) => {
                    // Fail safe: a valid record anywhere after the damage means
                    // this is not (only) a torn tail. This also refuses a torn
                    // last block whose data embeds a record-shaped byte string
                    // (block data is partly user-chosen); `repair` recovers such
                    // a file without losing any valid record, because there the
                    // damaged region is the tail.
                    if let Some(at) = next_valid_record(codec, &data, pos + 1) {
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

/// End of the longest run of valid record frames from `start`.
fn valid_prefix(codec: Codec, data: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos < data.len() {
        match codec.parse_frame(&data[pos..]) {
            Ok((_, used)) => pos += used,
            Err(_) => break,
        }
    }
    pos
}

/// The intact operator records (`invalid` of origin operator, `reconsider`)
/// of a damaged typed region (`FileStore::repair`), in order: each one's
/// offset in `region`, its framed bytes and a description naming the full
/// block id. `region` starts at the first damaged record.
///
/// The region is walked record by record, so the bytes inside an intact
/// record (block data is partly user-chosen) are never read as records.
/// Past a damaged record the walk resumes at the end its length field
/// names, when a valid record (or the end of the region) starts exactly
/// there; otherwise at the next position holding a valid record. Only that
/// search can land inside a damaged record's data, so a record-shaped byte
/// string embedded in a block is taken for a record only if damage hit that
/// very block record before it. Every kept record is logged with its block
/// id; the operator compares them with the verdicts they gave.
fn operator_records(region: &[u8]) -> Vec<(usize, Vec<u8>, String)> {
    let codec = Codec::Typed;
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < region.len() {
        match codec.parse_frame(&region[pos..]) {
            Ok((body, used)) => {
                let what = match codec.decode_body(body) {
                    Ok(Some(Record::Marker(Marker::Invalid(m))))
                        if m.origin == InvalidOrigin::Operator =>
                    {
                        Some(format!("block {} invalidated", hex(&m.id)))
                    }
                    Ok(Some(Record::Marker(Marker::Reconsider(id)))) => {
                        Some(format!("block {} reconsidered", hex(&id)))
                    }
                    _ => None,
                };
                if let Some(what) = what {
                    out.push((pos, region[pos..pos + used].to_vec(), what));
                }
                pos += used;
            }
            Err(_) => {
                let named_end = (region.len() - pos >= RECORD_HEADER
                    && &region[pos..pos + 4] == codec.magic())
                .then(|| {
                    let n =
                        u32::from_le_bytes(region[pos + 4..pos + 8].try_into().expect("4 bytes"))
                            as usize;
                    pos + RECORD_HEADER + n
                })
                .filter(|&end| {
                    end == region.len()
                        || (end < region.len() && codec.parse_frame(&region[end..]).is_ok())
                });
                match named_end.or_else(|| next_valid_record(codec, region, pos + 1)) {
                    Some(next) => pos = next,
                    None => break,
                }
            }
        }
    }
    out
}

/// Offset of the first valid record frame starting at or after `from`. Each
/// position holding the magic is parsed once, so the scan is linear in the
/// data plus the checksummed bodies of the candidates.
fn next_valid_record(codec: Codec, data: &[u8], from: usize) -> Option<usize> {
    let magic = codec.magic();
    let mut at = from;
    while at + magic.len() <= data.len() {
        let off = data[at..].windows(magic.len()).position(|w| w == magic)?;
        at += off;
        if codec.parse_frame(&data[at..]).is_ok() {
            return Some(at);
        }
        at += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    const NET: u32 = 0x0001_D672;
    const GENESIS: Hash = [0x42; 32];

    fn ident(network: Network) -> StoreIdentity {
        StoreIdentity {
            network,
            network_id: NET,
            genesis_id: GENESIS,
        }
    }

    const REGTEST: StoreIdentity = StoreIdentity {
        network: Network::Regtest,
        network_id: NET,
        genesis_id: GENESIS,
    };

    /// A new store bound to `REGTEST`.
    fn bound(path: &Path) -> FileStore {
        let mut s = FileStore::open(path).unwrap();
        s.bind(&REGTEST).unwrap();
        s
    }

    fn load(path: &Path) -> io::Result<Vec<Record>> {
        let mut s = FileStore::open(path).unwrap();
        s.bind(&REGTEST)?;
        s.load()
    }

    fn block(i: u8) -> Record {
        Record::Block(([i; 32], vec![i; 10 + i as usize]))
    }

    fn fill(store: &mut dyn BlockStore, n: u8) {
        for i in 0..n {
            store.append(&[i; 32], &vec![i; 10 + i as usize]).unwrap();
        }
    }

    fn invalid(i: u8, origin: InvalidOrigin) -> Marker {
        Marker::Invalid(InvalidMarker {
            id: [i; 32],
            origin,
            reason: format!("reason {i}"),
        })
    }

    fn checkpoint(i: u8) -> Marker {
        Marker::Checkpoint(Checkpoint {
            tip_id: [i; 32],
            height: 1_000 + i as u64,
            state_digest: [i ^ 0x55; 32],
            fingerprint: [i ^ 0xaa; 32],
            build_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        })
    }

    fn append(s: &mut dyn BlockStore, r: &Record) {
        match r {
            Record::Block((pow, b)) => s.append(pow, b).unwrap(),
            Record::Marker(m) => s.append_marker(m).unwrap(),
        }
    }

    /// A mixed log: blocks, both invalid origins and checkpoints.
    fn mixed() -> Vec<Record> {
        vec![
            block(0),
            Record::Marker(checkpoint(1)),
            block(2),
            Record::Marker(invalid(3, InvalidOrigin::Verdict)),
            block(4),
            Record::Marker(invalid(5, InvalidOrigin::Operator)),
            block(6),
            Record::Marker(Marker::Reconsider([5; 32])),
        ]
    }

    /// The raw file of a new store holding `records`, and the end offset of
    /// each record.
    fn file_of(path: &Path, records: &[Record]) -> (Vec<u8>, Vec<usize>) {
        std::fs::remove_file(path).ok();
        let mut s = bound(path);
        let mut ends = Vec::new();
        for r in records {
            append(&mut s, r);
            ends.push(std::fs::metadata(path).unwrap().len() as usize);
        }
        (std::fs::read(path).unwrap(), ends)
    }

    /// A typed record frame with any type and payload (valid checksum).
    fn raw_record(ty: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![ty];
        body.extend_from_slice(payload);
        Codec::Typed.frame(&body)
    }

    #[test]
    fn round_trip_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = bound(&path);
            fill(&mut s, 5);
        }
        let mut s = bound(&path);
        let recs = s.load().unwrap();
        assert_eq!(recs.len(), 5);
        assert_eq!(recs[3], block(3));
        // Appending after a load continues the log.
        s.append(&[9; 32], b"more").unwrap();
        assert_eq!(load(&path).unwrap().len(), 6);
    }

    /// Every record type round-trips in order, including the longest texts.
    #[test]
    fn typed_records_round_trip_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut records = mixed();
        records.push(Record::Marker(Marker::Invalid(InvalidMarker {
            id: [7; 32],
            origin: InvalidOrigin::Verdict,
            reason: "é".repeat(MAX_REASON / 2),
        })));
        records.push(Record::Marker(Marker::Checkpoint(Checkpoint {
            tip_id: [8; 32],
            height: u64::MAX,
            state_digest: [0; 32],
            fingerprint: [0xff; 32],
            build_commit: "x".repeat(MAX_BUILD_COMMIT),
        })));
        records.push(Record::Marker(Marker::Invalid(InvalidMarker {
            id: [9; 32],
            origin: InvalidOrigin::Operator,
            reason: String::new(),
        })));
        file_of(&path, &records);
        assert_eq!(load(&path).unwrap(), records);
        // The memory store keeps the same log.
        let mut m = MemoryStore::default();
        for r in &records {
            append(&mut m, r);
        }
        assert_eq!(m.load().unwrap(), records);
    }

    /// A marker text over its limit is refused before anything is written.
    #[test]
    fn an_oversized_marker_is_refused_unwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = bound(&path);
        fill(&mut s, 1);
        let len = std::fs::metadata(&path).unwrap().len();
        let long = Marker::Invalid(InvalidMarker {
            id: [1; 32],
            origin: InvalidOrigin::Verdict,
            reason: "r".repeat(MAX_REASON + 1),
        });
        let err = s.append_marker(&long).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let Marker::Checkpoint(mut c) = checkpoint(1) else {
            unreachable!()
        };
        c.build_commit = "c".repeat(MAX_BUILD_COMMIT + 1);
        assert!(s.append_marker(&Marker::Checkpoint(c)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        assert!(!s.failed());
    }

    /// An unknown advisory type is skipped; an unknown critical type, or a
    /// checksum-valid record that is not a valid record of its type, is
    /// refused wherever it is (also as the last record: it is not a torn
    /// write) and nothing is truncated.
    #[test]
    fn unknown_and_malformed_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let (good, _) = file_of(&path, &[block(0), block(1)]);

        let mut with_advisory = good.clone();
        with_advisory.extend(raw_record(0xC7, b"future advisory data"));
        with_advisory.extend(raw_record(TYPE_QUARANTINE_RESERVED, &[3; 32]));
        with_advisory.extend(Codec::Typed.block_record(&[2; 32], &[2; 12]));
        std::fs::write(&path, &with_advisory).unwrap();
        assert_eq!(
            load(&path).unwrap(),
            vec![block(0), block(1), block(2)],
            "advisory record skipped"
        );

        let mut bad_origin = [7u8; 32].to_vec();
        bad_origin.push(9);
        bad_origin.extend_from_slice(&0u16.to_le_bytes());
        let mut bad_text = [7u8; 32].to_vec();
        bad_text.push(1);
        bad_text.extend_from_slice(&2u16.to_le_bytes());
        bad_text.extend_from_slice(&[0xff, 0xfe]); // not UTF-8
        let mut long_text = [7u8; 32].to_vec();
        long_text.push(1);
        long_text.extend_from_slice(&((MAX_REASON + 1) as u16).to_le_bytes());
        long_text.extend(std::iter::repeat_n(b'a', MAX_REASON + 1));
        let mut trailing = [7u8; 32].to_vec();
        trailing.push(1);
        trailing.extend_from_slice(&1u16.to_le_bytes());
        trailing.extend_from_slice(b"ab"); // one byte more than the length says
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                raw_record(0x04, b"future critical data"),
                "unknown record type",
            ),
            (raw_record(0x7f, b""), "unknown record type"),
            (raw_record(TYPE_BLOCK, &[1; 31]), "block record"),
            (raw_record(TYPE_INVALID, &[1; 32]), "too short"),
            (raw_record(TYPE_INVALID, &bad_origin), "origin"),
            (raw_record(TYPE_INVALID, &bad_text), "UTF-8"),
            (raw_record(TYPE_INVALID, &long_text), "bad length"),
            (raw_record(TYPE_INVALID, &trailing), "bad length"),
            (raw_record(TYPE_CHECKPOINT, &[1; 103]), "too short"),
            (raw_record(TYPE_RECONSIDER, &[1; 31]), "reconsider marker"),
            (raw_record(TYPE_RECONSIDER, &[1; 33]), "reconsider marker"),
        ];
        for (rec, why) in cases {
            for last in [true, false] {
                let mut bytes = good.clone();
                bytes.extend_from_slice(&rec);
                if !last {
                    bytes.extend(Codec::Typed.block_record(&[2; 32], &[2; 12]));
                }
                std::fs::write(&path, &bytes).unwrap();
                let err = load(&path).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert!(err.to_string().contains(why), "{why}: {err}");
                assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing truncated");
            }
        }
    }

    #[test]
    fn torn_tail_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = bound(&path);
            fill(&mut s, 3);
        }
        let full = std::fs::metadata(&path).unwrap().len();
        // Simulate a crash in the middle of writing the last record.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(full - 5).unwrap();
        drop(f);
        let mut s = bound(&path);
        assert_eq!(s.load().unwrap().len(), 2);
        // The damaged bytes are gone; the log is appendable again.
        s.append(&[7; 32], b"x").unwrap();
        let recs = load(&path).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[2], Record::Block(([7; 32], b"x".to_vec())));
    }

    /// A crash at every byte of the log (the file is then a prefix of the
    /// complete file): the store opens, holds exactly the records complete
    /// before the cut, the torn bytes are gone, and appends continue.
    #[test]
    fn a_crash_at_every_byte_keeps_every_complete_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let records = mixed();
        let (full, ends) = file_of(&path, &records);
        let cut_path = dir.path().join("cut.dat");
        for cut in 0..=full.len() {
            std::fs::write(&cut_path, &full[..cut]).unwrap();
            let mut s = FileStore::open(&cut_path).unwrap();
            s.bind(&REGTEST)
                .unwrap_or_else(|e| panic!("cut {cut}: {e}"));
            let got = s.load().unwrap_or_else(|e| panic!("cut {cut}: {e}"));
            let complete = ends.iter().filter(|&&e| e <= cut).count();
            assert_eq!(got, records[..complete], "cut {cut}");
            let kept = if complete == 0 {
                FILE_HEADER
            } else {
                ends[complete - 1]
            };
            assert_eq!(
                std::fs::metadata(&cut_path).unwrap().len() as usize,
                kept,
                "cut {cut}"
            );
            s.append(&[9; 32], b"after").unwrap();
            drop(s);
            let again = load(&cut_path).unwrap();
            assert_eq!(again.len(), complete + 1, "cut {cut}");
        }
    }

    /// Fault injection at every write boundary: the append of record `k`
    /// fails after `n` bytes, for every `k` and `n`. With the undo working the
    /// file is unchanged and the store stays usable; with the undo failing too
    /// (a crash: the partial bytes stay) the store refuses writes, and after
    /// a restart it holds exactly the records before `k`.
    #[test]
    fn a_write_failing_at_every_byte_loses_no_earlier_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let records = mixed();
        for (k, rec) in records.iter().enumerate() {
            let (before, _) = file_of(&path, &records[..k]);
            let size = match rec {
                Record::Block((_, b)) => RECORD_HEADER + 1 + 32 + b.len(),
                Record::Marker(m) => RECORD_HEADER + encode_marker(m).unwrap().len(),
            };
            for n in 0..size {
                for undo_fails in [false, true] {
                    std::fs::write(&path, &before).unwrap();
                    let mut s = bound(&path);
                    assert_eq!(s.load().unwrap(), records[..k]);
                    s.fail_after = Some(n);
                    s.fail_undo = undo_fails;
                    let r = match rec {
                        Record::Block((pow, b)) => s.append(pow, b),
                        Record::Marker(m) => s.append_marker(m),
                    };
                    assert!(r.is_err(), "k {k} n {n}");
                    assert_eq!(s.failed(), undo_fails, "k {k} n {n}");
                    let on_disk = std::fs::read(&path).unwrap();
                    if undo_fails {
                        assert_eq!(on_disk.len(), before.len() + n, "partial bytes stay");
                        assert!(s.append(&[1; 32], b"refused").is_err());
                    } else {
                        assert_eq!(on_disk, before, "undone");
                    }
                    drop(s);
                    let mut s = bound(&path);
                    assert_eq!(s.load().unwrap(), records[..k], "k {k} n {n}");
                    append(&mut s, rec);
                    drop(s);
                    assert_eq!(load(&path).unwrap(), records[..=k], "k {k} n {n}");
                }
            }
        }
    }

    /// Every single-bit flip anywhere in the file: the store either refuses
    /// (a damaged header, damage followed by valid data) or returns an exact
    /// prefix of the records, and it truncates only damage in the last
    /// record. It never returns a record that differs from what was written.
    #[test]
    fn every_single_bit_flip_is_refused_or_cut_to_an_exact_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let records = mixed();
        let (full, ends) = file_of(&path, &records);
        let last_start = ends[ends.len() - 2];
        let flip_path = dir.path().join("flip.dat");
        let (mut refused, mut cut) = (0, 0);
        for byte in 0..full.len() {
            for bit in 0..8 {
                let mut bytes = full.clone();
                bytes[byte] ^= 1 << bit;
                std::fs::write(&flip_path, &bytes).unwrap();
                let mut s = FileStore::open(&flip_path).unwrap();
                match s.bind(&REGTEST).and_then(|()| s.load()) {
                    Err(e) => {
                        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{byte}.{bit}");
                        assert!(byte < last_start, "damage in the last record is a tail");
                        assert_eq!(std::fs::read(&flip_path).unwrap(), bytes, "untouched");
                        refused += 1;
                    }
                    Ok(recs) => {
                        assert!(byte >= last_start, "flip at {byte}.{bit} accepted");
                        assert_eq!(recs, records[..records.len() - 1], "{byte}.{bit}");
                        cut += 1;
                    }
                }
            }
        }
        assert!(refused > 0 && cut > 0);
    }

    /// Random bytes (a fuzz-style property with a fixed seed): the frame
    /// parser and the body decoder never panic, and a decoded record is never
    /// larger than its input (allocation is bounded by the bytes read);
    /// `load` over files of random records after a valid header returns or
    /// refuses without panicking. A frame claiming a huge length is rejected
    /// from its length field alone.
    #[test]
    fn random_bytes_never_panic_and_allocate_within_the_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x35);
        let types = [
            TYPE_BLOCK,
            TYPE_INVALID,
            TYPE_RECONSIDER,
            TYPE_CHECKPOINT,
            0x99,
        ];
        for codec in [Codec::Typed, Codec::Legacy] {
            for round in 0..20_000usize {
                let n = (rng.next_u32() % 300) as usize;
                let mut data = vec![0u8; n];
                rng.fill_bytes(&mut data);
                // Often plant the magic, and sometimes a matching length, a
                // known type and a valid checksum, so the decoder is reached.
                if n >= RECORD_HEADER && round % 2 == 0 {
                    data[..4].copy_from_slice(codec.magic());
                    if round % 4 == 0 {
                        let len = n - RECORD_HEADER;
                        data[4..8].copy_from_slice(&(len as u32).to_le_bytes());
                        if len > 0 && round % 8 == 0 {
                            data[RECORD_HEADER] = types[(round / 8) % types.len()];
                        }
                        let crc = codec.checksum(&data[RECORD_HEADER..]);
                        data[8..12].copy_from_slice(&crc.to_le_bytes());
                    }
                }
                if let Ok((body, used)) = codec.parse_frame(&data) {
                    assert!(used <= data.len() && body.len() + RECORD_HEADER == used);
                    if let Ok(Some(r)) = codec.decode_body(body) {
                        let size = match r {
                            Record::Block((_, b)) => 32 + b.len(),
                            Record::Marker(Marker::Invalid(m)) => 35 + m.reason.len(),
                            Record::Marker(Marker::Reconsider(_)) => 32,
                            Record::Marker(Marker::Checkpoint(c)) => 106 + c.build_commit.len(),
                        };
                        assert!(size <= body.len());
                    }
                }
                let _ = next_valid_record(codec, &data, 0);
            }
        }
        // A frame claiming 4 GiB is refused by its length alone.
        let mut huge = Codec::Typed.magic().to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        huge.extend_from_slice(&[0; 4]);
        assert_eq!(Codec::Typed.parse_frame(&huge), Err("bad length"));
        // Whole files of random records.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let types = [
            TYPE_BLOCK,
            TYPE_INVALID,
            TYPE_RECONSIDER,
            TYPE_CHECKPOINT,
            0x05,
            0x85,
        ];
        for _ in 0..300 {
            let mut bytes = encode_file_header(&REGTEST).to_vec();
            for _ in 0..(rng.next_u32() % 6) {
                let mut payload = vec![0u8; (rng.next_u32() % 80) as usize];
                rng.fill_bytes(&mut payload);
                let ty = types[(rng.next_u32() % types.len() as u32) as usize];
                bytes.extend(raw_record(ty, &payload));
            }
            let mut tail = vec![0u8; (rng.next_u32() % 40) as usize];
            rng.fill_bytes(&mut tail);
            bytes.extend(tail);
            std::fs::write(&path, &bytes).unwrap();
            let _ = load(&path);
        }
    }

    #[test]
    fn corruption_in_the_middle_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = bound(&path);
            fill(&mut s, 3);
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[FILE_HEADER + RECORD_HEADER + 40] ^= 0xff; // inside the first body
        std::fs::write(&path, &bytes).unwrap();
        let err = load(&path).unwrap_err();
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
        let mut s = bound(&path);
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
        let recs = load(&path).unwrap();
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[3], Record::Block(([9; 32], b"next".to_vec())));
    }

    /// If the partial record cannot be removed, no further record is written,
    /// so the damage stays the file's tail and a restart truncates it.
    #[test]
    fn a_failed_append_that_cannot_be_undone_stops_writes_until_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = bound(&path);
        fill(&mut s, 3);
        s.fail_after = Some(20);
        s.fail_undo = true;
        assert!(s.append(&[8; 32], &[8; 500]).is_err());
        assert!(
            s.append(&[9; 32], b"next").is_err(),
            "refused while poisoned"
        );
        assert!(
            s.append_marker(&checkpoint(1)).is_err(),
            "markers refused too"
        );
        drop(s);
        let mut s = bound(&path);
        assert_eq!(s.load().unwrap().len(), 3, "the damaged tail is truncated");
        s.append(&[9; 32], b"next").unwrap();
        assert_eq!(load(&path).unwrap().len(), 4);
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
        {
            let mut s = bound(&path);
            fill(&mut s, 2);
            // A block whose data embeds a complete, valid record.
            let inner = Codec::Typed.block_record(&[5; 32], &[5; 8]);
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
        let err = load(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), torn, "nothing truncated");
        let aside = FileStore::repair(&path, 42).unwrap();
        let recs = load(&path).unwrap();
        assert_eq!(recs.len(), 2, "both valid records kept");
        assert_eq!(recs[1], block(1));
        assert_eq!(
            aside as usize,
            torn.len() - valid_prefix(Codec::Typed, &torn, FILE_HEADER)
        );
        assert_eq!(
            std::fs::read(path.with_extension("dat.damaged-42")).unwrap(),
            torn[torn.len() - aside as usize..]
        );
    }

    /// A bit flip in the middle of the file plus a torn last record. Every
    /// record after the flip is valid, so the file is refused (not
    /// truncated), and quickly: a rule that re-parsed the rest of the file
    /// from every later byte would be quadratic.
    #[test]
    fn mid_file_corruption_and_a_torn_tail_are_refused_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        const N: usize = 20_000;
        // Built in memory: 20 000 synced appends would only measure fsync.
        let mut bytes = encode_file_header(&REGTEST).to_vec();
        for i in 0..N {
            bytes.extend(
                Codec::Typed.block_record(&[(i % 251) as u8; 32], &(i as u64).to_le_bytes()),
            );
        }
        let rec = RECORD_HEADER + 1 + 32 + 8;
        assert_eq!(bytes.len(), FILE_HEADER + N * rec);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(load(&path).unwrap().len(), N);
        let at = FILE_HEADER + 10 * rec;
        bytes[at + RECORD_HEADER + 3] ^= 0x01; // record 10's body
        bytes.truncate(bytes.len() - 7); // torn last record
        std::fs::write(&path, &bytes).unwrap();

        let started = std::time::Instant::now();
        let err = load(&path).unwrap_err();
        let took = started.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(&format!("offset {at}")), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing truncated");
        assert!(
            took < std::time::Duration::from_secs(2),
            "load took {took:?}"
        );

        // The operator's repair keeps the valid prefix (records 0..10).
        let started = std::time::Instant::now();
        let aside = FileStore::repair(&path, 7).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(aside as usize, bytes.len() - at);
        let recs = load(&path).unwrap();
        assert_eq!(recs.len(), 10);
        assert_eq!(
            recs[9],
            Record::Block(([9; 32], 9u64.to_le_bytes().to_vec()))
        );
    }

    /// A long damaged tail full of record-shaped candidates (magic with bad
    /// lengths or checksums) is truncated in linear time.
    #[test]
    fn a_long_damaged_tail_of_record_candidates_is_truncated_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        {
            let mut s = bound(&path);
            fill(&mut s, 3);
        }
        let good = std::fs::metadata(&path).unwrap().len() as usize;
        let mut bytes = std::fs::read(&path).unwrap();
        // 4 MiB of candidates claiming 64-byte bodies with a wrong checksum.
        let mut cand = Vec::new();
        cand.extend_from_slice(Codec::Typed.magic());
        cand.extend_from_slice(&64u32.to_le_bytes());
        cand.extend_from_slice(&0u32.to_le_bytes());
        while bytes.len() < good + (4 << 20) {
            bytes.extend_from_slice(&cand);
        }
        std::fs::write(&path, &bytes).unwrap();
        let started = std::time::Instant::now();
        let recs = load(&path).unwrap();
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

    /// Repair refuses what it cannot parse (a damaged header, another
    /// format version) and changes nothing.
    #[test]
    fn repair_refuses_unknown_formats_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let (good, _) = file_of(&path, &[block(0)]);
        let mut damaged = good.clone();
        damaged[9] ^= 1;
        let mut v1 = good.clone();
        v1[4..8].copy_from_slice(&1u32.to_le_bytes());
        let crc = crc32fast::hash(&v1[..44]);
        v1[44..48].copy_from_slice(&crc.to_le_bytes());
        for bytes in [damaged, v1] {
            std::fs::write(&path, &bytes).unwrap();
            assert!(FileStore::repair(&path, 3).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        // A torn header: nothing to repair (bind writes it again).
        std::fs::write(&path, &good[..20]).unwrap();
        assert_eq!(FileStore::repair(&path, 3).unwrap(), 0);
    }

    /// A store whose failed append could not be undone reports it.
    #[test]
    fn a_poisoned_store_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = bound(&path);
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
        let (mut bytes, ends) = file_of(&path, &[block(0), block(1), block(2), block(3)]);
        let second = ends[0]; // start of the second record
        bytes[second + RECORD_HEADER + 5] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(load(&path).is_err());
        let aside = FileStore::repair(&path, 1_234).unwrap();
        assert_eq!(aside as usize, bytes.len() - second);
        assert_eq!(
            std::fs::read(path.with_extension("dat.damaged-1234")).unwrap(),
            bytes[second..]
        );
        assert_eq!(load(&path).unwrap().len(), 1);
        assert_eq!(
            FileStore::repair(&path, 1_235).unwrap(),
            0,
            "nothing more to repair"
        );
    }

    /// RTW3-7: repair writes the intact operator records of the moved region
    /// back after the kept prefix, in order (verdict records of the node and
    /// checkpoints are not kept: replay recomputes them), past a second
    /// damaged record too. A block whose data embeds an operator-record frame
    /// is never read as records: not when intact, and not when damaged with
    /// its record header intact (the walk resumes at the end its length
    /// names).
    #[test]
    fn repair_keeps_the_operator_records_of_the_moved_region() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let fake = Codec::Typed.frame(&encode_marker(&Marker::Reconsider([0xee; 32])).unwrap());
        let mut data = vec![0x11; 40];
        data.extend_from_slice(&fake);
        data.extend_from_slice(&[0x22; 40]);
        let carrier = Record::Block(([7; 32], data));
        let records = [
            block(0),
            block(1),
            Record::Marker(invalid(5, InvalidOrigin::Operator)),
            carrier.clone(),
            Record::Marker(invalid(6, InvalidOrigin::Verdict)),
            Record::Marker(checkpoint(7)),
            block(2),
            Record::Marker(Marker::Reconsider([5; 32])),
            carrier,
            Record::Marker(invalid(8, InvalidOrigin::Operator)),
        ];
        let (mut bytes, ends) = file_of(&path, &records);
        // Damage block 1's body, and the first carrier's data before its
        // embedded frame (its record header stays intact).
        bytes[ends[0] + RECORD_HEADER + 5] ^= 0xff;
        bytes[ends[2] + RECORD_HEADER + 40] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(load(&path).is_err());
        let moved = FileStore::repair(&path, 7).unwrap();
        assert_eq!(moved as usize, bytes.len() - ends[0]);
        assert_eq!(
            load(&path).unwrap(),
            vec![
                block(0),
                Record::Marker(invalid(5, InvalidOrigin::Operator)),
                Record::Marker(Marker::Reconsider([5; 32])),
                Record::Marker(invalid(8, InvalidOrigin::Operator)),
            ]
        );
        assert_eq!(FileStore::repair(&path, 8).unwrap(), 0, "nothing more");
    }

    /// A store is used only after `bind`.
    #[test]
    fn an_unbound_store_refuses_reads_and_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut s = FileStore::open(&path).unwrap();
        assert!(s.load().is_err());
        assert!(s.append(&[1; 32], b"x").is_err());
        assert!(s.append_marker(&checkpoint(1)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    // ------------------------------------------------------------ file header

    /// A new store starts with the file header; it reopens under the same
    /// network with every record, and refuses another network or genesis
    /// without touching the file.
    #[test]
    fn a_new_store_is_bound_to_its_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            std::fs::remove_file(&path).ok();
            {
                let mut s = FileStore::open(&path).unwrap();
                s.bind(&ident(network)).unwrap();
                assert_eq!(s.format_version(), FORMAT_VERSION);
                assert!(s.load().unwrap().is_empty());
                fill(&mut s, 3);
                s.append_marker(&checkpoint(4)).unwrap();
            }
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(&bytes[..FILE_HEADER], &encode_file_header(&ident(network)));
            let mut s = FileStore::open(&path).unwrap();
            s.bind(&ident(network)).unwrap();
            let recs = s.load().unwrap();
            assert_eq!(recs.len(), 4);
            assert_eq!(recs[2], block(2));
            drop(s);

            for (net, genesis) in [(NET + 1, GENESIS), (NET, [0x43; 32])] {
                let other = StoreIdentity {
                    network,
                    network_id: net,
                    genesis_id: genesis,
                };
                let err = FileStore::open(&path).unwrap().bind(&other).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert!(err.to_string().contains("wrong network data directory"));
            }
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
        }
    }

    /// F35-1: a store written before the file header existed (format 0) is
    /// refused on testnet and mainnet, unchanged, with remediation text. On
    /// regtest it is accepted as it is and stays headerless: records load,
    /// block appends continue in its own layout, markers are refused.
    #[test]
    fn a_legacy_headerless_store_is_refused_except_on_regtest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let legacy: Vec<u8> = (0..3u8)
            .flat_map(|i| Codec::Legacy.block_record(&[i; 32], &vec![i; 10 + i as usize]))
            .collect();
        std::fs::write(&path, &legacy).unwrap();
        for network in [Network::Testnet, Network::Mainnet] {
            let err = FileStore::open(&path)
                .unwrap()
                .bind(&ident(network))
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            let msg = err.to_string();
            assert!(msg.contains("format 0") && msg.contains("move"), "{msg}");
            assert_eq!(std::fs::read(&path).unwrap(), legacy, "nothing changed");
        }
        let mut s = FileStore::open(&path).unwrap();
        s.bind(&REGTEST).unwrap();
        assert_eq!(s.format_version(), 0);
        assert_eq!(s.load().unwrap(), vec![block(0), block(1), block(2)]);
        s.append(&[9; 32], b"new").unwrap();
        assert_eq!(
            s.append_marker(&checkpoint(1)).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        drop(s);
        let now = std::fs::read(&path).unwrap();
        assert_eq!(&now[..legacy.len()], &legacy[..], "nothing rewritten");
        assert_eq!(load(&path).unwrap().len(), 4);
    }

    /// A damaged header is refused (fail safe), as are a file that is no
    /// block store, format 1 and an unknown version, with nothing changed; a
    /// header torn while the store was being created (no record after it) is
    /// written again; a torn record after a good header is truncated as
    /// usual; repair keeps the header.
    #[test]
    fn damaged_torn_and_foreign_file_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let (good, _) = file_of(&path, &[block(0), block(1)]);
        let bind_err = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            let e = FileStore::open(&path).unwrap().bind(&REGTEST).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing changed");
            e.to_string()
        };
        let mut bad = good.clone();
        bad[20] ^= 1; // inside the genesis id
        assert!(bind_err(&bad).contains("damaged file header"));
        let mut bad_magic = good.clone();
        bad_magic[3] ^= 1;
        assert!(bind_err(&bad_magic).contains("not a block store"));
        assert!(bind_err(b"hello, this is not a store").contains("not a block store"));
        for (v, text) in [(1u32, "format version 1"), (3, "version 3")] {
            let mut other = good.clone();
            other[4..8].copy_from_slice(&v.to_le_bytes());
            let crc = crc32fast::hash(&other[..44]);
            other[44..48].copy_from_slice(&crc.to_le_bytes());
            let msg = bind_err(&other);
            assert!(msg.contains(text), "{msg}");
        }

        // Torn header on creation.
        for cut in [1, 4, 30, FILE_HEADER - 1] {
            std::fs::write(&path, &good[..cut]).unwrap();
            let mut s = bound(&path);
            assert!(s.load().unwrap().is_empty());
            drop(s);
            assert_eq!(std::fs::read(&path).unwrap(), &good[..FILE_HEADER]);
        }

        // A torn last record after the header.
        std::fs::write(&path, &good[..good.len() - 3]).unwrap();
        assert_eq!(load(&path).unwrap().len(), 1);

        // Mid-file corruption after the header: repair keeps header and prefix.
        let mut bytes = good.clone();
        bytes[FILE_HEADER + RECORD_HEADER + 3] ^= 0xff; // first record's body
        std::fs::write(&path, &bytes).unwrap();
        assert!(load(&path).is_err());
        FileStore::repair(&path, 5).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), &good[..FILE_HEADER]);
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn a_memory_store_is_bound_too() {
        let mut s = MemoryStore::default();
        s.bind(&REGTEST).unwrap();
        s.bind(&REGTEST).unwrap();
        assert!(s
            .bind(&StoreIdentity {
                genesis_id: [0; 32],
                ..REGTEST
            })
            .is_err());
    }
}
