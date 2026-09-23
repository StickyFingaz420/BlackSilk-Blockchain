//! Contract state, its commitment and per-block undo (docs/contracts.md §10).
//!
//! Execution never mutates [`ContractState`] directly. It produces a
//! [`StateDiff`] against a read-only state; [`ContractState::commit`] applies a
//! diff and records how to undo it. Blocks group undo records, so a
//! reorganization can disconnect them in reverse order, exactly like the
//! transaction state (`tx::state::MemoryChain`).

use crate::smt::{Hash, Smt};
use crate::types::{Id, Note};
use blacksilk_crypto::hash::{h32, tags};
use blacksilk_crypto::Point;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Leaf types of the state tree (§10.2).
const LEAF_KV: u8 = 0;
const LEAF_NOTE: u8 = 1;
const LEAF_KEYSET: u8 = 2;
const LEAF_CONTRACT: u8 = 3;

fn path(contract: &Id, kind: u8, key: &[u8]) -> Hash {
    h32(tags::CONTRACT_STATE_KEY, &[contract, &[kind], key])
}

fn leaf(kind: u8, body: &[&[u8]]) -> Hash {
    let mut parts: Vec<&[u8]> = vec![std::slice::from_ref(&kind)];
    parts.extend_from_slice(body);
    h32(tags::CONTRACT_STATE_LEAF, &parts)
}

fn keyset_key(set: u32, index: u32) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[..4].copy_from_slice(&set.to_le_bytes());
    k[4..].copy_from_slice(&index.to_le_bytes());
    k
}

/// Size of a key–value entry for storage accounting (§9.6).
pub fn entry_size(key: &[u8], value: &[u8]) -> u64 {
    32 + key.len() as u64 + value.len() as u64
}

/// Everything one transaction changes. Maps are ordered, so applying a diff is
/// deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDiff {
    /// `(contract, key) → Some(value)` (write) or `None` (delete).
    pub kv: BTreeMap<(Id, Vec<u8>), Option<Vec<u8>>>,
    pub notes_created: Vec<Note>,
    pub notes_consumed: Vec<Id>,
    /// Appended keys per `(contract, set)`, in order.
    pub keyset_appends: BTreeMap<(Id, u32), Vec<Point>>,
    /// A new contract: `(id, code)`.
    pub deployed: Option<(Id, Arc<Vec<u8>>)>,
}

enum Undo {
    Kv {
        contract: Id,
        key: Vec<u8>,
        old: Option<Vec<u8>>,
    },
    NoteCreated(Id),
    NoteConsumed(Box<Note>),
    KeysetAppend {
        contract: Id,
        set: u32,
    },
    Deployed {
        id: Id,
        code_hash: Id,
        code_was_new: bool,
    },
}

#[derive(Default)]
pub struct ContractState {
    code: HashMap<Id, Arc<Vec<u8>>>,
    contracts: HashMap<Id, Id>,
    kv: HashMap<Id, BTreeMap<Vec<u8>, Vec<u8>>>,
    kv_bytes: HashMap<Id, u64>,
    notes: HashMap<Id, Note>,
    keysets: HashMap<(Id, u32), Vec<Point>>,
    tree: Smt,
    blocks: Vec<Vec<Undo>>,
}

pub fn code_hash(code: &[u8]) -> Id {
    h32(tags::CONTRACT_CODE, &[code])
}

impl ContractState {
    pub fn new() -> Self {
        Self::default()
    }

    // ---- reads ----

    pub fn contract_code(&self, id: &Id) -> Option<&Arc<Vec<u8>>> {
        self.contracts.get(id).and_then(|h| self.code.get(h))
    }

    pub fn contract_code_hash(&self, id: &Id) -> Option<&Id> {
        self.contracts.get(id)
    }

    pub fn contract_exists(&self, id: &Id) -> bool {
        self.contracts.contains_key(id)
    }

    pub fn code_known(&self, hash: &Id) -> bool {
        self.code.contains_key(hash)
    }

    pub fn get(&self, contract: &Id, key: &[u8]) -> Option<&Vec<u8>> {
        self.kv.get(contract).and_then(|m| m.get(key))
    }

    /// Total key–value bytes of a contract (`Σ entry_size`).
    pub fn kv_bytes(&self, contract: &Id) -> u64 {
        self.kv_bytes.get(contract).copied().unwrap_or(0)
    }

    pub fn note(&self, id: &Id) -> Option<&Note> {
        self.notes.get(id)
    }

    /// Unconsumed notes owned by `contract`, sorted by id.
    pub fn notes_of(&self, contract: &Id) -> Vec<&Note> {
        let mut v: Vec<&Note> = self
            .notes
            .values()
            .filter(|n| &n.owner == contract)
            .collect();
        v.sort_by_key(|n| n.id);
        v
    }

    pub fn keyset(&self, contract: &Id, set: u32) -> &[Point] {
        self.keysets
            .get(&(*contract, set))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Number of blocks with undo records (= height of the next block to apply).
    pub fn blocks(&self) -> usize {
        self.blocks.len()
    }

    /// The state root after all committed changes (§10.2).
    pub fn root(&mut self) -> Hash {
        self.tree.root()
    }

    // ---- writes ----

    /// Starts the undo record of a new block. Every [`Self::commit`] until the
    /// next `begin_block` belongs to this block.
    pub fn begin_block(&mut self) {
        self.blocks.push(Vec::new());
    }

    fn set_kv(&mut self, contract: Id, key: Vec<u8>, value: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let map = self.kv.entry(contract).or_default();
        let old = match &value {
            Some(v) => map.insert(key.clone(), v.clone()),
            None => map.remove(&key),
        };
        if map.is_empty() {
            self.kv.remove(&contract);
        }
        let bytes = self.kv_bytes.entry(contract).or_default();
        if let Some(o) = &old {
            *bytes -= entry_size(&key, o);
        }
        if let Some(v) = &value {
            *bytes += entry_size(&key, v);
        }
        if *bytes == 0 {
            self.kv_bytes.remove(&contract);
        }
        let p = path(&contract, LEAF_KV, &key);
        let l = value.as_ref().map(|v| {
            leaf(
                LEAF_KV,
                &[&contract, &(key.len() as u32).to_le_bytes(), &key, v],
            )
        });
        self.tree.update(p, l);
        old
    }

    fn insert_note(&mut self, note: Note) {
        self.tree.update(
            path(&note.owner, LEAF_NOTE, &note.id),
            Some(leaf(LEAF_NOTE, &[&note.encode()])),
        );
        self.notes.insert(note.id, note);
    }

    fn remove_note(&mut self, id: &Id) -> Option<Note> {
        let note = self.notes.remove(id)?;
        self.tree.update(path(&note.owner, LEAF_NOTE, id), None);
        Some(note)
    }

    /// Applies a diff produced by execution against this exact state. Panics on
    /// a diff that does not fit the state (a node bug, never a peer's fault:
    /// diffs are produced locally).
    pub fn commit(&mut self, diff: StateDiff) {
        let mut undo = Vec::new();
        if let Some((id, code)) = diff.deployed {
            let hash = code_hash(&code);
            let code_was_new = !self.code.contains_key(&hash);
            if code_was_new {
                self.code.insert(hash, code);
            }
            assert!(
                self.contracts.insert(id, hash).is_none(),
                "contract id reused"
            );
            self.tree.update(
                path(&id, LEAF_CONTRACT, &[]),
                Some(leaf(LEAF_CONTRACT, &[&hash])),
            );
            undo.push(Undo::Deployed {
                id,
                code_hash: hash,
                code_was_new,
            });
        }
        for ((contract, key), value) in diff.kv {
            let old = self.set_kv(contract, key.clone(), value);
            undo.push(Undo::Kv { contract, key, old });
        }
        for id in diff.notes_consumed {
            let note = self.remove_note(&id).expect("consumed note exists");
            undo.push(Undo::NoteConsumed(Box::new(note)));
        }
        for note in diff.notes_created {
            assert!(!self.notes.contains_key(&note.id), "note id reused");
            undo.push(Undo::NoteCreated(note.id));
            self.insert_note(note);
        }
        for ((contract, set), keys) in diff.keyset_appends {
            for key in keys {
                let list = self.keysets.entry((contract, set)).or_default();
                let index = list.len() as u32;
                list.push(key);
                self.tree.update(
                    path(&contract, LEAF_KEYSET, &keyset_key(set, index)),
                    Some(leaf(LEAF_KEYSET, &[key.bytes()])),
                );
                undo.push(Undo::KeysetAppend { contract, set });
            }
        }
        match self.blocks.last_mut() {
            Some(block) => block.extend(undo),
            None => panic!("commit outside a block"),
        }
    }

    /// Disconnects the last block. Returns `false` if there is none.
    pub fn undo_block(&mut self) -> bool {
        let Some(block) = self.blocks.pop() else {
            return false;
        };
        for u in block.into_iter().rev() {
            match u {
                Undo::Kv { contract, key, old } => {
                    self.set_kv(contract, key, old);
                }
                Undo::NoteCreated(id) => {
                    self.remove_note(&id);
                }
                Undo::NoteConsumed(note) => self.insert_note(*note),
                Undo::KeysetAppend { contract, set } => {
                    let list = self.keysets.get_mut(&(contract, set)).expect("keyset");
                    list.pop();
                    let index = list.len() as u32;
                    if list.is_empty() {
                        self.keysets.remove(&(contract, set));
                    }
                    self.tree
                        .update(path(&contract, LEAF_KEYSET, &keyset_key(set, index)), None);
                }
                Undo::Deployed {
                    id,
                    code_hash,
                    code_was_new,
                } => {
                    self.contracts.remove(&id);
                    if code_was_new {
                        self.code.remove(&code_hash);
                    }
                    self.tree.update(path(&id, LEAF_CONTRACT, &[]), None);
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteBody;

    fn note(id: u8, owner: u8, amount: u64) -> Note {
        Note {
            id: [id; 32],
            owner: [owner; 32],
            policy: vec![id],
            height: 1,
            body: NoteBody::Public { amount },
        }
    }

    #[test]
    fn commit_and_undo_restore_state_and_root() {
        let mut s = ContractState::new();
        let empty = s.root();
        assert_eq!(empty, [0; 32]);

        s.begin_block();
        let mut d = StateDiff {
            deployed: Some(([1; 32], Arc::new(vec![0, 97, 115, 109]))),
            ..Default::default()
        };
        d.kv.insert(([1; 32], b"a".to_vec()), Some(b"1".to_vec()));
        d.notes_created.push(note(5, 1, 100));
        d.keyset_appends.insert(
            ([1; 32], 0),
            vec![Point::from_point(
                blacksilk_crypto::RistrettoPoint::mul_base(&blacksilk_crypto::Scalar::ONE),
            )],
        );
        s.commit(d);
        let r1 = s.root();
        assert_ne!(r1, empty);
        assert_eq!(s.get(&[1; 32], b"a"), Some(&b"1".to_vec()));
        assert_eq!(s.kv_bytes(&[1; 32]), entry_size(b"a", b"1"));
        assert_eq!(s.keyset(&[1; 32], 0).len(), 1);

        s.begin_block();
        let mut d = StateDiff::default();
        d.kv.insert(([1; 32], b"a".to_vec()), Some(b"22".to_vec()));
        d.kv.insert(([1; 32], b"b".to_vec()), Some(vec![]));
        d.notes_consumed.push([5; 32]);
        d.notes_created.push(note(6, 1, 60));
        s.commit(d);
        assert_ne!(s.root(), r1);
        assert!(s.note(&[5; 32]).is_none());

        assert!(s.undo_block());
        assert_eq!(s.root(), r1, "undo restores the exact root");
        assert_eq!(s.get(&[1; 32], b"a"), Some(&b"1".to_vec()));
        assert!(s.get(&[1; 32], b"b").is_none());
        assert_eq!(s.note(&[5; 32]), Some(&note(5, 1, 100)));
        assert!(s.note(&[6; 32]).is_none());
        assert_eq!(s.kv_bytes(&[1; 32]), entry_size(b"a", b"1"));

        assert!(s.undo_block());
        assert_eq!(s.root(), empty);
        assert!(!s.contract_exists(&[1; 32]));
        assert!(s.contract_code(&[1; 32]).is_none());
        assert_eq!(s.keyset(&[1; 32], 0).len(), 0);
        assert_eq!(s.kv_bytes(&[1; 32]), 0);
        assert!(!s.undo_block());
    }

    #[test]
    fn root_depends_on_content_not_history() {
        let mut a = ContractState::new();
        a.begin_block();
        let mut d = StateDiff::default();
        d.kv.insert(([2; 32], b"k".to_vec()), Some(b"v".to_vec()));
        a.commit(d);

        let mut b = ContractState::new();
        b.begin_block();
        let mut d = StateDiff::default();
        d.kv.insert(([2; 32], b"k".to_vec()), Some(b"x".to_vec()));
        d.kv.insert(([2; 32], b"tmp".to_vec()), Some(b"y".to_vec()));
        b.commit(d);
        b.begin_block();
        let mut d = StateDiff::default();
        d.kv.insert(([2; 32], b"k".to_vec()), Some(b"v".to_vec()));
        d.kv.insert(([2; 32], b"tmp".to_vec()), None);
        b.commit(d);

        assert_eq!(a.root(), b.root());
        // Same key and value under another contract is another leaf.
        let mut c = ContractState::new();
        c.begin_block();
        let mut d = StateDiff::default();
        d.kv.insert(([3; 32], b"k".to_vec()), Some(b"v".to_vec()));
        c.commit(d);
        assert_ne!(a.root(), c.root());
    }

    #[test]
    fn shared_code_is_stored_once_and_kept_on_partial_undo() {
        let code = Arc::new(vec![1, 2, 3]);
        let mut s = ContractState::new();
        s.begin_block();
        s.commit(StateDiff {
            deployed: Some(([1; 32], code.clone())),
            ..Default::default()
        });
        s.begin_block();
        s.commit(StateDiff {
            deployed: Some(([2; 32], code.clone())),
            ..Default::default()
        });
        assert_eq!(
            s.contract_code_hash(&[1; 32]),
            s.contract_code_hash(&[2; 32])
        );
        s.undo_block();
        assert!(
            s.contract_code(&[1; 32]).is_some(),
            "code still used by contract 1"
        );
        assert!(!s.contract_exists(&[2; 32]));
    }
}
