//! Contract objects and the fixed-layout records passed to contracts
//! (docs/contracts.md §4, §9.4).

use blacksilk_crypto::commitment::coinbase_commitment;
use blacksilk_crypto::Point;

/// Contract ids, note ids and code hashes are 32-byte hashes.
pub type Id = [u8; 32];

/// Longest note policy (§4.3).
pub const MAX_POLICY: usize = 64;

/// The stealth fields of a private note: a stealth output toward the
/// beneficiary (transactions.md §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateNote {
    pub one_time_key: Point,
    pub ephemeral: Point,
    pub view_tag: u8,
    pub commitment: Point,
    pub enc_amount: [u8; 8],
    pub enc_anchor: [u8; 16],
}

/// A note body: private (boxed; it is large) or public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoteBody {
    Private(Box<PrivateNote>),
    Public { amount: u64 },
}

/// Value held by a contract (§4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: Id,
    pub owner: Id,
    pub policy: Vec<u8>,
    pub height: u64,
    pub body: NoteBody,
}

impl Note {
    /// The note's commitment: transmitted for private notes, `1·G + a·H` for
    /// public ones (like a coinbase output).
    pub fn commitment(&self) -> Point {
        match &self.body {
            NoteBody::Private(p) => p.commitment,
            NoteBody::Public { amount } => Point::from_point(coinbase_commitment(*amount)),
        }
    }

    pub fn is_public(&self) -> bool {
        matches!(self.body, NoteBody::Public { .. })
    }

    /// Canonical encoding, hashed into the state root (§10.2).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.owner);
        out.push(self.policy.len() as u8);
        out.extend_from_slice(&self.policy);
        out.extend_from_slice(&self.height.to_le_bytes());
        match &self.body {
            NoteBody::Private(p) => {
                out.push(0);
                out.extend_from_slice(p.one_time_key.bytes());
                out.extend_from_slice(p.ephemeral.bytes());
                out.push(p.view_tag);
                out.extend_from_slice(p.commitment.bytes());
                out.extend_from_slice(&p.enc_amount);
                out.extend_from_slice(&p.enc_anchor);
            }
            NoteBody::Public { amount } => {
                out.push(1);
                out.extend_from_slice(&amount.to_le_bytes());
            }
        }
        out
    }

    /// The 200-byte record a contract reads (§9.4):
    ///
    /// ```text
    /// id 32 ‖ type u8 ‖ policy_len u8 ‖ policy 64 (zero-padded) ‖ height u64 ‖
    /// amount u64 (public; 0 for private) ‖ O 32 (private; zero for public) ‖ Cm 32 ‖
    /// index-in-tx u16 ‖ pad 20
    /// ```
    pub fn record(&self, index_in_tx: u16) -> [u8; NOTE_RECORD_BYTES] {
        let mut r = [0u8; NOTE_RECORD_BYTES];
        r[0..32].copy_from_slice(&self.id);
        r[32] = u8::from(self.is_public());
        r[33] = self.policy.len() as u8;
        r[34..34 + self.policy.len()].copy_from_slice(&self.policy);
        r[98..106].copy_from_slice(&self.height.to_le_bytes());
        match &self.body {
            NoteBody::Private(p) => r[114..146].copy_from_slice(p.one_time_key.bytes()),
            NoteBody::Public { amount } => r[106..114].copy_from_slice(&amount.to_le_bytes()),
        }
        r[146..178].copy_from_slice(self.commitment().bytes());
        r[178..180].copy_from_slice(&index_in_tx.to_le_bytes());
        r
    }
}

pub const NOTE_RECORD_BYTES: usize = 200;
pub const CLAIM_RECORD_BYTES: usize = 96;
pub const MEMBER_RECORD_BYTES: usize = 80;

/// Where a claim's commitment comes from (§5.1 `ref`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefTag {
    PseudoOutput = 0,
    Output = 1,
    NewNote = 2,
    ConsumedNote = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref {
    pub tag: RefTag,
    pub index: u16,
}

/// A claim, already verified by the transaction layer (§8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimFact {
    Range {
        at: Ref,
        commitment: Point,
        min: u64,
        max: u64,
    },
    Equal {
        a: Ref,
        b: Ref,
        commitment_a: Point,
        commitment_b: Point,
    },
    Reveal {
        at: Ref,
        commitment: Point,
        value: u64,
    },
}

impl ClaimFact {
    /// The 96-byte record (§9.4):
    ///
    /// ```text
    /// kind u8 ‖ ref_tag u8 ‖ ref_index u16 ‖ ref2_tag u8 ‖ pad 1 ‖ ref2_index u16 ‖
    /// min u64 ‖ max u64 ‖ value u64 ‖ C 32 ‖ C2 32 (Equal only; zero otherwise)
    /// ```
    pub fn record(&self) -> [u8; CLAIM_RECORD_BYTES] {
        let mut r = [0u8; CLAIM_RECORD_BYTES];
        let put_ref = |r: &mut [u8; CLAIM_RECORD_BYTES], tag_at: usize, idx_at: usize, x: &Ref| {
            r[tag_at] = x.tag as u8;
            r[idx_at..idx_at + 2].copy_from_slice(&x.index.to_le_bytes());
        };
        match self {
            ClaimFact::Range {
                at,
                commitment,
                min,
                max,
            } => {
                r[0] = 0;
                put_ref(&mut r, 1, 2, at);
                r[8..16].copy_from_slice(&min.to_le_bytes());
                r[16..24].copy_from_slice(&max.to_le_bytes());
                r[32..64].copy_from_slice(commitment.bytes());
            }
            ClaimFact::Equal {
                a,
                b,
                commitment_a,
                commitment_b,
            } => {
                r[0] = 1;
                put_ref(&mut r, 1, 2, a);
                put_ref(&mut r, 4, 6, b);
                r[32..64].copy_from_slice(commitment_a.bytes());
                r[64..96].copy_from_slice(commitment_b.bytes());
            }
            ClaimFact::Reveal {
                at,
                commitment,
                value,
            } => {
                r[0] = 2;
                put_ref(&mut r, 1, 2, at);
                r[24..32].copy_from_slice(&value.to_le_bytes());
                r[32..64].copy_from_slice(commitment.bytes());
            }
        }
        r
    }
}

/// A scoped membership proof, already verified by the transaction layer (§7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberFact {
    pub owner: Id,
    pub set_id: u32,
    pub scope: Vec<u8>,
    pub ring_size: u8,
    pub tag: Point,
}

impl MemberFact {
    /// The 80-byte record (§9.4):
    /// `set_id u32 ‖ ring_size u8 ‖ scope_len u8 ‖ pad 2 ‖ scope 32 ‖ tag 32 ‖ pad 8`.
    pub fn record(&self) -> [u8; MEMBER_RECORD_BYTES] {
        let mut r = [0u8; MEMBER_RECORD_BYTES];
        r[0..4].copy_from_slice(&self.set_id.to_le_bytes());
        r[4] = self.ring_size;
        r[5] = self.scope.len() as u8;
        r[8..8 + self.scope.len()].copy_from_slice(&self.scope);
        r[40..72].copy_from_slice(self.tag.bytes());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_crypto::RistrettoPoint;

    fn pt(n: u64) -> Point {
        Point::from_point(RistrettoPoint::mul_base(&blacksilk_crypto::Scalar::from(n)))
    }

    #[test]
    fn note_records_have_the_documented_layout() {
        let private = Note {
            id: [1; 32],
            owner: [2; 32],
            policy: vec![9; MAX_POLICY],
            height: 77,
            body: NoteBody::Private(Box::new(PrivateNote {
                one_time_key: pt(3),
                ephemeral: pt(4),
                view_tag: 5,
                commitment: pt(6),
                enc_amount: [7; 8],
                enc_anchor: [8; 16],
            })),
        };
        let r = private.record(3);
        assert_eq!(&r[0..32], &[1; 32]);
        assert_eq!(r[32], 0);
        assert_eq!(r[33], 64);
        assert_eq!(&r[34..98], &[9; 64][..]);
        assert_eq!(u64::from_le_bytes(r[98..106].try_into().unwrap()), 77);
        assert_eq!(&r[106..114], &[0; 8]);
        assert_eq!(&r[114..146], pt(3).bytes());
        assert_eq!(&r[146..178], pt(6).bytes());
        assert_eq!(u16::from_le_bytes([r[178], r[179]]), 3);
        assert!(r[180..].iter().all(|b| *b == 0));

        let public = Note {
            body: NoteBody::Public { amount: 1_000 },
            policy: vec![1, 2],
            ..private
        };
        let r = public.record(0);
        assert_eq!(r[32], 1);
        assert_eq!(r[33], 2);
        assert_eq!(&r[36..98], &[0; 62][..], "policy is zero-padded");
        assert_eq!(u64::from_le_bytes(r[106..114].try_into().unwrap()), 1_000);
        assert_eq!(&r[114..146], &[0; 32]);
        assert_eq!(
            public.commitment(),
            Point::from_point(coinbase_commitment(1_000))
        );
    }

    #[test]
    fn encodings_distinguish_note_kinds_and_fields() {
        let base = Note {
            id: [1; 32],
            owner: [2; 32],
            policy: vec![],
            height: 1,
            body: NoteBody::Public { amount: 5 },
        };
        let mut other = base.clone();
        other.body = NoteBody::Public { amount: 6 };
        assert_ne!(base.encode(), other.encode());
        let mut other = base.clone();
        other.policy = vec![0];
        assert_ne!(base.encode(), other.encode());
    }

    #[test]
    fn claim_and_member_records() {
        let c = ClaimFact::Equal {
            a: Ref {
                tag: RefTag::NewNote,
                index: 2,
            },
            b: Ref {
                tag: RefTag::ConsumedNote,
                index: 0x0102,
            },
            commitment_a: pt(1),
            commitment_b: pt(2),
        };
        let r = c.record();
        assert_eq!(r[0], 1);
        assert_eq!((r[1], r[2], r[3]), (2, 2, 0));
        assert_eq!((r[4], r[6], r[7]), (3, 2, 1));
        assert_eq!(&r[32..64], pt(1).bytes());
        assert_eq!(&r[64..96], pt(2).bytes());

        let m = MemberFact {
            owner: [0; 32],
            set_id: 7,
            scope: b"proposal-17".to_vec(),
            ring_size: 16,
            tag: pt(9),
        };
        let r = m.record();
        assert_eq!(u32::from_le_bytes(r[0..4].try_into().unwrap()), 7);
        assert_eq!((r[4], r[5]), (16, 11));
        assert_eq!(&r[8..19], b"proposal-17");
        assert_eq!(&r[40..72], pt(9).bytes());
    }
}
