//! Record delivery (zk.md §4.6, DR-7; docs/px.md §6): each output carries its
//! record, encrypted to the recipient's address.
//!
//! **Hybrid encryption.** Both parts are needed to decrypt:
//! - ECDH on Ristretto255 with the address's view key: `ss_ec = r·V`;
//! - ML-KEM-768 (FIPS 203) to the address's encapsulation key: `ss_kem`.
//!
//! The AEAD key (combiner v2) is
//! `H32("px/delivery-key/v2", ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ V ‖ H(ek) ‖ cm)`
//! with `H(ek) = H32("px/delivery-ek", ek)`: a hash of both shared secrets,
//! both ciphertexts (the ephemeral `R` and the KEM ciphertext) and both of
//! the recipient's public keys (the view key `V` and the hash of the
//! encapsulation key `ek`), bound to the output's commitment `cm`. Every part
//! has a fixed length, so the concatenation is unambiguous. The body is
//! ChaCha20-Poly1305 with `cm` as associated data. Every key is fresh (new `r`
//! and new KEM randomness), so the nonce is zero.
//!
//! **Why `V` and `H(ek)` are bound** (decided for the v3 reset, decisions.md
//! "RES-FREEZE verified"): binding the classical ciphertext and both
//! recipient public keys, in the style of the X-Wing and generic hybrid KEM
//! combiners, ties the key to one recipient, so a hybrid share cannot be
//! re-targeted to another key pair. Including `ct_kem` is redundant given
//! ML-KEM's own ciphertext binding, but harmless. The v1 combiner (tag
//! `"px/delivery-key"`, without `V` and `H(ek)`) is gone; the reset leaves no
//! ciphertext made with it.
//!
//! **This is not the X-Wing combiner**, and its security argument must not be
//! borrowed from X-Wing. X-Wing (draft-connolly-cfrg-xwing-kem) hashes
//! `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label` over its own fixed component KEMs; this
//! combiner differs in its inputs, its hash and its classical component. Its
//! argument rests on what it shares with them (every shared secret, every
//! ciphertext and every recipient public key are hashed) and on its use:
//! every key is used once, for one body whose tag and associated data bind
//! `cm`, and the recipient accepts a record only if it recomputes `cm`.
//!
//! **Key separation (limits).** The delivery keys of an address derive from
//! the PX spend secret `sk` and the index alone:
//! - there is no view/spend separation: no view key from which a scanning
//!   (watch-only) wallet could derive the delivery keys of every address
//!   without `sk`. Exporting one address's delivery keys would not give
//!   `sk` (the derivation is one-way), but no wallet mode does this, and such
//!   keys would not see spends (nullifiers need `nk`);
//! - the derivation does not include the network: one seed gives the same PX
//!   keys (and owner tags) on every network. Address encodings differ per
//!   network; the keys do not.
//!
//! **Hedged randomness** (docs/transactions.md §10). The sender's ephemeral
//! scalar `r` and the ML-KEM encapsulation coins `m` are not drawn from the
//! caller's RNG directly. They come from a
//! [`HedgedRng`](blacksilk_crypto::nonce::HedgedRng) keyed with a sender
//! secret (required: [`seal`] refuses an empty or all-zero one) and bound to
//! the full delivery statement: the recipient's owner tag, view key and whole
//! encapsulation key, the commitment `cm`, and the complete plaintext
//! (contract, value, data, `rcm`) plus `rho` (which fixes the output index).
//! With a broken or constant RNG, `r` and `m` therefore stay unknown to anyone
//! without the sender secret, and two deliveries of different records never
//! share them. The ciphertext format is unchanged.
//!
//! Record contents therefore stay confidential unless **both** the discrete
//! logarithm in Ristretto255 and ML-KEM-768 are broken: a future quantum
//! adversary that breaks the first still faces the second.
//!
//! **Acceptance (Janus principle).** A recipient accepts a decrypted record
//! only if it recomputes the on-chain commitment exactly, with its own owner
//! tag. A ciphertext whose contents disagree with `cm` (a probe) is ignored.
//!
//! **Contract records** (docs/px.md §13). The plaintext carries the record's
//! contract (zero for a user record). A contract record has owner 0, so it is
//! opened without the recipient's owner tag: the caller that creates it
//! addresses it to the party that will act on it. The same commitment check
//! applies, so a recipient only ever accepts a real record.
//!
//! **Scanning.** The one-byte view tag, from `ss_ec`, lets a wallet skip ~255
//! of 256 foreign outputs after one scalar multiplication per address. Keys
//! are per address (unlinkable addresses), so scanning costs one scalar
//! multiplication per output and wallet address.
//!
//! This is wallet-side code: consensus only fixes the ciphertext length.

use blacksilk_crypto::hash::{h32, h64, tags};
use blacksilk_crypto::nonce::HedgedRng;
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar;
use ml_kem::{Decapsulate, KeyExport, MlKem768};
use rand_core::{CryptoRng, RngCore};

pub const EK_BYTES: usize = 1184;
pub const KEM_CT_BYTES: usize = 1088;
/// Plaintext: contract (32) ‖ value (8) ‖ data (32) ‖ rcm (32). The same
/// length for user and contract records, so the ciphertext does not reveal
/// the kind.
pub const PLAIN_BYTES: usize = 104;
pub const TAG_BYTES: usize = 16;
/// Encoded ciphertext: `R ‖ view tag ‖ ct_kem ‖ body`.
pub const CIPHERTEXT_BYTES: usize = 32 + 1 + KEM_CT_BYTES + PLAIN_BYTES + TAG_BYTES;

type Dk = ml_kem::DecapsulationKey<MlKem768>;
type Ek = ml_kem::EncapsulationKey<MlKem768>;

/// The secret delivery keys of one address (zeroized on drop; the ML-KEM key
/// zeroizes itself), with the address's public view key `V` and `H(ek)`, which
/// the key combiner binds (module docs), computed once.
pub struct DeliveryKeys {
    view: Scalar,
    dk: Dk,
    view_pub: [u8; 32],
    ek_hash: [u8; 32],
}

impl Drop for DeliveryKeys {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.view);
    }
}

/// The public part of an address: what a sender needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address {
    /// Owner tag of the records paid to this address.
    pub owner: Digest,
    /// Compressed Ristretto view key `V = v·G`.
    pub view: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ek: Vec<u8>,
}

fn digest_bytes(d: &Digest) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    b
}

impl DeliveryKeys {
    /// Keys of address `index`, derived from the PX spend secret.
    pub fn derive(sk: &Digest, index: u32) -> DeliveryKeys {
        let skb = digest_bytes(sk);
        let idx = index.to_le_bytes();
        let view = Scalar::from_bytes_mod_order_wide(&h64(tags::PX_DELIVERY_VIEW, &[&skb, &idx]));
        let seed = h64(tags::PX_DELIVERY_KEM, &[&skb, &idx]);
        let dk = Dk::from_seed(seed.into());
        let view_pub = (&view * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
        let ek_hash = ek_hash(&dk.encapsulation_key().to_bytes());
        DeliveryKeys {
            view,
            dk,
            view_pub,
            ek_hash,
        }
    }

    pub fn address(&self, owner: Digest) -> Address {
        Address {
            owner,
            view: self.view_pub,
            ek: self.dk.encapsulation_key().to_bytes().to_vec(),
        }
    }
}

/// `H(ek)`: the hash of an encoded ML-KEM-768 encapsulation key, as the key
/// combiner binds it.
fn ek_hash(ek: &[u8]) -> [u8; 32] {
    h32(tags::PX_DELIVERY_EK, &[ek])
}

fn view_tag(ss_ec: &[u8; 32], r: &[u8; 32]) -> u8 {
    h32(tags::PX_VIEW_TAG, &[ss_ec, r])[0]
}

/// The recipient's public keys as the key combiner binds them: the canonical
/// view key `V` and `H(ek)`.
struct Recipient<'a> {
    view: &'a [u8; 32],
    ek_hash: &'a [u8; 32],
}

/// The AEAD key (combiner v2, module docs):
/// `H32("px/delivery-key/v2", ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ V ‖ H(ek) ‖ cm)`.
fn key(
    ss_ec: &[u8; 32],
    ss_kem: &[u8],
    r: &[u8; 32],
    ct: &[u8],
    to: &Recipient<'_>,
    cm: &Digest,
) -> [u8; 32] {
    h32(
        tags::PX_DELIVERY_KEY,
        &[ss_ec, ss_kem, r, ct, to.view, to.ek_hash, &digest_bytes(cm)],
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// The address's view key or encapsulation key does not decode, or the
    /// view key is the identity.
    BadAddress,
    /// No hedge secret was supplied (empty or all zero): the ephemeral
    /// secrets would depend on the RNG alone.
    NoSecret,
}

/// Purpose label of the delivery hedge (first context item).
const HEDGE_LABEL: &[u8] = b"px/delivery/hedge/v1";

/// The hedge stream for one delivery: keyed with `secret`, bound to every
/// public and private input of the delivery.
fn hedge<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &[u8],
    to: &Address,
    record: &Record,
    cm: &Digest,
) -> HedgedRng {
    let owner = digest_bytes(&to.owner);
    let cm = digest_bytes(cm);
    let contract = digest_bytes(&record.contract);
    let value = record.value.to_le_bytes();
    let data = digest_bytes(&record.data);
    let rcm = zeroize::Zeroizing::new(digest_bytes(&record.rcm));
    let rho = digest_bytes(&record.rho);
    HedgedRng::new(
        &[secret],
        &[
            HEDGE_LABEL,
            &owner,
            &to.view,
            &to.ek,
            &cm,
            &contract,
            &value,
            &data,
            &*rcm,
            &rho,
        ],
        rng,
    )
}

/// Encrypts `record` (committed as `cm`) to `to`.
///
/// `hedge_secret` must be secret to the sender (for example
/// `blacksilk_px::wallet::Account::hedge_secret`); it keys the hedged
/// derivation of the ephemeral secrets (module docs). An empty or all-zero
/// secret is refused with [`SealError::NoSecret`].
pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    hedge_secret: &[u8],
    to: &Address,
    record: &Record,
    cm: &Digest,
) -> Result<Vec<u8>, SealError> {
    if hedge_secret.iter().all(|&b| b == 0) {
        return Err(SealError::NoSecret);
    }
    let v = CompressedRistretto(to.view)
        .decompress()
        .ok_or(SealError::BadAddress)?;
    // An identity view key makes `ss_ec` the identity for every `r`: the
    // classical half would give nothing (R2-C9).
    if v.is_identity() {
        return Err(SealError::BadAddress);
    }
    let ek_arr =
        ml_kem::Key::<Ek>::try_from(to.ek.as_slice()).map_err(|_| SealError::BadAddress)?;
    let ek = Ek::new(&ek_arr).map_err(|_| SealError::BadAddress)?;

    // Ephemeral secrets (hedged, module docs) are wiped on drop.
    let mut stream = hedge(rng, hedge_secret, to, record, cm);
    let r = zeroize::Zeroizing::new(stream.scalar());
    let r_pub = (&*r * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
    let ss_ec = zeroize::Zeroizing::new((*r * v).compress().to_bytes());
    let mut m = zeroize::Zeroizing::new([0u8; 32]);
    stream.fill_bytes(&mut *m);
    drop(stream);
    let (ct, ss_kem) = ek.encapsulate_deterministic(&(*m).into());

    // `V` decoded, so `to.view` is its canonical encoding; `ek` is hashed as
    // re-encoded, the bytes the recipient hashes.
    let recipient = Recipient {
        view: &to.view,
        ek_hash: &ek_hash(&ek.to_bytes()),
    };
    let k = zeroize::Zeroizing::new(key(
        &ss_ec,
        ss_kem.as_slice(),
        &r_pub,
        ct.as_slice(),
        &recipient,
        cm,
    ));
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(PLAIN_BYTES));
    plain.extend_from_slice(&digest_bytes(&record.contract));
    plain.extend_from_slice(&record.value.to_le_bytes());
    plain.extend_from_slice(&digest_bytes(&record.data));
    plain.extend_from_slice(&digest_bytes(&record.rcm));
    let body = ChaCha20Poly1305::new(&(*k).into())
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: plain.as_slice(),
                aad: &digest_bytes(cm),
            },
        )
        .expect("encryption of a short message cannot fail");

    let mut out = Vec::with_capacity(CIPHERTEXT_BYTES);
    out.extend_from_slice(&r_pub);
    out.push(view_tag(&ss_ec, &r_pub));
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(&body);
    debug_assert_eq!(out.len(), CIPHERTEXT_BYTES);
    Ok(out)
}

fn digest_from(b: &[u8]) -> Option<Digest> {
    let mut d = [0u32; 8];
    for (i, x) in d.iter_mut().enumerate() {
        *x = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().ok()?);
        if *x >= P {
            return None;
        }
    }
    Some(d)
}

/// Tries to open output ciphertext `c` with commitment `cm` and nullifier-
/// derived `rho`, as the address with `keys` and owner tag `owner`. Returns the
/// record only if it recomputes `cm`: a user record paid to `owner`, or a
/// contract record (`contract ≠ 0`, owner 0) addressed to this address.
pub fn open(
    keys: &DeliveryKeys,
    owner: &Digest,
    c: &[u8],
    cm: &Digest,
    rho: &Digest,
) -> Option<Record> {
    if c.len() != CIPHERTEXT_BYTES {
        return None;
    }
    let r_pub: [u8; 32] = c[..32].try_into().ok()?;
    let r = CompressedRistretto(r_pub).decompress()?;
    let ss_ec = zeroize::Zeroizing::new((keys.view * r).compress().to_bytes());
    if view_tag(&ss_ec, &r_pub) != c[32] {
        return None;
    }
    let ct_bytes = &c[33..33 + KEM_CT_BYTES];
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes).ok()?;
    let ss_kem = keys.dk.decapsulate(&ct);
    let recipient = Recipient {
        view: &keys.view_pub,
        ek_hash: &keys.ek_hash,
    };
    let k = zeroize::Zeroizing::new(key(
        &ss_ec,
        ss_kem.as_slice(),
        &r_pub,
        ct_bytes,
        &recipient,
        cm,
    ));
    let plain = zeroize::Zeroizing::new(
        ChaCha20Poly1305::new(&(*k).into())
            .decrypt(
                &[0u8; 12].into(),
                Payload {
                    msg: &c[33 + KEM_CT_BYTES..],
                    aad: &digest_bytes(cm),
                },
            )
            .ok()?,
    );
    if plain.len() != PLAIN_BYTES {
        return None;
    }
    let contract = digest_from(&plain[..32])?;
    let value = u64::from_le_bytes(plain[32..40].try_into().ok()?);
    let data = digest_from(&plain[40..72])?;
    let rcm = digest_from(&plain[72..104])?;
    let record = Record {
        owner: if contract == ZERO_DIGEST {
            *owner
        } else {
            ZERO_DIGEST
        },
        contract,
        asset: ZERO_DIGEST,
        value,
        data,
        rho: *rho,
        rcm,
    };
    let mut perm = crate::perm::HostPerm::new();
    (record.commit(&mut perm) == *cm).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perm::HostPerm;
    use crate::wallet::Account;

    /// A "CSPRNG" that always outputs the same byte: a completely broken RNG.
    struct ConstRng;
    impl RngCore for ConstRng {
        fn next_u32(&mut self) -> u32 {
            0x4242_4242
        }
        fn next_u64(&mut self) -> u64 {
            0x4242_4242_4242_4242
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x42)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(0x42);
            Ok(())
        }
    }
    impl CryptoRng for ConstRng {}

    const SENDER: [u8; 32] = [0x5e; 32];

    fn record(owner: Digest, value: u64) -> (Record, Digest) {
        let rec = Record::plain(owner, value, [3; 8], [4; 8], [5; 8]);
        let cm = rec.commit(&mut HostPerm::new());
        (rec, cm)
    }

    fn r_and_kem(c: &[u8]) -> (&[u8], &[u8]) {
        (&c[..32], &c[33..33 + KEM_CT_BYTES])
    }

    /// R2-C2: under a constant RNG, two deliveries of different openings to
    /// the same recipient use different `r` and different ML-KEM coins (so a
    /// different `R` and KEM ciphertext), and both still open.
    #[test]
    fn broken_rng_different_openings_get_different_ephemeral_secrets() {
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(0);
        let keys = bob.delivery_keys(0);
        let (rec1, cm1) = record(to.owner, 10);
        let (rec2, cm2) = record(to.owner, 11);
        let c1 = seal(&mut ConstRng, &SENDER, &to, &rec1, &cm1).unwrap();
        let c2 = seal(&mut ConstRng, &SENDER, &to, &rec2, &cm2).unwrap();
        let (r1, k1) = r_and_kem(&c1);
        let (r2, k2) = r_and_kem(&c2);
        assert_ne!(r1, r2, "ECDH scalar r must differ");
        assert_ne!(k1, k2, "ML-KEM coins must differ");
        assert_eq!(open(&keys, &to.owner, &c1, &cm1, &rec1.rho), Some(rec1));
        assert_eq!(open(&keys, &to.owner, &c2, &cm2, &rec2.rho), Some(rec2));

        // Only rcm differs (same value, owner, data, rho): still separated.
        let mut rec3 = rec1;
        rec3.rcm = [6; 8];
        let cm3 = rec3.commit(&mut HostPerm::new());
        let c3 = seal(&mut ConstRng, &SENDER, &to, &rec3, &cm3).unwrap();
        assert_ne!(r_and_kem(&c1).0, r_and_kem(&c3).0);
        assert_ne!(r_and_kem(&c1).1, r_and_kem(&c3).1);

        // Same opening values, another address of the same wallet.
        let to1 = bob.address(1);
        let (rec4, cm4) = record(to1.owner, 10);
        let c4 = seal(&mut ConstRng, &SENDER, &to1, &rec4, &cm4).unwrap();
        assert_ne!(r_and_kem(&c1).0, r_and_kem(&c4).0);
    }

    /// Under a constant RNG the ephemeral values are unknown without the
    /// sender secret: another secret gives other values. Everything equal
    /// gives the same ciphertext (a deterministic, safe re-encryption).
    #[test]
    fn broken_rng_ephemeral_secrets_depend_on_the_sender_secret() {
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(0);
        let (rec, cm) = record(to.owner, 10);
        let a = seal(&mut ConstRng, &SENDER, &to, &rec, &cm).unwrap();
        let b = seal(&mut ConstRng, &[0x5f; 32], &to, &rec, &cm).unwrap();
        assert_ne!(r_and_kem(&a).0, r_and_kem(&b).0);
        assert_ne!(r_and_kem(&a).1, r_and_kem(&b).1);
        assert_eq!(a, seal(&mut ConstRng, &SENDER, &to, &rec, &cm).unwrap());
    }

    /// A working RNG still randomizes each delivery, and the result opens.
    #[test]
    fn working_rng_randomizes_and_opens() {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(2);
        let keys = bob.delivery_keys(2);
        let (rec, cm) = record(to.owner, 99);
        let a = seal(&mut rng, &SENDER, &to, &rec, &cm).unwrap();
        let b = seal(&mut rng, &SENDER, &to, &rec, &cm).unwrap();
        assert_ne!(r_and_kem(&a).0, r_and_kem(&b).0);
        assert_ne!(r_and_kem(&a).1, r_and_kem(&b).1);
        assert_eq!(open(&keys, &to.owner, &a, &cm, &rec.rho), Some(rec));
        assert_eq!(open(&keys, &to.owner, &b, &cm, &rec.rho), Some(rec));
    }

    /// Fail closed: no sender secret, no delivery.
    #[test]
    fn a_missing_hedge_secret_is_refused() {
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(0);
        let (rec, cm) = record(to.owner, 1);
        assert_eq!(
            seal(&mut ConstRng, &[], &to, &rec, &cm),
            Err(SealError::NoSecret)
        );
        assert_eq!(
            seal(&mut ConstRng, &[0; 32], &to, &rec, &cm),
            Err(SealError::NoSecret)
        );
    }

    /// The recipient side of one ciphertext: `(R, ss_ec, ss_kem, ct_kem)`.
    fn shared_secrets(keys: &DeliveryKeys, c: &[u8]) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
        let r_pub: [u8; 32] = c[..32].try_into().unwrap();
        let r = CompressedRistretto(r_pub).decompress().unwrap();
        let ss_ec = (keys.view * r).compress().to_bytes();
        let ct_bytes = c[33..33 + KEM_CT_BYTES].to_vec();
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice()).unwrap();
        let ss_kem = keys.dk.decapsulate(&ct).as_slice().to_vec();
        (r_pub, ss_ec, ss_kem, ct_bytes)
    }

    fn body_opens(k: &[u8; 32], c: &[u8], cm: &Digest) -> bool {
        ChaCha20Poly1305::new(&(*k).into())
            .decrypt(
                &[0u8; 12].into(),
                Payload {
                    msg: &c[33 + KEM_CT_BYTES..],
                    aad: &digest_bytes(cm),
                },
            )
            .is_ok()
    }

    /// Combiner v2: a sealed ciphertext opens under the v2 key, and the v1
    /// combiner (`"px/delivery-key"` over `ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ cm`,
    /// without `V` and `H(ek)`) gives another key that does not open it.
    #[test]
    fn the_v2_combiner_differs_from_v1() {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(21);
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(0);
        let keys = bob.delivery_keys(0);
        let (rec, cm) = record(to.owner, 7);
        let c = seal(&mut rng, &SENDER, &to, &rec, &cm).unwrap();
        let (r_pub, ss_ec, ss_kem, ct) = shared_secrets(&keys, &c);

        let v2 = key(
            &ss_ec,
            &ss_kem,
            &r_pub,
            &ct,
            &Recipient {
                view: &to.view,
                ek_hash: &h32(tags::PX_DELIVERY_EK, &[&to.ek]),
            },
            &cm,
        );
        let v1 = h32(
            "px/delivery-key",
            &[&ss_ec, &ss_kem, &r_pub, &ct, &digest_bytes(&cm)],
        );
        assert_ne!(v1, v2);
        assert!(body_opens(&v2, &c, &cm));
        assert!(!body_opens(&v1, &c, &cm));
        assert_eq!(open(&keys, &to.owner, &c, &cm, &rec.rho), Some(rec));
    }

    /// An address whose view key is the identity is refused: its classical
    /// shared secret would be the identity for every `r`.
    #[test]
    fn an_identity_view_key_is_refused() {
        let bob = Account::from_seed(&[6; 32]);
        let mut to = bob.address(0);
        let (rec, cm) = record(to.owner, 1);
        to.view = [0; 32];
        assert_eq!(
            seal(&mut ConstRng, &SENDER, &to, &rec, &cm),
            Err(SealError::BadAddress)
        );
    }

    /// The cached public keys are the address's: `V` and `H(ek)` of the
    /// published address.
    #[test]
    fn cached_recipient_keys_match_the_address() {
        let bob = Account::from_seed(&[6; 32]);
        for i in 0..3 {
            let keys = bob.delivery_keys(i);
            let to = bob.address(i);
            assert_eq!(keys.view_pub, to.view);
            assert_eq!(keys.ek_hash, h32(tags::PX_DELIVERY_EK, &[&to.ek]));
        }
    }

    /// The key binds the recipient's `V` and `H(ek)`: a recipient whose
    /// cached `V` or `H(ek)` differs from the sealed-to address derives
    /// another key and does not open the record, although both shared
    /// secrets are right.
    #[test]
    fn the_key_binds_both_recipient_public_keys() {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(22);
        let bob = Account::from_seed(&[6; 32]);
        let to = bob.address(0);
        let (rec, cm) = record(to.owner, 8);
        let c = seal(&mut rng, &SENDER, &to, &rec, &cm).unwrap();
        let other = bob.address(1);

        let mut keys = bob.delivery_keys(0);
        assert_eq!(open(&keys, &to.owner, &c, &cm, &rec.rho), Some(rec));
        keys.view_pub = other.view;
        assert_eq!(open(&keys, &to.owner, &c, &cm, &rec.rho), None);

        let mut keys = bob.delivery_keys(0);
        keys.ek_hash = h32(tags::PX_DELIVERY_EK, &[&other.ek]);
        assert_eq!(open(&keys, &to.owner, &c, &cm, &rec.rho), None);
    }

    /// The combiner's tags are distinct from every other tag, the v2 key tag
    /// is not the v1 one, and neither is a consensus tag (they are
    /// wallet-side: changing them changes no verdict and no fingerprint).
    #[test]
    fn delivery_tags_are_distinct_wallet_side_tags() {
        for t in [tags::PX_DELIVERY_KEY, tags::PX_DELIVERY_EK] {
            assert_eq!(
                tags::ALL.iter().filter(|x| **x == t).count(),
                1,
                "{t} must be listed once in ALL"
            );
            assert!(!tags::CONSENSUS.contains(&t), "{t} is not a consensus tag");
        }
        assert_ne!(tags::PX_DELIVERY_KEY, "px/delivery-key");
        assert!(!tags::ALL.contains(&"px/delivery-key"));
        let set: std::collections::HashSet<_> = tags::ALL.iter().collect();
        assert_eq!(set.len(), tags::ALL.len(), "duplicate tag name");
    }
}
