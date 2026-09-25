//! Record delivery (zk.md §4.6, DR-7; docs/px.md §6): each output carries its
//! record, encrypted to the recipient's address.
//!
//! **Hybrid encryption.** Both parts are needed to decrypt:
//! - ECDH on Ristretto255 with the address's view key: `ss_ec = r·V`;
//! - ML-KEM-768 (FIPS 203) to the address's encapsulation key: `ss_kem`.
//!
//! The AEAD key is `H32("px/delivery-key", ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ cm)`,
//! a combiner over both secrets and both ciphertexts (as in X-Wing), bound to
//! the output's commitment `cm`. The body is ChaCha20-Poly1305 with `cm` as
//! associated data. Every key is fresh (new `r` and new KEM randomness), so
//! the nonce is zero.
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
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
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
/// zeroizes itself).
pub struct DeliveryKeys {
    view: Scalar,
    dk: Dk,
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
        DeliveryKeys { view, dk }
    }

    pub fn address(&self, owner: Digest) -> Address {
        Address {
            owner,
            view: (&self.view * RISTRETTO_BASEPOINT_TABLE)
                .compress()
                .to_bytes(),
            ek: self.dk.encapsulation_key().to_bytes().to_vec(),
        }
    }
}

fn view_tag(ss_ec: &[u8; 32], r: &[u8; 32]) -> u8 {
    h32(tags::PX_VIEW_TAG, &[ss_ec, r])[0]
}

fn key(ss_ec: &[u8; 32], ss_kem: &[u8], r: &[u8; 32], ct: &[u8], cm: &Digest) -> [u8; 32] {
    h32(
        tags::PX_DELIVERY_KEY,
        &[ss_ec, ss_kem, r, ct, &digest_bytes(cm)],
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// The address's view key or encapsulation key does not decode.
    BadAddress,
}

/// Encrypts `record` (committed as `cm`) to `to`.
pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    to: &Address,
    record: &Record,
    cm: &Digest,
) -> Result<Vec<u8>, SealError> {
    let v = CompressedRistretto(to.view)
        .decompress()
        .ok_or(SealError::BadAddress)?;
    let ek_arr =
        ml_kem::Key::<Ek>::try_from(to.ek.as_slice()).map_err(|_| SealError::BadAddress)?;
    let ek = Ek::new(&ek_arr).map_err(|_| SealError::BadAddress)?;

    // Ephemeral secrets are wiped on drop.
    let mut wide = zeroize::Zeroizing::new([0u8; 64]);
    rng.fill_bytes(&mut *wide);
    let r = zeroize::Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    let r_pub = (&*r * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
    let ss_ec = zeroize::Zeroizing::new((*r * v).compress().to_bytes());
    let mut m = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *m);
    let (ct, ss_kem) = ek.encapsulate_deterministic(&(*m).into());

    let k = zeroize::Zeroizing::new(key(&ss_ec, ss_kem.as_slice(), &r_pub, ct.as_slice(), cm));
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
    let k = zeroize::Zeroizing::new(key(&ss_ec, ss_kem.as_slice(), &r_pub, ct_bytes, cm));
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
