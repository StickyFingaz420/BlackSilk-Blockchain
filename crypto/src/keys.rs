//! Wallet keys, view keys and (sub)addresses (spec §2).
//!
//! ```text
//! k_s, k_v                      spend and view secrets, derived from a 32-byte seed
//! K_s = k_s·G
//! m(a,i) = 0 for (0,0), else Hs("subaddress", k_v ‖ LE32(a) ‖ LE32(i))
//! D(a,i) = K_s + m(a,i)·G       spend public key of the (sub)address
//! C(a,i) = k_v·D(a,i)           view public key of the (sub)address
//! d(a,i) = k_s + m(a,i)         its spend secret
//! ```
//!
//! [`ViewKeys`] (`k_v`, `K_s`) is everything a view-only wallet holds. It can derive
//! every address, detect incoming outputs, decrypt amounts and check Janus anchors,
//! but not spend or compute key images.

use crate::hash::{hash_to_scalar, tags};
use crate::point::Point;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubaddressIndex {
    pub account: u32,
    pub index: u32,
}

impl SubaddressIndex {
    pub const PRIMARY: Self = Self {
        account: 0,
        index: 0,
    };

    pub fn new(account: u32, index: u32) -> Self {
        Self { account, index }
    }
}

/// A public (sub)address `(D, C)`. Both points are non-identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    spend: Point,
    view: Point,
}

impl Address {
    pub fn new(spend: Point, view: Point) -> Option<Self> {
        if spend.is_identity() || view.is_identity() {
            return None;
        }
        Some(Self { spend, view })
    }

    /// `D`.
    pub fn spend(&self) -> &Point {
        &self.spend
    }

    /// `C`.
    pub fn view(&self) -> &Point {
        &self.view
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.spend.bytes());
        out[32..].copy_from_slice(self.view.bytes());
        out
    }

    /// Strict decoding: canonical, non-identity points only.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let spend = Point::decode(bytes[..32].try_into().ok()?)?;
        let view = Point::decode(bytes[32..].try_into().ok()?)?;
        Self::new(spend, view)
    }
}

/// View-only key material: `k_v` and `K_s`.
#[derive(Clone)]
pub struct ViewKeys {
    view: Scalar,
    spend_public: Point,
}

impl ViewKeys {
    /// `None` if `k_v = 0` or `K_s` is the identity (degenerate keys).
    pub fn new(view_secret: Scalar, spend_public: Point) -> Option<Self> {
        if view_secret == Scalar::ZERO || spend_public.is_identity() {
            return None;
        }
        Some(Self {
            view: view_secret,
            spend_public,
        })
    }

    pub fn view_secret(&self) -> &Scalar {
        &self.view
    }

    pub fn spend_public(&self) -> &Point {
        &self.spend_public
    }

    /// `m(a,i)`.
    pub fn subaddress_offset(&self, idx: SubaddressIndex) -> Scalar {
        if idx == SubaddressIndex::PRIMARY {
            return Scalar::ZERO;
        }
        hash_to_scalar(
            tags::SUBADDRESS,
            &[
                self.view.as_bytes(),
                &idx.account.to_le_bytes(),
                &idx.index.to_le_bytes(),
            ],
        )
    }

    /// `D(a,i)`.
    pub fn subaddress_spend_key(&self, idx: SubaddressIndex) -> RistrettoPoint {
        self.spend_public.point() + RistrettoPoint::mul_base(&self.subaddress_offset(idx))
    }

    /// The address `(D, k_v·D)` for `idx`.
    pub fn address(&self, idx: SubaddressIndex) -> Address {
        let d = self.subaddress_spend_key(idx);
        let c = self.view * d;
        // D = K_s + m·G is the identity only if m = -k_s (probability 2^-252); C = k_v·D
        // with k_v ≠ 0 is then non-identity as well.
        Address::new(Point::from_point(d), Point::from_point(c))
            .expect("subaddress keys are non-identity except with negligible probability")
    }
}

impl Drop for ViewKeys {
    fn drop(&mut self) {
        self.view.zeroize();
    }
}

/// Full wallet keys: `k_s` plus the view keys.
#[derive(Clone)]
pub struct WalletKeys {
    spend: Scalar,
    view_keys: ViewKeys,
}

impl WalletKeys {
    /// Derives `k_s = Hs("wallet/spend-key", seed)`, `k_v = Hs("wallet/view-key", seed)`.
    /// The seed must come from a CSPRNG (see [`WalletKeys::generate`]); there is no
    /// default seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let spend = hash_to_scalar(tags::WALLET_SPEND_KEY, &[seed]);
        let view = hash_to_scalar(tags::WALLET_VIEW_KEY, &[seed]);
        let spend_public = Point::from_point(RistrettoPoint::mul_base(&spend));
        let view_keys = ViewKeys::new(view, spend_public)
            .expect("hash-derived keys are non-zero except with negligible probability");
        Self { spend, view_keys }
    }

    /// A new wallet from 32 CSPRNG bytes. Returns the seed so it can be backed up.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, WalletSeed) {
        let mut seed = WalletSeed([0u8; 32]);
        rng.fill_bytes(&mut seed.0);
        (Self::from_seed(&seed.0), seed)
    }

    pub fn view_keys(&self) -> &ViewKeys {
        &self.view_keys
    }

    pub fn address(&self, idx: SubaddressIndex) -> Address {
        self.view_keys.address(idx)
    }

    /// `d(a,i) = k_s + m(a,i)`.
    pub fn subaddress_spend_secret(&self, idx: SubaddressIndex) -> Scalar {
        self.spend + self.view_keys.subaddress_offset(idx)
    }

    /// The one-time secret `p = x + d(a,i)` of an output received at `idx` with
    /// output-key offset `x` (from scanning).
    pub fn one_time_secret(&self, idx: SubaddressIndex, output_key_offset: &Scalar) -> Scalar {
        output_key_offset + self.subaddress_spend_secret(idx)
    }

    /// Secret bytes used to hedge the wallet's randomness (spec §10): the spend
    /// secret. Only pass them to [`crate::nonce::HedgedRng`], and zeroize them after.
    pub fn hedge_secret(&self) -> [u8; 32] {
        self.spend.to_bytes()
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        self.spend.zeroize();
    }
}

/// A wallet seed; zeroized on drop.
pub struct WalletSeed(pub [u8; 32]);

impl Drop for WalletSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Lookup table `D(a,i) → (a,i)` used when scanning (spec §2.2, §3.3 step 4).
#[derive(Clone, Default)]
pub struct SubaddressTable {
    map: HashMap<[u8; 32], (SubaddressIndex, Address)>,
}

impl SubaddressTable {
    /// All indices `(a, i)` with `a < accounts` and `i < per_account`.
    pub fn new(view: &ViewKeys, accounts: u32, per_account: u32) -> Self {
        let mut table = Self::default();
        for a in 0..accounts {
            for i in 0..per_account {
                table.insert(view, SubaddressIndex::new(a, i));
            }
        }
        table
    }

    pub fn insert(&mut self, view: &ViewKeys, idx: SubaddressIndex) {
        let address = view.address(idx);
        self.map.insert(*address.spend().bytes(), (idx, address));
    }

    /// The index and full address whose `D` has this encoding.
    pub fn lookup(&self, spend_key: &[u8; 32]) -> Option<&(SubaddressIndex, Address)> {
        self.map.get(spend_key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::test_rng::seeded;

    #[test]
    fn address_structure() {
        let (w, _) = WalletKeys::generate(&mut seeded(1));
        let v = w.view_keys();
        for idx in [
            SubaddressIndex::PRIMARY,
            SubaddressIndex::new(0, 1),
            SubaddressIndex::new(3, 7),
        ] {
            let addr = w.address(idx);
            // D = d·G and C = k_v·D.
            let d = w.subaddress_spend_secret(idx);
            assert_eq!(*addr.spend().point(), RistrettoPoint::mul_base(&d));
            assert_eq!(*addr.view().point(), v.view_secret() * addr.spend().point());
        }
        // Primary: D = K_s.
        assert_eq!(
            w.address(SubaddressIndex::PRIMARY).spend(),
            v.spend_public()
        );
    }

    #[test]
    fn subaddresses_are_distinct() {
        let (w, _) = WalletKeys::generate(&mut seeded(2));
        let t = SubaddressTable::new(w.view_keys(), 3, 50);
        assert_eq!(t.len(), 150);
    }

    #[test]
    fn different_seeds_give_unrelated_wallets() {
        let a = WalletKeys::from_seed(&[1; 32]);
        let b = WalletKeys::from_seed(&[2; 32]);
        assert_ne!(
            a.address(SubaddressIndex::PRIMARY),
            b.address(SubaddressIndex::PRIMARY)
        );
        // The same seed always gives the same wallet (recovery).
        let a2 = WalletKeys::from_seed(&[1; 32]);
        assert_eq!(
            a.address(SubaddressIndex::new(1, 2)),
            a2.address(SubaddressIndex::new(1, 2))
        );
    }

    #[test]
    fn generated_wallets_are_unique() {
        // Regression for audit finding K1 (every wallet shared one hard-coded seed).
        let mut rng = seeded(3);
        let (a, _) = WalletKeys::generate(&mut rng);
        let (b, _) = WalletKeys::generate(&mut rng);
        assert_ne!(a.hedge_secret(), b.hedge_secret());
    }

    #[test]
    fn address_encoding_is_strict() {
        let (w, _) = WalletKeys::generate(&mut seeded(4));
        let addr = w.address(SubaddressIndex::new(0, 5));
        assert_eq!(Address::from_bytes(&addr.to_bytes()), Some(addr));
        let mut zero_view = addr.to_bytes();
        zero_view[32..].fill(0); // identity
        assert!(Address::from_bytes(&zero_view).is_none());
        let mut bad = addr.to_bytes();
        bad[0..32].fill(0xff); // not canonical
        assert!(Address::from_bytes(&bad).is_none());
    }

    #[test]
    fn view_keys_reject_degenerate_values() {
        let (w, _) = WalletKeys::generate(&mut seeded(5));
        assert!(ViewKeys::new(Scalar::ZERO, *w.view_keys().spend_public()).is_none());
        assert!(ViewKeys::new(Scalar::ONE, Point::decode(&[0; 32]).unwrap()).is_none());
    }
}
