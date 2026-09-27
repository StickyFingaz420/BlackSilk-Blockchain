//! Wallet side of PX: keys from the wallet seed, addresses, record creation
//! and transfer witnesses (zk.md §4.2; docs/px.md §3).

use crate::delivery::{Address, DeliveryKeys};
use crate::perm::HostPerm;
use blacksilk_px_core::call::MAX_FN;
use blacksilk_px_core::hash::{domain, hash};
use blacksilk_px_core::kernel::{InputWitness, OutputWitness, Public, Witness, TREE_DEPTH};
use blacksilk_px_core::record::{diversifier, output_rho, Keys, Record};
use blacksilk_px_core::{Digest, P, ZERO_DIGEST};
use rand_core::{CryptoRng, RngCore};

/// A uniformly random digest (rejection sampling of canonical elements).
pub fn random_digest<R: RngCore + CryptoRng>(rng: &mut R) -> Digest {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = loop {
            // p > 2^30: at most ~6% of 31-bit samples are rejected.
            let v = rng.next_u32() >> 1;
            if v < P {
                break v;
            }
        };
    }
    d
}

/// Wallet-side `Hk` domains of the hierarchical key derivation (docs/px.md
/// §3.1). They are not consensus: the kernel takes `d` as a free witness and
/// never recomputes these. They sit in their own block, apart from the
/// consensus domains of `blacksilk_px_core::hash::domain` (`0x0050_58xx`).
pub mod key_domain {
    const BASE: u32 = 0x0050_5A00;
    /// `dk = Hk(DIV_KEY, sk)`: the diversifier key.
    pub const DIV_KEY: u32 = BASE + 1;
    /// `ivk = Hk(IVK, sk)`: the incoming-viewing (delivery) root.
    pub const IVK: u32 = BASE + 2;
    /// `dk_k = Hk(DIV_RANGE, dk ‖ k)`.
    pub const DIV_RANGE: u32 = BASE + 3;
    /// `ivk_k = Hk(IVK_RANGE, ivk ‖ k)`.
    pub const IVK_RANGE: u32 = BASE + 4;
    /// `d_i = Hk(DIVERSIFIER_V2, dk_k ‖ i)`.
    pub const DIVERSIFIER_V2: u32 = BASE + 5;
}

/// How a wallet derives its PX addresses from `sk` (docs/px.md §3.1).
///
/// The version must travel with the wallet (the wallet file stores it): the
/// same seed gives different PX addresses under different versions. The
/// spend key `sk`, and so `ak`, `nk` and every nullifier rule, is the same in
/// both; only diversifiers and delivery keys differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Derivation {
    /// The original flat derivation: `d_i = Hk(DIVERSIFIER, sk ‖ i)`, delivery
    /// keys from `sk ‖ i`. Every capability short of spending needs `sk`.
    V1,
    /// Hierarchical by index range (reviews R11-W2, I2-R1): diversifiers and
    /// delivery keys derive from per-range roots, so one range can be
    /// disclosed ([`RangeViewKey`], [`IncomingViewKey`]) without `sk`.
    V2,
}

impl Derivation {
    /// What new wallets use.
    pub const LATEST: Derivation = Derivation::V2;

    pub fn number(self) -> u32 {
        match self {
            Derivation::V1 => 1,
            Derivation::V2 => 2,
        }
    }

    pub fn from_number(n: u32) -> Option<Derivation> {
        match n {
            1 => Some(Derivation::V1),
            2 => Some(Derivation::V2),
            _ => None,
        }
    }
}

/// Address indexes per range in [`Derivation::V2`]: range `k` holds indexes
/// `k·2^16 .. (k+1)·2^16`.
pub const RANGE_BITS: u32 = 16;

/// The range of address `index` in [`Derivation::V2`].
pub fn range_of(index: u32) -> u32 {
    index >> RANGE_BITS
}

fn split(x: u32) -> [u32; 2] {
    // A u32 may exceed p: absorb it as 16-bit halves.
    [x & 0xffff, x >> 16]
}

fn range_root(domain: u32, root: &Digest, range: u32) -> Digest {
    hash(&mut HostPerm::new(), domain, &[root, &split(range)])
}

fn diversifier_v2(dk_range: &Digest, index: u32) -> Digest {
    hash(
        &mut HostPerm::new(),
        key_domain::DIVERSIFIER_V2,
        &[dk_range, &split(index)],
    )
}

/// The PX keys of a wallet. The spend secret is zeroized on drop and never
/// printed.
#[derive(Clone)]
pub struct Account {
    sk: Digest,
    keys: Keys,
    derivation: Derivation,
    /// `dk` and `ivk` ([`Derivation::V2`]; zero under V1, where they are unused).
    dk: Digest,
    ivk: Digest,
}

impl core::fmt::Debug for Account {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Account { .. }")
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.sk);
        zeroize::Zeroize::zeroize(&mut self.keys.nk);
        zeroize::Zeroize::zeroize(&mut self.keys.ak);
        zeroize::Zeroize::zeroize(&mut self.dk);
        zeroize::Zeroize::zeroize(&mut self.ivk);
    }
}

/// Full viewing key of one address range ([`Derivation::V2`]): `(ak, nk, dk_k,
/// ivk_k)`. It finds the records received in the range **and their spends**
/// (`nk` gives the nullifiers of records it can open). It cannot spend
/// (that needs a preimage `sk` of `ak`) and says nothing about other ranges.
/// Sensitive: zeroized on drop, never printed.
#[derive(Clone)]
pub struct RangeViewKey {
    pub range: u32,
    keys: Keys,
    dk_range: Digest,
    ivk_range: Digest,
}

impl core::fmt::Debug for RangeViewKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RangeViewKey {{ range: {}, .. }}", self.range)
    }
}

impl Drop for RangeViewKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.keys.nk);
        zeroize::Zeroize::zeroize(&mut self.keys.ak);
        zeroize::Zeroize::zeroize(&mut self.dk_range);
        zeroize::Zeroize::zeroize(&mut self.ivk_range);
    }
}

impl RangeViewKey {
    fn contains(&self, index: u32) -> bool {
        range_of(index) == self.range
    }

    /// The owner tag of address `index`; `None` outside the range.
    pub fn owner(&self, index: u32) -> Option<Digest> {
        self.contains(index).then(|| {
            let d = diversifier_v2(&self.dk_range, index);
            self.keys.owner(&mut HostPerm::new(), &d)
        })
    }

    /// The delivery keys of address `index`; `None` outside the range.
    pub fn delivery_keys(&self, index: u32) -> Option<DeliveryKeys> {
        self.contains(index)
            .then(|| DeliveryKeys::derive(&self.ivk_range, index))
    }

    /// The nullifier key: with it, spends of the range's records are visible.
    pub fn nk(&self) -> &Digest {
        &self.keys.nk
    }

    /// The incoming-only view of the first `count` addresses of the range.
    pub fn incoming(&self, count: u32) -> IncomingViewKey {
        let first = self.range << RANGE_BITS;
        let count = count.min(1 << RANGE_BITS);
        IncomingViewKey {
            range: self.range,
            ivk_range: self.ivk_range,
            owners: (0..count)
                .map(|j| {
                    let i = first + j;
                    (i, self.owner(i).expect("in range"))
                })
                .collect(),
        }
    }
}

/// Incoming-only viewing key of one address range (review I2-F3):
/// `(ivk_k, owner tags of the disclosed addresses)`. It finds and opens the
/// records received at those addresses. It has no `nk`, so it cannot compute
/// nullifiers or see spends, and it cannot derive further addresses (no
/// `ak`, `nk` or `dk_k`). Sensitive: zeroized on drop, never printed.
#[derive(Clone)]
pub struct IncomingViewKey {
    pub range: u32,
    ivk_range: Digest,
    /// `(index, owner tag)` of every disclosed address. Owner tags are public
    /// (they are part of the addresses).
    pub owners: Vec<(u32, Digest)>,
}

impl core::fmt::Debug for IncomingViewKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "IncomingViewKey {{ range: {}, addresses: {}, .. }}",
            self.range,
            self.owners.len()
        )
    }
}

impl Drop for IncomingViewKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.ivk_range);
    }
}

impl IncomingViewKey {
    /// The delivery keys and owner tag of disclosed address `index`.
    pub fn address_keys(&self, index: u32) -> Option<(DeliveryKeys, Digest)> {
        let (_, owner) = self.owners.iter().find(|(i, _)| *i == index)?;
        Some((DeliveryKeys::derive(&self.ivk_range, index), *owner))
    }
}

impl Account {
    /// Derives the PX spend secret from the 32-byte wallet seed:
    /// `sk = Hk("px/sk", seed as sixteen 16-bit limbs)`, with the original
    /// flat address derivation ([`Derivation::V1`]).
    pub fn from_seed(seed: &[u8; 32]) -> Account {
        Self::from_seed_with(seed, Derivation::V1)
    }

    /// Like [`Account::from_seed`], with the address derivation `derivation`.
    /// The spend secret and `ak`, `nk` are the same for every version.
    pub fn from_seed_with(seed: &[u8; 32], derivation: Derivation) -> Account {
        let mut limbs = [0u32; 16];
        for (i, l) in limbs.iter_mut().enumerate() {
            *l = u16::from_le_bytes([seed[2 * i], seed[2 * i + 1]]) as u32;
        }
        let mut perm = HostPerm::new();
        let sk = hash(&mut perm, domain::SK, &[&limbs]);
        zeroize::Zeroize::zeroize(&mut limbs);
        let keys = Keys::derive(&mut perm, &sk);
        let (dk, ivk) = match derivation {
            Derivation::V1 => (ZERO_DIGEST, ZERO_DIGEST),
            Derivation::V2 => (
                hash(&mut perm, key_domain::DIV_KEY, &[&sk]),
                hash(&mut perm, key_domain::IVK, &[&sk]),
            ),
        };
        Account {
            sk,
            keys,
            derivation,
            dk,
            ivk,
        }
    }

    pub fn derivation(&self) -> Derivation {
        self.derivation
    }

    /// The full viewing key of address range `range`; `None` under
    /// [`Derivation::V1`], which has no hierarchy (only `sk` sees anything).
    pub fn range_view(&self, range: u32) -> Option<RangeViewKey> {
        match self.derivation {
            Derivation::V1 => None,
            Derivation::V2 => Some(RangeViewKey {
                range,
                keys: self.keys,
                dk_range: range_root(key_domain::DIV_RANGE, &self.dk, range),
                ivk_range: range_root(key_domain::IVK_RANGE, &self.ivk, range),
            }),
        }
    }

    /// The diversifier of address `index`.
    fn diversifier(&self, index: u32) -> Digest {
        match self.derivation {
            Derivation::V1 => diversifier(&mut HostPerm::new(), &self.sk, index),
            Derivation::V2 => {
                let mut dk_range = range_root(key_domain::DIV_RANGE, &self.dk, range_of(index));
                let d = diversifier_v2(&dk_range, index);
                zeroize::Zeroize::zeroize(&mut dk_range);
                d
            }
        }
    }

    /// Secret bytes that key the wallet's hedged randomness on the PX side
    /// (record delivery, PX transaction building; docs/transactions.md §10):
    /// the spend secret, little-endian. Only pass them to
    /// `blacksilk_crypto::nonce::HedgedRng` (directly or through
    /// [`crate::delivery::seal`]), and zeroize them after.
    pub fn hedge_secret(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in self.sk.iter().enumerate() {
            b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
        }
        b
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The delivery keys of address `index` (record decryption).
    pub fn delivery_keys(&self, index: u32) -> DeliveryKeys {
        match self.derivation {
            Derivation::V1 => DeliveryKeys::derive(&self.sk, index),
            Derivation::V2 => {
                let mut ivk_range = range_root(key_domain::IVK_RANGE, &self.ivk, range_of(index));
                let keys = DeliveryKeys::derive(&ivk_range, index);
                zeroize::Zeroize::zeroize(&mut ivk_range);
                keys
            }
        }
    }

    /// The public address `index`: owner tag and delivery keys.
    pub fn address(&self, index: u32) -> Address {
        self.delivery_keys(index).address(self.owner(index))
    }

    /// The owner tag of address `index`: what a sender needs to pay it.
    pub fn owner(&self, index: u32) -> Digest {
        let d = self.diversifier(index);
        self.keys.owner(&mut HostPerm::new(), &d)
    }

    /// The witness for spending `record`, received at address `index`, which
    /// sits at `position` with authentication `path`.
    pub fn spend(
        &self,
        index: u32,
        record: &Record,
        position: u64,
        path: [Digest; TREE_DEPTH],
    ) -> InputWitness {
        assert!(position < 1 << 32);
        let d = self.diversifier(index);
        InputWitness {
            dummy: false,
            contract: ZERO_DIGEST,
            sk: self.sk,
            d,
            value: record.value,
            data: record.data,
            rho: record.rho,
            rcm: record.rcm,
            position: position as u32,
            path,
        }
    }
}

/// A dummy input: a random key and record of value 0, not in the tree. Its
/// nullifier is indistinguishable from a real one.
pub fn dummy_input<R: RngCore + CryptoRng>(rng: &mut R) -> InputWitness {
    let mut path = [ZERO_DIGEST; TREE_DEPTH];
    for s in path.iter_mut() {
        *s = random_digest(rng);
    }
    InputWitness {
        dummy: true,
        contract: ZERO_DIGEST,
        sk: random_digest(rng),
        d: random_digest(rng),
        value: 0,
        data: [0; 8],
        rho: random_digest(rng),
        rcm: random_digest(rng),
        position: rng.next_u32(),
        path,
    }
}

/// An output paying `value` to `owner`, with fresh commitment randomness.
/// A zero-value output to a random owner fills an unused slot.
pub fn output<R: RngCore + CryptoRng>(rng: &mut R, owner: Digest, value: u64) -> OutputWitness {
    OutputWitness {
        owner,
        contract: ZERO_DIGEST,
        value,
        data: [0; 8],
        rcm: random_digest(rng),
    }
}

/// An output record owned by `contract` (new contract state); a function of
/// that contract must specify it.
pub fn contract_output<R: RngCore + CryptoRng>(
    rng: &mut R,
    contract: Digest,
    value: u64,
    data: [u32; 8],
) -> OutputWitness {
    OutputWitness {
        owner: ZERO_DIGEST,
        contract,
        value,
        data,
        rcm: random_digest(rng),
    }
}

/// The witness for spending a contract-owned `record` at `position`. No key
/// is involved: a function of the contract must approve it. The key fields
/// are random (the kernel computes them anyway, for constant work).
pub fn contract_input<R: RngCore + CryptoRng>(
    rng: &mut R,
    record: &Record,
    position: u64,
    path: [Digest; TREE_DEPTH],
) -> InputWitness {
    assert!(position < 1 << 32);
    InputWitness {
        dummy: false,
        contract: record.contract,
        sk: random_digest(rng),
        d: random_digest(rng),
        value: record.value,
        data: record.data,
        rho: record.rho,
        rcm: record.rcm,
        position: position as u32,
        path,
    }
}

pub fn empty_output<R: RngCore + CryptoRng>(rng: &mut R) -> OutputWitness {
    let owner = random_digest(rng);
    output(rng, owner, 0)
}

/// The record created by output `j` of a transfer with public statement
/// `public` (what the recipient receives, zk.md §4.6).
pub fn created_record(public: &Public, j: usize, out: &OutputWitness) -> Record {
    let rho = output_rho(&mut HostPerm::new(), &public.nullifiers[0], j as u32);
    Record {
        owner: out.owner,
        contract: out.contract,
        asset: ZERO_DIGEST,
        value: out.value,
        data: out.data,
        rho,
        rcm: out.rcm,
    }
}

/// Assembles a 2×2 witness without function calls.
pub fn witness(
    anchor: Digest,
    bridge_in: u64,
    bridge_out: u64,
    inputs: [InputWitness; 2],
    outputs: [OutputWitness; 2],
) -> Witness {
    Witness {
        anchor,
        bridge_in,
        bridge_out,
        n_fn: 0,
        functions: [None; MAX_FN],
        inputs,
        outputs,
    }
}

/// Key derivation (docs/px.md §3.1).
#[cfg(test)]
mod derivation_tests {
    use super::*;
    use crate::delivery;
    use crate::tree::Tree;
    use blacksilk_px_core::kernel::{self, SliceSource};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SEED: [u8; 32] = [7; 32];

    /// V1 is exactly the original flat derivation (existing wallets keep
    /// their addresses).
    #[test]
    fn v1_is_the_original_derivation() {
        let a = Account::from_seed(&SEED);
        assert_eq!(a.derivation(), Derivation::V1);
        let mut perm = HostPerm::new();
        for i in [0u32, 1, 70_000] {
            let d = diversifier(&mut perm, &a.sk, i);
            assert_eq!(a.owner(i), a.keys.owner(&mut perm, &d));
            assert_eq!(
                a.address(i),
                DeliveryKeys::derive(&a.sk, i).address(a.owner(i))
            );
        }
        assert!(a.range_view(0).is_none(), "V1 has no hierarchy");
    }

    /// V2 keeps the spend key and changes every address.
    #[test]
    fn v2_keeps_the_spend_key_and_changes_the_addresses() {
        let v1 = Account::from_seed_with(&SEED, Derivation::V1);
        let v2 = Account::from_seed_with(&SEED, Derivation::V2);
        assert_eq!(v1.sk, v2.sk);
        assert_eq!(v1.keys, v2.keys);
        for i in [0u32, 1, 65_536] {
            assert_ne!(v1.owner(i), v2.owner(i));
            assert_ne!(v1.address(i).view, v2.address(i).view);
        }
        // Addresses within V2 stay distinct, across ranges too.
        let owners: std::collections::HashSet<Digest> = [0u32, 1, 65_535, 65_536, 65_537]
            .map(|i| v2.owner(i))
            .into();
        assert_eq!(owners.len(), 5);
        assert_eq!(Derivation::from_number(2), Some(Derivation::V2));
        assert_eq!(Derivation::from_number(3), None);
        assert_eq!(Derivation::LATEST.number(), 2);
    }

    /// A range view derives exactly the range's addresses, and nothing
    /// outside it; the incoming view opens records without `nk`.
    #[test]
    fn range_views_see_their_range_only() {
        let a = Account::from_seed_with(&SEED, Derivation::V2);
        let r1 = a.range_view(1).unwrap();
        for i in [65_536u32, 65_537, 131_071] {
            assert_eq!(r1.owner(i), Some(a.owner(i)));
            assert_eq!(
                r1.delivery_keys(i).unwrap().address(a.owner(i)),
                a.address(i)
            );
        }
        assert_eq!(r1.owner(3), None);
        assert!(r1.delivery_keys(131_072).is_none());
        assert_ne!(
            a.range_view(0).unwrap().dk_range,
            r1.dk_range,
            "ranges have unrelated roots"
        );

        // A record sent to address 65_540 opens with the incoming view.
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let incoming = r1.incoming(8);
        assert_eq!(incoming.owners.len(), 8);
        let to = a.address(65_540);
        let mut perm = HostPerm::new();
        let rho = random_digest(&mut rng);
        let rec = Record::plain(to.owner, 42, [0; 8], rho, random_digest(&mut rng));
        let cm = rec.commit(&mut perm);
        let c = delivery::seal(&mut rng, &[1; 32], &to, &rec, &cm).unwrap();
        let (keys, owner) = incoming.address_keys(65_540).unwrap();
        assert_eq!(delivery::open(&keys, &owner, &c, &cm, &rho), Some(rec));
        assert!(incoming.address_keys(65_548).is_none(), "not disclosed");
        assert!(incoming.address_keys(4).is_none(), "another range");
    }

    /// The kernel takes `d` as a free witness: a spend of a record received
    /// at a V2 address passes the (native) kernel. No proof is generated.
    #[test]
    fn the_kernel_accepts_v2_spends() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut perm = HostPerm::new();
        let a = Account::from_seed_with(&SEED, Derivation::V2);
        let mut tree = Tree::new(&mut perm);
        let index = 70_001;
        let rec = Record::plain(
            a.owner(index),
            1_000,
            [0; 8],
            random_digest(&mut rng),
            random_digest(&mut rng),
        );
        let cm = rec.commit(&mut perm);
        tree.append(&mut perm, random_digest(&mut rng)).unwrap();
        let pos = tree.append(&mut perm, cm).unwrap();
        let inputs = [
            a.spend(index, &rec, pos, tree.path(pos).unwrap()),
            dummy_input(&mut rng),
        ];
        let outputs = [output(&mut rng, a.owner(3), 1_000), empty_output(&mut rng)];
        let w = witness(tree.root(), 0, 0, inputs, outputs);
        let words = crate::prove::witness_words(&w);
        kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words))
            .expect("a V2 spend is a valid kernel witness");
        // The wrong derivation's diversifier is refused (owner mismatch).
        let v1 = Account::from_seed_with(&SEED, Derivation::V1);
        let inputs = [
            v1.spend(index, &rec, pos, tree.path(pos).unwrap()),
            dummy_input(&mut rng),
        ];
        let outputs = [output(&mut rng, a.owner(3), 1_000), empty_output(&mut rng)];
        let w = witness(tree.root(), 0, 0, inputs, outputs);
        let words = crate::prove::witness_words(&w);
        assert!(kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).is_err());
    }
}
