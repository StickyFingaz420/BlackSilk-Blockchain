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

/// The PX keys of a wallet. The spend secret is zeroized on drop and never
/// printed.
#[derive(Clone)]
pub struct Account {
    sk: Digest,
    keys: Keys,
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
    }
}

impl Account {
    /// Derives the PX spend secret from the 32-byte wallet seed:
    /// `sk = Hk("px/sk", seed as sixteen 16-bit limbs)`.
    pub fn from_seed(seed: &[u8; 32]) -> Account {
        let mut limbs = [0u32; 16];
        for (i, l) in limbs.iter_mut().enumerate() {
            *l = u16::from_le_bytes([seed[2 * i], seed[2 * i + 1]]) as u32;
        }
        let mut perm = HostPerm::new();
        let sk = hash(&mut perm, domain::SK, &[&limbs]);
        let keys = Keys::derive(&mut perm, &sk);
        Account { sk, keys }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The delivery keys of address `index` (record decryption).
    pub fn delivery_keys(&self, index: u32) -> DeliveryKeys {
        DeliveryKeys::derive(&self.sk, index)
    }

    /// The public address `index`: owner tag and delivery keys.
    pub fn address(&self, index: u32) -> Address {
        self.delivery_keys(index).address(self.owner(index))
    }

    /// The owner tag of address `index`: what a sender needs to pay it.
    pub fn owner(&self, index: u32) -> Digest {
        let mut perm = HostPerm::new();
        let d = diversifier(&mut perm, &self.sk, index);
        self.keys.owner(&mut perm, &d)
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
        let d = diversifier(&mut HostPerm::new(), &self.sk, index);
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
