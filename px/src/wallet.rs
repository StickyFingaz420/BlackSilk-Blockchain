//! Wallet side of PX: keys from the wallet seed, addresses, record creation
//! and transfer witnesses (zk.md §4.2; docs/px.md §3).

use crate::delivery::{Address, DeliveryKeys};
use crate::perm::HostPerm;
use blacksilk_crypto::nonce::HedgedRng;
use blacksilk_px_core::call::MAX_FN;
use blacksilk_px_core::hash::{domain, hash};
use blacksilk_px_core::kernel::{
    InputWitness, OutputWitness, Public, Witness, N_IN, N_OUT, TREE_DEPTH,
};
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
///
/// Draws from `rng` directly. A transaction builder must re-derive the
/// values with [`hedge_witness`] (`build_px` does), so that they do not
/// depend on the RNG alone.
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
///
/// `rcm` is drawn from `rng` directly; [`hedge_witness`] (called by
/// `build_px`) replaces it with a hedged value.
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

/// A placeholder for an unused output slot: value 0 to a random owner.
/// [`hedge_witness`] (called by `build_px`) replaces the owner and `rcm`
/// with hedged values when the slot is marked empty.
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

/// Purpose labels of the witness hedge (first context item of each stream).
pub mod witness_labels {
    /// `rcm` of a user output.
    pub const RCM: &[u8] = b"px/witness/rcm/v1";
    /// Every field of a dummy input (key, diversifier, `rho`, `rcm`,
    /// position, path).
    pub const DUMMY: &[u8] = b"px/witness/dummy/v1";
    /// The owner tag of an empty output slot.
    pub const EMPTY_OWNER: &[u8] = b"px/witness/empty-owner/v1";
    /// The unused key fields of a contract input.
    pub const CONTRACT_KEY: &[u8] = b"px/witness/contract-key/v1";
}

/// A hedged stream as an `RngCore`, so that the samplers above
/// ([`random_digest`], [`dummy_input`]) are reused unchanged: uniform
/// canonical elements by rejection sampling, no modulo bias. Bytes are taken
/// in order from 64-byte stream blocks; the buffer is wiped on drop.
struct HedgedWords {
    stream: HedgedRng,
    buf: [u8; 64],
    pos: usize,
}

impl HedgedWords {
    fn new(stream: HedgedRng) -> Self {
        HedgedWords {
            stream,
            buf: [0; 64],
            pos: 64,
        }
    }
}

impl RngCore for HedgedWords {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        lo | (self.next_u32() as u64) << 32
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.pos == self.buf.len() {
                self.stream.fill_bytes(&mut self.buf);
                self.pos = 0;
            }
            *byte = self.buf[self.pos];
            self.pos += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HedgedWords {}

impl Drop for HedgedWords {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

fn digest_bytes(d: &Digest) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    b
}

/// The statement a witness's random values are bound to: everything in the
/// witness except the values being derived. Items (fixed layout; `HedgedRng`
/// prefixes each with its length): anchor, `LE64(bridge_in)`,
/// `LE64(bridge_out)`; per input `"dummy"`, or `contract ‖ LE64(value) ‖
/// data ‖ rho ‖ rcm ‖ LE32(position)` of the record spent; per output
/// `"empty"`, or `owner ‖ contract ‖ LE64(value) ‖ data`; `LE64(n_fn)` and
/// per function `contract ‖ blind ‖ approve flags ‖ spec flags`.
fn witness_statement(w: &Witness, empty: &[bool; N_OUT]) -> Vec<zeroize::Zeroizing<Vec<u8>>> {
    let item = zeroize::Zeroizing::new;
    let mut items = Vec::with_capacity(4 + N_IN + N_OUT + w.n_fn);
    items.push(item(digest_bytes(&w.anchor).to_vec()));
    items.push(item(w.bridge_in.to_le_bytes().to_vec()));
    items.push(item(w.bridge_out.to_le_bytes().to_vec()));
    for input in &w.inputs {
        if input.dummy {
            items.push(item(b"dummy".to_vec()));
        } else {
            let mut v = Vec::with_capacity(172);
            v.extend_from_slice(&digest_bytes(&input.contract));
            v.extend_from_slice(&input.value.to_le_bytes());
            v.extend_from_slice(&digest_bytes(&input.data));
            v.extend_from_slice(&digest_bytes(&input.rho));
            v.extend_from_slice(&digest_bytes(&input.rcm));
            v.extend_from_slice(&input.position.to_le_bytes());
            items.push(item(v));
        }
    }
    for (out, &is_empty) in w.outputs.iter().zip(empty) {
        if is_empty {
            items.push(item(b"empty".to_vec()));
        } else {
            let mut v = Vec::with_capacity(104);
            v.extend_from_slice(&digest_bytes(&out.owner));
            v.extend_from_slice(&digest_bytes(&out.contract));
            v.extend_from_slice(&out.value.to_le_bytes());
            v.extend_from_slice(&digest_bytes(&out.data));
            items.push(item(v));
        }
    }
    items.push(item((w.n_fn as u64).to_le_bytes().to_vec()));
    for f in w.functions.iter().take(w.n_fn) {
        let mut v = Vec::with_capacity(64 + N_IN + N_OUT);
        match f {
            Some(f) => {
                v.extend_from_slice(&digest_bytes(&f.contract));
                v.extend_from_slice(&digest_bytes(&f.blind));
                v.extend(f.approve.iter().map(|&a| a as u8));
                v.extend(f.spec.iter().map(|s| s.is_some() as u8));
            }
            None => v.extend_from_slice(b"none"),
        }
        items.push(item(v));
    }
    items
}

/// Re-derives the secret random values of `witness` from hedged streams
/// (docs/transactions.md §10), so that none depends on the RNG alone:
///
/// - `rcm` of every user output (contract zero; label [`witness_labels::RCM`]);
/// - the owner of every output slot marked in `empty` (a user output of
///   value 0 that nobody receives; [`witness_labels::EMPTY_OWNER`]);
/// - every field of every dummy input ([`witness_labels::DUMMY`]);
/// - the unused key fields `sk`, `d` of contract inputs
///   ([`witness_labels::CONTRACT_KEY`]).
///
/// Each value has its own stream, keyed with `secrets` (the PX hedge secret,
/// [`Account::hedge_secret`], plus any other sender secret) and bound to its
/// label, its slot index, the whole witness statement (real inputs, outputs,
/// bridge amounts, anchor, functions; see `witness_statement`) and the
/// caller's `context` (the rest of the transaction: network, fee, v1 rings,
/// payouts, change). With a broken or constant RNG the values stay
/// unpredictable without the secret, and two transactions that differ in
/// anything bound get unrelated values; an identical statement repeats them
/// (a deterministic rebuild). With a working RNG they are uniformly random
/// canonical elements (rejection sampling).
///
/// Left unchanged: real inputs, contract outputs (their `rcm` is part of the
/// opening the caller keeps, so the caller chooses it) and function witnesses
/// (the `blind` is also in the function's private input). Wallet side only:
/// validators never re-derive these values.
pub fn hedge_witness<R: RngCore + CryptoRng>(
    secrets: &[&[u8]],
    context: &[&[u8]],
    witness: &mut Witness,
    empty: [bool; N_OUT],
    rng: &mut R,
) {
    let statement = witness_statement(witness, &empty);
    let count = (context.len() as u64).to_le_bytes();
    let stream = |label: &[u8], index: usize, rng: &mut R| {
        let index = (index as u64).to_le_bytes();
        let mut items: Vec<&[u8]> = Vec::with_capacity(3 + statement.len() + context.len());
        items.push(label);
        items.push(&index);
        items.extend(statement.iter().map(|v| v.as_slice()));
        items.push(&count);
        items.extend_from_slice(context);
        HedgedWords::new(HedgedRng::new(secrets, &items, rng))
    };
    for (j, out) in witness.outputs.iter_mut().enumerate() {
        if empty[j] {
            out.owner = random_digest(&mut stream(witness_labels::EMPTY_OWNER, j, rng));
        }
        if out.contract == ZERO_DIGEST {
            out.rcm = random_digest(&mut stream(witness_labels::RCM, j, rng));
        }
    }
    for (i, input) in witness.inputs.iter_mut().enumerate() {
        if input.dummy {
            *input = dummy_input(&mut stream(witness_labels::DUMMY, i, rng));
        } else if input.contract != ZERO_DIGEST {
            let mut s = stream(witness_labels::CONTRACT_KEY, i, rng);
            input.sk = random_digest(&mut s);
            input.d = random_digest(&mut s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// A completely broken "CSPRNG": always zero.
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(0);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}

    const SECRET: &[u8] = &[7u8; 32];

    fn owner(k: u32) -> Digest {
        [k; 8]
    }

    /// A payment of `value` to `to` from one real input and a dummy, with
    /// change in slot 1 or (`empty_slot`) an empty slot 1. The placeholders
    /// come from a zero RNG, so only the hedge can make them differ.
    fn plan(to: Digest, value: u64, empty_slot: bool) -> (Witness, [bool; N_OUT]) {
        let acct = Account::from_seed(&[1; 32]);
        let rec = Record::plain(acct.owner(0), 1000, [0; 8], [3; 8], [4; 8]);
        let real = acct.spend(0, &rec, 5, [[9; 8]; TREE_DEPTH]);
        let second = if empty_slot {
            empty_output(&mut ZeroRng)
        } else {
            output(&mut ZeroRng, acct.owner(1), 1000 - value)
        };
        let w = witness(
            [2; 8],
            0,
            0,
            [real, dummy_input(&mut ZeroRng)],
            [output(&mut ZeroRng, to, value), second],
        );
        (w, [false, empty_slot])
    }

    fn hedged<R: RngCore + CryptoRng>(
        to: Digest,
        value: u64,
        empty_slot: bool,
        rng: &mut R,
    ) -> Witness {
        let (mut w, empty) = plan(to, value, empty_slot);
        hedge_witness(&[SECRET], &[b"tx"], &mut w, empty, rng);
        w
    }

    /// Every hedged digest of `w`: both output `rcm`s and the dummy's fields.
    fn secrets_of(w: &Witness) -> Vec<Digest> {
        let d = &w.inputs[1];
        let mut v = vec![w.outputs[0].rcm, w.outputs[1].rcm, d.sk, d.d, d.rho, d.rcm];
        v.extend_from_slice(&d.path);
        v
    }

    fn assert_disjoint(a: &Witness, b: &Witness) {
        let sb = secrets_of(b);
        for x in secrets_of(a) {
            assert!(!sb.contains(&x), "a hedged value repeats across statements");
        }
        assert_ne!(a.inputs[1].position, b.inputs[1].position);
    }

    #[test]
    fn broken_rng_values_differ_when_value_or_recipient_differ() {
        let base = hedged(owner(1), 300, false, &mut ZeroRng);
        let other_value = hedged(owner(1), 301, false, &mut ZeroRng);
        let other_to = hedged(owner(2), 300, false, &mut ZeroRng);
        assert_disjoint(&base, &other_value);
        assert_disjoint(&base, &other_to);
        assert_disjoint(&other_value, &other_to);
        // The unhedged placeholders were identical (zero RNG)...
        let (p1, _) = plan(owner(1), 300, false);
        let (p2, _) = plan(owner(2), 301, false);
        assert_eq!(p1.inputs[1], p2.inputs[1]);
        assert_eq!(p1.outputs[0].rcm, p2.outputs[0].rcm);
        // ...and the hedge replaced them; the two outputs' rcm differ.
        assert_ne!(base.inputs[1], p1.inputs[1]);
        assert_ne!(base.outputs[0].rcm, base.outputs[1].rcm);
        // An identical statement repeats (a deterministic rebuild).
        assert_eq!(base, hedged(owner(1), 300, false, &mut ZeroRng));
    }

    #[test]
    fn broken_rng_values_differ_with_the_caller_context_and_secret() {
        let (a0, empty) = plan(owner(1), 300, true);
        let (mut a, mut b, mut c) = (a0.clone(), a0.clone(), a0);
        hedge_witness(&[SECRET], &[b"tx-1"], &mut a, empty, &mut ZeroRng);
        hedge_witness(&[SECRET], &[b"tx-2"], &mut b, empty, &mut ZeroRng);
        hedge_witness(&[&[8u8; 32]], &[b"tx-1"], &mut c, empty, &mut ZeroRng);
        assert_disjoint(&a, &b);
        assert_disjoint(&a, &c);
        assert_ne!(a.outputs[1].owner, b.outputs[1].owner);
        assert_ne!(a.outputs[1].owner, c.outputs[1].owner);
    }

    #[test]
    fn working_rng_values_are_fresh() {
        let a = hedged(owner(1), 300, true, &mut ChaCha20Rng::seed_from_u64(1));
        let b = hedged(owner(1), 300, true, &mut ChaCha20Rng::seed_from_u64(2));
        assert_disjoint(&a, &b);
        assert_ne!(a.outputs[1].owner, b.outputs[1].owner);
    }

    #[test]
    fn only_the_random_fields_change() {
        let (orig, _) = plan(owner(1), 300, true);
        let w = hedged(owner(1), 300, true, &mut ZeroRng);
        assert_eq!(w.inputs[0], orig.inputs[0], "a real input is untouched");
        assert!(w.inputs[1].dummy);
        assert_eq!((w.inputs[1].value, w.inputs[1].contract), (0, ZERO_DIGEST));
        assert_eq!((w.outputs[0].owner, w.outputs[0].value), (owner(1), 300));
        assert_ne!(
            w.outputs[1].owner, orig.outputs[1].owner,
            "empty owner hedged"
        );
        assert_eq!(
            (w.outputs[1].value, w.outputs[1].contract),
            (0, ZERO_DIGEST)
        );
        assert_eq!((w.anchor, w.bridge_in, w.bridge_out), ([2; 8], 0, 0));
        // A slot not marked empty keeps its owner.
        let (mut w2, _) = plan(owner(1), 300, true);
        let kept = w2.outputs[1].owner;
        hedge_witness(&[SECRET], &[], &mut w2, [false; N_OUT], &mut ZeroRng);
        assert_eq!(w2.outputs[1].owner, kept);
    }

    #[test]
    fn contract_outputs_keep_their_rcm_and_contract_inputs_get_hedged_keys() {
        let c = [5u32; 8];
        let rec = Record {
            owner: ZERO_DIGEST,
            contract: c,
            asset: ZERO_DIGEST,
            value: 70,
            data: [1; 8],
            rho: [2; 8],
            rcm: [3; 8],
        };
        let cin = contract_input(&mut ZeroRng, &rec, 4, [[0; 8]; TREE_DEPTH]);
        let cout = contract_output(&mut ChaCha20Rng::seed_from_u64(3), c, 70, [1; 8]);
        let mut w = witness(
            [0; 8],
            0,
            0,
            [cin.clone(), dummy_input(&mut ZeroRng)],
            [cout.clone(), empty_output(&mut ZeroRng)],
        );
        hedge_witness(&[SECRET], &[], &mut w, [false, true], &mut ZeroRng);
        assert_eq!(w.outputs[0], cout, "the caller keeps this opening");
        let i = &w.inputs[0];
        assert_eq!(
            (i.contract, i.value, i.data, i.rho, i.rcm, i.position),
            (c, 70, [1; 8], [2; 8], [3; 8], 4)
        );
        assert_ne!(i.sk, cin.sk);
        assert_ne!(i.d, cin.d);
        assert_ne!(i.sk, i.d);
    }

    /// The kernel accepts a hedged witness (run natively, no proof): the
    /// dummies and the empty slot are well formed, the nullifiers distinct.
    #[test]
    fn the_kernel_accepts_a_hedged_witness() {
        use blacksilk_px_core::kernel::{transfer, SliceSource};
        let fresh = || {
            witness(
                [0; 8],
                0,
                0,
                [dummy_input(&mut ZeroRng), dummy_input(&mut ZeroRng)],
                [
                    output(&mut ZeroRng, owner(1), 0),
                    empty_output(&mut ZeroRng),
                ],
            )
        };
        let mut w = fresh();
        hedge_witness(&[SECRET], &[b"tx"], &mut w, [false, true], &mut ZeroRng);
        let words = crate::prove::witness_words(&w);
        let public = transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).unwrap();
        assert_ne!(public.nullifiers[0], public.nullifiers[1]);
        // Unhedged, the two zero-RNG dummies collide.
        let words = crate::prove::witness_words(&fresh());
        assert!(transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).is_err());
    }

    /// Hedged `rcm` limbs are canonical and uniform over the field: the
    /// sampler rejects 31-bit words `>= P` instead of reducing them. A
    /// reduction mod P would put about 53% of the mass below P/2 (the
    /// 2^31 - P ≈ 2^27 smallest values would count twice); rejection gives
    /// 50%.
    #[test]
    fn hedged_rcm_is_uniform_over_the_field() {
        let (base, empty) = plan(owner(1), 300, false);
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let (mut low, mut total) = (0u32, 0u32);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1500 {
            let mut w = base.clone();
            hedge_witness(&[SECRET], &[], &mut w, empty, &mut rng);
            for out in &w.outputs {
                assert!(seen.insert(out.rcm));
                for &x in &out.rcm {
                    assert!(x < P, "non-canonical limb");
                    low += (x < P / 2) as u32;
                    total += 1;
                }
            }
        }
        // 24 000 limbs: the fraction's standard deviation is about 0.0032.
        let frac = low as f64 / total as f64;
        assert!((0.485..0.515).contains(&frac), "fraction below P/2: {frac}");
    }

    /// The sampler rejects, it does not reduce: a word `>= P` (after the
    /// shift) is skipped.
    #[test]
    fn the_sampler_rejects_out_of_range_words() {
        struct Words(Vec<u32>);
        impl RngCore for Words {
            fn next_u32(&mut self) -> u32 {
                self.0.remove(0)
            }
            fn next_u64(&mut self) -> u64 {
                unimplemented!()
            }
            fn fill_bytes(&mut self, _: &mut [u8]) {
                unimplemented!()
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
                unimplemented!()
            }
        }
        impl CryptoRng for Words {}
        let mut words = vec![u32::MAX, P << 1, (P - 1) << 1];
        words.extend((1..8).map(|k| k << 1));
        assert_eq!(
            random_digest(&mut Words(words)),
            [P - 1, 1, 2, 3, 4, 5, 6, 7]
        );
    }
}
