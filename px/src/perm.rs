//! The host implementation of [`blacksilk_px_core::Permutation`]: Plonky3's
//! Poseidon2 (BabyBear, width 16, standard constants), the same permutation
//! the zkVM's `POSEIDON2` table constrains and its interpreter executes.

use blacksilk_px_core::{Permutation, P};
use blacksilk_zk::config::{permutation, Perm, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation as _;

pub struct HostPerm(Perm);

impl HostPerm {
    pub fn new() -> Self {
        HostPerm(permutation())
    }
}

impl Default for HostPerm {
    fn default() -> Self {
        Self::new()
    }
}

impl Permutation for HostPerm {
    fn permute(&mut self, state: &mut [u32; 16]) {
        assert!(
            state.iter().all(|&x| x < P),
            "non-canonical permutation input"
        );
        let mut s = state.map(Val::from_u32);
        self.0.permute_mut(&mut s);
        *state = s.map(|x| x.as_canonical_u32());
    }
}
