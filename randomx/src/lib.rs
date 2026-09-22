//! Pure-Rust implementation of the RandomX proof-of-work (version 1, as used by Monero).
//!
//! This is a port of the reference implementation by tevador
//! (<https://github.com/tevador/RandomX>, BSD-3-Clause) and is verified against its
//! official test vectors. It contains no `unsafe` code and no FFI. Floating point
//! rounding modes are emulated exactly in software (module `fpu`), so results are
//! identical on every platform.
//!
//! * [`Cache`]: built from a key (256 MiB); enough to verify hashes ("light mode").
//! * [`Dataset`]: expanded from a cache (~2 GiB); makes hashing much faster ("full mode").
//! * [`Vm`]: computes hashes against either.
//!
//! ```no_run
//! use blacksilk_randomx::{Cache, Vm};
//! let cache = Cache::new(b"seed key");
//! let mut vm = Vm::light(&cache);
//! let hash = vm.hash(b"block header bytes");
//! ```

#![forbid(unsafe_code)]

mod aes_gen;
mod argon2d;
mod config;
mod dataset;
mod fpu;
mod hash;
mod superscalar;
mod vm;

pub use dataset::{Cache, Dataset};
pub use vm::Vm;

/// Size of a RandomX hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Maximum key length that affects the SuperscalarHash programs (spec 3.4).
/// Longer keys are accepted; only Argon2 sees the extra bytes, exactly as in the reference.
pub const MAX_KEY_SIZE: usize = 60;

/// Convenience: build a cache for `key` and hash `input` in light mode.
/// Building the cache dominates the cost; reuse a [`Cache`] when hashing repeatedly.
pub fn hash_light(key: &[u8], input: &[u8]) -> [u8; HASH_SIZE] {
    let cache = Cache::new(key);
    Vm::light(&cache).hash(input)
}

#[cfg(test)]
mod tests {
    //! Official test vectors from the reference `src/tests/tests.cpp`.

    use super::*;
    use crate::aes_gen::fill_aes_1rx4;
    use crate::hash::blake2b_256;
    use crate::superscalar::{generate, reciprocal, Blake2Generator};
    use std::sync::OnceLock;

    fn cache_000() -> &'static Cache {
        static CACHE: OnceLock<Cache> = OnceLock::new();
        CACHE.get_or_init(|| Cache::new(b"test key 000"))
    }

    fn cache_001() -> &'static Cache {
        static CACHE: OnceLock<Cache> = OnceLock::new();
        CACHE.get_or_init(|| Cache::new(b"test key 001"))
    }

    #[test]
    fn cache_initialization() {
        let mem = cache_000().memory();
        assert_eq!(mem[0], 0x191e0e1d23c02186);
        assert_eq!(mem[1568413], 0xf1b62fe6210bf8b1);
        assert_eq!(mem[33554431], 0x1f47f056d05cd99b);
    }

    #[test]
    fn superscalar_generator() {
        let expected = [
            "d3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61",
            "f5e7e0bbc7e93c609003d6359208688070afb4a77165a552ff7be63b38dfbc86",
            "85ed8b11734de5b3e9836641413a8f36e99e89694f419c8cd25c3f3f16c40c5a",
            "5dd956292cf5d5704ad99e362d70098b2777b2a1730520be52f772ca48cd3bc0",
            "6f14018ca7d519e9b48d91af094c0f2d7e12e93af0228782671a8640092af9e5",
            "134be097c92e2c45a92f23208cacd89e4ce51f1009a0b900dbe83b38de11d791",
            "268f9392c20c6e31371a5131f82bd7713d3910075f2f0468baafaa1abd2f3187",
            "c668a05fd909714ed4a91e8d96d67b17e44329e88bc71e0672b529a3fc16be47",
            "99739351315840963011e4c5d8e90ad0bfed3facdcb713fe8f7138fbf01c4c94",
            "14ab53d61880471f66e80183968d97effd5492b406876060e595fcf9682f9295",
        ];
        let mut gen = Blake2Generator::new(b"test key 000", 0);
        for (i, want) in expected.iter().enumerate() {
            let prog = generate(&mut gen);
            let bytes: Vec<u8> = prog.instrs.iter().flat_map(|ins| ins.to_bytes()).collect();
            assert_eq!(
                hex::encode(blake2b_256(&bytes)),
                *want,
                "superscalar program {i}"
            );
        }
    }

    #[test]
    fn reciprocals() {
        assert_eq!(reciprocal(3), 12297829382473034410);
        assert_eq!(reciprocal(13), 11351842506898185609);
        assert_eq!(reciprocal(33), 17887751829051686415);
        assert_eq!(reciprocal(65537), 18446462603027742720);
        assert_eq!(reciprocal(15000001), 10316166306300415204);
        assert_eq!(reciprocal(3845182035), 10302264209224146340);
        assert_eq!(reciprocal(0xffffffff), 9223372039002259456);
    }

    #[test]
    fn dataset_items() {
        let cache = cache_000();
        assert_eq!(cache.dataset_item(0)[0], 0x680588a85ae222db);
        assert_eq!(cache.dataset_item(10000000)[0], 0x7943a1f6186ffb72);
        assert_eq!(cache.dataset_item(20000000)[0], 0x9035244d718095e1);
        assert_eq!(cache.dataset_item(30000000)[0], 0x145a5091f7853099);
    }

    #[test]
    fn aes_generator_1r() {
        let mut state = [0u8; 64];
        state[..32].copy_from_slice(
            &hex::decode("6c19536eb2de31b6c0065f7f116e86f960d8af0c57210a6584c3237b9d064dc7")
                .unwrap(),
        );
        let mut out = [0u8; 64];
        fill_aes_1rx4(&mut state, &mut out);
        assert_eq!(
            hex::encode(&out[..32]),
            "fa89397dd6ca422513aeadba3f124b5540324c4ad4b6db434394307a17c833ab"
        );
    }

    fn check(cache: &Cache, input: &[u8], want: &str) {
        assert_eq!(hex::encode(Vm::light(cache).hash(input)), want);
    }

    #[test]
    fn hash_1a() {
        check(
            cache_000(),
            b"This is a test",
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
        );
    }

    #[test]
    fn hash_1b() {
        check(
            cache_000(),
            b"Lorem ipsum dolor sit amet",
            "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
        );
    }

    #[test]
    fn hash_1c() {
        check(
            cache_000(),
            b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
            "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
        );
    }

    #[test]
    fn hash_1d() {
        check(
            cache_001(),
            b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
            "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
        );
    }

    #[test]
    fn hash_1e() {
        let input = hex::decode(
            "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416",
        )
        .unwrap();
        check(
            cache_001(),
            &input,
            "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1",
        );
    }

    /// Full mode must agree with light mode. Needs ~2.3 GiB RAM, so it is opt-in:
    /// `cargo test --release -p blacksilk-randomx -- --ignored`
    #[test]
    #[ignore]
    fn full_mode_matches_light_mode() {
        let dataset = Dataset::new(
            cache_000(),
            std::thread::available_parallelism().map_or(4, |n| n.get()),
        );
        let mut full = Vm::full(&dataset);
        assert_eq!(
            hex::encode(full.hash(b"This is a test")),
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        );
    }
}
