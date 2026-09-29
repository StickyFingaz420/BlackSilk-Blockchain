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

// Without SSE2, x86 f64 arithmetic runs on the x87 FPU with 80-bit intermediates:
// double rounding would change hashes silently.
#[cfg(all(target_arch = "x86", not(target_feature = "sse2")))]
compile_error!("RandomX requires SSE2 f64 arithmetic on x86");

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

/// One value of [`config_entries`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigValue {
    /// An integer parameter (widened to 64 bits; the signed superscalar
    /// latency sign-extended, so distinct values stay distinct).
    Int(u64),
    /// A byte-string parameter (the Argon2 salt).
    Bytes(&'static [u8]),
    /// A list of integers (the instruction frequencies, in opcode order).
    Ints(Vec<u64>),
}

/// The RandomX configuration this crate hashes with, read from its own
/// constants (`config.rs`), in a fixed order: the consensus fingerprint lists
/// these (node/src/fingerprint.rs, RTFP3-2), so a changed parameter changes
/// the fingerprint. Every value is consensus-critical.
pub fn config_entries() -> Vec<(&'static str, ConfigValue)> {
    use config::*;
    use ConfigValue::{Bytes, Int, Ints};
    vec![
        ("ARGON_MEMORY_KIB", Int(ARGON_MEMORY.into())),
        ("ARGON_ITERATIONS", Int(ARGON_ITERATIONS.into())),
        ("ARGON_LANES", Int(ARGON_LANES.into())),
        ("ARGON_SALT", Bytes(ARGON_SALT)),
        ("CACHE_ACCESSES", Int(CACHE_ACCESSES as u64)),
        ("SUPERSCALAR_LATENCY", Int(SUPERSCALAR_LATENCY as u64)),
        ("SUPERSCALAR_MAX_SIZE", Int(SUPERSCALAR_MAX_SIZE as u64)),
        ("DATASET_BASE_SIZE", Int(DATASET_BASE_SIZE)),
        ("DATASET_EXTRA_SIZE", Int(DATASET_EXTRA_SIZE)),
        ("DATASET_ITEM_SIZE", Int(DATASET_ITEM_SIZE)),
        ("DATASET_ITEM_COUNT", Int(DATASET_ITEM_COUNT)),
        ("DATASET_EXTRA_ITEMS", Int(DATASET_EXTRA_ITEMS)),
        ("CACHE_SIZE", Int(CACHE_SIZE as u64)),
        ("CACHE_LINE_SIZE", Int(CACHE_LINE_SIZE as u64)),
        ("CACHE_LINE_ALIGN_MASK", Int(CACHE_LINE_ALIGN_MASK.into())),
        ("PROGRAM_SIZE", Int(PROGRAM_SIZE as u64)),
        ("PROGRAM_ITERATIONS", Int(PROGRAM_ITERATIONS as u64)),
        ("PROGRAM_COUNT", Int(PROGRAM_COUNT as u64)),
        (
            "SCRATCHPAD_L3_L2_L1",
            Ints(vec![
                SCRATCHPAD_L3 as u64,
                SCRATCHPAD_L2 as u64,
                SCRATCHPAD_L1 as u64,
            ]),
        ),
        (
            "SCRATCHPAD_L1_L2_L3_L3_64_MASKS",
            Ints(
                [
                    SCRATCHPAD_L1_MASK,
                    SCRATCHPAD_L2_MASK,
                    SCRATCHPAD_L3_MASK,
                    SCRATCHPAD_L3_MASK64,
                ]
                .map(u64::from)
                .to_vec(),
            ),
        ),
        ("JUMP_BITS", Int(JUMP_BITS.into())),
        ("JUMP_OFFSET", Int(JUMP_OFFSET.into())),
        ("CONDITION_MASK", Int(CONDITION_MASK.into())),
        ("STORE_L3_CONDITION", Int(STORE_L3_CONDITION.into())),
        (
            "REGISTER_NEEDS_DISPLACEMENT",
            Int(REGISTER_NEEDS_DISPLACEMENT as u64),
        ),
        (
            "FREQ",
            Ints(
                [
                    FREQ_IADD_RS,
                    FREQ_IADD_M,
                    FREQ_ISUB_R,
                    FREQ_ISUB_M,
                    FREQ_IMUL_R,
                    FREQ_IMUL_M,
                    FREQ_IMULH_R,
                    FREQ_IMULH_M,
                    FREQ_ISMULH_R,
                    FREQ_ISMULH_M,
                    FREQ_IMUL_RCP,
                    FREQ_INEG_R,
                    FREQ_IXOR_R,
                    FREQ_IXOR_M,
                    FREQ_IROR_R,
                    FREQ_IROL_R,
                    FREQ_ISWAP_R,
                    FREQ_FSWAP_R,
                    FREQ_FADD_R,
                    FREQ_FADD_M,
                    FREQ_FSUB_R,
                    FREQ_FSUB_M,
                    FREQ_FSCAL_R,
                    FREQ_FMUL_R,
                    FREQ_FDIV_M,
                    FREQ_FSQRT_R,
                    FREQ_CBRANCH,
                    FREQ_CFROUND,
                    FREQ_ISTORE,
                ]
                .map(u64::from)
                .to_vec(),
            ),
        ),
    ]
}

/// A RandomX known answer: `hash_light(key, input) = hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownAnswer {
    pub key: &'static [u8],
    pub input: &'static [u8],
    /// Lowercase hex.
    pub hash: &'static str,
}

/// The pinned known answer of the consensus fingerprint (RTFP3-2): the
/// reference implementation's "Hash test 1a" (`src/tests/tests.cpp`). A light
/// hash needs a 256 MiB cache, too costly at node start-up, so the
/// fingerprint lists this **pinned copy** and `tests::hash_1a` requires the
/// crate to compute it (the pattern of `zkvm::prove::CIRCUIT_DIGEST`). A
/// change of the algorithm fails that test; a change of this value changes
/// the fingerprint.
pub const FINGERPRINT_KAT: KnownAnswer = KnownAnswer {
    key: b"test key 000",
    input: b"This is a test",
    hash: "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
};

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

    /// Key of "Hash test 1f" (upstream PR #326): 31 bytes. The reference declares a
    /// 32-byte array whose trailing zero its `initCache` helper drops (`sizeof - 1`).
    const KEY_1F: [u8; 31] = [
        0x77, 0x97, 0x37, 0x3e, 0xa4, 0x63, 0x31, 0x94, 0x64, 0x0b, 0xf8, 0xd8, 0xc3, 0xb6, 0x67,
        0x24, 0xd6, 0xaa, 0x7b, 0xd2, 0xdc, 0x20, 0xe0, 0x09, 0xdf, 0x2f, 0x8f, 0x17, 0x10, 0xab,
        0xe8,
    ];
    /// Input of "Hash test 1f": a 76-byte blob.
    const INPUT_1F: &str = "1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f6821fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d90689721c4aac5a9bb0d";
    const HASH_1F: &str = "78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8";

    fn cache_1f() -> &'static Cache {
        static CACHE: OnceLock<Cache> = OnceLock::new();
        CACHE.get_or_init(|| Cache::new(&KEY_1F))
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
        // The fingerprint's pinned known answer is this vector, and the crate
        // computes it (RTFP3-2).
        assert_eq!(FINGERPRINT_KAT.key, b"test key 000");
        check(cache_000(), FINGERPRINT_KAT.input, FINGERPRINT_KAT.hash);
    }

    /// `config_entries` reads the crate's own constants: spot values of the
    /// reference `configuration.h`, and names unique.
    #[test]
    fn config_entries_are_the_reference_values() {
        let e = config_entries();
        let get = |k: &str| e.iter().find(|(n, _)| *n == k).unwrap().1.clone();
        assert_eq!(get("PROGRAM_ITERATIONS"), ConfigValue::Int(2048));
        assert_eq!(get("ARGON_MEMORY_KIB"), ConfigValue::Int(262_144));
        assert_eq!(get("ARGON_SALT"), ConfigValue::Bytes(b"RandomX\x03"));
        assert_eq!(get("SUPERSCALAR_LATENCY"), ConfigValue::Int(170));
        match get("FREQ") {
            ConfigValue::Ints(f) => assert_eq!((f.len(), f.iter().sum::<u64>()), (29, 256)),
            other => panic!("{other:?}"),
        }
        let mut names: Vec<&str> = e.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), e.len());
    }

    /// `Cache::try_new` (fallible allocation, for optional builds) builds the
    /// same cache as `Cache::new`: the same memory, and vector 1a.
    #[test]
    fn try_new_builds_the_same_cache() {
        let cache = Cache::try_new(b"test key 000").expect("256 MiB");
        assert!(cache.memory() == cache_000().memory());
        check(
            &cache,
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

    /// "Hash test 1f (ISUB_R edge case)", added upstream with the fix of PR #326
    /// (in v1.2.3): per upstream, its programs execute ISUB_R with src = dst and the
    /// immediate 0x80000000, the case on which the upstream JIT produced invalid
    /// hashes. This port has no JIT; the vector pins the interpreter path.
    #[test]
    fn hash_1f() {
        let input = hex::decode(INPUT_1F).unwrap();
        assert_eq!(input.len(), 76);
        check(cache_1f(), &input, HASH_1F);
    }

    /// Full mode (the miner's default) must give the official vectors and agree
    /// with light mode (what nodes verify with) on random inputs, for both
    /// reference keys and the 31-byte key of vector 1f. Needs ~2.3 GiB RAM and
    /// several minutes (one dataset per key), so it is opt-in:
    /// `cargo test --release -p blacksilk-randomx -- --ignored --nocapture`.
    /// CI runs it in the `randomx-full` job.
    #[test]
    #[ignore]
    fn full_mode_matches_light_mode() {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let vector_1e = hex::decode(
            "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416",
        )
        .unwrap();
        type Vectors<'a> = Vec<(&'a [u8], &'a str)>;
        let vector_1f = hex::decode(INPUT_1F).unwrap();
        let cases: [(&Cache, Vectors); 3] = [
            (
                cache_000(),
                vec![
                    (
                        b"This is a test",
                        "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
                    ),
                    (
                        b"Lorem ipsum dolor sit amet",
                        "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
                    ),
                    (
                        b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                        "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
                    ),
                ],
            ),
            (
                cache_001(),
                vec![
                    (
                        b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                        "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
                    ),
                    (
                        &vector_1e,
                        "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1",
                    ),
                ],
            ),
            (cache_1f(), vec![(&vector_1f, HASH_1F)]),
        ];
        for (k, (cache, vectors)) in cases.iter().enumerate() {
            let started = std::time::Instant::now();
            let dataset = Dataset::new(cache, threads);
            println!("key {k}: dataset built in {:.1?}", started.elapsed());
            let mut full = Vm::full(&dataset);
            for (input, want) in vectors {
                assert_eq!(hex::encode(full.hash(input)), *want, "key {k}, full mode");
            }
            // Random inputs of 0..200 bytes, as headers and arbitrary blobs.
            let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ k as u64;
            let mut next = || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let inputs: Vec<Vec<u8>> = (0..512)
                .map(|_| {
                    let len = (next() % 200) as usize;
                    (0..len).map(|_| next() as u8).collect()
                })
                .collect();
            let started = std::time::Instant::now();
            let full_hashes: Vec<[u8; HASH_SIZE]> = inputs.iter().map(|i| full.hash(i)).collect();
            let full_time = started.elapsed();
            let started = std::time::Instant::now();
            let light_hashes: Vec<[u8; HASH_SIZE]> = std::thread::scope(|s| {
                let chunk = inputs.len().div_ceil(threads);
                let handles: Vec<_> = inputs
                    .chunks(chunk)
                    .map(|part| {
                        s.spawn(move || {
                            let mut vm = Vm::light(cache);
                            part.iter().map(|i| vm.hash(i)).collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            });
            let light_time = started.elapsed();
            assert_eq!(
                full_hashes, light_hashes,
                "key {k}: full and light disagree"
            );
            println!(
                "key {k}: {} random inputs agree; full {:.2} ms/hash (1 thread), light {:.0} ms/hash ({threads} threads)",
                inputs.len(),
                full_time.as_secs_f64() * 1e3 / inputs.len() as f64,
                light_time.as_secs_f64() * 1e3 * threads as f64 / inputs.len() as f64,
            );
        }
    }
}
