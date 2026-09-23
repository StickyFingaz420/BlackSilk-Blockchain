use std::time::Instant;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_challenger::DuplexChallenger;
use p3_uni_stark::{prove, verify, StarkConfig};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use rand::SeedableRng;
use rand::rngs::StdRng;

macro_rules! bench {
    ($name:expr, $F:ty, $D:expr, $W:expr, $RATE:expr, $OUT:expr, $perm:expr, $LL:ty, $HALF:expr, $PART:expr, $rc:expr, $blow:expr, $q:expr, $pow:expr, $n:expr) => {{
        type Val = $F;
        type Ch = BinomialExtensionField<Val, $D>;
        let perm = $perm;
        type P = <$F as BenchPerm>::Perm;
        type H = PaddingFreeSponge<P, $W, $RATE, $OUT>;
        type C = TruncatedPermutation<P, 2, $OUT, $W>;
        type VM = MerkleTreeHidingMmcs<<Val as Field>::Packing, <Val as Field>::Packing, H, C, StdRng, 2, $OUT, 4>;
        type CM = ExtensionMmcs<Val, Ch, VM>;
        type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, VM, CM, StdRng>;
        type Chal = DuplexChallenger<Val, P, $W, $RATE>;
        let mk = |seed: u64| {
            let vm = VM::new(H::new(perm.clone()), C::new(perm.clone()), 2, StdRng::seed_from_u64(seed));
            let fri = FriParameters { log_blowup: $blow, log_final_poly_len: 0, max_log_arity: 1, num_queries: $q, commit_proof_of_work_bits: 0, query_proof_of_work_bits: $pow, mmcs: CM::new(vm.clone()) };
            let pcs = Pcs::new(Radix2DitParallel::<Val>::default(), vm, fri, 4, StdRng::seed_from_u64(seed + 1));
            StarkConfig::new(pcs, Chal::new(perm.clone()))
        };
        let (a, b, c) = $rc;
        let air = Poseidon2Air::<Val, $LL, $W, 7, 1, $HALF, $PART>::new(RoundConstants::new(a, b, c));
        let trace = air.generate_random_trace_rows($n, $blow + 1);
        let cfg = mk(7);
        let t = Instant::now();
        let proof = prove(&cfg, &air, trace, &[]);
        let tp = t.elapsed();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let t = Instant::now();
        verify(&cfg, &air, &proof, &[]).expect("verifies");
        let tv = t.elapsed();
        println!("{:12} perms={} blowup=2^{} q={} pow={}: prove {:?}, verify {:?}, proof {} KB", $name, $n, $blow, $q, $pow, tp, tv, bytes.len() / 1024);
    }};
}

trait BenchPerm { type Perm: Clone; }
impl BenchPerm for p3_baby_bear::BabyBear { type Perm = p3_baby_bear::Poseidon2BabyBear<16>; }
impl BenchPerm for p3_goldilocks::Goldilocks { type Perm = p3_goldilocks::Poseidon2Goldilocks<8>; }

fn main() {
    use p3_baby_bear::*;
    use p3_goldilocks::*;
    for n in [1usize << 7, 1 << 10, 1 << 12] {
        bench!("BabyBear^5", BabyBear, 5, 16, 8, 8, default_babybear_poseidon2_16(), GenericPoseidon2LinearLayersBabyBear, 4, 13,
            (BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL), 3, 128, 16, n);
        bench!("Goldilocks^5", Goldilocks, 5, 8, 4, 4, default_goldilocks_poseidon2_8(), GenericPoseidon2LinearLayersGoldilocks, 4, 22,
            (GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL), 2, 160, 16, n);
    }
}
