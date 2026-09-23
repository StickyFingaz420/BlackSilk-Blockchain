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
    ($name:expr, $F:ty, $D:expr, $W:expr, $RATE:expr, $OUT:expr, $perm:expr, $LL:ty, $HALF:expr, $PART:expr, $rc:expr, $blow:expr, $q:expr, $pow:expr, $n:expr, $ar:expr, $fin:expr) => {{
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
            let fri = FriParameters { log_blowup: $blow, log_final_poly_len: $fin, max_log_arity: $ar, num_queries: $q, commit_proof_of_work_bits: 0, query_proof_of_work_bits: $pow, mmcs: CM::new(vm.clone()) };
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
        println!("{:12} perms={:5} blowup=2^{} q={} pow={} arity=2^{} final=2^{}: prove {:?}, verify {:?}, proof {} KB", $name, $n, $blow, $q, $pow, $ar, $fin, tp, tv, bytes.len() / 1024);
    }};
}


struct Narrow { w: usize }
impl<F> p3_air::BaseAir<F> for Narrow { fn width(&self) -> usize { self.w } }
impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for Narrow {
    fn eval(&self, b: &mut AB) {
        use p3_air::{AirBuilder, WindowAccess};
        let m = b.main();
        let l: Vec<_> = m.current_slice().to_vec();
        let n: Vec<_> = m.next_slice().to_vec();
        for i in 0..self.w {
            let j = (i + 1) % self.w;
            { let e: AB::Expr = n[i].into(); let li: AB::Expr = l[i].into(); let lj: AB::Expr = l[j].into(); b.when_transition().assert_zero(e - li.clone() * lj.clone() * li - lj); }
        }
    }
}
fn narrow_trace<F: p3_field::PrimeField64>(w: usize, rows: usize) -> p3_matrix::dense::RowMajorMatrix<F> {
    let mut v = vec![F::ZERO; w * rows];
    for i in 0..w { v[i] = F::from_u64(i as u64 + 2); }
    for r in 1..rows { for i in 0..w { let j = (i + 1) % w; let (a, c) = (v[(r-1)*w+i], v[(r-1)*w+j]); v[r*w+i] = a * c * a + c; } }
    p3_matrix::dense::RowMajorMatrix::new(v, w)
}
trait BenchPerm { type Perm: Clone; }
impl BenchPerm for p3_baby_bear::BabyBear { type Perm = p3_baby_bear::Poseidon2BabyBear<16>; }
impl BenchPerm for p3_goldilocks::Goldilocks { type Perm = p3_goldilocks::Poseidon2Goldilocks<8>; }

fn main() {
    use p3_baby_bear::*;
    use p3_goldilocks::*;
    use p3_field::extension::BinomialExtensionField as BEF;
    type Val = BabyBear; type Ch = BEF<Val, 5>;
    type P = Poseidon2BabyBear<16>;
    type H = PaddingFreeSponge<P, 16, 8, 8>; type C = TruncatedPermutation<P, 2, 8, 16>;
    type VM = MerkleTreeHidingMmcs<<Val as Field>::Packing, <Val as Field>::Packing, H, C, StdRng, 2, 8, 4>;
    type CM = ExtensionMmcs<Val, Ch, VM>;
    type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, VM, CM, StdRng>;
    type Chal = DuplexChallenger<Val, P, 16, 8>;
    let perm = default_babybear_poseidon2_16();
    for (w, rows) in [(20usize, 1usize << 12), (20, 1 << 16)] {
        for (blow, q, ar, fin) in [(5usize, 50usize, 4usize, 6usize)] {
            let vm = VM::new(H::new(perm.clone()), C::new(perm.clone()), 2, StdRng::seed_from_u64(1));
            let fri = FriParameters { log_blowup: blow, log_final_poly_len: fin, max_log_arity: ar, num_queries: q, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: CM::new(vm.clone()) };
            let pcs = Pcs::new(Radix2DitParallel::<Val>::default(), vm, fri, 4, StdRng::seed_from_u64(2));
            let cfg = StarkConfig::new(pcs, Chal::new(perm.clone()));
            let air = Narrow { w };
            let t = Instant::now();
            let proof = prove(&cfg, &air, narrow_trace::<Val>(w, rows), &[]);
            let tp = t.elapsed();
            let bytes = postcard::to_allocvec(&proof).unwrap();
            let t = Instant::now();
            verify(&cfg, &air, &proof, &[]).expect("ok");
            println!("narrow w={w:3} rows=2^{:2} blowup=2^{blow} q={q} arity=2^{ar} final=2^{fin}: prove {:?} verify {:?} proof {} KB", rows.trailing_zeros(), tp, t.elapsed(), bytes.len()/1024);
        }
    }
}
