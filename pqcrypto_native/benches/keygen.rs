use criterion::{criterion_group, criterion_main, Criterion};
use pqcrypto_native::{Algo, generate_keypair_from_seed};

fn bench_dilithium2_keygen(c: &mut Criterion) {
    let seed = b"benchmark-seed-123";
    c.bench_function("dilithium2_keygen", |b| {
        b.iter(|| {
            let _ = generate_keypair_from_seed(Algo::Dilithium2, seed);
        })
    });
}

criterion_group!(benches, bench_dilithium2_keygen);
criterion_main!(benches);
