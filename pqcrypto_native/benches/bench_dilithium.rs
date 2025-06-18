use criterion::{criterion_group, criterion_main, Criterion};
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;

fn bench_keygen(c: &mut Criterion) {
    let seed = [0u8; 16];
    c.bench_function("dilithium2_keygen", |b| {
        b.iter(|| {
            Dilithium2::keypair_from_seed(&seed).unwrap();
        })
    });
}

fn bench_sign(c: &mut Criterion) {
    let seed = [0u8; 16];
    let (pk, sk) = Dilithium2::keypair_from_seed(&seed).unwrap();
    let msg = b"benchmark message";
    c.bench_function("dilithium2_sign", |b| {
        b.iter(|| {
            Dilithium2::sign(&sk, msg).unwrap();
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let seed = [0u8; 16];
    let (pk, sk) = Dilithium2::keypair_from_seed(&seed).unwrap();
    let msg = b"benchmark message";
    let sig = Dilithium2::sign(&sk, msg).unwrap();
    c.bench_function("dilithium2_verify", |b| {
        b.iter(|| {
            Dilithium2::verify(&pk, msg, &sig).unwrap();
        })
    });
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
