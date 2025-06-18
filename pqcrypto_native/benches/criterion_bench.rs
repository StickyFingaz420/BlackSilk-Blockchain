use criterion::{criterion_group, criterion_main, Criterion};
use pqcrypto_native::algorithms::falcon::Falcon512;
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;

fn bench_falcon(c: &mut Criterion) {
    let msg = b"benchmark message";
    let seed = [42u8; 32];
    let (pk, sk) = Falcon512::keypair_from_seed(&seed).unwrap();
    c.bench_function("falcon512_sign", |b| b.iter(|| Falcon512::sign(&sk, msg)));
    let sig = Falcon512::sign(&sk, msg).unwrap();
    c.bench_function("falcon512_verify", |b| b.iter(|| Falcon512::verify(&pk, msg, &sig)));
}

fn bench_dilithium(c: &mut Criterion) {
    let msg = b"benchmark message";
    let seed = [24u8; 32];
    let (pk, sk) = Dilithium2::keypair_from_seed(&seed).unwrap();
    c.bench_function("dilithium2_sign", |b| b.iter(|| Dilithium2::sign(&sk, msg)));
    let sig = Dilithium2::sign(&sk, msg).unwrap();
    c.bench_function("dilithium2_verify", |b| b.iter(|| Dilithium2::verify(&pk, msg, &sig)));
}

criterion_group!(benches, bench_falcon, bench_dilithium);
criterion_main!(benches);
