use criterion::{black_box, criterion_group, criterion_main, Criterion};
use randomx::{RandomXVM, Flags};

fn bench_randomx_hash(c: &mut Criterion) {
    // Initialize VM in light mode
    let mut vm = RandomXVM::new(Flags::DEFAULT).unwrap();
    vm.init_cache(b"benchmark key").unwrap();

    let input = b"benchmark input";

    c.bench_function("randomx_hash_light", |b| {
        b.iter(|| {
            vm.calculate_hash(black_box(input)).unwrap()
        })
    });

    // Initialize VM in fast mode
    let mut vm = RandomXVM::new(Flags::FULL_MEM).unwrap();
    vm.init_cache(b"benchmark key").unwrap();
    vm.init_dataset(0, 1).unwrap();

    c.bench_function("randomx_hash_fast", |b| {
        b.iter(|| {
            vm.calculate_hash(black_box(input)).unwrap()
        })
    });

    // Test with hardware AES
    if let Ok(mut vm) = RandomXVM::new(Flags::HARDWARE_AES | Flags::FULL_MEM) {
        vm.init_cache(b"benchmark key").unwrap();
        vm.init_dataset(0, 1).unwrap();

        c.bench_function("randomx_hash_aes", |b| {
            b.iter(|| {
                vm.calculate_hash(black_box(input)).unwrap()
            })
        });
    }

    // Test with JIT compilation
    if let Ok(mut vm) = RandomXVM::new(Flags::JIT | Flags::FULL_MEM) {
        vm.init_cache(b"benchmark key").unwrap();
        vm.init_dataset(0, 1).unwrap();

        c.bench_function("randomx_hash_jit", |b| {
            b.iter(|| {
                vm.calculate_hash(black_box(input)).unwrap()
            })
        });
    }
}

criterion_group!(benches, bench_randomx_hash);
criterion_main!(benches);
