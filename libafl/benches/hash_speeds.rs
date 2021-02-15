//! Compare the speed of rust hash implementations

use ahash;
use fxhash;
use std::hash::Hasher;
use xxhash_rust::const_xxh3;
use xxhash_rust::xxh3;

use libafl::utils::{Rand, StdRand};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let mut rand = StdRand::new(0);
    let mut bench_vec: Vec<u8> = vec![];
    for _ in 0..2 << 16 {
        bench_vec.push(rand.below(256) as u8);
    }

    c.bench_function("xxh3", |b| {
        b.iter(|| xxh3::xxh3_64_with_seed(black_box(&bench_vec), 0))
    });
    c.bench_function("const_xxh3", |b| {
        b.iter(|| const_xxh3::xxh3_64_with_seed(black_box(&bench_vec), 0))
    });
    c.bench_function("ahash", |b| {
        b.iter(|| {
            let mut hasher = ahash::AHasher::new_with_keys(123, 456);
            hasher.write(black_box(&bench_vec));
            hasher.finish();
        })
    });
    c.bench_function("fxhash", |b| {
        b.iter(|| fxhash::hash64(black_box(&bench_vec)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
