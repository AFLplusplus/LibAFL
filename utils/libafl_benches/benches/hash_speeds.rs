//! Compare the speed of rust hash implementations

use std::hash::{BuildHasher, Hasher};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libafl_bolts::rands::{Rand, StdRand};
//use xxhash_rust::const_xxh3;
use xxhash_rust::xxh3;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rand = StdRand::with_seed(0);
    let mut bench_vec: Vec<u8> = vec![];
    for _ in 0..2 << 16 {
        bench_vec.push(rand.below(256) as u8);
    }

    c.bench_function("xxh3", |b| {
        b.iter(|| xxh3::xxh3_64_with_seed(black_box(&bench_vec), 0));
    });
    /*c.bench_function("const_xxh3", |b| {
        b.iter(|| const_xxh3::xxh3_64_with_seed(black_box(&bench_vec), 0))
    });*/
    c.bench_function("ahash", |b| {
        b.iter(|| {
            let mut hasher =
                black_box(ahash::RandomState::with_seeds(123, 456, 789, 123).build_hasher());
            hasher.write(black_box(&bench_vec));
            hasher.finish();
        });
    });
    c.bench_function("fxhash", |b| {
        b.iter(|| {
            let mut hasher = black_box(rustc_hash::FxHasher::default());
            hasher.write(black_box(&bench_vec));
            hasher.finish();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
