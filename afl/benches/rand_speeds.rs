//! Compare the speed of rand implementations

use afl::utils::{Rand, XorShift64Rand, Xoshiro256StarRand};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let mut xorshift = XorShift64Rand::new(0);
    let mut xoshiro = Xoshiro256StarRand::new(0);

    c.bench_function("xorshift", |b| b.iter(|| black_box(xorshift.next())));
    c.bench_function("xoshiro", |b| b.iter(|| black_box(xoshiro.next())));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
