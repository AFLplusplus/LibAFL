//! Compare the speed of rand implementations

use libafl::utils::{
    Lehmer64Rand, Rand, RomuDuoJrRand, RomuTrioRand, XorShift64Rand, Xoshiro256StarRand,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let mut xorshift = XorShift64Rand::new(1);
    let mut xoshiro = Xoshiro256StarRand::new(1);
    let mut romu = RomuDuoJrRand::new(1);
    let mut lehmer = Lehmer64Rand::new(1);
    let mut romu_trio = RomuTrioRand::new(1);

    c.bench_function("xorshift", |b| b.iter(|| black_box(xorshift.next())));
    c.bench_function("xoshiro", |b| b.iter(|| black_box(xoshiro.next())));
    c.bench_function("romu", |b| b.iter(|| black_box(romu.next())));
    c.bench_function("romu_trio", |b| b.iter(|| black_box(romu_trio.next())));
    c.bench_function("lehmer", |b| b.iter(|| black_box(lehmer.next())));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
