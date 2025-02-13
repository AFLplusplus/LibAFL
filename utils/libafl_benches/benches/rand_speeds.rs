//! Compare the speed of rand implementations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libafl_bolts::rands::{
    Lehmer64Rand, Rand, RomuDuoJrRand, RomuTrioRand, Sfc64Rand, XorShift64Rand,
    Xoshiro256PlusPlusRand,
};

fn criterion_benchmark(c: &mut Criterion) {
    let mut sfc64 = Sfc64Rand::with_seed(1);
    let mut xorshift = XorShift64Rand::with_seed(1);
    let mut xoshiro = Xoshiro256PlusPlusRand::with_seed(1);
    let mut romu = RomuDuoJrRand::with_seed(1);
    let mut lehmer = Lehmer64Rand::with_seed(1);
    let mut romu_trio = RomuTrioRand::with_seed(1);

    c.bench_function("sfc64", |b| b.iter(|| black_box(sfc64.next())));
    c.bench_function("xorshift", |b| b.iter(|| black_box(xorshift.next())));
    c.bench_function("xoshiro", |b| b.iter(|| black_box(xoshiro.next())));
    c.bench_function("romu", |b| b.iter(|| black_box(romu.next())));
    c.bench_function("romu_trio", |b| b.iter(|| black_box(romu_trio.next())));
    c.bench_function("lehmer", |b| b.iter(|| black_box(lehmer.next())));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
