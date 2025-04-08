//! Module for SIMD assisted methods.

use alloc::{vec, vec::Vec};
#[rustversion::nightly]
use core::simd::cmp::SimdOrd;

/// `simplify_map` naive implementaion. In most cases, this can be auto-vectorized.
pub fn simplify_map_naive(map: &mut [u8]) {
    for it in map.iter_mut() {
        *it = if *it == 0 { 0x1 } else { 0x80 };
    }
}

/// `simplify_map` implementation by u8x16, worse performance compared to LLVM
/// auto-vectorization buf faster if LLVM doesn't vectorize.
#[cfg(feature = "wide")]
pub fn simplify_map_u8x16(map: &mut [u8]) {
    type VectorType = wide::u8x16;
    const N: usize = VectorType::LANES as usize;
    let size = map.len();
    let steps = size / N;
    let left = size % N;
    let lhs = VectorType::new([0x1; N]);
    let rhs = VectorType::new([0x80; N]);

    for step in 0..steps {
        let i = step * N;
        let mp = VectorType::new(map[i..(i + N)].try_into().unwrap());

        let mask = mp.cmp_eq(VectorType::ZERO);
        let out = mask.blend(lhs, rhs);
        map[i..i + N].copy_from_slice(out.as_array_ref());
    }

    #[allow(clippy::needless_range_loop)]
    for j in (size - left)..size {
        map[j] = if map[j] == 0 { 0x1 } else { 0x80 }
    }
}

/// `simplify_map` implementation by u64x4, achieving comparable performance with
/// LLVM auto-vectorization.
#[cfg(feature = "wide")]
pub fn simplify_map_u64x4(map: &mut [u8]) {
    type VectorType = wide::u64x4;
    const N: usize = 8 * VectorType::LANES as usize;
    let size = map.len();
    let steps = size / N;
    let left = size % N;
    let lhs = VectorType::new([0x01010101010101; 4]);
    let rhs = VectorType::new([0x80808080808080; 4]);

    for step in 0..steps {
        let i = step * N;
        let buf: [u8; 32] = map[i..i + N].try_into().unwrap();
        let mp = VectorType::new(unsafe { core::mem::transmute::<[u8; 32], [u64; 4]>(buf) });

        let mask = mp.cmp_eq(VectorType::ZERO);
        let out = mask.blend(lhs, rhs);
        unsafe {
            (out.as_array_ref().as_ptr() as *const u8)
                .copy_to_nonoverlapping(map.as_mut_ptr().add(i), N);
        }
    }

    #[allow(clippy::needless_range_loop)]
    for j in (size - left)..size {
        map[j] = if map[j] == 0 { 0x1 } else { 0x80 }
    }
}

/// The std implementation of `simplify_map`. Use the fastest implementation by benchamrk by default.
pub fn std_simplify_map(map: &mut [u8]) {
    #[cfg(feature = "simplify_map_naive")]
    simplify_map_naive(map);

    #[cfg(feature = "simplify_map_wide128")]
    simplify_map_u8x16(map);

    #[cfg(feature = "simplify_map_wide256")]
    simplify_map_u64x4(map);

    #[cfg(not(any(
        feature = "simplify_map_naive",
        feature = "simplify_map_wide128",
        feature = "simplify_map_wide256"
    )))]
    simplify_map_naive(map);
}

/// Coverage map insteresting implementation by nightly portable simd.
#[rustversion::nightly]
#[must_use]
pub fn covmap_is_interesting_stdsimd(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    type VectorType = core::simd::u8x16;
    let mut novelties = vec![];
    let mut interesting = false;
    let size = map.len();
    let steps = size / VectorType::LEN;
    let left = size % VectorType::LEN;

    if collect_novelties {
        for step in 0..steps {
            let i = step * VectorType::LEN;
            let history = VectorType::from_slice(&hist[i..]);
            let items = VectorType::from_slice(&map[i..]);

            if items.simd_max(history) != history {
                interesting = true;
                unsafe {
                    for j in i..(i + VectorType::LEN) {
                        let item = *map.get_unchecked(j);
                        if item > *hist.get_unchecked(j) {
                            novelties.push(j);
                        }
                    }
                }
            }
        }

        for j in (size - left)..size {
            unsafe {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    interesting = true;
                    novelties.push(j);
                }
            }
        }
    } else {
        for step in 0..steps {
            let i = step * VectorType::LEN;
            let history = VectorType::from_slice(&hist[i..]);
            let items = VectorType::from_slice(&map[i..]);

            if items.simd_max(history) != history {
                interesting = true;
                break;
            }
        }

        if !interesting {
            for j in (size - left)..size {
                unsafe {
                    let item = *map.get_unchecked(j);
                    if item > *hist.get_unchecked(j) {
                        interesting = true;
                        break;
                    }
                }
            }
        }
    }

    (interesting, novelties)
}

/// Coverage map insteresting implementation by u8x16. Slightly faster than nightly simd.
#[cfg(feature = "wide")]
#[must_use]
pub fn covmap_is_interesting_u8x16(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    type VectorType = wide::u8x16;
    let mut novelties = vec![];
    let mut interesting = false;
    let size = map.len();
    let steps = size / VectorType::LANES as usize;
    let left = size % VectorType::LANES as usize;

    if collect_novelties {
        for step in 0..steps {
            let i = step * VectorType::LANES as usize;
            let history =
                VectorType::new(hist[i..i + VectorType::LANES as usize].try_into().unwrap());
            let items = VectorType::new(map[i..i + VectorType::LANES as usize].try_into().unwrap());

            if items.max(history) != history {
                interesting = true;
                unsafe {
                    for j in i..(i + VectorType::LANES as usize) {
                        let item = *map.get_unchecked(j);
                        if item > *hist.get_unchecked(j) {
                            novelties.push(j);
                        }
                    }
                }
            }
        }

        for j in (size - left)..size {
            unsafe {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    interesting = true;
                    novelties.push(j);
                }
            }
        }
    } else {
        for step in 0..steps {
            let i = step * VectorType::LANES as usize;
            let history =
                VectorType::new(hist[i..i + VectorType::LANES as usize].try_into().unwrap());
            let items = VectorType::new(map[i..i + VectorType::LANES as usize].try_into().unwrap());

            if items.max(history) != history {
                interesting = true;
                break;
            }
        }

        if !interesting {
            for j in (size - left)..size {
                unsafe {
                    let item = *map.get_unchecked(j);
                    if item > *hist.get_unchecked(j) {
                        interesting = true;
                        break;
                    }
                }
            }
        }
    }

    (interesting, novelties)
}

/// Coverage map insteresting implementation by u32x4. Slightly faster than nightly simd but slightly
/// slower than u8x16 version.
#[cfg(feature = "wide")]
#[must_use]
pub fn covmap_is_interesting_u32x4(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    type VectorType = wide::u32x4;
    const N: usize = 4 * VectorType::LANES as usize;
    let mut novelties = vec![];
    let mut interesting = false;
    let size = map.len();
    let steps = size / N;
    let left = size % N;

    if collect_novelties {
        for step in 0..steps {
            let i = step * N;
            let buf: [u8; N] = hist[i..i + N].try_into().unwrap();
            let history =
                VectorType::new(unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(buf) });
            let buf: [u8; N] = map[i..i + N].try_into().unwrap();
            let items = VectorType::new(unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(buf) });

            if items.max(history) != history {
                interesting = true;
                unsafe {
                    // Break into two loops so that LLVM will vectorize both loops.
                    // Or LLVM won't vectorize them and is super slow. We need a few
                    // extra intrinsic to wide and safe_arch to vectorize this manually.
                    for j in i..(i + N / 2) {
                        let item = *map.get_unchecked(j);
                        if item > *hist.get_unchecked(j) {
                            novelties.push(j);
                        }
                    }

                    for j in (i + N / 2)..(i + N) {
                        let item = *map.get_unchecked(j);
                        if item > *hist.get_unchecked(j) {
                            novelties.push(j);
                        }
                    }
                }
            }
        }

        for j in (size - left)..size {
            unsafe {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    interesting = true;
                    novelties.push(j);
                }
            }
        }
    } else {
        for step in 0..steps {
            let i = step * N;
            let buf: [u8; N] = hist[i..i + N].try_into().unwrap();
            let history =
                VectorType::new(unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(buf) });
            let buf: [u8; N] = map[i..i + N].try_into().unwrap();
            let items = VectorType::new(unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(buf) });

            if items.max(history) != history {
                interesting = true;
                break;
            }
        }

        if !interesting {
            for j in (size - left)..size {
                unsafe {
                    let item = *map.get_unchecked(j);
                    if item > *hist.get_unchecked(j) {
                        interesting = true;
                        break;
                    }
                }
            }
        }
    }

    (interesting, novelties)
}

/// Coverage map insteresting naive implementation. Do not use it unless you have strong reasons to do.
#[must_use]
pub fn covmap_is_interesting_naive(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    let mut novelties = vec![];
    let mut interesting = false;
    let initial = 0;
    if collect_novelties {
        for (i, item) in map.iter().enumerate().filter(|(_, item)| **item != initial) {
            let existing = unsafe { *hist.get_unchecked(i) };
            let reduced = existing.max(*item);
            if existing != reduced {
                interesting = true;
                novelties.push(i);
            }
        }
    } else {
        for (i, item) in map.iter().enumerate().filter(|(_, item)| **item != initial) {
            let existing = unsafe { *hist.get_unchecked(i) };
            let reduced = existing.max(*item);
            if existing != reduced {
                interesting = true;
                break;
            }
        }
    }

    (interesting, novelties)
}

/// Standard coverage map instereting implementation. Use the fastest implementation by default.
#[must_use]
pub fn std_covmap_is_interesting(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    #[cfg(feature = "covmap_naive")]
    let ret = covmap_is_interesting_naive(hist, map, collect_novelties);

    #[cfg(feature = "covmap_wide128")]
    let ret = covmap_is_interesting_u8x16(hist, map, collect_novelties);

    #[cfg(feature = "covmap_wide256")]
    let ret = covmap_is_interesting_u32x4(hist, map, collect_novelties);

    #[cfg(feature = "covmap_stdsimd")]
    let ret = covmap_is_interesting_stdsimd(hist, map, collect_novelties);

    #[cfg(not(any(
        feature = "covmap_naive",
        feature = "covmap_wide128",
        feature = "covmap_wide256",
        feature = "covmap_stdsimd"
    )))]
    let ret = covmap_is_interesting_naive(hist, map, collect_novelties);

    ret
}
