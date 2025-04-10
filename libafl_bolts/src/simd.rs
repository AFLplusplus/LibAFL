//! Module for SIMD assisted methods.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

/// `simplify_map` naive implementaion. In most cases, this can be auto-vectorized.
pub fn simplify_map_naive(map: &mut [u8]) {
    for it in map.iter_mut() {
        *it = if *it == 0 { 0x1 } else { 0x80 };
    }
}

/// `simplify_map` implementation by u8x16, worse performance compared to LLVM
/// auto-vectorization but faster if LLVM doesn't vectorize.
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

/// `simplify_map` implementation by i8x32, achieving comparable performance with
/// LLVM auto-vectorization.
#[cfg(feature = "wide")]
pub fn simplify_map_u8x32(map: &mut [u8]) {
    use wide::CmpEq;

    type VectorType = wide::u8x32;
    const N: usize = VectorType::LANES as usize;
    let size = map.len();
    let steps = size / N;
    let left = size % N;
    let lhs = VectorType::new([0x01; 32]);
    let rhs = VectorType::new([0x80; 32]);

    for step in 0..steps {
        let i = step * N;
        let mp = VectorType::new(map[i..i + N].try_into().unwrap());

        let mask = mp.cmp_eq(VectorType::ZERO);
        let out = mask.blend(lhs, rhs);
        unsafe {
            out.as_array_ref()
                .as_ptr()
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
    #[cfg(not(feature = "wide"))]
    simplify_map_naive(map);

    #[cfg(feature = "wide")]
    simplify_map_u8x32(map);
}

/// Coverage map insteresting implementation by u8x16. Slightly faster than nightly simd.
#[cfg(all(feature = "alloc", feature = "wide"))]
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

/// Coverage map insteresting implementation by u8x32. Slightly faster than nightly simd but slightly
/// slower than u8x16 version.
#[cfg(all(feature = "alloc", feature = "wide"))]
#[must_use]
pub fn covmap_is_interesting_u8x32(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    type VectorType = wide::u8x32;
    const N: usize = VectorType::LANES as usize;
    let mut novelties = vec![];
    let mut interesting = false;
    let size = map.len();
    let steps = size / N;
    let left = size % N;

    if collect_novelties {
        for step in 0..steps {
            let i = step * N;
            let history = VectorType::new(hist[i..i + N].try_into().unwrap());
            let items = VectorType::new(map[i..i + N].try_into().unwrap());

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
            let history = VectorType::new(hist[i..i + N].try_into().unwrap());
            let items = VectorType::new(map[i..i + N].try_into().unwrap());

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
#[cfg(feature = "alloc")]
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

/// Standard coverage map instereting implementation. Use the available fastest implementation by default.
#[cfg(feature = "alloc")]
#[allow(unused_variables)] // or we fail cargo doc
#[must_use]
pub fn std_covmap_is_interesting(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>) {
    #[cfg(not(feature = "wide"))]
    return covmap_is_interesting_naive(hist, map, collect_novelties);

    #[cfg(feature = "wide")]
    {
        // Supported by benchmark:
        // - on aarch64, u8x32 is 15% faster than u8x16
        // - on amd64, u8x16 is 10% faster compared to the u8x32
        #[cfg(target_arch = "aarch64")]
        return covmap_is_interesting_u8x32(hist, map, collect_novelties);

        #[cfg(not(target_arch = "aarch64"))]
        return covmap_is_interesting_u8x16(hist, map, collect_novelties);
    }
}
