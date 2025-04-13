//! Module for SIMD assisted methods.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};
use core::ops::{BitAnd, BitOr};

/// Re-export our vector types
#[cfg(feature = "wide")]
pub mod vector {
    pub use wide::{u8x16, u8x32};
}

/// The SIMD based reducer implementation
#[cfg(feature = "wide")]
pub trait SimdReducer<T>: Reducer<T> {
    /// The associated primitive reducer
    type PrimitiveReducer: Reducer<u8>;
}

/// A `Reducer` function is used to aggregate values for the novelty search
pub trait Reducer<T> {
    /// Reduce two values to one value, with the current [`Reducer`].
    fn reduce(first: T, second: T) -> T;
}

#[cfg(feature = "wide")]
trait HasMax: Sized {
    fn max_(self, rhs: Self) -> Self;
}

#[cfg(feature = "wide")]
impl HasMax for wide::u8x16 {
    fn max_(self, rhs: Self) -> Self {
        self.max(rhs)
    }
}

#[cfg(feature = "wide")]
impl HasMax for wide::u8x32 {
    fn max_(self, rhs: Self) -> Self {
        self.max(rhs)
    }
}

#[cfg(feature = "wide")]
trait HasMin: Sized {
    fn min_(self, rhs: Self) -> Self;
}

#[cfg(feature = "wide")]
impl HasMin for wide::u8x16 {
    fn min_(self, rhs: Self) -> Self {
        self.min(rhs)
    }
}

#[cfg(feature = "wide")]
impl HasMin for wide::u8x32 {
    fn min_(self, rhs: Self) -> Self {
        self.min(rhs)
    }
}

/// A [`MaxReducer`] reduces int values and returns their maximum.
#[derive(Clone, Debug)]
pub struct MaxReducer {}

impl<T> Reducer<T> for MaxReducer
where
    T: PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first > second { first } else { second }
    }
}

/// Unforunately we have to keep this type due to [`wide::*`] might not PartialOrd
#[cfg(feature = "wide")]
#[derive(Debug)]
pub struct SimdMaxReducer;

#[cfg(feature = "wide")]
impl<T> Reducer<T> for SimdMaxReducer
where
    T: HasMax,
{
    fn reduce(first: T, second: T) -> T {
        first.max_(second)
    }
}

#[cfg(feature = "wide")]
impl<T> SimdReducer<T> for SimdMaxReducer
where
    T: HasMax,
{
    type PrimitiveReducer = MaxReducer;
}

/// A [`NopReducer`] does nothing, and just "reduces" to the second/`new` value.
#[derive(Clone, Debug)]
pub struct NopReducer {}

impl<T> Reducer<T> for NopReducer {
    #[inline]
    fn reduce(_history: T, new: T) -> T {
        new
    }
}

#[cfg(feature = "wide")]
impl<T> SimdReducer<T> for NopReducer {
    type PrimitiveReducer = NopReducer;
}

/// A [`MinReducer`] reduces int values and returns their minimum.
#[derive(Clone, Debug)]
pub struct MinReducer {}

impl<T> Reducer<T> for MinReducer
where
    T: PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first < second { first } else { second }
    }
}

/// Unforunately we have to keep this type due to [`wide::*`] might not PartialOrd
#[cfg(feature = "wide")]
#[derive(Debug)]
pub struct SimdMinReducer;

#[cfg(feature = "wide")]
impl<T> Reducer<T> for SimdMinReducer
where
    T: HasMin,
{
    fn reduce(first: T, second: T) -> T {
        first.min_(second)
    }
}

#[cfg(feature = "wide")]
impl<T> SimdReducer<T> for SimdMinReducer
where
    T: HasMin,
{
    type PrimitiveReducer = MinReducer;
}

/// A [`OrReducer`] reduces the values returning the bitwise OR with the old value
#[derive(Clone, Debug)]
pub struct OrReducer {}

impl<T> Reducer<T> for OrReducer
where
    T: BitOr<Output = T>,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history | new
    }
}

#[cfg(feature = "wide")]
impl<T> SimdReducer<T> for OrReducer
where
    T: BitOr<Output = T>,
{
    type PrimitiveReducer = OrReducer;
}

/// SIMD based OrReducer, alias for consistency
#[cfg(feature = "wide")]
pub type SimdOrReducer = OrReducer;

/// A [`AndReducer`] reduces the values returning the bitwise AND with the old value
#[derive(Clone, Debug)]
pub struct AndReducer {}

impl<T> Reducer<T> for AndReducer
where
    T: BitAnd<Output = T>,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history & new
    }
}

#[cfg(feature = "wide")]
impl<T> SimdReducer<T> for AndReducer
where
    T: BitAnd<Output = T>,
{
    type PrimitiveReducer = AndReducer;
}

/// SIMD based AndReducer, alias for consistency
#[cfg(feature = "wide")]
pub type SimdAndReducer = AndReducer;

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

/// The vector type that can be used with coverage map
pub trait VectorType {
    /// Number of bytes
    const N: usize;

    /// Construct vector from slice
    fn from_array(arr: &[u8]) -> Self;

    /// Collect novelties. We pass in base to avoid redo calculate for novelties indice.
    fn novelties(hist: &[u8], map: &[u8], base: usize, novelties: &mut Vec<usize>);
}

impl VectorType for wide::u8x16 {
    const N: usize = Self::LANES as usize;

    fn from_array(arr: &[u8]) -> Self {
        Self::new(arr[0..Self::N].try_into().unwrap())
    }

    fn novelties(hist: &[u8], map: &[u8], base: usize, novelties: &mut Vec<usize>) {
        unsafe {
            for j in base..(base + Self::N) {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    novelties.push(j);
                }
            }
        }
    }
}

impl VectorType for wide::u8x32 {
    const N: usize = Self::LANES as usize;

    fn from_array(arr: &[u8]) -> Self {
        Self::new(arr[0..Self::N].try_into().unwrap())
    }

    fn novelties(hist: &[u8], map: &[u8], base: usize, novelties: &mut Vec<usize>) {
        unsafe {
            // Break into two loops so that LLVM will vectorize both loops.
            // Or LLVM won't vectorize them and is super slow. We need a few
            // extra intrinsic to wide and safe_arch to vectorize this manually.
            for j in base..(base + Self::N / 2) {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    novelties.push(j);
                }
            }

            for j in (base + Self::N / 2)..(base + Self::N) {
                let item = *map.get_unchecked(j);
                if item > *hist.get_unchecked(j) {
                    novelties.push(j);
                }
            }
        }
    }
}

/// Coverage map insteresting implementation by u8x16. Slightly faster than nightly simd.
#[cfg(all(feature = "alloc", feature = "wide"))]
#[must_use]
pub fn covmap_is_interesting_simd<R, V>(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>)
where
    V: VectorType + Eq + Copy,
    R: SimdReducer<V>,
{
    let mut novelties = vec![];
    let mut interesting = false;
    let size = map.len();
    let steps = size / V::N;
    let left = size % V::N;

    if collect_novelties {
        for step in 0..steps {
            let i = step * V::N;
            let history = V::from_array(&hist[i..]);
            let items = V::from_array(&map[i..]);

            let out = R::reduce(history, items);
            if out != history {
                interesting = true;
                V::novelties(hist, map, i, &mut novelties);
            }
        }

        for j in (size - left)..size {
            unsafe {
                let item = *map.get_unchecked(j);
                let history = *hist.get_unchecked(j);
                let out = R::PrimitiveReducer::reduce(item, history);
                if out != history {
                    interesting = true;
                    novelties.push(j);
                }
            }
        }
    } else {
        for step in 0..steps {
            let i = step * V::N;
            let history = V::from_array(&hist[i..]);
            let items = V::from_array(&map[i..]);

            let out = R::reduce(history, items);
            if out != history {
                interesting = true;
                break;
            }
        }

        if !interesting {
            for j in (size - left)..size {
                unsafe {
                    let item = *map.get_unchecked(j);
                    let history = *hist.get_unchecked(j);
                    let out = R::PrimitiveReducer::reduce(item, history);
                    if out != history {
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
pub fn covmap_is_interesting_naive<R>(
    hist: &[u8],
    map: &[u8],
    collect_novelties: bool,
) -> (bool, Vec<usize>)
where
    R: Reducer<u8>,
{
    let mut novelties = vec![];
    let mut interesting = false;
    let initial = 0;
    if collect_novelties {
        for (i, item) in map.iter().enumerate().filter(|(_, item)| **item != initial) {
            let existing = unsafe { *hist.get_unchecked(i) };
            let reduced = R::reduce(existing, *item);
            if existing != reduced {
                interesting = true;
                novelties.push(i);
            }
        }
    } else {
        for (i, item) in map.iter().enumerate().filter(|(_, item)| **item != initial) {
            let existing = unsafe { *hist.get_unchecked(i) };
            let reduced = R::reduce(existing, *item);
            if existing != reduced {
                interesting = true;
                break;
            }
        }
    }

    (interesting, novelties)
}
