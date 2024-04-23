//! The random number generators of `LibAFL`
use core::{debug_assert, fmt::Debug};

#[cfg(feature = "rand_trait")]
use rand_core::{impls::fill_bytes_via_next, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::current_nanos;

/// The standard rand implementation for `LibAFL`.
/// It is usually the right choice, with very good speed and a reasonable randomness.
/// Not cryptographically secure (which is not what you want during fuzzing ;) )
pub type StdRand = RomuDuoJrRand;

/// Choose an item at random from the given iterator, sampling uniformly.
///
/// Note: the runtime cost is bound by the iterator's [`nth`][`Iterator::nth`] implementation
///  * For `Vec`, slice, array, this is O(1)
///  * For `HashMap`, `HashSet`, this is O(n)
pub fn choose<I>(from: I, rand: u64) -> I::Item
where
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
{
    // create iterator
    let mut iter = from.into_iter();

    // make sure there is something to choose from
    debug_assert!(iter.len() > 0, "choosing from an empty iterator");

    // pick a random, valid index
    let index = fast_bound(rand, iter.len() as u64) as usize;

    // return the item chosen
    iter.nth(index).unwrap()
}

/// Faster and almost unbiased alternative to `rand % n`.
///
/// For N-bit bound, probability of getting a biased value is 1/2^(64-N).
/// At least 2^2*(64-N) samples are required to detect this amount of bias.
///
/// See: [An optimal algorithm for bounded random integers](https://github.com/apple/swift/pull/39143).
#[inline]
#[must_use]
pub fn fast_bound(rand: u64, n: u64) -> u64 {
    debug_assert_ne!(n, 0);
    let mul = u128::from(rand).wrapping_mul(u128::from(n));
    (mul >> 64) as u64
}

/// Ways to get random around here.
/// Please note that these are not cryptographically secure.
/// Or, even if some might be by accident, at least they are not seeded in a cryptographically secure fashion.
pub trait Rand: Debug + Serialize + DeserializeOwned {
    /// Sets the seed of this Rand
    fn set_seed(&mut self, seed: u64);

    /// Gets the next 64 bit value
    fn next(&mut self) -> u64;

    /// Gets a value between 0.0 (inclusive) and 1.0 (exclusive)
    #[inline]
    #[allow(clippy::cast_precision_loss)]
    fn next_float(&mut self) -> f64 {
        // both 2^53 and 2^-53 can be represented in f64 exactly
        const MAX: u64 = 1u64 << 53;
        const MAX_DIV: f64 = 1.0 / (MAX as f64);
        let u = self.next() & MAX.wrapping_sub(1);
        u as f64 * MAX_DIV
    }

    /// Returns true with specified probability
    #[inline]
    fn coinflip(&mut self, success_prob: f64) -> bool {
        debug_assert!((0.0..=1.0).contains(&success_prob));
        self.next_float() < success_prob
    }

    /// Gets a value below the given 64 bit val (exclusive)
    #[inline]
    fn below(&mut self, upper_bound_excl: u64) -> u64 {
        fast_bound(self.next(), upper_bound_excl)
    }

    /// Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    #[inline]
    fn between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        debug_assert!(lower_bound_incl <= upper_bound_incl);
        lower_bound_incl + self.below(upper_bound_incl - lower_bound_incl + 1)
    }

    /// Convenient variant of [`choose`].
    fn choose<I>(&mut self, from: I) -> I::Item
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
    {
        choose(from, self.next())
    }
}

// helper macro for deriving Default
macro_rules! default_rand {
    ($rand: ty) => {
        /// A default RNG will usually produce a nondeterministic stream of random numbers.
        /// As we do not have any way to get random seeds for `no_std`, they have to be reproducible there.
        /// Use [`$rand::with_seed`] to generate a reproducible RNG.
        impl Default for $rand {
            #[cfg(feature = "std")]
            fn default() -> Self {
                Self::new()
            }
            #[cfg(not(feature = "std"))]
            fn default() -> Self {
                Self::with_seed(0xAF1)
            }
        }
    };
}

// https://prng.di.unimi.it/splitmix64.c
fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

// Derive Default by calling `new(DEFAULT_SEED)` on each of the following Rand types.
default_rand!(Xoshiro256PlusPlusRand);
default_rand!(XorShift64Rand);
default_rand!(Lehmer64Rand);
default_rand!(RomuTrioRand);
default_rand!(RomuDuoJrRand);
default_rand!(Sfc64Rand);

/// Initialize Rand types from a source of randomness.
///
/// Default implementations are provided with the "std" feature enabled, using system time in
/// nanoseconds as the initial seed.
pub trait RandomSeed: Rand + Default {
    /// Creates a new [`RandomSeed`].
    fn new() -> Self;
}

// helper macro to impl RandomSeed
macro_rules! impl_random {
    ($rand: ty) => {
        #[cfg(feature = "std")]
        impl RandomSeed for $rand {
            /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
            fn new() -> Self {
                Self::with_seed(current_nanos())
            }
        }

        #[cfg(feature = "rand_trait")]
        impl RngCore for $rand {
            fn next_u32(&mut self) -> u32 {
                self.next() as u32
            }

            fn next_u64(&mut self) -> u64 {
                self.next()
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                fill_bytes_via_next(self, dest)
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                Ok(self.fill_bytes(dest))
            }
        }
    };
}

impl_random!(Xoshiro256PlusPlusRand);
impl_random!(XorShift64Rand);
impl_random!(Lehmer64Rand);
impl_random!(RomuTrioRand);
impl_random!(RomuDuoJrRand);
impl_random!(Sfc64Rand);

/// xoshiro256++ PRNG: <https://prng.di.unimi.it/>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Xoshiro256PlusPlusRand {
    s: [u64; 4],
}

impl Rand for Xoshiro256PlusPlusRand {
    fn set_seed(&mut self, mut seed: u64) {
        self.s[0] = splitmix64(&mut seed);
        self.s[1] = splitmix64(&mut seed);
        self.s[2] = splitmix64(&mut seed);
        self.s[3] = splitmix64(&mut seed);
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let ret: u64 = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t: u64 = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];

        self.s[2] ^= t;

        self.s[3] = self.s[3].rotate_left(45);

        ret
    }
}

impl Xoshiro256PlusPlusRand {
    /// Creates a new xoshiro256++ rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self { s: [0; 4] };
        rand.set_seed(seed);
        rand
    }
}

/// Xorshift64 PRNG
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct XorShift64Rand {
    s: u64,
}

impl Rand for XorShift64Rand {
    fn set_seed(&mut self, mut seed: u64) {
        self.s = splitmix64(&mut seed) | 1;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.s = x;
        x
    }
}

impl XorShift64Rand {
    /// Creates a new xorshift64 rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { s: 0 };
        ret.set_seed(seed);
        ret
    }
}

/// Lehmer64 PRNG
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Lehmer64Rand {
    s: u128,
}

impl Rand for Lehmer64Rand {
    fn set_seed(&mut self, mut seed: u64) {
        let hi = splitmix64(&mut seed);
        let lo = splitmix64(&mut seed) | 1;
        self.s = u128::from(hi) << 64 | u128::from(lo);
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        self.s *= 0xda942042e4dd58b5;
        (self.s >> 64) as u64
    }
}

impl Lehmer64Rand {
    /// Creates a new Lehmer rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { s: 0 };
        ret.set_seed(seed);
        ret
    }
}

/// Extremely quick rand implementation
/// see <https://arxiv.org/pdf/2002.11331.pdf>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuTrioRand {
    x_state: u64,
    y_state: u64,
    z_state: u64,
}

impl RomuTrioRand {
    /// Creates a new `RomuTrioRand` with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self {
            x_state: 0,
            y_state: 0,
            z_state: 0,
        };
        rand.set_seed(seed);
        rand
    }
}

impl Rand for RomuTrioRand {
    fn set_seed(&mut self, mut seed: u64) {
        self.x_state = splitmix64(&mut seed);
        self.y_state = splitmix64(&mut seed);
        self.z_state = splitmix64(&mut seed);
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        let yp = self.y_state;
        let zp = self.z_state;
        self.x_state = 15241094284759029579_u64.wrapping_mul(zp);
        self.y_state = yp.wrapping_sub(xp).rotate_left(12);
        self.z_state = zp.wrapping_sub(yp).rotate_left(44);
        xp
    }
}

/// see <https://arxiv.org/pdf/2002.11331.pdf>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuDuoJrRand {
    x_state: u64,
    y_state: u64,
}

impl RomuDuoJrRand {
    /// Creates a new `RomuDuoJrRand` with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self {
            x_state: 0,
            y_state: 0,
        };
        rand.set_seed(seed);
        rand
    }
}

impl Rand for RomuDuoJrRand {
    fn set_seed(&mut self, mut seed: u64) {
        self.x_state = splitmix64(&mut seed);
        self.y_state = splitmix64(&mut seed);
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        self.x_state = 15241094284759029579_u64.wrapping_mul(self.y_state);
        self.y_state = self.y_state.wrapping_sub(xp).rotate_left(27);
        xp
    }
}

/// [SFC64][1] algorithm by Chris Doty-Humphrey.
///
/// [1]: https://numpy.org/doc/stable/reference/random/bit_generators/sfc64.html
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Sfc64Rand {
    a: u64,
    b: u64,
    c: u64,
    w: u64,
}

impl Sfc64Rand {
    /// Creates a new [`Sfc64Rand`] with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut s = Sfc64Rand {
            a: 0,
            b: 0,
            c: 0,
            w: 0,
        };
        s.set_seed(seed);
        s
    }
}

impl Rand for Sfc64Rand {
    fn set_seed(&mut self, seed: u64) {
        self.a = seed;
        self.b = seed;
        self.c = seed;
        self.w = 1;
        for _ in 0..12 {
            self.next();
        }
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let out = self.a.wrapping_add(self.b).wrapping_add(self.w);
        self.w = self.w.wrapping_add(1);
        self.a = self.b ^ (self.b >> 11);
        self.b = self.c.wrapping_add(self.c << 3);
        self.c = self.c.rotate_left(24).wrapping_add(out);
        out
    }
}

/// fake rand, for testing purposes
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct XkcdRand {
    val: u64,
}

impl Rand for XkcdRand {
    fn set_seed(&mut self, mut seed: u64) {
        self.val = splitmix64(&mut seed);
    }

    fn next(&mut self) -> u64 {
        self.val
    }
}

/// A test rng that will return the same value (chose by fair dice roll) for testing.
impl XkcdRand {
    /// Creates a new [`XkcdRand`] with the rand of 4, [chosen by fair dice roll, guaranteed to be random](https://xkcd.com/221/).
    #[must_use]
    pub fn new() -> Self {
        Self { val: 4 }
    }

    /// Creates a new [`XkcdRand`] with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = XkcdRand { val: 0 };
        rand.set_seed(seed);
        rand
    }
}

#[cfg(test)]
mod tests {
    use crate::rands::{
        Rand, RomuDuoJrRand, RomuTrioRand, Sfc64Rand, StdRand, XorShift64Rand,
        Xoshiro256PlusPlusRand,
    };

    fn test_single_rand<R: Rand>(rand: &mut R) {
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }

    #[test]
    fn test_rands() {
        // see cargo bench for speed comparisons
        test_single_rand(&mut StdRand::with_seed(0));
        test_single_rand(&mut RomuTrioRand::with_seed(0));
        test_single_rand(&mut RomuDuoJrRand::with_seed(0));
        test_single_rand(&mut XorShift64Rand::with_seed(0));
        test_single_rand(&mut Xoshiro256PlusPlusRand::with_seed(0));
        test_single_rand(&mut Sfc64Rand::with_seed(0));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_random_seed() {
        use crate::rands::RandomSeed;

        let mut rand_fixed = StdRand::with_seed(0);
        let mut rand = StdRand::new();

        // The seed should be reasonably random so these never fail
        assert_ne!(rand.next(), rand_fixed.next());
        test_single_rand(&mut rand);
    }

    #[test]
    #[cfg(feature = "rand_trait")]
    fn test_rgn_core_support() {
        use rand_core::RngCore;

        use crate::rands::StdRand;
        pub struct Mutator<R: RngCore> {
            rng: R,
        }

        let mut mutator = Mutator {
            rng: StdRand::with_seed(0),
        };

        log::info!("random value: {}", mutator.rng.next_u32());
    }

    #[test]
    fn test_sfc64_golden_zig() {
        // https://github.com/ziglang/zig/blob/130fb5cb0fb9039e79450c9db58d6590c5bee3b3/lib/std/Random/Sfc64.zig#L73-L99
        let golden: [u64; 16] = [
            0x3acfa029e3cc6041,
            0xf5b6515bf2ee419c,
            0x1259635894a29b61,
            0xb6ae75395f8ebd6,
            0x225622285ce302e2,
            0x520d28611395cb21,
            0xdb909c818901599d,
            0x8ffd195365216f57,
            0xe8c4ad5e258ac04a,
            0x8f8ef2c89fdb63ca,
            0xf9865b01d98d8e2f,
            0x46555871a65d08ba,
            0x66868677c6298fcd,
            0x2ce15a7e6329f57d,
            0xb2f1833ca91ca79,
            0x4b0890ac9bf453ca,
        ];

        let mut s = Sfc64Rand::with_seed(0);
        for v in golden {
            let u = s.next();
            assert_eq!(v, u);
        }
    }
}

#[cfg(feature = "python")]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
#[allow(missing_docs)]
/// `Rand` Python bindings
pub mod pybind {
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use super::Rand;
    use crate::{current_nanos, rands::StdRand};

    #[pyclass(unsendable, name = "StdRand")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for StdRand
    pub struct PythonStdRand {
        /// Rust wrapped StdRand object
        pub inner: StdRand,
    }

    #[pymethods]
    impl PythonStdRand {
        #[staticmethod]
        fn with_current_nanos() -> Self {
            Self {
                inner: StdRand::with_seed(current_nanos()),
            }
        }

        #[staticmethod]
        fn with_seed(seed: u64) -> Self {
            Self {
                inner: StdRand::with_seed(seed),
            }
        }

        fn as_rand(slf: Py<Self>) -> PythonRand {
            PythonRand::new_std(slf)
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    enum PythonRandWrapper {
        Std(Py<PythonStdRand>),
    }

    /// Rand Trait binding
    #[pyclass(unsendable, name = "Rand")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PythonRand {
        wrapper: PythonRandWrapper,
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_mut_body!($wrapper, $name, $body, PythonRandWrapper, { Std })
        };
    }

    #[pymethods]
    impl PythonRand {
        #[staticmethod]
        fn new_std(py_std_rand: Py<PythonStdRand>) -> Self {
            Self {
                wrapper: PythonRandWrapper::Std(py_std_rand),
            }
        }
    }

    impl Rand for PythonRand {
        fn set_seed(&mut self, seed: u64) {
            unwrap_me_mut!(self.wrapper, r, { r.set_seed(seed) });
        }

        #[inline]
        fn next(&mut self) -> u64 {
            unwrap_me_mut!(self.wrapper, r, { r.next() })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdRand>()?;
        m.add_class::<PythonRand>()?;
        Ok(())
    }
}
