//! The random number generators of `LibAFL`
use core::{debug_assert, fmt::Debug};

#[cfg(feature = "rand_trait")]
use rand_core::{impls::fill_bytes_via_next, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::current_nanos;
#[cfg(any(feature = "xxh3", feature = "alloc"))]
use crate::hash_std;

/// The standard rand implementation for `LibAFL`.
/// It is usually the right choice, with very good speed and a reasonable randomness.
/// Not cryptographically secure (which is not what you want during fuzzing ;) )
pub type StdRand = RomuDuoJrRand;

/// Ways to get random around here.
/// Please note that these are not cryptographically secure.
/// Or, even if some might be by accident, at least they are not seeded in a cryptographically secure fashion.
pub trait Rand: Debug + Serialize + DeserializeOwned {
    /// Sets the seed of this Rand
    fn set_seed(&mut self, seed: u64);

    /// Gets the next 64 bit value
    fn next(&mut self) -> u64;

    /// Gets a value below the given 64 bit val (exclusive)
    fn below(&mut self, upper_bound_excl: u64) -> u64 {
        if upper_bound_excl <= 1 {
            return 0;
        }

        /*
        Modulo is biased - we don't want our fuzzing to be biased so let's do it
        right. See
        https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
        */
        let mut unbiased_rnd: u64;
        loop {
            unbiased_rnd = self.next();
            if unbiased_rnd < (u64::MAX - (u64::MAX % upper_bound_excl)) {
                break;
            }
        }

        unbiased_rnd % upper_bound_excl
    }

    /// Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        debug_assert!(lower_bound_incl <= upper_bound_incl);
        lower_bound_incl + self.below(upper_bound_incl - lower_bound_incl + 1)
    }

    /// Choose an item at random from the given iterator, sampling uniformly.
    ///
    /// Note: the runtime cost is bound by the iterator's [`nth`][`Iterator::nth`] implementation
    ///  * For `Vec`, slice, array, this is O(1)
    ///  * For `HashMap`, `HashSet`, this is O(n)
    fn choose<I, E, T>(&mut self, from: I) -> T
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
    {
        // create iterator
        let mut iter = from.into_iter();

        // make sure there is something to choose from
        debug_assert!(iter.len() > 0, "choosing from an empty iterator");

        // pick a random, valid index
        let index = self.below(iter.len() as u64) as usize;

        // return the item chosen
        iter.nth(index).unwrap()
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

// Derive Default by calling `new(DEFAULT_SEED)` on each of the following Rand types.
#[cfg(any(feature = "xxh3", feature = "alloc"))]
default_rand!(Xoshiro256StarRand);
default_rand!(XorShift64Rand);
default_rand!(Lehmer64Rand);
default_rand!(RomuTrioRand);
default_rand!(RomuDuoJrRand);

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

#[cfg(any(feature = "xxh3", feature = "alloc"))]
impl_random!(Xoshiro256StarRand);
impl_random!(XorShift64Rand);
impl_random!(Lehmer64Rand);
impl_random!(RomuTrioRand);
impl_random!(RomuDuoJrRand);

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Xoshiro256StarRand {
    rand_seed: [u64; 4],
}

// TODO: re-enable ahash works without alloc
#[cfg(any(feature = "xxh3", feature = "alloc"))]
impl Rand for Xoshiro256StarRand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed[0] = hash_std(&seed.to_be_bytes());
        self.rand_seed[1] = self.rand_seed[0] ^ 0x1234567890abcdef;
        self.rand_seed[2] = self.rand_seed[0] & 0x0123456789abcdef;
        self.rand_seed[3] = self.rand_seed[0] | 0x01abcde43f567908;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let ret: u64 = self.rand_seed[0]
            .wrapping_add(self.rand_seed[3])
            .rotate_left(23)
            .wrapping_add(self.rand_seed[0]);
        let t: u64 = self.rand_seed[1] << 17;

        self.rand_seed[2] ^= self.rand_seed[0];
        self.rand_seed[3] ^= self.rand_seed[1];
        self.rand_seed[1] ^= self.rand_seed[2];
        self.rand_seed[0] ^= self.rand_seed[3];

        self.rand_seed[2] ^= t;

        self.rand_seed[3] = self.rand_seed[3].rotate_left(45);

        ret
    }
}

#[cfg(any(feature = "xxh3", feature = "alloc"))]
impl Xoshiro256StarRand {
    /// Creates a new Xoshiro rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self { rand_seed: [0; 4] };
        rand.set_seed(seed); // TODO: Proper random seed?
        rand
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct XorShift64Rand {
    rand_seed: u64,
}

impl Rand for XorShift64Rand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = seed ^ 0x1234567890abcdef;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.rand_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rand_seed = x;
        x
    }
}

impl XorShift64Rand {
    /// Creates a new Xoshiro rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { rand_seed: 0 };
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Lehmer64Rand {
    rand_seed: u128,
}

impl Rand for Lehmer64Rand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = u128::from(seed) ^ 0x1234567890abcdef;
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        self.rand_seed *= 0xda942042e4dd58b5;
        (self.rand_seed >> 64) as u64
    }
}

impl Lehmer64Rand {
    /// Creates a new Lehmer rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { rand_seed: 0 };
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
    fn set_seed(&mut self, seed: u64) {
        self.x_state = seed ^ 0x12345;
        self.y_state = seed ^ 0x6789A;
        self.z_state = seed ^ 0xBCDEF;
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
    fn set_seed(&mut self, seed: u64) {
        self.x_state = seed ^ 0x12345;
        self.y_state = seed ^ 0x6789A;
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

/// fake rand, for testing purposes
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct XkcdRand {
    val: u64,
}

impl Rand for XkcdRand {
    fn set_seed(&mut self, val: u64) {
        self.val = val;
    }

    fn next(&mut self) -> u64 {
        self.val
    }
}

/// A test rng that will return the same value (chose by fair dice roll) for testing.
impl XkcdRand {
    /// Creates a new [`XkcdRand`] with the rand of 4, [chosen by fair dice roll, guaranteed to be random](https://xkcd.com/221/).
    /// Will always return this seed.
    #[must_use]
    pub fn new() -> Self {
        Self::with_seed(4)
    }

    /// Creates a new [`XkcdRand`] with the given seed. Will always return this seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self { val: seed }
    }
}

#[cfg(test)]
mod tests {
    //use xxhash_rust::xxh3::xxh3_64_with_seed;

    #[cfg(any(feature = "xxh3", feature = "alloc"))]
    use crate::rands::Xoshiro256StarRand;
    use crate::rands::{Rand, RomuDuoJrRand, RomuTrioRand, StdRand, XorShift64Rand};

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
        #[cfg(any(feature = "xxh3", feature = "alloc"))]
        test_single_rand(&mut Xoshiro256StarRand::with_seed(0));
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
