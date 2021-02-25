//! Utility functions for AFL

use core::{cell::RefCell, debug_assert, default::Default, fmt::Debug, time};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64_with_seed;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

pub type StdRand = RomuTrioRand;

/// Ways to get random around here
pub trait Rand: Debug + Serialize + DeserializeOwned {
    // Sets the seed of this Rand
    fn set_seed(&mut self, seed: u64);

    // Gets the next 64 bit value
    fn next(&mut self) -> u64;

    // Gets a value below the given 64 bit val (inclusive)
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

    // Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        debug_assert!(lower_bound_incl <= upper_bound_incl);
        lower_bound_incl + self.below(upper_bound_incl - lower_bound_incl + 1)
    }
}

/// Has a Rand field, that can be used to get random values
pub trait HasRand<R>
where
    R: Rand,
{
    /// Get the hold RefCell Rand instance
    fn rand(&self) -> &RefCell<R>;

    // Gets the next 64 bit value
    fn rand_next(&mut self) -> u64 {
        self.rand().borrow_mut().next()
    }
    // Gets a value below the given 64 bit val (inclusive)
    fn rand_below(&mut self, upper_bound_excl: u64) -> u64 {
        self.rand().borrow_mut().below(upper_bound_excl)
    }

    // Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn rand_between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        self.rand()
            .borrow_mut()
            .between(lower_bound_incl, upper_bound_incl)
    }
}

#[cfg(feature = "std")]
mod random_seed {
    use super::*;

    pub trait RandomSeed: Rand + Default {
        /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
        /// Needs stdlib timer
        fn with_random_seed() -> Self {
            let mut rng = Self::default();
            rng.set_seed(current_nanos());
            rng
        }
    }

    impl RandomSeed for Xoshiro256StarRand {}
    impl RandomSeed for XorShift64Rand {}
    impl RandomSeed for Lehmer64Rand {}
    impl RandomSeed for RomuTrioRand {}
    impl RandomSeed for RomuDuoJrRand {}
}

#[cfg(feature = "std")]
pub use random_seed::*;

const HASH_CONST: u64 = 0xa5b35705;
const DEFAULT_SEED: u64 = 0x54d3a3130133750b;

/// Current time
#[cfg(feature = "std")]
#[inline]
pub fn current_time() -> time::Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}
/// Current time (fixed fallback for no_std)
#[cfg(not(feature = "std"))]
#[inline]
pub fn current_time() -> time::Duration {
    // We may not have a rt clock available.
    // TODO: Make it somehow plugin-able
    time::Duration::from_millis(1)
}

#[cfg(feature = "std")]
#[inline]
/// Gets current nanoseconds since UNIX_EPOCH
pub fn current_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Xoshiro256StarRand {
    rand_seed: [u64; 4],
}

impl Rand for Xoshiro256StarRand {
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed[0] = xxh3_64_with_seed(&HASH_CONST.to_le_bytes(), seed);
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

        return ret;
    }
}

impl Default for Xoshiro256StarRand {
    fn default() -> Self {
        let mut xoshiro = Self { rand_seed: [0; 4] };
        xoshiro.set_seed(DEFAULT_SEED);
        xoshiro
    }
}

impl Xoshiro256StarRand {
    /// Creates a new Xoshiro rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
///
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct XorShift64Rand {
    rand_seed: u64,
}

impl Rand for XorShift64Rand {
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
        return x;
    }
}

impl Default for XorShift64Rand {
    fn default() -> Self {
        Self {
            rand_seed: DEFAULT_SEED,
        }
    }
}

impl XorShift64Rand {
    /// Creates a new Xoshiro rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
///
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Lehmer64Rand {
    rand_seed: u128,
}

impl Rand for Lehmer64Rand {
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = (seed as u128) ^ 0x1234567890abcdef;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        self.rand_seed *= 0xda942042e4dd58b5;
        return (self.rand_seed >> 64) as u64;
    }
}

impl Default for Lehmer64Rand {
    fn default() -> Self {
        let mut lehmer = Self {
            rand_seed: DEFAULT_SEED as u128,
        };

        // warm up the rng so the 64-bit DEFAULT_SEED can expand to fill 128 bits
        for _ in 0..16 {
            lehmer.next();
        }

        lehmer
    }
}

impl Lehmer64Rand {
    /// Creates a new Lehmer rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
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
    pub fn new(seed: u64) -> Self {
        let mut rand = Self::default();
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
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        let yp = self.y_state;
        let zp = self.z_state;
        self.x_state = 15241094284759029579u64.wrapping_mul(zp);
        self.y_state = yp.wrapping_sub(xp).rotate_left(12);
        self.z_state = zp.wrapping_sub(yp).rotate_left(44);
        xp
    }
}

/// see <https://arxiv.org/pdf/2002.11331.pdf>
impl Default for RomuTrioRand {
    fn default() -> Self {
        let mut romutrio = Self {
            x_state: 0,
            y_state: 0,
            z_state: 0,
        };
        romutrio.set_seed(DEFAULT_SEED);
        romutrio
    }
}

/// see https://arxiv.org/pdf/2002.11331.pdf
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuDuoJrRand {
    x_state: u64,
    y_state: u64,
}

impl RomuDuoJrRand {
    pub fn new(seed: u64) -> Self {
        let mut rand = Self::default();
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
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        self.x_state = 15241094284759029579u64.wrapping_mul(self.y_state);
        self.y_state = self.y_state.wrapping_sub(xp).rotate_left(27);
        xp
    }
}

impl Default for RomuDuoJrRand {
    fn default() -> Self {
        let mut romuduo = Self {
            x_state: 0,
            y_state: 0,
        };
        romuduo.set_seed(DEFAULT_SEED);
        romuduo
    }
}

#[cfg(feature = "std")]
pub fn current_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(not(feature = "std"))]
pub fn current_milliseconds() -> u64 {
    1000
}

/// fake rand, for testing purposes
#[cfg(test)]
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct XKCDRand {
    val: u64,
}

#[cfg(test)]
impl Rand for XKCDRand {
    fn set_seed(&mut self, val: u64) {
        self.val = val
    }

    fn next(&mut self) -> u64 {
        self.val
    }
}

#[cfg(test)]
impl XKCDRand {
    pub fn new() -> Self {
        Self { val: 4 }
    }
}

#[cfg(test)]
mod tests {
    //use xxhash_rust::xxh3::xxh3_64_with_seed;

    use crate::utils::{Rand, StdRand, RandomSeed};

    #[test]
    fn test_rand() {
        let mut rand = StdRand::new(0);
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_rand_with_random_seed() {
        let mut rand_fixed = StdRand::new(0);
        let mut rand = StdRand::with_random_seed();
        assert_ne!(rand.next(), rand_fixed.next());
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }
}
