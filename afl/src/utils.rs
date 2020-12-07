//! Utility functions for AFL

use alloc::rc::Rc;
use core::cell::RefCell;
use core::debug_assert;
use core::fmt::Debug;
use xxhash_rust::const_xxh3::xxh3_64_with_seed;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

pub type StdRand = Xoshiro256StarRand;

/// Ways to get random around here
pub trait Rand: Debug {
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

const HASH_CONST: u64 = 0xa5b35705;

/// XXH3 Based, hopefully speedy, rnd implementation
///
#[derive(Copy, Clone, Debug, Default)]
pub struct Xoshiro256StarRand {
    rand_seed: [u64; 4],
    seeded: bool,
}

impl Rand for Xoshiro256StarRand {
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed[0] = xxh3_64_with_seed(&HASH_CONST.to_le_bytes(), seed);
        self.rand_seed[1] = self.rand_seed[0] ^ 0x1234567890abcdef;
        self.rand_seed[2] = self.rand_seed[0] & 0x0123456789abcdef;
        self.rand_seed[3] = self.rand_seed[0] | 0x01abcde43f567908;

        self.seeded = true;
    }

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

impl Into<Rc<RefCell<Self>>> for Xoshiro256StarRand {
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

impl Xoshiro256StarRand {
    /// Creates a new Xoshiro rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }

    pub fn to_rc_refcell(self) -> Rc<RefCell<Self>> {
        self.into()
    }

    /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
    /// Needs stdlib timer
    #[cfg(feature = "std")]
    pub fn preseeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self::new(seed)
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
///
#[derive(Copy, Clone, Debug, Default)]
pub struct XorShift64Rand {
    rand_seed: u64,
    seeded: bool,
}

impl Rand for XorShift64Rand {
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = seed ^ 0x1234567890abcdef;
        self.seeded = true;
    }

    fn next(&mut self) -> u64 {
        let mut x = self.rand_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rand_seed = x;
        return x;
    }
}

impl Into<Rc<RefCell<Self>>> for XorShift64Rand {
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

impl XorShift64Rand {
    /// Creates a new Xoshiro rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }

    pub fn to_rc_refcell(self) -> Rc<RefCell<Self>> {
        self.into()
    }

    /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
    /// Needs stdlib timer
    #[cfg(feature = "std")]
    pub fn preseeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self::new(seed)
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
///
#[derive(Copy, Clone, Debug, Default)]
pub struct Lehmer64Rand {
    rand_seed: u128,
    seeded: bool,
}

impl Rand for Lehmer64Rand {
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = (seed as u128) ^ 0x1234567890abcdef;
        self.seeded = true;
    }

    fn next(&mut self) -> u64 {
        self.rand_seed *= 0xda942042e4dd58b5;
        return (self.rand_seed >> 64) as u64;
    }
}

impl Into<Rc<RefCell<Self>>> for Lehmer64Rand {
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

impl Lehmer64Rand {
    /// Creates a new Xoshiro rand with the given seed
    pub fn new(seed: u64) -> Self {
        let mut ret: Self = Default::default();
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }

    pub fn to_rc_refcell(self) -> Rc<RefCell<Self>> {
        self.into()
    }

    /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
    /// Needs stdlib timer
    #[cfg(feature = "std")]
    pub fn preseeded() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self::new(seed)
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
#[derive(Copy, Clone, Debug, Default)]
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
impl Into<Rc<RefCell<Self>>> for XKCDRand {
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

#[cfg(test)]
impl XKCDRand {
    pub fn new() -> Self {
        Self { val: 4 }
    }
}

/// Get the next higher power of two
pub const fn next_pow2(val: u64) -> u64 {
    let mut out = val.wrapping_sub(1);
    out |= out >> 1;
    out |= out >> 2;
    out |= out >> 4;
    out |= out >> 8;
    out |= out >> 16;
    out.wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use xxhash_rust::xxh3::xxh3_64_with_seed;

    use crate::utils::{next_pow2, Rand, StdRand};

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
    fn test_rand_preseeded() {
        let mut rand_fixed = StdRand::new(0);
        let mut rand = StdRand::preseeded();
        assert_ne!(rand.next(), rand_fixed.next());
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(0), 0);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(1000), 1024);
        assert_eq!(next_pow2(0xFFFFFFFF as u64), (0xFFFFFFFF as u64) + 1);
    }
}
