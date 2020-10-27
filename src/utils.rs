//! Utility functions for AFL

use std::debug_assert;
use std::fmt::Debug;
use xxhash_rust::xxh3::xxh3_64_with_seed;

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

impl Xoshiro256StarRand {
    pub fn new() -> Xoshiro256StarRand {
        let mut ret: Xoshiro256StarRand = Default::default();
        ret.set_seed(0); // TODO: Proper random seed?
        ret
    }
}

/// Get the next higher power of two
fn next_pow2(val: u64) -> u64 {
    // Early exit so we don't have to do a wrapping subtract;
    if val <= 2 {
        return val;
    }
    let mut out: u64 = val.wrapping_sub(1);
    out |= out >> 1;
    out |= out >> 2;
    out |= out >> 4;
    out |= out >> 8;
    out |= out >> 16;
    return out + 1;
}

#[cfg(test)]
mod tests {
    use crate::utils::{next_pow2, Rand, Xoshiro256StarRand};

    #[test]
    fn test_rand() {
        let mut rand = Xoshiro256StarRand::new();
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
    }
}
