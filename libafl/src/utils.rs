//! Utility functions for AFL

use core::{cell::RefCell, debug_assert, fmt::Debug, time};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64_with_seed;

#[cfg(unix)]
use libc::pid_t;
#[cfg(unix)]
use std::ffi::CString;

use crate::Error;

#[cfg(feature = "std")]
use std::{
    env,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub trait AsSlice<T> {
    /// Convert to a slice
    fn as_slice(&self) -> &[T];
}

pub type StdRand = RomuTrioRand;

/// Ways to get random around here
/// Please note that these are not cryptographically secure
/// Or, even if some might be by accident, at least they are not seeded in a cryptographically secure fashion.
pub trait Rand: Debug + Serialize + DeserializeOwned {
    /// Sets the seed of this Rand
    fn set_seed(&mut self, seed: u64);

    /// Gets the next 64 bit value
    fn next(&mut self) -> u64;

    /// Gets a value below the given 64 bit val (inclusive)
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
}

/// Has a Rand field, that can be used to get random values
pub trait HasRand<R>
where
    R: Rand,
{
    /// Get the hold RefCell Rand instance
    fn rand(&self) -> &RefCell<R>;

    /// Gets the next 64 bit value
    fn rand_next(&mut self) -> u64 {
        self.rand().borrow_mut().next()
    }
    /// Gets a value below the given 64 bit val (inclusive)
    fn rand_below(&mut self, upper_bound_excl: u64) -> u64 {
        self.rand().borrow_mut().below(upper_bound_excl)
    }

    /// Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn rand_between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        self.rand()
            .borrow_mut()
            .between(lower_bound_incl, upper_bound_incl)
    }
}

// helper macro for deriving Default
macro_rules! default_rand {
    ($rand: ty) => {
        /// A default RNG will usually produce a nondeterministic stream of random numbers.
        /// As we do not have any way to get random seeds for no_std, they have to be reproducible there.
        /// Use [`RandomSeed::with_seed`] to generate a reproducible RNG.
        impl core::default::Default for $rand {
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
    fn new() -> Self;
}

// helper macro to impl RandomSeed
macro_rules! impl_randomseed {
    ($rand: ty) => {
        #[cfg(feature = "std")]
        impl RandomSeed for $rand {
            /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
            fn new() -> Self {
                Self::with_seed(current_nanos())
            }
        }
    };
}

impl_randomseed!(Xoshiro256StarRand);
impl_randomseed!(XorShift64Rand);
impl_randomseed!(Lehmer64Rand);
impl_randomseed!(RomuTrioRand);
impl_randomseed!(RomuDuoJrRand);

const HASH_CONST: u64 = 0xa5b35705;

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

#[cfg(feature = "std")]
/// Gets current milliseconds since UNIX_EPOCH
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

        ret
    }
}

impl Xoshiro256StarRand {
    /// Creates a new Xoshiro rand with the given seed
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
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = (seed as u128) ^ 0x1234567890abcdef;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        self.rand_seed *= 0xda942042e4dd58b5;
        (self.rand_seed >> 64) as u64
    }
}

impl Lehmer64Rand {
    /// Creates a new Lehmer rand with the given seed
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
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuDuoJrRand {
    x_state: u64,
    y_state: u64,
}

impl RomuDuoJrRand {
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
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        self.x_state = 15241094284759029579u64.wrapping_mul(self.y_state);
        self.y_state = self.y_state.wrapping_sub(xp).rotate_left(27);
        xp
    }
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

/// A test rng that will return the same value (chose by fair dice roll) for testing.
#[cfg(test)]
impl XKCDRand {
    pub fn new() -> Self {
        Self::with_seed(4)
    }

    pub fn with_seed(seed: u64) -> Self {
        Self { val: seed }
    }
}

/// Child Process Handle
#[cfg(unix)]
pub struct ChildHandle {
    pid: pid_t,
}

#[cfg(unix)]
impl ChildHandle {
    /// Block until the child exited and the status code becomes available
    pub fn status(&self) -> i32 {
        let mut status = -1;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        status
    }
}

#[cfg(unix)]
/// The ForkResult
pub enum ForkResult {
    Parent(ChildHandle),
    Child,
}

/// Unix has forks.
/// # Safety
/// A Normal fork. Runs on in two processes. Should be memory safe in general.
#[cfg(unix)]
pub unsafe fn fork() -> Result<ForkResult, Error> {
    match libc::fork() {
        pid if pid > 0 => Ok(ForkResult::Parent(ChildHandle { pid })),
        pid if pid < 0 => {
            // Getting errno from rust is hard, we'll just let the libc print to stderr for now.
            // In any case, this should usually not happen.
            libc::perror(CString::new("Fork failed").unwrap().as_ptr());
            Err(Error::Unknown(format!("Fork failed ({})", pid)))
        }
        _ => Ok(ForkResult::Child),
    }
}

/// Executes the current process from the beginning, as subprocess.
/// use `start_self.status()?` to wait for the child
#[cfg(feature = "std")]
pub fn startable_self() -> Result<Command, Error> {
    let mut startable = Command::new(env::current_exe()?);
    startable.current_dir(env::current_dir()?).args(env::args());
    Ok(startable)
}

#[cfg(test)]
mod tests {
    //use xxhash_rust::xxh3::xxh3_64_with_seed;

    use crate::utils::{Rand, *};

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
        test_single_rand(&mut Xoshiro256StarRand::with_seed(0));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_random_seed() {
        use crate::utils::RandomSeed;

        let mut rand_fixed = StdRand::with_seed(0);
        let mut rand = StdRand::new();

        // The seed should be reasonably random so these never fail
        assert_ne!(rand.next(), rand_fixed.next());
        test_single_rand(&mut rand);
    }
}
