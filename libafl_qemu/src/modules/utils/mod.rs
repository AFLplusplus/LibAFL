pub mod filters;

/// Fast hash function for 64 bits integers minimizing collisions.
/// Adapted from <https://xorshift.di.unimi.it/splitmix64.c>
#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x ^ (x.overflowing_shr(30).0))
        .overflowing_mul(0xbf58476d1ce4e5b9)
        .0;
    x = (x ^ (x.overflowing_shr(27).0))
        .overflowing_mul(0x94d049bb133111eb)
        .0;
    x ^ (x.overflowing_shr(31).0)
}
