//! Various utility functions

/// Given a value v, return a random number using this mixing function
/// Mixing function http://mostlymangling.blogspot.com/2018/07/on-mixing-functions-in-fast-splittable.html
#[inline]
pub fn rrxmrrxmsx_0(v: u64) -> u64 {
    let tmp = (v >> 32) + ((v & 0xffffffff) << 32);
    let bitflip = 0x1cad21f72c81017c ^ 0xdb979082e96dd4de;
    let mut h64 = tmp ^ bitflip;
    h64 = h64.rotate_left(49) & h64.rotate_left(24);
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^= (h64 >> 35) + 8;
    h64 = h64.wrapping_mul(0x9FB21C651E98DF25);
    h64 ^= h64 >> 28;
    h64
}
