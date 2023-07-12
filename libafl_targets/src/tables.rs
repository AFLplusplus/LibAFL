//! Tables state transition pass runtime for `LibAFL`.

use crate::TABLES_MAP_SIZE;

/// Map with tables transitions
pub static mut TABLES_MAP: [u8; TABLES_MAP_SIZE] = [0; TABLES_MAP_SIZE];

fn merge_u32(a: u32, b: u32) -> u64 {
    (a as u64) << 32 + (b as u64)
}

/// From https://sair.synerise.com/efficient-integer-pairs-hashing/
fn splitmix64(target: u64, seed: u64) -> u64 {
    let sp_step = 0x9E3779B97F4A7C15_u64;
    let mut out = target;
    out = out + seed * sp_step;
    out ^= out >> 30;
    out *= 0xBF58476D1CE4E5B9_u64;
    out ^= out >> 27;
    out *= 0x94D049BB133111EB_u64;
    out ^= out >> 31;
    out
}

#[no_mangle]
/// Log tables transitions and insert them in the map
pub extern "C" fn __libafl_tables_transition(cur: u32, next: u32) {
    let hash = splitmix64(merge_u32(cur, next), 52) as usize % TABLES_MAP_SIZE;
    unsafe {
        TABLES_MAP[hash] += 1;
    }
}
