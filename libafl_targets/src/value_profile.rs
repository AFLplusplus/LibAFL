//! Value profile support for `LibAFL`

use crate::CMP_MAP_SIZE;

/// The constant cmplog map for the current `LibAFL` target
#[unsafe(no_mangle)]
pub static mut libafl_cmp_map: [u8; CMP_MAP_SIZE] = [0; CMP_MAP_SIZE];

pub use libafl_cmp_map as CMP_MAP;

/*
extern {
    #[link_name = "llvm.returnaddress"]
    fn return_address() -> usize;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_cmp1(arg1: u8, arg2: u8) {
    let mut pos = return_address();
    pos = (pos >> 4) ^ (pos << 8);
    pos &= CMP_MAP_SIZE - 1;
    *CMP_MAP.get_unchecked_mut(pos) = core::cmp::max(*CMP_MAP.get_unchecked(pos), (!(arg1 ^ arg2)).count_ones() as u8);
}
*/

// TODO complete when linking to LLVM intrinsic will land to stable Rust
