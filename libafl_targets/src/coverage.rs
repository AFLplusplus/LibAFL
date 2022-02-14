//! Coverage maps as static mut array

use crate::{ACCOUNTING_MAP_SIZE, EDGES_MAP_SIZE};
#[cfg(target_os = "linux")]
use libafl::{mutators::Tokens, Error};

/// The map for edges.
#[no_mangle]
pub static mut __afl_area_ptr_local: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
pub use __afl_area_ptr_local as EDGES_MAP;

/// The map for accounting mem writes.
#[no_mangle]
pub static mut __afl_acc_memop_ptr_local: [u32; ACCOUNTING_MAP_SIZE] = [0; ACCOUNTING_MAP_SIZE];
pub use __afl_acc_memop_ptr_local as ACCOUNTING_MEMOP_MAP;

/// The max count of edges tracked.
pub static mut MAX_EDGES_NUM: usize = 0;

extern "C" {
    /// The area pointer points to the edges map.
    pub static mut __afl_area_ptr: *mut u8;

    /// The area pointer points to the accounting mem operations map.
    pub static mut __afl_acc_memop_ptr: *mut u32;

    /// Start of libafl token section
    #[cfg(target_os = "linux")]
    pub static __token_start: *const u8;

    /// End of libafl token section
    #[cfg(target_os = "linux")]
    pub static __token_stop: *const u8;
}
pub use __afl_acc_memop_ptr as ACCOUNTING_MEMOP_MAP_PTR;
pub use __afl_area_ptr as EDGES_MAP_PTR;

/// Return Tokens from the compile-time token section
/// Will return `Error::IllegalState` if no token section was found
/// In this case, the compilation probably did not include an `AutoTokens`-pass
///
/// # Safety
///
/// This fn is safe to call, as long as the compilation did not break, previously
#[cfg(target_os = "linux")]
pub fn autotokens() -> Result<Tokens, Error> {
    unsafe {
        if __token_start.is_null() || __token_stop.is_null() {
            Err(Error::IllegalState(
                "AutoTokens section not found, likely the targe is not compiled with AutoTokens"
                    .into(),
            ))
        } else {
            // we can safely unwrap
            Tokens::from_ptrs(__token_start, __token_stop)
        }
    }
}

/// The size of the map for edges.
#[no_mangle]
pub static mut __afl_map_size: usize = EDGES_MAP_SIZE;
pub use __afl_map_size as EDGES_MAP_PTR_SIZE;
use libafl::bolts::ownedref::OwnedSliceMut;

/// Gets the edges map from the `EDGES_MAP_PTR` raw pointer.
///
/// # Safety
///
/// This function will crash if `EDGES_MAP_PTR` is not a valid pointer.
/// The `EDGES_MAP_PTR_SIZE` needs to be smaller than, or equal to the size of the map.
#[must_use]
pub unsafe fn edges_map_from_ptr<'a>() -> OwnedSliceMut<'a, u8> {
    debug_assert!(!EDGES_MAP_PTR.is_null());
    OwnedSliceMut::from_raw_parts_mut(EDGES_MAP_PTR, EDGES_MAP_PTR_SIZE)
}

/// Gets the current maximum number of edges tracked.
#[must_use]
pub fn edges_max_num() -> usize {
    unsafe {
        if MAX_EDGES_NUM > 0 {
            MAX_EDGES_NUM
        } else {
            #[cfg(feature = "pointer_maps")]
            {
                EDGES_MAP_PTR_SIZE
            }
            #[cfg(not(feature = "pointer_maps"))]
            {
                EDGES_MAP.len()
            }
        }
    }
}
