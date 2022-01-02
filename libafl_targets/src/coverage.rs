//! Coverage maps as static mut array

use crate::EDGES_MAP_SIZE;
use core::slice::from_raw_parts_mut;

/// The map for edges.
#[no_mangle]
pub static mut __afl_area_ptr_local: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
pub use __afl_area_ptr_local as EDGES_MAP;

/// The max count of edges tracked.
pub static mut MAX_EDGES_NUM: usize = 0;

extern "C" {
    /// The area pointer points to the edges map.
    pub static mut __afl_area_ptr: *mut u8;
}
pub use __afl_area_ptr as EDGES_MAP_PTR;

/// The size of the map for edges.
#[no_mangle]
pub static mut __afl_map_size: usize = EDGES_MAP_SIZE;
pub use __afl_map_size as EDGES_MAP_PTR_SIZE;

/// Gets the edges map from the `EDGES_MAP_PTR` raw pointer.
#[must_use]
pub fn edges_map_from_ptr<'a>() -> &'a mut [u8] {
    unsafe {
        debug_assert!(!EDGES_MAP_PTR.is_null());
        from_raw_parts_mut(EDGES_MAP_PTR, EDGES_MAP_PTR_SIZE)
    }
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
