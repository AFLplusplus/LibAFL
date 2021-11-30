//! Coverage maps as static mut array

use crate::EDGES_MAP_SIZE;
use core::ptr;

/// The map for edges.
pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];

/// The max count of edges tracked.
pub static mut MAX_EDGES_NUM: usize = 0;

#[no_mangle]
pub static mut __afl_area_ptr: *mut u8 = ptr::null_mut();
pub use __afl_area_ptr as EDGES_MAP_PTR;

#[no_mangle]
pub static mut __afl_map_size: usize = 0;
pub use __afl_map_size as EDGES_MAP_PTR_SIZE;
