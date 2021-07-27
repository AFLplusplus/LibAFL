//! Coverage maps as static mut array

use crate::EDGES_MAP_SIZE;
use core::ptr;

/// The map for edges.
pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
/// The pointer to the map.
pub static mut EDGES_MAP_PTR: *mut u8 = ptr::null_mut();

/// The max count of edges tracked.
pub static mut MAX_EDGES_NUM: usize = 0;
