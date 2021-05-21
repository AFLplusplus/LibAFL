//! Coverage maps as static mut array

// TODO compile time flag
/// The map size for the edges map.
pub const EDGES_MAP_SIZE: usize = 65536;

/// The map for edges.
pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
/// The max count of edges tracked.
pub static mut MAX_EDGES_NUM: usize = 0;
