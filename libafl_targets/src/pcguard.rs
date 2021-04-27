#[cfg(all(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
compile_error!(
    "the libafl_targets `pcguard_edges` and `pcguard_hitcounts` features are mutually exclusive."
);

// TODO compile time flag
pub const EDGES_MAP_SIZE: usize = 65536;

pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
//pub static mut CMP_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
pub static mut MAX_EDGES_NUM: usize = 0;

/// Sanitizer Coverage PC_Guard implementation.
/// Will trace edges if `pcguard_edges` is set.
/// Will trace hitcounts, if `pcguard_hitcounts` is set.
///
/// # Safety
/// The function write to the `EDGES_MAP` global map, if guard exceeds this size, access is out of bounds.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let pos = *guard as usize;
    #[cfg(feature = "pcguard_edges")]
    {
        *EDGES_MAP.get_unchecked_mut(pos) = 1;
    }
    #[cfg(feature = "pcguard_hitcounts")]
    {
        let val = (*EDGES_MAP.get_unchecked(pos) as u8).wrapping_add(1);
        *EDGES_MAP.get_unchecked_mut(pos) = val;
    }
}

/// Pcguard sancov implementation, used for coverage feedback.
///
/// # Safety
/// Dereferences, and writes to the handed `start` pointer.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        MAX_EDGES_NUM += 1;
        *start = (MAX_EDGES_NUM & (EDGES_MAP_SIZE - 1)) as u32;
        start = start.offset(1);
    }
}
