#[cfg(all(feature = "pcguard_edges", feature = "pcguard_hitcounts"))]
compile_error!(
    "the libafl_targets `pcguard_edges` and `pcguard_hitcounts` features are mutually exclusive."
);

// TODO compile time flag
pub const MAP_SIZE: usize = 65536;

pub static mut EDGES_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
//pub static mut CMP_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
pub static mut MAX_EDGES_NUM: usize = 0;

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

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        MAX_EDGES_NUM += 1;
        *start = (MAX_EDGES_NUM & (MAP_SIZE - 1)) as u32;
        start = start.offset(1);
    }
}
