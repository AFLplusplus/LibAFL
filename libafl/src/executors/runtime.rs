//! A sancov runtime to update a simple u8 map with coverage-information during fuzzing

//#![feature(asm)]

/// The map size used by this instance.
const MAP_SIZE: usize = 65536;

#[no_mangle]
pub static mut __lafl_dummy_map: [u8; MAP_SIZE] = [0; MAP_SIZE];
#[no_mangle]
pub static mut __lafl_edges_map: *mut u8 = unsafe { __lafl_dummy_map.as_ptr() as *mut _ };
#[no_mangle]
pub static mut __lafl_cmp_map: *mut u8 = unsafe { __lafl_dummy_map.as_ptr() as *mut _ };
#[no_mangle]
pub static mut __lafl_max_edges_size: u32 = 0;

/// Called for each branch the target program takes.
#[no_mangle]
#[inline]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: &u32) {
    let ref mut trace_byte = *__lafl_edges_map.offset(*guard as isize);
    /* TODO: translate to RUST inline ASM once it's stable (neverzero)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    asm! volatile(                     \
      "addb $1, (%0, %1, 1)\n"      \
      "adcb $0, (%0, %1, 1)\n"      \
      : /* no out */                \
      : "r"(afl_area_ptr), "r"(loc) \
      : "memory", "eax")

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    */

    // Make sure we wrap to 0, not zero, it's empirically proven to be better for fuzzing.
    let added = (*trace_byte as u16) + 1;
    *trace_byte = (added as u8) + (added >> 8) as u8;

    //*trace_byte = (*trace_byte).wrapping_add(1);
}

/// Called when the targetprogram starts
#[no_mangle]
#[inline]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    if start == stop || *start != 0 {
        return;
    }
    __lafl_max_edges_size = __lafl_max_edges_size.wrapping_add(1);
    let fresh1 = start;
    start = start.offset(1);
    *fresh1 = __lafl_max_edges_size & (MAP_SIZE - 1) as u32;
    while start < stop {
        __lafl_max_edges_size = __lafl_max_edges_size.wrapping_add(1);
        *start = __lafl_max_edges_size & (MAP_SIZE - 1) as u32;
        start = start.offset(1)
    }
}
