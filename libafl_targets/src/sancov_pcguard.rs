//! [`LLVM` `PcGuard`](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards) runtime for `LibAFL`.

#[cfg(feature = "sancov_pcguard_scoped")]
use {alloc::vec::Vec, core::cell::RefCell, core::cmp::Ordering};

use crate::coverage::{EDGES_MAP, MAX_EDGES_NUM};
#[cfg(feature = "pointer_maps")]
use crate::coverage::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};

#[cfg(all(feature = "sancov_pcguard_edges", feature = "sancov_pcguard_hitcounts"))]
#[cfg(not(any(doc, feature = "clippy")))]
compile_error!(
    "the libafl_targets `sancov_pcguard_edges` and `sancov_pcguard_hitcounts` features are mutually exclusive."
);

#[cfg(feature = "sancov_pcguard_scoped")]
thread_local! {
    static COV_SCOPES: RefCell<Vec<(usize, usize, u8)>> = RefCell::new(Vec::new());
}

/// Callback for sancov `pc_guard` - usually called by `llvm` on each block or edge.
///
/// # Safety
/// Dereferences `guard`, reads the position from there, then dereferences the [`EDGES_MAP`] at that position.
/// Should usually not be called directly.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    let pos = *guard as usize;
    let ptr = {
        #[cfg(feature = "pointer_maps")]
        {
            EDGES_MAP_PTR
        }
        #[cfg(not(feature = "pointer_maps"))]
        {
            EDGES_MAP.as_mut_ptr()
        }
    };

    #[cfg(feature = "sancov_pcguard_edges")]
    {
        ptr.add(pos).write(1);
    }
    #[cfg(feature = "sancov_pcguard_hitcounts")]
    {
        #[cfg(feature = "sancov_pcguard_scoped")]
        {
            let mut addr = None;
            backtrace::trace_unsynchronized(|frame| {
                addr = Some(frame.sp() as usize);
                false
            });

            if let Some(addr) = addr {
                let update_scope = |scopes: &mut Vec<(usize, usize, u8)>, addr, pos| match scopes
                    .iter_mut()
                    .rev()
                    .take_while(|(old_addr, _, _)| *old_addr == addr)
                    .find_map(|(_, old_pos, count)| (*old_pos == pos).then_some(count))
                {
                    None => {
                        scopes.push((addr, pos, 1));
                    }
                    Some(count) => {
                        *count = count.saturating_add(1);
                    }
                };
                let _ = COV_SCOPES.try_with(|scopes| {
                    let mut scopes = scopes.borrow_mut();
                    match scopes.last() {
                        None => scopes.push((addr, pos, 1)),
                        Some((old_addr, _, _)) => match old_addr.cmp(&addr) {
                            Ordering::Less => {
                                // if old addr is less, it is in a deeper stack frame
                                // commit edges back until we get to our depth, then truncate
                                let mut new_len = scopes.len();
                                for (i, &(_, pos, count)) in scopes
                                    .iter()
                                    .enumerate()
                                    .rev()
                                    .take_while(|(_, (old_addr, _, _))| *old_addr < addr)
                                {
                                    let addr = ptr.add(pos);
                                    let val = addr.read().max(count);
                                    addr.write(val);
                                    new_len = i;
                                }
                                scopes.truncate(new_len);

                                // we might be returning to an existing scope; commit to this
                                update_scope(scopes, addr, pos);
                            }
                            Ordering::Equal => {
                                // we are in the same stack frame
                                // try to find an existing guard to increment, otherwise add our own
                                update_scope(scopes, addr, pos);
                            }
                            Ordering::Greater => {
                                // if old addr is greater, it is in a higher stack frame
                                // we know there are no edges matching us here; push the new scope
                                scopes.push((addr, pos, 1));
                            }
                        },
                    }
                });
            }
        }
        #[cfg(not(feature = "sancov_pcguard_scoped"))]
        {
            let addr = ptr.add(pos);
            let val = addr.read().wrapping_add(1);
            addr.write(val);
        }
    }
}

/// Initialize the sancov `pc_guard` - usually called by `llvm`.
///
/// # Safety
/// Dereferences at `start` and writes to it.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    #[cfg(feature = "pointer_maps")]
    if EDGES_MAP_PTR.is_null() {
        EDGES_MAP_PTR = EDGES_MAP.as_mut_ptr();
        EDGES_MAP_PTR_NUM = EDGES_MAP.len();
    }

    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        *start = MAX_EDGES_NUM as u32;
        start = start.offset(1);

        #[cfg(feature = "pointer_maps")]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1) % EDGES_MAP_PTR_NUM;
        }
        #[cfg(not(feature = "pointer_maps"))]
        {
            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
            assert!((MAX_EDGES_NUM <= EDGES_MAP.len()), "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({}). Use the LIBAFL_EDGES_MAP_SIZE env to increase it at compile time.", EDGES_MAP.len());
        }
    }
}
