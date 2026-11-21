//! Coverage maps as static mut array

#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
use alloc::borrow::Cow;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl::mutators::Tokens;
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_bolts::Error;

use crate::{ACCOUNTING_MAP_SIZE, EDGES_MAP_ALLOCATED_SIZE, EDGES_MAP_DEFAULT_SIZE};

/// The map for edges.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // expect breaks here for some reason
pub static mut __afl_area_ptr_local: [u8; EDGES_MAP_ALLOCATED_SIZE] = [0; EDGES_MAP_ALLOCATED_SIZE];
pub use __afl_area_ptr_local as EDGES_MAP;

/// The map for accounting mem writes.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // expect breaks here for some reason
pub static mut __afl_acc_memop_ptr_local: [u32; ACCOUNTING_MAP_SIZE] = [0; ACCOUNTING_MAP_SIZE];
pub use __afl_acc_memop_ptr_local as ACCOUNTING_MEMOP_MAP;

/// The max count of edges found.
///
/// This is either computed during the compilation time or at runtime (in this case this is used to shrink the map).
/// You can use this for the initial map size for the observer only if you compute this time at compilation time.
pub static mut MAX_EDGES_FOUND: usize = 0;

unsafe extern "C" {
    /// The sharedmemort fuzzing flag
    pub static mut __afl_sharedmem_fuzzing: core::ffi::c_uint;

    /// The area pointer points to the edges map.
    pub static mut __afl_area_ptr: *mut u8;

    /// The area pointer points to the accounting mem operations map.
    pub static mut __afl_acc_memop_ptr: *mut u32;

    /// Start of libafl token section
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    pub static __token_start: *const u8;

    /// End of libafl token section
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    pub static __token_stop: *const u8;
}
pub use __afl_acc_memop_ptr as ACCOUNTING_MEMOP_MAP_PTR;
pub use __afl_area_ptr as EDGES_MAP_PTR;
pub use __afl_fuzz_len as INPUT_LENGTH_PTR;
pub use __afl_fuzz_ptr as INPUT_PTR;
pub use __afl_sharedmem_fuzzing as SHM_FUZZING;

/// Check if we have enabled autotokens
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(crate) fn has_autotokens() -> bool {
    unsafe {
        !__token_start.is_null()
            && !__token_stop.is_null()
            && (__token_stop as usize) > (__token_start as usize)
    }
}

/// Return Tokens from the compile-time token section
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub fn autotokens() -> Result<Tokens, Error> {
    // # Safety
    // All values are checked before dereferencing.

    unsafe {
        if has_autotokens() {
            // we can safely unwrap
            Tokens::from_mut_ptrs(__token_start, __token_stop)
        } else {
            Ok(Tokens::default())
        }
    }
}

/// The actual size we use for the map of edges.
/// This is used for forkserver backend
#[allow(non_upper_case_globals)] // expect breaks here for some reason
#[unsafe(no_mangle)]
pub static mut __afl_map_size: usize = EDGES_MAP_DEFAULT_SIZE;
/// The pointer points to the AFL++ inputs
#[allow(non_upper_case_globals)] // expect breaks here for some reason
#[unsafe(no_mangle)]
pub static mut __afl_fuzz_ptr: *mut u8 = core::ptr::null_mut();
#[allow(non_upper_case_globals)] // expect breaks here for some reason
static mut __afl_fuzz_len_local: u32 = 0;
/// The pointer points to the length of AFL++ inputs
#[allow(non_upper_case_globals)] // expect breaks here for some reason
#[unsafe(no_mangle)]
pub static mut __afl_fuzz_len: *mut u32 = &raw mut __afl_fuzz_len_local;

#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
use libafl::observers::StdMapObserver;
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
use libafl_bolts::ownedref::OwnedMutSlice;

/// Gets the edges map from the `EDGES_MAP_PTR` raw pointer.
/// Assumes a `len` of at least `EDGES_MAP_PTR_MAX`.
///
/// # Safety
///
/// This function will crash if `edges_map_mut_ptr` is not a valid pointer.
/// The [`edges_max_num`] needs to be smaller than, or equal to the size of the map.
#[must_use]
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
pub unsafe fn edges_map_mut_slice<'a>() -> OwnedMutSlice<'a, u8> {
    unsafe { OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), edges_max_num()) }
}

/// Gets a new [`StdMapObserver`] from the current [`edges_map_mut_slice`].
/// This is roughly equivalent to running:
///
/// ```rust,ignore
/// use libafl::observers::StdMapObserver;
/// use libafl_targets::{EDGES_MAP, EDGES_MAP_DEFAULT_SIZE};
///
/// #[cfg(not(feature = "pointer_maps"))]
/// let observer = unsafe {
///     StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), EDGES_MAP_DEFAULT_SIZE)
/// };
/// ```
///
/// or, for the `pointer_maps` feature:
///
/// ```rust,ignore
/// use libafl::observers::StdMapObserver;
/// use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};
///
/// #[cfg(feature = "pointer_maps")]
/// let observer = unsafe {
///     StdMapObserver::from_mut_ptr("edges", EDGES_MAP_PTR, EDGES_MAP_PTR_NUM)
/// };
/// ```
///
/// # Safety
/// This will dereference [`edges_map_mut_ptr`] and crash if it is not a valid address.
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
pub unsafe fn std_edges_map_observer<'a, S>(name: S) -> StdMapObserver<'a, u8, false>
where
    S: Into<Cow<'static, str>>,
{
    unsafe { StdMapObserver::from_mut_slice(name, edges_map_mut_slice()) }
}

/// Gets the current edges map pt
/// It will usually take `EDGES_MAP`, but `EDGES_MAP_PTR`,
/// if built with the `pointer_maps` feature.
#[must_use]
pub fn edges_map_mut_ptr() -> *mut u8 {
    unsafe {
        if cfg!(feature = "pointer_maps") {
            let ptr = core::sync::atomic::AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR)
                .load(core::sync::atomic::Ordering::Acquire);
            assert!(!ptr.is_null());
            ptr
        } else {
            (&raw mut EDGES_MAP).cast::<u8>()
        }
    }
}

/// Gets the current maximum number of edges tracked.
#[cfg(any(
    feature = "sancov_pcguard_edges",
    feature = "sancov_pcguard_hitcounts",
    feature = "sancov_ngram4",
    feature = "sancov_ngram8",
    feature = "sancov_ctx"
))]
#[must_use]
pub fn edges_max_num() -> usize {
    let max_edges = unsafe {
        core::sync::atomic::AtomicUsize::from_ptr(&raw mut MAX_EDGES_FOUND)
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    let clamped = if max_edges > 0 {
        max_edges.min(EDGES_MAP_ALLOCATED_SIZE)
    } else {
        EDGES_MAP_ALLOCATED_SIZE
    };
    if cfg!(any(
        feature = "sancov_ngram4",
        feature = "sancov_ngram8",
        feature = "sancov_ctx"
    )) {
        clamped.max(EDGES_MAP_DEFAULT_SIZE)
    } else {
        clamped
    }
}

#[cfg(feature = "pointer_maps")]
pub use swap::*;

#[cfg(feature = "pointer_maps")]
mod swap {
    use alloc::borrow::Cow;
    use core::{fmt::Debug, ptr::NonNull};

    use libafl::{
        Error,
        observers::{DifferentialObserver, Observer, StdMapObserver},
    };
    use libafl_bolts::{Named, ownedref::OwnedMutSlice};
    use serde::{Deserialize, Serialize};

    use super::EDGES_MAP_PTR;

    /// Observer to be used with `DiffExecutor`s when executing a differential target that shares
    /// the AFL map in order to swap out the maps (and thus allow for map observing the two targets
    /// separately).
    #[derive(Debug, Serialize, Deserialize)]
    pub struct DifferentialAFLMapSwapObserver<'a, 'b> {
        first_map: OwnedMutSlice<'a, u8>,
        second_map: OwnedMutSlice<'b, u8>,
        first_name: Cow<'static, str>,
        second_name: Cow<'static, str>,
        name: Cow<'static, str>,
        #[serde(skip)]
        first_ptr: Option<NonNull<u8>>,
        #[serde(skip)]
        second_ptr: Option<NonNull<u8>>,
    }

    impl<'a, 'b> DifferentialAFLMapSwapObserver<'a, 'b> {
        /// Create a new `DifferentialAFLMapSwapObserver`.
        ///
        /// # Safety
        ///
        /// `first` and `second` maps must outlive this observer and cover all instrumented guards
        /// without concurrent mutable aliasing while `EDGES_MAP_PTR` points to them.
        pub unsafe fn new<const D1: bool, const D2: bool>(
            first: &mut StdMapObserver<'a, u8, D1>,
            second: &mut StdMapObserver<'b, u8, D2>,
        ) -> Self {
            let first_name = first.name().clone();
            let second_name = second.name().clone();
            let name = Cow::from(format!("differential_{first_name}_{second_name}"));
            let (first_map, first_ptr) = unsafe {
                let slice = first.map_mut();
                let ptr = slice.as_mut_ptr();
                let len = slice.len();
                (
                    OwnedMutSlice::from_raw_parts_mut(ptr, len),
                    (!slice.is_empty()).then(|| NonNull::new(ptr)).flatten(),
                )
            };
            let (second_map, second_ptr) = unsafe {
                let slice = second.map_mut();
                let ptr = slice.as_mut_ptr();
                let len = slice.len();
                (
                    OwnedMutSlice::from_raw_parts_mut(ptr, len),
                    (!slice.is_empty()).then(|| NonNull::new(ptr)).flatten(),
                )
            };
            Self {
                first_map,
                second_map,
                first_name,
                second_name,
                name,
                first_ptr,
                second_ptr,
            }
        }

        /// Get the first map
        #[must_use]
        pub fn first_map(&self) -> &OwnedMutSlice<'a, u8> {
            &self.first_map
        }

        /// Get the second map
        #[must_use]
        pub fn second_map(&self) -> &OwnedMutSlice<'b, u8> {
            &self.second_map
        }

        /// Get the first name
        #[must_use]
        pub fn first_name(&self) -> &str {
            &self.first_name
        }

        /// Get the second name
        #[must_use]
        pub fn second_name(&self) -> &str {
            &self.second_name
        }
    }

    impl Named for DifferentialAFLMapSwapObserver<'_, '_> {
        fn name(&self) -> &Cow<'static, str> {
            &self.name
        }
    }

    impl<I, S> Observer<I, S> for DifferentialAFLMapSwapObserver<'_, '_> {}

    impl<OTA, OTB, I, S> DifferentialObserver<OTA, OTB, I, S>
        for DifferentialAFLMapSwapObserver<'_, '_>
    {
        fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
            let Some(ptr) = self.first_ptr else {
                return Err(Error::illegal_state(
                    "Deserialized DifferentialAFLMapSwapObserver cannot update EDGES_MAP_PTR",
                ));
            };
            unsafe {
                core::sync::atomic::AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR)
                    .store(ptr.as_ptr(), core::sync::atomic::Ordering::Relaxed);
            }
            Ok(())
        }

        fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
            let Some(ptr) = self.second_ptr else {
                return Err(Error::illegal_state(
                    "Deserialized DifferentialAFLMapSwapObserver cannot update EDGES_MAP_PTR",
                ));
            };
            unsafe {
                core::sync::atomic::AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR)
                    .store(ptr.as_ptr(), core::sync::atomic::Ordering::Relaxed);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use core::sync::atomic::{AtomicPtr, Ordering};

        use super::*;

        struct RestoreEdgesPtr(*mut u8);

        impl Drop for RestoreEdgesPtr {
            fn drop(&mut self) {
                unsafe {
                    AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR).store(self.0, Ordering::Relaxed);
                }
            }
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn test_differential_afl_map_swap_observer_swaps_and_rejects_deserialized() {
            let _restore = RestoreEdgesPtr(unsafe {
                AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR).load(Ordering::Relaxed)
            });
            let mut buf1 = [0u8; 64];
            let mut buf2 = [0u8; 64];
            let ptr1 = buf1.as_mut_ptr();
            let ptr2 = buf2.as_mut_ptr();

            let mut obs1 = unsafe { StdMapObserver::from_mut_ptr("m1", ptr1, buf1.len()) };
            let mut obs2 = unsafe { StdMapObserver::from_mut_ptr("m2", ptr2, buf2.len()) };
            let mut diff = unsafe { DifferentialAFLMapSwapObserver::new(&mut obs1, &mut obs2) };

            <DifferentialAFLMapSwapObserver as DifferentialObserver<(), (), (), ()>>::pre_observe_first(
                &mut diff,
                &mut (),
            )
            .unwrap();
            assert_eq!(
                unsafe { AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR).load(Ordering::Relaxed) },
                ptr1
            );

            <DifferentialAFLMapSwapObserver as DifferentialObserver<(), (), (), ()>>::pre_observe_second(
                &mut diff,
                &mut (),
            )
            .unwrap();
            assert_eq!(
                unsafe { AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR).load(Ordering::Relaxed) },
                ptr2
            );

            let encoded = postcard::to_allocvec(&diff).unwrap();
            let mut roundtripped: DifferentialAFLMapSwapObserver =
                postcard::from_bytes(&encoded).unwrap();
            assert!(
                <DifferentialAFLMapSwapObserver as DifferentialObserver<(), (), (), ()>>::pre_observe_first(
                    &mut roundtripped,
                    &mut (),
                )
                .is_err()
            );
            assert!(
                <DifferentialAFLMapSwapObserver as DifferentialObserver<(), (), (), ()>>::pre_observe_second(
                    &mut roundtripped,
                    &mut (),
                )
                .is_err()
            );
        }
    }
}
