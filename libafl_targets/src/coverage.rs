//! Coverage maps as static mut array

use alloc::string::String;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl::{mutators::Tokens, Error};

use crate::{ACCOUNTING_MAP_SIZE, EDGES_MAP_SIZE};

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
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    pub static __token_start: *const u8;

    /// End of libafl token section
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    pub static __token_stop: *const u8;
}
pub use __afl_acc_memop_ptr as ACCOUNTING_MEMOP_MAP_PTR;
pub use __afl_area_ptr as EDGES_MAP_PTR;

/// Return Tokens from the compile-time token section
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub fn autotokens() -> Result<Tokens, Error> {
    unsafe {
        if __token_start.is_null() || __token_stop.is_null() {
            Ok(Tokens::default())
        } else {
            // we can safely unwrap
            Tokens::from_mut_ptrs(__token_start, __token_stop)
        }
    }
}

/// The size of the map for edges.
#[no_mangle]
pub static mut __afl_map_size: usize = EDGES_MAP_SIZE;
pub use __afl_map_size as EDGES_MAP_PTR_NUM;
use libafl::observers::StdMapObserver;
use libafl_bolts::ownedref::OwnedMutSlice;

/// Gets the edges map from the `EDGES_MAP_PTR` raw pointer.
/// Assumes a `len` of `EDGES_MAP_PTR_NUM`.
///
/// # Safety
///
/// This function will crash if `edges_map_mut_ptr` is not a valid pointer.
/// The [`edges_max_num`] needs to be smaller than, or equal to the size of the map.
#[must_use]
pub unsafe fn edges_map_mut_slice<'a>() -> OwnedMutSlice<'a, u8> {
    OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), edges_max_num())
}

/// Gets a new [`StdMapObserver`] from the current [`edges_map_mut_slice`].
/// This is roughly equivalent to running:
///
/// ```rust,ignore
/// use libafl::observers::StdMapObserver;
/// use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
///
/// #[cfg(not(feature = "pointer_maps"))]
/// let observer = unsafe {
///     StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), MAX_EDGES_NUM)
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
pub unsafe fn std_edges_map_observer<'a, S>(name: S) -> StdMapObserver<'a, u8, false>
where
    S: Into<String>,
{
    StdMapObserver::from_mut_slice(name, edges_map_mut_slice())
}

/// Gets the current edges map pt
/// It will usually take `EDGES_MAP`, but `EDGES_MAP_PTR`,
/// if built with the `pointer_maps` feature.
#[must_use]
pub fn edges_map_mut_ptr() -> *mut u8 {
    unsafe {
        if cfg!(feature = "pointer_maps") {
            assert!(!EDGES_MAP_PTR.is_null());
            EDGES_MAP_PTR
        } else {
            EDGES_MAP.as_mut_ptr()
        }
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
                EDGES_MAP_PTR_NUM
            }
            #[cfg(not(feature = "pointer_maps"))]
            {
                EDGES_MAP.len()
            }
        }
    }
}

#[cfg(feature = "pointer_maps")]
pub use swap::*;

#[cfg(feature = "pointer_maps")]
mod swap {
    use alloc::string::{String, ToString};
    use core::fmt::Debug;

    use libafl::{
        inputs::UsesInput,
        observers::{DifferentialObserver, Observer, ObserversTuple, StdMapObserver},
        Error,
    };
    use libafl_bolts::{ownedref::OwnedMutSlice, AsMutSlice, Named};
    use serde::{Deserialize, Serialize};

    use super::{EDGES_MAP_PTR, EDGES_MAP_PTR_NUM};

    /// Observer to be used with `DiffExecutor`s when executing a differential target that shares
    /// the AFL map in order to swap out the maps (and thus allow for map observing the two targets
    /// separately).
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct DifferentialAFLMapSwapObserver<'a, 'b> {
        first_map: OwnedMutSlice<'a, u8>,
        second_map: OwnedMutSlice<'b, u8>,
        first_name: String,
        second_name: String,
        name: String,
    }

    impl<'a, 'b> DifferentialAFLMapSwapObserver<'a, 'b> {
        /// Create a new `DifferentialAFLMapSwapObserver`.
        pub fn new<const D1: bool, const D2: bool>(
            first: &mut StdMapObserver<'a, u8, D1>,
            second: &mut StdMapObserver<'b, u8, D2>,
        ) -> Self {
            Self {
                first_name: first.name().to_string(),
                second_name: second.name().to_string(),
                name: format!("differential_{}_{}", first.name(), second.name()),
                first_map: unsafe {
                    let slice = first.map_mut().as_mut_slice();
                    OwnedMutSlice::from_raw_parts_mut(slice.as_mut_ptr(), slice.len())
                },
                second_map: unsafe {
                    let slice = second.map_mut().as_mut_slice();
                    OwnedMutSlice::from_raw_parts_mut(slice.as_mut_ptr(), slice.len())
                },
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

    impl<'a, 'b> Named for DifferentialAFLMapSwapObserver<'a, 'b> {
        fn name(&self) -> &str {
            &self.name
        }
    }

    impl<'a, 'b, S> Observer<S> for DifferentialAFLMapSwapObserver<'a, 'b> where S: UsesInput {}

    impl<'a, 'b, OTA, OTB, S> DifferentialObserver<OTA, OTB, S>
        for DifferentialAFLMapSwapObserver<'a, 'b>
    where
        OTA: ObserversTuple<S>,
        OTB: ObserversTuple<S>,
        S: UsesInput,
    {
        fn pre_observe_first(&mut self, _: &mut OTA) -> Result<(), Error> {
            let slice = self.first_map.as_mut_slice();
            unsafe {
                EDGES_MAP_PTR = slice.as_mut_ptr();
                EDGES_MAP_PTR_NUM = slice.len();
            }
            Ok(())
        }

        fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
            let slice = self.second_map.as_mut_slice();
            unsafe {
                EDGES_MAP_PTR = slice.as_mut_ptr();
                EDGES_MAP_PTR_NUM = slice.len();
            }
            Ok(())
        }
    }
}
