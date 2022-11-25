//! Coverage maps as static mut array

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
            Tokens::from_ptrs(__token_start, __token_stop)
        }
    }
}

/// The size of the map for edges.
#[no_mangle]
pub static mut __afl_map_size: usize = EDGES_MAP_SIZE;
pub use __afl_map_size as EDGES_MAP_PTR_SIZE;
use libafl::bolts::ownedref::OwnedSliceMut;

/// Gets the edges map from the `EDGES_MAP_PTR` raw pointer.
///
/// # Safety
///
/// This function will crash if `EDGES_MAP_PTR` is not a valid pointer.
/// The `EDGES_MAP_PTR_SIZE` needs to be smaller than, or equal to the size of the map.
#[must_use]
pub unsafe fn edges_map_from_ptr<'a>() -> OwnedSliceMut<'a, u8> {
    debug_assert!(!EDGES_MAP_PTR.is_null());
    OwnedSliceMut::from_raw_parts_mut(EDGES_MAP_PTR, EDGES_MAP_PTR_SIZE)
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

#[cfg(feature = "pointer_maps")]
pub use swap::*;

#[cfg(feature = "pointer_maps")]
mod swap {
    use alloc::string::{String, ToString};
    use core::fmt::Debug;

    use libafl::{
        bolts::{ownedref::OwnedSliceMut, tuples::Named, AsMutSlice},
        inputs::UsesInput,
        observers::{DifferentialObserver, Observer, ObserversTuple, StdMapObserver},
        Error,
    };
    use serde::{Deserialize, Serialize};

    use super::{EDGES_MAP_PTR, EDGES_MAP_PTR_SIZE};

    /// Observer to be used with `DiffExecutor`s when executing a differential target that shares
    /// the AFL map in order to swap out the maps (and thus allow for map observing the two targets
    /// separately).
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct DifferentialAFLMapSwapObserver<'a, 'b> {
        first_map: OwnedSliceMut<'a, u8>,
        second_map: OwnedSliceMut<'b, u8>,
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
                    OwnedSliceMut::from_raw_parts_mut(slice.as_mut_ptr(), slice.len())
                },
                second_map: unsafe {
                    let slice = second.map_mut().as_mut_slice();
                    OwnedSliceMut::from_raw_parts_mut(slice.as_mut_ptr(), slice.len())
                },
            }
        }

        /// Get the first map
        #[must_use]
        pub fn first_map(&self) -> &OwnedSliceMut<'a, u8> {
            &self.first_map
        }

        /// Get the second map
        #[must_use]
        pub fn second_map(&self) -> &OwnedSliceMut<'b, u8> {
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
                EDGES_MAP_PTR_SIZE = slice.len();
            }
            Ok(())
        }

        fn pre_observe_second(&mut self, _: &mut OTB) -> Result<(), Error> {
            let slice = self.second_map.as_mut_slice();
            unsafe {
                EDGES_MAP_PTR = slice.as_mut_ptr();
                EDGES_MAP_PTR_SIZE = slice.len();
            }
            Ok(())
        }
    }
}
