/// cmp related observers
pub mod observers;
pub use observers::*;

/// cmp related stages
pub mod stages;
use alloc::{alloc::alloc_zeroed, boxed::Box};
use core::{
    alloc::Layout,
    fmt::{self, Debug, Formatter},
    mem::{size_of, zeroed},
    ptr, slice,
};

use libafl::observers::{CmpMap, CmpValues, CmplogBytes, cmp::AflppCmpLogHeader};
use libafl_bolts::{Error, HasLen, ownedref::OwnedRefMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shmem_providers::ShMem;
pub use stages::*;

use crate::{CMPLOG_MAP_H, CMPLOG_MAP_W};

// CONSTANTS

/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// The size of a logged routine argument in bytes
pub const CMPLOG_RTN_LEN: usize = 32;

/// The hight of a cmplog routine map
pub const CMPLOG_MAP_RTN_H: usize =
    (CMPLOG_MAP_H * size_of::<CmpLogInstruction>()) / size_of::<CmpLogRoutine>();

/// The height of extended rountine map
pub const CMPLOG_MAP_RTN_EXTENDED_H: usize =
    CMPLOG_MAP_H * size_of::<AflppCmpLogOperands>() / size_of::<AflppCmpLogFnOperands>();

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` routine kind
pub const CMPLOG_KIND_RTN: u8 = 1;

// EXTERNS, GLOBALS

#[cfg(feature = "cmplog")]
// void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t size, uint64_t arg1, uint64_t arg2)
unsafe extern "C" {
    /// Logs an instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions(k: usize, size: u8, arg1: u64, arg2: u64);

    /// Logs an AFL++ style instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions_extended(k: usize, size: u8, arg1: u64, arg2: u64);

    /// Logs a routine for feedback during fuzzing
    pub fn __libafl_targets_cmplog_routines(k: usize, ptr1: *const u8, ptr2: *const u8);

    /// Cmplog routines but with len specified.
    pub fn __libafl_targets_cmplog_routines_len(
        k: usize,
        ptr1: *const u8,
        ptr2: *const u8,
        len: usize,
    );

    /// Cmplog string routines with a maximum byte length.
    pub fn __libafl_targets_cmplog_routines_strn(
        k: usize,
        ptr1: *const u8,
        ptr2: *const u8,
        len: usize,
    );

    /// Pointer to the `CmpLog` map
    pub static mut libafl_cmplog_map_ptr: *mut CmpLogMap;
}

#[cfg(feature = "cmplog_extended_instrumentation")]
unsafe extern "C" {
    /// Logs an AFL++ style routine for feedback during fuzzing
    pub fn __libafl_targets_cmplog_routines_extended(k: usize, ptr1: *const u8, ptr2: *const u8);
    /// Extended cmplog routines but with len specified.
    pub fn __libafl_targets_cmplog_routines_extended_len(
        k: usize,
        ptr1: *const u8,
        ptr2: *const u8,
        len: usize,
    );
    /// Pointer to the extended `CmpLog` map
    pub static mut libafl_cmplog_map_extended_ptr: *mut AflppCmpLogMap;
}

#[cfg(feature = "cmplog_extended_instrumentation")]
pub use libafl_cmplog_map_extended_ptr as EXTENDED_CMPLOG_MAP_PTR;
#[cfg(feature = "cmplog")]
pub use libafl_cmplog_map_ptr as CMPLOG_MAP_PTR;

/// Value indicating if cmplog is enabled.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // expect breaks here for some reason
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

// HEADERS

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct CmpLogHeader {
    hits: u16,
    shape: u8,
    kind: u8,
}

// VALS

/// The AFL++ `cmp_operands` struct
///
/// Comparison operands, represented as either two (left and right of comparison) u64 values or
/// two (left and right of comparison) u128 values, split into two u64 values. If the left and
/// right values are smaller than u64, they can be sign or zero extended to 64 bits, as the actual
/// comparison size is determined by the `hits` field of the associated `AflppCmpLogHeader`.
#[derive(Default, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct AflppCmpLogOperands {
    v0: u64,
    v0_128: u64,
    v0_256_0: u64,
    v0_256_1: u64,
    v1: u64,
    v1_128: u64,
    v1_256_0: u64,
    v1_256_1: u64,
    unused: [u8; 8],
}

impl AflppCmpLogOperands {
    #[must_use]
    /// Create new `AflppCmpLogOperands`
    pub fn new(v0: u64, v1: u64) -> Self {
        Self {
            v0,
            v0_128: 0,
            v0_256_0: 0,
            v0_256_1: 0,
            v1,
            v1_128: 0,
            v1_256_0: 0,
            v1_256_1: 0,
            unused: [0; 8],
        }
    }

    #[must_use]
    /// Create new `AflppCmpLogOperands` with 128-bit comparison values
    pub fn new_128bit(v0: u128, v1: u128) -> Self {
        let v0_128 = (v0 >> 64) as u64;
        let v0 = v0 as u64;
        let v1_128 = (v1 >> 64) as u64;
        let v1 = v1 as u64;

        Self {
            v0,
            v0_128,
            v0_256_0: 0,
            v0_256_1: 0,
            v1,
            v1_128,
            v1_256_0: 0,
            v1_256_1: 0,
            unused: [0; 8],
        }
    }

    #[must_use]
    /// 64bit first cmp operand
    pub fn v0(&self) -> u64 {
        self.v0
    }

    #[must_use]
    /// 64bit second cmp operand
    pub fn v1(&self) -> u64 {
        self.v1
    }

    #[must_use]
    /// 128bit first cmp operand
    pub fn v0_128(&self) -> u64 {
        self.v0_128
    }

    #[must_use]
    /// 128bit second cmp operand
    pub fn v1_128(&self) -> u64 {
        self.v1_128
    }

    /// Set the v0 (left) side of the comparison
    pub fn set_v0(&mut self, v0: u64) {
        self.v0 = v0;
        self.v0_128 = 0;
    }

    /// Set the v1 (right) side of the comparison
    pub fn set_v1(&mut self, v1: u64) {
        self.v1 = v1;
        self.v1_128 = 0;
    }

    /// Set the v0 (left) side of the comparison from a 128-bit comparison value
    pub fn set_v0_128(&mut self, v0: u128) {
        self.v0_128 = (v0 >> 64) as u64;
        self.v0 = v0 as u64;
    }

    /// Set the v1 (right) side of the comparison from a 128-bit comparison value
    pub fn set_v1_128(&mut self, v1: u128) {
        self.v1_128 = (v1 >> 64) as u64;
        self.v1 = v1 as u64;
    }
}

/// The AFL++ `cmpfn_operands` struct
#[derive(Default, Debug, Copy, Clone)]
#[repr(C, packed)]
/// Comparison function operands, like for strcmp/memcmp, represented as two byte arrays.
pub struct AflppCmpLogFnOperands {
    v0: [u8; CMPLOG_RTN_LEN],
    v1: [u8; CMPLOG_RTN_LEN],
    v0_len: u8,
    v1_len: u8,
    unused: [u8; 6],
}

impl AflppCmpLogFnOperands {
    #[must_use]
    /// Create a new AFL++ function operands comparison values from two byte slices
    pub fn new(v0: &[u8], v1: &[u8]) -> Self {
        let v0_len = v0.len().min(CMPLOG_RTN_LEN) as u8;
        let v0_truncated = &v0[..v0_len as usize];
        let v1_len = v1.len().min(CMPLOG_RTN_LEN) as u8;
        let v1_truncated = &v1[..v1_len as usize];

        let mut v0_arr = [0; CMPLOG_RTN_LEN];
        let mut v1_arr = [0; CMPLOG_RTN_LEN];

        v0_arr[..v0_len as usize].copy_from_slice(v0_truncated);
        v1_arr[..v1_len as usize].copy_from_slice(v1_truncated);

        Self {
            v0: v0_arr,
            v0_len,
            v1: v1_arr,
            v1_len,
            unused: [0; 6],
        }
    }

    #[must_use]
    /// first rtn operand
    pub fn v0(&self) -> &[u8; CMPLOG_RTN_LEN] {
        &self.v0
    }

    #[must_use]
    /// second rtn operand
    pub fn v0_len(&self) -> u8 {
        self.v0_len
    }

    #[must_use]
    /// first rtn operand len
    pub fn v1(&self) -> &[u8; CMPLOG_RTN_LEN] {
        &self.v1
    }

    #[must_use]
    /// second rtn operand len
    pub fn v1_len(&self) -> u8 {
        self.v1_len
    }

    /// Set the v0 (left) side of the comparison
    pub fn set_v0(&mut self, v0: &[u8]) {
        self.v0_len = v0.len().min(CMPLOG_RTN_LEN) as u8;
        self.v0[..self.v0_len as usize].copy_from_slice(&v0[..self.v0_len as usize]);
    }

    /// Set the v1 (right) side of the comparison
    pub fn set_v1(&mut self, v1: &[u8]) {
        self.v1_len = v1.len().min(CMPLOG_RTN_LEN) as u8;
        self.v1[..self.v1_len as usize].copy_from_slice(&v1[..self.v1_len as usize]);
    }
}

/// The operands logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct CmpLogInstruction(u64, u64, u8);

/// The routine arguments logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct CmpLogRoutine([u8; CMPLOG_RTN_LEN], [u8; CMPLOG_RTN_LEN]);

/// Union of cmplog operands and routines
#[repr(C)]
#[derive(Copy, Clone)]
pub union CmpLogVals {
    operands: [[CmpLogInstruction; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    routines: [[CmpLogRoutine; CMPLOG_MAP_RTN_H]; CMPLOG_MAP_W],
}

impl Debug for CmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmpLogVals").finish_non_exhaustive()
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
/// Comparison values
pub union AflppCmpLogVals {
    operands: [[AflppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    fn_operands: [[AflppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W],
}

impl Debug for AflppCmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AflppCmpLogVals").finish_non_exhaustive()
    }
}

impl AflppCmpLogVals {
    #[must_use]
    /// Handle comparison values as comparison operands
    pub fn operands(&self) -> &[[AflppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W] {
        unsafe { &self.operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison operands
    pub fn operands_mut(&mut self) -> &mut [[AflppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W] {
        unsafe { &mut self.operands }
    }

    #[must_use]
    /// Handle comparison values as comparison function operands
    pub fn fn_operands(
        &self,
    ) -> &[[AflppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W] {
        unsafe { &self.fn_operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison function operands
    pub fn fn_operands_mut(
        &mut self,
    ) -> &mut [[AflppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W] {
        unsafe { &mut self.fn_operands }
    }
}

// MAPS

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CmpLogMap {
    headers: [CmpLogHeader; CMPLOG_MAP_W],
    vals: CmpLogVals,
}

impl Default for CmpLogMap {
    fn default() -> Self {
        unsafe { zeroed() }
    }
}

impl CmpMap for CmpLogMap {
    fn len(&self) -> usize {
        CMPLOG_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx].kind == CMPLOG_KIND_INS {
            if self.executions_for(idx) < CMPLOG_MAP_H {
                self.executions_for(idx)
            } else {
                CMPLOG_MAP_H
            }
        } else if self.executions_for(idx) < CMPLOG_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            CMPLOG_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        if self.headers[idx].kind == CMPLOG_KIND_INS {
            let shape = self.headers[idx].shape;
            unsafe {
                match shape {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].0 as u8,
                        self.vals.operands[idx][execution].1 as u8,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].0 as u16,
                        self.vals.operands[idx][execution].1 as u16,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    2..=3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].0 as u32,
                        self.vals.operands[idx][execution].1 as u32,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    4..=7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].0,
                        self.vals.operands[idx][execution].1,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    // Wider comparison shapes (e.g. 128/256/512-bit) are ignored.
                    _ => None,
                }
            }
        } else {
            unsafe {
                Some(CmpValues::Bytes((
                    CmplogBytes::from_buf_and_len(
                        self.vals.routines[idx][execution].0,
                        CMPLOG_RTN_LEN as u8,
                    ),
                    CmplogBytes::from_buf_and_len(
                        self.vals.routines[idx][execution].1,
                        CMPLOG_RTN_LEN as u8,
                    ),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(CmpLogHeader {
            hits: 0,
            shape: 0,
            kind: 0,
        });

        Ok(())
    }
}

/// The global `CmpLog` map for the current `LibAFL` run.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // expect breaks here for some reason
pub static mut libafl_cmplog_map: CmpLogMap = unsafe { zeroed() };

/// The globale `CmpLog` map, aflpp style
#[unsafe(no_mangle)]
#[cfg(feature = "cmplog_extended_instrumentation")]
pub static mut libafl_cmplog_map_extended: AflppCmpLogMap = unsafe { zeroed() };

pub use libafl_cmplog_map as CMPLOG_MAP;
#[cfg(feature = "cmplog_extended_instrumentation")]
pub use libafl_cmplog_map_extended as CMPLOG_MAP_EXTENDED;

#[derive(Debug, Clone)]
#[repr(C)]
/// Comparison map compatible with AFL++ cmplog instrumentation
pub struct AflppCmpLogMap {
    headers: [AflppCmpLogHeader; CMPLOG_MAP_W],
    vals: AflppCmpLogVals,
}

impl HasLen for AflppCmpLogMap {
    fn len(&self) -> usize {
        CMPLOG_MAP_W
    }
}

impl AflppCmpLogMap {
    /// Returns a new [`OwnedRefMut`] to an [`AflppCmpLogMap`], pointing to the given [`ShMem`].
    ///
    /// # Panics
    /// Panics if the given shared mem is too small or unaligned for [`AflppCmpLogMap`].
    ///
    /// # Safety
    /// The shared memory needs to start with a valid [`AflppCmpLogMap`] object.
    /// Any use of this [`OwnedRefMut`] will dereference a pointer to the given shared memory accordingly
    pub unsafe fn from_shmem<SHM: ShMem>(shmem: &mut SHM) -> OwnedRefMut<'_, Self> {
        let ptr = shmem
            .as_mut_ptr_of::<Self>()
            .filter(|p| p.is_aligned())
            .expect("Shared memory is too small or unaligned for AflppCmpLogMap");
        unsafe { OwnedRefMut::from_mut_ptr(ptr) }
    }

    #[must_use]
    /// Instantiate a new boxed zeroed `AflppCmpLogMap`. This should be used to create a new
    /// map, because it is so large it cannot be allocated on the stack with default
    /// runtime configuration.
    pub fn boxed() -> Box<Self> {
        let layout = Layout::new::<AflppCmpLogMap>();
        unsafe {
            let raw = alloc_zeroed(layout);
            if raw.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            #[expect(clippy::cast_ptr_alignment)]
            Box::from_raw(raw.cast::<AflppCmpLogMap>())
        }
    }

    #[must_use = "the map headers slice should not be ignored"]
    /// Handle the headers for the map
    pub fn headers(&self) -> &[AflppCmpLogHeader] {
        &self.headers
    }

    /// Mutably reference the headers for the map
    pub fn headers_mut(&mut self) -> &mut [AflppCmpLogHeader] {
        &mut self.headers
    }

    #[must_use]
    /// Handle the values for the map
    pub fn values(&self) -> &AflppCmpLogVals {
        &self.vals
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn values_mut(&mut self) -> &mut AflppCmpLogVals {
        &mut self.vals
    }
}

impl Serialize for AflppCmpLogMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let slice =
            unsafe { slice::from_raw_parts(ptr::from_ref(self) as *const u8, size_of::<Self>()) };
        serializer.serialize_bytes(slice)
    }
}

impl<'de> Deserialize<'de> for AflppCmpLogMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut boxed = Self::boxed();
        Self::deserialize_in_place(deserializer, &mut boxed)?;
        Ok(*boxed)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InPlaceVisitor<'a>(&'a mut AflppCmpLogMap);

        impl<'de> serde::de::Visitor<'de> for InPlaceVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a byte array of length {}",
                    size_of::<AflppCmpLogMap>()
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != size_of::<AflppCmpLogMap>() {
                    return Err(E::invalid_length(v.len(), &self));
                }
                // SAFETY: `v` has exact length `size_of::<AflppCmpLogMap>()` and does not overlap `self.0`.
                unsafe {
                    ptr::copy_nonoverlapping(
                        v.as_ptr(),
                        ptr::from_mut(self.0).cast::<u8>(),
                        size_of::<AflppCmpLogMap>(),
                    );
                }
                Ok(())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let dst = unsafe {
                    slice::from_raw_parts_mut(
                        ptr::from_mut(self.0).cast::<u8>(),
                        size_of::<AflppCmpLogMap>(),
                    )
                };
                for (idx, slot) in dst.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(idx, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(
                        size_of::<AflppCmpLogMap>() + 1,
                        &self,
                    ));
                }
                Ok(())
            }
        }

        deserializer.deserialize_bytes(InPlaceVisitor(place))
    }
}

impl CmpMap for AflppCmpLogMap {
    fn len(&self) -> usize {
        CMPLOG_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits().value() as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx].type_().value() == CMPLOG_KIND_INS {
            if self.executions_for(idx) < CMPLOG_MAP_H {
                self.executions_for(idx)
            } else {
                CMPLOG_MAP_H
            }
        } else if self.executions_for(idx) < CMPLOG_MAP_RTN_EXTENDED_H {
            self.executions_for(idx)
        } else {
            CMPLOG_MAP_RTN_EXTENDED_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        let header = self.headers[idx];
        if header.type_().value() == CMPLOG_KIND_INS {
            let shape = self.headers[idx].shape().value();
            unsafe {
                match shape {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].v0 as u8,
                        self.vals.operands[idx][execution].v1 as u8,
                        false,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].v0 as u16,
                        self.vals.operands[idx][execution].v1 as u16,
                        false,
                    ))),
                    2..=3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].v0 as u32,
                        self.vals.operands[idx][execution].v1 as u32,
                        false,
                    ))),
                    4..=7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].v0,
                        self.vals.operands[idx][execution].v1,
                        false,
                    ))),
                    // TODO handle 128 bits & 256 bits & 512 bits cmps
                    8..=63 => None,
                    _ => panic!("Invalid CmpLog shape {shape}"),
                }
            }
        } else {
            unsafe {
                let v0_len = (self.vals.fn_operands[idx][execution].v0_len & 0x7f)
                    .min(CMPLOG_RTN_LEN as u8);
                let v1_len = (self.vals.fn_operands[idx][execution].v1_len & 0x7f)
                    .min(CMPLOG_RTN_LEN as u8);
                Some(CmpValues::Bytes((
                    CmplogBytes::from_buf_and_len(self.vals.fn_operands[idx][execution].v0, v0_len),
                    CmplogBytes::from_buf_and_len(self.vals.fn_operands[idx][execution].v1, v1_len),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(AflppCmpLogHeader::new_with_raw_value(0));

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::{string::ToString, vec};
    #[cfg(all(feature = "cmplog", not(miri)))]
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    #[cfg(all(feature = "cmplog", not(miri)))]
    use libafl::observers::CmpMap;
    use serde::Deserialize;

    use super::{AflppCmpLogMap, AflppCmpLogOperands, ptr, size_of, slice};

    #[cfg(all(feature = "cmplog", not(miri)))]
    static CMPLOG_TEST_LOCK: AtomicBool = AtomicBool::new(false);

    #[cfg(all(feature = "cmplog", not(miri)))]
    pub(crate) struct CmplogTestGuard;

    #[cfg(all(feature = "cmplog", not(miri)))]
    impl Drop for CmplogTestGuard {
        fn drop(&mut self) {
            CMPLOG_TEST_LOCK.store(false, Ordering::Release);
        }
    }

    #[cfg(all(feature = "cmplog", not(miri)))]
    pub(crate) fn lock_cmplog_test() -> CmplogTestGuard {
        while CMPLOG_TEST_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        CmplogTestGuard
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_aflpp_cmplog_map_boxed_and_deserialize_bounds() {
        let mut boxed = AflppCmpLogMap::boxed();
        boxed.values_mut().operands_mut()[0][0] = AflppCmpLogOperands::new(0x1122, 0x3344);
        assert_eq!(boxed.values().operands()[0][0].v0(), 0x1122);
        assert_eq!(boxed.values().operands()[0][0].v1(), 0x3344);

        let short_deser =
            serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(&[0u8; 16]);
        let err = AflppCmpLogMap::deserialize_in_place(short_deser, &mut *boxed).unwrap_err();
        assert!(err.to_string().contains("invalid length 16"));

        let mut words = vec![0u64; size_of::<AflppCmpLogMap>().div_ceil(8) + 1];
        let unaligned = unsafe {
            slice::from_raw_parts_mut(
                words.as_mut_ptr().cast::<u8>().add(1),
                size_of::<AflppCmpLogMap>(),
            )
        };
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::from_ref(&*boxed).cast::<u8>(),
                unaligned.as_mut_ptr(),
                size_of::<AflppCmpLogMap>(),
            );
        }
        boxed.values_mut().operands_mut()[0][0] = AflppCmpLogOperands::new(0, 0);
        let deser = serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(unaligned);
        AflppCmpLogMap::deserialize_in_place(deser, &mut *boxed).unwrap();
        assert_eq!(boxed.values().operands()[0][0].v0(), 0x1122);
        assert_eq!(boxed.values().operands()[0][0].v1(), 0x3344);
    }

    #[test]
    #[cfg(all(feature = "cmplog", not(miri)))]
    fn test_cmplog_routines_hit_wrap_no_oob() {
        use crate::{
            __libafl_targets_cmplog_routines, __libafl_targets_cmplog_routines_len, CMPLOG_ENABLED,
            CMPLOG_MAP_RTN_H, CMPLOG_MAP_W, cmps::CMPLOG_MAP_PTR,
        };

        let _guard = lock_cmplog_test();
        let lhs = [b'A'; 32];
        let rhs = [b'B'; 32];
        unsafe {
            let map = CMPLOG_MAP_PTR;
            assert!(!map.is_null());
            (*map).reset().unwrap();
            AtomicU8::from_ptr(&raw mut CMPLOG_ENABLED).store(1, Ordering::Relaxed);

            for _ in 0..40 {
                __libafl_targets_cmplog_routines(CMPLOG_MAP_W - 1, lhs.as_ptr(), rhs.as_ptr());
            }
            __libafl_targets_cmplog_routines_len(
                CMPLOG_MAP_W - 1,
                lhs.as_ptr(),
                rhs.as_ptr(),
                usize::MAX / 2,
            );
            AtomicU8::from_ptr(&raw mut CMPLOG_ENABLED).store(0, Ordering::Relaxed);

            assert_eq!((*map).headers[CMPLOG_MAP_W - 1].hits, 41);
            let wrapped_slot = 40 % CMPLOG_MAP_RTN_H;
            assert_eq!((*map).vals.routines[CMPLOG_MAP_W - 1][wrapped_slot].0, lhs);
            assert_eq!((*map).vals.routines[CMPLOG_MAP_W - 1][wrapped_slot].1, rhs);
            (*map).reset().unwrap();
        }
    }
}
