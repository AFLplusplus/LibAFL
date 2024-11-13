/// cmp related observers
pub mod observers;
pub use observers::*;

/// cmp related stages
pub mod stages;
use alloc::{alloc::alloc_zeroed, boxed::Box, vec::Vec};
use core::{
    alloc::Layout,
    fmt::{self, Debug, Formatter},
    mem::{size_of, zeroed},
    ptr, slice,
};

use libafl::{
    observers::{cmp::AFLppCmpLogHeader, CmpMap, CmpValues, CmplogBytes},
    Error,
};
use libafl_bolts::HasLen;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    CMPLOG_MAP_H * size_of::<AFLppCmpLogOperands>() / size_of::<AFLppCmpLogFnOperands>();

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` routine kind
pub const CMPLOG_KIND_RTN: u8 = 1;

// EXTERNS, GLOBALS

#[cfg(feature = "cmplog")]
// void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2)
extern "C" {
    /// Logs an instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions(k: usize, shape: u8, arg1: u64, arg2: u64);

    /// Logs a routine for feedback during fuzzing
    pub fn __libafl_targets_cmplog_routines(k: usize, ptr1: *const u8, ptr2: *const u8);

    /// Pointer to the `CmpLog` map
    pub static mut libafl_cmplog_map_ptr: *mut CmpLogMap;
}

#[cfg(feature = "cmplog")]
pub use libafl_cmplog_map_ptr as CMPLOG_MAP_PTR;

/// Value indicating if cmplog is enabled.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

// HEADERS

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
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
/// comparison size is determined by the `hits` field of the associated `AFLppCmpLogHeader`.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLppCmpLogOperands {
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

impl AFLppCmpLogOperands {
    #[must_use]
    /// Create new `AFLppCmpLogOperands`
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
    /// Create new `AFLppCmpLogOperands` with 128-bit comparison values
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
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison function operands, like for strcmp/memcmp, represented as two byte arrays.
pub struct AFLppCmpLogFnOperands {
    v0: [u8; 32],
    v1: [u8; 32],
    v0_len: u8,
    v1_len: u8,
    unused: [u8; 6],
}

impl AFLppCmpLogFnOperands {
    #[must_use]
    /// Create a new AFL++ function operands comparison values from two byte slices
    pub fn new(v0: &[u8], v1: &[u8]) -> Self {
        let v0_len = v0.len() as u8;
        let v1_len = v1.len() as u8;

        let mut v0_arr = [0; 32];
        let mut v1_arr = [0; 32];

        v0_arr.copy_from_slice(v0);
        v1_arr.copy_from_slice(v1);

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
    pub fn v0(&self) -> &[u8; 32] {
        &self.v0
    }

    #[must_use]
    /// second rtn operand
    pub fn v0_len(&self) -> u8 {
        self.v0_len
    }

    #[must_use]
    /// first rtn operand len
    pub fn v1(&self) -> &[u8; 32] {
        &self.v1
    }

    #[must_use]
    /// second rtn operand len
    pub fn v1_len(&self) -> u8 {
        self.v1_len
    }

    /// Set the v0 (left) side of the comparison
    pub fn set_v0(&mut self, v0: &[u8]) {
        self.v0_len = v0.len() as u8;
        self.v0.copy_from_slice(v0);
    }

    /// Set the v1 (right) side of the comparison
    pub fn set_v1(&mut self, v1: &[u8]) {
        self.v1_len = v1.len() as u8;
        self.v1.copy_from_slice(v1);
    }
}

/// The operands logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogInstruction(u64, u64, u8);

/// The routine arguments logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogRoutine([u8; CMPLOG_RTN_LEN], [u8; CMPLOG_RTN_LEN]);

/// Union of cmplog operands and routines
#[repr(C)]
#[derive(Clone, Copy)]
pub union CmpLogVals {
    operands: [[CmpLogInstruction; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    routines: [[CmpLogRoutine; CMPLOG_MAP_RTN_H]; CMPLOG_MAP_W],
}

impl Debug for CmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmpLogVals").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
/// Comparison values
pub union AFLppCmpLogVals {
    operands: [[AFLppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    fn_operands: [[AFLppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W],
}

impl Debug for AFLppCmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AFLppCmpLogVals").finish_non_exhaustive()
    }
}

impl AFLppCmpLogVals {
    #[must_use]
    /// Handle comparison values as comparison operands
    pub fn operands(&self) -> &[[AFLppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W] {
        unsafe { &self.operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison operands
    pub fn operands_mut(&mut self) -> &mut [[AFLppCmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W] {
        unsafe { &mut self.operands }
    }

    #[must_use]
    /// Handle comparison values as comparison function operands
    pub fn fn_operands(
        &self,
    ) -> &[[AFLppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W] {
        unsafe { &self.fn_operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison function operands
    pub fn fn_operands_mut(
        &mut self,
    ) -> &mut [[AFLppCmpLogFnOperands; CMPLOG_MAP_RTN_EXTENDED_H]; CMPLOG_MAP_W] {
        unsafe { &mut self.fn_operands }
    }
}

// MAPS

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
            unsafe {
                match self.headers[idx].shape {
                    1 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].0 as u8,
                        self.vals.operands[idx][execution].1 as u8,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    2 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].0 as u16,
                        self.vals.operands[idx][execution].1 as u16,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    4 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].0 as u32,
                        self.vals.operands[idx][execution].1 as u32,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    8 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].0,
                        self.vals.operands[idx][execution].1,
                        self.vals.operands[idx][execution].2 == 1,
                    ))),
                    // other => panic!("Invalid CmpLog shape {}", other),
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
#[no_mangle]
#[allow(clippy::large_stack_arrays)]
#[allow(non_upper_case_globals)]
pub static mut libafl_cmplog_map: CmpLogMap = CmpLogMap {
    headers: [CmpLogHeader {
        hits: 0,
        shape: 0,
        kind: 0,
    }; CMPLOG_MAP_W],
    vals: CmpLogVals {
        operands: [[CmpLogInstruction(0, 0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W],
    },
};

/// The globale `CmpLog` map, aflpp style
#[no_mangle]
#[cfg(feature = "cmplog_extended_instrumentation")]
#[allow(clippy::large_stack_arrays)]
pub static mut libafl_cmplog_map_extended: AFLppCmpLogMap = AFLppCmpLogMap {
    headers: [AFLppCmpLogHeader::new_with_raw_value(0); CMPLOG_MAP_W],
    vals: AFLppCmpLogVals {
        operands: [[AFLppCmpLogOperands {
            v0: 0,
            v0_128: 0,
            v0_256_0: 0,
            v0_256_1: 0,
            v1: 0,
            v1_128: 0,
            v1_256_0: 0,
            v1_256_1: 0,
            unused: [0; 8],
        }; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    },
};

pub use libafl_cmplog_map as CMPLOG_MAP;
#[cfg(feature = "cmplog_extended_instrumentation")]
pub use libafl_cmplog_map_extended as CMPLOG_MAP_EXTENDED;

#[derive(Debug, Clone)]
#[repr(C)]
/// Comparison map compatible with AFL++ cmplog instrumentation
pub struct AFLppCmpLogMap {
    headers: [AFLppCmpLogHeader; CMPLOG_MAP_W],
    vals: AFLppCmpLogVals,
}

impl HasLen for AFLppCmpLogMap {
    fn len(&self) -> usize {
        CMPLOG_MAP_W
    }
}

impl AFLppCmpLogMap {
    #[must_use]
    #[allow(clippy::cast_ptr_alignment)]
    /// Instantiate a new boxed zeroed `AFLppCmpLogMap`. This should be used to create a new
    /// map, because it is so large it cannot be allocated on the stack with default
    /// runtime configuration.
    pub fn boxed() -> Box<Self> {
        unsafe {
            Box::from_raw(alloc_zeroed(Layout::new::<AFLppCmpLogMap>()) as *mut AFLppCmpLogMap)
        }
    }

    #[must_use]
    /// Handle the headers for the map
    pub fn headers(&self) -> &[AFLppCmpLogHeader] {
        &self.headers
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn headers_mut(&mut self) -> &mut [AFLppCmpLogHeader] {
        &mut self.headers
    }

    #[must_use]
    /// Handle the values for the map
    pub fn values(&self) -> &AFLppCmpLogVals {
        &self.vals
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn values_mut(&mut self) -> &mut AFLppCmpLogVals {
        &mut self.vals
    }
}

impl Serialize for AFLppCmpLogMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let slice =
            unsafe { slice::from_raw_parts(ptr::from_ref(self) as *const u8, size_of::<Self>()) };
        serializer.serialize_bytes(slice)
    }
}

impl<'de> Deserialize<'de> for AFLppCmpLogMap {
    #[allow(clippy::cast_ptr_alignment)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let map: Self = unsafe { ptr::read(bytes.as_ptr() as *const _) };
        Ok(map)
    }
}

impl CmpMap for AFLppCmpLogMap {
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
        } else if self.executions_for(idx) < CMPLOG_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            CMPLOG_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        let header = self.headers[idx];
        if header.type_().value() == CMPLOG_KIND_INS {
            unsafe {
                match self.headers[idx].shape().value() {
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
                    3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].v0 as u32,
                        self.vals.operands[idx][execution].v1 as u32,
                        false,
                    ))),
                    7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].v0,
                        self.vals.operands[idx][execution].v1,
                        false,
                    ))),
                    // TODO handle 128 bits & 256 bits cmps
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                let v0_len = self.vals.fn_operands[idx][execution].v0_len & (0x80 - 1);
                let v1_len = self.vals.fn_operands[idx][execution].v1_len & (0x80 - 1);
                Some(CmpValues::Bytes((
                    CmplogBytes::from_buf_and_len(self.vals.fn_operands[idx][execution].v0, v0_len),
                    CmplogBytes::from_buf_and_len(self.vals.fn_operands[idx][execution].v1, v1_len),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(AFLppCmpLogHeader::new_with_raw_value(0));

        Ok(())
    }
}
