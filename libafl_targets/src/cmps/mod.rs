/// cmp related observers
pub mod observers;
pub use observers::*;

/// cmp related stages
pub mod stages;
use alloc::{alloc::alloc_zeroed, boxed::Box, vec::Vec};
use core::{
    alloc::Layout,
    fmt::{self, Debug, Formatter},
};

use libafl::{
    observers::{cmp::AFLppCmpLogHeader, CmpMap, CmpValues},
    Error,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use stages::*;

use crate::{AFLPP_CMPLOG_MAP_H, AFLPP_CMPLOG_MAP_W, CMPLOG_MAP_H, CMPLOG_MAP_W};

// CONSTANTS

/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// The size of a logged routine argument in bytes
pub const CMPLOG_RTN_LEN: usize = 32;

/// The hight of a cmplog routine map
pub const CMPLOG_MAP_RTN_H: usize = (CMPLOG_MAP_H * core::mem::size_of::<CmpLogInstruction>())
    / core::mem::size_of::<CmpLogRoutine>();

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` routine kind
pub const CMPLOG_KIND_RTN: u8 = 1;

/// The height for RTN
pub const AFL_CMPLOG_MAP_RTN_H: usize = AFLPP_CMPLOG_MAP_H / 2;

/// The AFL++ `CMP_TYPE_INS`
pub const AFL_CMP_TYPE_INS: u32 = 1;
/// The AFL++ `CMP_TYPE_RTN`
pub const AFL_CMP_TYPE_RTN: u32 = 2;

// EXTERNS, GLOBALS

// void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2)
extern "C" {
    /// Logs an instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions(k: usize, shape: u8, arg1: u64, arg2: u64);

    /// Pointer to the `CmpLog` map
    pub static mut libafl_cmplog_map_ptr: *mut CmpLogMap;
}

pub use libafl_cmplog_map_ptr as CMPLOG_MAP_PTR;

/// Value indicating if cmplog is enabled.
#[no_mangle]
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
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison operands, represented as either two (left and right of comparison) u64 values or
/// two (left and right of comparison) u128 values, split into two u64 values. If the left and
/// right values are smaller than u64, they can be sign or zero extended to 64 bits, as the actual
/// comparison size is determined by the `hits` field of the associated `AFLppCmpLogHeader`.
pub struct AFLppCmpLogOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

impl AFLppCmpLogOperands {
    #[must_use]
    /// Create new `AFLppCmpLogOperands`
    pub fn new(v0: u64, v1: u64) -> Self {
        Self {
            v0,
            v1,
            v0_128: 0,
            v1_128: 0,
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
            v1,
            v0_128,
            v1_128,
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
    v0: [u8; 31],
    v0_len: u8,
    v1: [u8; 31],
    v1_len: u8,
}

impl AFLppCmpLogFnOperands {
    #[must_use]
    /// Create a new AFL++ function operands comparison values from two byte slices
    pub fn new(v0: &[u8], v1: &[u8]) -> Self {
        let v0_len = v0.len() as u8;
        let v1_len = v1.len() as u8;

        let mut v0_arr = [0; 31];
        let mut v1_arr = [0; 31];

        v0_arr.copy_from_slice(v0);
        v1_arr.copy_from_slice(v1);

        Self {
            v0: v0_arr,
            v0_len,
            v1: v1_arr,
            v1_len,
        }
    }

    #[must_use]
    /// first rtn operand
    pub fn v0(&self) -> &[u8; 31] {
        &self.v0
    }

    #[must_use]
    /// second rtn operand
    pub fn v0_len(&self) -> u8 {
        self.v0_len
    }

    #[must_use]
    /// first rtn operand len
    pub fn v1(&self) -> &[u8; 31] {
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
pub struct CmpLogInstruction(u64, u64);

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
    operands: [[AFLppCmpLogOperands; AFLPP_CMPLOG_MAP_H]; AFLPP_CMPLOG_MAP_W],
    fn_operands: [[AFLppCmpLogFnOperands; AFL_CMPLOG_MAP_RTN_H]; AFLPP_CMPLOG_MAP_W],
}

impl Debug for AFLppCmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AFLppCmpLogVals").finish_non_exhaustive()
    }
}

impl AFLppCmpLogVals {
    #[must_use]
    /// Reference comparison values as comparison operands
    pub fn operands(&self) -> &[[AFLppCmpLogOperands; AFLPP_CMPLOG_MAP_H]; AFLPP_CMPLOG_MAP_W] {
        unsafe { &self.operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison operands
    pub fn operands_mut(
        &mut self,
    ) -> &mut [[AFLppCmpLogOperands; AFLPP_CMPLOG_MAP_H]; AFLPP_CMPLOG_MAP_W] {
        unsafe { &mut self.operands }
    }

    #[must_use]
    /// Reference comparison values as comparison function operands
    pub fn fn_operands(
        &self,
    ) -> &[[AFLppCmpLogFnOperands; AFL_CMPLOG_MAP_RTN_H]; AFLPP_CMPLOG_MAP_W] {
        unsafe { &self.fn_operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison function operands
    pub fn fn_operands_mut(
        &mut self,
    ) -> &mut [[AFLppCmpLogFnOperands; AFL_CMPLOG_MAP_RTN_H]; AFLPP_CMPLOG_MAP_W] {
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
        unsafe { core::mem::zeroed() }
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
                    ))),
                    2 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].0 as u16,
                        self.vals.operands[idx][execution].1 as u16,
                    ))),
                    4 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].0 as u32,
                        self.vals.operands[idx][execution].1 as u32,
                    ))),
                    8 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].0,
                        self.vals.operands[idx][execution].1,
                    ))),
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                Some(CmpValues::Bytes((
                    self.vals.routines[idx][execution].0.to_vec(),
                    self.vals.routines[idx][execution].1.to_vec(),
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
pub static mut libafl_cmplog_map: CmpLogMap = CmpLogMap {
    headers: [CmpLogHeader {
        hits: 0,
        shape: 0,
        kind: 0,
    }; CMPLOG_MAP_W],
    vals: CmpLogVals {
        operands: [[CmpLogInstruction(0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W],
    },
};

/// The globale `CmpLog` map, aflpp style
#[no_mangle]
#[allow(clippy::large_stack_arrays)]
pub static mut libafl_cmplog_map_extended: AFLppCmpLogMap = AFLppCmpLogMap {
    headers: [AFLppCmpLogHeader { data: [0; 8] }; CMPLOG_MAP_W],
    vals: AFLppCmpLogVals {
        operands: [[AFLppCmpLogOperands {
            v0: 0,
            v1: 0,
            v0_128: 0,
            v1_128: 0,
        }; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    },
};

pub use libafl_cmplog_map as CMPLOG_MAP;
pub use libafl_cmplog_map_extended as CMPLOG_MAP_EXTENDED;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison map compatible with AFL++ cmplog instrumentation
pub struct AFLppCmpLogMap {
    headers: [AFLppCmpLogHeader; AFLPP_CMPLOG_MAP_W],
    vals: AFLppCmpLogVals,
}

impl AFLppCmpLogMap {
    #[must_use]
    /// Instantiate a new boxed zeroed `AFLppCmpLogMap`. This should be used to create a new
    /// map, because it is so large it cannot be allocated on the stack with default
    /// runtime configuration.
    pub fn boxed() -> Box<Self> {
        unsafe {
            Box::from_raw(alloc_zeroed(Layout::new::<AFLppCmpLogMap>()) as *mut AFLppCmpLogMap)
        }
    }

    #[must_use]
    /// Reference the headers for the map
    pub fn headers(&self) -> &[AFLppCmpLogHeader] {
        &self.headers
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn headers_mut(&mut self) -> &mut [AFLppCmpLogHeader] {
        &mut self.headers
    }

    #[must_use]
    /// Reference the values for the map
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
        let slice = unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        };
        serializer.serialize_bytes(slice)
    }
}

impl<'de> Deserialize<'de> for AFLppCmpLogMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let map: Self = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
        Ok(map)
    }
}

impl CmpMap for AFLppCmpLogMap {
    fn len(&self) -> usize {
        AFLPP_CMPLOG_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits() as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx]._type() == AFL_CMP_TYPE_INS {
            if self.executions_for(idx) < AFLPP_CMPLOG_MAP_H {
                self.executions_for(idx)
            } else {
                AFLPP_CMPLOG_MAP_H
            }
        } else if self.executions_for(idx) < AFL_CMPLOG_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            AFL_CMPLOG_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        if self.headers[idx]._type() == AFL_CMP_TYPE_INS {
            unsafe {
                match self.headers[idx].shape() {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].v0 as u8,
                        self.vals.operands[idx][execution].v1 as u8,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].v0 as u16,
                        self.vals.operands[idx][execution].v1 as u16,
                    ))),
                    3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].v0 as u32,
                        self.vals.operands[idx][execution].v1 as u32,
                    ))),
                    7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].v0,
                        self.vals.operands[idx][execution].v1,
                    ))),
                    // TODO handle 128 bits cmps
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                let v0_len = self.vals.fn_operands[idx][execution].v0_len & (0x80 - 1);
                let v1_len = self.vals.fn_operands[idx][execution].v1_len & (0x80 - 1);
                Some(CmpValues::Bytes((
                    self.vals.fn_operands[idx][execution].v0[..(v0_len as usize)].to_vec(),
                    self.vals.fn_operands[idx][execution].v1[..(v1_len as usize)].to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(AFLppCmpLogHeader { data: [0; 8] });

        Ok(())
    }
}
