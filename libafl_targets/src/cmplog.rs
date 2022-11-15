//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.
//!

use alloc::string::{String, ToString};
use core::fmt::{self, Debug, Formatter};

use c2rust_bitfields::BitfieldStruct;
use libafl::{
    bolts::{ownedref::OwnedRefMut, tuples::Named},
    executors::ExitKind,
    inputs::UsesInput,
    observers::{CmpMap, CmpObserver, CmpValues, Observer},
    state::HasMetadata,
    Error,
};

use crate::{CMPLOG_MAP_H, CMPLOG_MAP_W};

/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// The size of a logged routine argument in bytes
pub const CMPLOG_RTN_LEN: usize = 32;

/// The hight of a cmplog routine map
pub const CMPLOG_MAP_RTN_H: usize = (CMPLOG_MAP_H * core::mem::size_of::<CmpLogInstruction>())
    / core::mem::size_of::<CmpLogRoutine>();

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` return kind
pub const CMPLOG_KIND_RTN: u8 = 1;

// void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2)
extern "C" {
    /// Logs an instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions(k: usize, shape: u8, arg1: u64, arg2: u64);

    /// Pointer to the `CmpLog` map
    pub static mut libafl_cmplog_map_ptr: *mut CmpLogMap;
}

pub use libafl_cmplog_map_ptr as CMPLOG_MAP_PTR;

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogHeader {
    hits: u16,
    shape: u8,
    kind: u8,
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
        self.headers = unsafe { core::mem::zeroed() };
        // self.vals.operands = unsafe { core::mem::zeroed() };
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

pub use libafl_cmplog_map as CMPLOG_MAP;

/// Value indicating if cmplog is enabled.
#[no_mangle]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

/// A [`CmpObserver`] observer for `CmpLog`
#[derive(Debug)]
pub struct CmpLogObserver<'a> {
    map: OwnedRefMut<'a, CmpLogMap>,
    size: Option<OwnedRefMut<'a, usize>>,
    add_meta: bool,
    name: String,
}

impl<'a, S> CmpObserver<CmpLogMap, S> for CmpLogObserver<'a>
where
    S: UsesInput + HasMetadata,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.map.as_ref().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn cmp_map(&self) -> &CmpLogMap {
        self.map.as_ref()
    }

    fn cmp_map_mut(&mut self) -> &mut CmpLogMap {
        self.map.as_mut()
    }
}

impl<'a, S> Observer<S> for CmpLogObserver<'a>
where
    S: UsesInput + HasMetadata,
    Self: CmpObserver<CmpLogMap, S>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.map.as_mut().reset()?;
        unsafe {
            CMPLOG_ENABLED = 1;
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            CMPLOG_ENABLED = 0;
        }
        if self.add_meta {
            self.add_cmpvalues_meta(state);
        }
        Ok(())
    }
}

impl<'a> Named for CmpLogObserver<'a> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a> CmpLogObserver<'a> {
    /// Creates a new [`CmpLogObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut CmpLogMap, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            add_meta,
            map: OwnedRefMut::Ref(map),
        }
    }

    // TODO with_size
}

/* From AFL++ cmplog.h

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 4)

struct cmp_header {

  unsigned hits : 24;
  unsigned id : 24;
  unsigned shape : 5;
  unsigned type : 2;
  unsigned attribute : 4;
  unsigned overflow : 1;
  unsigned reserved : 4;

} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;
  u64 v0_128;
  u64 v1_128;

} __attribute__((packed));

struct cmpfn_operands {

  u8 v0[31];
  u8 v0_len;
  u8 v1[31];
  u8 v1_len;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};
*/

/// The AFL++ `CMP_MAP_W`
pub const AFL_CMP_MAP_W: usize = 65536;
/// The AFL++ `CMP_MAP_H`
pub const AFL_CMP_MAP_H: usize = 32;
/// The AFL++ `CMP_MAP_RTN_H`
pub const AFL_CMP_MAP_RTN_H: usize = AFL_CMP_MAP_H / 4;

/// The AFL++ `CMP_TYPE_INS`
pub const AFL_CMP_TYPE_INS: u32 = 1;
/// The AFL++ `CMP_TYPE_RTN`
pub const AFL_CMP_TYPE_RTN: u32 = 2;

/// The AFL++ `cmp_header` struct
#[derive(Debug, Copy, Clone, BitfieldStruct)]
#[repr(C, packed)]
pub struct AFLCmpHeader {
    #[bitfield(name = "hits", ty = "u32", bits = "0..=23")]
    #[bitfield(name = "id", ty = "u32", bits = "24..=47")]
    #[bitfield(name = "shape", ty = "u32", bits = "48..=52")]
    #[bitfield(name = "_type", ty = "u32", bits = "53..=54")]
    #[bitfield(name = "attribute", ty = "u32", bits = "55..=58")]
    #[bitfield(name = "overflow", ty = "u32", bits = "59..=59")]
    #[bitfield(name = "reserved", ty = "u32", bits = "60..=63")]
    data: [u8; 8],
}

/// The AFL++ `cmp_operands` struct
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLCmpOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

/// The AFL++ `cmpfn_operands` struct
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLCmpFnOperands {
    v0: [u8; 31],
    v0_len: u8,
    v1: [u8; 31],
    v1_len: u8,
}

/// A proxy union to avoid casting operands as in AFL++
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub union AFLCmpVals {
    operands: [[AFLCmpOperands; AFL_CMP_MAP_H]; AFL_CMP_MAP_W],
    fn_operands: [[AFLCmpFnOperands; AFL_CMP_MAP_RTN_H]; AFL_CMP_MAP_W],
}

impl Debug for AFLCmpVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AFLCmpVals").finish_non_exhaustive()
    }
}

/// The AFL++ `cmp_map` struct, use with `libafl::StdCmpObserver`
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLCmpMap {
    headers: [AFLCmpHeader; AFL_CMP_MAP_W],
    vals: AFLCmpVals,
}

impl CmpMap for AFLCmpMap {
    fn len(&self) -> usize {
        AFL_CMP_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits() as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx]._type() == AFL_CMP_TYPE_INS {
            if self.executions_for(idx) < AFL_CMP_MAP_H {
                self.executions_for(idx)
            } else {
                AFL_CMP_MAP_H
            }
        } else if self.executions_for(idx) < AFL_CMP_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            AFL_CMP_MAP_RTN_H
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
                Some(CmpValues::Bytes((
                    self.vals.fn_operands[idx][execution].v0
                        [..self.headers[idx].shape() as usize + 1]
                        .to_vec(),
                    self.vals.fn_operands[idx][execution].v1
                        [..self.headers[idx].shape() as usize + 1]
                        .to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers = unsafe { core::mem::zeroed() };
        // self.vals.operands = unsafe { core::mem::zeroed() };
        Ok(())
    }
}
