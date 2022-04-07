//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.
//!

use core::fmt::{self, Debug, Formatter};

use libafl::{
    bolts::{ownedref::OwnedRefMut, tuples::Named},
    executors::ExitKind,
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

impl<'a, I, S> CmpObserver<CmpLogMap, I, S> for CmpLogObserver<'a>
where
    S: HasMetadata,
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

impl<'a, I, S> Observer<I, S> for CmpLogObserver<'a>
where
    S: HasMetadata,
    Self: CmpObserver<CmpLogMap, I, S>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.map.as_mut().reset()?;
        unsafe {
            CMPLOG_ENABLED = 1;
        }
        Ok(())
    }

    fn post_exec(&mut self, state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
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
