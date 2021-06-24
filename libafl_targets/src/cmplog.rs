//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.

use libafl::{
    bolts::{ownedref::OwnedRefMut, tuples::Named},
    observers::{CmpMap, CmpObserver, CmpValues, Observer},
    state::HasMetadata,
    Error,
};

use serde::{Deserialize, Serialize};

use crate::{CMPLOG_MAP_H, CMPLOG_MAP_W};

/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// The size of a logged routine argument in bytes
pub const CMPLOG_RTN_LEN: usize = 32;

pub const CMPLOG_MAP_RTN_H: usize = (CMPLOG_MAP_H * core::mem::size_of::<CmpLogOperands>()) / core::mem::size_of::<CmpLogRoutine>();

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` return kind
pub const CMPLOG_KIND_RTN: u8 = 1;

big_array! { BigArray; }

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub struct CmpLogHeader {
    hits: u16,
    shape: u8,
    kind: u8,
}

/// The operands logged during `CmpLog`.
#[repr(C)]
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub struct CmpLogOperands(u64, u64);

/// The routine arguments logged during `CmpLog`.
#[repr(C)]
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub struct CmpLogRoutine([u8; CMPLOG_RTN_LEN], [u8; CMPLOG_RTN_LEN]);

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub union CmpLogVals {
    #[serde(with = "BigArray")]
    operands: [[CmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    #[serde(with = "BigArray")]
    routines: [[CmpLogRoutine; CMPLOG_MAP_RTN_H]; CMPLOG_MAP_W],
}

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct CmpLogMap {
    #[serde(with = "BigArray")]
    headers: [CmpLogHeader; CMPLOG_MAP_W],
    vals: CmpLogVals,
}

impl Default for CmpLogMap {
    fn default() -> Self {
        Self {
            headers: [CmpLogHeader {
                hits: 0,
                shape: 0,
                kind: 0,
            }; CMPLOG_MAP_W],
            operands: [[CmpLogOperands(0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W],
        }
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
        if self.executions_for(idx) < CMPLOG_MAP_H {
            self.executions_for(idx)
        } else {
            CMPLOG_MAP_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> CmpValues {
        if self.headers[idx].kind == CMPLOG_KIND_INS {
            match self.headers[idx].shape {
                1 => {
                    return CmpValues::U8((
                        self.vals.operands[idx][execution].0 as u8,
                        self.vals.operands[idx][execution].1 as u8,
                    ))
                }
                2 => {
                    return CmpValues::U16((
                        self.vals.operands[idx][execution].0 as u16,
                        self.vals.operands[idx][execution].1 as u16,
                    ))
                }
                4 => {
                    return CmpValues::U32((
                        self.vals.operands[idx][execution].0 as u32,
                        self.vals.operands[idx][execution].1 as u32,
                    ))
                }
                8 => {
                    return CmpValues::U64((
                        self.vals.operands[idx][execution].0 as u64,
                        self.vals.operands[idx][execution].1 as u64,
                    ))
                }
                _ => {}
            };
        }
        // TODO bytes
        CmpValues::Bytes((vec![], vec![]))
    }

    fn reset(&mut self) -> Result<(), Error> {
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
    operands: [[CmpLogOperands(0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W],
};

pub use libafl_cmplog_map as CMPLOG_MAP;

/// Value indicating if cmplog is enabled.
#[no_mangle]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

/// A [`CmpObserver`] observer for `CmpLog`
#[derive(Serialize, Deserialize, Debug)]
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

    fn map(&self) -> &CmpLogMap {
        self.map.as_ref()
    }

    fn map_mut(&mut self) -> &mut CmpLogMap {
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

    fn post_exec(&mut self, state: &mut S, _input: &I) -> Result<(), Error> {
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
