//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.

use libafl::{
    observers::{CmpMap, CmpValues},
    Error,
};
use serde::{Deserialize, Serialize};

// TODO compile time flag
/// The `CmpLogMap` W value
pub const CMPLOG_MAP_W: usize = 65536;
/// The `CmpLogMap` H value
pub const CMPLOG_MAP_H: usize = 32;
/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

big_array! { BigArray; }

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` return kind
pub const CMPLOG_KIND_RTN: u8 = 1;

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

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CmpLogMap {
    #[serde(with = "BigArray")]
    headers: [CmpLogHeader; CMPLOG_MAP_W],
    #[serde(with = "BigArray")]
    operands: [[CmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
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
                        self.operands[idx][execution].0 as u8,
                        self.operands[idx][execution].1 as u8,
                    ))
                }
                2 => {
                    return CmpValues::U16((
                        self.operands[idx][execution].0 as u16,
                        self.operands[idx][execution].1 as u16,
                    ))
                }
                4 => {
                    return CmpValues::U32((
                        self.operands[idx][execution].0 as u32,
                        self.operands[idx][execution].1 as u32,
                    ))
                }
                8 => {
                    return CmpValues::U64((
                        self.operands[idx][execution].0 as u64,
                        self.operands[idx][execution].1 as u64,
                    ))
                }
                _ => {}
            };
        }
        // TODO bytes
        CmpValues::Bytes((vec![], vec![]))
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.headers = [CmpLogHeader {
            hits: 0,
            shape: 0,
            kind: 0,
        }; CMPLOG_MAP_W];
        self.operands = [[CmpLogOperands(0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W];
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
