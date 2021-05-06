//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.

// TODO compile time flag
/// The `CmpLogMap` W value
pub const CMPLOG_MAP_W: usize = 65536;
/// The `CmpLogMap` H value
pub const CMPLOG_MAP_H: usize = 32;
/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` return kind
pub const CMPLOG_KIND_RTN: u8 = 1;

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogHeader {
    hits: u16,
    shape: u8,
    kind: u8,
}

/// The operands logged during `CmpLog.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogOperands(u64, u64);

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogMap {
    headers: [CmpLogHeader; CMPLOG_MAP_W],
    operands: [[CmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
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
