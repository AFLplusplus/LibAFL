// TODO compile time flag
pub const CMPLOG_MAP_W: usize = 65536;
pub const CMPLOG_MAP_H: usize = 32;
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

pub const CMPLOG_KIND_INS: u8 = 0;
pub const CMPLOG_KIND_RTN: u8 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogHeader {
    hits: u16,
    shape: u8,
    kind: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogOperands(u64, u64);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogMap {
    headers: [CmpLogHeader; CMPLOG_MAP_W],
    operands: [[CmpLogOperands; CMPLOG_MAP_H]; CMPLOG_MAP_W],
}

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

#[no_mangle]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;
