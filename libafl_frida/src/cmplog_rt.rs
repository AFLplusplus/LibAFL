use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use nix::{
    libc::{memmove, memset},
    sys::mman::{mmap, MapFlags, ProtFlags},
};
use std::ffi::c_void;

// TODO compile time flag
//pub const CMPLOG_MAP_W: usize = 65536;
pub const CMPLOG_MAP_W: usize = 8000;
pub const CMPLOG_MAP_H: usize = 32;
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

pub const CMPLOG_KIND_INS: u8 = 0;
pub const CMPLOG_KIND_RTN: u8 = 1;

extern crate libafl_targets;
extern "C" {
    pub fn __sanitizer_cov_trace_cmp8(arg1: u64, arg2: u64);
}

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
    operands: [CmpLogOperands; CMPLOG_MAP_W],
}

#[no_mangle]
pub static mut libafl_cmplog_map: CmpLogMap = CmpLogMap {
    headers: [CmpLogHeader {
        hits: 0,
        shape: 0,
        kind: 0,
    }; CMPLOG_MAP_W],
    operands: [CmpLogOperands(0, 0); CMPLOG_MAP_W],
};

pub use libafl_cmplog_map as CMPLOG_MAP;

#[no_mangle]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

pub struct CmpLogRuntime {
    regs: [u64; 2],
    cmp_idx: usize,
    cmplog_map: CmpLogMap,
    ops_save_register_and_blr_to_populate: Option<Box<[u8]>>,
}

impl CmpLogRuntime {
    pub fn new() -> CmpLogRuntime {
        Self {
            regs: [0; 2],
            cmp_idx: 0,
            cmplog_map: CmpLogMap {
                headers: [CmpLogHeader {
                    hits: 0,
                    shape: 0,
                    kind: 0,
                }; CMPLOG_MAP_W],
                operands: [CmpLogOperands(0, 0); CMPLOG_MAP_W],
            },
            ops_save_register_and_blr_to_populate: None,
        }
    }

    extern "C" fn populate_lists(&mut self) {
        let op1 = self.regs[0];
        let op2 = self.regs[1];

        self.cmplog_map.headers[self.cmp_idx].hits += 1;
        self.cmplog_map.headers[self.cmp_idx].shape = 8;
        let cmplog_ops: CmpLogOperands = CmpLogOperands(op1, op2);
        self.cmplog_map.operands[self.cmp_idx] = cmplog_ops;
        self.cmp_idx += 1;
    }

    /// Generate the instrumentation blobs for the current arch.
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! blr_to_populate {
            ($ops:ident, $bit:expr) => {dynasm!($ops
                ; .arch aarch64
                ; stp x2, x3, [sp, #-0x10]!
                ; stp x4, x5, [sp, #-0x10]!
                ; stp x6, x7, [sp, #-0x10]!
                ; stp x8, x9, [sp, #-0x10]!
                ; stp x10, x11, [sp, #-0x10]!
                ; stp x12, x13, [sp, #-0x10]!
                ; stp x14, x15, [sp, #-0x10]!
                ; stp x16, x17, [sp, #-0x10]!
                ; stp x18, x19, [sp, #-0x10]!
                ; stp x20, x21, [sp, #-0x10]!
                ; stp x22, x23, [sp, #-0x10]!
                ; stp x24, x25, [sp, #-0x10]!
                ; stp x26, x27, [sp, #-0x10]!
                ; stp x28, x29, [sp, #-0x10]!
                ; stp x30, xzr, [sp, #-0x10]!
              // jump to rust based population of the lists
              //  ; ldr x2, >self_regs_addr
              //  ; stp x0, x1, [x2]
              // jump to c implementation of cmplog pupolation
                ; ldr x2, >populate_lists
                ; blr x2
                ; ldp x30, xzr, [sp], #0x10
                ; ldp x28, x29, [sp], #0x10
                ; ldp x26, x27, [sp], #0x10
                ; ldp x24, x25, [sp], #0x10
                ; ldp x22, x23, [sp], #0x10
                ; ldp x20, x21, [sp], #0x10
                ; ldp x18, x19, [sp], #0x10
                ; ldp x16, x17, [sp], #0x10
                ; ldp x14, x15, [sp], #0x10
                ; ldp x12, x13, [sp], #0x10
                ; ldp x10, x11, [sp], #0x10
                ; ldp x8, x9, [sp], #0x10
                ; ldp x6, x7, [sp], #0x10
                ; ldp x4, x5, [sp], #0x10
                ; ldp x2, x3, [sp], #0x10
                ; b >done
                ; self_regs_addr: //for rust based population of the lists..
                ; .qword &mut self.regs as *mut _ as *mut c_void as i64
                ; populate_lists:
                ; .qword __sanitizer_cov_trace_cmp8 as *mut c_void as i64
                ; done:
            );};
        }

        let mut ops_save_register_and_blr_to_populate =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        blr_to_populate!(ops_save_register_and_blr_to_populate, 0);

        self.ops_save_register_and_blr_to_populate = Some(
            ops_save_register_and_blr_to_populate
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );
    }
    pub fn init(&mut self) {
        // workaround frida's frida-gum-allocate-near bug:
        unsafe {
            for _ in 0..64 {
                mmap(
                    std::ptr::null_mut(),
                    128 * 1024,
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    -1,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
                mmap(
                    std::ptr::null_mut(),
                    4 * 1024 * 1024,
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    -1,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
            }
        }

        self.generate_instrumentation_blobs();
    }

    /// Get the blob which saves the context, jumps to the populate function and restores the context
    #[inline]
    pub fn ops_save_register_and_blr_to_populate(&self) -> &[u8] {
        self.ops_save_register_and_blr_to_populate.as_ref().unwrap()
    }
}
