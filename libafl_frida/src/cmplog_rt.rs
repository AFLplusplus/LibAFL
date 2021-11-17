use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use libafl_targets::CMPLOG_MAP_W;
use std::ffi::c_void;

extern crate libafl_targets;
extern "C" {
    pub fn __libafl_targets_cmplog_instructions(k: u64, shape: u8, arg1: u64, arg2: u64);
}

pub struct CmpLogRuntime {
    ops_save_register_and_blr_to_populate: Option<Box<[u8]>>,
    ops_handle_tbz_masking: Option<Box<[u8]>>,
    ops_handle_tbnz_masking: Option<Box<[u8]>>,
}

impl CmpLogRuntime {
    #[must_use]
    pub fn new() -> CmpLogRuntime {
        Self {
            ops_save_register_and_blr_to_populate: None,
            ops_handle_tbz_masking: None,
            ops_handle_tbnz_masking: None,
        }
    }

    /// Call the external function that populates the `cmplog_map` with the relevant values
    #[allow(clippy::unused_self)]
    extern "C" fn populate_lists(&mut self, op1: u64, op2: u64, retaddr: u64) {
        // println!(
        //     "entered populate_lists with: {:#02x}, {:#02x}, {:#02x}",
        //     op1, op2, retaddr
        // );
        let mut k = (retaddr >> 4) ^ (retaddr << 8);

        k &= (CMPLOG_MAP_W as u64) - 1;

        unsafe {
            __libafl_targets_cmplog_instructions(k, 8, op1, op2);
        }
    }

    /// Generate the instrumentation blobs for the current arch.
    #[allow(clippy::similar_names)]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! blr_to_populate {
            ($ops:ident) => {dynasm!($ops
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
                ; .dword 0xd53b4218u32 as i32 // mrs x24, nzcv
                // jump to rust based population of the lists
                ; mov x2, x0
                ; adr x3, >done
                ; ldr x4, >populate_lists
                ; ldr x0, >self_addr
                ; blr x4
                // restore the reg state before returning to the caller
                ; .dword 0xd51b4218u32 as i32 // msr nzcv, x24
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
                ; self_addr:
                ; .qword self as *mut _  as *mut c_void as i64
                ; populate_lists:
                ; .qword  CmpLogRuntime::populate_lists as *mut c_void as i64
                ; done:
            );};
        }

        // ldp/stp is more efficient than str/ldr so we use them instead.
        macro_rules! tbz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, x5, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; eor x5, x5, #255
                ; orr x1, x0, x5
                ; ldp x5, x5, [sp], #0x10
            );};
        }

        macro_rules! tbnz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, x5, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; orr x1, x0, x5
                ; ldp x5, x5, [sp], #0x10
            );};

        }

        let mut ops_handle_tbz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbz_masking!(ops_handle_tbz_masking);

        let mut ops_handle_tbnz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbnz_masking!(ops_handle_tbnz_masking);

        let mut ops_save_register_and_blr_to_populate =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        blr_to_populate!(ops_save_register_and_blr_to_populate);

        self.ops_handle_tbz_masking = Some(
            ops_handle_tbz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_handle_tbnz_masking = Some(
            ops_handle_tbnz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_save_register_and_blr_to_populate = Some(
            ops_save_register_and_blr_to_populate
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );
    }
    pub fn init(&mut self) {
        self.generate_instrumentation_blobs();
    }

    /// Get the blob which saves the context, jumps to the populate function and restores the context
    #[inline]
    #[must_use]
    pub fn ops_save_register_and_blr_to_populate(&self) -> &[u8] {
        self.ops_save_register_and_blr_to_populate.as_ref().unwrap()
    }

    /// Get the blob which handles the tbz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbz_masking(&self) -> &[u8] {
        self.ops_handle_tbz_masking.as_ref().unwrap()
    }

    /// Get the blob which handles the tbnz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbnz_masking(&self) -> &[u8] {
        self.ops_handle_tbnz_masking.as_ref().unwrap()
    }
}

impl Default for CmpLogRuntime {
    fn default() -> Self {
        Self::new()
    }
}
