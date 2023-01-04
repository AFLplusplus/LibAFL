//! Functionality regarding binary-only coverage collection.
use core::ptr::addr_of_mut;
use std::{
    cell::{Ref, RefCell},
    marker::PhantomPinned,
    ops::Deref,
    pin::Pin,
    rc::Rc,
};

#[cfg(target_arch = "aarch64")]
use dynasmrt::DynasmLabelApi;
use dynasmrt::{dynasm, DynasmApi};
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86InstructionWriter;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};
use frida_gum::{instruction_writer::InstructionWriter, stalker::StalkerOutput};
use libafl::bolts::xxh3_rrmxmx_mixer;
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageRuntimeInner {
    map: [u8; MAP_SIZE],
    previous_pc: u64,
    #[cfg(target_arch = "aarch64")]
    current_log_impl: u64,
    blob_maybe_log: Option<Box<[u8]>>,
    _pinned: PhantomPinned,
}

/// Frida binary-only coverage
#[derive(Debug)]
pub struct CoverageRuntime(Pin<Rc<RefCell<CoverageRuntimeInner>>>);

impl Default for CoverageRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl FridaRuntime for CoverageRuntime {
    /// Initialize the coverage runtime
    /// The struct MUST NOT be moved after this function is called, as the generated assembly references it
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _modules_to_instrument: &[&str],
    ) {
        #[cfg(target_arch = "aarch64")]
        self.generate_maybe_log_blob();
    }

    fn pre_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl CoverageRuntime {
    /// Create a new coverage runtime
    #[must_use]
    pub fn new() -> Self {
        Self(Rc::pin(RefCell::new(CoverageRuntimeInner {
            map: [0_u8; MAP_SIZE],
            previous_pc: 0,
            #[cfg(target_arch = "aarch64")]
            current_log_impl: 0,
            blob_maybe_log: None,
            _pinned: PhantomPinned,
        })))
    }

    /// Retrieve the coverage map pointer
    pub fn map_mut_ptr(&mut self) -> *mut u8 {
        self.0.borrow_mut().map.as_mut_ptr()
    }

    /// Retrieve the `maybe_log` code blob, that will write coverage into the map
    #[must_use]
    pub fn blob_maybe_log(&self) -> impl Deref<Target = Box<[u8]>> + '_ {
        Ref::map(self.0.borrow(), |s| s.blob_maybe_log.as_ref().unwrap())
    }

    /// A minimal `maybe_log` implementation. We insert this into the transformed instruction stream
    /// every time we need a copy that is within a direct branch of the start of the transformed basic
    /// block.
    #[cfg(target_arch = "aarch64")]
    pub fn generate_maybe_log_blob(&mut self) {
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops
            ;   .arch aarch64
            ;   stp x1, x2, [sp, -0x10]!
            ;   stp x3, x4, [sp, -0x10]!
            ;   ldr x1, >map_addr
            ;   ldr x2, >previous_loc
            ;   ldr x4, [x2]
            ;   eor x4, x4, x0
            ;   mov x3, u64::from((MAP_SIZE - 1) as u32)
            ;   and x4, x4, x3
            ;   ldr x3, [x1, x4]
            ;   add x3, x3, #1
            ;   str x3, [x1, x4]
            ;   add x0, xzr, x0, LSR #1
            ;   str x0, [x2]
            ;   ldp x3, x4, [sp], #0x10
            ;   ldp x1, x2, [sp], #0x10
            ;   ret
            ;map_addr:
            ;.qword addr_of_mut!(self.0.borrow_mut().map) as i64
            ;previous_loc:
            ;.qword 0
        );
        let ops_vec = ops.finalize().unwrap();
        self.0.borrow_mut().blob_maybe_log =
            Some(ops_vec[..ops_vec.len() - 8].to_vec().into_boxed_slice());
    }

    /// Write inline instrumentation for coverage
    #[cfg(target_arch = "x86_64")]
    pub fn generate_inline_code(&mut self, writer: &X86InstructionWriter, h64: u64) {
        let mut borrow = self.0.borrow_mut();
        let prev_loc_ptr = addr_of_mut!(borrow.previous_pc);
        let map_addr_ptr = addr_of_mut!(borrow.map);
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        dynasm!(ops
            ;   .arch x64
            // Store the context
            ; mov    QWORD [rsp-0x88], rax
            ; lahf
            ; mov    QWORD [rsp-0x90], rax
            ; mov    QWORD [rsp-0x98], rbx

            // Load the previous_pc
            ; mov rax, QWORD prev_loc_ptr as *mut u64 as _
            ; mov rax, QWORD [rax]

            // Calculate the edge id
            ; mov ebx, WORD h64 as i32
            ; xor rax, rbx

            // Load the map byte address
            ; mov rbx, QWORD map_addr_ptr as *mut [u8; MAP_SIZE] as _
            ; add rax, rbx

            // Update the map byte
            ; mov bl, BYTE [rax]
            ; add bl,0x1
            ; adc bl,0x0
            ; mov BYTE [rax],bl

            // Update the previous_pc value
            ; mov rax, QWORD prev_loc_ptr as *mut u64 as _
            ; mov ebx, WORD h64 as i32
            ; mov QWORD [rax], rbx

            // Restore the context
            ; mov    rbx, QWORD [rsp-0x98]
            ; mov    rax, QWORD [rsp-0x90]
            ; sahf
            ; mov    rax, QWORD [rsp-0x88]
        );
        let ops_vec = ops.finalize().unwrap();

        writer.put_bytes(&ops_vec[..ops_vec.len()].to_vec().into_boxed_slice());
    }

    /// Emits coverage mapping into the current basic block.
    #[inline]
    pub fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let h64 = xxh3_rrmxmx_mixer(address);
        let writer = output.writer();

        #[cfg(target_arch = "x86_64")]
        {
            self.generate_inline_code(&writer, h64 & (MAP_SIZE as u64 - 1));
        }
        #[cfg(target_arch = "aarch64")]
        {
            #[allow(clippy::cast_possible_wrap)]
            // gum redzone size is u32, we need an offset as i32.
            let redzone_size = i64::from(frida_gum_sys::GUM_RED_ZONE_SIZE);
            if self.0.borrow().current_log_impl == 0
                || !writer.can_branch_directly_to(self.0.borrow().current_log_impl)
                || !writer.can_branch_directly_between(
                    writer.pc() + 128,
                    self.0.borrow().current_log_impl,
                )
            {
                let after_log_impl = writer.code_offset() + 1;

                #[cfg(target_arch = "x86_64")]
                writer.put_jmp_near_label(after_log_impl);
                #[cfg(target_arch = "aarch64")]
                writer.put_b_label(after_log_impl);

                self.0.borrow_mut().current_log_impl = writer.pc();
                writer.put_bytes(&self.blob_maybe_log());
                let prev_loc_pointer = addr_of_mut!(self.0.borrow_mut().previous_pc) as u64; // Get the pointer to self.previous_pc

                writer.put_bytes(&prev_loc_pointer.to_ne_bytes());

                writer.put_label(after_log_impl);
            }

            writer.put_stp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                -(16 + redzone_size),
                IndexMode::PreAdjust,
            );
            writer.put_ldr_reg_u64(Aarch64Register::X0, h64 & (MAP_SIZE as u64 - 1));

            writer.put_bl_imm(self.0.borrow().current_log_impl);
            writer.put_ldp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                16 + redzone_size,
                IndexMode::PostAdjust,
            );
        }
    }
}
