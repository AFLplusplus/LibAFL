use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use std::ffi::c_void;

#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};

use frida_gum::{
    instruction_writer::InstructionWriter,
    stalker::{StalkerOutput, Transformer},
    ModuleDetails, ModuleMap,
};

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

pub struct CoverageRuntime {
    map: [u8; MAP_SIZE],
    previous_pc: [u64; 1],
    current_log_impl: u64,
    maybe_log_blob: Option<Box<[u8]>>,
}

impl CoverageRuntime {
    pub fn new() -> Self {
        Self {
            map: [0u8; MAP_SIZE],
            previous_pc: [0u64; 1],
            current_log_impl: 0,
            maybe_log_blob: None,
        }
    }

    pub fn init() {}

    pub fn map_ptr(&mut self) -> *mut u8 {
        self.map.as_mut_ptr()
    }

    pub fn generate_maybe_log_blob(&mut self) -> Box<[u8]> {
        macro_rules! maybe_log{
            ($ops:ident) => {dynasm!($ops
                ;   .arch x64
                ;   pushfq
                ;   push rax
                ;   push rcx
                ;   push rdx
                ;   lea rax, [>map_addr]
                ;   mov rax, QWORD [rax]
                ;   lea rcx, [>previous_loc]
                ;   mov rdx, QWORD [rcx]
                ;   mov rdx, QWORD [rdx]
                ;   xor rdx, rdi
                ;   inc BYTE [rax + rdx]
                ;   shr rdi, 1
                ;   mov rax, QWORD [rcx]
                ;   mov QWORD [rax], rdi
                ;   pop rdx
                ;   pop rcx
                ;   pop rax
                ;   popfq
                ;   ret
                ;map_addr:
                ;.qword &mut self.map as *mut _ as *mut c_void as i64
                ;previous_loc:
                ;.qword 0
            );};
        }
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        maybe_log!(ops);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 8].to_vec().into_boxed_slice() //????
    }

    #[inline]
    pub fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let writer = output.writer();
        #[allow(clippy::cast_possible_wrap)] // gum redzone size is u32, we need an offset as i32.
        let redzone_size = i64::from(frida_gum_sys::GUM_RED_ZONE_SIZE);
        if self.current_log_impl == 0
            || !writer.can_branch_directly_to(self.current_log_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_log_impl)
        {
            let after_log_impl = writer.code_offset() + 1;

            #[cfg(target_arch = "x86_64")]
            writer.put_jmp_near_label(after_log_impl);
            #[cfg(target_arch = "aarch64")]
            writer.put_b_label(after_log_impl);

            self.current_log_impl = writer.pc();
            writer.put_bytes(&self.maybe_log_blob);
            let prev_loc_pointer = self.previous_pc.as_ptr() as usize;
            let map_pointer = self.map.as_ptr() as usize;

            writer.put_bytes(&map_pointer.to_ne_bytes());
            writer.put_bytes(&prev_loc_pointer.to_ne_bytes());

            writer.put_label(after_log_impl);
        }
        #[cfg(target_arch = "x86_64")]
        {
            writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, -(redzone_size));
            writer.put_push_reg(X86Register::Rdi);
            writer.put_mov_reg_address(
                X86Register::Rdi,
                ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 1) as u64,
            );
            writer.put_call_address(self.current_log_impl);
            writer.put_pop_reg(X86Register::Rdi);
            writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, redzone_size);
        }
        #[cfg(target_arch = "aarch64")]
        {
            writer.put_stp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                -(16 + redzone_size) as i64,
                IndexMode::PreAdjust,
            );
            writer.put_ldr_reg_u64(
                Aarch64Register::X0,
                ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 1) as u64,
            );
            writer.put_bl_imm(self.current_log_impl);
            writer.put_ldp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                16 + redzone_size as i64,
                IndexMode::PostAdjust,
            );
        }
    }
}
