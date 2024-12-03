//! Functionality regarding binary-only coverage collection.

use std::{cell::RefCell, marker::PhantomPinned, pin::Pin, rc::Rc};

#[cfg(target_arch = "aarch64")]
use dynasmrt::DynasmLabelApi;
use dynasmrt::{dynasm, DynasmApi};
use frida_gum::{instruction_writer::InstructionWriter, stalker::StalkerOutput, ModuleMap};
use libafl_bolts::hash_std;
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageRuntimeInner {
    map: [u8; MAP_SIZE],
    previous_pc: u64,
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
        _ranges: &RangeMap<u64, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
    }

    fn deinit(&mut self, _gum: &frida_gum::Gum) {}

    fn pre_exec(&mut self, _input_bytes: &[u8]) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec(&mut self, _input_bytes: &[u8]) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl CoverageRuntime {
    /// Create a new coverage runtime
    #[must_use]
    #[allow(clippy::large_stack_arrays)]
    pub fn new() -> Self {
        Self(Rc::pin(RefCell::new(CoverageRuntimeInner {
            map: [0_u8; MAP_SIZE],
            previous_pc: 0,
            _pinned: PhantomPinned,
        })))
    }

    /// Retrieve the coverage map pointer
    pub fn map_mut_ptr(&mut self) -> *mut u8 {
        self.0.borrow_mut().map.as_mut_ptr()
    }

    /// A minimal `maybe_log` implementation. We insert this into the transformed instruction stream
    /// every time we need a copy that is within a direct branch of the start of the transformed basic
    /// block.
    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::cast_possible_wrap)]
    pub fn generate_inline_code(&mut self, h64: u64) -> Box<[u8]> {
        let mut borrow = self.0.borrow_mut();
        let prev_loc_ptr = &raw mut borrow.previous_pc;
        let map_addr_ptr = &raw mut borrow.map;
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops
            ;   .arch aarch64
            // Store the context
            ;   b >start

            ;   stp x16, x17, [sp, -0x90]!
            ; start:

            // Load the previous_pc
            ;   ldr x17, >previous_loc
            ;   ldr x17, [x17]

            // Caltulate the edge id
            ;   ldr x16, >loc
            ;   eor x16, x17, x16

            // Load the map byte address
            ;   ldr x17, >map_addr
            ;   add x16, x17, x16

            // Update the map byte
            ;   ldrb w17, [x16]
            ;   add w17, w17, #1
            ;   add x17, x17, x17, lsr #8
            ;   strb w17, [x16]

            // Update the previous_pc value
            ;   ldr x16, >loc_shr
            ;   ldr x17, >previous_loc
            ;   str x16, [x17]

            // Restore the context
            ;   ldp x16, x17, [sp], #0x90

            // Skip the data
            ;   b >end

            ;map_addr:
            ;.i64 map_addr_ptr as i64
            ;previous_loc:
            ;.i64 prev_loc_ptr as i64
            ;loc:
            ;.i64 h64 as i64
            ;loc_shr:
            ;.i64 (h64 >> 1) as i64
            ;end:
        );
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Write inline instrumentation for coverage
    #[cfg(target_arch = "x86_64")]
    pub fn generate_inline_code(&mut self, h64: u64) -> Box<[u8]> {
        let mut borrow = self.0.borrow_mut();
        let prev_loc_ptr = &raw mut borrow.previous_pc;
        let map_addr_ptr = &raw mut borrow.map;
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        dynasm!(ops
            ;   .arch x64
            // Store the context
            ; mov    QWORD [rsp-0x88], rax
            ; lahf
            ; mov    QWORD [rsp-0x90], rax
            ; mov    QWORD [rsp-0x98], rbx

            // Load the previous_pc
            ; mov rax, QWORD prev_loc_ptr as _
            ; mov rax, QWORD [rax]

            // Calculate the edge id
            ; mov ebx, WORD h64 as i32
            ; xor rax, rbx

            // Load the map byte address
            ; mov rbx, QWORD map_addr_ptr as _
            ; add rax, rbx

            // Update the map byte
            ; mov bl, BYTE [rax]
            ; add bl,0x1
            ; adc bl,0x0
            ; mov BYTE [rax],bl

            // Update the previous_pc value
            ; mov rax, QWORD prev_loc_ptr as _
            ; mov ebx, WORD (h64 >> 1) as i32
            ; mov QWORD [rax], rbx

            // Restore the context
            ; mov    rbx, QWORD [rsp-0x98]
            ; mov    rax, QWORD [rsp-0x90]
            ; sahf
            ; mov    rax, QWORD [rsp-0x88]
        );
        let ops_vec = ops.finalize().unwrap();

        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Emits coverage mapping into the current basic block.
    #[inline]
    pub fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let h64 = hash_std(&address.to_le_bytes());
        let writer = output.writer();

        // Since the AARCH64 instruction set requires that a register be used if
        // performing a long branch, if the Stalker engine is unable to use a near
        // branch to transition between branches, then it spills some registers
        // into the stack beyond the red-zone so that it can use them to perform
        // the branch. Accordingly each block is transparently prefixed with an
        // instruction to restore these registers. If however a near branch can
        // be used, then this instruction is simply skipped and Stalker simply
        // branches to the second instruction in the block.
        //
        // Since we also need to spill some registers in order to update our
        // coverage map, in the event of a long branch, we can simply re-use
        // these spilt registers. This, however, means we need to reset the
        // code writer so that we can overwrite the so-called "restoration
        // prologue".
        #[cfg(target_arch = "aarch64")]
        {
            let pc = writer.pc();
            writer.reset(pc - 4);
        }

        let code = self.generate_inline_code(h64 & (MAP_SIZE as u64 - 1));
        writer.put_bytes(&code);
    }
}
