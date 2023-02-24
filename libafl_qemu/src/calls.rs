use capstone::prelude::*;
use libafl::inputs::UsesInput;

use crate::{
    capstone,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    Emulator, GuestAddr, Regs,
};

#[derive(Debug)]
pub struct QemuCallTracerHelper {
    filter: QemuInstrumentationFilter,
    cs: Capstone,
    callstack: Vec<GuestAddr>,
}

impl QemuCallTracerHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            cs: capstone().detail(true).build().unwrap(),
            callstack: vec![],
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    #[must_use]
    pub fn callstack(&self) -> &[GuestAddr] {
        &self.callstack
    }

    pub fn reset(&mut self) {
        self.callstack.clear();
    }
}

impl Default for QemuCallTracerHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<S> QemuHelper<S> for QemuCallTracerHelper
where
    S: UsesInput,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks(Some(gen_blocks_calls::<QT, S>), None);
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &S::Input) {
        self.reset();
    }
}

/*pub fn on_call<QT, S>(hooks: &mut QemuHooks<'_, QT, S>, _state: Option<&mut S>, pc: GuestAddr)
where

    QT: QemuHelperTuple<S>,
{
}*/

pub fn on_ret<QT, S>(hooks: &mut QemuHooks<'_, QT, S>, _state: Option<&mut S>, _pc: GuestAddr)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    #[cfg(cpu_target = "x86_64")]
    let ret_addr = {
        let emu = hooks.emulator();
        let stack_ptr: GuestAddr = emu.read_reg(Regs::Rsp).unwrap();
        let mut ret_addr = [0; 8];
        unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
        GuestAddr::from_le_bytes(ret_addr)
    };

    #[cfg(cpu_target = "i386")]
    let ret_addr = {
        let emu = hooks.emulator();
        let stack_ptr: GuestAddr = emu.read_reg(Regs::Esp).unwrap();
        let mut ret_addr = [0; 4];
        unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
        GuestAddr::from_le_bytes(ret_addr)
    };

    #[cfg(any(cpu_target = "arm", cpu_target = "aarch64"))]
    let ret_addr = {
        let emu = hooks.emulator();
        let ret_addr: GuestAddr = emu.read_reg(Regs::Lr).unwrap();
        ret_addr
    };

    #[cfg(cpu_target = "mips")]
    let ret_addr = {
        let emu = hooks.emulator();
        let ret_addr: GuestAddr = emu.read_reg(Regs::Ra).unwrap();
        ret_addr
    };

    // log::info!("RET @ 0x{:#x}", ret_addr);

    if let Some(h) = hooks
        .helpers_mut()
        .match_first_type_mut::<QemuCallTracerHelper>()
    {
        while let Some(addr) = h.callstack.pop() {
            if addr == ret_addr {
                break;
            }
        }
    }
}

pub fn gen_blocks_calls<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emu = hooks.emulator();
    if let Some(h) = hooks.helpers().match_first_type::<QemuCallTracerHelper>() {
        if !h.must_instrument(pc) {
            return None;
        }

        #[allow(unused_mut)]
        let mut code = {
            #[cfg(emulation_mode = "usermode")]
            unsafe {
                std::slice::from_raw_parts(emu.g2h(pc), 512)
            }
            #[cfg(emulation_mode = "systemmode")]
            &mut [0; 512]
        };
        #[cfg(emulation_mode = "systemmode")]
        unsafe {
            emu.read_mem(pc, code)
        }; // TODO handle faults

        let mut iaddr = pc;

        'disasm: while let Ok(insns) = h.cs.disasm_count(code, iaddr.into(), 1) {
            if insns.is_empty() {
                break;
            }
            let insn = insns.first().unwrap();
            let insn_detail: InsnDetail = h.cs.insn_detail(insn).unwrap();
            for detail in insn_detail.groups() {
                match u32::from(detail.0) {
                    capstone::InsnGroupType::CS_GRP_CALL => {
                        // hooks.instruction_closure(insn.address() as GuestAddr, on_call, false);
                        let call_len = insn.bytes().len() as GuestAddr;
                        let call_cb = move |hooks: &mut QemuHooks<'_, QT, S>, _, pc| {
                            // eprintln!("CALL @ 0x{:#x}", pc + call_len);
                            if let Some(h) = hooks
                                .helpers_mut()
                                .match_first_type_mut::<QemuCallTracerHelper>()
                            {
                                h.callstack.push(pc + call_len);
                            }
                        };
                        unsafe {
                            hooks.instruction_closure(
                                insn.address() as GuestAddr,
                                Box::new(call_cb),
                                false,
                            );
                        }
                    }
                    capstone::InsnGroupType::CS_GRP_RET => {
                        hooks.instruction(insn.address() as GuestAddr, on_ret, false);
                        break 'disasm;
                    }
                    capstone::InsnGroupType::CS_GRP_INVALID
                    | capstone::InsnGroupType::CS_GRP_JUMP
                    | capstone::InsnGroupType::CS_GRP_IRET
                    | capstone::InsnGroupType::CS_GRP_PRIVILEGE => {
                        break 'disasm;
                    }
                    _ => {}
                }
            }

            iaddr += insn.bytes().len() as GuestAddr;

            #[cfg(emulation_mode = "usermode")]
            unsafe {
                code = std::slice::from_raw_parts(emu.g2h(iaddr), 512);
            }
            #[cfg(emulation_mode = "systemmode")]
            unsafe {
                emu.read_mem(pc, code);
            } // TODO handle faults
        }
    }

    None
}
