use capstone::prelude::*;
use libafl::inputs::Input;

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
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }

    pub fn callstack(&self) -> &[GuestAddr] {
        &self.callstack
    }

    pub fn reset(&mut self) {
        self.callstack.clear()
    }
}

impl Default for QemuCallTracerHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<I, S> QemuHelper<I, S> for QemuCallTracerHelper
where
    I: Input,
{
    fn init_hooks<'a, QT>(&self, hooks: &QemuHooks<'a, I, QT, S>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        hooks.blocks(Some(gen_blocks_calls::<I, QT, S>), None);
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &I) {
        self.reset();
    }
}

/*pub fn on_call<I, QT, S>(hooks: &mut QemuHooks<'_, I, QT, S>, _state: Option<&mut S>, pc: GuestAddr)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
}*/

pub fn on_ret<I, QT, S>(hooks: &mut QemuHooks<'_, I, QT, S>, _state: Option<&mut S>, _pc: GuestAddr)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
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

    // eprintln!("RET @ 0x{:#x}", ret_addr);

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

pub fn gen_blocks_calls<I, QT, S>(
    hooks: &mut QemuHooks<'_, I, QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let emu = hooks.emulator();
    if let Some(h) = hooks.helpers().match_first_type::<QemuCallTracerHelper>() {
        if !h.must_instrument(pc) {
            return None;
        }

        let mut code = unsafe { std::slice::from_raw_parts(emu.g2h(pc), 512) };
        let mut iaddr = pc;

        'disasm: while let Ok(insns) = h.cs.disasm_count(code, iaddr, 1) {
            if insns.is_empty() {
                break;
            }
            let insn = insns.first().unwrap();
            let insn_detail: InsnDetail = h.cs.insn_detail(insn).unwrap();
            for detail in insn_detail.groups() {
                match detail.0 as u32 {
                    capstone::InsnGroupType::CS_GRP_CALL => {
                        // hooks.instruction_closure(insn.address() as GuestAddr, on_call, false);
                        let call_len = insn.bytes().len() as GuestAddr;
                        let call_cb = move |hooks: &mut QemuHooks<'_, I, QT, S>, _, pc| {
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

            iaddr += insn.bytes().len() as u64;
            code = unsafe { std::slice::from_raw_parts(emu.g2h(iaddr), 512) };
        }
    }

    None
}
