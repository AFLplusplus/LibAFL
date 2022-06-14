use capstone::prelude::*;
use libafl::inputs::Input;

use crate::{
    capstone,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    GuestAddr,
};

#[derive(Debug)]
pub struct QemuCallTracerHelper {
    filter: QemuInstrumentationFilter,
    cs: Capstone,
}

impl QemuCallTracerHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            cs: capstone().detail(true).build().unwrap(),
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
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
}

pub fn on_call<I, QT, S>(hooks: &mut QemuHooks<'_, I, QT, S>, _state: Option<&mut S>, pc: GuestAddr)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    //eprintln!("CALL @ 0x{:#x}", pc)
}

pub fn on_ret<I, QT, S>(hooks: &mut QemuHooks<'_, I, QT, S>, _state: Option<&mut S>, pc: GuestAddr)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    //eprintln!("RET @ 0x{:#x}", pc)
}

pub fn gen_blocks_calls<I, QT, S>(
    hooks: &mut QemuHooks<'_, I, QT, S>,
    _state: Option<&mut S>,
    pc: u64,
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
                        hooks.instruction(insn.address() as GuestAddr, on_call, false);
                    }
                    capstone::InsnGroupType::CS_GRP_RET => {
                        hooks.instruction(insn.address() as GuestAddr, on_ret, false);
                        break 'disasm;
                    }
                    capstone::InsnGroupType::CS_GRP_INVALID
                    | capstone::InsnGroupType::CS_GRP_JUMP
                    | capstone::InsnGroupType::CS_GRP_IRET => {
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
