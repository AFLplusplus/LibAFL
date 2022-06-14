use capstone::prelude::*;
use libafl::{inputs::Input, state::HasMetadata};
use std::pin::Pin;

use crate::{
    capstone,
    emu::Emulator,
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
    S: HasMetadata,
{
    fn init_hooks<'a, QT>(&self, hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        hooks.block_generation(gen_blocks_calls::<I, QT, S>);
    }
}

extern "C" fn on_call(pc: u64) {
    eprintln!("CALL @ 0x{:#x}", pc)
}

extern "C" fn on_ret(pc: u64) {
    eprintln!("RET @ 0x{:#x}", pc)
}

pub fn gen_blocks_calls<I, QT, S>(
    emulator: &Emulator,
    helpers: &mut QT,
    _state: Option<&mut S>,
    pc: u64,
) -> Option<u64>
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if let Some(h) = helpers.match_first_type::<QemuCallTracerHelper>() {
        if !h.must_instrument(pc) {
            return None;
        }

        let mut code = unsafe { std::slice::from_raw_parts(emulator.g2h(pc), 512) };
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
                        emulator.set_hook(insn.address() as GuestAddr, on_call, insn.address());
                    }
                    capstone::InsnGroupType::CS_GRP_RET => {
                        emulator.set_hook(insn.address() as GuestAddr, on_ret, insn.address());
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
            code = unsafe { std::slice::from_raw_parts(emulator.g2h(iaddr), 512) };
        }
    }

    None
}
