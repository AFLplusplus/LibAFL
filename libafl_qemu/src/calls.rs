use core::fmt::Debug;

use capstone::prelude::*;
use libafl::{
    bolts::tuples::{MatchFirstType, Named},
    executors::ExitKind,
    inputs::{Input, UsesInput},
    observers::{stacktrace::BacktraceObserver, ObserversTuple},
};

use crate::{
    capstone,
    emu::Emulator,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    GuestAddr, Regs,
};

pub trait CallTraceCollector: 'static + Debug {
    fn on_call<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>;

    fn on_ret<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>;

    // Frowarded from the `QemuCallTracerHelper`
    fn pre_exec<I>(&mut self, _emulator: &Emulator, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec<OT, S>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: UsesInput,
    {
    }
}

pub trait CallTraceCollectorTuple: 'static + MatchFirstType + Debug {
    fn on_call_all<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>;

    fn on_ret_all<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>;

    fn pre_exec_all<I>(&mut self, _emulator: &Emulator, input: &I)
    where
        I: Input;

    fn post_exec_all<OT, S>(
        &mut self,
        _emulator: &Emulator,
        input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: UsesInput;
}

impl CallTraceCollectorTuple for () {
    fn on_call_all<QT, S>(
        &mut self,
        _hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _call_len: usize,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
    }

    fn on_ret_all<QT, S>(
        &mut self,
        _hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _ret_addr: GuestAddr,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
    }

    fn pre_exec_all<I>(&mut self, _emulator: &Emulator, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec_all<OT, S>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: UsesInput,
    {
    }
}

impl<Head, Tail> CallTraceCollectorTuple for (Head, Tail)
where
    Head: CallTraceCollector,
    Tail: CallTraceCollectorTuple,
{
    fn on_call_all<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        self.0.on_call(
            hooks,
            match state.as_mut() {
                Some(s) => Some(*s),
                None => None,
            },
            pc,
            call_len,
        );
        self.1.on_call_all(hooks, state, pc, call_len);
    }

    fn on_ret_all<QT, S>(
        &mut self,
        hooks: &mut QemuHooks<'_, QT, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        self.0.on_ret(
            hooks,
            match state.as_mut() {
                Some(s) => Some(*s),
                None => None,
            },
            pc,
            ret_addr,
        );
        self.1.on_ret_all(hooks, state, pc, ret_addr);
    }

    fn pre_exec_all<I>(&mut self, emulator: &Emulator, input: &I)
    where
        I: Input,
    {
        self.0.pre_exec(emulator, input);
        self.1.pre_exec_all(emulator, input);
    }

    fn post_exec_all<OT, S>(
        &mut self,
        emulator: &Emulator,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: UsesInput,
    {
        self.0.post_exec(emulator, input, observers, exit_kind);
        self.1.post_exec_all(emulator, input, observers, exit_kind);
    }
}

#[derive(Debug)]
pub struct QemuCallTracerHelper<T>
where
    T: CallTraceCollectorTuple,
{
    filter: QemuInstrumentationFilter,
    cs: Capstone,
    collectors: Option<T>,
}

impl<T> QemuCallTracerHelper<T>
where
    T: CallTraceCollectorTuple,
{
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter, collectors: T) -> Self {
        Self {
            filter,
            cs: capstone().detail(true).build().unwrap(),
            collectors: Some(collectors),
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    fn on_ret<QT, S>(hooks: &mut QemuHooks<'_, QT, S>, state: Option<&mut S>, pc: GuestAddr)
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

        let mut collectors = if let Some(h) = hooks.helpers_mut().match_first_type_mut::<Self>() {
            h.collectors.take()
        } else {
            return;
        };
        collectors
            .as_mut()
            .unwrap()
            .on_ret_all(hooks, state, pc, ret_addr);
        hooks
            .helpers_mut()
            .match_first_type_mut::<Self>()
            .unwrap()
            .collectors = collectors;
    }

    fn gen_blocks_calls<QT, S>(
        hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        if let Some(h) = hooks.helpers_mut().match_first_type_mut::<Self>() {
            if !h.must_instrument(pc) {
                return None;
            }

            #[cfg(cpu_target = "arm")]
            h.cs.set_mode(if pc & 1 == 1 {
                arch::arm::ArchMode::Thumb.into()
            } else {
                arch::arm::ArchMode::Arm.into()
            })
            .unwrap();
        }

        let emu = hooks.emulator();

        if let Some(h) = hooks.helpers().match_first_type::<Self>() {
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
                            let call_len = insn.bytes().len();
                            // TODO do not use a closure, find a more efficient way to pass call_len
                            let call_cb = move |hooks: &mut QemuHooks<'_, QT, S>,
                                                state: Option<&mut S>,
                                                pc| {
                                // eprintln!("CALL @ 0x{:#x}", pc + call_len);
                                let mut collectors = if let Some(h) =
                                    hooks.helpers_mut().match_first_type_mut::<Self>()
                                {
                                    h.collectors.take()
                                } else {
                                    return;
                                };
                                collectors
                                    .as_mut()
                                    .unwrap()
                                    .on_call_all(hooks, state, pc, call_len);
                                hooks
                                    .helpers_mut()
                                    .match_first_type_mut::<Self>()
                                    .unwrap()
                                    .collectors = collectors;
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
                            hooks.instruction(insn.address() as GuestAddr, Self::on_ret, false);
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
}

impl<S, T> QemuHelper<S> for QemuCallTracerHelper<T>
where
    S: UsesInput,
    T: CallTraceCollectorTuple,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks(Some(Self::gen_blocks_calls::<QT, S>), None);
    }

    fn pre_exec(&mut self, emulator: &Emulator, input: &S::Input) {
        self.collectors
            .as_mut()
            .unwrap()
            .pre_exec_all(emulator, input);
    }

    fn post_exec<OT>(
        &mut self,
        emulator: &Emulator,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        self.collectors
            .as_mut()
            .unwrap()
            .post_exec_all(emulator, input, observers, exit_kind);
    }
}

#[derive(Debug)]
pub struct OnCrashBacktraceCollector {
    callstack_hash: u64,
    observer_name: String,
}

impl OnCrashBacktraceCollector {
    #[must_use]
    pub fn new(observer: &BacktraceObserver<'_>) -> Self {
        Self {
            callstack_hash: 0,
            observer_name: observer.name().to_string(),
        }
    }

    #[must_use]
    pub fn with_name(observer_name: String) -> Self {
        Self {
            callstack_hash: 0,
            observer_name,
        }
    }

    #[must_use]
    pub fn callstack_hash(&self) -> u64 {
        self.callstack_hash
    }

    pub fn reset(&mut self) {
        self.callstack_hash = 0;
    }
}

impl CallTraceCollector for OnCrashBacktraceCollector {
    #[allow(clippy::unnecessary_cast)]
    fn on_call<QT, S>(
        &mut self,
        _hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        self.callstack_hash ^= pc as u64 + call_len as u64;
    }

    #[allow(clippy::unnecessary_cast)]
    fn on_ret<QT, S>(
        &mut self,
        _hooks: &mut QemuHooks<'_, QT, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        self.callstack_hash ^= ret_addr as u64;
    }

    fn pre_exec<I>(&mut self, _emulator: &Emulator, _input: &I)
    where
        I: Input,
    {
        self.reset();
    }

    fn post_exec<OT, S>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: UsesInput,
    {
        let observer = observers
            .match_name_mut::<BacktraceObserver<'_>>(&self.observer_name)
            .expect("A OnCrashBacktraceCollector needs a BacktraceObserver");
        observer.fill_external(self.callstack_hash, exit_kind);
    }
}
