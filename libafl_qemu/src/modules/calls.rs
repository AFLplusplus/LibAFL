use core::{cell::UnsafeCell, fmt::Debug};

use capstone::prelude::*;
use libafl::{
    executors::ExitKind,
    inputs::{Input, UsesInput},
    observers::{stacktrace::BacktraceObserver, ObserversTuple},
};
use libafl_bolts::tuples::{Handle, Handled, MatchFirstType, MatchNameRef};
use libafl_qemu_sys::GuestAddr;
use thread_local::ThreadLocal;

use crate::{
    capstone,
    modules::{
        EmulatorModule, EmulatorModuleTuple, EmulatorModules, HasInstrumentationFilter, IsFilter,
        QemuInstrumentationAddressRangeFilter,
    },
    qemu::{ArchExtras, Hook},
    Qemu,
};

pub trait CallTraceCollector: 'static {
    fn on_call<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>;

    fn on_ret<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>;

    // Frowarded from the `CallTracerModule`
    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec<OT, S>(
        &mut self,
        _qemu: Qemu,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: Unpin + UsesInput,
    {
    }
}

pub trait CallTraceCollectorTuple: 'static + MatchFirstType {
    fn on_call_all<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>;

    fn on_ret_all<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<I>(&mut self, _qemu: Qemu, input: &I)
    where
        I: Input;

    fn post_exec_all<OT, S>(
        &mut self,
        _qemu: Qemu,
        input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: Unpin + UsesInput;
}

impl CallTraceCollectorTuple for () {
    fn on_call_all<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _call_len: usize,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn on_ret_all<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _ret_addr: GuestAddr,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec_all<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec_all<OT, S>(
        &mut self,
        _emulator: Qemu,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: Unpin + UsesInput,
    {
    }
}

impl<Head, Tail> CallTraceCollectorTuple for (Head, Tail)
where
    Head: CallTraceCollector,
    Tail: CallTraceCollectorTuple,
{
    fn on_call_all<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
        self.0.on_call(
            emulator_modules,
            match state.as_mut() {
                Some(s) => Some(*s),
                None => None,
            },
            pc,
            call_len,
        );
        self.1.on_call_all(emulator_modules, state, pc, call_len);
    }

    fn on_ret_all<ET, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
        self.0.on_ret(
            emulator_modules,
            match state.as_mut() {
                Some(s) => Some(*s),
                None => None,
            },
            pc,
            ret_addr,
        );
        self.1.on_ret_all(emulator_modules, state, pc, ret_addr);
    }

    fn pre_exec_all<I>(&mut self, qemu: Qemu, input: &I)
    where
        I: Input,
    {
        self.0.pre_exec(qemu, input);
        self.1.pre_exec_all(qemu, input);
    }

    fn post_exec_all<OT, S>(
        &mut self,
        qemu: Qemu,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: Unpin + UsesInput,
    {
        self.0.post_exec(qemu, input, observers, exit_kind);
        self.1.post_exec_all(qemu, input, observers, exit_kind);
    }
}

#[derive(Debug)]
pub struct CallTracerModule<T>
where
    T: CallTraceCollectorTuple,
{
    filter: QemuInstrumentationAddressRangeFilter,
    cs: Capstone,
    collectors: Option<T>,
}

impl<T> CallTracerModule<T>
where
    T: CallTraceCollectorTuple + Debug,
{
    #[must_use]
    pub fn new(filter: QemuInstrumentationAddressRangeFilter, collectors: T) -> Self {
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

    fn on_ret<ET, S>(
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
    ) where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
        let ret_addr: GuestAddr = emulator_modules.qemu().read_return_address().unwrap();

        // log::info!("RET @ 0x{:#x}", ret_addr);

        let mut collectors = if let Some(h) = emulator_modules.get_mut::<Self>() {
            h.collectors.take()
        } else {
            return;
        };
        if collectors.is_none() {
            return; // TODO fix this, it can be None on races ret
        }
        collectors
            .as_mut()
            .unwrap()
            .on_ret_all(emulator_modules, state, pc, ret_addr);
        emulator_modules.get_mut::<Self>().unwrap().collectors = collectors;
    }

    fn gen_blocks_calls<ET, S>(
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        S: Unpin + UsesInput,
        ET: EmulatorModuleTuple<S>,
    {
        if let Some(h) = emulator_modules.get_mut::<Self>() {
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

        let qemu = emulator_modules.qemu();

        let mut call_addrs: Vec<(GuestAddr, usize)> = Vec::new();
        let mut ret_addrs: Vec<GuestAddr> = Vec::new();

        if let Some(h) = emulator_modules.modules().match_first_type::<Self>() {
            #[allow(unused_mut)]
            let mut code = {
                #[cfg(emulation_mode = "usermode")]
                unsafe {
                    std::slice::from_raw_parts(qemu.g2h(pc), 512)
                }
                #[cfg(emulation_mode = "systemmode")]
                &mut [0; 512]
            };
            #[cfg(emulation_mode = "systemmode")]
            unsafe {
                qemu.read_mem(pc, code)
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
                            call_addrs.push((insn.address() as GuestAddr, call_len));
                        }
                        capstone::InsnGroupType::CS_GRP_RET => {
                            ret_addrs.push(insn.address() as GuestAddr);
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
                    code = std::slice::from_raw_parts(qemu.g2h(iaddr), 512);
                }
                #[cfg(emulation_mode = "systemmode")]
                unsafe {
                    qemu.read_mem(pc, code);
                } // TODO handle faults
            }
        }

        for (call_addr, call_len) in call_addrs {
            // TODO do not use a closure, find a more efficient way to pass call_len
            let call_cb = Box::new(
                move |emulator_modules: &mut EmulatorModules<ET, S>, state: Option<&mut S>, pc| {
                    // eprintln!("CALL @ 0x{:#x}", pc + call_len);
                    let mut collectors = if let Some(h) = emulator_modules.get_mut::<Self>() {
                        h.collectors.take()
                    } else {
                        return;
                    };
                    if collectors.is_none() {
                        return; // TODO fix this, it can be None on races ret
                    }
                    collectors
                        .as_mut()
                        .unwrap()
                        .on_call_all(emulator_modules, state, pc, call_len);
                    emulator_modules.get_mut::<Self>().unwrap().collectors = collectors;
                },
            );
            emulator_modules.instruction_closure(call_addr, call_cb, false);
        }

        for ret_addr in ret_addrs {
            emulator_modules.instruction_function(ret_addr, Self::on_ret, false);
        }

        None
    }
}

impl<T> HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for CallTracerModule<T>
where
    T: CallTraceCollectorTuple,
{
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.filter
    }
}

impl<S, T> EmulatorModule<S> for CallTracerModule<T>
where
    S: Unpin + UsesInput,
    T: CallTraceCollectorTuple + Debug,
{
    fn init_module<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.blocks(
            Hook::Function(Self::gen_blocks_calls::<ET, S>),
            Hook::Empty,
            Hook::Empty,
        );
    }

    fn pre_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, input: &S::Input)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.collectors
            .as_mut()
            .unwrap()
            .pre_exec_all(emulator_modules.qemu(), input);
    }

    fn post_exec<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.collectors.as_mut().unwrap().post_exec_all(
            emulator_modules.qemu(),
            input,
            observers,
            exit_kind,
        );
    }
}

// TODO support multiple threads with thread local callstack
#[derive(Debug)]
pub struct OnCrashBacktraceCollector<'a> {
    callstack_hash: u64,
    observer_handle: Handle<BacktraceObserver<'a>>,
}

impl<'a> OnCrashBacktraceCollector<'a> {
    #[must_use]
    pub fn new(observer: &BacktraceObserver<'a>) -> Self {
        Self {
            callstack_hash: 0,
            observer_handle: observer.handle(),
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

impl<'a> CallTraceCollector for OnCrashBacktraceCollector<'a>
where
    'a: 'static,
{
    #[allow(clippy::unnecessary_cast)]
    fn on_call<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<S>,
        S: Unpin + UsesInput,
    {
        self.callstack_hash ^= pc as u64 + call_len as u64;
    }

    #[allow(clippy::unnecessary_cast)]
    fn on_ret<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<S>,
        S: Unpin + UsesInput,
    {
        self.callstack_hash ^= ret_addr as u64;
    }

    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
        self.reset();
    }

    fn post_exec<OT, S>(
        &mut self,
        _qemu: Qemu,
        _input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        S: Unpin + UsesInput,
    {
        let observer = observers
            .get_mut(&self.observer_handle)
            .expect("A OnCrashBacktraceCollector needs a BacktraceObserver");
        observer.fill_external(self.callstack_hash, exit_kind);
    }
}

static mut CALLSTACKS: Option<ThreadLocal<UnsafeCell<Vec<GuestAddr>>>> = None;

#[derive(Debug)]
pub struct FullBacktraceCollector {}

impl Default for FullBacktraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl FullBacktraceCollector {
    pub fn new() -> Self {
        unsafe { CALLSTACKS = Some(ThreadLocal::new()) };
        Self {}
    }

    pub fn reset(&mut self) {
        unsafe {
            for tls in CALLSTACKS.as_mut().unwrap().iter_mut() {
                (*tls.get()).clear();
            }
        }
    }

    pub fn backtrace() -> Option<&'static [GuestAddr]> {
        unsafe {
            if let Some(c) = CALLSTACKS.as_mut() {
                Some(&*c.get_or_default().get())
            } else {
                None
            }
        }
    }
}

impl CallTraceCollector for FullBacktraceCollector {
    #[allow(clippy::unnecessary_cast)]
    fn on_call<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<S>,
        S: Unpin + UsesInput,
    {
        // TODO handle Thumb
        unsafe {
            (*CALLSTACKS.as_mut().unwrap().get_or_default().get()).push(pc + call_len as GuestAddr);
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn on_ret<ET, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<S>,
        S: Unpin + UsesInput,
    {
        unsafe {
            let v = &mut *CALLSTACKS.as_mut().unwrap().get_or_default().get();
            if !v.is_empty() {
                // if *v.last().unwrap() == ret_addr {
                //    v.pop();
                // }
                while let Some(p) = v.pop() {
                    if p == ret_addr {
                        break;
                    }
                }
            }
        }
    }

    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
        self.reset();
    }
}
