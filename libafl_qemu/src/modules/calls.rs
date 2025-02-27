use core::{cell::UnsafeCell, fmt::Debug};

use capstone::prelude::*;
use libafl::{
    executors::ExitKind,
    inputs::Input,
    observers::{ObserversTuple, stacktrace::BacktraceObserver},
};
use libafl_bolts::tuples::{Handle, Handled, MatchFirstType, MatchNameRef};
use libafl_qemu_sys::GuestAddr;
use thread_local::ThreadLocal;

use super::utils::filters::HasAddressFilter;
#[cfg(feature = "systemmode")]
use crate::modules::utils::filters::{HasPageFilter, NOP_PAGE_FILTER, NopPageFilter};
use crate::{
    Qemu, capstone,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple, EmulatorModules,
        utils::filters::StdAddressFilter,
    },
    qemu::{ArchExtras, Hook},
};

pub trait CallTraceCollector: 'static {
    fn on_call<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin;

    fn on_ret<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin;

    // Frowarded from the `CallTracerModule`
    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec<OT, I, S>(
        &mut self,
        _qemu: Qemu,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        I: Unpin,
        OT: ObserversTuple<I, S>,
        S: Unpin,
    {
    }
}

pub trait CallTraceCollectorTuple: 'static + MatchFirstType {
    fn on_call_all<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin;

    fn on_ret_all<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin;

    fn pre_exec_all<I>(&mut self, _qemu: Qemu, input: &I)
    where
        I: Input;

    fn post_exec_all<I, OT, S>(
        &mut self,
        _qemu: Qemu,
        input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        I: Unpin,
        OT: ObserversTuple<I, S>,
        S: Unpin;
}

impl CallTraceCollectorTuple for () {
    fn on_call_all<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
    }

    fn on_ret_all<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        _ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
    }

    fn pre_exec_all<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
    }

    fn post_exec_all<I, OT, S>(
        &mut self,
        _emulator: Qemu,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        I: Unpin,
        OT: ObserversTuple<I, S>,
        S: Unpin,
    {
    }
}

impl<Head, Tail> CallTraceCollectorTuple for (Head, Tail)
where
    Head: CallTraceCollector,
    Tail: CallTraceCollectorTuple,
{
    fn on_call_all<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
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

    fn on_ret_all<ET, I, S>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        mut state: Option<&mut S>,
        pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
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

    fn post_exec_all<I, OT, S>(
        &mut self,
        qemu: Qemu,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        I: Unpin,
        OT: ObserversTuple<I, S>,
        S: Unpin,
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
    filter: StdAddressFilter,
    cs: Capstone,
    collectors: Option<T>,
}

impl<T> CallTracerModule<T>
where
    T: CallTraceCollectorTuple + Debug,
{
    #[must_use]
    pub fn new(filter: StdAddressFilter, collectors: T) -> Self {
        Self {
            filter,
            cs: capstone().detail(true).build().unwrap(),
            collectors: Some(collectors),
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(&addr)
    }

    fn on_ret<ET, I, S>(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: Option<&mut S>,
        pc: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Input + Unpin,
        S: Unpin,
    {
        let ret_addr: GuestAddr = qemu.read_return_address().unwrap();

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

    #[allow(clippy::needless_pass_by_value)] // no longer a problem in nightly
    fn gen_blocks_calls<ET, I, S>(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        ET: EmulatorModuleTuple<I, S>,
        I: Input + Unpin,
        S: Unpin,
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

        let mut call_addrs: Vec<(GuestAddr, usize)> = Vec::new();
        let mut ret_addrs: Vec<GuestAddr> = Vec::new();

        if let Some(h) = emulator_modules.modules().match_first_type::<Self>() {
            #[allow(unused_mut)] // cfg dependent
            let mut code = {
                #[cfg(feature = "usermode")]
                unsafe {
                    std::slice::from_raw_parts(qemu.g2h(pc), 512)
                }
                #[cfg(feature = "systemmode")]
                &mut [0; 512]
            };
            #[cfg(feature = "systemmode")]
            if let Err(err) = qemu.read_mem(pc, code) {
                // TODO handle faults
                log::error!("gen_block_calls: Failed to read mem at pc {pc:#x}: {err:?}");
                return None;
            }

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

                #[cfg(feature = "usermode")]
                {
                    code = unsafe { std::slice::from_raw_parts(qemu.g2h(iaddr), 512) };
                }
                #[cfg(feature = "systemmode")]
                {
                    if let Err(err) = qemu.read_mem(pc, code) {
                        // TODO handle faults
                        log::error!(
                            "gen_block_calls error 2: Failed to read mem at pc {pc:#x}: {err:?}"
                        );
                        return None;
                    }
                }
            }
        }

        for (call_addr, call_len) in call_addrs {
            // TODO do not use a closure, find a more efficient way to pass call_len
            let call_cb = Box::new(
                move |_qemu: Qemu,
                      emulator_modules: &mut EmulatorModules<ET, I, S>,
                      state: Option<&mut S>,
                      pc| {
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

impl<I, S, T> EmulatorModule<I, S> for CallTracerModule<T>
where
    I: Input + Unpin,
    S: Unpin,
    T: CallTraceCollectorTuple + Debug,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.blocks(
            Hook::Function(Self::gen_blocks_calls::<ET, I, S>),
            Hook::Empty,
            Hook::Empty,
        );
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.collectors.as_mut().unwrap().pre_exec_all(qemu, input);
    }

    fn post_exec<OT, ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        self.collectors
            .as_mut()
            .unwrap()
            .post_exec_all(qemu, input, observers, exit_kind);
    }
}

impl<T> HasAddressFilter for CallTracerModule<T>
where
    T: CallTraceCollectorTuple,
{
    type AddressFilter = StdAddressFilter;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.filter
    }
}

#[cfg(feature = "systemmode")]
impl<T> HasPageFilter for CallTracerModule<T>
where
    T: CallTraceCollectorTuple,
{
    type PageFilter = NopPageFilter;

    fn page_filter(&self) -> &Self::PageFilter {
        &NopPageFilter
    }

    fn page_filter_mut(&mut self) -> &mut Self::PageFilter {
        unsafe { (&raw mut NOP_PAGE_FILTER).as_mut().unwrap().get_mut() }
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
    #[expect(clippy::unnecessary_cast)]
    fn on_call<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        self.callstack_hash ^= pc as u64 + call_len as u64;
    }

    #[expect(clippy::unnecessary_cast)]
    fn on_ret<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        self.callstack_hash ^= ret_addr as u64;
    }

    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
        self.reset();
    }

    fn post_exec<OT, I, S>(
        &mut self,
        _qemu: Qemu,
        _input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        I: Unpin,
        OT: ObserversTuple<I, S>,
        S: Unpin,
    {
        let observer = observers
            .get_mut(&self.observer_handle)
            .expect("A OnCrashBacktraceCollector needs a BacktraceObserver");
        observer.fill_external(self.callstack_hash, exit_kind);
    }
}

static mut CALLSTACKS: Option<ThreadLocal<UnsafeCell<Vec<GuestAddr>>>> = None;

#[derive(Debug)]
pub struct FullBacktraceCollector;

impl FullBacktraceCollector {
    /// # Safety
    ///
    /// This accesses the global [`CALLSTACKS`] variable and may not be called concurrently.
    #[expect(rustdoc::private_intra_doc_links)]
    pub unsafe fn new() -> Self {
        let callstacks_ptr = &raw mut CALLSTACKS;
        unsafe { (*callstacks_ptr) = Some(ThreadLocal::new()) };
        Self
    }

    pub fn reset(&mut self) {
        // # Safety
        // This accesses the global [`CALLSTACKS`] variable.
        // While it is racey, it might be fine if multiple clear the vecs concurrently.
        // TODO: This should probably be rewritten in a safer way.
        let callstacks_ptr = &raw mut CALLSTACKS;
        unsafe {
            for tls in (*callstacks_ptr).as_mut().unwrap().iter_mut() {
                (*tls.get()).clear();
            }
        }
    }

    pub fn backtrace() -> Option<&'static [GuestAddr]> {
        // # Safety
        // This accesses the global [`CALLSTACKS`] variable.
        // However, the actual variable access is behind a `ThreadLocal` class.
        let callstacks_ptr = &raw mut CALLSTACKS;
        unsafe {
            if let Some(c) = (*callstacks_ptr).as_mut() {
                Some(&*c.get_or_default().get())
            } else {
                None
            }
        }
    }
}

impl CallTraceCollector for FullBacktraceCollector {
    #[allow(clippy::unnecessary_cast)] // dependent on the target instruction size
    fn on_call<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        let callstacks_ptr = &raw mut CALLSTACKS;
        // TODO handle Thumb
        unsafe {
            (*(*callstacks_ptr).as_mut().unwrap().get_or_default().get())
                .push(pc + call_len as GuestAddr);
        }
    }

    #[allow(clippy::unnecessary_cast)] // dependent on the target instruction size
    fn on_ret<ET, I, S>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        let callstacks_ptr = &raw mut CALLSTACKS;
        unsafe {
            let v = &mut *(*callstacks_ptr).as_mut().unwrap().get_or_default().get();
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
