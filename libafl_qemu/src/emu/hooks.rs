#![allow(clippy::missing_transmute_annotations)]

use std::{fmt::Debug, marker::PhantomData, mem::transmute, pin::Pin, ptr};

use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_qemu_sys::{CPUArchStatePtr, CPUStatePtr, FatPtr, GuestAddr, GuestUsize, TCGTemp};

#[cfg(feature = "usermode")]
use crate::qemu::{
    closure_post_syscall_hook_wrapper, closure_pre_syscall_hook_wrapper,
    func_post_syscall_hook_wrapper, func_pre_syscall_hook_wrapper, PostSyscallHook,
    PostSyscallHookId, PreSyscallHook, PreSyscallHookId, SyscallHookResult,
};
#[cfg(feature = "usermode")]
use crate::qemu::{
    CrashHookClosure, CrashHookFn, PostSyscallHookClosure, PostSyscallHookFn,
    PreSyscallHookClosure, PreSyscallHookFn,
};
use crate::{
    cpu_run_post_exec_hook_wrapper, cpu_run_pre_exec_hook_wrapper,
    modules::{EmulatorModule, EmulatorModuleTuple},
    qemu::{
        block_0_exec_hook_wrapper, block_gen_hook_wrapper, block_post_gen_hook_wrapper,
        closure_backdoor_hook_wrapper, closure_instruction_hook_wrapper,
        closure_new_thread_hook_wrapper, cmp_0_exec_hook_wrapper, cmp_1_exec_hook_wrapper,
        cmp_2_exec_hook_wrapper, cmp_3_exec_hook_wrapper, cmp_gen_hook_wrapper,
        edge_0_exec_hook_wrapper, edge_gen_hook_wrapper, func_backdoor_hook_wrapper,
        func_instruction_hook_wrapper, func_new_thread_hook_wrapper, read_0_exec_hook_wrapper,
        read_1_exec_hook_wrapper, read_2_exec_hook_wrapper, read_3_exec_hook_wrapper,
        read_4_exec_hook_wrapper, read_gen_hook_wrapper, write_0_exec_hook_wrapper,
        write_1_exec_hook_wrapper, write_2_exec_hook_wrapper, write_3_exec_hook_wrapper,
        write_4_exec_hook_wrapper, write_gen_hook_wrapper, BackdoorHook, BackdoorHookClosure,
        BackdoorHookFn, BackdoorHookId, BlockExecHook, BlockGenHook, BlockHookId, BlockPostGenHook,
        CmpExecHook, CmpGenHook, CmpHookId, EdgeExecHook, EdgeGenHook, EdgeHookId, Hook, HookRepr,
        InstructionHook, InstructionHookClosure, InstructionHookFn, InstructionHookId,
        NewThreadHook, NewThreadHookClosure, NewThreadHookId, QemuHooks, ReadExecHook,
        ReadExecNHook, ReadGenHook, ReadHookId, TcgHookState, WriteExecHook, WriteExecNHook,
        WriteGenHook, WriteHookId,
    },
    CpuPostRunHook, CpuPreRunHook, CpuRunHookId, HookState, MemAccessInfo, Qemu,
};

macro_rules! get_raw_hook {
    ($h:expr, $replacement:expr, $fntype:ty) => {
        match $h {
            Hook::Function(_) | Hook::Closure(_) => Some($replacement as $fntype),
            Hook::Raw(r) => {
                let v: $fntype = transmute(r);
                Some(v)
            }
            Hook::Empty => None,
        }
    };
}

macro_rules! hook_to_repr {
    ($h:expr) => {
        match $h {
            Hook::Function(f) => HookRepr::Function(f as *const libc::c_void),
            Hook::Closure(c) => HookRepr::Closure(transmute(c)),
            Hook::Raw(_) => HookRepr::Empty, // managed by emu
            Hook::Empty => HookRepr::Empty,
        }
    };
}

static mut EMULATOR_MODULES: *mut () = ptr::null_mut();

#[cfg(feature = "usermode")]
pub extern "C" fn crash_hook_wrapper<ET, S>(target_sig: i32)
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    unsafe {
        let emulator_modules = EmulatorModules::<ET, S>::emulator_modules_mut().unwrap();

        let crash_hooks_ptr = &raw mut emulator_modules.hooks.crash_hooks;

        for crash_hook in &mut (*crash_hooks_ptr) {
            match crash_hook {
                HookRepr::Function(ptr) => {
                    let func: CrashHookFn<ET, S> = transmute(*ptr);
                    func(emulator_modules, target_sig);
                }
                HookRepr::Closure(ptr) => {
                    let func: &mut CrashHookClosure<ET, S> =
                        &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut CrashHookClosure<ET, S>);
                    func(emulator_modules, target_sig);
                }
                HookRepr::Empty => (),
            }
        }
    }
}

/// High-level `Emulator` modules, using `QemuHooks`.
#[derive(Debug)]
pub struct EmulatorModules<ET, S>
where
    S: UsesInput,
{
    qemu: Qemu,
    modules: Pin<Box<ET>>,
    hooks: EmulatorHooks<ET, S>,
    phantom: PhantomData<S>,
}

/// Hook collection,
#[derive(Debug)]
pub struct EmulatorHooks<ET, S>
where
    S: UsesInput,
{
    qemu_hooks: QemuHooks,

    instruction_hooks: Vec<Pin<Box<(InstructionHookId, FatPtr)>>>,
    backdoor_hooks: Vec<Pin<Box<(BackdoorHookId, FatPtr)>>>,
    edge_hooks: Vec<Pin<Box<TcgHookState<1, EdgeHookId>>>>,
    block_hooks: Vec<Pin<Box<TcgHookState<1, BlockHookId>>>>,
    read_hooks: Vec<Pin<Box<TcgHookState<5, ReadHookId>>>>,
    write_hooks: Vec<Pin<Box<TcgHookState<5, WriteHookId>>>>,
    cmp_hooks: Vec<Pin<Box<TcgHookState<4, CmpHookId>>>>,

    cpu_run_hooks: Vec<Pin<Box<HookState<CpuRunHookId>>>>,

    new_thread_hooks: Vec<Pin<Box<(NewThreadHookId, FatPtr)>>>,

    #[cfg(feature = "usermode")]
    pre_syscall_hooks: Vec<Pin<Box<(PreSyscallHookId, FatPtr)>>>,

    #[cfg(feature = "usermode")]
    post_syscall_hooks: Vec<Pin<Box<(PostSyscallHookId, FatPtr)>>>,

    #[cfg(feature = "usermode")]
    crash_hooks: Vec<HookRepr>,

    phantom: PhantomData<(ET, S)>,
}

impl<ET, S> EmulatorHooks<ET, S>
where
    S: UsesInput + Unpin,
{
    #[must_use]
    pub fn new(qemu_hooks: QemuHooks) -> Self {
        Self {
            qemu_hooks,
            phantom: PhantomData,
            instruction_hooks: Vec::new(),
            backdoor_hooks: Vec::new(),
            edge_hooks: Vec::new(),
            block_hooks: Vec::new(),
            read_hooks: Vec::new(),
            write_hooks: Vec::new(),
            cmp_hooks: Vec::new(),

            cpu_run_hooks: Vec::new(),

            new_thread_hooks: Vec::new(),

            #[cfg(feature = "usermode")]
            pre_syscall_hooks: Vec::new(),

            #[cfg(feature = "usermode")]
            post_syscall_hooks: Vec::new(),

            #[cfg(feature = "usermode")]
            crash_hooks: Vec::new(),
        }
    }

    pub fn instruction_closure(
        &mut self,
        addr: GuestAddr,
        hook: InstructionHookClosure<ET, S>,
        invalidate_block: bool,
    ) -> InstructionHookId {
        let fat: FatPtr = unsafe { transmute(hook) };

        self.instruction_hooks
            .push(Box::pin((InstructionHookId::invalid(), fat)));

        unsafe {
            let hook_state = &mut self
                .instruction_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .1 as *mut FatPtr;

            let id = self.qemu_hooks.add_instruction_hooks(
                &mut *hook_state,
                addr,
                closure_instruction_hook_wrapper::<ET, S>,
                invalidate_block,
            );
            self.instruction_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .0 = id;
            id
        }
    }

    pub fn instructions(
        &mut self,
        addr: GuestAddr,
        hook: InstructionHook<ET, S>,
        invalidate_block: bool,
    ) -> Option<InstructionHookId> {
        match hook {
            Hook::Function(f) => Some(self.instruction_function(addr, f, invalidate_block)),
            Hook::Closure(c) => Some(self.instruction_closure(addr, c, invalidate_block)),
            Hook::Raw(r) => {
                let z: *const () = ptr::null::<()>();
                Some(
                    self.qemu_hooks
                        .add_instruction_hooks(z, addr, r, invalidate_block),
                )
            }
            Hook::Empty => None,
        }
    }

    pub fn instruction_function(
        &mut self,
        addr: GuestAddr,
        hook: InstructionHookFn<ET, S>,
        invalidate_block: bool,
    ) -> InstructionHookId {
        unsafe {
            self.qemu_hooks.add_instruction_hooks(
                transmute(hook),
                addr,
                func_instruction_hook_wrapper::<ET, S>,
                invalidate_block,
            )
        }
    }

    pub fn edges(
        &mut self,
        generation_hook: EdgeGenHook<ET, S>,
        execution_hook: EdgeExecHook<ET, S>,
    ) -> EdgeHookId {
        unsafe {
            let gen = get_raw_hook!(
                generation_hook,
                edge_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<1, EdgeHookId>,
                    src: GuestAddr,
                    dest: GuestAddr,
                ) -> u64
            );

            let exec = get_raw_hook!(
                execution_hook,
                edge_0_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<1, EdgeHookId>, id: u64)
            );

            self.edge_hooks.push(Box::pin(TcgHookState::new(
                EdgeHookId::invalid(),
                hook_to_repr!(generation_hook),
                HookRepr::Empty,
                [hook_to_repr!(execution_hook)],
            )));

            let hook_state = &mut *ptr::from_mut::<TcgHookState<1, EdgeHookId>>(
                self.edge_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self.qemu_hooks.add_edge_hooks(hook_state, gen, exec);

            self.edge_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    pub fn blocks(
        &mut self,
        generation_hook: BlockGenHook<ET, S>,
        post_generation_hook: BlockPostGenHook<ET, S>,
        execution_hook: BlockExecHook<ET, S>,
    ) -> BlockHookId {
        unsafe {
            let gen = get_raw_hook!(
                generation_hook,
                block_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<1, BlockHookId>, pc: GuestAddr) -> u64
            );

            let postgen = get_raw_hook!(
                post_generation_hook,
                block_post_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<1, BlockHookId>,
                    pc: GuestAddr,
                    block_length: GuestUsize,
                )
            );

            let exec = get_raw_hook!(
                execution_hook,
                block_0_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<1, BlockHookId>, id: u64)
            );

            self.block_hooks.push(Box::pin(TcgHookState::new(
                BlockHookId::invalid(),
                hook_to_repr!(generation_hook),
                hook_to_repr!(post_generation_hook),
                [hook_to_repr!(execution_hook)],
            )));

            let hook_state = &mut *ptr::from_mut::<TcgHookState<1, BlockHookId>>(
                self.block_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self
                .qemu_hooks
                .add_block_hooks(hook_state, gen, postgen, exec);

            self.block_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    pub fn cpu_runs(
        &mut self,
        pre_exec_hook: CpuPreRunHook<ET, S>,
        post_exec_hook: CpuPostRunHook<ET, S>,
    ) -> CpuRunHookId {
        unsafe {
            let pre_run = get_raw_hook!(
                pre_exec_hook,
                cpu_run_pre_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut HookState<CpuRunHookId>, cpu: CPUStatePtr)
            );

            let post_run = get_raw_hook!(
                post_exec_hook,
                cpu_run_post_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut HookState<CpuRunHookId>, cpu: CPUStatePtr)
            );

            self.cpu_run_hooks.push(Box::pin(HookState::new(
                CpuRunHookId::invalid(),
                hook_to_repr!(pre_exec_hook),
                hook_to_repr!(post_exec_hook),
            )));

            let hook_state = &mut *ptr::from_mut::<HookState<CpuRunHookId>>(
                self.cpu_run_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self
                .qemu_hooks
                .add_cpu_run_hooks(hook_state, pre_run, post_run);

            self.cpu_run_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    #[allow(clippy::similar_names)]
    pub fn reads(
        &mut self,
        generation_hook: ReadGenHook<ET, S>,
        execution_hook_1: ReadExecHook<ET, S>,
        execution_hook_2: ReadExecHook<ET, S>,
        execution_hook_4: ReadExecHook<ET, S>,
        execution_hook_8: ReadExecHook<ET, S>,
        execution_hook_n: ReadExecNHook<ET, S>,
    ) -> ReadHookId {
        unsafe {
            let gen = get_raw_hook!(
                generation_hook,
                read_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<5, ReadHookId>,
                    pc: GuestAddr,
                    addr: *mut TCGTemp,
                    info: MemAccessInfo,
                ) -> u64
            );
            let exec1 = get_raw_hook!(
                execution_hook_1,
                read_0_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, ReadHookId>, id: u64, addr: GuestAddr)
            );
            let exec2 = get_raw_hook!(
                execution_hook_2,
                read_1_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, ReadHookId>, id: u64, addr: GuestAddr)
            );
            let exec4 = get_raw_hook!(
                execution_hook_4,
                read_2_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, ReadHookId>, id: u64, addr: GuestAddr)
            );
            let exec8 = get_raw_hook!(
                execution_hook_8,
                read_3_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, ReadHookId>, id: u64, addr: GuestAddr)
            );
            let execn = get_raw_hook!(
                execution_hook_n,
                read_4_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<5, ReadHookId>,
                    id: u64,
                    addr: GuestAddr,
                    size: usize,
                )
            );

            self.read_hooks.push(Box::pin(TcgHookState::new(
                ReadHookId::invalid(),
                hook_to_repr!(generation_hook),
                HookRepr::Empty,
                [
                    hook_to_repr!(execution_hook_1),
                    hook_to_repr!(execution_hook_2),
                    hook_to_repr!(execution_hook_4),
                    hook_to_repr!(execution_hook_8),
                    hook_to_repr!(execution_hook_n),
                ],
            )));

            let hook_state = &mut *ptr::from_mut::<TcgHookState<5, ReadHookId>>(
                self.read_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self
                .qemu_hooks
                .add_read_hooks(hook_state, gen, exec1, exec2, exec4, exec8, execn);

            self.read_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    #[allow(clippy::similar_names)]
    pub fn writes(
        &mut self,
        generation_hook: WriteGenHook<ET, S>,
        execution_hook_1: WriteExecHook<ET, S>,
        execution_hook_2: WriteExecHook<ET, S>,
        execution_hook_4: WriteExecHook<ET, S>,
        execution_hook_8: WriteExecHook<ET, S>,
        execution_hook_n: WriteExecNHook<ET, S>,
    ) -> WriteHookId {
        unsafe {
            let gen = get_raw_hook!(
                generation_hook,
                write_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<5, WriteHookId>,
                    pc: GuestAddr,
                    addr: *mut TCGTemp,
                    info: MemAccessInfo,
                ) -> u64
            );
            let exec1 = get_raw_hook!(
                execution_hook_1,
                write_0_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, WriteHookId>, id: u64, addr: GuestAddr)
            );
            let exec2 = get_raw_hook!(
                execution_hook_2,
                write_1_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, WriteHookId>, id: u64, addr: GuestAddr)
            );
            let exec4 = get_raw_hook!(
                execution_hook_4,
                write_2_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, WriteHookId>, id: u64, addr: GuestAddr)
            );
            let exec8 = get_raw_hook!(
                execution_hook_8,
                write_3_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<5, WriteHookId>, id: u64, addr: GuestAddr)
            );
            let execn = get_raw_hook!(
                execution_hook_n,
                write_4_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<5, WriteHookId>,
                    id: u64,
                    addr: GuestAddr,
                    size: usize,
                )
            );

            self.write_hooks.push(Box::pin(TcgHookState::new(
                WriteHookId::invalid(),
                hook_to_repr!(generation_hook),
                HookRepr::Empty,
                [
                    hook_to_repr!(execution_hook_1),
                    hook_to_repr!(execution_hook_2),
                    hook_to_repr!(execution_hook_4),
                    hook_to_repr!(execution_hook_8),
                    hook_to_repr!(execution_hook_n),
                ],
            )));

            let hook_state = &mut *ptr::from_mut::<TcgHookState<5, WriteHookId>>(
                self.write_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self
                .qemu_hooks
                .add_write_hooks(hook_state, gen, exec1, exec2, exec4, exec8, execn);

            self.write_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    pub fn cmps(
        &mut self,
        generation_hook: CmpGenHook<ET, S>,
        execution_hook_1: CmpExecHook<ET, S, u8>,
        execution_hook_2: CmpExecHook<ET, S, u16>,
        execution_hook_4: CmpExecHook<ET, S, u32>,
        execution_hook_8: CmpExecHook<ET, S, u64>,
    ) -> CmpHookId {
        unsafe {
            let gen = get_raw_hook!(
                generation_hook,
                cmp_gen_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(
                    &mut TcgHookState<4, CmpHookId>,
                    pc: GuestAddr,
                    size: usize,
                ) -> u64
            );
            let exec1 = get_raw_hook!(
                execution_hook_1,
                cmp_0_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<4, CmpHookId>, id: u64, v0: u8, v1: u8)
            );
            let exec2 = get_raw_hook!(
                execution_hook_2,
                cmp_1_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<4, CmpHookId>, id: u64, v0: u16, v1: u16)
            );
            let exec4 = get_raw_hook!(
                execution_hook_4,
                cmp_2_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<4, CmpHookId>, id: u64, v0: u32, v1: u32)
            );
            let exec8 = get_raw_hook!(
                execution_hook_8,
                cmp_3_exec_hook_wrapper::<ET, S>,
                unsafe extern "C" fn(&mut TcgHookState<4, CmpHookId>, id: u64, v0: u64, v1: u64)
            );

            self.cmp_hooks.push(Box::pin(TcgHookState::new(
                CmpHookId::invalid(),
                hook_to_repr!(generation_hook),
                HookRepr::Empty,
                [
                    hook_to_repr!(execution_hook_1),
                    hook_to_repr!(execution_hook_2),
                    hook_to_repr!(execution_hook_4),
                    hook_to_repr!(execution_hook_8),
                ],
            )));

            let hook_state = &mut *ptr::from_mut::<TcgHookState<4, CmpHookId>>(
                self.cmp_hooks
                    .last_mut()
                    .unwrap()
                    .as_mut()
                    .get_unchecked_mut(),
            );

            let id = self
                .qemu_hooks
                .add_cmp_hooks(hook_state, gen, exec1, exec2, exec4, exec8);

            self.cmp_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .set_id(id);

            id
        }
    }

    /// # Safety
    /// Will dereference the hook as [`FatPtr`].
    pub unsafe fn backdoor_closure(&mut self, hook: BackdoorHookClosure<ET, S>) -> BackdoorHookId {
        unsafe {
            let fat: FatPtr = transmute(hook);
            self.backdoor_hooks
                .push(Box::pin((BackdoorHookId::invalid(), fat)));

            let hook_state = &mut self
                .backdoor_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .1 as *mut FatPtr;

            let id = self
                .qemu_hooks
                .add_backdoor_hook(&mut *hook_state, closure_backdoor_hook_wrapper::<ET, S>);

            self.backdoor_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .0 = id;

            id
        }
    }

    pub fn backdoor_function(
        &self,
        hook: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, cpu: CPUArchStatePtr, pc: GuestAddr),
    ) -> BackdoorHookId {
        unsafe {
            self.qemu_hooks
                .add_backdoor_hook(transmute(hook), func_backdoor_hook_wrapper::<ET, S>)
        }
    }

    /// # Safety
    /// This can call through to a potentialy unsafe `backtoor_function`
    pub unsafe fn backdoor(&mut self, hook: BackdoorHook<ET, S>) -> Option<BackdoorHookId> {
        match hook {
            Hook::Function(f) => Some(self.backdoor_function(f)),
            Hook::Closure(c) => Some(self.backdoor_closure(c)),
            Hook::Raw(r) => {
                let z: *const () = ptr::null::<()>();
                Some(self.qemu_hooks.add_backdoor_hook(z, r))
            }
            Hook::Empty => None, // TODO error type
        }
    }

    pub fn thread_creation(&mut self, hook: NewThreadHook<ET, S>) -> Option<NewThreadHookId> {
        match hook {
            Hook::Function(f) => Some(self.thread_creation_function(f)),
            Hook::Closure(c) => Some(self.thread_creation_closure(c)),
            Hook::Raw(r) => {
                let z: *const () = ptr::null::<()>();
                Some(self.qemu_hooks.add_new_thread_hook(z, r))
            }
            Hook::Empty => None, // TODO error type
        }
    }

    pub fn thread_creation_function(
        &mut self,
        hook: fn(
            &mut EmulatorModules<ET, S>,
            Option<&mut S>,
            env: CPUArchStatePtr,
            tid: u32,
        ) -> bool,
    ) -> NewThreadHookId {
        unsafe {
            self.qemu_hooks
                .add_new_thread_hook(transmute(hook), func_new_thread_hook_wrapper::<ET, S>)
        }
    }

    pub fn thread_creation_closure(
        &mut self,
        hook: NewThreadHookClosure<ET, S>,
    ) -> NewThreadHookId {
        unsafe {
            let fat: FatPtr = transmute(hook);
            self.new_thread_hooks
                .push(Box::pin((NewThreadHookId::invalid(), fat)));

            let hook_state = &mut self
                .new_thread_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .1 as *mut FatPtr;

            let id = self
                .qemu_hooks
                .add_new_thread_hook(&mut *hook_state, closure_new_thread_hook_wrapper::<ET, S>);
            self.new_thread_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .0 = id;
            id
        }
    }
}

#[cfg(feature = "usermode")]
impl<ET, S> EmulatorHooks<ET, S>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    #[allow(clippy::type_complexity)]
    pub fn syscalls(&mut self, hook: PreSyscallHook<ET, S>) -> Option<PreSyscallHookId> {
        match hook {
            Hook::Function(f) => Some(self.syscalls_function(f)),
            Hook::Closure(c) => Some(self.syscalls_closure(c)),
            Hook::Raw(r) => {
                let z: *const () = ptr::null::<()>();
                Some(self.qemu_hooks.add_pre_syscall_hook(z, r))
            }
            Hook::Empty => None, // TODO error type
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn syscalls_function(&mut self, hook: PreSyscallHookFn<ET, S>) -> PreSyscallHookId {
        // # Safety
        // Will dereference the hook as [`FatPtr`].
        unsafe {
            self.qemu_hooks
                .add_pre_syscall_hook(transmute(hook), func_pre_syscall_hook_wrapper::<ET, S>)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn syscalls_closure(&mut self, hook: PreSyscallHookClosure<ET, S>) -> PreSyscallHookId {
        // # Safety
        // Will dereference the hook as [`FatPtr`].
        unsafe {
            let fat: FatPtr = transmute(hook);

            self.pre_syscall_hooks
                .push(Box::pin((PreSyscallHookId::invalid(), fat)));

            let hook_state = &mut self
                .pre_syscall_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .1 as *mut FatPtr;

            let id = self
                .qemu_hooks
                .add_pre_syscall_hook(&mut *hook_state, closure_pre_syscall_hook_wrapper::<ET, S>);
            self.pre_syscall_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .0 = id;
            id
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls(&mut self, hook: PostSyscallHook<ET, S>) -> Option<PostSyscallHookId> {
        match hook {
            Hook::Function(f) => Some(self.after_syscalls_function(f)),
            Hook::Closure(c) => Some(self.after_syscalls_closure(c)),
            Hook::Raw(r) => {
                let z: *const () = ptr::null::<()>();
                Some(self.qemu_hooks.add_post_syscall_hook(z, r))
            }
            Hook::Empty => None, // TODO error type
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls_function(&mut self, hook: PostSyscallHookFn<ET, S>) -> PostSyscallHookId {
        // # Safety
        // Will dereference the hook as [`FatPtr`]. This should be ok.
        unsafe {
            self.qemu_hooks
                .add_post_syscall_hook(transmute(hook), func_post_syscall_hook_wrapper::<ET, S>)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls_closure(
        &mut self,
        hook: PostSyscallHookClosure<ET, S>,
    ) -> PostSyscallHookId {
        unsafe {
            let fat: FatPtr = transmute(hook);
            self.post_syscall_hooks
                .push(Box::pin((PostSyscallHookId::invalid(), fat)));

            let hooks_state = &mut self
                .post_syscall_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .1 as *mut FatPtr;

            let id = self.qemu_hooks.add_post_syscall_hook(
                &mut *hooks_state,
                closure_post_syscall_hook_wrapper::<ET, S>,
            );
            self.post_syscall_hooks
                .last_mut()
                .unwrap()
                .as_mut()
                .get_unchecked_mut()
                .0 = id;
            id
        }
    }

    pub fn crash_function(&mut self, hook: fn(&mut EmulatorModules<ET, S>, target_signal: i32)) {
        // # Safety
        // Will cast the valid hook to a ptr.
        self.qemu_hooks.set_crash_hook(crash_hook_wrapper::<ET, S>);
        self.crash_hooks
            .push(HookRepr::Function(hook as *const libc::c_void));
    }

    pub fn crash_closure(&mut self, hook: CrashHookClosure<ET, S>) {
        // # Safety
        // Will cast the hook to a [`FatPtr`].
        unsafe {
            self.qemu_hooks.set_crash_hook(crash_hook_wrapper::<ET, S>);
            self.crash_hooks.push(HookRepr::Closure(transmute(hook)));
        }
    }
}

impl<ET, S> Default for EmulatorHooks<ET, S>
where
    S: Unpin + UsesInput,
{
    fn default() -> Self {
        Self::new(QemuHooks::get().unwrap())
    }
}

impl<ET, S> EmulatorModules<ET, S>
where
    S: UsesInput,
{
    /// Get a mutable reference to `EmulatorModules` (supposedly initialized beforehand).
    ///
    /// # Safety
    ///
    /// This will always return a reference, but it will be incorrect if `EmulatorModules` has not
    /// been initialized previously.
    /// The user should also be consistent with the generic use (it will suppose they are the same
    /// as the ones used at initialization time).
    #[must_use]
    pub unsafe fn emulator_modules_mut_unchecked<'a>() -> &'a mut EmulatorModules<ET, S> {
        #[cfg(debug_assertions)]
        {
            (EMULATOR_MODULES as *mut EmulatorModules<ET, S>)
                .as_mut()
                .unwrap()
        }

        #[cfg(not(debug_assertions))]
        {
            &mut *(EMULATOR_MODULES as *mut EmulatorModules<ET, S>)
        }
    }

    /// Get a mutable reference to `EmulatorModules`.
    /// This version is safer than `emulator_modules_mut_unchecked` since it will check that
    /// initialization has occurred previously.
    ///
    /// # Safety
    ///
    /// This version still presents some unsafeness: The user should be consistent with the
    /// generic use (it will suppose they are the same as the ones used at initialization time).
    #[must_use]
    pub unsafe fn emulator_modules_mut<'a>() -> Option<&'a mut EmulatorModules<ET, S>> {
        unsafe { (EMULATOR_MODULES as *mut EmulatorModules<ET, S>).as_mut() }
    }
}

impl<ET, S> EmulatorModules<ET, S>
where
    ET: Unpin,
    S: UsesInput + Unpin,
{
    pub fn modules_mut(&mut self) -> &mut ET {
        self.modules.as_mut().get_mut()
    }

    pub fn instructions(
        &mut self,
        addr: GuestAddr,
        hook: InstructionHook<ET, S>,
        invalidate_block: bool,
    ) -> Option<InstructionHookId> {
        self.hooks.instructions(addr, hook, invalidate_block)
    }

    pub fn instruction_function(
        &mut self,
        addr: GuestAddr,
        hook: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, GuestAddr),
        invalidate_block: bool,
    ) -> InstructionHookId {
        self.hooks
            .instruction_function(addr, hook, invalidate_block)
    }

    pub fn instruction_closure(
        &mut self,
        addr: GuestAddr,
        hook: InstructionHookClosure<ET, S>,
        invalidate_block: bool,
    ) -> InstructionHookId {
        self.hooks.instruction_closure(addr, hook, invalidate_block)
    }

    pub fn edges(
        &mut self,
        generation_hook: EdgeGenHook<ET, S>,
        execution_hook: EdgeExecHook<ET, S>,
    ) -> EdgeHookId {
        self.hooks.edges(generation_hook, execution_hook)
    }

    pub fn blocks(
        &mut self,
        generation_hook: BlockGenHook<ET, S>,
        post_generation_hook: BlockPostGenHook<ET, S>,
        execution_hook: BlockExecHook<ET, S>,
    ) -> BlockHookId {
        self.hooks
            .blocks(generation_hook, post_generation_hook, execution_hook)
    }

    #[allow(clippy::similar_names)]
    pub fn reads(
        &mut self,
        generation_hook: ReadGenHook<ET, S>,
        execution_hook_1: ReadExecHook<ET, S>,
        execution_hook_2: ReadExecHook<ET, S>,
        execution_hook_4: ReadExecHook<ET, S>,
        execution_hook_8: ReadExecHook<ET, S>,
        execution_hook_n: ReadExecNHook<ET, S>,
    ) -> ReadHookId {
        self.hooks.reads(
            generation_hook,
            execution_hook_1,
            execution_hook_2,
            execution_hook_4,
            execution_hook_8,
            execution_hook_n,
        )
    }

    #[allow(clippy::similar_names)]
    pub fn writes(
        &mut self,
        generation_hook: WriteGenHook<ET, S>,
        execution_hook_1: WriteExecHook<ET, S>,
        execution_hook_2: WriteExecHook<ET, S>,
        execution_hook_4: WriteExecHook<ET, S>,
        execution_hook_8: WriteExecHook<ET, S>,
        execution_hook_n: WriteExecNHook<ET, S>,
    ) -> WriteHookId {
        self.hooks.writes(
            generation_hook,
            execution_hook_1,
            execution_hook_2,
            execution_hook_4,
            execution_hook_8,
            execution_hook_n,
        )
    }

    pub fn cmps(
        &mut self,
        generation_hook: CmpGenHook<ET, S>,
        execution_hook_1: CmpExecHook<ET, S, u8>,
        execution_hook_2: CmpExecHook<ET, S, u16>,
        execution_hook_4: CmpExecHook<ET, S, u32>,
        execution_hook_8: CmpExecHook<ET, S, u64>,
    ) -> CmpHookId {
        self.hooks.cmps(
            generation_hook,
            execution_hook_1,
            execution_hook_2,
            execution_hook_4,
            execution_hook_8,
        )
    }

    /// # Safety
    /// This will potentially call an unsafe backdoor hook
    pub unsafe fn backdoor(&mut self, hook: BackdoorHook<ET, S>) -> Option<BackdoorHookId> {
        self.hooks.backdoor(hook)
    }

    pub fn backdoor_function(&mut self, hook: BackdoorHookFn<ET, S>) -> BackdoorHookId {
        self.hooks.backdoor_function(hook)
    }

    /// # Safety
    /// Calls through to the potentially unsafe `backdoor_closure`
    pub unsafe fn backdoor_closure(&mut self, hook: BackdoorHookClosure<ET, S>) -> BackdoorHookId {
        self.hooks.backdoor_closure(hook)
    }

    pub fn thread_creation(&mut self, hook: NewThreadHook<ET, S>) -> Option<NewThreadHookId> {
        self.hooks.thread_creation(hook)
    }

    pub fn thread_creation_function(
        &mut self,
        hook: fn(
            &mut EmulatorModules<ET, S>,
            Option<&mut S>,
            env: CPUArchStatePtr,
            tid: u32,
        ) -> bool,
    ) -> NewThreadHookId {
        self.hooks.thread_creation_function(hook)
    }

    pub fn thread_creation_closure(
        &mut self,
        hook: NewThreadHookClosure<ET, S>,
    ) -> NewThreadHookId {
        self.hooks.thread_creation_closure(hook)
    }
}

impl<ET, S> EmulatorModules<ET, S>
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    pub(super) fn new(
        qemu: Qemu,
        emulator_hooks: EmulatorHooks<ET, S>,
        modules: ET,
    ) -> Pin<Box<Self>> {
        let mut modules = Box::pin(Self {
            qemu,
            modules: Box::pin(modules),
            hooks: emulator_hooks,
            phantom: PhantomData,
        });

        // re-translate blocks with hooks
        // qemu.flush_jit();
        // -> it should be useless, since EmulatorModules must be init before QEMU ever runs
        // TODO: Check if this is true

        // Set global EmulatorModules pointer
        unsafe {
            if EMULATOR_MODULES.is_null() {
                EMULATOR_MODULES = ptr::from_mut::<Self>(modules.as_mut().get_mut()) as *mut ();
            } else {
                panic!("Emulator Modules have already been set and is still active. It is not supported to have multiple instances of `EmulatorModules` at the same time yet.")
            }
        }

        modules
    }

    pub fn post_qemu_init_all(&mut self) {
        // We give access to EmulatorModuleTuple<S> during init, the compiler complains (for good reasons)
        // TODO: We should find a way to be able to check for a module without giving full access to the tuple.
        unsafe {
            self.modules_mut()
                .post_qemu_init_all(Self::emulator_modules_mut_unchecked());
        }
    }

    pub fn first_exec_all(&mut self, state: &mut S) {
        // # Safety
        // We assume that the emulator was initialized correctly
        unsafe {
            self.modules_mut()
                .first_exec_all(Self::emulator_modules_mut_unchecked(), state);
        }
    }

    pub fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) {
        // # Safety
        // We assume that the emulator was initialized correctly
        unsafe {
            self.modules_mut()
                .pre_exec_all(Self::emulator_modules_mut_unchecked(), state, input);
        }
    }

    pub fn post_exec_all<OT>(
        &mut self,
        state: &mut S,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
    {
        unsafe {
            self.modules_mut().post_exec_all(
                Self::emulator_modules_mut_unchecked(),
                state,
                input,
                observers,
                exit_kind,
            );
        }
    }

    /// Get a reference to the first (type) matching member of the tuple.
    #[must_use]
    pub fn get<T>(&self) -> Option<&T>
    where
        T: EmulatorModule<S>,
    {
        self.modules.match_first_type::<T>()
    }

    /// Get a mutable reference to the first (type) matching member of the tuple.
    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: EmulatorModule<S>,
    {
        self.modules.match_first_type_mut::<T>()
    }
}

impl<ET, S> EmulatorModules<ET, S>
where
    S: UsesInput,
{
    #[must_use]
    pub fn qemu(&self) -> Qemu {
        self.qemu
    }

    #[must_use]
    pub fn modules(&self) -> &ET {
        self.modules.as_ref().get_ref()
    }

    pub fn hooks_mut(&mut self) -> &mut EmulatorHooks<ET, S> {
        &mut self.hooks
    }
}

/// Usermode-only high-level functions
#[cfg(feature = "usermode")]
impl<ET, S> EmulatorModules<ET, S>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    #[allow(clippy::type_complexity)]
    pub fn syscalls(&mut self, hook: PreSyscallHook<ET, S>) -> Option<PreSyscallHookId> {
        self.hooks.syscalls(hook)
    }

    /// # Safety
    /// Calls through to the, potentially unsafe, `syscalls_function`
    #[allow(clippy::type_complexity)]
    pub unsafe fn syscalls_function(
        &mut self,
        hook: fn(
            &mut EmulatorModules<ET, S>,
            Option<&mut S>,
            sys_num: i32,
            a0: GuestAddr,
            a1: GuestAddr,
            a2: GuestAddr,
            a3: GuestAddr,
            a4: GuestAddr,
            a5: GuestAddr,
            a6: GuestAddr,
            a7: GuestAddr,
        ) -> SyscallHookResult,
    ) -> PreSyscallHookId {
        self.hooks.syscalls_function(hook)
    }

    /// # Safety
    /// Calls through to the, potentially unsafe, `syscalls_closure`
    #[allow(clippy::type_complexity)]
    pub unsafe fn syscalls_closure(
        &mut self,
        hook: Box<
            dyn for<'a> FnMut(
                &'a mut EmulatorModules<ET, S>,
                Option<&'a mut S>,
                i32,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
            ) -> SyscallHookResult,
        >,
    ) -> PreSyscallHookId {
        self.hooks.syscalls_closure(hook)
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls(&mut self, hook: PostSyscallHook<ET, S>) -> Option<PostSyscallHookId> {
        self.hooks.after_syscalls(hook)
    }

    /// # Safety
    /// Calls through to the, potentially unsafe, `after_syscalls_function`
    #[allow(clippy::type_complexity)]
    pub unsafe fn after_syscalls_function(
        &mut self,
        hook: fn(
            &mut EmulatorModules<ET, S>,
            Option<&mut S>,
            res: GuestAddr,
            sys_num: i32,
            a0: GuestAddr,
            a1: GuestAddr,
            a2: GuestAddr,
            a3: GuestAddr,
            a4: GuestAddr,
            a5: GuestAddr,
            a6: GuestAddr,
            a7: GuestAddr,
        ) -> GuestAddr,
    ) -> PostSyscallHookId {
        self.hooks.after_syscalls_function(hook)
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls_closure(
        &mut self,
        hook: Box<
            dyn for<'a> FnMut(
                &'a mut EmulatorModules<ET, S>,
                Option<&mut S>,
                GuestAddr,
                i32,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
            ) -> GuestAddr,
        >,
    ) -> PostSyscallHookId {
        self.hooks.after_syscalls_closure(hook)
    }

    pub fn crash_function(&mut self, hook: fn(&mut EmulatorModules<ET, S>, target_signal: i32)) {
        self.hooks.crash_function(hook);
    }

    /// # Safety
    /// Calls through to the, potentially unsafe, registered `crash_closure`
    pub unsafe fn crash_closure(&mut self, hook: CrashHookClosure<ET, S>) {
        self.hooks.crash_closure(hook);
    }
}

impl<ET, S> Drop for EmulatorModules<ET, S>
where
    S: UsesInput,
{
    fn drop(&mut self) {
        // Make the global pointer null at drop time
        unsafe {
            EMULATOR_MODULES = ptr::null_mut();
        }
    }
}
