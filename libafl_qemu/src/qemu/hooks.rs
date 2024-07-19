//! The high-level hooks
#![allow(clippy::type_complexity, clippy::missing_transmute_annotations)]

use core::{ffi::c_void, fmt::Debug, mem::transmute, ptr};

use libafl::{executors::hooks::inprocess::inprocess_get_state, inputs::UsesInput};
#[cfg(emulation_mode = "usermode")]
use libafl_qemu_sys::libafl_dump_core_hook;
use libafl_qemu_sys::{CPUArchStatePtr, FatPtr, GuestAddr, GuestUsize};
#[cfg(feature = "python")]
use pyo3::{pyclass, pymethods, FromPyObject};

use crate::{
    emu::EmulatorModules,
    modules::EmulatorModuleTuple,
    qemu::{MemAccessInfo, Qemu},
    sys::TCGTemp,
    HookData, HookId,
};

pub const SKIP_EXEC_HOOK: u64 = u64::MAX;

// all kinds of hooks
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HookRepr {
    Function(*const c_void),
    Closure(FatPtr),
    Empty,
}

#[derive(Debug)]
pub struct HookState<const N: usize, H: HookId> {
    id: H,
    gen: HookRepr,
    post_gen: HookRepr,
    execs: [HookRepr; N],
}

impl<const N: usize, H: HookId> HookState<N, H> {
    pub fn new(id: H, gen: HookRepr, post_gen: HookRepr, execs: [HookRepr; N]) -> Self {
        Self {
            id,
            gen,
            post_gen,
            execs,
        }
    }

    pub unsafe fn set_id(&mut self, id: H) {
        self.id = id;
    }
}

pub enum Hook<F, C, R: Clone> {
    Function(F),
    Closure(C),
    Raw(R),
    Empty,
}

#[repr(C)]
#[cfg_attr(feature = "python", pyclass)]
#[cfg_attr(feature = "python", derive(FromPyObject))]
pub struct SyscallHookResult {
    pub retval: GuestAddr,
    pub skip_syscall: bool,
}

impl<F, C, R: Clone> Hook<F, C, R> {
    pub fn is_empty(&self) -> bool {
        matches!(self, Hook::Empty)
    }
}

macro_rules! create_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*)) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, S>(hook: &mut c_void, $($param: $param_type),*)
            where
                ET: EmulatorModuleTuple<S>,
                S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    let func: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) = transmute(ptr::from_mut::<c_void>(hook));
                    func(modules, inprocess_get_state::<S>(), $($param),*);
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, S>(hook: &mut FatPtr, $($param: $param_type),*)
            where
                ET: EmulatorModuleTuple<S>,
                S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*)> = transmute(hook);
                    func(modules, inprocess_get_state::<S>(), $($param),*);
                }
            }
        }
    };
    ($name:ident, ($($param:ident : $param_type:ty),*), $ret_type:ty) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, S>(hook: &mut c_void, $($param: $param_type),*) -> $ret_type
            where
                ET: EmulatorModuleTuple<S>,
                S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    let func: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) -> $ret_type= transmute(ptr::from_mut::<c_void>(hook));
                    func(modules, inprocess_get_state::<S>(), $($param),*)
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, S>(hook: &mut FatPtr, $($param: $param_type),*) -> $ret_type
            where
                ET: EmulatorModuleTuple<S>,
                S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) -> $ret_type> = transmute(hook);
                    func(modules, inprocess_get_state::<S>(), $($param),*)
                }
            }
        }
    };
}

macro_rules! create_gen_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $ret_type:ty, $execs:literal, $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _gen_hook_wrapper>]<ET, S>(hook: &mut HookState<{ $execs }, $hook_id>, $($param: $param_type),*) -> $ret_type
            where
                ET: EmulatorModuleTuple<S>,
               S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();

                    match &mut hook.gen {
                        HookRepr::Function(ptr) => {
                            let func: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) -> Option<$ret_type> =
                                transmute(*ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*).map_or(SKIP_EXEC_HOOK, |id| id)
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) -> Option<$ret_type>,
                            > = transmute(ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*).map_or(SKIP_EXEC_HOOK, |id| id)
                        }
                        _ => 0,
                    }
                }
            }
        }
    }
}

macro_rules! create_post_gen_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $execs:literal, $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _post_gen_hook_wrapper>]<ET, S>(hook: &mut HookState<{ $execs }, $hook_id>, $($param: $param_type),*)
            where
                ET: EmulatorModuleTuple<S>,
               S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    match &mut hook.post_gen {
                        HookRepr::Function(ptr) => {
                            let func: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) =
                                transmute(*ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*),
                            > = transmute(ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

macro_rules! create_exec_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $execidx:literal, $execs:literal, $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _ $execidx _exec_hook_wrapper>]<ET, S>(hook: &mut HookState<{ $execs }, $hook_id>, $($param: $param_type),*)
            where
                ET: EmulatorModuleTuple<S>,
               S: Unpin + UsesInput,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, S>::emulator_modules_mut_unchecked();
                    match &mut hook.execs[$execidx] {
                        HookRepr::Function(ptr) => {
                            let func: fn(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*) = transmute(*ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<dyn FnMut(&mut EmulatorModules<ET, S>, Option<&mut S>, $($param_type),*)> =
                                transmute(ptr);
                            func(modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

macro_rules! create_hook_id {
    ($name:ident, $sys:ident, true) => {
        paste::paste! {
            #[derive(Clone, Copy, PartialEq, Debug)]
            pub struct [<$name HookId>](pub(crate) usize);
            impl [<$name HookId>] {
                #[must_use]
                pub fn invalid() -> Self {
                    Self(0)
                }
            }
            impl HookId for [<$name HookId>] {
                fn remove(&self, invalidate_block: bool) -> bool {
                    unsafe { libafl_qemu_sys::$sys(self.0, invalidate_block.into()) != 0 }
                }
            }
        }
    };
    ($name:ident, $sys:ident, false) => {
        paste::paste! {
            #[derive(Clone, Copy, PartialEq, Debug)]
            pub struct [<$name HookId>](pub(crate) usize);
            impl [<$name HookId>] {
                #[must_use]
                pub fn invalid() -> Self {
                    Self(0)
                }
            }
            impl HookId for [<$name HookId>] {
                fn remove(&self, _invalidate_block: bool) -> bool {
                    unsafe { libafl_qemu_sys::$sys(self.0) != 0 }
                }
            }
        }
    };
}

macro_rules! create_hook_types {
    ($name:ident, $fn_type:ty, $closure_type:ty, $raw_type:ty) => {
        paste::paste! {
            pub type [<$name HookFn>]<ET, S> = $fn_type;
            pub type [<$name HookClosure>]<ET, S> = $closure_type;
            pub type [<$name HookRaw>] = $raw_type;

            pub type [<$name Hook>]<ET, S> = Hook<
                [<$name HookFn>]<ET, S>,
                [<$name HookClosure>]<ET, S>,
                [<$name HookRaw>],
            >;
        }
    };
}

#[cfg(emulation_mode = "usermode")]
create_hook_id!(PostSyscall, libafl_qemu_remove_post_syscall_hook, false);
#[cfg(emulation_mode = "usermode")]
create_hook_id!(NewThread, libafl_qemu_remove_new_thread_hook, false);

// Instruction hook wrappers
create_hook_types!(
    Instruction,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, GuestAddr),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, GuestAddr)>,
    extern "C" fn(*const (), pc: GuestAddr)
);
create_hook_id!(Instruction, libafl_qemu_remove_instruction_hook, true);
create_wrapper!(instruction, (pc: GuestAddr));

// Backdoor hook wrappers
create_hook_types!(
    Backdoor,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, cpu: CPUArchStatePtr, GuestAddr),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, GuestAddr)>,
    extern "C" fn(*const (), cpu: CPUArchStatePtr, pc: GuestAddr)
);
create_hook_id!(Backdoor, libafl_qemu_remove_backdoor_hook, true);
create_wrapper!(backdoor, (cpu: CPUArchStatePtr, pc: GuestAddr));

// Pre-syscall hook wrappers
#[cfg(emulation_mode = "usermode")]
create_hook_types!(
    PreSyscall,
    fn(
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
    Box<
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
    extern "C" fn(
        *const (),
        i32,
        GuestAddr,
        GuestAddr,
        GuestAddr,
        GuestAddr,
        GuestAddr,
        GuestAddr,
        GuestAddr,
        GuestAddr,
    ) -> SyscallHookResult
);
#[cfg(emulation_mode = "usermode")]
create_hook_id!(PreSyscall, libafl_qemu_remove_pre_syscall_hook, false);
#[cfg(emulation_mode = "usermode")]
create_wrapper!(
    pre_syscall,
    (
        sys_num: i32,
        a0: GuestAddr,
        a1: GuestAddr,
        a2: GuestAddr,
        a3: GuestAddr,
        a4: GuestAddr,
        a5: GuestAddr,
        a6: GuestAddr,
        a7: GuestAddr
    ),
    SyscallHookResult
);

// Post-syscall hook wrappers
#[cfg(emulation_mode = "usermode")]
create_hook_types!(
    PostSyscall,
    fn(
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
    Box<
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
    extern "C" fn(
        *const (),
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
    ) -> GuestAddr
);
#[cfg(emulation_mode = "usermode")]
create_wrapper!(
    post_syscall,
    (
        res: GuestAddr,
        sys_num: i32,
        a0: GuestAddr,
        a1: GuestAddr,
        a2: GuestAddr,
        a3: GuestAddr,
        a4: GuestAddr,
        a5: GuestAddr,
        a6: GuestAddr,
        a7: GuestAddr
    ),
    GuestAddr
);

// New thread hook wrappers
#[cfg(emulation_mode = "usermode")]
create_hook_types!(
    NewThread,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, tid: u32) -> bool,
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u32) -> bool>,
    extern "C" fn(*const (), tid: u32) -> bool
);
#[cfg(emulation_mode = "usermode")]
create_wrapper!(new_thread, (tid: u32), bool);

// Edge hook wrappers
create_hook_types!(
    EdgeGen,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, src: GuestAddr, dest: GuestAddr) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, S>,
            Option<&'a mut S>,
            GuestAddr,
            GuestAddr,
        ) -> Option<u64>,
    >,
    extern "C" fn(*const (), src: GuestAddr, dest: GuestAddr) -> u64
);
create_hook_types!(
    EdgeExec,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64)>,
    extern "C" fn(*const (), id: u64)
);
create_hook_id!(Edge, libafl_qemu_remove_edge_hook, true);
create_gen_wrapper!(edge, (src: GuestAddr, dest: GuestAddr), u64, 1, EdgeHookId);
create_exec_wrapper!(edge, (id: u64), 0, 1, EdgeHookId);

// Block hook wrappers
create_hook_types!(
    BlockGen,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, pc: GuestAddr) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, S>,
            Option<&'a mut S>,
            GuestAddr,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(*const (), pc: GuestAddr) -> u64
);
create_hook_types!(
    BlockPostGen,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, pc: GuestAddr, block_length: GuestUsize),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&mut S>, GuestAddr, GuestUsize)>,
    unsafe extern "C" fn(*const (), pc: GuestAddr, block_length: GuestUsize)
);
create_hook_types!(
    BlockExec,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64)>,
    unsafe extern "C" fn(*const (), id: u64)
);

create_hook_id!(Block, libafl_qemu_remove_block_hook, true);
create_gen_wrapper!(block, (addr: GuestAddr), u64, 1, BlockHookId);
create_post_gen_wrapper!(block, (addr: GuestAddr, len: GuestUsize), 1, BlockHookId);
create_exec_wrapper!(block, (id: u64), 0, 1, BlockHookId);

// Read hook wrappers
create_hook_types!(
    ReadGen,
    fn(
        qemu_modules: &mut EmulatorModules<ET, S>,
        Option<&mut S>,
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, S>,
            Option<&'a mut S>,
            GuestAddr,
            *mut TCGTemp,
            MemAccessInfo,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(*const (), pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo) -> u64
);
create_hook_types!(
    ReadExec,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64, addr: GuestAddr),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64, GuestAddr)>,
    unsafe extern "C" fn(*const (), id: u64, addr: GuestAddr)
);
create_hook_types!(
    ReadExecN,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64, addr: GuestAddr, size: usize),
    Box<
        dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64, GuestAddr, usize),
    >,
    unsafe extern "C" fn(*const (), id: u64, addr: GuestAddr, size: usize)
);
create_hook_id!(Read, libafl_qemu_remove_read_hook, true);
create_gen_wrapper!(read, (pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo), u64, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, addr: GuestAddr), 0, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, addr: GuestAddr), 1, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, addr: GuestAddr), 2, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, addr: GuestAddr), 3, 5, ReadHookId);
create_exec_wrapper!(
    read,
    (id: u64, addr: GuestAddr, size: usize),
    4,
    5,
    ReadHookId
);

// Write hook wrappers
create_hook_types!(
    WriteGen,
    fn(
        &mut EmulatorModules<ET, S>,
        Option<&mut S>,
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, S>,
            Option<&'a mut S>,
            GuestAddr,
            *mut TCGTemp,
            MemAccessInfo,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(*const (), pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo) -> u64
);
create_hook_types!(
    WriteExec,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64, addr: GuestAddr),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64, GuestAddr)>,
    unsafe extern "C" fn(*const (), id: u64, addr: GuestAddr)
);
create_hook_types!(
    WriteExecN,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64, addr: GuestAddr, size: usize),
    Box<
        dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64, GuestAddr, usize),
    >,
    unsafe extern "C" fn(*const (), id: u64, addr: GuestAddr, size: usize)
);
create_hook_id!(Write, libafl_qemu_remove_write_hook, true);
create_gen_wrapper!(write, (pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo), u64, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, addr: GuestAddr), 0, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, addr: GuestAddr), 1, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, addr: GuestAddr), 2, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, addr: GuestAddr), 3, 5, WriteHookId);
create_exec_wrapper!(
    write,
    (id: u64, addr: GuestAddr, size: usize),
    4,
    5,
    WriteHookId
);

// Cmp hook wrappers
create_hook_types!(
    CmpGen,
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, pc: GuestAddr, size: usize) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, S>,
            Option<&'a mut S>,
            GuestAddr,
            usize,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(*const (), pc: GuestAddr, size: usize) -> u64
);
pub type CmpExecHook<ET, S, SZ> = Hook<
    fn(&mut EmulatorModules<ET, S>, Option<&mut S>, id: u64, v0: SZ, v1: SZ),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, S>, Option<&'a mut S>, u64, SZ, SZ)>,
    unsafe extern "C" fn(*const (), id: u64, v0: SZ, v1: SZ),
>;
create_hook_id!(Cmp, libafl_qemu_remove_cmp_hook, true);
create_gen_wrapper!(cmp, (pc: GuestAddr, size: usize), u64, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u8, v1: u8), 0, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u16, v1: u16), 1, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u32, v1: u32), 2, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u64, v1: u64), 3, 4, CmpHookId);

// Crash hook wrappers
#[cfg(emulation_mode = "usermode")]
pub type CrashHookClosure<ET, S> = Box<dyn FnMut(&mut EmulatorModules<ET, S>, i32)>;

/// The thin wrapper around QEMU hooks.
/// It is considered unsafe to use it directly.
#[derive(Clone, Copy, Debug)]
pub struct QemuHooks {
    _private: (),
}

impl QemuHooks {
    /// Get a `QemuHooks` object.
    /// Same as `QemuHooks::get`, but without checking whether `QemuHooks` have been correctly initialized.
    ///
    /// # Safety
    ///
    /// Should not be used out of Qemu itself.
    /// Prefer `Qemu::get` for a safe version of this method.
    #[must_use]
    pub unsafe fn get_unchecked() -> Self {
        QemuHooks { _private: () }
    }

    #[must_use]
    pub fn get() -> Option<Self> {
        // Use QEMU to check if hooks have been initialized.
        Some(Qemu::get()?.hooks())
    }

    // TODO set T lifetime to be like Emulator
    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_instruction_hooks<T: Into<HookData>>(
        &self,
        data: T,
        addr: GuestAddr,
        callback: extern "C" fn(T, GuestAddr),
        invalidate_block: bool,
    ) -> InstructionHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, GuestAddr) = transmute(callback);
            let num = libafl_qemu_sys::libafl_qemu_add_instruction_hooks(
                addr.into(),
                Some(callback),
                data,
                i32::from(invalidate_block),
            );
            InstructionHookId(num)
        }
    }

    #[must_use]
    pub fn remove_instruction_hooks_at(&self, addr: GuestAddr, invalidate_block: bool) -> usize {
        unsafe {
            libafl_qemu_sys::libafl_qemu_remove_instruction_hooks_at(
                addr.into(),
                i32::from(invalidate_block),
            )
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_edge_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr, GuestAddr) -> u64>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> EdgeHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<unsafe extern "C" fn(u64, GuestAddr, GuestAddr) -> u64> =
                transmute(gen);
            let exec: Option<unsafe extern "C" fn(u64, u64)> = transmute(exec);
            let num = libafl_qemu_sys::libafl_add_edge_hook(gen, exec, data);
            EdgeHookId(num)
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<unsafe extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> BlockHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<unsafe extern "C" fn(u64, GuestAddr) -> u64> = transmute(gen);
            let post_gen: Option<unsafe extern "C" fn(u64, GuestAddr, GuestUsize)> =
                transmute(post_gen);
            let exec: Option<unsafe extern "C" fn(u64, u64)> = transmute(exec);
            let num = libafl_qemu_sys::libafl_add_block_hook(gen, post_gen, exec, data);
            BlockHookId(num)
        }
    }

    /// `data` can be used to pass data that can be accessed as the first argument in the `gen` and the `exec` functions
    ///
    /// `gen` gets passed the current programm counter, mutable access to a `TCGTemp` and information about the memory
    /// access being performed.
    ///  The `u64` return value is an id that gets passed to the `exec` functions as their second argument.
    ///
    /// `exec` hooks get invoked on every read performed by the guest
    ///
    /// `exec1`-`exec8` special case accesses of width 1-8
    ///
    /// If there is no specialized hook for a given read width, the `exec_n` will be
    /// called and its last argument will specify the access width
    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_read_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, usize)>,
    ) -> ReadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<
                unsafe extern "C" fn(
                    u64,
                    GuestAddr,
                    *mut TCGTemp,
                    libafl_qemu_sys::MemOpIdx,
                ) -> u64,
            > = transmute(gen);
            let exec1: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec8);
            let exec_n: Option<unsafe extern "C" fn(u64, u64, GuestAddr, usize)> =
                transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_read_hook(
                gen, exec1, exec2, exec4, exec8, exec_n, data,
            );
            ReadHookId(num)
        }
    }

    // TODO add MemOp info
    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_write_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, usize)>,
    ) -> WriteHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<
                unsafe extern "C" fn(
                    u64,
                    GuestAddr,
                    *mut TCGTemp,
                    libafl_qemu_sys::MemOpIdx,
                ) -> u64,
            > = transmute(gen);
            let exec1: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, GuestAddr)> = transmute(exec8);
            let exec_n: Option<unsafe extern "C" fn(u64, u64, GuestAddr, usize)> =
                transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_write_hook(
                gen, exec1, exec2, exec4, exec8, exec_n, data,
            );
            WriteHookId(num)
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_cmp_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr, usize) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, u8, u8)>,
        exec2: Option<unsafe extern "C" fn(T, u64, u16, u16)>,
        exec4: Option<unsafe extern "C" fn(T, u64, u32, u32)>,
        exec8: Option<unsafe extern "C" fn(T, u64, u64, u64)>,
    ) -> CmpHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<unsafe extern "C" fn(u64, GuestAddr, usize) -> u64> = transmute(gen);
            let exec1: Option<unsafe extern "C" fn(u64, u64, u8, u8)> = transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, u16, u16)> = transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, u32, u32)> = transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, u64, u64)> = transmute(exec8);
            let num = libafl_qemu_sys::libafl_add_cmp_hook(gen, exec1, exec2, exec4, exec8, data);
            CmpHookId(num)
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    pub fn add_backdoor_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, CPUArchStatePtr, GuestAddr),
    ) -> BackdoorHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, CPUArchStatePtr, GuestAddr) = transmute(callback);
            let num = libafl_qemu_sys::libafl_add_backdoor_hook(Some(callback), data);
            BackdoorHookId(num)
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl QemuHooks {
    #[allow(clippy::type_complexity)]
    pub fn add_pre_syscall_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(
            T,
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
    ) -> PreSyscallHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(
                u64,
                i32,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
            ) -> libafl_qemu_sys::syshook_ret = transmute(callback);
            let num = libafl_qemu_sys::libafl_add_pre_syscall_hook(Some(callback), data);
            PreSyscallHookId(num)
        }
    }

    pub fn add_new_thread_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, tid: u32) -> bool,
    ) -> NewThreadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, u32) -> bool = transmute(callback);
            let num = libafl_qemu_sys::libafl_add_new_thread_hook(Some(callback), data);
            NewThreadHookId(num)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn add_post_syscall_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(
            T,
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
    ) -> PostSyscallHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(
                u64,
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
            ) -> GuestAddr = transmute(callback);
            let num = libafl_qemu_sys::libafl_add_post_syscall_hook(Some(callback), data);
            PostSyscallHookId(num)
        }
    }

    #[allow(clippy::type_complexity)]
    #[allow(clippy::unused_self)]
    pub(crate) fn set_crash_hook(self, callback: extern "C" fn(i32)) {
        unsafe {
            libafl_dump_core_hook = callback;
        }
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl SyscallHookResult {
    #[new]
    #[must_use]
    pub fn new(value: Option<GuestAddr>) -> Self {
        value.map_or(
            Self {
                retval: 0,
                skip_syscall: false,
            },
            |v| Self {
                retval: v,
                skip_syscall: true,
            },
        )
    }
}

#[cfg(not(feature = "python"))]
impl SyscallHookResult {
    #[must_use]
    pub fn new(value: Option<GuestAddr>) -> Self {
        value.map_or(
            Self {
                retval: 0,
                skip_syscall: false,
            },
            |v| Self {
                retval: v,
                skip_syscall: true,
            },
        )
    }
}
