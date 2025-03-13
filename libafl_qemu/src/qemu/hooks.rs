//! The high-level hooks

#![allow(clippy::type_complexity)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::too_many_arguments)]

use core::{ffi::c_void, fmt::Debug, mem::transmute, ptr};

use libafl::executors::hooks::inprocess::inprocess_get_state;
use libafl_qemu_sys::{CPUArchStatePtr, CPUStatePtr, FatPtr, GuestAddr, GuestUsize};
#[cfg(feature = "python")]
use pyo3::{FromPyObject, pyclass, pymethods};

use crate::{
    HookData, HookId,
    emu::EmulatorModules,
    qemu::{MemAccessInfo, Qemu},
    sys::TCGTemp,
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
pub struct TcgHookState<const N: usize, H: HookId> {
    id: H,
    generator: HookRepr,
    post_gen: HookRepr,
    execs: [HookRepr; N],
}

#[derive(Debug)]
pub struct HookState<H: HookId> {
    id: H,
    pre_run: HookRepr,
    post_run: HookRepr,
}

impl<const N: usize, H: HookId> TcgHookState<N, H> {
    pub fn new(id: H, generator: HookRepr, post_gen: HookRepr, execs: [HookRepr; N]) -> Self {
        Self {
            id,
            generator,
            post_gen,
            execs,
        }
    }

    /// # Safety
    ///
    /// ids should be in sync with QEMU hooks ids.
    pub unsafe fn set_id(&mut self, id: H) {
        self.id = id;
    }
}

impl<H: HookId> HookState<H> {
    pub fn new(id: H, pre_run: HookRepr, post_run: HookRepr) -> Self {
        Self {
            id,
            pre_run,
            post_run,
        }
    }

    /// # Safety
    ///
    /// ids should be in sync with QEMU hooks ids.
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

macro_rules! create_pre_init_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*)) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, I, S>(hook: &mut (), $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: fn(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) = transmute(ptr::from_mut::<()>(hook));
                    func(modules, inprocess_get_state::<S>(), $($param),*);
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, I, S>(hook: &mut FatPtr, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)> = &mut *(ptr::from_mut::<FatPtr>(hook) as *mut Box<dyn FnMut(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)>);
                    func(modules, inprocess_get_state::<S>(), $($param),*);
                }
            }
        }
    };
    ($name:ident, ($($param:ident : $param_type:ty),*), $ret_type:ty) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, I, S>(hook: &mut (), $($param: $param_type),*) -> $ret_type
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: fn(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type= transmute(ptr::from_mut::<()>(hook));
                    func(modules, inprocess_get_state::<S>(), $($param),*)
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, I, S>(hook: &mut FatPtr, $($param: $param_type),*) -> $ret_type
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type> = &mut *(ptr::from_mut::<FatPtr>(hook) as *mut Box<dyn FnMut(&mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type>);
                    func(modules, inprocess_get_state::<S>(), $($param),*)
                }
            }
        }
    };
}

macro_rules! create_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*)) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, I, S>(hook: &mut (), $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) = transmute(ptr::from_mut::<()>(hook));
                    func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, I, S>(hook: &mut FatPtr, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)> = &mut *(ptr::from_mut::<FatPtr>(hook) as *mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)>);
                    func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                }
            }
        }
    };
    ($name:ident, ($($param:ident : $param_type:ty),*), $ret_type:ty) => {
        paste::paste! {
            pub extern "C" fn [<func_ $name _hook_wrapper>]<ET, I, S>(hook: &mut (), $($param: $param_type),*) -> $ret_type
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type= transmute(ptr::from_mut::<()>(hook));
                    func(qemu, modules, inprocess_get_state::<S>(), $($param),*)
                }
            }

            pub extern "C" fn [<closure_ $name _hook_wrapper>]<ET, I, S>(hook: &mut FatPtr, $($param: $param_type),*) -> $ret_type
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();
                    let func: &mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type> = &mut *(ptr::from_mut::<FatPtr>(hook) as *mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> $ret_type>);
                    func(qemu, modules, inprocess_get_state::<S>(), $($param),*)
                }
            }
        }
    };
}

macro_rules! create_pre_exec_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _pre_exec_hook_wrapper>]<ET, I, S>(hook: &mut HookState<$hook_id>, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();

                    match &mut hook.pre_run {
                        HookRepr::Function(ptr) => {
                            let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) =
                                transmute(*ptr);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*)
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*),
                            > = &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*),
                            >);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*)
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

macro_rules! create_post_exec_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _post_exec_hook_wrapper>]<ET, I, S>(hook: &mut HookState<$hook_id>, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();

                    match &mut hook.post_run {
                        HookRepr::Function(ptr) => {
                            let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) =
                                transmute(*ptr);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*),
                            > = &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*),
                            >);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

macro_rules! create_gen_wrapper {
    ($name:ident, ($($param:ident : $param_type:ty),*), $ret_type:ty, $execs:literal, $hook_id:ident) => {
        paste::paste! {
            pub extern "C" fn [<$name _gen_hook_wrapper>]<ET, I, S>(hook: &mut TcgHookState<{ $execs }, $hook_id>, $($param: $param_type),*) -> $ret_type
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();

                    match &mut hook.generator {
                        HookRepr::Function(ptr) => {
                            let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> Option<$ret_type> =
                                transmute(*ptr);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*).map_or(SKIP_EXEC_HOOK, |id| id)
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> Option<$ret_type>,
                            > = &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) -> Option<$ret_type>>);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*).map_or(SKIP_EXEC_HOOK, |id| id)
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
            pub extern "C" fn [<$name _post_gen_hook_wrapper>]<ET, I, S>(hook: &mut TcgHookState<{ $execs }, $hook_id>, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();

                    match &mut hook.post_gen {
                        HookRepr::Function(ptr) => {
                            let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) =
                                transmute(*ptr);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<
                                dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*),
                            > = &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)>);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
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
            pub extern "C" fn [<$name _ $execidx _exec_hook_wrapper>]<ET, I, S>(hook: &mut TcgHookState<{ $execs }, $hook_id>, $($param: $param_type),*)
            where
                I: Unpin,
                S: Unpin,
            {
                unsafe {
                    let qemu = Qemu::get_unchecked();
                    let modules = EmulatorModules::<ET, I, S>::emulator_modules_mut_unchecked();

                    match &mut hook.execs[$execidx] {
                        HookRepr::Function(ptr) => {
                            let func: fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*) = transmute(*ptr);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        HookRepr::Closure(ptr) => {
                            let func: &mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)> =
                                &mut *(ptr::from_mut::<FatPtr>(ptr) as *mut Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, $($param_type),*)>);
                            func(qemu, modules, inprocess_get_state::<S>(), $($param),*);
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}

macro_rules! create_hook_id {
    ($name:ident, $sys:ident,true) => {
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
    ($name:ident, $sys:ident,false) => {
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
            pub type [<$name HookFn>]<ET, I, S> = $fn_type;
            pub type [<$name HookClosure>]<ET, I, S> = $closure_type;
            pub type [<$name HookRaw>] = $raw_type;

            pub type [<$name Hook>]<ET, I, S> = Hook<
                [<$name HookFn>]<ET, I, S>,
                [<$name HookClosure>]<ET, I, S>,
                [<$name HookRaw>],
            >;
        }
    };
}

// Instruction hook wrappers
create_hook_types!(
    Instruction,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, GuestAddr),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, GuestAddr)>,
    extern "C" fn(*const (), pc: GuestAddr)
);
create_hook_id!(Instruction, libafl_qemu_remove_instruction_hook, true);
create_wrapper!(instruction, (pc: GuestAddr));

// Backdoor hook wrappers
create_hook_types!(
    Backdoor,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, cpu: CPUArchStatePtr, GuestAddr),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, GuestAddr)>,
    extern "C" fn(libafl_qemu_opaque: *const (), cpu: CPUArchStatePtr, pc: GuestAddr)
);
create_hook_id!(Backdoor, libafl_qemu_remove_backdoor_hook, true);
create_wrapper!(backdoor, (cpu: CPUArchStatePtr, pc: GuestAddr));

// Pre-syscall hook wrappers
#[cfg(feature = "usermode")]
create_hook_types!(
    PreSyscall,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
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
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
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
#[cfg(feature = "usermode")]
create_hook_id!(PreSyscall, libafl_qemu_remove_pre_syscall_hook, false);
#[cfg(feature = "usermode")]
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
#[cfg(feature = "usermode")]
create_hook_types!(
    PostSyscall,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
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
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
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
#[cfg(feature = "usermode")]
create_hook_id!(PostSyscall, libafl_qemu_remove_post_syscall_hook, false);
#[cfg(feature = "usermode")]
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
create_hook_types!(
    NewThread,
    fn(&mut EmulatorModules<ET, I, S>, Option<&mut S>, env: CPUArchStatePtr, tid: u32) -> bool,
    Box<
        dyn for<'a> FnMut(
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            CPUArchStatePtr,
            u32,
        ) -> bool,
    >,
    extern "C" fn(libafl_qemu_opaque: *const (), env: CPUArchStatePtr, tid: u32) -> bool
);
create_hook_id!(NewThread, libafl_qemu_remove_new_thread_hook, false);
create_pre_init_wrapper!(new_thread, (env: CPUArchStatePtr, tid: u32), bool);

// CPU Run hook wrappers
create_hook_types!(
    CpuPreRun,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, cpu: CPUStatePtr),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, CPUStatePtr)>,
    extern "C" fn(libafl_qemu_opaque: *const (), cpu: CPUStatePtr)
);
create_hook_types!(
    CpuPostRun,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, cpu: CPUStatePtr),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, CPUStatePtr)>,
    extern "C" fn(libafl_qemu_opaque: *const (), cpu: CPUStatePtr)
);
create_hook_id!(CpuRun, libafl_qemu_remove_cpu_run_hook, false);
create_pre_exec_wrapper!(cpu_run, (cpu: CPUStatePtr), CpuRunHookId);
create_post_exec_wrapper!(cpu_run, (addr: CPUStatePtr), CpuRunHookId);
create_wrapper!(cpu_run, (cpu: CPUStatePtr));

// Edge hook wrappers
create_hook_types!(
    EdgeGen,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        src: GuestAddr,
        dest: GuestAddr,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            GuestAddr,
            GuestAddr,
        ) -> Option<u64>,
    >,
    extern "C" fn(libafl_qemu_opaque: *const (), src: GuestAddr, dest: GuestAddr) -> u64
);
create_hook_types!(
    EdgeExec,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, id: u64),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, u64)>,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), id: u64)
);
create_hook_id!(Edge, libafl_qemu_remove_edge_hook, true);
create_gen_wrapper!(edge, (src: GuestAddr, dest: GuestAddr), u64, 1, EdgeHookId);
create_exec_wrapper!(edge, (id: u64), 0, 1, EdgeHookId);

// Block hook wrappers
create_hook_types!(
    BlockGen,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, pc: GuestAddr) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            GuestAddr,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), pc: GuestAddr) -> u64
);
create_hook_types!(
    BlockPostGen,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        pc: GuestAddr,
        block_length: GuestUsize,
    ),
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&mut S>,
            GuestAddr,
            GuestUsize,
        ),
    >,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), pc: GuestAddr, block_length: GuestUsize)
);
create_hook_types!(
    BlockExec,
    fn(Qemu, &mut EmulatorModules<ET, I, S>, Option<&mut S>, id: u64),
    Box<dyn for<'a> FnMut(Qemu, &'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, u64)>,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), id: u64)
);

create_hook_id!(Block, libafl_qemu_remove_block_hook, true);
create_gen_wrapper!(block, (addr: GuestAddr), u64, 1, BlockHookId);
create_post_gen_wrapper!(block, (addr: GuestAddr, len: GuestUsize), 1, BlockHookId);
create_exec_wrapper!(block, (id: u64), 0, 1, BlockHookId);

// Read hook wrappers
create_hook_types!(
    ReadGen,
    fn(
        Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            GuestAddr,
            *mut TCGTemp,
            MemAccessInfo,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(
        libafl_qemu_opaque: *const (),
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> u64
);
create_hook_types!(
    ReadExec,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
    ),
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            u64,
            GuestAddr,
            GuestAddr,
        ),
    >,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), id: u64, pc: GuestAddr, addr: GuestAddr)
);
create_hook_types!(
    ReadExecN,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
        size: usize,
    ),
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            u64,
            GuestAddr,
            GuestAddr,
            usize,
        ),
    >,
    unsafe extern "C" fn(
        libafl_qemu_opaque: *const (),
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
        size: usize,
    )
);
create_hook_id!(Read, libafl_qemu_remove_read_hook, true);
create_gen_wrapper!(read, (pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo), u64, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, pc: GuestAddr, addr: GuestAddr), 0, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, pc: GuestAddr, addr: GuestAddr), 1, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, pc: GuestAddr, addr: GuestAddr), 2, 5, ReadHookId);
create_exec_wrapper!(read, (id: u64, pc: GuestAddr, addr: GuestAddr), 3, 5, ReadHookId);
create_exec_wrapper!(
    read,
    (id: u64, addr: GuestAddr, pc: GuestAddr, size: usize),
    4,
    5,
    ReadHookId
);

// Write hook wrappers
create_hook_types!(
    WriteGen,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            GuestAddr,
            *mut TCGTemp,
            MemAccessInfo,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(
        libafl_qemu_opaque: *const (),
        pc: GuestAddr,
        addr: *mut TCGTemp,
        info: MemAccessInfo,
    ) -> u64
);
create_hook_types!(
    WriteExec,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
    ),
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            u64,
            GuestAddr,
            GuestAddr,
        ),
    >,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), id: u64, pc: GuestAddr, addr: GuestAddr)
);
create_hook_types!(
    WriteExecN,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
        size: usize,
    ),
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            u64,
            GuestAddr,
            GuestAddr,
            usize,
        ),
    >,
    unsafe extern "C" fn(
        libafl_qemu_opaque: *const (),
        id: u64,
        pc: GuestAddr,
        addr: GuestAddr,
        size: usize,
    )
);
create_hook_id!(Write, libafl_qemu_remove_write_hook, true);
create_gen_wrapper!(write, (pc: GuestAddr, addr: *mut TCGTemp, info: MemAccessInfo), u64, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, pc: GuestAddr, addr: GuestAddr), 0, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, pc: GuestAddr, addr: GuestAddr), 1, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, pc: GuestAddr, addr: GuestAddr), 2, 5, WriteHookId);
create_exec_wrapper!(write, (id: u64, pc: GuestAddr, addr: GuestAddr), 3, 5, WriteHookId);
create_exec_wrapper!(
    write,
    (id: u64, pc: GuestAddr, addr: GuestAddr, size: usize),
    4,
    5,
    WriteHookId
);

// Cmp hook wrappers
create_hook_types!(
    CmpGen,
    fn(
        Qemu,
        &mut EmulatorModules<ET, I, S>,
        Option<&mut S>,
        pc: GuestAddr,
        size: usize,
    ) -> Option<u64>,
    Box<
        dyn for<'a> FnMut(
            Qemu,
            &'a mut EmulatorModules<ET, I, S>,
            Option<&'a mut S>,
            GuestAddr,
            usize,
        ) -> Option<u64>,
    >,
    unsafe extern "C" fn(libafl_qemu_opaque: *const (), pc: GuestAddr, size: usize) -> u64
);
pub type CmpExecHook<ET, I, S, SZ> = Hook<
    fn(&mut EmulatorModules<ET, I, S>, Option<&mut S>, id: u64, v0: SZ, v1: SZ),
    Box<dyn for<'a> FnMut(&'a mut EmulatorModules<ET, I, S>, Option<&'a mut S>, u64, SZ, SZ)>,
    unsafe extern "C" fn(*const (), id: u64, v0: SZ, v1: SZ),
>;
create_hook_id!(Cmp, libafl_qemu_remove_cmp_hook, true);
create_gen_wrapper!(cmp, (pc: GuestAddr, size: usize), u64, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u8, v1: u8), 0, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u16, v1: u16), 1, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u32, v1: u32), 2, 4, CmpHookId);
create_exec_wrapper!(cmp, (id: u64, v0: u64, v1: u64), 3, 4, CmpHookId);

// Crash hook wrappers
#[cfg(feature = "usermode")]
pub type CrashHookFn<ET, I, S> = fn(Qemu, &mut EmulatorModules<ET, I, S>, i32);
#[cfg(feature = "usermode")]
pub type CrashHookClosure<ET, I, S> = Box<dyn FnMut(Qemu, &mut EmulatorModules<ET, I, S>, i32)>;

/// The thin wrapper around QEMU hooks.
/// It is considered unsafe to use it directly.
///
/// There are several types of hooks in place:
///
/// • **Instruction** hooks: as the name suggests, to hook a specific
///   instruction given its address;
///
/// • **Blocks** hooks: to run code before the execution of each
///   translation block in the target; Be aware that a translation
///   block consist of a unique sequence of contiguous instructions encountered
///   during execution, whereas a basic-block is a sequence of contiguous
///   instructions without jumps AND with no incoming edge.
///   For this reason two translation blocks can overlap.
///
/// • **Edges** hooks: to run code between two translation blocks, for
///   instance, to log the execution of an edge in the CFG. In
///   detail, it is implemented by emitting an intermediate block
///   when chaining 1 two blocks with more than one exit;
///
/// • **Read and write** hooks: executed every memory read or
///   write;
///
/// • **Comparisons** hooks: executed before every comparison
///   instruction, carrying information about the operands;
///
/// • **Thread creation** hook: triggered when a new thread is
///   spawned in user mode;
///
/// • **Syscalls** and **post-syscalls** hooks: they are triggered before
///   or after syscalls in user mode and can be used as filters;
///
/// • **Crash** hooks: to hook crashes in the virtual CPU in user
///   mode;
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
    pub(crate) unsafe fn get_unchecked() -> Self {
        QemuHooks { _private: () }
    }

    #[must_use]
    pub fn get() -> Option<Self> {
        // Use QEMU to check if hooks have been initialized.
        Some(Qemu::get()?.hooks())
    }

    /// Add `callback` in the instruction hooks.
    ///
    /// `addr` is the address of the instruction hooked.
    ///
    /// `callback` gets passed `data` and the current instruction address.
    ///
    /// Set `invalidate_block` to invalidate the virtual pages related to the translation block.
    // TODO set T lifetime to be like Emulator
    pub fn add_instruction_hooks<T: Into<HookData>>(
        &self,
        data: T,
        addr: GuestAddr,
        callback: unsafe extern "C" fn(T, GuestAddr),
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

    /// Remove all instruction hooks for the address `addr`.
    ///
    /// Set `invalidate_block` to invalidate the virtual pages related to the translation block.
    #[must_use]
    pub fn remove_instruction_hooks_at(&self, addr: GuestAddr, invalidate_block: bool) -> usize {
        unsafe {
            libafl_qemu_sys::libafl_qemu_remove_instruction_hooks_at(
                addr.into(),
                i32::from(invalidate_block),
            )
        }
    }

    /// Add `gen` in the edge generation hooks and `exec` in the edge execution hooks.
    ///
    /// `gen` gets passed `data` and the source/destination translation blocks addresses
    /// when this edge is reached for the first time.
    ///
    /// `exec` gets passed `data` and the return value of `gen` every time this edge is reached.
    pub fn add_edge_hooks<T: Into<HookData>>(
        &self,
        data: T,
        generator: Option<unsafe extern "C" fn(T, GuestAddr, GuestAddr) -> u64>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> EdgeHookId {
        unsafe {
            let data: u64 = data.into().0;
            let generator: Option<unsafe extern "C" fn(u64, GuestAddr, GuestAddr) -> u64> =
                transmute(generator);
            let exec: Option<unsafe extern "C" fn(u64, u64)> = transmute(exec);
            let num = libafl_qemu_sys::libafl_add_edge_hook(generator, exec, data);
            EdgeHookId(num)
        }
    }

    /// Add `gen` in the translation block (pre-)generation hooks, `post_gen` in post-generation hooks and `exec`
    /// in the execution hooks.
    ///
    /// `gen` gets passed `data` and the block start address, when this block is translated
    /// for the first time.
    ///
    /// `post_gen` gets passed `data`, the block start address and the block size in bytes,
    /// at the end of the block generation.
    ///
    /// `exec` gets passed `data` and the return value of `gen`, every time this block is reached.
    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        generator: Option<unsafe extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<unsafe extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> BlockHookId {
        unsafe {
            let data: u64 = data.into().0;
            let generator: Option<unsafe extern "C" fn(u64, GuestAddr) -> u64> =
                transmute(generator);
            let post_gen: Option<unsafe extern "C" fn(u64, GuestAddr, GuestUsize)> =
                transmute(post_gen);
            let exec: Option<unsafe extern "C" fn(u64, u64)> = transmute(exec);
            let num = libafl_qemu_sys::libafl_add_block_hook(generator, post_gen, exec, data);
            BlockHookId(num)
        }
    }

    /// Add `pre_exec` in the (pre-)execution hooks, `post_exec` in the post-execution hooks.
    ///
    /// `pre_exec` gets passed a pointer to the cpu state before the code is run.
    ///
    /// `post_exec` gets passed a pointer to the cpu state after the code is run.
    pub fn add_cpu_run_hooks<T: Into<HookData>>(
        &self,
        data: T,
        pre_exec: Option<unsafe extern "C" fn(T, CPUStatePtr)>,
        post_exec: Option<unsafe extern "C" fn(T, CPUStatePtr)>,
    ) -> CpuRunHookId {
        unsafe {
            let data: u64 = data.into().0;
            let pre_exec: Option<unsafe extern "C" fn(u64, CPUStatePtr)> = transmute(pre_exec);
            let post_gen: Option<unsafe extern "C" fn(u64, CPUStatePtr)> = transmute(post_exec);
            let num = libafl_qemu_sys::libafl_hook_cpu_run_add(pre_exec, post_gen, data);
            CpuRunHookId(num)
        }
    }

    /// Add hooks for memory read access.
    ///
    /// `data` can be used to pass data that can be accessed as the first argument in the `gen` and the `exec` functions.
    ///
    /// `gen` gets passed `data`, the current program counter, mutable access to the address accessed and
    /// information about the memory access being performed.
    ///
    /// `exec` hooks get invoked on every read performed by the guest with `data`, the return value of `gen`,
    /// the current instruction index and the address of the memory accessed.
    ///
    /// `exec1`-`exec8` are called for special case accesses of width 1-8.
    ///
    /// If there is no specialized hook for a given read width, the `exec_n` will be
    /// called and its last argument will specify the access width.
    pub fn add_read_hooks<T: Into<HookData>>(
        &self,
        data: T,
        generator: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr, usize)>,
    ) -> ReadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let generator: Option<
                unsafe extern "C" fn(
                    u64,
                    GuestAddr,
                    *mut TCGTemp,
                    libafl_qemu_sys::MemOpIdx,
                ) -> u64,
            > = transmute(generator);
            let exec1: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec8);
            let exec_n: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr, usize)> =
                transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_read_hook(
                generator, exec1, exec2, exec4, exec8, exec_n, data,
            );
            ReadHookId(num)
        }
    }

    /// Add hooks for memory write access.
    ///
    /// `data` can be used to pass data that can be accessed as the first argument in the `gen` and the `exec` functions.
    ///
    /// `gen` gets passed `data`, the current program counter, mutable access to the address written and
    /// information about the memory access being performed.
    ///
    /// `exec` hooks get invoked on every write performed by the guest with `data`, the return value of `gen`,
    /// the current instruction index and the address of the memory written.
    ///
    /// `exec1`-`exec8` are called for special case write of width 1-8.
    ///
    /// If there is no specialized hook for a given write width, the `exec_n` will be
    /// called and its last argument will specify the write width.
    // TODO add MemOp info
    pub fn add_write_hooks<T: Into<HookData>>(
        &self,
        data: T,
        generator: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, GuestAddr, usize)>,
    ) -> WriteHookId {
        unsafe {
            let data: u64 = data.into().0;
            let generator: Option<
                unsafe extern "C" fn(
                    u64,
                    GuestAddr,
                    *mut TCGTemp,
                    libafl_qemu_sys::MemOpIdx,
                ) -> u64,
            > = transmute(generator);
            let exec1: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr)> =
                transmute(exec8);
            let exec_n: Option<unsafe extern "C" fn(u64, u64, GuestAddr, GuestAddr, usize)> =
                transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_write_hook(
                generator, exec1, exec2, exec4, exec8, exec_n, data,
            );
            WriteHookId(num)
        }
    }

    pub fn add_cmp_hooks<T: Into<HookData>>(
        &self,
        data: T,
        generator: Option<unsafe extern "C" fn(T, GuestAddr, usize) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, u8, u8)>,
        exec2: Option<unsafe extern "C" fn(T, u64, u16, u16)>,
        exec4: Option<unsafe extern "C" fn(T, u64, u32, u32)>,
        exec8: Option<unsafe extern "C" fn(T, u64, u64, u64)>,
    ) -> CmpHookId {
        unsafe {
            let data: u64 = data.into().0;
            let generator: Option<unsafe extern "C" fn(u64, GuestAddr, usize) -> u64> =
                transmute(generator);
            let exec1: Option<unsafe extern "C" fn(u64, u64, u8, u8)> = transmute(exec1);
            let exec2: Option<unsafe extern "C" fn(u64, u64, u16, u16)> = transmute(exec2);
            let exec4: Option<unsafe extern "C" fn(u64, u64, u32, u32)> = transmute(exec4);
            let exec8: Option<unsafe extern "C" fn(u64, u64, u64, u64)> = transmute(exec8);
            let num =
                libafl_qemu_sys::libafl_add_cmp_hook(generator, exec1, exec2, exec4, exec8, data);
            CmpHookId(num)
        }
    }

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

    pub fn add_new_thread_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, env: CPUArchStatePtr, tid: u32) -> bool,
    ) -> NewThreadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, CPUArchStatePtr, u32) -> bool = transmute(callback);
            let num = libafl_qemu_sys::libafl_add_new_thread_hook(Some(callback), data);
            NewThreadHookId(num)
        }
    }
}

#[cfg(feature = "usermode")]
impl QemuHooks {
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
}

#[cfg(feature = "python")]
#[pymethods]
impl SyscallHookResult {
    #[new]
    #[pyo3(signature = (
        value=None
    ))]
    #[must_use]
    pub fn new(value: Option<GuestAddr>) -> Self {
        Self::new_internal(value)
    }
}

impl SyscallHookResult {
    #[cfg(not(feature = "python"))]
    #[must_use]
    pub fn new(value: Option<GuestAddr>) -> Self {
        Self::new_internal(value)
    }

    #[must_use]
    fn new_internal(value: Option<GuestAddr>) -> Self {
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
