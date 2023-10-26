//! The high-level hooks
#![allow(clippy::type_complexity)]

use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    mem::transmute,
    ptr::{self, addr_of},
};

use libafl::{
    executors::{inprocess::inprocess_get_state, ExitKind},
    inputs::UsesInput,
    state::NopState,
};

pub use crate::emu::SyscallHookResult;
use crate::{
    emu::{Emulator, FatPtr, MemAccessInfo, SKIP_EXEC_HOOK},
    helper::QemuHelperTuple,
    GuestAddr, GuestUsize,
};

// all kinds of hooks
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Hook {
    Function(*const c_void),
    Closure(FatPtr),
    #[cfg(emulation_mode = "usermode")]
    Once(FatPtr),
    Empty,
}

/*
// function signature for Read or Write hook functions with known length (1, 2, 4, 8)
type FixedLenHookFn<QT, S> = fn(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr);
type FixedLenHookCl<QT, S> = Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr)>;

// function signature for Read or Write hook functions with runtime length n
type DynamicLenHookFn<QT, S> = fn(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr, usize);
type DynamicLenHookCl<QT, S> =
    Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr, usize)>;
*/

static mut QEMU_HOOKS_PTR: *const c_void = ptr::null();
unsafe fn get_qemu_hooks<'a, QT, S>() -> &'a mut QemuHooks<'a, QT, S>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    (QEMU_HOOKS_PTR as *mut QemuHooks<'a, QT, S>)
        .as_mut()
        .expect("A high-level hook is installed but QemuHooks is not initialized")
}

static mut GENERIC_HOOKS: Vec<Hook> = vec![];

extern "C" fn generic_hook_wrapper<QT, S>(pc: GuestAddr, index: u64)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let hook = &mut GENERIC_HOOKS[index as usize];
        match hook {
            Hook::Function(ptr) => {
                let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr) =
                    transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc);
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr),
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc);
            }
            _ => (),
        }
    }
}

static mut EDGE_HOOKS: Vec<(Hook, Hook)> = vec![];

extern "C" fn gen_edge_hook_wrapper<QT, S>(src: GuestAddr, dst: GuestAddr, index: u64) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (gen, _) = &mut EDGE_HOOKS[index as usize];
        match gen {
            Hook::Function(ptr) => {
                let func: fn(
                    &mut QemuHooks<'_, QT, S>,
                    Option<&mut S>,
                    GuestAddr,
                    GuestAddr,
                ) -> Option<u64> = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), src, dst).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        GuestAddr,
                        GuestAddr,
                    ) -> Option<u64>,
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), src, dst).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => 0,
        }
    }
}

extern "C" fn exec_edge_hook_wrapper<QT, S>(id: u64, index: u64)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (_, exec) = &mut EDGE_HOOKS[index as usize];
        match exec {
            Hook::Function(ptr) => {
                let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64) = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), id);
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64)> =
                    transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), id);
            }
            _ => (),
        }
    }
}

static mut BLOCK_HOOKS: Vec<(Hook, Hook, Hook)> = vec![];

extern "C" fn gen_block_hook_wrapper<QT, S>(pc: GuestAddr, index: u64) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (gen, _, _) = &mut BLOCK_HOOKS[index as usize];
        match gen {
            Hook::Function(ptr) => {
                let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr) -> Option<u64> =
                    transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr) -> Option<u64>,
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => 0,
        }
    }
}

extern "C" fn gen_post_block_hook_wrapper<QT, S>(
    pc: GuestAddr,
    block_length: GuestUsize,
    index: u64,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (_, post_gen, _) = &mut BLOCK_HOOKS[index as usize];
        match post_gen {
            Hook::Function(ptr) => {
                let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr, GuestUsize) =
                    transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc, block_length);
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, GuestAddr, GuestUsize),
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc, block_length);
            }
            _ => (),
        }
    }
}

extern "C" fn exec_block_hook_wrapper<QT, S>(id: u64, index: u64)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (_, _, exec) = &mut BLOCK_HOOKS[index as usize];
        match exec {
            Hook::Function(ptr) => {
                let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64) = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), id);
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64)> =
                    transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), id);
            }
            _ => (),
        }
    }
}

static mut READ_HOOKS: Vec<(Hook, Hook, Hook, Hook, Hook, Hook)> = vec![];
static mut WRITE_HOOKS: Vec<(Hook, Hook, Hook, Hook, Hook, Hook)> = vec![];

extern "C" fn gen_read_hook_wrapper<QT, S>(pc: GuestAddr, info: MemAccessInfo, index: u64) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (gen, _, _, _, _, _) = &mut READ_HOOKS[index as usize];
        match gen {
            Hook::Function(ptr) => {
                let func: fn(
                    &mut QemuHooks<'_, QT, S>,
                    Option<&mut S>,
                    GuestAddr,
                    MemAccessInfo,
                ) -> Option<u64> = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc, info).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        GuestAddr,
                        MemAccessInfo,
                    ) -> Option<u64>,
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc, info).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => 0,
        }
    }
}

extern "C" fn gen_write_hook_wrapper<QT, S>(pc: GuestAddr, info: MemAccessInfo, index: u64) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (gen, _, _, _, _, _) = &mut WRITE_HOOKS[index as usize];
        match gen {
            Hook::Function(ptr) => {
                let func: fn(
                    &mut QemuHooks<'_, QT, S>,
                    Option<&mut S>,
                    GuestAddr,
                    MemAccessInfo,
                ) -> Option<u64> = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc, info).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        GuestAddr,
                        MemAccessInfo,
                    ) -> Option<u64>,
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc, info).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => 0,
        }
    }
}

macro_rules! define_rw_exec_hook {
    ($name:ident, $field:tt, $global:ident) => {
        extern "C" fn $name<QT, S>(id: u64, addr: GuestAddr, index: u64)
        where
            S: UsesInput,
            QT: QemuHelperTuple<S>,
        {
            unsafe {
                let hooks = get_qemu_hooks::<QT, S>();
                let exec = &mut $global[index as usize].$field;
                match exec {
                    Hook::Function(ptr) => {
                        let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64, GuestAddr) =
                            transmute(*ptr);
                        func(hooks, inprocess_get_state::<S>(), id, addr);
                    }
                    Hook::Closure(ptr) => {
                        let func: &mut Box<
                            dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u64, GuestAddr),
                        > = transmute(ptr);
                        func(hooks, inprocess_get_state::<S>(), id, addr);
                    }
                    _ => (),
                }
            }
        }
    };
}

macro_rules! define_rw_exec_hook_n {
    ($name:ident, $field:tt, $global:ident) => {
        extern "C" fn $name<QT, S>(id: u64, addr: GuestAddr, size: usize, index: u64)
        where
            S: UsesInput,
            QT: QemuHelperTuple<S>,
        {
            unsafe {
                let hooks = get_qemu_hooks::<QT, S>();
                let exec = &mut $global[index as usize].$field;
                match exec {
                    Hook::Function(ptr) => {
                        let func: fn(
                            &mut QemuHooks<'_, QT, S>,
                            Option<&mut S>,
                            u64,
                            GuestAddr,
                            usize,
                        ) = transmute(*ptr);
                        func(hooks, inprocess_get_state::<S>(), id, addr, size);
                    }
                    Hook::Closure(ptr) => {
                        let func: &mut Box<
                            dyn FnMut(
                                &mut QemuHooks<'_, QT, S>,
                                Option<&mut S>,
                                u64,
                                GuestAddr,
                                usize,
                            ),
                        > = transmute(ptr);
                        func(hooks, inprocess_get_state::<S>(), id, addr, size);
                    }
                    _ => (),
                }
            }
        }
    };
}

define_rw_exec_hook!(exec_read1_hook_wrapper, 1, READ_HOOKS);
define_rw_exec_hook!(exec_read2_hook_wrapper, 2, READ_HOOKS);
define_rw_exec_hook!(exec_read4_hook_wrapper, 3, READ_HOOKS);
define_rw_exec_hook!(exec_read8_hook_wrapper, 4, READ_HOOKS);
define_rw_exec_hook_n!(exec_read_n_hook_wrapper, 5, READ_HOOKS);

define_rw_exec_hook!(exec_write1_hook_wrapper, 1, WRITE_HOOKS);
define_rw_exec_hook!(exec_write2_hook_wrapper, 2, WRITE_HOOKS);
define_rw_exec_hook!(exec_write4_hook_wrapper, 3, WRITE_HOOKS);
define_rw_exec_hook!(exec_write8_hook_wrapper, 4, WRITE_HOOKS);
define_rw_exec_hook_n!(exec_write_n_hook_wrapper, 5, WRITE_HOOKS);

static mut CMP_HOOKS: Vec<(Hook, Hook, Hook, Hook, Hook)> = vec![];

extern "C" fn gen_cmp_hook_wrapper<QT, S>(pc: GuestAddr, size: usize, index: u64) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let (gen, _, _, _, _) = &mut CMP_HOOKS[index as usize];
        match gen {
            Hook::Function(ptr) => {
                let func: fn(
                    &mut QemuHooks<'_, QT, S>,
                    Option<&mut S>,
                    GuestAddr,
                    usize,
                ) -> Option<u64> = transmute(*ptr);
                func(hooks, inprocess_get_state::<S>(), pc, size).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let func: &mut Box<
                    dyn FnMut(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        GuestAddr,
                        usize,
                    ) -> Option<u64>,
                > = transmute(ptr);
                func(hooks, inprocess_get_state::<S>(), pc, size).map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => 0,
        }
    }
}

macro_rules! define_cmp_exec_hook {
    ($name:ident, $field:tt, $itype:ty) => {
        extern "C" fn $name<QT, S>(id: u64, v0: $itype, v1: $itype, index: u64)
        where
            S: UsesInput,
            QT: QemuHelperTuple<S>,
        {
            unsafe {
                let hooks = get_qemu_hooks::<QT, S>();
                let exec = &mut CMP_HOOKS[index as usize].$field;
                match exec {
                    Hook::Function(ptr) => {
                        let func: fn(
                            &mut QemuHooks<'_, QT, S>,
                            Option<&mut S>,
                            u64,
                            $itype,
                            $itype,
                        ) = transmute(*ptr);
                        func(hooks, inprocess_get_state::<S>(), id, v0, v1);
                    }
                    Hook::Closure(ptr) => {
                        let func: &mut Box<
                            dyn FnMut(
                                &mut QemuHooks<'_, QT, S>,
                                Option<&mut S>,
                                u64,
                                $itype,
                                $itype,
                            ),
                        > = transmute(ptr);
                        func(hooks, inprocess_get_state::<S>(), id, v0, v1);
                    }
                    _ => (),
                }
            }
        }
    };
}

define_cmp_exec_hook!(exec_cmp1_hook_wrapper, 1, u8);
define_cmp_exec_hook!(exec_cmp2_hook_wrapper, 2, u16);
define_cmp_exec_hook!(exec_cmp4_hook_wrapper, 3, u32);
define_cmp_exec_hook!(exec_cmp8_hook_wrapper, 4, u64);

#[cfg(emulation_mode = "usermode")]
static mut ON_THREAD_HOOKS: Vec<Hook> = vec![];
#[cfg(emulation_mode = "usermode")]
extern "C" fn on_thread_hooks_wrapper<QT, S>(tid: u32)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        for hook in &mut ON_THREAD_HOOKS {
            let hooks = get_qemu_hooks::<QT, S>();
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u32) = transmute(*ptr);
                    func(hooks, inprocess_get_state::<S>(), tid);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<dyn FnMut(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u32)> =
                        transmute(*ptr);
                    func(hooks, inprocess_get_state::<S>(), tid);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                Hook::Once(ptr) => {
                    let func: Box<dyn FnOnce(&mut QemuHooks<'_, QT, S>, Option<&mut S>, u32)> =
                        transmute(*ptr);
                    func(hooks, inprocess_get_state::<S>(), tid);
                    *hook = Hook::Empty;
                }
                Hook::Empty => (),
            }
        }
    }
}

#[cfg(emulation_mode = "usermode")]
static mut SYSCALL_HOOKS: Vec<Hook> = vec![];
#[cfg(emulation_mode = "usermode")]
extern "C" fn syscall_hooks_wrapper<QT, S>(
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
) -> SyscallHookResult
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let mut res = SyscallHookResult::new(None);
        for hook in &SYSCALL_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let func: fn(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        i32,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                    ) -> SyscallHookResult = transmute(*ptr);
                    let r = func(
                        hooks,
                        inprocess_get_state::<S>(),
                        sys_num,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        a6,
                        a7,
                    );
                    if r.skip_syscall {
                        res.skip_syscall = true;
                        res.retval = r.retval;
                    }
                }
                Hook::Closure(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let mut func: Box<
                        dyn FnMut(
                            &mut QemuHooks<'_, QT, S>,
                            Option<&mut S>,
                            i32,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                        ) -> SyscallHookResult,
                    > = transmute(*ptr);
                    let r = func(
                        hooks,
                        inprocess_get_state::<S>(),
                        sys_num,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        a6,
                        a7,
                    );

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);

                    if r.skip_syscall {
                        res.skip_syscall = true;
                        res.retval = r.retval;
                    }
                }
                _ => (),
            }
        }
        res
    }
}

#[cfg(emulation_mode = "usermode")]
static mut SYSCALL_POST_HOOKS: Vec<Hook> = vec![];
#[cfg(emulation_mode = "usermode")]
extern "C" fn syscall_after_hooks_wrapper<QT, S>(
    result: u64,
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
) -> u64
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        let mut res = result;
        for hook in &SYSCALL_POST_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let func: fn(
                        &mut QemuHooks<'_, QT, S>,
                        Option<&mut S>,
                        u64,
                        i32,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                        u64,
                    ) -> u64 = transmute(*ptr);
                    res = func(
                        hooks,
                        inprocess_get_state::<S>(),
                        res,
                        sys_num,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        a6,
                        a7,
                    );
                }
                Hook::Closure(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let mut func: Box<
                        dyn FnMut(
                            &mut QemuHooks<'_, QT, S>,
                            Option<&mut S>,
                            u64,
                            i32,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                            u64,
                        ) -> u64,
                    > = transmute(*ptr);
                    res = func(
                        hooks,
                        inprocess_get_state::<S>(),
                        res,
                        sys_num,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        a6,
                        a7,
                    );

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
        res
    }
}

#[cfg(emulation_mode = "usermode")]
static mut CRASH_HOOKS: Vec<Hook> = vec![];

#[cfg(emulation_mode = "usermode")]
extern "C" fn crash_hook_wrapper<QT, S>(target_sig: i32)
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    unsafe {
        let hooks = get_qemu_hooks::<QT, S>();
        for hook in &mut CRASH_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&mut QemuHooks<'_, QT, S>, i32) = transmute(*ptr);
                    func(hooks, target_sig);
                }
                Hook::Closure(ptr) => {
                    let func: &mut Box<dyn FnMut(&mut QemuHooks<'_, QT, S>, i32)> = transmute(ptr);
                    func(hooks, target_sig);
                }
                _ => (),
            }
        }
    }
}

static mut HOOKS_IS_INITIALIZED: bool = false;

pub struct QemuHooks<'a, QT, S>
where
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    helpers: QT,
    emulator: &'a Emulator,
    phantom: PhantomData<S>,
}

impl<'a, QT, S> Debug for QemuHooks<'a, QT, S>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuHooks")
            .field("helpers", &self.helpers)
            .field("emulator", &self.emulator)
            .finish()
    }
}

impl<'a, I, QT> QemuHooks<'a, QT, NopState<I>>
where
    QT: QemuHelperTuple<NopState<I>>,
    NopState<I>: UsesInput<Input = I>,
{
    pub fn reproducer(emulator: &'a Emulator, helpers: QT) -> Box<Self> {
        Self::new(emulator, helpers)
    }

    pub fn repro_run<H>(&mut self, harness: &mut H, input: &I) -> ExitKind
    where
        H: FnMut(&I) -> ExitKind,
    {
        self.helpers.first_exec_all(self);
        self.helpers.pre_exec_all(self.emulator, input);

        let mut exit_kind = harness(input);

        self.helpers
            .post_exec_all(self.emulator, input, &mut (), &mut exit_kind);

        exit_kind
    }
}

impl<'a, QT, S> QemuHooks<'a, QT, S>
where
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    pub fn new(emulator: &'a Emulator, helpers: QT) -> Box<Self> {
        unsafe {
            assert!(
                !HOOKS_IS_INITIALIZED,
                "Only an instance of QemuHooks is permitted"
            );
            HOOKS_IS_INITIALIZED = true;
        }
        // re-translate blocks with hooks
        emulator.flush_jit();
        let slf = Box::new(Self {
            emulator,
            helpers,
            phantom: PhantomData,
        });
        slf.helpers.init_hooks_all(&slf);
        unsafe {
            QEMU_HOOKS_PTR = addr_of!(*slf) as *const c_void;
        }
        slf
    }

    #[must_use]
    pub fn match_helper<T>(&self) -> Option<&T>
    where
        T: 'static,
    {
        self.helpers.match_first_type::<T>()
    }

    #[must_use]
    pub fn match_helper_mut<T>(&mut self) -> Option<&mut T>
    where
        T: 'static,
    {
        self.helpers.match_first_type_mut::<T>()
    }

    pub fn emulator(&self) -> &Emulator {
        self.emulator
    }

    pub fn helpers(&self) -> &QT {
        &self.helpers
    }

    pub fn helpers_mut(&mut self) -> &mut QT {
        &mut self.helpers
    }

    pub fn instruction(
        &self,
        addr: GuestAddr,
        hook: fn(&mut Self, Option<&mut S>, GuestAddr),
        invalidate_block: bool,
    ) {
        unsafe {
            let index = GENERIC_HOOKS.len();
            self.emulator.set_hook(
                addr,
                generic_hook_wrapper::<QT, S>,
                index as u64,
                invalidate_block,
            );
            GENERIC_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
    }

    pub unsafe fn instruction_closure(
        &self,
        addr: GuestAddr,
        hook: Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr)>,
        invalidate_block: bool,
    ) {
        let index = GENERIC_HOOKS.len();
        self.emulator.set_hook(
            addr,
            generic_hook_wrapper::<QT, S>,
            index as u64,
            invalidate_block,
        );
        GENERIC_HOOKS.push(Hook::Closure(transmute(hook)));
    }

    pub fn edges(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, src: GuestAddr, dest: GuestAddr) -> Option<u64>,
        >,
        execution_hook: Option<fn(&mut Self, Option<&mut S>, id: u64)>,
    ) {
        unsafe {
            let index = EDGE_HOOKS.len();
            self.emulator.add_edge_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_edge_hook_wrapper::<QT, S> as _),
                execution_hook
                    .as_ref()
                    .map(|_| exec_edge_hook_wrapper::<QT, S> as _),
                index as u64,
            );
            EDGE_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
            ));
        }
    }

    pub unsafe fn edges_closures(
        &self,
        generation_hook: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr, GuestAddr) -> Option<u64>>,
        >,
        execution_hook: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64)>>,
    ) {
        let index = EDGE_HOOKS.len();
        self.emulator.add_edge_hooks(
            generation_hook
                .as_ref()
                .map(|_| gen_edge_hook_wrapper::<QT, S> as _),
            execution_hook
                .as_ref()
                .map(|_| exec_edge_hook_wrapper::<QT, S> as _),
            index as u64,
        );
        EDGE_HOOKS.push((
            generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
        ));
    }

    pub fn edges_raw(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, src: GuestAddr, dest: GuestAddr) -> Option<u64>,
        >,
        execution_hook: Option<extern "C" fn(id: u64, data: u64)>,
    ) {
        unsafe {
            let index = EDGE_HOOKS.len();
            self.emulator.add_edge_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_edge_hook_wrapper::<QT, S> as _),
                execution_hook,
                index as u64,
            );
            EDGE_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                Hook::Empty,
            ));
        }
    }

    pub fn blocks(
        &self,
        generation_hook: Option<fn(&mut Self, Option<&mut S>, pc: GuestAddr) -> Option<u64>>,
        post_generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, block_length: GuestUsize),
        >,
        execution_hook: Option<fn(&mut Self, Option<&mut S>, id: u64)>,
    ) {
        unsafe {
            let index = BLOCK_HOOKS.len();
            self.emulator.add_block_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_block_hook_wrapper::<QT, S> as _),
                post_generation_hook
                    .as_ref()
                    .map(|_| gen_post_block_hook_wrapper::<QT, S> as _),
                execution_hook
                    .as_ref()
                    .map(|_| exec_block_hook_wrapper::<QT, S> as _),
                index as u64,
            );
            BLOCK_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                post_generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
            ));
        }
    }

    pub unsafe fn blocks_closures(
        &self,
        generation_hook: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr) -> Option<u64>>,
        >,
        post_generation_hook: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr, GuestUsize)>,
        >,
        execution_hook: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64)>>,
    ) {
        let index = BLOCK_HOOKS.len();
        self.emulator.add_block_hooks(
            generation_hook
                .as_ref()
                .map(|_| gen_block_hook_wrapper::<QT, S> as _),
            post_generation_hook
                .as_ref()
                .map(|_| gen_post_block_hook_wrapper::<QT, S> as _),
            execution_hook
                .as_ref()
                .map(|_| exec_block_hook_wrapper::<QT, S> as _),
            index as u64,
        );
        BLOCK_HOOKS.push((
            generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            post_generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
        ));
    }

    pub fn blocks_raw(
        &self,
        generation_hook: Option<fn(&mut Self, Option<&mut S>, pc: GuestAddr) -> Option<u64>>,
        post_generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, block_length: GuestUsize),
        >,
        execution_hook: Option<extern "C" fn(id: u64, data: u64)>,
    ) {
        unsafe {
            let index = BLOCK_HOOKS.len();
            self.emulator.add_block_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_block_hook_wrapper::<QT, S> as _),
                post_generation_hook
                    .as_ref()
                    .map(|_| gen_post_block_hook_wrapper::<QT, S> as _),
                execution_hook,
                index as u64,
            );
            BLOCK_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                post_generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                Hook::Empty,
            ));
        }
    }

    pub fn reads(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, info: MemAccessInfo) -> Option<u64>,
        >,
        execution_hook1: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook2: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook4: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook8: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook_n: Option<
            fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr, size: usize),
        >,
    ) {
        unsafe {
            let index = READ_HOOKS.len();
            self.emulator.add_read_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_read_hook_wrapper::<QT, S> as _),
                execution_hook1
                    .as_ref()
                    .map(|_| exec_read1_hook_wrapper::<QT, S> as _),
                execution_hook2
                    .as_ref()
                    .map(|_| exec_read2_hook_wrapper::<QT, S> as _),
                execution_hook4
                    .as_ref()
                    .map(|_| exec_read4_hook_wrapper::<QT, S> as _),
                execution_hook8
                    .as_ref()
                    .map(|_| exec_read8_hook_wrapper::<QT, S> as _),
                execution_hook_n
                    .as_ref()
                    .map(|_| exec_read_n_hook_wrapper::<QT, S> as _),
                index as u64,
            );
            READ_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook1.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook2.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook4.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook8.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook_n.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
            ));
        }
    }

    pub unsafe fn reads_closures(
        &self,
        generation_hook: Option<
            Box<
                dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr, MemAccessInfo) -> Option<u64>,
            >,
        >,
        execution_hook1: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook2: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook4: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook8: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook_n: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr, usize)>,
        >,
    ) {
        let index = READ_HOOKS.len();
        self.emulator.add_read_hooks(
            generation_hook
                .as_ref()
                .map(|_| gen_read_hook_wrapper::<QT, S> as _),
            execution_hook1
                .as_ref()
                .map(|_| exec_read1_hook_wrapper::<QT, S> as _),
            execution_hook2
                .as_ref()
                .map(|_| exec_read2_hook_wrapper::<QT, S> as _),
            execution_hook4
                .as_ref()
                .map(|_| exec_read4_hook_wrapper::<QT, S> as _),
            execution_hook8
                .as_ref()
                .map(|_| exec_read8_hook_wrapper::<QT, S> as _),
            execution_hook_n
                .as_ref()
                .map(|_| exec_read_n_hook_wrapper::<QT, S> as _),
            index as u64,
        );
        READ_HOOKS.push((
            generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook1.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook2.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook4.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook8.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook_n.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
        ));
    }

    pub fn reads_raw(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, info: MemAccessInfo) -> Option<u64>,
        >,
        execution_hook1: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook2: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook4: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook8: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook_n: Option<extern "C" fn(id: u64, addr: GuestAddr, size: usize, data: u64)>,
    ) {
        unsafe {
            let index = READ_HOOKS.len();
            self.emulator.add_read_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_read_hook_wrapper::<QT, S> as _),
                execution_hook1,
                execution_hook2,
                execution_hook4,
                execution_hook8,
                execution_hook_n,
                index as u64,
            );
            READ_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
            ));
        }
    }

    pub fn writes(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, info: MemAccessInfo) -> Option<u64>,
        >,
        execution_hook1: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook2: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook4: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook8: Option<fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr)>,
        execution_hook_n: Option<
            fn(&mut Self, Option<&mut S>, id: u64, addr: GuestAddr, size: usize),
        >,
    ) {
        unsafe {
            let index = WRITE_HOOKS.len();
            self.emulator.add_write_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_write_hook_wrapper::<QT, S> as _),
                execution_hook1
                    .as_ref()
                    .map(|_| exec_write1_hook_wrapper::<QT, S> as _),
                execution_hook2
                    .as_ref()
                    .map(|_| exec_write2_hook_wrapper::<QT, S> as _),
                execution_hook4
                    .as_ref()
                    .map(|_| exec_write4_hook_wrapper::<QT, S> as _),
                execution_hook8
                    .as_ref()
                    .map(|_| exec_write8_hook_wrapper::<QT, S> as _),
                execution_hook_n
                    .as_ref()
                    .map(|_| exec_write_n_hook_wrapper::<QT, S> as _),
                index as u64,
            );
            WRITE_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook1.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook2.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook4.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook8.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook_n.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
            ));
        }
    }

    pub unsafe fn writes_closures(
        &self,
        generation_hook: Option<
            Box<
                dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr, MemAccessInfo) -> Option<u64>,
            >,
        >,
        execution_hook1: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook2: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook4: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook8: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr)>>,
        execution_hook_n: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, GuestAddr, usize)>,
        >,
    ) {
        let index = WRITE_HOOKS.len();
        self.emulator.add_write_hooks(
            generation_hook
                .as_ref()
                .map(|_| gen_write_hook_wrapper::<QT, S> as _),
            execution_hook1
                .as_ref()
                .map(|_| exec_write1_hook_wrapper::<QT, S> as _),
            execution_hook2
                .as_ref()
                .map(|_| exec_write2_hook_wrapper::<QT, S> as _),
            execution_hook4
                .as_ref()
                .map(|_| exec_write4_hook_wrapper::<QT, S> as _),
            execution_hook8
                .as_ref()
                .map(|_| exec_write8_hook_wrapper::<QT, S> as _),
            execution_hook_n
                .as_ref()
                .map(|_| exec_write_n_hook_wrapper::<QT, S> as _),
            index as u64,
        );
        WRITE_HOOKS.push((
            generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook1.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook2.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook4.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook8.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook_n.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
        ));
    }

    pub fn writes_raw(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, info: MemAccessInfo) -> Option<u64>,
        >,
        execution_hook1: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook2: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook4: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook8: Option<extern "C" fn(id: u64, addr: GuestAddr, data: u64)>,
        execution_hook_n: Option<extern "C" fn(id: u64, addr: GuestAddr, size: usize, data: u64)>,
    ) {
        unsafe {
            let index = WRITE_HOOKS.len();
            self.emulator.add_write_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_write_hook_wrapper::<QT, S> as _),
                execution_hook1,
                execution_hook2,
                execution_hook4,
                execution_hook8,
                execution_hook_n,
                index as u64,
            );
            WRITE_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
            ));
        }
    }

    pub fn cmps(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, size: usize) -> Option<u64>,
        >,
        execution_hook1: Option<fn(&mut Self, Option<&mut S>, id: u64, v0: u8, v1: u8)>,
        execution_hook2: Option<fn(&mut Self, Option<&mut S>, id: u64, v0: u16, v1: u16)>,
        execution_hook4: Option<fn(&mut Self, Option<&mut S>, id: u64, v0: u32, v1: u32)>,
        execution_hook8: Option<fn(&mut Self, Option<&mut S>, id: u64, v0: u64, v1: u64)>,
    ) {
        unsafe {
            let index = CMP_HOOKS.len();
            self.emulator.add_cmp_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_cmp_hook_wrapper::<QT, S> as _),
                execution_hook1
                    .as_ref()
                    .map(|_| exec_cmp1_hook_wrapper::<QT, S> as _),
                execution_hook2
                    .as_ref()
                    .map(|_| exec_cmp2_hook_wrapper::<QT, S> as _),
                execution_hook4
                    .as_ref()
                    .map(|_| exec_cmp4_hook_wrapper::<QT, S> as _),
                execution_hook8
                    .as_ref()
                    .map(|_| exec_cmp8_hook_wrapper::<QT, S> as _),
                index as u64,
            );
            CMP_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook1.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook2.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook4.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                execution_hook8.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
            ));
        }
    }

    pub unsafe fn cmps_closures(
        &self,
        generation_hook: Option<
            Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr, usize) -> Option<u64>>,
        >,
        execution_hook1: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, u8, u8)>>,
        execution_hook2: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, u16, u16)>>,
        execution_hook4: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, u32, u32)>>,
        execution_hook8: Option<Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u64, u64, u64)>>,
    ) {
        let index = CMP_HOOKS.len();
        self.emulator.add_cmp_hooks(
            generation_hook
                .as_ref()
                .map(|_| gen_cmp_hook_wrapper::<QT, S> as _),
            execution_hook1
                .as_ref()
                .map(|_| exec_cmp1_hook_wrapper::<QT, S> as _),
            execution_hook2
                .as_ref()
                .map(|_| exec_cmp2_hook_wrapper::<QT, S> as _),
            execution_hook4
                .as_ref()
                .map(|_| exec_cmp4_hook_wrapper::<QT, S> as _),
            execution_hook8
                .as_ref()
                .map(|_| exec_cmp8_hook_wrapper::<QT, S> as _),
            index as u64,
        );
        CMP_HOOKS.push((
            generation_hook.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook1.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook2.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook4.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
            execution_hook8.map_or(Hook::Empty, |hook| Hook::Closure(transmute(hook))),
        ));
    }

    pub fn cmps_raw(
        &self,
        generation_hook: Option<
            fn(&mut Self, Option<&mut S>, pc: GuestAddr, size: usize) -> Option<u64>,
        >,
        execution_hook1: Option<extern "C" fn(id: u64, v0: u8, v1: u8, data: u64)>,
        execution_hook2: Option<extern "C" fn(id: u64, v0: u16, v1: u16, data: u64)>,
        execution_hook4: Option<extern "C" fn(id: u64, v0: u32, v1: u32, data: u64)>,
        execution_hook8: Option<extern "C" fn(id: u64, v0: u64, v1: u64, data: u64)>,
    ) {
        unsafe {
            let index = CMP_HOOKS.len();
            self.emulator.add_cmp_hooks(
                generation_hook
                    .as_ref()
                    .map(|_| gen_cmp_hook_wrapper::<QT, S> as _),
                execution_hook1,
                execution_hook2,
                execution_hook4,
                execution_hook8,
                index as u64,
            );
            CMP_HOOKS.push((
                generation_hook.map_or(Hook::Empty, |hook| {
                    Hook::Function(hook as *const libc::c_void)
                }),
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
            ));
        }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn thread_creation(&self, hook: fn(&mut Self, Option<&mut S>, tid: u32)) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn thread_creation_closure(
        &self,
        hook: Box<dyn FnMut(&'a mut Self, Option<&'a mut S>, u32) + 'a>,
    ) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn thread_creation_once(&self, hook: Box<dyn FnOnce(&mut Self, Option<&mut S>, u32) + 'a>) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Once(transmute(hook)));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::type_complexity)]
    pub fn syscalls(
        &self,
        hook: fn(
            &mut Self,
            Option<&mut S>,
            sys_num: i32,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> SyscallHookResult,
    ) {
        unsafe {
            SYSCALL_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_pre_syscall_hook(syscall_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::type_complexity)]
    pub fn syscalls_closure(
        &self,
        hook: Box<
            dyn FnMut(
                &mut Self,
                Option<&mut S>,
                i32,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> SyscallHookResult,
        >,
    ) {
        unsafe {
            SYSCALL_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_pre_syscall_hook(syscall_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::type_complexity)]
    pub fn after_syscalls(
        &self,
        hook: fn(
            &mut Self,
            Option<&mut S>,
            result: u64,
            sys_num: i32,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> u64,
    ) {
        unsafe {
            SYSCALL_POST_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_post_syscall_hook(syscall_after_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::type_complexity)]
    pub fn after_syscalls_closure(
        &self,
        hook: Box<
            dyn FnMut(
                &mut Self,
                Option<&mut S>,
                u64,
                i32,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64,
        >,
    ) {
        unsafe {
            SYSCALL_POST_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_post_syscall_hook(syscall_after_hooks_wrapper::<QT, S>);
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn crash_closure(&self, hook: Box<dyn FnMut(&mut Self, i32)>) {
        unsafe {
            self.emulator.set_crash_hook(crash_hook_wrapper::<QT, S>);
            CRASH_HOOKS.push(Hook::Closure(transmute(hook)));
        }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn crash(&self, hook: fn(&mut Self, target_signal: i32)) {
        unsafe {
            self.emulator.set_crash_hook(crash_hook_wrapper::<QT, S>);
            CRASH_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
    }
}
