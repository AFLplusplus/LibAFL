//! The high-level hooks
#![allow(clippy::type_complexity)]

use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::{PhantomData, PhantomPinned},
    mem::transmute,
    pin::Pin,
    ptr::{self, addr_of},
};

use libafl::{executors::inprocess::inprocess_get_state, inputs::Input};

pub use crate::emu::SyscallHookResult;
use crate::{
    emu::{Emulator, SKIP_EXEC_HOOK},
    helper::{QemuHelper, QemuHelperTuple},
    GuestAddr,
};

#[repr(C)]
#[derive(PartialEq, Clone, Copy)]
struct FatPtr(*const c_void, *const c_void);

// all kinds of hooks
#[derive(PartialEq, Clone, Copy)]
enum Hook {
    Function(*const c_void),
    Closure(FatPtr),
    Once(FatPtr),
    Empty,
}

// function signature for Read or Write hook functions with known length (1, 2, 4, 8)
type FixedLenHookFn<QT, S> = fn(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr);
type FixedLenHookCl<QT, S> = Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr)>;

// function signature for Read or Write hook functions with runtime length n
type DynamicLenHookFn<QT, S> = fn(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr, usize);
type DynamicLenHookCl<QT, S> =
    Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, GuestAddr, usize)>;

static mut QEMU_HELPERS_PTR: *const c_void = ptr::null();
unsafe fn get_qemu_helpers<'a, QT>() -> &'a mut QT {
    (QEMU_HELPERS_PTR as *mut QT)
        .as_mut()
        .expect("A high-level hook is installed but QemuHooks is not initialized")
}

static mut QEMU_HOOKS_PTR: *const c_void = ptr::null();
unsafe fn get_qemu_hooks<'a, I, QT, S>() -> Pin<&'a mut QemuHooks<'a, I, QT, S>>
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    Pin::new_unchecked(
        (QEMU_HOOKS_PTR as *mut QemuHooks<'a, I, QT, S>)
            .as_mut()
            .expect("A high-level hook is installed but QemuHooks is not initialized"),
    )
}

static mut GEN_EDGE_HOOK: Hook = Hook::Empty;
extern "C" fn gen_edge_hook_wrapper<I, QT, S>(src: u64, dst: u64) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        match &GEN_EDGE_HOOK {
            Hook::Function(ptr) => {
                let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, u64) -> Option<u64> =
                    transmute(*ptr);
                (func)(&emulator, helpers, inprocess_get_state::<S>(), src, dst)
                    .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let mut func: Box<
                    dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u64) -> Option<u64>,
                > = transmute(*ptr);
                (func)(&emulator, helpers, inprocess_get_state::<S>(), src, dst)
                    .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            _ => SKIP_EXEC_HOOK,
        }
    }
}

static mut EDGE_HOOKS: Vec<Hook> = vec![];
extern "C" fn edge_hooks_wrapper<I, QT, S>(id: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &EDGE_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64) = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64)> =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut GEN_BLOCK_HOOK: Hook = Hook::Empty;
extern "C" fn gen_block_hook_wrapper<I, QT, S>(pc: u64) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        match &GEN_BLOCK_HOOK {
            Hook::Function(ptr) => {
                let func: fn(&Emulator, &mut QT, Option<&mut S>, u64) -> Option<u64> =
                    transmute(*ptr);
                (func)(&emulator, helpers, inprocess_get_state::<S>(), pc)
                    .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let mut func: Box<
                    dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64) -> Option<u64>,
                > = transmute(*ptr);
                let ret = (func)(&emulator, helpers, inprocess_get_state::<S>(), pc)
                    .map_or(SKIP_EXEC_HOOK, |id| id);

                // Forget the closure so that drop is not called on captured variables.
                core::mem::forget(func);

                ret
            }
            _ => SKIP_EXEC_HOOK,
        }
    }
}

static mut BLOCK_HOOKS: Vec<Hook> = vec![];
extern "C" fn block_hooks_wrapper<I, QT, S>(id: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &BLOCK_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64) = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64)> =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut GEN_READ_HOOK: Hook = Hook::Empty;
extern "C" fn gen_read_hook_wrapper<I, QT, S>(size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        match &GEN_READ_HOOK {
            Hook::Function(ptr) => {
                let func: fn(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64> =
                    transmute(*ptr);
                (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let mut func: Box<
                    dyn FnMut(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64>,
                > = transmute(*ptr);
                let ret = (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id);

                // Forget the closure so that drop is not called on captured variables.
                core::mem::forget(func);

                ret
            }
            _ => SKIP_EXEC_HOOK,
        }
    }
}

static mut GEN_WRITE_HOOK: Hook = Hook::Empty;
extern "C" fn gen_write_hook_wrapper<I, QT, S>(size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        match &GEN_WRITE_HOOK {
            Hook::Function(ptr) => {
                let func: fn(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64> =
                    transmute(*ptr);
                (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let mut func: Box<
                    dyn FnMut(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64>,
                > = transmute(*ptr);
                let ret = (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id);

                // Forget the closure so that drop is not called on captured variables.
                core::mem::forget(func);

                ret
            }
            _ => SKIP_EXEC_HOOK,
        }
    }
}

static mut READ1_HOOKS: Vec<Hook> = vec![];
extern "C" fn read1_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &READ1_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut READ2_HOOKS: Vec<Hook> = vec![];
extern "C" fn read2_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &READ2_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut READ4_HOOKS: Vec<Hook> = vec![];
extern "C" fn read4_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &READ4_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut READ8_HOOKS: Vec<Hook> = vec![];
extern "C" fn read8_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &READ8_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut READ_N_HOOKS: Vec<Hook> = vec![];
extern "C" fn read_n_hooks_wrapper<I, QT, S>(id: u64, addr: u64, size: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &READ_N_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: DynamicLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                        size as usize,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: DynamicLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                        size as usize,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut WRITE1_HOOKS: Vec<Hook> = vec![];
extern "C" fn write1_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &WRITE1_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut WRITE2_HOOKS: Vec<Hook> = vec![];
extern "C" fn write2_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &WRITE2_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut WRITE4_HOOKS: Vec<Hook> = vec![];
extern "C" fn write4_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &WRITE4_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut WRITE8_HOOKS: Vec<Hook> = vec![];
extern "C" fn write8_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &WRITE8_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: FixedLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: FixedLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut WRITE_N_HOOKS: Vec<Hook> = vec![];
extern "C" fn write_n_hooks_wrapper<I, QT, S>(id: u64, addr: u64, size: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &WRITE1_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: DynamicLenHookFn<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                        size as usize,
                    );
                }
                Hook::Closure(ptr) => {
                    let mut func: DynamicLenHookCl<QT, S> = transmute(*ptr);
                    (func)(
                        &emulator,
                        helpers,
                        inprocess_get_state::<S>(),
                        id,
                        addr as GuestAddr,
                        size as usize,
                    );
                }
                _ => (),
            }
        }
    }
}

static mut GEN_CMP_HOOK: Hook = Hook::Empty;
extern "C" fn gen_cmp_hook_wrapper<I, QT, S>(pc: u64, size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        match &GEN_CMP_HOOK {
            Hook::Function(ptr) => {
                let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, usize) -> Option<u64> =
                    transmute(*ptr);
                (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    pc,
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id)
            }
            Hook::Closure(ptr) => {
                let mut func: Box<
                    dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, usize) -> Option<u64>,
                > = transmute(*ptr);
                let ret = (func)(
                    &emulator,
                    helpers,
                    inprocess_get_state::<S>(),
                    pc,
                    size as usize,
                )
                .map_or(SKIP_EXEC_HOOK, |id| id);

                // Forget the closure so that drop is not called on captured variables.
                core::mem::forget(func);

                ret
            }
            _ => SKIP_EXEC_HOOK,
        }
    }
}

static mut CMP1_HOOKS: Vec<Hook> = vec![];
extern "C" fn cmp1_hooks_wrapper<I, QT, S>(id: u64, v0: u8, v1: u8)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &CMP1_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, u8, u8) = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u8, u8)> =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut CMP2_HOOKS: Vec<Hook> = vec![];
extern "C" fn cmp2_hooks_wrapper<I, QT, S>(id: u64, v0: u16, v1: u16)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &CMP2_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, u16, u16) =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<
                        dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u16, u16),
                    > = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut CMP4_HOOKS: Vec<Hook> = vec![];
extern "C" fn cmp4_hooks_wrapper<I, QT, S>(id: u64, v0: u32, v1: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &CMP4_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, u32, u32) =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<
                        dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u32, u32),
                    > = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut CMP8_HOOKS: Vec<Hook> = vec![];
extern "C" fn cmp8_hooks_wrapper<I, QT, S>(id: u64, v0: u64, v1: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        for hook in &CMP8_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(&Emulator, &mut QT, Option<&mut S>, u64, u64, u64) =
                        transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<
                        dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u64, u64),
                    > = transmute(*ptr);
                    (func)(&emulator, helpers, inprocess_get_state::<S>(), id, v0, v1);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                _ => (),
            }
        }
    }
}

static mut ON_THREAD_HOOKS: Vec<Hook> = vec![];
extern "C" fn on_thread_hooks_wrapper<I, QT, S>(tid: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let emu = Emulator::new_empty();
        for hook in &mut ON_THREAD_HOOKS {
            let hooks = get_qemu_hooks::<I, QT, S>();
            match hook {
                Hook::Function(ptr) => {
                    let func: fn(
                        &Emulator,
                        Pin<&mut QemuHooks<'_, I, QT, S>>,
                        Option<&mut S>,
                        u32,
                    ) = transmute(*ptr);
                    (func)(&emu, hooks, inprocess_get_state::<S>(), tid);
                }
                Hook::Closure(ptr) => {
                    let mut func: Box<
                        dyn FnMut(
                            &Emulator,
                            Pin<&mut QemuHooks<'_, I, QT, S>>,
                            Option<&mut S>,
                            u32,
                        ),
                    > = transmute(*ptr);
                    (func)(&emu, hooks, inprocess_get_state::<S>(), tid);

                    // Forget the closure so that drop is not called on captured variables.
                    core::mem::forget(func);
                }
                Hook::Once(ptr) => {
                    let func: Box<
                        dyn FnOnce(
                            &Emulator,
                            Pin<&mut QemuHooks<'_, I, QT, S>>,
                            Option<&mut S>,
                            u32,
                        ),
                    > = transmute(*ptr);
                    (func)(&emu, hooks, inprocess_get_state::<S>(), tid);
                    *hook = Hook::Empty;
                }
                Hook::Empty => (),
            }
        }
    }
}

static mut SYSCALL_HOOKS: Vec<Hook> = vec![];
extern "C" fn syscall_hooks_wrapper<I, QT, S>(
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
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        let mut res = SyscallHookResult::new(None);
        for hook in &SYSCALL_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let func: fn(
                        &Emulator,
                        &mut QT,
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
                    let r = (func)(
                        &emulator,
                        helpers,
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
                            &Emulator,
                            &mut QT,
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
                    let r = (func)(
                        &emulator,
                        helpers,
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

static mut SYSCALL_POST_HOOKS: Vec<Hook> = vec![];
extern "C" fn syscall_after_hooks_wrapper<I, QT, S>(
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
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = get_qemu_helpers::<QT>();
        let emulator = Emulator::new_empty();
        let mut res = result;
        for hook in &SYSCALL_POST_HOOKS {
            match hook {
                Hook::Function(ptr) => {
                    #[allow(clippy::type_complexity)]
                    let func: fn(
                        &Emulator,
                        &mut QT,
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
                    res = (func)(
                        &emulator,
                        helpers,
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
                            &Emulator,
                            &mut QT,
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
                    res = (func)(
                        &emulator,
                        helpers,
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

static mut HOOKS_IS_INITIALIZED: bool = false;

pub struct QemuHooks<'a, I, QT, S>
where
    QT: QemuHelperTuple<I, S>,
    I: Input,
{
    helpers: QT,
    emulator: &'a Emulator,
    phantom: PhantomData<(I, S)>,
    _pin: PhantomPinned,
}

impl<'a, I, QT, S> Debug for QemuHooks<'a, I, QT, S>
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuHooks")
            .field("helpers", &self.helpers)
            .field("emulator", &self.emulator)
            .finish()
    }
}

impl<'a, I, QT, S> QemuHooks<'a, I, QT, S>
where
    QT: QemuHelperTuple<I, S>,
    I: Input,
{
    pub fn new(emulator: &'a Emulator, helpers: QT) -> Pin<Box<Self>> {
        unsafe {
            assert!(
                !HOOKS_IS_INITIALIZED,
                "Only an instance of QemuHooks is permitted"
            );
            HOOKS_IS_INITIALIZED = true;
        }
        // re-translate blocks with hooks
        emulator.flush_jit();
        let slf = Box::pin(Self {
            emulator,
            helpers,
            phantom: PhantomData,
            _pin: PhantomPinned,
        });
        slf.helpers.init_hooks_all(slf.as_ref());
        unsafe {
            QEMU_HELPERS_PTR = addr_of!(slf.helpers) as *const c_void;
            QEMU_HOOKS_PTR = addr_of!(*slf) as *const c_void;
        }
        slf
    }

    #[must_use]
    pub fn match_helper<'b, T>(self: &'b Pin<&mut Self>) -> Option<&'b T>
    where
        T: QemuHelper<I, S>,
    {
        self.helpers.match_first_type::<T>()
    }

    #[must_use]
    pub fn match_helper_mut<'b, T>(self: &'b mut Pin<&mut Self>) -> Option<&'b mut T>
    where
        T: QemuHelper<I, S>,
    {
        unsafe {
            self.as_mut()
                .get_unchecked_mut()
                .helpers
                .match_first_type_mut::<T>()
        }
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

    pub fn edge_generation(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, src: u64, dest: u64) -> Option<u64>,
    ) {
        unsafe {
            GEN_EDGE_HOOK = Hook::Function(hook as *const libc::c_void);
        }
        self.emulator
            .set_gen_edge_hook(gen_edge_hook_wrapper::<I, QT, S>);
    }

    pub fn edge_generation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u64) -> Option<u64>>,
    ) {
        unsafe {
            GEN_EDGE_HOOK = Hook::Closure(transmute(hook));
        }
        self.emulator
            .set_gen_edge_hook(gen_edge_hook_wrapper::<I, QT, S>);
    }

    pub fn edge_execution(&self, hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64)) {
        unsafe {
            EDGE_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_edge_hook(edge_hooks_wrapper::<I, QT, S>);
    }

    pub fn edge_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64)>,
    ) {
        unsafe {
            EDGE_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_edge_hook(edge_hooks_wrapper::<I, QT, S>);
    }

    pub fn block_generation(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, pc: u64) -> Option<u64>,
    ) {
        unsafe {
            GEN_BLOCK_HOOK = Hook::Function(hook as *const libc::c_void);
        }
        self.emulator
            .set_gen_block_hook(gen_block_hook_wrapper::<I, QT, S>);
    }

    pub fn block_generation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64) -> Option<u64>>,
    ) {
        unsafe {
            GEN_BLOCK_HOOK = Hook::Closure(transmute(hook));
        }
        self.emulator
            .set_gen_block_hook(gen_block_hook_wrapper::<I, QT, S>);
    }

    pub fn block_execution(&self, hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64)) {
        unsafe {
            BLOCK_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_block_hook(block_hooks_wrapper::<I, QT, S>);
    }

    pub fn block_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64)>,
    ) {
        unsafe {
            BLOCK_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_block_hook(block_hooks_wrapper::<I, QT, S>);
    }

    pub fn read_generation(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, size: usize) -> Option<u64>,
    ) {
        unsafe {
            GEN_READ_HOOK = Hook::Function(hook as *const libc::c_void);
        }
        self.emulator
            .set_gen_read_hook(gen_read_hook_wrapper::<I, QT, S>);
    }

    pub fn read_generation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64>>,
    ) {
        unsafe {
            GEN_READ_HOOK = Hook::Closure(transmute(hook));
        }
        self.emulator
            .set_gen_read_hook(gen_read_hook_wrapper::<I, QT, S>);
    }

    pub fn read1_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            READ1_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_read1_hook(read1_hooks_wrapper::<I, QT, S>);
    }

    pub fn read1_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            READ1_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_read1_hook(read1_hooks_wrapper::<I, QT, S>);
    }

    pub fn read2_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            READ2_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_read2_hook(read2_hooks_wrapper::<I, QT, S>);
    }

    pub fn read2_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            READ2_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_read2_hook(read2_hooks_wrapper::<I, QT, S>);
    }

    pub fn read4_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            READ4_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_read4_hook(read4_hooks_wrapper::<I, QT, S>);
    }

    pub fn read4_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            READ4_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_read4_hook(read4_hooks_wrapper::<I, QT, S>);
    }

    pub fn read8_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            READ8_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_read8_hook(read8_hooks_wrapper::<I, QT, S>);
    }

    pub fn read8_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            READ8_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_read8_hook(read8_hooks_wrapper::<I, QT, S>);
    }

    pub fn read_n_execution(&self, hook: DynamicLenHookFn<QT, S>) {
        unsafe {
            READ_N_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_read_n_hook(read_n_hooks_wrapper::<I, QT, S>);
    }

    pub fn read_n_execution_closure(&self, hook: DynamicLenHookCl<QT, S>) {
        unsafe {
            READ_N_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_read_n_hook(read_n_hooks_wrapper::<I, QT, S>);
    }

    pub fn write_generation(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, size: usize) -> Option<u64>,
    ) {
        unsafe {
            GEN_WRITE_HOOK = Hook::Function(hook as *const libc::c_void);
        }
        self.emulator
            .set_gen_write_hook(gen_write_hook_wrapper::<I, QT, S>);
    }

    pub fn write_generation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, usize) -> Option<u64>>,
    ) {
        unsafe {
            GEN_WRITE_HOOK = Hook::Closure(transmute(hook));
        }
        self.emulator
            .set_gen_write_hook(gen_write_hook_wrapper::<I, QT, S>);
    }

    pub fn write1_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            WRITE1_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_write1_hook(write1_hooks_wrapper::<I, QT, S>);
    }

    pub fn write1_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            WRITE1_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_write1_hook(write1_hooks_wrapper::<I, QT, S>);
    }

    pub fn write2_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            WRITE2_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_write2_hook(write2_hooks_wrapper::<I, QT, S>);
    }

    pub fn write2_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            WRITE2_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_write2_hook(write2_hooks_wrapper::<I, QT, S>);
    }

    pub fn write4_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            WRITE4_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_write4_hook(write4_hooks_wrapper::<I, QT, S>);
    }

    pub fn write4_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            WRITE4_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_write4_hook(write4_hooks_wrapper::<I, QT, S>);
    }

    pub fn write8_execution(&self, hook: FixedLenHookFn<QT, S>) {
        unsafe {
            WRITE8_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_write8_hook(write8_hooks_wrapper::<I, QT, S>);
    }

    pub fn write8_execution_closure(&self, hook: FixedLenHookCl<QT, S>) {
        unsafe {
            WRITE8_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_write8_hook(write8_hooks_wrapper::<I, QT, S>);
    }

    pub fn write_n_execution(&self, hook: DynamicLenHookFn<QT, S>) {
        unsafe {
            WRITE_N_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_write_n_hook(write_n_hooks_wrapper::<I, QT, S>);
    }

    pub fn write_n_execution_closure(&self, hook: DynamicLenHookCl<QT, S>) {
        unsafe {
            WRITE_N_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_write_n_hook(write_n_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp_generation(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, pc: u64, size: usize) -> Option<u64>,
    ) {
        unsafe {
            GEN_CMP_HOOK = Hook::Function(hook as *const libc::c_void);
        }
        self.emulator
            .set_gen_cmp_hook(gen_cmp_hook_wrapper::<I, QT, S>);
    }

    pub fn cmp_generation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, usize) -> Option<u64>>,
    ) {
        unsafe {
            GEN_CMP_HOOK = Hook::Closure(transmute(hook));
        }
        self.emulator
            .set_gen_cmp_hook(gen_cmp_hook_wrapper::<I, QT, S>);
    }

    pub fn cmp1_execution(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64, v0: u8, v1: u8),
    ) {
        unsafe {
            CMP1_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_cmp1_hook(cmp1_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp1_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u8, u8)>,
    ) {
        unsafe {
            CMP1_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_cmp1_hook(cmp1_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp2_execution(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64, v0: u16, v1: u16),
    ) {
        unsafe {
            CMP2_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_cmp2_hook(cmp2_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp2_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u16, u16)>,
    ) {
        unsafe {
            CMP2_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_cmp2_hook(cmp2_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp4_execution(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64, v0: u32, v1: u32),
    ) {
        unsafe {
            CMP4_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_cmp4_hook(cmp4_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp4_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u32, u32)>,
    ) {
        unsafe {
            CMP4_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_cmp4_hook(cmp4_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp8_execution(
        &self,
        hook: fn(&Emulator, &mut QT, Option<&mut S>, id: u64, v0: u64, v1: u64),
    ) {
        unsafe {
            CMP8_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_exec_cmp8_hook(cmp8_hooks_wrapper::<I, QT, S>);
    }

    pub fn cmp8_execution_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, &mut QT, Option<&mut S>, u64, u64, u64)>,
    ) {
        unsafe {
            CMP8_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_exec_cmp8_hook(cmp8_hooks_wrapper::<I, QT, S>);
    }

    pub fn thread_creation(&self, hook: fn(&Emulator, Pin<&mut Self>, Option<&mut S>, tid: u32)) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Function(hook as *const libc::c_void));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<I, QT, S>);
    }

    pub fn thread_creation_closure(
        &self,
        hook: Box<dyn FnMut(&Emulator, Pin<&mut Self>, Option<&mut S>, u32) + 'a>,
    ) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Closure(transmute(hook)));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<I, QT, S>);
    }

    pub fn thread_creation_once(
        &self,
        hook: Box<dyn FnOnce(&Emulator, Pin<&mut Self>, Option<&mut S>, u32) + 'a>,
    ) {
        unsafe {
            ON_THREAD_HOOKS.push(Hook::Once(transmute(hook)));
        }
        self.emulator
            .set_on_thread_hook(on_thread_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::type_complexity)]
    pub fn syscalls(
        &self,
        hook: fn(
            &Emulator,
            &mut QT,
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
            .set_pre_syscall_hook(syscall_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::type_complexity)]
    pub fn syscalls_closure(
        &self,
        hook: Box<
            dyn FnMut(
                &Emulator,
                &mut QT,
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
            .set_pre_syscall_hook(syscall_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls(
        &self,
        hook: fn(
            &Emulator,
            &mut QT,
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
            .set_post_syscall_hook(syscall_after_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::type_complexity)]
    pub fn after_syscalls_closure(
        &self,
        hook: Box<
            dyn FnMut(
                &Emulator,
                &mut QT,
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
            .set_post_syscall_hook(syscall_after_hooks_wrapper::<I, QT, S>);
    }
}
