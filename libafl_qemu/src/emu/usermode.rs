use core::{convert::Into, ffi::c_void, mem::MaybeUninit, ptr::copy_nonoverlapping};
use std::{cell::OnceCell, slice::from_raw_parts, str::from_utf8_unchecked};

use libc::c_int;
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    emu::{
        exec_path, free_self_maps, guest_base, libafl_dump_core_hook, libafl_force_dfl,
        libafl_get_brk, libafl_load_addr, libafl_maps_next, libafl_qemu_run, libafl_set_brk,
        mmap_next_start, read_self_maps, strlen,
    },
    sync_exit::SyncExitError,
    EmuExitReason, EmuExitReasonError, Emulator, GuestAddr, GuestUsize, HookData, HookId,
    IsEmuExitHandler, MapInfo, MmapPerms, NopEmuExitHandler, SyscallHookResult, VerifyAccess, CPU,
};

#[derive(Debug, Clone)]
pub enum HandlerError {
    EmuExitReasonError(EmuExitReasonError),
    SyncExitError(SyncExitError),
    MultipleInputDefinition,
}

#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct GuestMaps {
    orig_c_iter: *const c_void,
    c_iter: *const c_void,
}

// Consider a private new only for Emulator
impl GuestMaps {
    #[must_use]
    pub(crate) fn new() -> Self {
        unsafe {
            let maps = read_self_maps();
            Self {
                orig_c_iter: maps,
                c_iter: maps,
            }
        }
    }
}

impl Iterator for GuestMaps {
    type Item = MapInfo;

    #[allow(clippy::uninit_assumed_init)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.c_iter.is_null() {
            return None;
        }
        unsafe {
            let mut ret = MaybeUninit::uninit();
            self.c_iter = libafl_maps_next(self.c_iter, ret.as_mut_ptr());
            if self.c_iter.is_null() {
                None
            } else {
                Some(ret.assume_init())
            }
        }
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl GuestMaps {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }
    fn __next__(mut slf: PyRefMut<Self>) -> Option<PyObject> {
        Python::with_gil(|py| slf.next().map(|x| x.into_py(py)))
    }
}

impl Drop for GuestMaps {
    fn drop(&mut self) {
        unsafe {
            free_self_maps(self.orig_c_iter);
        }
    }
}

impl CPU {
    /// Write a value to a guest address.
    ///
    /// # Safety
    /// This will write to a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        let host_addr = Emulator::<NopEmuExitHandler>::new_empty().g2h(addr);
        copy_nonoverlapping(buf.as_ptr(), host_addr, buf.len());
    }

    /// Read a value from a guest address.
    ///
    /// # Safety
    /// This will read from a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        let host_addr = Emulator::<NopEmuExitHandler>::new_empty().g2h(addr);
        copy_nonoverlapping(host_addr, buf.as_mut_ptr(), buf.len());
    }

    #[must_use]
    pub fn page_size(&self) -> usize {
        thread_local! {
            static PAGE_SIZE: OnceCell<usize> = OnceCell::new();
        }

        PAGE_SIZE.with(|s| {
            *s.get_or_init(|| {
                unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) }
                    .try_into()
                    .expect("Invalid page size")
            })
        })
    }
}

impl<E> Emulator<E>
where
    E: IsEmuExitHandler,
{
    /// This function gets the memory mappings from the emulator.
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        GuestMaps::new()
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .access_ok(kind, addr, size)
    }

    pub fn force_dfl(&self) {
        unsafe {
            libafl_force_dfl = 1;
        }
    }

    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) -> Result<EmuExitReason, EmuExitReasonError> {
        libafl_qemu_run();
        EmuExitReason::try_from(self)
    }

    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        unsafe { from_utf8_unchecked(from_raw_parts(exec_path, strlen(exec_path))) }
    }

    #[must_use]
    pub fn load_addr(&self) -> GuestAddr {
        unsafe { libafl_load_addr() as GuestAddr }
    }

    #[must_use]
    pub fn get_brk(&self) -> GuestAddr {
        unsafe { libafl_get_brk() as GuestAddr }
    }

    pub fn set_brk(&self, brk: GuestAddr) {
        unsafe { libafl_set_brk(brk.into()) };
    }

    #[must_use]
    pub fn get_mmap_start(&self) -> GuestAddr {
        unsafe { mmap_next_start }
    }

    pub fn set_mmap_start(&self, start: GuestAddr) {
        unsafe { mmap_next_start = start };
    }

    #[allow(clippy::cast_sign_loss, clippy::unused_self)]
    fn mmap(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
        flags: c_int,
    ) -> Result<GuestAddr, ()> {
        let res = unsafe {
            libafl_qemu_sys::target_mmap(addr, size as GuestUsize, perms.into(), flags, -1, 0)
        };
        if res <= 0 {
            Err(())
        } else {
            Ok(res as GuestAddr)
        }
    }

    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.mmap(addr, size, perms, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
            .map_err(|()| format!("Failed to map {addr}"))
            .map(|addr| addr as GuestAddr)
    }

    pub fn map_fixed(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.mmap(
            addr,
            size,
            perms,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        )
        .map_err(|()| format!("Failed to map {addr}"))
        .map(|addr| addr as GuestAddr)
    }

    pub fn mprotect(&self, addr: GuestAddr, size: usize, perms: MmapPerms) -> Result<(), String> {
        let res = unsafe {
            libafl_qemu_sys::target_mprotect(addr.into(), size as GuestUsize, perms.into())
        };
        if res == 0 {
            Ok(())
        } else {
            Err(format!("Failed to mprotect {addr}"))
        }
    }

    pub fn unmap(&self, addr: GuestAddr, size: usize) -> Result<(), String> {
        if unsafe { libafl_qemu_sys::target_munmap(addr.into(), size as GuestUsize) } == 0 {
            Ok(())
        } else {
            Err(format!("Failed to unmap {addr}"))
        }
    }

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
    ) -> HookId {
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
            ) -> libafl_qemu_sys::syshook_ret = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_pre_syscall_hook(Some(callback), data);
            HookId(num)
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
    ) -> HookId {
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
            ) -> GuestAddr = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_post_syscall_hook(Some(callback), data);
            HookId(num)
        }
    }

    pub fn add_new_thread_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, tid: u32) -> bool,
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, u32) -> bool = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_new_thread_hook(Some(callback), data);
            HookId(num)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn set_crash_hook(&self, callback: extern "C" fn(i32)) {
        unsafe {
            libafl_dump_core_hook = callback;
        }
    }
}
