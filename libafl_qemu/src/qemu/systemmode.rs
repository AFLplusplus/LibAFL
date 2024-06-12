use std::{
    ffi::{c_void, CStr, CString},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::null_mut,
    slice,
};

use bytes_utils::SegmentedBuf;
use libafl_qemu_sys::{
    libafl_load_qemu_snapshot, libafl_page_from_addr, libafl_qemu_current_paging_id,
    libafl_save_qemu_snapshot, qemu_cleanup, qemu_main_loop, vm_start, GuestAddr, GuestPhysAddr,
    GuestUsize, GuestVirtAddr,
};
use num_traits::Zero;

use crate::{
    EmulatorMemoryChunk, FastSnapshotPtr, GuestAddrKind, MemAccessInfo, Qemu, QemuExitError,
    QemuExitReason, QemuSnapshotCheckResult, CPU,
};

pub(super) extern "C" fn qemu_cleanup_atexit() {
    unsafe {
        qemu_cleanup();
    }
}

pub enum DeviceSnapshotFilter {
    All,
    AllowList(Vec<String>),
    DenyList(Vec<String>),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PhysMemoryChunk {
    addr: GuestPhysAddr,
    size: usize,
    qemu: Qemu,
    cpu: CPU,
}

pub struct PhysMemoryIter {
    addr: GuestAddrKind, // This address is correct when the iterator enters next, except if the remaining len is 0
    remaining_len: usize,
    qemu: Qemu,
    cpu: CPU,
}

#[allow(dead_code)]
pub struct HostMemoryIter<'a> {
    addr: GuestPhysAddr, // This address is correct when the iterator enters next, except if the remaining len is 0
    remaining_len: usize,
    qemu: Qemu,
    cpu: CPU,
    phantom: PhantomData<&'a ()>,
}

impl DeviceSnapshotFilter {
    fn enum_id(&self) -> libafl_qemu_sys::DeviceSnapshotKind {
        match self {
            DeviceSnapshotFilter::All => libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALL,
            DeviceSnapshotFilter::AllowList(_) => {
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALLOWLIST
            }
            DeviceSnapshotFilter::DenyList(_) => {
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_DENYLIST
            }
        }
    }

    fn devices(&self, v: &mut Vec<*mut i8>) -> *mut *mut i8 {
        v.clear();
        match self {
            DeviceSnapshotFilter::All => null_mut(),
            DeviceSnapshotFilter::AllowList(l) | DeviceSnapshotFilter::DenyList(l) => {
                for name in l {
                    v.push(name.as_bytes().as_ptr() as *mut i8);
                }
                v.push(core::ptr::null_mut());
                v.as_mut_ptr()
            }
        }
    }
}

impl CPU {
    #[must_use]
    pub fn get_phys_addr(&self, vaddr: GuestVirtAddr) -> Option<GuestPhysAddr> {
        unsafe {
            let page = libafl_page_from_addr(vaddr as GuestUsize) as GuestVirtAddr;
            let mut attrs = MaybeUninit::<libafl_qemu_sys::MemTxAttrs>::uninit();
            let paddr = libafl_qemu_sys::cpu_get_phys_page_attrs_debug(
                self.ptr,
                page as GuestVirtAddr,
                attrs.as_mut_ptr(),
            );
            if paddr == (-1i64 as GuestPhysAddr) {
                None
            } else {
                Some(paddr)
            }
        }
    }

    #[must_use]
    pub fn get_phys_addr_tlb(
        &self,
        vaddr: GuestAddr,
        info: MemAccessInfo,
        is_store: bool,
    ) -> Option<GuestPhysAddr> {
        unsafe {
            let pminfo = libafl_qemu_sys::make_plugin_meminfo(
                info.oi,
                if is_store {
                    libafl_qemu_sys::qemu_plugin_mem_rw_QEMU_PLUGIN_MEM_W
                } else {
                    libafl_qemu_sys::qemu_plugin_mem_rw_QEMU_PLUGIN_MEM_R
                },
            );
            let phwaddr = libafl_qemu_sys::qemu_plugin_get_hwaddr(pminfo, vaddr as GuestVirtAddr);
            if phwaddr.is_null() {
                None
            } else {
                Some(libafl_qemu_sys::qemu_plugin_hwaddr_phys_addr(phwaddr) as GuestPhysAddr)
            }
        }
    }

    #[must_use]
    pub fn current_paging_id(&self) -> Option<GuestPhysAddr> {
        let paging_id = unsafe { libafl_qemu_current_paging_id(self.ptr) };

        if paging_id == 0 {
            None
        } else {
            Some(paging_id)
        }
    }

    /// Write a value to a guest address.
    ///
    /// # Safety
    /// This will write to a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        // TODO use gdbstub's target_cpu_memory_rw_debug
        libafl_qemu_sys::cpu_memory_rw_debug(
            self.ptr,
            addr as GuestVirtAddr,
            buf.as_ptr() as *mut _,
            buf.len(),
            true,
        );
    }

    /// Read a value from a guest address.
    ///
    /// # Safety
    /// This will read from a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        // TODO use gdbstub's target_cpu_memory_rw_debug
        libafl_qemu_sys::cpu_memory_rw_debug(
            self.ptr,
            addr as GuestVirtAddr,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            false,
        );
    }
}

#[allow(clippy::unused_self)]
impl Qemu {
    pub fn guest_page_size(&self) -> usize {
        4096
    }

    /// Write a value to a physical guest address, including ROM areas.
    pub unsafe fn write_phys_mem(&self, paddr: GuestPhysAddr, buf: &[u8]) {
        libafl_qemu_sys::cpu_physical_memory_rw(
            paddr,
            buf.as_ptr() as *mut _,
            buf.len() as u64,
            true,
        );
    }

    /// Read a value from a physical guest address.
    pub unsafe fn read_phys_mem(&self, paddr: GuestPhysAddr, buf: &mut [u8]) {
        libafl_qemu_sys::cpu_physical_memory_rw(
            paddr,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u64,
            false,
        );
    }

    /// This function will run the emulator until the next breakpoint / sync exit, or until finish.
    /// It is a low-level function and simply kicks QEMU.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) -> Result<QemuExitReason, QemuExitError> {
        vm_start();
        qemu_main_loop();

        self.post_run()
    }

    pub fn save_snapshot(&self, name: &str, sync: bool) {
        let s = CString::new(name).expect("Invalid snapshot name");
        unsafe { libafl_save_qemu_snapshot(s.as_ptr() as *const _, sync) };
    }

    pub fn load_snapshot(&self, name: &str, sync: bool) {
        let s = CString::new(name).expect("Invalid snapshot name");
        unsafe { libafl_load_qemu_snapshot(s.as_ptr() as *const _, sync) };
    }

    #[must_use]
    pub fn create_fast_snapshot(&self, track: bool) -> FastSnapshotPtr {
        unsafe {
            libafl_qemu_sys::syx_snapshot_new(
                track,
                true,
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALL,
                null_mut(),
            )
        }
    }

    #[must_use]
    pub fn create_fast_snapshot_filter(
        &self,
        track: bool,
        device_filter: &DeviceSnapshotFilter,
    ) -> FastSnapshotPtr {
        let mut v = vec![];
        unsafe {
            libafl_qemu_sys::syx_snapshot_new(
                track,
                true,
                device_filter.enum_id(),
                device_filter.devices(&mut v),
            )
        }
    }

    pub unsafe fn restore_fast_snapshot(&self, snapshot: FastSnapshotPtr) {
        libafl_qemu_sys::syx_snapshot_root_restore(snapshot)
    }

    pub unsafe fn check_fast_snapshot(
        &self,
        ref_snapshot: FastSnapshotPtr,
    ) -> QemuSnapshotCheckResult {
        let check_result = libafl_qemu_sys::syx_snapshot_check(ref_snapshot);

        QemuSnapshotCheckResult {
            nb_page_inconsistencies: check_result.nb_inconsistencies,
        }
    }

    pub fn list_devices(&self) -> Vec<String> {
        let mut r = vec![];
        unsafe {
            let devices = libafl_qemu_sys::device_list_all();
            if devices.is_null() {
                return r;
            }

            let mut ptr = devices;
            while !(*ptr).is_null() {
                let c_str: &CStr = CStr::from_ptr(*ptr);
                let name = c_str.to_str().unwrap().to_string();
                r.push(name);

                ptr = ptr.add(1);
            }

            libc::free(devices as *mut c_void);
            r
        }
    }

    #[must_use]
    pub fn target_page_size(&self) -> usize {
        unsafe { libafl_qemu_sys::qemu_target_page_size() }
    }
}

impl EmulatorMemoryChunk {
    pub fn phys_iter(&self, qemu: Qemu) -> PhysMemoryIter {
        PhysMemoryIter {
            addr: self.addr,
            remaining_len: self.size as usize,
            qemu,
            cpu: if let Some(cpu) = self.cpu {
                cpu
            } else {
                qemu.current_cpu().unwrap()
            },
        }
    }

    #[allow(clippy::map_flatten)]
    pub fn host_iter(&self, qemu: Qemu) -> Box<dyn Iterator<Item = &[u8]>> {
        Box::new(
            self.phys_iter(qemu)
                .map(move |phys_mem_chunk| HostMemoryIter {
                    addr: phys_mem_chunk.addr,
                    remaining_len: phys_mem_chunk.size,
                    qemu,
                    cpu: phys_mem_chunk.cpu,
                    phantom: PhantomData,
                })
                .flatten()
                .into_iter(),
        )
    }

    pub fn to_host_segmented_buf(&self, qemu: Qemu) -> SegmentedBuf<&[u8]> {
        self.host_iter(qemu).collect()
    }
}

impl PhysMemoryChunk {
    pub fn new(addr: GuestPhysAddr, size: usize, qemu: Qemu, cpu: CPU) -> Self {
        Self {
            addr,
            size,
            qemu,
            cpu,
        }
    }
}

impl<'a> Iterator for HostMemoryIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_len.is_zero() {
            None
        } else {
            // Host memory allocation is always host-page aligned, so we can freely go from host page to host page.
            let start_host_addr: *const u8 =
                unsafe { libafl_qemu_sys::libafl_paddr2host(self.cpu.ptr, self.addr, false) };
            let host_page_size = Qemu::get().unwrap().host_page_size();
            let mut size_taken: usize = std::cmp::min(
                (start_host_addr as usize).next_multiple_of(host_page_size),
                self.remaining_len,
            );

            self.remaining_len -= size_taken;
            self.addr += size_taken as GuestPhysAddr;

            // Now self.addr is host-page aligned
            while self.remaining_len > 0 {
                let next_page_host_addr: *const u8 =
                    unsafe { libafl_qemu_sys::libafl_paddr2host(self.cpu.ptr, self.addr, false) };

                // Non-contiguous, we stop here for the slice
                if next_page_host_addr != start_host_addr {
                    unsafe { return Some(slice::from_raw_parts(start_host_addr, size_taken)) }
                }

                // The host memory is contiguous, we can widen the slice up to the next host page
                size_taken += std::cmp::min(self.remaining_len, host_page_size);

                self.remaining_len -= size_taken;
                self.addr += size_taken as GuestPhysAddr;
            }

            // We finished to explore the memory, return the last slice.
            assert_eq!(self.remaining_len, 0);

            unsafe { return Some(slice::from_raw_parts(start_host_addr, size_taken)) }
        }
    }
}

impl Iterator for PhysMemoryIter {
    type Item = PhysMemoryChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_len.is_zero() {
            None
        } else {
            // Physical memory allocation is always physical-page aligned, so we can freely go from host page to host page.
            let vaddr = match &mut self.addr {
                GuestAddrKind::Virtual(vaddr) => vaddr,
                GuestAddrKind::Physical(paddr) => {
                    let sz = self.remaining_len;
                    self.remaining_len = 0;
                    return Some(PhysMemoryChunk::new(*paddr, sz, self.qemu, self.cpu));
                }
            };
            let start_phys_addr: GuestPhysAddr = self.cpu.get_phys_addr(*vaddr)?;
            let phys_page_size = self.qemu.guest_page_size();

            // TODO: Turn this into a generic function
            let mut size_taken: usize = std::cmp::min(
                (start_phys_addr as usize).next_multiple_of(phys_page_size),
                self.remaining_len,
            );

            self.remaining_len -= size_taken;
            *vaddr += size_taken as GuestPhysAddr;

            // Now self.addr is host-page aligned
            while self.remaining_len > 0 {
                let next_page_phys_addr: GuestPhysAddr = self.cpu.get_phys_addr(*vaddr)?;

                // Non-contiguous, we stop here for the slice
                if next_page_phys_addr != start_phys_addr {
                    return Some(PhysMemoryChunk::new(
                        start_phys_addr,
                        size_taken,
                        self.qemu,
                        self.cpu,
                    ));
                }

                // The host memory is contiguous, we can widen the slice up to the next host page
                size_taken += std::cmp::min(self.remaining_len, phys_page_size);

                self.remaining_len -= size_taken;
                *vaddr += size_taken as GuestPhysAddr;
            }

            // We finished to explore the memory, return the last slice.
            assert_eq!(self.remaining_len, 0);

            Some(PhysMemoryChunk::new(
                start_phys_addr,
                size_taken,
                self.qemu,
                self.cpu,
            ))
        }
    }
}
