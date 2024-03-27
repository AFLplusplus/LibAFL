use std::{
    collections::HashMap,
    ffi::{c_void, CStr, CString},
    fmt::Debug,
    mem::MaybeUninit,
    ptr::null_mut,
    sync::atomic::{AtomicU64, Ordering},
};

use libafl::state::{HasExecutions, State};
use libafl_qemu_sys::{
    libafl_load_qemu_snapshot, libafl_qemu_current_paging_id, libafl_save_qemu_snapshot,
    qemu_cleanup, qemu_main_loop, vm_start, GuestAddr, GuestPhysAddr, GuestVirtAddr,
};

use crate::{
    emu::{libafl_page_from_addr, IsSnapshotManager},
    EmuExitHandler, Emulator, MemAccessInfo, Qemu, QemuExitReason, QemuExitReasonError,
    QemuHelperTuple, SnapshotId, SnapshotManagerError, CPU,
};

impl SnapshotId {
    fn gen_unique_id() -> SnapshotId {
        static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        let unique_id = UNIQUE_ID.fetch_add(1, Ordering::SeqCst);

        SnapshotId {
            id: unique_id.clone(),
        }
    }

    fn inner(&self) -> u64 {
        self.id
    }
}

#[derive(Debug, Clone)]
pub enum SnapshotManager {
    Qemu(QemuSnapshotManager),
    Fast(FastSnapshotManager),
}

impl IsSnapshotManager for SnapshotManager {
    fn save(&mut self, qemu: &Qemu) -> SnapshotId {
        match self {
            SnapshotManager::Qemu(qemu_sm) => qemu_sm.save(qemu),
            SnapshotManager::Fast(fast_sm) => fast_sm.save(qemu),
        }
    }

    fn restore(
        &mut self,
        snapshot_id: &SnapshotId,
        qemu: &Qemu,
    ) -> Result<(), SnapshotManagerError> {
        match self {
            SnapshotManager::Qemu(qemu_sm) => qemu_sm.restore(snapshot_id, qemu),
            SnapshotManager::Fast(fast_sm) => fast_sm.restore(snapshot_id, qemu),
        }
    }
}

pub type FastSnapshotPtr = *mut libafl_qemu_sys::SyxSnapshot;

#[derive(Debug, Clone)]
pub struct FastSnapshotManager {
    snapshots: HashMap<SnapshotId, FastSnapshotPtr>,
    check_memory_consistency: bool,
}

impl Default for FastSnapshotManager {
    fn default() -> Self {
        Self::new(false)
    }
}

impl FastSnapshotManager {
    pub fn new(check_memory_consistency: bool) -> Self {
        Self {
            snapshots: HashMap::new(),
            check_memory_consistency,
        }
    }

    pub unsafe fn get(&self, id: &SnapshotId) -> FastSnapshotPtr {
        self.snapshots.get(id).unwrap().clone()
    }
}

#[derive(Debug, Clone)]
pub struct QemuSnapshotManager {
    is_sync: bool,
}

impl QemuSnapshotManager {
    pub fn new(is_sync: bool) -> Self {
        Self { is_sync }
    }

    pub fn snapshot_id_to_name(&self, snapshot_id: &SnapshotId) -> String {
        format!("__libafl_qemu_snapshot_{}", snapshot_id.inner())
    }
}

impl IsSnapshotManager for QemuSnapshotManager {
    fn save(&mut self, qemu: &Qemu) -> SnapshotId {
        let snapshot_id = SnapshotId::gen_unique_id();
        qemu.save_snapshot(
            self.snapshot_id_to_name(&snapshot_id).as_str(),
            self.is_sync,
        );
        snapshot_id
    }

    fn restore(
        &mut self,
        snapshot_id: &SnapshotId,
        qemu: &Qemu,
    ) -> Result<(), SnapshotManagerError> {
        qemu.load_snapshot(self.snapshot_id_to_name(snapshot_id).as_str(), self.is_sync);
        Ok(())
    }
}

impl IsSnapshotManager for FastSnapshotManager {
    fn save(&mut self, qemu: &Qemu) -> SnapshotId {
        let snapshot_id = SnapshotId::gen_unique_id();
        self.snapshots
            .insert(snapshot_id, qemu.create_fast_snapshot(true));
        snapshot_id
    }

    fn restore(
        &mut self,
        snapshot_id: &SnapshotId,
        qemu: &Qemu,
    ) -> Result<(), SnapshotManagerError> {
        let fast_snapshot_ptr = self
            .snapshots
            .get(snapshot_id)
            .ok_or(SnapshotManagerError::SnapshotIdNotFound(
                snapshot_id.clone(),
            ))?
            .clone();

        qemu.restore_fast_snapshot(fast_snapshot_ptr);

        if self.check_memory_consistency {
            let nb_inconsistencies = qemu.check_fast_snapshot_memory_consistency(fast_snapshot_ptr);

            if nb_inconsistencies > 0 {
                return Err(SnapshotManagerError::MemoryInconsistencies(
                    nb_inconsistencies,
                ));
            }
        }

        Ok(())
    }
}

pub enum DeviceSnapshotFilter {
    All,
    AllowList(Vec<String>),
    DenyList(Vec<String>),
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
                v.as_mut_ptr()
            }
        }
    }
}

pub(super) extern "C" fn qemu_cleanup_atexit() {
    unsafe {
        qemu_cleanup();
    }
}

impl CPU {
    #[must_use]
    pub fn get_phys_addr(&self, vaddr: GuestAddr) -> Option<GuestPhysAddr> {
        unsafe {
            let page = libafl_page_from_addr(vaddr);
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

    #[must_use]
    pub fn page_size(&self) -> usize {
        unsafe { libafl_qemu_sys::qemu_target_page_size() }
    }
}

#[allow(clippy::unused_self)]
impl Qemu {
    /// Write a value to a phsical guest address, including ROM areas.
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
    pub unsafe fn run(&self) -> Result<QemuExitReason, QemuExitReasonError> {
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

    pub fn restore_fast_snapshot(&self, snapshot: FastSnapshotPtr) {
        unsafe { libafl_qemu_sys::syx_snapshot_root_restore(snapshot) }
    }

    pub fn check_fast_snapshot_memory_consistency(&self, snapshot: FastSnapshotPtr) -> u64 {
        unsafe { libafl_qemu_sys::syx_snapshot_check_memory_consistency(snapshot) }
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
}

impl<QT, S, E> Emulator<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmuExitHandler<QT, S>,
{
    /// Write a value to a phsical guest address, including ROM areas.
    pub unsafe fn write_phys_mem(&self, paddr: GuestPhysAddr, buf: &[u8]) {
        self.qemu.write_phys_mem(paddr, buf)
    }

    /// Read a value from a physical guest address.
    pub unsafe fn read_phys_mem(&self, paddr: GuestPhysAddr, buf: &mut [u8]) {
        self.qemu.read_phys_mem(paddr, buf)
    }

    pub fn save_snapshot(&self, name: &str, sync: bool) {
        self.qemu.save_snapshot(name, sync)
    }

    pub fn load_snapshot(&self, name: &str, sync: bool) {
        self.qemu.load_snapshot(name, sync)
    }

    #[must_use]
    pub fn create_fast_snapshot(&self, track: bool) -> FastSnapshotPtr {
        self.qemu.create_fast_snapshot(track)
    }

    #[must_use]
    pub fn create_fast_snapshot_filter(
        &self,
        track: bool,
        device_filter: &DeviceSnapshotFilter,
    ) -> FastSnapshotPtr {
        self.qemu.create_fast_snapshot_filter(track, device_filter)
    }

    pub fn restore_fast_snapshot(&self, snapshot: FastSnapshotPtr) {
        self.qemu.restore_fast_snapshot(snapshot)
    }

    pub fn check_fast_snapshot_memory_consistency(&self, snapshot: FastSnapshotPtr) -> u64 {
        self.qemu.check_fast_snapshot_memory_consistency(snapshot)
    }

    pub fn list_devices(&self) -> Vec<String> {
        self.qemu.list_devices()
    }
}
