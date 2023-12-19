use std::{
    collections::HashMap,
    ffi::{c_void, CStr, CString},
    fmt::Debug,
    mem::MaybeUninit,
    ptr::null_mut,
    sync::atomic::{AtomicU64, Ordering},
    borrow::BorrowMut,
};
use std::cell::OnceCell;
use std::collections::HashSet;
use std::marker::PhantomData;

use crate::{emu::{libafl_page_from_addr, BytesInput, ExitKind}, CPUStatePtr, EmuExitReason, EmuExitReasonError, Emulator, GuestAddr, GuestPhysAddr, GuestVirtAddr, IsEmuExitHandler, MemAccessInfo, CPU, CommandInput, Command, InnerHandlerResult, QemuHooks, get_qemu_hooks, QemuInstrumentationPagingFilter, HasInstrumentationFilter, QemuHelperTuple, QemuEdgeCoverageHelper};
use crate::sync_exit::{SyncExitError, SyncExit, VERSION};

use libafl::{inputs::{UsesInput, HasTargetBytes}, prelude::{StdState, InMemoryCorpus, OnDiskCorpus}};
use libafl_bolts::AsSlice;
use libafl_bolts::bolts_prelude::RomuDuoJrRand;

#[derive(Debug, Clone)]
pub enum HandlerError {
    EmuExitReasonError(EmuExitReasonError),
    SMError(SnapshotManagerError),
    SyncExitError(SyncExitError),
    MultipleSnapshotDefinition,
    MultipleInputDefinition,
    SnapshotNotFound,
}

impl From<SnapshotManagerError> for HandlerError {
    fn from(sm_error: SnapshotManagerError) -> Self {
        HandlerError::SMError(sm_error)
    }
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerError {
    SnapshotIdNotFound(SnapshotId),
    MemoryInconsistencies(u64),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SnapshotId {
    id: u64,
}

impl SnapshotId {
    fn get_fresh_id() -> SnapshotId {
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

pub type FastSnapshotPtr = *mut libafl_qemu_sys::SyxSnapshot;

pub trait IsSnapshotManager: Debug {
    fn save<E>(&mut self, emu: &Emulator<E>) -> SnapshotId
    where
        E: IsEmuExitHandler;
    fn restore<E>(
        &mut self,
        snapshot_id: &SnapshotId,
        emu: &Emulator<E>,
    ) -> Result<(), SnapshotManagerError>
    where
        E: IsEmuExitHandler;
}

#[derive(Debug, Clone)]
pub struct FastSnapshotBuilder {
    snapshots: HashMap<SnapshotId, FastSnapshotPtr>,
    check_memory_consistency: bool,
}

impl Default for FastSnapshotBuilder {
    fn default() -> Self {
        Self::new(false)
    }
}

impl FastSnapshotBuilder {
    pub fn new(check_memory_consistency: bool) -> Self {
        Self {
            snapshots: HashMap::new(),
            check_memory_consistency,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QemuSnapshotBuilder {
    is_sync: bool,
}

impl QemuSnapshotBuilder {
    pub fn new(is_sync: bool) -> Self {
        Self { is_sync }
    }

    pub fn snapshot_id_to_name(&self, snapshot_id: &SnapshotId) -> String {
        format!("__libafl_qemu_snapshot_{}", snapshot_id.inner())
    }
}

impl IsSnapshotManager for QemuSnapshotBuilder {
    fn save<E>(&mut self, emu: &Emulator<E>) -> SnapshotId
    where
        E: IsEmuExitHandler,
    {
        let snapshot_id = SnapshotId::get_fresh_id();
        emu.save_snapshot(
            self.snapshot_id_to_name(&snapshot_id).as_str(),
            self.is_sync,
        );
        snapshot_id
    }

    fn restore<E>(
        &mut self,
        snapshot_id: &SnapshotId,
        emu: &Emulator<E>,
    ) -> Result<(), SnapshotManagerError>
    where
        E: IsEmuExitHandler,
    {
        emu.load_snapshot(self.snapshot_id_to_name(snapshot_id).as_str(), self.is_sync);
        Ok(())
    }
}

impl IsSnapshotManager for FastSnapshotBuilder {
    fn save<E>(&mut self, emu: &Emulator<E>) -> SnapshotId
    where
        E: IsEmuExitHandler,
    {
        let snapshot_id = SnapshotId::get_fresh_id();
        self.snapshots
            .insert(snapshot_id, emu.create_fast_snapshot(true));
        snapshot_id
    }

    fn restore<E>(
        &mut self,
        snapshot_id: &SnapshotId,
        emu: &Emulator<E>,
    ) -> Result<(), SnapshotManagerError>
    where
        E: IsEmuExitHandler,
    {
        let fast_snapshot_ptr = self
            .snapshots
            .get(snapshot_id)
            .ok_or(SnapshotManagerError::SnapshotIdNotFound(
                snapshot_id.clone(),
            ))?
            .clone();

        emu.restore_fast_snapshot(fast_snapshot_ptr);

        if self.check_memory_consistency {
            let nb_inconsistencies = emu.check_fast_snapshot_memory_consistency(fast_snapshot_ptr);

            if nb_inconsistencies > 0 {
                return Err(SnapshotManagerError::MemoryInconsistencies(
                    nb_inconsistencies,
                ));
            }
        }

        Ok(())
    }
}

/// Synchronous Exit handler maintaining only one snapshot.
#[derive(Debug, Clone)]
pub struct StdEmuExitHandler<SM>
    where
        SM: IsSnapshotManager,
{
    snapshot_manager: SM,
    snapshot_id: OnceCell<SnapshotId>,
    input_backdoor: OnceCell<SyncExit>,
    input_command: OnceCell<CommandInput>,
}

impl<SM> StdEmuExitHandler<SM>
    where
        SM: IsSnapshotManager,
{
    pub fn new(snapshot_manager: SM) -> Self {
        Self {
            snapshot_manager,
            snapshot_id: OnceCell::new(),
            input_backdoor: OnceCell::new(),
            input_command: OnceCell::new(),
        }
    }
}

// TODO: replace handlers with generics to permit compile-time customization of handlers
impl<SM> IsEmuExitHandler for StdEmuExitHandler<SM>
    where
        SM: IsSnapshotManager,
{
    fn try_put_input(&mut self, emu: &Emulator<Self>, input: &BytesInput) {
        let target = input.target_bytes();
        let buf = target.as_slice();

        if let Some(input_command) = self.input_command.get() {
            input_command.exec(emu, None, buf)
        }

        if let Some(input_sync_exit) = self.input_backdoor.get() {
            match input_sync_exit.command() {
                Command::Input(cmd_input) => cmd_input.exec(emu, Some(input_sync_exit), buf),
                Command::Start(cmd_input) => cmd_input.exec(emu, Some(input_sync_exit), buf),
                _ => panic!("Unexpected command: {}", input_sync_exit),
            }
        }
    }

    fn handle(
        &mut self,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        emu: &Emulator<Self>,
        input: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let target = input.target_bytes();
        let buf = target.as_slice();

        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmuExitReasonError::UnexpectedExit => {
                    if let Some(snapshot_id) = self.snapshot_id.get() {
                        self.snapshot_manager.borrow_mut().restore(snapshot_id, emu)?;
                    }
                    return Ok(InnerHandlerResult::EndOfRun(ExitKind::Crash))
                }
                _ => Err(exit_error)?
            }
        };

        let mut is_sync_exit: Option<SyncExit> = None;
        let command = match &mut exit_reason {
            EmuExitReason::End => {
                return Ok(InnerHandlerResult::EndOfRun(ExitKind::Crash));
            }
            EmuExitReason::Breakpoint(bp) => bp.trigger(emu).cloned(),
            EmuExitReason::SyncBackdoor(sync_exit) => {
                let command = sync_exit.command().clone();
                is_sync_exit = Some(sync_exit.clone());
                Some(command)
            }
        };

        Ok(if let Some(cmd) = command {
            match cmd {
                Command::Save => {
                    self.snapshot_id
                        .set(self.snapshot_manager.save(emu))
                        .map_err(|_| HandlerError::MultipleSnapshotDefinition)?;

                    // TODO: get helpers from harness cleanly. Find a way to use generics without trait overflow.
                    let qemu_helpers: &mut QemuHooks<(QemuEdgeCoverageHelper, ()), StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, OnDiskCorpus<BytesInput>>, Self> = unsafe {
                        get_qemu_hooks::<(QemuEdgeCoverageHelper, ()), StdState<BytesInput, InMemoryCorpus<BytesInput>, RomuDuoJrRand, OnDiskCorpus<BytesInput>>, Self>()
                    };

                    // TODO: Improve this part used to perform paging filtering
                    let helpers = qemu_helpers.helpers_mut();

                    let mut allowed_paging_ids = HashSet::new();

                    let current_paging_id =
                        emu.current_cpu().unwrap().get_current_paging_id().unwrap();
                    allowed_paging_ids.insert(current_paging_id);

                    let paging_filter =
                        HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(helpers);

                    *paging_filter = QemuInstrumentationPagingFilter::AllowList(allowed_paging_ids);

                    InnerHandlerResult::Continue
                }

                Command::Load => {
                    self.snapshot_manager.restore(
                        self.snapshot_id
                            .get()
                            .ok_or(HandlerError::SnapshotNotFound)?,
                        emu,
                    )?;
                    InnerHandlerResult::Continue
                }
                Command::Input(command_input) => {
                    if let Some(sync_exit) = &is_sync_exit {
                        self.input_backdoor
                            .set(sync_exit.clone())
                            .map_err(|_| HandlerError::MultipleInputDefinition)?;
                    } else {
                        self.input_command
                            .set(command_input.clone())
                            .map_err(|_| HandlerError::MultipleInputDefinition)?;
                    }

                    command_input.exec(emu, is_sync_exit.as_ref(), buf);

                    InnerHandlerResult::Continue
                }
                Command::Start(command_input) => {
                    self.snapshot_id
                        .set(self.snapshot_manager.save(emu))
                        .map_err(|_| HandlerError::MultipleSnapshotDefinition)?;

                    if let Some(sync_exit) = &is_sync_exit {
                        self.input_backdoor
                            .set(sync_exit.clone())
                            .map_err(|_| HandlerError::MultipleInputDefinition)?;
                    } else {
                        self.input_command
                            .set(command_input.clone())
                            .map_err(|_| HandlerError::MultipleInputDefinition)?;
                    }

                    command_input.exec(emu, is_sync_exit.as_ref(), buf);

                    InnerHandlerResult::Continue
                }
                Command::Exit(exit_kind) => {
                    self.snapshot_manager.restore(
                        self.snapshot_id
                            .get()
                            .ok_or(HandlerError::SnapshotNotFound)?,
                        emu,
                    )?;
                    InnerHandlerResult::EndOfRun(exit_kind.unwrap())
                }
                Command::Version(version) => {
                    if VERSION != version {
                        return Err(SyncExitError::VersionDifference(version))?;
                    }

                    InnerHandlerResult::Continue
                }
            }
        } else {
            InnerHandlerResult::ReturnToHarness(exit_reason)
        })
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

extern "C" {
    pub(super) fn qemu_init(argc: i32, argv: *const *const u8, envp: *const *const u8);

    fn vm_start();
    fn qemu_main_loop();
    fn qemu_cleanup();

    fn libafl_save_qemu_snapshot(name: *const u8, sync: bool);
    fn libafl_load_qemu_snapshot(name: *const u8, sync: bool);
}

pub(super) extern "C" fn qemu_cleanup_atexit() {
    unsafe {
        qemu_cleanup();
    }
}

extern "C" {
    fn libafl_qemu_current_paging_id(cpu: CPUStatePtr) -> GuestPhysAddr;
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
    pub fn get_current_paging_id(&self) -> Option<GuestPhysAddr> {
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

impl<E> Emulator<E>
where
    E: IsEmuExitHandler,
{
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
    pub unsafe fn run(&self) -> Result<EmuExitReason, EmuExitReasonError> {
        vm_start();
        qemu_main_loop();
        EmuExitReason::try_from(self)
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
