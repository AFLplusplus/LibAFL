use std::fmt::Debug;

use hashbrown::HashMap;
use libafl::inputs::UsesInput;
use libafl_qemu_sys::GuestPhysAddr;

use crate::{
    command::CommandManager,
    emu::{IsSnapshotManager, QemuSnapshotCheckResult},
    DeviceSnapshotFilter, Emulator, Qemu, SnapshotId, SnapshotManagerError,
};

#[derive(Debug, Clone)]
pub enum SnapshotManager {
    Qemu(QemuSnapshotManager),
    Fast(FastSnapshotManager),
}

pub type StdSnapshotManager = FastSnapshotManager;

impl IsSnapshotManager for SnapshotManager {
    fn save(&mut self, qemu: Qemu) -> SnapshotId {
        match self {
            SnapshotManager::Qemu(qemu_sm) => qemu_sm.save(qemu),
            SnapshotManager::Fast(fast_sm) => fast_sm.save(qemu),
        }
    }

    fn restore(
        &mut self,
        qemu: Qemu,
        snapshot_id: &SnapshotId,
    ) -> Result<(), SnapshotManagerError> {
        match self {
            SnapshotManager::Qemu(qemu_sm) => qemu_sm.restore(qemu, snapshot_id),
            SnapshotManager::Fast(fast_sm) => fast_sm.restore(qemu, snapshot_id),
        }
    }

    fn do_check(
        &self,
        qemu: Qemu,
        reference_snapshot_id: &SnapshotId,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError> {
        match self {
            SnapshotManager::Qemu(qemu_sm) => qemu_sm.do_check(qemu, reference_snapshot_id),
            SnapshotManager::Fast(fast_sm) => fast_sm.do_check(qemu, reference_snapshot_id),
        }
    }
}

pub type FastSnapshotPtr = *mut libafl_qemu_sys::SyxSnapshot;

#[derive(Debug, Clone)]
pub struct FastSnapshotManager {
    snapshots: HashMap<SnapshotId, FastSnapshotPtr>,
}

impl Default for FastSnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FastSnapshotManager {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
        }
    }

    pub unsafe fn get(&self, id: &SnapshotId) -> FastSnapshotPtr {
        *self.snapshots.get(id).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct QemuSnapshotManager {
    is_sync: bool,
}

impl Default for QemuSnapshotManager {
    fn default() -> Self {
        QemuSnapshotManager::new(true)
    }
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
    fn save(&mut self, qemu: Qemu) -> SnapshotId {
        let snapshot_id = SnapshotId::gen_unique_id();
        qemu.save_snapshot(
            self.snapshot_id_to_name(&snapshot_id).as_str(),
            self.is_sync,
        );
        snapshot_id
    }

    fn restore(
        &mut self,
        qemu: Qemu,
        snapshot_id: &SnapshotId,
    ) -> Result<(), SnapshotManagerError> {
        qemu.load_snapshot(self.snapshot_id_to_name(snapshot_id).as_str(), self.is_sync);
        Ok(())
    }

    fn do_check(
        &self,
        _qemu: Qemu,
        _reference_snapshot_id: &SnapshotId,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError> {
        // We consider the qemu implementation to be 'ideal' for now.
        Ok(QemuSnapshotCheckResult::default())
    }
}

impl IsSnapshotManager for FastSnapshotManager {
    fn save(&mut self, qemu: Qemu) -> SnapshotId {
        let snapshot_id = SnapshotId::gen_unique_id();
        self.snapshots
            .insert(snapshot_id, qemu.create_fast_snapshot(true));
        snapshot_id
    }

    fn restore(
        &mut self,
        qemu: Qemu,
        snapshot_id: &SnapshotId,
    ) -> Result<(), SnapshotManagerError> {
        let fast_snapshot_ptr = *self
            .snapshots
            .get(snapshot_id)
            .ok_or(SnapshotManagerError::SnapshotIdNotFound(*snapshot_id))?;

        unsafe {
            qemu.restore_fast_snapshot(fast_snapshot_ptr);
        }

        Ok(())
    }

    fn do_check(
        &self,
        qemu: Qemu,
        reference_snapshot_id: &SnapshotId,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError> {
        let fast_snapshot_ptr = *self.snapshots.get(reference_snapshot_id).ok_or(
            SnapshotManagerError::SnapshotIdNotFound(*reference_snapshot_id),
        )?;

        unsafe { Ok(qemu.check_fast_snapshot(fast_snapshot_ptr)) }
    }
}

impl<CM, ED, ET, S, SM> Emulator<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
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

    pub unsafe fn restore_fast_snapshot(&self, snapshot: FastSnapshotPtr) {
        self.qemu.restore_fast_snapshot(snapshot)
    }

    pub fn list_devices(&self) -> Vec<String> {
        self.qemu.list_devices()
    }
}
