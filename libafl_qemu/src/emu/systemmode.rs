use std::{
    collections::HashMap,
    fmt::Debug,
    sync::atomic::{AtomicU64, Ordering},
};

use libafl::state::{HasExecutions, State};
use libafl_qemu_sys::GuestPhysAddr;

use crate::{
    emu::IsSnapshotManager, DeviceSnapshotFilter, Emulator, EmulatorExitHandler, Qemu,
    QemuHelperTuple, SnapshotId, SnapshotManagerError,
};

impl SnapshotId {
    fn gen_unique_id() -> SnapshotId {
        static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        let unique_id = UNIQUE_ID.fetch_add(1, Ordering::SeqCst);

        SnapshotId { id: unique_id }
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
        *self.snapshots.get(id).unwrap()
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
        let fast_snapshot_ptr = *self
            .snapshots
            .get(snapshot_id)
            .ok_or(SnapshotManagerError::SnapshotIdNotFound(*snapshot_id))?;

        unsafe {
            qemu.restore_fast_snapshot(fast_snapshot_ptr);
        }

        if self.check_memory_consistency {
            let nb_inconsistencies =
                unsafe { qemu.check_fast_snapshot_memory_consistency(fast_snapshot_ptr) };

            if nb_inconsistencies > 0 {
                return Err(SnapshotManagerError::MemoryInconsistencies(
                    nb_inconsistencies,
                ));
            }
        }

        Ok(())
    }
}

impl<QT, S, E> Emulator<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmulatorExitHandler<QT, S>,
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

    pub unsafe fn check_fast_snapshot_memory_consistency(&self, snapshot: FastSnapshotPtr) -> u64 {
        self.qemu.check_fast_snapshot_memory_consistency(snapshot)
    }

    pub fn list_devices(&self) -> Vec<String> {
        self.qemu.list_devices()
    }
}
