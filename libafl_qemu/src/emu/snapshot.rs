use std::{
    fmt::Debug,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::Qemu;

pub trait IsSnapshotManager: Clone + Debug {
    fn init(&mut self, _qemu: Qemu) {}

    fn save(&mut self, qemu: Qemu) -> SnapshotId;
    fn restore(&mut self, qemu: Qemu, snapshot_id: &SnapshotId)
    -> Result<(), SnapshotManagerError>;
    fn do_check(
        &self,
        qemu: Qemu,
        reference_snapshot_id: &SnapshotId,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError>;

    fn check(
        &self,
        qemu: Qemu,
        reference_snapshot_id: &SnapshotId,
    ) -> Result<(), SnapshotManagerCheckError> {
        let check_result = self
            .do_check(qemu, reference_snapshot_id)
            .map_err(SnapshotManagerCheckError::SnapshotManagerError)?;

        if check_result == QemuSnapshotCheckResult::default() {
            Ok(())
        } else {
            Err(SnapshotManagerCheckError::SnapshotCheckError(check_result))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuSnapshotCheckResult {
    nb_page_inconsistencies: u64,
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerError {
    SnapshotIdNotFound(SnapshotId),
    MemoryInconsistencies(u64),
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerCheckError {
    SnapshotManagerError(SnapshotManagerError),
    SnapshotCheckError(QemuSnapshotCheckResult),
}

#[derive(Debug, Clone, Copy)]
pub struct NopSnapshotManager;

impl Default for NopSnapshotManager {
    fn default() -> Self {
        NopSnapshotManager
    }
}

impl IsSnapshotManager for NopSnapshotManager {
    fn save(&mut self, _qemu: Qemu) -> SnapshotId {
        log::debug!("Saving snapshot with the NopSnapshotManager");
        SnapshotId { id: 0 }
    }

    fn restore(
        &mut self,
        _qemu: Qemu,
        _snapshot_id: &SnapshotId,
    ) -> Result<(), SnapshotManagerError> {
        log::debug!("Restoring snapshot with the NopSnapshotManager");
        Ok(())
    }

    fn do_check(
        &self,
        _qemu: Qemu,
        _reference_snapshot_id: &SnapshotId,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError> {
        Ok(QemuSnapshotCheckResult::default())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SnapshotId {
    id: u64,
}

/// Represents a QEMU snapshot check result for which no error was detected
impl Default for QemuSnapshotCheckResult {
    fn default() -> Self {
        Self {
            nb_page_inconsistencies: 0,
        }
    }
}

impl QemuSnapshotCheckResult {
    #[must_use]
    pub fn new(nb_page_inconsistencies: u64) -> Self {
        Self {
            nb_page_inconsistencies,
        }
    }
}

impl SnapshotId {
    pub fn gen_unique_id() -> SnapshotId {
        static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        let unique_id = UNIQUE_ID.fetch_add(1, Ordering::SeqCst);

        SnapshotId { id: unique_id }
    }

    #[must_use]
    pub fn inner(&self) -> u64 {
        self.id
    }
}
