use libafl::inputs::UsesInput;
use libafl_qemu_sys::{GuestAddr, MmapPerms, VerifyAccess};

use crate::{command::CommandManager, Emulator, GuestMaps, NopSnapshotManager};

pub type StdSnapshotManager = NopSnapshotManager;

impl<CM, ED, ET, S, SM> Emulator<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    /// This function gets the memory mappings from the emulator.
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        self.qemu.mappings()
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        self.qemu.g2h(addr)
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        self.qemu.h2g(addr)
    }

    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        self.qemu.access_ok(kind, addr, size)
    }

    pub fn force_dfl(&self) {
        self.qemu.force_dfl();
    }

    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        self.qemu.binary_path()
    }

    #[must_use]
    pub fn load_addr(&self) -> GuestAddr {
        self.qemu.load_addr()
    }

    #[must_use]
    pub fn get_brk(&self) -> GuestAddr {
        self.qemu.get_brk()
    }

    pub fn set_brk(&self, brk: GuestAddr) {
        self.qemu.set_brk(brk);
    }

    #[must_use]
    pub fn get_mmap_start(&self) -> GuestAddr {
        self.qemu.get_mmap_start()
    }

    pub fn set_mmap_start(&self, start: GuestAddr) {
        self.qemu.set_mmap_start(start);
    }

    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.qemu.map_private(addr, size, perms)
    }

    pub fn map_fixed(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.qemu.map_fixed(addr, size, perms)
    }

    pub fn mprotect(&self, addr: GuestAddr, size: usize, perms: MmapPerms) -> Result<(), String> {
        self.qemu.mprotect(addr, size, perms)
    }

    pub fn unmap(&self, addr: GuestAddr, size: usize) -> Result<(), String> {
        self.qemu.unmap(addr, size)
    }
}
