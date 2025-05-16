use alloc::fmt::Debug;
use core::cell::UnsafeCell;

use crate::GuestAddr;

pub struct AtomicGuestAddr {
    addr: UnsafeCell<GuestAddr>,
}

unsafe impl Sync for AtomicGuestAddr {}

impl AtomicGuestAddr {
    pub const fn new() -> Self {
        AtomicGuestAddr {
            addr: UnsafeCell::new(GuestAddr::MIN),
        }
    }

    pub fn load(&self) -> Option<GuestAddr> {
        let addr = unsafe { *self.addr.get() };
        match addr {
            GuestAddr::MIN => None,
            _ => Some(addr),
        }
    }

    pub fn store(&self, addr: GuestAddr) {
        unsafe { *self.addr.get() = addr };
    }

    pub fn get_or_insert_with<F>(&self, f: F) -> GuestAddr
    where
        F: FnOnce() -> GuestAddr,
    {
        if let Some(addr) = self.load() {
            addr
        } else {
            let addr = f();
            self.store(addr);
            addr
        }
    }

    pub fn try_get_or_insert_with<F, E>(&self, f: F) -> Result<GuestAddr, E>
    where
        F: FnOnce() -> Result<GuestAddr, E>,
        E: Debug,
    {
        if let Some(addr) = self.load() {
            Ok(addr)
        } else {
            let addr = f()?;
            self.store(addr);
            Ok(addr)
        }
    }
}

impl Default for AtomicGuestAddr {
    fn default() -> Self {
        Self::new()
    }
}
