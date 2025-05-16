use alloc::fmt::Debug;
use core::{
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use crate::GuestAddr;

pub struct AtomicGuestAddr {
    addr: AtomicPtr<c_void>,
}

impl AtomicGuestAddr {
    pub const fn new() -> Self {
        AtomicGuestAddr {
            addr: AtomicPtr::new(null_mut()),
        }
    }

    pub fn load(&self) -> Option<GuestAddr> {
        let addr = self.addr.load(Ordering::SeqCst) as GuestAddr;
        match addr {
            GuestAddr::MIN => None,
            _ => Some(addr),
        }
    }

    pub fn store(&self, addr: GuestAddr) {
        self.addr.store(addr as *mut c_void, Ordering::SeqCst);
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
