use std::{
    borrow::Borrow,
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use libafl_qemu_sys::GuestAddr;

use crate::Qemu;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointId(u64);

// TODO: distinguish breakpoints with IDs instead of addresses to avoid collisions.
#[derive(Clone)]
pub struct Breakpoint<C> {
    id: BreakpointId,
    addr: GuestAddr,
    cmd: Option<C>,
    disable_on_trigger: bool,
    enabled: bool,
}

impl<C> Debug for Breakpoint<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BP {:?} @ addr {:?}", self.id, self.addr)
    }
}

impl BreakpointId {
    pub fn new() -> Self {
        static BREAKPOINT_ID_COUNTER: OnceLock<AtomicU64> = OnceLock::new();
        let counter = BREAKPOINT_ID_COUNTER.get_or_init(|| AtomicU64::new(0));

        BreakpointId(counter.fetch_add(1, Ordering::SeqCst))
    }
}

impl Default for BreakpointId {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> Hash for Breakpoint<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<C> PartialEq for Breakpoint<C> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<C> Eq for Breakpoint<C> {}

impl<C> Display for Breakpoint<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Breakpoint @vaddr 0x{:x}", self.addr)
    }
}

impl<C> Borrow<BreakpointId> for Breakpoint<C> {
    fn borrow(&self) -> &BreakpointId {
        &self.id
    }
}

impl<C> Borrow<GuestAddr> for Breakpoint<C> {
    fn borrow(&self) -> &GuestAddr {
        &self.addr
    }
}

impl<C> Breakpoint<C> {
    // Emu will return with the breakpoint as exit reason.
    #[must_use]
    pub fn without_command(addr: GuestAddr, disable_on_trigger: bool) -> Self {
        Self {
            id: BreakpointId::new(),
            addr,
            cmd: None,
            disable_on_trigger,
            enabled: false,
        }
    }

    // Emu will execute the command when it meets the breakpoint.
    #[must_use]
    pub fn with_command(addr: GuestAddr, cmd: C, disable_on_trigger: bool) -> Self {
        Self {
            id: BreakpointId::new(),
            addr,
            cmd: Some(cmd),
            disable_on_trigger,
            enabled: false,
        }
    }

    #[must_use]
    pub fn id(&self) -> BreakpointId {
        self.id
    }

    #[must_use]
    pub fn addr(&self) -> GuestAddr {
        self.addr
    }

    pub fn enable(&mut self, qemu: Qemu) {
        if !self.enabled {
            qemu.set_breakpoint(self.addr);
            self.enabled = true;
        }
    }

    pub fn disable(&mut self, qemu: Qemu) {
        if self.enabled {
            qemu.remove_breakpoint(self.addr.into());
            self.enabled = false;
        }
    }

    pub fn trigger(&mut self, qemu: Qemu) -> Option<C>
    where
        C: Clone,
    {
        if self.disable_on_trigger {
            self.disable(qemu);
        }

        self.cmd.clone()
    }
}
