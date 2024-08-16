use std::{
    borrow::Borrow,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use libafl::inputs::UsesInput;
use libafl_qemu_sys::GuestAddr;

use crate::{command::CommandManager, Qemu};

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointId(u64);

// TODO: distinguish breakpoints with IDs instead of addresses to avoid collisions.
#[derive(Clone, Debug)]
pub struct Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    id: BreakpointId,
    addr: GuestAddr,
    cmd: Option<CM::Commands>,
    disable_on_trigger: bool,
    enabled: bool,
}

impl BreakpointId {
    pub fn new() -> Self {
        static mut BREAKPOINT_ID_COUNTER: OnceLock<AtomicU64> = OnceLock::new();

        let counter = unsafe { BREAKPOINT_ID_COUNTER.get_or_init(|| AtomicU64::new(0)) };

        BreakpointId(counter.fetch_add(1, Ordering::SeqCst))
    }
}

impl Default for BreakpointId {
    fn default() -> Self {
        Self::new()
    }
}

impl<CM, S> Hash for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<CM, S> PartialEq for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<CM, S> Eq for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
}

impl<CM, S> Display for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Breakpoint @vaddr 0x{:x}", self.addr)
    }
}

impl<CM, S> Borrow<BreakpointId> for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn borrow(&self) -> &BreakpointId {
        &self.id
    }
}

impl<CM, S> Borrow<GuestAddr> for Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn borrow(&self) -> &GuestAddr {
        &self.addr
    }
}

impl<CM, S> Breakpoint<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
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
    pub fn with_command(addr: GuestAddr, cmd: CM::Commands, disable_on_trigger: bool) -> Self {
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

    pub fn trigger(&mut self, qemu: Qemu) -> Option<CM::Commands> {
        if self.disable_on_trigger {
            self.disable(qemu);
        }

        self.cmd.clone()
    }
}
