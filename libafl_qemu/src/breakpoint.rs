use std::{
    borrow::Borrow,
    fmt::{Debug, Display, Formatter},
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
pub struct Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    id: BreakpointId,
    addr: GuestAddr,
    cmd: Option<CM::Commands>,
    disable_on_trigger: bool,
    enabled: bool,
}

impl<CM, ED, ET, S, SM> Clone for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            addr: self.addr,
            cmd: self.cmd.clone(),
            disable_on_trigger: self.disable_on_trigger,
            enabled: self.enabled,
        }
    }
}

impl<CM, ED, ET, S, SM> Debug for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
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

impl<CM, ED, ET, S, SM> Hash for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<CM, ED, ET, S, SM> PartialEq for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<CM, ED, ET, S, SM> Eq for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
}

impl<CM, ED, ET, S, SM> Display for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Breakpoint @vaddr 0x{:x}", self.addr)
    }
}

impl<CM, ED, ET, S, SM> Borrow<BreakpointId> for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn borrow(&self) -> &BreakpointId {
        &self.id
    }
}

impl<CM, ED, ET, S, SM> Borrow<GuestAddr> for Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn borrow(&self) -> &GuestAddr {
        &self.addr
    }
}

impl<CM, ED, ET, S, SM> Breakpoint<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
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
