use std::{
    borrow::Borrow,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use libafl::state::{HasExecutions, State};
use libafl_qemu_sys::GuestAddr;

use crate::{
    command::{CommandManager, IsCommand},
    EmulatorExitHandler, Qemu, QemuHelperTuple,
};

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointId(u64);

// TODO: distinguish breakpoints with IDs instead of addresses to avoid collisions.
#[derive(Debug)]
pub struct Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    id: BreakpointId,
    addr: GuestAddr,
    cmd: Option<Rc<dyn IsCommand<CM, E, QT, S>>>,
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

impl<CM, E, QT, S> Hash for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<CM, E, QT, S> PartialEq for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<CM, E, QT, S> Eq for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
}

impl<CM, E, QT, S> Display for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Breakpoint @vaddr 0x{:x}", self.addr)
    }
}

impl<CM, E, QT, S> Borrow<BreakpointId> for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn borrow(&self) -> &BreakpointId {
        &self.id
    }
}

impl<CM, E, QT, S> Borrow<GuestAddr> for Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn borrow(&self) -> &GuestAddr {
        &self.addr
    }
}

impl<CM, E, QT, S> Breakpoint<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
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
    pub fn with_command<C: IsCommand<CM, E, QT, S> + 'static>(
        addr: GuestAddr,
        cmd: C,
        disable_on_trigger: bool,
    ) -> Self {
        Self {
            id: BreakpointId::new(),
            addr,
            cmd: Some(Rc::new(cmd)),
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

    pub fn enable(&mut self, qemu: &Qemu) {
        if !self.enabled {
            qemu.set_breakpoint(self.addr);
            self.enabled = true;
        }
    }

    pub fn disable(&mut self, qemu: &Qemu) {
        if self.enabled {
            qemu.remove_breakpoint(self.addr.into());
            self.enabled = false;
        }
    }

    pub fn trigger(&mut self, qemu: &Qemu) -> Option<Rc<dyn IsCommand<CM, E, QT, S>>> {
        if self.disable_on_trigger {
            self.disable(qemu);
        }

        self.cmd.clone()
    }
}
