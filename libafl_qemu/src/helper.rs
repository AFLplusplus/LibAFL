use core::{fmt::Debug, ops::Range};

use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};

use crate::{
    emu::{Emulator, GuestAddr},
    hooks::QemuHooks,
};

/// A helper for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait QemuHelper<S>: 'static + Debug
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn init_hooks<QT>(&self, _hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn first_exec<QT>(&self, _hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &S::Input) {}

    fn post_exec<OT>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
    }
}

pub trait QemuHelperTuple<S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Debug
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_hooks_all<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>;

    fn first_exec_all<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>;

    fn pre_exec_all(&mut self, _emulator: &Emulator, input: &S::Input);

    fn post_exec_all<OT>(
        &mut self,
        _emulator: &Emulator,
        input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>;
}

impl<S> QemuHelperTuple<S> for ()
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_hooks_all<QT>(&self, _hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn first_exec_all<QT>(&self, _hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn pre_exec_all(&mut self, _emulator: &Emulator, _input: &S::Input) {}

    fn post_exec_all<OT>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
    }
}

impl<Head, Tail, S> QemuHelperTuple<S> for (Head, Tail)
where
    Head: QemuHelper<S>,
    Tail: QemuHelperTuple<S>,
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_hooks_all<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        self.0.init_hooks(hooks);
        self.1.init_hooks_all(hooks);
    }

    fn first_exec_all<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        self.0.first_exec(hooks);
        self.1.first_exec_all(hooks);
    }

    fn pre_exec_all(&mut self, emulator: &Emulator, input: &S::Input) {
        self.0.pre_exec(emulator, input);
        self.1.pre_exec_all(emulator, input);
    }

    fn post_exec_all<OT>(
        &mut self,
        emulator: &Emulator,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        self.0.post_exec(emulator, input, observers, exit_kind);
        self.1.post_exec_all(emulator, input, observers, exit_kind);
    }
}

#[derive(Debug)]
pub enum QemuInstrumentationFilter {
    AllowList(Vec<Range<GuestAddr>>),
    DenyList(Vec<Range<GuestAddr>>),
    None,
}

impl QemuInstrumentationFilter {
    #[must_use]
    pub fn allowed(&self, addr: GuestAddr) -> bool {
        match self {
            QemuInstrumentationFilter::AllowList(l) => {
                for rng in l {
                    if rng.contains(&addr) {
                        return true;
                    }
                }
                false
            }
            QemuInstrumentationFilter::DenyList(l) => {
                for rng in l {
                    if rng.contains(&addr) {
                        return false;
                    }
                }
                true
            }
            QemuInstrumentationFilter::None => true,
        }
    }
}

#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x) ^ x;
    x
}
