use core::{fmt::Debug, ops::Range, pin::Pin};
use libafl::{bolts::tuples::MatchFirstType, inputs::Input};

use crate::{emu::Emulator, hooks::QemuHooks};

/// A helper for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait QemuHelper<I, S>: 'static + Debug
where
    I: Input,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn init_hooks<'a, QT>(&self, _hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &I) {}

    fn post_exec(&mut self, _emulator: &Emulator, _input: &I) {}
}

pub trait QemuHelperTuple<I, S>: MatchFirstType + Debug
where
    I: Input,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_hooks_all<'a, QT>(&self, hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>;

    fn pre_exec_all(&mut self, _emulator: &Emulator, input: &I);

    fn post_exec_all(&mut self, _emulator: &Emulator, input: &I);
}

impl<I, S> QemuHelperTuple<I, S> for ()
where
    I: Input,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_hooks_all<'a, QT>(&self, _hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
    }

    fn pre_exec_all(&mut self, _emulator: &Emulator, _input: &I) {}

    fn post_exec_all(&mut self, _emulator: &Emulator, _input: &I) {}
}

impl<Head, Tail, I, S> QemuHelperTuple<I, S> for (Head, Tail)
where
    Head: QemuHelper<I, S>,
    Tail: QemuHelperTuple<I, S>,
    I: Input,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_hooks_all<'a, QT>(&self, hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        self.0.init_hooks(hooks);
        self.1.init_hooks_all(hooks);
    }

    fn pre_exec_all(&mut self, emulator: &Emulator, input: &I) {
        self.0.pre_exec(emulator, input);
        self.1.pre_exec_all(emulator, input);
    }

    fn post_exec_all(&mut self, emulator: &Emulator, input: &I) {
        self.0.post_exec(emulator, input);
        self.1.post_exec_all(emulator, input);
    }
}

#[derive(Debug)]
pub enum QemuInstrumentationFilter {
    AllowList(Vec<Range<u64>>),
    DenyList(Vec<Range<u64>>),
    None,
}

impl QemuInstrumentationFilter {
    #[must_use]
    pub fn allowed(&self, addr: u64) -> bool {
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
