use core::{fmt::Debug, ops::Range};
use libafl::{
    bolts::tuples::MatchFirstType, executors::ExitKind, inputs::Input, observers::ObserversTuple,
};

use crate::{emu::Emulator, executor::QemuExecutor};

/// A helper for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait QemuHelper<I, S>: 'static + Debug
where
    I: Input,
{
    fn init<'a, H, OT, QT>(&self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
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
    fn init_all<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>;

    fn pre_exec_all(&mut self, _emulator: &Emulator, input: &I);

    fn post_exec_all(&mut self, _emulator: &Emulator, input: &I);
}

impl<I, S> QemuHelperTuple<I, S> for ()
where
    I: Input,
{
    fn init_all<'a, H, OT, QT>(&self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
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
    fn init_all<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        self.0.init(executor);
        self.1.init_all(executor);
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
