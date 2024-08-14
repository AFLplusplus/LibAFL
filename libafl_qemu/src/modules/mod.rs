use core::{fmt::Debug, ops::Range};
use std::{cell::UnsafeCell, hash::BuildHasher};

use hashbrown::HashSet;
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

use crate::Qemu;

#[cfg(emulation_mode = "usermode")]
pub mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[cfg(emulation_mode = "systemmode")]
pub mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

pub mod edges;
pub use edges::EdgeCoverageModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::CallTracerModule;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::CmpLogModule;

use crate::emu::EmulatorModules;

/// A module for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<S>: 'static + Debug
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Initialize the module, mostly used to install some hooks early.
    fn init_module<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn first_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _input: &S::Input)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }
}

pub trait EmulatorModuleTuple<S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Unpin
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_modules_all<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>;

    fn first_exec_all<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>;
}

impl<S> EmulatorModuleTuple<S> for ()
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_modules_all<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn first_exec_all<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }
}

impl<Head, Tail, S> EmulatorModuleTuple<S> for (Head, Tail)
where
    Head: EmulatorModule<S> + Unpin,
    Tail: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_modules_all<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.init_module(emulator_modules);
        self.1.init_modules_all(emulator_modules);
    }

    fn first_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.first_exec(emulator_modules);
        self.1.first_exec_all(emulator_modules);
    }

    fn pre_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, input: &S::Input)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_exec(emulator_modules, input);
        self.1.pre_exec_all(emulator_modules, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.0
            .post_exec(emulator_modules, input, observers, exit_kind);
        self.1
            .post_exec_all(emulator_modules, input, observers, exit_kind);
    }
}

impl HasInstrumentationFilter<()> for () {
    fn filter(&self) -> &() {
        self
    }

    fn filter_mut(&mut self) -> &mut () {
        self
    }
}

impl<Head, F> HasInstrumentationFilter<F> for (Head, ())
where
    Head: HasInstrumentationFilter<F>,
    F: IsFilter,
{
    fn filter(&self) -> &F {
        self.0.filter()
    }

    fn filter_mut(&mut self) -> &mut F {
        self.0.filter_mut()
    }
}

#[derive(Debug, Clone)]
pub enum QemuFilterList<T: IsFilter + Debug + Clone> {
    AllowList(T),
    DenyList(T),
    None,
}

impl<T> IsFilter for QemuFilterList<T>
where
    T: IsFilter + Clone,
{
    type FilterParameter = T::FilterParameter;

    fn allowed(&self, filter_parameter: Self::FilterParameter) -> bool {
        match self {
            QemuFilterList::AllowList(allow_list) => allow_list.allowed(filter_parameter),
            QemuFilterList::DenyList(deny_list) => !deny_list.allowed(filter_parameter),
            QemuFilterList::None => true,
        }
    }
}

pub type QemuInstrumentationPagingFilter = QemuFilterList<HashSet<GuestPhysAddr>>;

impl<H> IsFilter for HashSet<GuestPhysAddr, H>
where
    H: BuildHasher,
{
    type FilterParameter = Option<GuestPhysAddr>;

    fn allowed(&self, paging_id: Self::FilterParameter) -> bool {
        paging_id.is_some_and(|pid| self.contains(&pid))
    }
}

pub type QemuInstrumentationAddressRangeFilter = QemuFilterList<Vec<Range<GuestAddr>>>;

impl IsFilter for Vec<Range<GuestAddr>> {
    type FilterParameter = GuestAddr;

    fn allowed(&self, addr: Self::FilterParameter) -> bool {
        for rng in self {
            if rng.contains(&addr) {
                return true;
            }
        }
        false
    }
}

pub trait HasInstrumentationFilter<F>
where
    F: IsFilter,
{
    fn filter(&self) -> &F;

    fn filter_mut(&mut self) -> &mut F;

    fn update_filter(&mut self, filter: F, emu: &Qemu) {
        *self.filter_mut() = filter;
        emu.flush_jit();
    }
}

static mut EMPTY_ADDRESS_FILTER: UnsafeCell<QemuInstrumentationAddressRangeFilter> =
    UnsafeCell::new(QemuFilterList::None);
static mut EMPTY_PAGING_FILTER: UnsafeCell<QemuInstrumentationPagingFilter> =
    UnsafeCell::new(QemuFilterList::None);

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for () {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &QemuFilterList::None
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        unsafe { EMPTY_ADDRESS_FILTER.get_mut() }
    }
}

impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for () {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &QemuFilterList::None
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        unsafe { EMPTY_PAGING_FILTER.get_mut() }
    }
}

pub trait IsFilter: Debug {
    type FilterParameter;

    fn allowed(&self, filter_parameter: Self::FilterParameter) -> bool;
}

impl IsFilter for () {
    type FilterParameter = ();

    fn allowed(&self, _filter_parameter: Self::FilterParameter) -> bool {
        true
    }
}

pub trait IsAddressFilter: IsFilter<FilterParameter = GuestAddr> {}

impl IsAddressFilter for QemuInstrumentationAddressRangeFilter {}

#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x) ^ x;
    x
}
