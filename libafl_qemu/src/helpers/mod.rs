use core::{fmt::Debug, ops::Range};
use std::{cell::UnsafeCell, collections::HashSet, hash::BuildHasher};

use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

use crate::{hooks::QemuHooks, Qemu};

pub mod edges;
pub use edges::QemuEdgeCoverageHelper;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::QemuCallTracerHelper;

#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;
#[cfg(not(cpu_target = "hexagon"))]
pub use drcov::QemuDrCovHelper;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::QemuCmpLogHelper;

#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub mod injections;
#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub use injections::QemuInjectionHelper;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod snapshot;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use snapshot::IntervalSnapshotFilter;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use snapshot::QemuSnapshotHelper;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod asan;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use asan::{init_qemu_with_asan, QemuAsanHelper};

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod asan_guest;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use asan_guest::{init_qemu_with_asan_guest, QemuAsanGuestHelper};

/// A helper for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait QemuHelper<S>: 'static + Debug
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn init_hooks<QT>(&self, _hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn first_exec<QT>(&self, _hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn pre_exec(&mut self, _qemu: Qemu, _input: &S::Input) {}

    fn post_exec<OT>(
        &mut self,
        _qemu: Qemu,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
    }
}

pub trait QemuHelperTuple<S>: MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a>
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_hooks_all<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>;

    fn first_exec_all<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>;

    fn pre_exec_all(&mut self, _qemu: Qemu, input: &S::Input);

    fn post_exec_all<OT>(
        &mut self,
        _qemu: Qemu,
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

    fn init_hooks_all<QT>(&self, _hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn first_exec_all<QT>(&self, _hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
    }

    fn pre_exec_all(&mut self, _qemu: Qemu, _input: &S::Input) {}

    fn post_exec_all<OT>(
        &mut self,
        _qemu: Qemu,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
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

impl<Head, Tail, S> QemuHelperTuple<S> for (Head, Tail)
where
    Head: QemuHelper<S>,
    Tail: QemuHelperTuple<S>,
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_hooks_all<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        self.0.init_hooks(hooks);
        self.1.init_hooks_all(hooks);
    }

    fn first_exec_all<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        self.0.first_exec(hooks);
        self.1.first_exec_all(hooks);
    }

    fn pre_exec_all(&mut self, qemu: Qemu, input: &S::Input) {
        self.0.pre_exec(qemu, input);
        self.1.pre_exec_all(qemu, input);
    }

    fn post_exec_all<OT>(
        &mut self,
        qemu: Qemu,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        self.0.post_exec(qemu, input, observers, exit_kind);
        self.1.post_exec_all(qemu, input, observers, exit_kind);
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

#[cfg(emulation_mode = "usermode")]
pub trait StdInstrumentationFilter:
    HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
{
}

#[cfg(emulation_mode = "systemmode")]
pub trait StdInstrumentationFilter:
    HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
    + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
{
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

#[cfg(emulation_mode = "systemmode")]
impl<Head> StdInstrumentationFilter for (Head, ()) where
    Head: HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
        + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
{
}

#[cfg(emulation_mode = "usermode")]
impl<Head> StdInstrumentationFilter for (Head, ()) where
    Head: HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
{
}

#[cfg(emulation_mode = "systemmode")]
impl StdInstrumentationFilter for () {}

#[cfg(emulation_mode = "usermode")]
impl StdInstrumentationFilter for () {}

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

#[cfg(emulation_mode = "systemmode")]
pub trait IsPagingFilter: IsFilter<FilterParameter = Option<GuestPhysAddr>> {}

#[cfg(emulation_mode = "systemmode")]
impl IsPagingFilter for QemuInstrumentationPagingFilter {}

impl IsAddressFilter for QemuInstrumentationAddressRangeFilter {}

#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x).overflowing_mul(0x45d9f3b).0;
    x = (x.overflowing_shr(16).0 ^ x) ^ x;
    x
}
