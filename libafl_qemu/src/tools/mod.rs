use core::{fmt::Debug, ops::Range};
use std::{cell::UnsafeCell, hash::BuildHasher};

use hashbrown::HashSet;
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

use crate::Qemu;

pub mod edges;
pub use edges::QemuEdgeCoverageTool;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::QemuCallTracerTool;

#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;
#[cfg(not(cpu_target = "hexagon"))]
pub use drcov::QemuDrCovTool;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::QemuCmpLogTool;

#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub mod injections;
#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub use injections::QemuInjectionTool;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod snapshot;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use snapshot::IntervalSnapshotFilter;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use snapshot::QemuSnapshotTool;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod asan;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use asan::{init_qemu_with_asan, QemuAsanTool};

use crate::emu::EmulatorTools;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod asan_guest;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use asan_guest::{init_qemu_with_asan_guest, QemuAsanGuestTool};

/// A tool for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorTool<S>: 'static + Debug
where
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Initialize the tool, mostly used to install some hooks early.
    fn init_tool<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn first_exec<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn pre_exec<ET>(&mut self, _emulator_tools: &mut EmulatorTools<ET, S>, _input: &S::Input)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_tools: &mut EmulatorTools<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorToolTuple<S>,
    {
    }
}

pub trait EmulatorToolTuple<S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Unpin
where
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn init_tools_all<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>;

    fn first_exec_all<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>;

    fn pre_exec_all<ET>(&mut self, _emulator_tools: &mut EmulatorTools<ET, S>, _input: &S::Input)
    where
        ET: EmulatorToolTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_tools: &mut EmulatorTools<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorToolTuple<S>;
}

impl<S> EmulatorToolTuple<S> for ()
where
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_tools_all<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn first_exec_all<ET>(&self, _emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn pre_exec_all<ET>(&mut self, _emulator_tools: &mut EmulatorTools<ET, S>, _input: &S::Input)
    where
        ET: EmulatorToolTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_tools: &mut EmulatorTools<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorToolTuple<S>,
    {
    }
}

impl<Head, Tail, S> EmulatorToolTuple<S> for (Head, Tail)
where
    Head: EmulatorTool<S> + Unpin,
    Tail: EmulatorToolTuple<S>,
    S: Unpin + UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn init_tools_all<ET>(&self, emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
        self.0.init_tool(emulator_tools);
        self.1.init_tools_all(emulator_tools);
    }

    fn first_exec_all<ET>(&self, emulator_tools: &mut EmulatorTools<ET, S>)
    where
        ET: EmulatorToolTuple<S>,
    {
        self.0.first_exec(emulator_tools);
        self.1.first_exec_all(emulator_tools);
    }

    fn pre_exec_all<ET>(&mut self, emulator_tools: &mut EmulatorTools<ET, S>, input: &S::Input)
    where
        ET: EmulatorToolTuple<S>,
    {
        self.0.pre_exec(emulator_tools, input);
        self.1.pre_exec_all(emulator_tools, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_tools: &mut EmulatorTools<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorToolTuple<S>,
    {
        self.0
            .post_exec(emulator_tools, input, observers, exit_kind);
        self.1
            .post_exec_all(emulator_tools, input, observers, exit_kind);
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
