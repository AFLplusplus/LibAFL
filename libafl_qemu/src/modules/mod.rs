use core::{fmt::Debug, ops::Range};
use std::cell::UnsafeCell;

use hashbrown::HashSet;
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

#[cfg(emulation_mode = "usermode")]
pub mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[cfg(emulation_mode = "systemmode")]
pub mod systemmode;
#[cfg(emulation_mode = "systemmode")]
#[allow(unused_imports)]
pub use systemmode::*;

pub mod edges;
pub use edges::*;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::CallTracerModule;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::CmpLogModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;
#[cfg(not(cpu_target = "hexagon"))]
pub use drcov::*;

use crate::{emu::EmulatorModules, Qemu};

/// A module for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<S>: 'static + Debug
where
    S: UsesInput,
{
    type ModuleAddressFilter: AddressFilter;

    #[cfg(emulation_mode = "systemmode")]
    type ModulePageFilter: PageFilter;

    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Initialize the module, mostly used to install some hooks early.
    /// This is always run when Emulator gets initialized, in any case.
    /// Install here hooks that should be alive for the whole execution of the VM.
    fn init_module<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run once just before fuzzing starts.
    /// This call can be delayed to the point at which fuzzing is supposed to start.
    /// It is mostly used to avoid running hooks during VM initialization, either
    /// because it is useless or it would produce wrong results.
    fn first_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run before a new fuzzing run starts.
    /// On the first run, it is executed after [`Self::first_exec`].
    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run after a fuzzing run ends.
    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter;
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter;
    fn update_address_filter(&mut self, qemu: Qemu, filter: Self::ModuleAddressFilter) {
        *self.address_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
    }

    #[cfg(emulation_mode = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter;
    #[cfg(emulation_mode = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter;
    #[cfg(emulation_mode = "systemmode")]
    fn update_page_filter(&mut self, qemu: Qemu, filter: Self::ModulePageFilter) {
        *self.page_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
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

    fn first_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, state: &mut S)
    where
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>;

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>);

    #[cfg(emulation_mode = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr);
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

    fn first_exec_all<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn allow_address_range_all(&mut self, _address_range: Range<GuestAddr>) {}

    #[cfg(emulation_mode = "systemmode")]
    fn allow_page_id_all(&mut self, _page_id: GuestPhysAddr) {}
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

    fn first_exec_all<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.first_exec(emulator_modules, state);
        self.1.first_exec_all(emulator_modules, state);
    }

    fn pre_exec_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_exec(emulator_modules, state, input);
        self.1.pre_exec_all(emulator_modules, state, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.0
            .post_exec(emulator_modules, state, input, observers, exit_kind);
        self.1
            .post_exec_all(emulator_modules, state, input, observers, exit_kind);
    }

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>) {
        self.0.address_filter_mut().register(address_range.clone());
        self.1.allow_address_range_all(address_range);
    }

    #[cfg(emulation_mode = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr) {
        self.0.page_filter_mut().register(page_id.clone());
        self.1.allow_page_id_all(page_id)
    }
}

#[derive(Debug, Clone)]
pub enum FilterList<T> {
    AllowList(T),
    DenyList(T),
    None,
}

impl<T> AddressFilter for FilterList<T>
where
    T: AddressFilter,
{
    fn register(&mut self, address_range: Range<GuestAddr>) {
        match self {
            FilterList::AllowList(allow_list) => allow_list.register(address_range),
            FilterList::DenyList(deny_list) => deny_list.register(address_range),
            FilterList::None => {}
        }
    }

    fn allowed(&self, address: &GuestAddr) -> bool {
        match self {
            FilterList::AllowList(allow_list) => allow_list.allowed(address),
            FilterList::DenyList(deny_list) => !deny_list.allowed(address),
            FilterList::None => true,
        }
    }
}

impl<T> PageFilter for FilterList<T>
where
    T: PageFilter,
{
    fn register(&mut self, page_id: GuestPhysAddr) {
        match self {
            FilterList::AllowList(allow_list) => allow_list.register(page_id),
            FilterList::DenyList(deny_list) => deny_list.register(page_id),
            FilterList::None => {}
        }
    }

    fn allowed(&self, page: &GuestPhysAddr) -> bool {
        match self {
            FilterList::AllowList(allow_list) => allow_list.allowed(page),
            FilterList::DenyList(deny_list) => !deny_list.allowed(page),
            FilterList::None => true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AddressFilterVec {
    // ideally, we should use a tree
    registered_addresses: Vec<Range<GuestAddr>>,
}
#[derive(Clone, Debug)]
pub struct StdAddressFilter(FilterList<AddressFilterVec>);

impl Default for StdAddressFilter {
    fn default() -> Self {
        Self(FilterList::None)
    }
}

impl StdAddressFilter {
    #[must_use]
    pub fn allow_list(registered_addresses: Vec<Range<GuestAddr>>) -> Self {
        StdAddressFilter(FilterList::AllowList(AddressFilterVec::new(
            registered_addresses,
        )))
    }

    #[must_use]
    pub fn deny_list(registered_addresses: Vec<Range<GuestAddr>>) -> Self {
        StdAddressFilter(FilterList::DenyList(AddressFilterVec::new(
            registered_addresses,
        )))
    }
}

impl AddressFilterVec {
    #[must_use]
    pub fn new(registered_addresses: Vec<Range<GuestAddr>>) -> Self {
        Self {
            registered_addresses,
        }
    }
}

impl AddressFilter for AddressFilterVec {
    fn register(&mut self, address_range: Range<GuestAddr>) {
        self.registered_addresses.push(address_range);
        Qemu::get().unwrap().flush_jit();
    }

    fn allowed(&self, addr: &GuestAddr) -> bool {
        if self.registered_addresses.is_empty() {
            return true;
        }

        for addr_range in &self.registered_addresses {
            if addr_range.contains(addr) {
                return true;
            }
        }

        false
    }
}

impl AddressFilter for StdAddressFilter {
    fn register(&mut self, address_range: Range<GuestAddr>) {
        self.0.register(address_range);
    }

    fn allowed(&self, address: &GuestAddr) -> bool {
        self.0.allowed(address)
    }
}

#[derive(Clone, Debug)]
pub struct PageFilterVec {
    registered_pages: HashSet<GuestPhysAddr>,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Clone, Debug)]
pub struct StdPageFilter(FilterList<PageFilterVec>);

#[cfg(emulation_mode = "usermode")]
pub type StdPageFilter = NopPageFilter;

impl Default for PageFilterVec {
    fn default() -> Self {
        Self {
            registered_pages: HashSet::new(),
        }
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for StdPageFilter {
    fn default() -> Self {
        Self(FilterList::None)
    }
}

impl PageFilter for PageFilterVec {
    fn register(&mut self, page_id: GuestPhysAddr) {
        self.registered_pages.insert(page_id);
        Qemu::get().unwrap().flush_jit();
    }

    fn allowed(&self, paging_id: &GuestPhysAddr) -> bool {
        // if self.allowed_pages.is_empty() {
        //     return true;
        // }

        self.registered_pages.contains(paging_id)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl PageFilter for StdPageFilter {
    fn register(&mut self, page_id: GuestPhysAddr) {
        self.0.register(page_id);
    }

    fn allowed(&self, page_id: &GuestPhysAddr) -> bool {
        self.0.allowed(page_id)
    }
}

// adapted from https://xorshift.di.unimi.it/splitmix64.c
#[must_use]
pub fn hash_me(mut x: u64) -> u64 {
    x = (x ^ (x.overflowing_shr(30).0))
        .overflowing_mul(0xbf58476d1ce4e5b9)
        .0;
    x = (x ^ (x.overflowing_shr(27).0))
        .overflowing_mul(0x94d049bb133111eb)
        .0;
    x ^ (x.overflowing_shr(31).0)
}

pub trait AddressFilter: 'static + Debug {
    fn register(&mut self, address_range: Range<GuestAddr>);

    fn allowed(&self, address: &GuestAddr) -> bool;
}

#[derive(Debug)]
pub struct NopAddressFilter;
impl AddressFilter for NopAddressFilter {
    fn register(&mut self, _address: Range<GuestAddr>) {}

    fn allowed(&self, _address: &GuestAddr) -> bool {
        true
    }
}

pub trait PageFilter: 'static + Debug {
    fn register(&mut self, page_id: GuestPhysAddr);

    fn allowed(&self, page_id: &GuestPhysAddr) -> bool;
}

#[derive(Clone, Debug, Default)]
pub struct NopPageFilter;
impl PageFilter for NopPageFilter {
    fn register(&mut self, _page_id: GuestPhysAddr) {}

    fn allowed(&self, _page_id: &GuestPhysAddr) -> bool {
        true
    }
}

#[cfg(emulation_mode = "usermode")]
static mut NOP_ADDRESS_FILTER: UnsafeCell<NopAddressFilter> = UnsafeCell::new(NopAddressFilter);
#[cfg(emulation_mode = "systemmode")]
static mut NOP_PAGE_FILTER: UnsafeCell<NopPageFilter> = UnsafeCell::new(NopPageFilter);
