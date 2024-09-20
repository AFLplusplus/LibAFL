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
pub use edges::EdgeCoverageModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::CallTracerModule;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::CmpLogModule;

use crate::{emu::EmulatorModules, Qemu};

/// A module for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<S>: 'static + Debug
where
    S: UsesInput,
{
    type ModuleAddressFilter: AddressFilter;
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
    fn first_exec<ET>(&mut self, _state: &mut S, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run before a new fuzzing run starts.
    fn pre_exec<ET>(
        &mut self,
        _state: &mut S,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run after a fuzzing run ends.
    fn post_exec<OT, ET>(
        &mut self,
        _state: &mut S,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter;
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter;

    fn page_filter(&self) -> &Self::ModulePageFilter;
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter;
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

    fn first_exec_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>;

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>);

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
        _input: &S::Input,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _state: &mut S,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn allow_address_range_all(&mut self, _address_range: Range<GuestAddr>) {}

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
        self.0.first_exec(state, emulator_modules);
        self.1.first_exec_all(emulator_modules, state);
    }

    fn pre_exec_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_exec(state, emulator_modules, input);
        self.1.pre_exec_all(emulator_modules, input, state);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        input: &S::Input,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.0
            .post_exec(state, emulator_modules, input, observers, exit_kind);
        self.1
            .post_exec_all(emulator_modules, input, observers, state, exit_kind);
    }

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>) {
        self.0.address_filter_mut().allow(address_range.clone());
        self.1.allow_address_range_all(address_range)
    }

    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr) {
        self.0.page_filter_mut().allow(page_id.clone());
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
    fn allow(&mut self, address_range: Range<GuestAddr>) {
        match self {
            FilterList::AllowList(allow_list) => allow_list.allow(address_range),
            FilterList::DenyList(_deny_list) => {
                todo!()
            }
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
    fn allow(&mut self, page_id: GuestPhysAddr) {
        match self {
            FilterList::AllowList(allow_list) => allow_list.allow(page_id),
            FilterList::DenyList(_deny_list) => {
                todo!()
            }
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

#[derive(Clone, Debug)]
pub struct StdAddressFilter {
    // ideally, we should use a tree
    allowed_addresses: Vec<Range<GuestAddr>>,
}

impl Default for StdAddressFilter {
    fn default() -> Self {
        Self {
            allowed_addresses: Vec::new(),
        }
    }
}

impl AddressFilter for StdAddressFilter {
    fn allow(&mut self, address_range: Range<GuestAddr>) {
        self.allowed_addresses.push(address_range);
        Qemu::get().unwrap().flush_jit()
    }

    fn allowed(&self, addr: &GuestAddr) -> bool {
        if self.allowed_addresses.is_empty() {
            return true;
        }

        for addr_range in &self.allowed_addresses {
            if addr_range.contains(addr) {
                return true;
            }
        }

        false
    }
}

#[derive(Clone, Debug)]
pub struct StdPageFilter {
    allowed_pages: HashSet<GuestPhysAddr>,
}

impl Default for StdPageFilter {
    fn default() -> Self {
        Self {
            allowed_pages: HashSet::new(),
        }
    }
}

impl PageFilter for StdPageFilter {
    fn allow(&mut self, page_id: GuestPhysAddr) {
        self.allowed_pages.insert(page_id);
        Qemu::get().unwrap().flush_jit()
    }

    fn allowed(&self, paging_id: &GuestPhysAddr) -> bool {
        // if self.allowed_pages.is_empty() {
        //     return true;
        // }

        self.allowed_pages.contains(paging_id)
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
    fn allow(&mut self, address_range: Range<GuestAddr>);

    fn allowed(&self, address: &GuestAddr) -> bool;
}

#[derive(Debug)]
pub struct NopAddressFilter;
impl AddressFilter for NopAddressFilter {
    fn allow(&mut self, _address: Range<GuestAddr>) {}

    fn allowed(&self, _address: &GuestAddr) -> bool {
        true
    }
}

pub trait PageFilter: 'static + Debug {
    fn allow(&mut self, page_id: GuestPhysAddr);

    fn allowed(&self, page_id: &GuestPhysAddr) -> bool;
}

#[derive(Debug)]
pub struct NopPageFilter;
impl PageFilter for NopPageFilter {
    fn allow(&mut self, _page_id: GuestPhysAddr) {}

    fn allowed(&self, _page_id: &GuestPhysAddr) -> bool {
        true
    }
}

// static mut NOP_ADDRESS_FILTER: UnsafeCell<NopAddressFilter> =
//      UnsafeCell::new(NopAddressFilter);
static mut NOP_PAGE_FILTER: UnsafeCell<NopPageFilter> = UnsafeCell::new(NopPageFilter);
