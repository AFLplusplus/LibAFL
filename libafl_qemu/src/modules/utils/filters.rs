//! Helpers to get filtering for modules
//!
//! It is not a module by itself, but instead used as helper to have filters
//! in other modules.

use std::{cell::UnsafeCell, fmt::Debug, ops::Range};

use hashbrown::HashSet;
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

use crate::Qemu;

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

#[cfg(feature = "systemmode")]
#[derive(Clone, Debug)]
pub struct StdPageFilter(FilterList<PageFilterVec>);

#[cfg(feature = "usermode")]
pub type StdPageFilter = NopPageFilter;

impl Default for PageFilterVec {
    fn default() -> Self {
        Self {
            registered_pages: HashSet::new(),
        }
    }
}

#[cfg(feature = "systemmode")]
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

#[cfg(feature = "systemmode")]
impl PageFilter for StdPageFilter {
    fn register(&mut self, page_id: GuestPhysAddr) {
        self.0.register(page_id);
    }

    fn allowed(&self, page_id: &GuestPhysAddr) -> bool {
        self.0.allowed(page_id)
    }
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

#[cfg(feature = "usermode")]
pub(crate) static mut NOP_ADDRESS_FILTER: UnsafeCell<NopAddressFilter> =
    UnsafeCell::new(NopAddressFilter);
#[cfg(feature = "systemmode")]
pub(crate) static mut NOP_PAGE_FILTER: UnsafeCell<NopPageFilter> = UnsafeCell::new(NopPageFilter);
