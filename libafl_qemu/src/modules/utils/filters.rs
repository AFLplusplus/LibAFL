//! Helpers to get filtering for modules
//!
//! It is not a module by itself, but instead used as helper to have filters
//! in other modules.

use std::{cell::UnsafeCell, fmt::Debug, ops::Range};

use hashbrown::HashSet;
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr};

use crate::Qemu;

// TODO: make a better arch-specific / os-specific system. only works for x86_64 for now.
#[cfg(feature = "x86_64")]
pub const LINUX_PROCESS_ADDRESS_RANGE: Range<u64> = 0..0x0000_7fff_ffff_ffff;
#[cfg(feature = "x86_64")]
pub const LINUX_KERNEL_ADDRESS_RANGE: Range<u64> = 0xFFFFFFFF80000000..0xFFFFFFFF9FFFFFFF;

/// Generic Filter that can be:
/// - an allow list: allow nothing but the given list
/// - a deny list: allow anything but the given list
/// - none: allow everything (no filtering applied)
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

/// Offers accessors to modules' address filters.
pub trait HasAddressFilter {
    type ModuleAddressFilter: AddressFilter;
    #[cfg(feature = "systemmode")]
    type ModulePageFilter: PageFilter;
    fn address_filter(&self) -> &Self::ModuleAddressFilter;

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter;

    fn update_address_filter(&mut self, qemu: Qemu, filter: Self::ModuleAddressFilter) {
        *self.address_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
    }

    #[cfg(feature = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter;
    #[cfg(feature = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter;
    #[cfg(feature = "systemmode")]
    fn update_page_filter(&mut self, qemu: Qemu, filter: Self::ModulePageFilter) {
        *self.page_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
    }
}

pub trait HasAddressFilterTuples {
    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>);

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr);
}

impl HasAddressFilterTuples for () {
    fn allow_address_range_all(&mut self, _address_range: Range<GuestAddr>) {}

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, _page_id: GuestPhysAddr) {}
}

impl<Head, Tail> HasAddressFilterTuples for (Head, Tail)
where
    Head: HasAddressFilter,
    Tail: HasAddressFilterTuples,
{
    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>) {
        self.0.address_filter_mut().register(address_range.clone());
        self.1.allow_address_range_all(address_range);
    }

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr) {
        self.0.page_filter_mut().register(page_id);
        self.1.allow_page_id_all(page_id);
    }
}

/// An address filter list.
///
/// It will allow anything in the registered ranges, and deny anything else.
/// If there is no range registered, it will allow anything.
#[derive(Clone, Debug, Default)]
pub struct AddressFilterVec {
    // ideally, we should use a tree
    registered_addresses: Vec<Range<GuestAddr>>,
}

#[derive(Clone, Debug)]
pub struct StdAddressFilter(FilterList<AddressFilterVec>);

impl Default for StdAddressFilter {
    fn default() -> Self {
        Self::allow_list(Vec::new())
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

        if let Some(qemu) = Qemu::get() {
            qemu.flush_jit();
        }
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

/// A page filter list.
///
/// It will allow anything in the registered pages, and deny anything else.
/// If there is no page registered, it will allow anything.
#[derive(Clone, Debug)]
pub struct PageFilterVec {
    registered_pages: HashSet<GuestPhysAddr>,
}

#[cfg(feature = "systemmode")]
#[derive(Clone, Debug)]
pub struct StdPageFilter(FilterList<PageFilterVec>);

#[cfg(feature = "usermode")]
pub type StdPageFilter = NopPageFilter;

#[cfg(feature = "systemmode")]
impl StdPageFilter {
    #[must_use]
    pub fn allow_list(registered_pages: PageFilterVec) -> Self {
        StdPageFilter(FilterList::AllowList(registered_pages))
    }

    #[must_use]
    pub fn deny_list(registered_pages: PageFilterVec) -> Self {
        StdPageFilter(FilterList::DenyList(registered_pages))
    }
}

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
        Self::allow_list(PageFilterVec::default())
    }
}

impl PageFilter for PageFilterVec {
    fn register(&mut self, page_id: GuestPhysAddr) {
        self.registered_pages.insert(page_id);

        if let Some(qemu) = Qemu::get() {
            qemu.flush_jit();
        }
    }

    fn allowed(&self, paging_id: &GuestPhysAddr) -> bool {
        if self.registered_pages.is_empty() {
            return true;
        }

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
#[allow(dead_code)]
pub(crate) static mut NOP_ADDRESS_FILTER: UnsafeCell<NopAddressFilter> =
    UnsafeCell::new(NopAddressFilter);
#[cfg(feature = "systemmode")]
pub(crate) static mut NOP_PAGE_FILTER: UnsafeCell<NopPageFilter> = UnsafeCell::new(NopPageFilter);

#[cfg(all(feature = "systemmode", test))]
mod tests {
    use libafl::{inputs::NopInput, state::NopState, HasMetadata};
    use libafl_bolts::tuples::tuple_list;

    use crate::modules::{
        utils::filters::{
            AddressFilter, NopAddressFilter, NopPageFilter, PageFilter, StdAddressFilter,
            StdPageFilter,
        },
        EmulatorModule, EmulatorModuleTuple,
    };

    #[derive(Clone, Debug)]
    struct DummyModule<AF, PF> {
        address_filter: AF,
        page_filter: PF,
    }

    impl<I, S, AF, PF> EmulatorModule<I, S> for DummyModule<AF, PF>
    where
        AF: AddressFilter + 'static,
        PF: PageFilter + 'static,
        I: Unpin,
        S: Unpin + HasMetadata,
    {
        type ModuleAddressFilter = AF;
        type ModulePageFilter = PF;

        fn address_filter(&self) -> &Self::ModuleAddressFilter {
            &self.address_filter
        }

        fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
            &mut self.address_filter
        }

        fn page_filter(&self) -> &Self::ModulePageFilter {
            &self.page_filter
        }

        fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
            &mut self.page_filter
        }
    }

    fn gen_module<AF, PF, I, S>(
        af: AF,
        pf: PF,
    ) -> impl EmulatorModule<I, S, ModuleAddressFilter = AF, ModulePageFilter = PF>
    where
        AF: AddressFilter,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        DummyModule {
            address_filter: af,
            page_filter: pf,
        }
    }

    macro_rules! test_module {
        ($modules:ident, $Id:tt) => {
            assert!($modules.$Id.address_filter().allowed(&0x100));
            assert!($modules.$Id.address_filter().allowed(&0x101));
            assert!($modules.$Id.address_filter().allowed(&0x1ff));
            assert!($modules.$Id.address_filter().allowed(&0x301));

            assert!(!$modules.$Id.address_filter().allowed(&0xff));
            assert!(!$modules.$Id.address_filter().allowed(&0x200));
            assert!(!$modules.$Id.address_filter().allowed(&0x201));

            assert!($modules.$Id.page_filter().allowed(&0xaaaa));
            assert!($modules.$Id.page_filter().allowed(&0xbbbb));

            assert!(!$modules.$Id.page_filter().allowed(&0xcccc));
        };
    }

    #[test]
    fn test_filter_nop() {
        let module = gen_module::<NopAddressFilter, NopPageFilter, NopState<NopInput>>(
            NopAddressFilter,
            NopPageFilter,
        );
        let mut modules = tuple_list!(module);

        modules.allow_address_range_all(0x100..0x200);
        modules.allow_address_range_all(0x300..0x400);

        modules.allow_page_id_all(0xaaaa);
        modules.allow_page_id_all(0xbbbb);

        assert!(modules.0.address_filter().allowed(&0xff));
        assert!(modules.0.address_filter().allowed(&0x200));
        assert!(modules.0.address_filter().allowed(&0x201));
        assert!(modules.0.address_filter().allowed(&0x300));

        assert!(modules.0.page_filter().allowed(&0xaaaa));
        assert!(modules.0.page_filter().allowed(&0xbbbb));
        assert!(modules.0.page_filter().allowed(&0xcccc));
    }

    #[test]
    fn test_filters_simple() {
        let module = gen_module::<StdAddressFilter, StdPageFilter, NopState<NopInput>>(
            StdAddressFilter::default(),
            StdPageFilter::default(),
        );
        let mut modules = tuple_list!(module);

        assert!(modules.0.address_filter().allowed(&0x000));
        assert!(modules.0.address_filter().allowed(&0x100));
        assert!(modules.0.address_filter().allowed(&0x200));
        assert!(modules.0.address_filter().allowed(&0xffffffff));

        assert!(modules.0.page_filter().allowed(&0xabcd));

        modules.allow_address_range_all(0x100..0x200);
        modules.allow_address_range_all(0x300..0x400);

        modules.allow_page_id_all(0xaaaa);
        modules.allow_page_id_all(0xbbbb);

        assert!(modules.0.address_filter().allowed(&0x100));
        assert!(modules.0.address_filter().allowed(&0x101));
        assert!(modules.0.address_filter().allowed(&0x1ff));
        assert!(modules.0.address_filter().allowed(&0x301));

        assert!(!modules.0.address_filter().allowed(&0xff));
        assert!(!modules.0.address_filter().allowed(&0x200));
        assert!(!modules.0.address_filter().allowed(&0x201));

        assert!(modules.0.page_filter().allowed(&0xaaaa));
        assert!(modules.0.page_filter().allowed(&0xbbbb));

        assert!(!modules.0.page_filter().allowed(&0xcccc));
    }

    #[test]
    fn test_filters_multiple() {
        let module1 = gen_module::<StdAddressFilter, StdPageFilter, NopState<NopInput>>(
            StdAddressFilter::default(),
            StdPageFilter::default(),
        );
        let module2 = gen_module::<StdAddressFilter, StdPageFilter, NopState<NopInput>>(
            StdAddressFilter::default(),
            StdPageFilter::default(),
        );
        let module3 = gen_module::<StdAddressFilter, StdPageFilter, NopState<NopInput>>(
            StdAddressFilter::default(),
            StdPageFilter::default(),
        );
        let mut modules = tuple_list!(module1, module2, module3);

        modules.allow_address_range_all(0x100..0x200);
        modules.allow_address_range_all(0x300..0x400);

        modules.allow_page_id_all(0xaaaa);
        modules.allow_page_id_all(0xbbbb);

        test_module!(modules, 0);
    }
}
