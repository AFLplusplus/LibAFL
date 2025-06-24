use std::fmt::Debug;

use libafl::{HasMetadata, observers::VarLenMapObserver};
use libafl_bolts::Error;
use libafl_qemu_sys::GuestAddr;
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;

use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{AddressFilter, EmulatorModule, EmulatorModuleTuple, PageFilter},
};

mod helpers;
use helpers::{
    LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE, LIBAFL_QEMU_EDGES_MAP_MASK_MAX,
    LIBAFL_QEMU_EDGES_MAP_PTR, LIBAFL_QEMU_EDGES_MAP_SIZE_PTR,
};

pub mod full;
pub use full::{
    EdgeCoverageFullVariant, StdEdgeCoverageFullModule, StdEdgeCoverageFullModuleBuilder,
};

pub mod classic;
pub use classic::{
    EdgeCoverageClassicVariant, StdEdgeCoverageClassicModule, StdEdgeCoverageClassicModuleBuilder,
};

pub mod child;
pub use child::{
    EdgeCoverageChildVariant, StdEdgeCoverageChildModule, StdEdgeCoverageChildModuleBuilder,
};
use libafl::observers::ConstLenMapObserver;

use super::utils::filters::HasAddressFilter;
#[cfg(feature = "systemmode")]
use super::utils::filters::HasPageFilter;

/// Standard edge coverage module, adapted to most use cases
pub type StdEdgeCoverageModule = StdEdgeCoverageFullModule;

/// Standard edge coverage module builder, adapted to most use cases
pub type StdEdgeCoverageModuleBuilder = StdEdgeCoverageFullModuleBuilder;

pub type CollidingEdgeCoverageModule<AF, PF, const IS_CONST_MAP: bool, const MAP_SIZE: usize> =
    EdgeCoverageModule<AF, PF, EdgeCoverageChildVariant, IS_CONST_MAP, MAP_SIZE>;

/// An edge coverage module variant.
trait EdgeCoverageVariant<AF, PF, const IS_CONST_MAP: bool, const MAP_SIZE: usize>:
    'static + Debug
{
    const DO_SIDE_EFFECTS: bool = true;

    fn jit_hitcount<ET, I, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        panic!("JIT hitcount is not supported.")
    }

    fn jit_no_hitcount<ET, I, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        panic!("JIT no hitcount is not supported.")
    }

    fn fn_hitcount<ET, I, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        panic!("Func hitcount is not supported.")
    }

    fn fn_no_hitcount<ET, I, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        panic!("Func no hitcount is not supported.")
    }
}

#[derive(Debug)]
pub struct EdgeCoverageModuleBuilder<
    AF,
    PF,
    V,
    const IS_INITIALIZED: bool,
    const IS_CONST_MAP: bool,
    const MAP_SIZE: usize,
> {
    variant: V,
    address_filter: AF,
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
}

#[derive(Debug)]
pub struct EdgeCoverageModule<AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize> {
    variant: V,
    address_filter: AF,
    // we only use it in system mode at the moment.
    #[cfg_attr(not(feature = "systemmode"), allow(dead_code))]
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
}

impl<AF, PF, V, const IS_INITIALIZED: bool, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE>
{
    pub fn build(self) -> Result<EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>, Error> {
        const {
            assert!(
                IS_INITIALIZED,
                "The edge module builder must be first initialized with a call to `map_observer`."
            );
        };

        Ok(EdgeCoverageModule::new(
            self.address_filter,
            self.page_filter,
            self.variant,
            self.use_hitcounts,
            self.use_jit,
        ))
    }
}

impl<AF, PF, V, const IS_INITIALIZED: bool, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE>
{
    fn new(
        variant: V,
        address_filter: AF,
        page_filter: PF,
        use_hitcounts: bool,
        use_jit: bool,
    ) -> Self {
        Self {
            variant,
            address_filter,
            page_filter,
            use_hitcounts,
            use_jit,
        }
    }

    #[must_use]
    pub fn map_observer<O>(
        self,
        map_observer: &mut O,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, true, false, 0>
    where
        O: VarLenMapObserver,
    {
        let map_ptr = map_observer.map_slice_mut().as_mut_ptr() as *mut u8;
        let map_max_size = map_observer.map_slice_mut().len();
        let size_ptr = map_observer.as_mut().size_mut() as *mut usize;

        unsafe {
            LIBAFL_QEMU_EDGES_MAP_PTR = map_ptr;
            LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = size_ptr;
            LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE = map_max_size;
            LIBAFL_QEMU_EDGES_MAP_MASK_MAX = map_max_size - 1;
        }

        EdgeCoverageModuleBuilder::<AF, PF, V, true, false, 0>::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    #[must_use]
    pub fn const_map_observer<O, const NEW_MAP_SIZE: usize>(
        self,
        map_observer: &mut O,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, true, true, NEW_MAP_SIZE>
    where
        O: ConstLenMapObserver<NEW_MAP_SIZE>,
    {
        let map_ptr = map_observer.map_slice_mut().as_mut_ptr() as *mut u8;

        unsafe {
            LIBAFL_QEMU_EDGES_MAP_PTR = map_ptr;
            // LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = size_ptr; do i need this ?
            LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE = NEW_MAP_SIZE;
            LIBAFL_QEMU_EDGES_MAP_MASK_MAX = NEW_MAP_SIZE - 1;
        }

        EdgeCoverageModuleBuilder::<AF, PF, V, true, true, NEW_MAP_SIZE>::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn variant<V2>(
        self,
        variant: V2,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V2, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE> {
        EdgeCoverageModuleBuilder::new(
            variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn address_filter<AF2>(
        self,
        address_filter: AF2,
    ) -> EdgeCoverageModuleBuilder<AF2, PF, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn page_filter<PF2>(
        self,
        page_filter: PF2,
    ) -> EdgeCoverageModuleBuilder<AF, PF2, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    #[must_use]
    pub fn hitcounts(
        self,
        use_hitcounts: bool,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            use_hitcounts,
            self.use_jit,
        )
    }

    #[must_use]
    pub fn jit(
        self,
        use_jit: bool,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED, IS_CONST_MAP, MAP_SIZE> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            use_jit,
        )
    }
}

impl<AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>
{
    #[must_use]
    pub fn new(
        address_filter: AF,
        page_filter: PF,
        variant: V,
        use_hitcounts: bool,
        use_jit: bool,
    ) -> Self {
        Self {
            variant,
            address_filter,
            page_filter,
            use_hitcounts,
            use_jit,
        }
    }
}

impl<AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>
where
    AF: AddressFilter,
    PF: PageFilter,
{
    #[cfg(feature = "usermode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }

    #[cfg(feature = "systemmode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

impl<I, S, AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize> EmulatorModule<I, S>
    for EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>
where
    AF: AddressFilter + 'static,
    PF: PageFilter + 'static,
    I: Unpin,
    S: Unpin + HasMetadata,
    V: EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE> + 'static,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = V::DO_SIDE_EFFECTS;

    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.use_hitcounts {
            if self.use_jit {
                self.variant.jit_hitcount(emulator_modules);
            } else {
                self.variant.fn_hitcount(emulator_modules);
            }
        } else if self.use_jit {
            self.variant.jit_no_hitcount(emulator_modules);
        } else {
            self.variant.fn_no_hitcount(emulator_modules);
        }
    }
}

impl<AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize> HasAddressFilter
    for EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>
where
    AF: AddressFilter,
{
    type AddressFilter = AF;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.address_filter
    }
}

#[cfg(feature = "systemmode")]
impl<AF, PF, V, const IS_CONST_MAP: bool, const MAP_SIZE: usize> HasPageFilter
    for EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>
where
    PF: PageFilter,
{
    type PageFilter = PF;

    fn page_filter(&self) -> &Self::PageFilter {
        &self.page_filter
    }

    fn page_filter_mut(&mut self) -> &mut Self::PageFilter {
        &mut self.page_filter
    }
}

#[cfg(any(test, doc))]
mod tests {

    use libafl::observers::{CanTrack, HitcountsMapObserver, VariableMapObserver};
    use libafl_bolts::ownedref::OwnedMutSlice;
    use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};

    use crate::modules::StdEdgeCoverageModule;

    /// The test is actually implemented as a doctest, since Rust does not
    /// permit tests that must not compile by default...
    ///
    /// ```compile_fail
    /// use libafl_qemu::modules::StdEdgeCoverageModule;
    ///
    /// StdEdgeCoverageModule::builder().build().unwrap();
    /// ```
    #[expect(unused)]
    pub fn does_not_build() {}

    #[test]
    pub fn does_build() {
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()
            .unwrap();
    }
}
