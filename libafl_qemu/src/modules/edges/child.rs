use libafl::{inputs::UsesInput, HasMetadata};

use super::{
    helpers::{gen_hashed_edge_ids, trace_edge_hitcount_ptr, trace_edge_single_ptr},
    EdgeCoverageVariant,
};
use crate::{
    modules::{
        AddressFilter, EdgeCoverageModule, EdgeCoverageModuleBuilder, EmulatorModuleTuple,
        PageFilter, StdAddressFilter, StdPageFilter,
    },
    EmulatorModules, Hook,
};

#[derive(Debug)]
pub struct EdgeCoverageChildVariant;
pub type StdEdgeCoverageChildModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageChildVariant>;
pub type StdEdgeCoverageChildModuleBuilder =
    EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageChildVariant, false>;

impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageChildVariant {
    const DO_SIDE_EFFECTS: bool = false;

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_hashed_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_hitcount_ptr),
        );
    }

    fn fn_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_hashed_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_single_ptr),
        );
    }
}

impl Default for StdEdgeCoverageChildModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageChildVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
        }
    }
}

impl StdEdgeCoverageChildModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageChildModuleBuilder {
        EdgeCoverageModuleBuilder::default().jit(false)
    }
}
