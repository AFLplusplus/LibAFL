use libafl::{inputs::UsesInput, HasMetadata};

use super::{
    helpers::{gen_unique_edge_ids, trace_edge_hitcount, trace_edge_single},
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
pub struct EdgeCoverageFullVariant;

pub type StdEdgeCoverageFullModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant, false, 0>;
pub type StdEdgeCoverageFullModuleBuilder = EdgeCoverageModuleBuilder<
    StdAddressFilter,
    StdPageFilter,
    EdgeCoverageFullVariant,
    false,
    false,
    0,
>;

impl<AF, PF, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE> for EdgeCoverageFullVariant
{
    fn jit_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
        );
        unsafe {
            libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
            );
        }
    }

    fn jit_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
        );
        unsafe {
            libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
            );
        }
    }

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Raw(trace_edge_hitcount),
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
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Raw(trace_edge_single),
        );
    }
}

impl Default for StdEdgeCoverageFullModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageFullVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
        }
    }
}

impl StdEdgeCoverageFullModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageFullModuleBuilder {
        EdgeCoverageModuleBuilder::default()
    }
}
