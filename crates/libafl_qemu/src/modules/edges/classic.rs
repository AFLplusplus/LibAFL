use libafl::HasMetadata;

use super::{
    EdgeCoverageVariant,
    helpers::{
        gen_hashed_block_ids, trace_block_transition_hitcount, trace_block_transition_single,
    },
};
use crate::{
    EmulatorModules, Hook,
    modules::{
        AddressFilter, EdgeCoverageModule, EdgeCoverageModuleBuilder, EmulatorModuleTuple,
        PageFilter,
        utils::filters::{StdAddressFilter, StdPageFilter},
    },
};

#[derive(Debug)]
pub struct EdgeCoverageClassicVariant;

pub type StdEdgeCoverageClassicModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageClassicVariant, false, 0>;
pub type StdEdgeCoverageClassicModuleBuilder = EdgeCoverageModuleBuilder<
    StdAddressFilter,
    StdPageFilter,
    EdgeCoverageClassicVariant,
    false,
    false,
    0,
>;

impl<AF, PF, const IS_CONST_MAP: bool, const MAP_SIZE: usize>
    EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE> for EdgeCoverageClassicVariant
{
    const DO_SIDE_EFFECTS: bool = false;

    fn jit_hitcount<ET, I, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
            Hook::Empty,
        );

        unsafe {
            libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_block_hitcount),
            );
        }
    }

    fn jit_no_hitcount<ET, I, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
            Hook::Empty,
        );

        unsafe {
            libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_block_single),
            );
        }
    }

    fn fn_hitcount<ET, I, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_hitcount),
        );
    }

    fn fn_no_hitcount<ET, I, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_single),
        );
    }
}

impl Default for StdEdgeCoverageClassicModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageClassicVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
        }
    }
}

impl StdEdgeCoverageClassicModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageClassicModuleBuilder {
        EdgeCoverageModuleBuilder::default()
    }
}
