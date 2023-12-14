use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, state::HasMetadata};
pub use libafl_targets::{
    edges_map_mut_ptr, edges_map_mut_slice, edges_max_num, std_edges_map_observer, EDGES_MAP,
    EDGES_MAP_PTR, EDGES_MAP_PTR_NUM, EDGES_MAP_SIZE, MAX_EDGES_NUM,
};
use serde::{Deserialize, Serialize};

use crate::{
    emu::GuestAddr,
    helper::{
        hash_me, HasInstrumentationFilter, QemuHelper, QemuHelperTuple, QemuInstrumentationFilter,
    },
    hooks::{Hook, QemuHooks},
};

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(GuestAddr, GuestAddr), u64>,
    pub current_id: u64,
}

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

#[derive(Debug)]
pub struct QemuEdgeCoverageHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
}

impl QemuEdgeCoverageHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuEdgeCoverageHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageHelper
where
    S: UsesInput + HasMetadata,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            // hooks.edges(
            //     Hook::Function(gen_unique_edge_ids::<QT, S>),
            //     Hook::Raw(trace_edge_hitcount),
            // );
            let hook_id = hooks.edges(Hook::Function(gen_unique_edge_ids::<QT, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
                );
            }
        } else {
            // hooks.edges(
            //     Hook::Function(gen_unique_edge_ids::<QT, S>),
            //     Hook::Raw(trace_edge_single),
            // );
            let hook_id = hooks.edges(Hook::Function(gen_unique_edge_ids::<QT, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
                );
            }
        }
    }
}

pub type QemuCollidingEdgeCoverageHelper = QemuEdgeCoverageChildHelper;

#[derive(Debug)]
pub struct QemuEdgeCoverageChildHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
}

impl QemuEdgeCoverageChildHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuEdgeCoverageChildHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageChildHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageChildHelper
where
    S: UsesInput,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            hooks.edges(
                Hook::Function(gen_hashed_edge_ids::<QT, S>),
                Hook::Raw(trace_edge_hitcount_ptr),
            );
        } else {
            hooks.edges(
                Hook::Function(gen_hashed_edge_ids::<QT, S>),
                Hook::Raw(trace_edge_single_ptr),
            );
        }
    }
}

#[derive(Debug)]
pub struct QemuEdgeCoverageClassicHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
}

impl QemuEdgeCoverageClassicHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuEdgeCoverageClassicHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageClassicHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageClassicHelper
where
    S: UsesInput,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            hooks.blocks(
                Hook::Function(gen_hashed_block_ids::<QT, S>),
                Hook::Empty,
                Hook::Raw(trace_block_transition_hitcount),
            );
        } else {
            hooks.blocks(
                Hook::Function(gen_hashed_block_ids::<QT, S>),
                Hook::Empty,
                Hook::Raw(trace_block_transition_single),
            );
        }
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = UnsafeCell::new(0));

pub fn gen_unique_edge_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks.helpers().match_first_type::<QemuEdgeCoverageHelper>() {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    if state.metadata_map().get::<QemuEdgesMapMetadata>().is_none() {
        state.add_metadata(QemuEdgesMapMetadata::new());
    }
    let meta = state
        .metadata_map_mut()
        .get_mut::<QemuEdgesMapMetadata>()
        .unwrap();

    match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            let nxt = (id as usize + 1) & (EDGES_MAP_SIZE - 1);
            unsafe {
                MAX_EDGES_NUM = max(MAX_EDGES_NUM, nxt);
            }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = (id + 1) & (EDGES_MAP_SIZE as u64 - 1);
            unsafe {
                MAX_EDGES_NUM = meta.current_id as usize;
            }
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

pub extern "C" fn trace_edge_hitcount(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub fn gen_hashed_edge_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks
        .helpers()
        .match_first_type::<QemuEdgeCoverageChildHelper>()
    {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some((hash_me(src as u64) ^ hash_me(dest as u64)) & (unsafe { EDGES_MAP_PTR_NUM } as u64 - 1))
}

pub extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

/*
pub fn gen_addr_block_ids<QT, S>(
    _hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(pc as u64)
}
*/

pub fn gen_hashed_block_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks
        .helpers()
        .match_first_type::<QemuEdgeCoverageClassicHelper>()
    {
        if !h.must_instrument(pc) {
            return None;
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(hash_me(pc as u64))
}

pub extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_NUM - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_NUM - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}
