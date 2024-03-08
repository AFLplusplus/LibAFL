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
        hash_me, HasInstrumentationFilter, QemuHelper, QemuHelperTuple,
        QemuInstrumentationAddressRangeFilter,
    },
    hooks::{Hook, QemuHooks},
    IsFilter,
};
#[cfg(emulation_mode = "systemmode")]
use crate::{helper::QemuInstrumentationPagingFilter, GuestPhysAddr};

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

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl QemuEdgeCoverageHelper {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl QemuEdgeCoverageHelper {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for QemuEdgeCoverageHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for QemuEdgeCoverageHelper {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for QemuEdgeCoverageHelper {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for QemuEdgeCoverageHelper {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
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

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageChildHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageChildHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl QemuEdgeCoverageChildHelper {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl QemuEdgeCoverageChildHelper {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for QemuEdgeCoverageChildHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for QemuEdgeCoverageChildHelper {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
    for QemuEdgeCoverageChildHelper
{
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for QemuEdgeCoverageChildHelper {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
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

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageClassicHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct QemuEdgeCoverageClassicHelper {
    address_filter: QemuInstrumentationAddressRangeFilter,
    paging_filter: QemuInstrumentationPagingFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl QemuEdgeCoverageClassicHelper {
    #[must_use]
    pub fn new(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: QemuInstrumentationAddressRangeFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl QemuEdgeCoverageClassicHelper {
    #[must_use]
    pub fn new(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: QemuInstrumentationAddressRangeFilter,
        paging_filter: QemuInstrumentationPagingFilter,
    ) -> Self {
        Self {
            address_filter,
            paging_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, paging_id: Option<GuestPhysAddr>) -> bool {
        self.address_filter.allowed(addr) && self.paging_filter.allowed(paging_id)
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for QemuEdgeCoverageClassicHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationAddressRangeFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for QemuEdgeCoverageClassicHelper {
    fn default() -> Self {
        Self::new(
            QemuInstrumentationAddressRangeFilter::None,
            QemuInstrumentationPagingFilter::None,
        )
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
    for QemuEdgeCoverageClassicHelper
{
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.address_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.address_filter
    }
}

#[cfg(emulation_mode = "systemmode")]
impl HasInstrumentationFilter<QemuInstrumentationPagingFilter> for QemuEdgeCoverageClassicHelper {
    fn filter(&self) -> &QemuInstrumentationPagingFilter {
        &self.paging_filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationPagingFilter {
        &mut self.paging_filter
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

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });

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
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(src) && !h.must_instrument(dest) {
                return None;
            }
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = hooks
                .emulator()
                .current_cpu()
                .map(|cpu| cpu.get_current_paging_id())
                .flatten();

            if !h.must_instrument(src, paging_id) && !h.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    let meta = state.metadata_or_insert_with(QemuEdgesMapMetadata::new);

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
        #[cfg(emulation_mode = "usermode")]
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = hooks
                .emulator()
                .current_cpu()
                .map(|cpu| cpu.get_current_paging_id())
                .flatten();

            if !h.must_instrument(src, paging_id) && !h.must_instrument(dest, paging_id) {
                return None;
            }
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
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = hooks
                .emulator()
                .current_cpu()
                .map(|cpu| cpu.get_current_paging_id())
                .flatten();

            if !h.must_instrument(pc, paging_id) {
                return None;
            }
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
