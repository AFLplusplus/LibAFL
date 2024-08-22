use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, HasMetadata};
use libafl_qemu_sys::GuestAddr;
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
pub use libafl_targets::{
    edges_map_mut_ptr, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE_IN_USE, EDGES_MAP_SIZE_MAX,
    MAX_EDGES_FOUND,
};
use serde::{Deserialize, Serialize};

use crate::{
    emu::EmulatorModules,
    modules::{
        hash_me, AddressFilter, EmulatorModule, EmulatorModuleTuple, PageFilter, StdAddressFilter,
        StdPageFilter,
    },
    qemu::Hook,
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

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageModule {
    address_filter: StdAddressFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageModule {
    address_filter: StdAddressFilter,
    page_filter: StdPageFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: StdAddressFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter, page_filter: StdPageFilter) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: StdAddressFilter, page_filter: StdPageFilter) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageModule {
    fn default() -> Self {
        Self::new(AddressFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageModule {
    fn default() -> Self {
        Self::new(StdAddressFilter::default(), StdPageFilter::default())
    }
}

impl<S> EmulatorModule<S> for EdgeCoverageModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    type ModuleAddressFilter = StdAddressFilter;
    type ModulePageFilter = StdPageFilter;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if self.use_hitcounts {
            // emulator_modules.edges(
            //     Hook::Function(gen_unique_edge_ids::<ET, S>),
            //     Hook::Raw(trace_edge_hitcount),
            // );
            let hook_id =
                emulator_modules.edges(Hook::Function(gen_unique_edge_ids::<ET, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
                );
            }
        } else {
            // emulator_modules.edges(
            //     Hook::Function(gen_unique_edge_ids::<ET, S>),
            //     Hook::Raw(trace_edge_single),
            // );
            let hook_id =
                emulator_modules.edges(Hook::Function(gen_unique_edge_ids::<ET, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
                );
            }
        }
    }

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

pub type CollidingEdgeCoverageModule = EdgeCoverageChildModule;

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageChildModule {
    address_filter: StdAddressFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageChildModule {
    address_filter: StdAddressFilter,
    page_filter: StdPageFilter,
    use_hitcounts: bool,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageChildModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: StdAddressFilter) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageChildModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter, page_filter: StdPageFilter) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: true,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: StdAddressFilter, page_filter: StdPageFilter) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: false,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageChildModule {
    fn default() -> Self {
        Self::new(AddressFilter::None)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageChildModule {
    fn default() -> Self {
        Self::new(StdAddressFilter::default(), StdPageFilter::default())
    }
}

impl<S> EmulatorModule<S> for EdgeCoverageChildModule
where
    S: Unpin + UsesInput,
{
    type ModuleAddressFilter = StdAddressFilter;
    type ModulePageFilter = StdPageFilter;
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if self.use_hitcounts {
            emulator_modules.edges(
                Hook::Function(gen_hashed_edge_ids::<ET, S>),
                Hook::Raw(trace_edge_hitcount_ptr),
            );
        } else {
            emulator_modules.edges(
                Hook::Function(gen_hashed_edge_ids::<ET, S>),
                Hook::Raw(trace_edge_single_ptr),
            );
        }
    }

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

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct EdgeCoverageClassicModule {
    address_filter: StdAddressFilter,
    use_hitcounts: bool,
    use_jit: bool,
}

#[cfg(emulation_mode = "systemmode")]
#[derive(Debug)]
pub struct EdgeCoverageClassicModule {
    address_filter: StdAddressFilter,
    page_filter: StdPageFilter,
    use_hitcounts: bool,
    use_jit: bool,
}

#[cfg(emulation_mode = "usermode")]
impl EdgeCoverageClassicModule {
    #[must_use]
    pub fn new(address_filter: AddressFilter, use_jit: bool) -> Self {
        Self {
            address_filter,
            use_hitcounts: true,
            use_jit,
        }
    }

    #[must_use]
    pub fn without_hitcounts(address_filter: StdAddressFilter, use_jit: bool) -> Self {
        Self {
            address_filter,
            use_hitcounts: false,
            use_jit,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl EdgeCoverageClassicModule {
    #[must_use]
    pub fn new(
        address_filter: StdAddressFilter,
        page_filter: StdPageFilter,
        use_jit: bool,
    ) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: true,
            use_jit,
        }
    }

    #[must_use]
    pub fn without_hitcounts(
        address_filter: StdAddressFilter,
        page_filter: StdPageFilter,
        use_jit: bool,
    ) -> Self {
        Self {
            address_filter,
            page_filter,
            use_hitcounts: false,
            use_jit,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl Default for EdgeCoverageClassicModule {
    fn default() -> Self {
        Self::new(AddressFilter::None, true)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Default for EdgeCoverageClassicModule {
    fn default() -> Self {
        Self::new(StdAddressFilter::default(), StdPageFilter::default(), false)
    }
}

#[allow(clippy::collapsible_else_if)]
impl<S> EmulatorModule<S> for EdgeCoverageClassicModule
where
    S: Unpin + UsesInput,
{
    type ModuleAddressFilter = StdAddressFilter;
    type ModulePageFilter = StdPageFilter;

    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if self.use_hitcounts {
            if self.use_jit {
                let hook_id = emulator_modules.blocks(
                    Hook::Function(gen_hashed_block_ids::<ET, S>),
                    Hook::Empty,
                    Hook::Empty,
                );

                unsafe {
                    libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                        hook_id.0,
                        Some(libafl_qemu_sys::libafl_jit_trace_block_hitcount),
                    );
                }
            } else {
                emulator_modules.blocks(
                    Hook::Function(gen_hashed_block_ids::<ET, S>),
                    Hook::Empty,
                    Hook::Raw(trace_block_transition_hitcount),
                );
            }
        } else {
            if self.use_jit {
                let hook_id = emulator_modules.blocks(
                    Hook::Function(gen_hashed_block_ids::<ET, S>),
                    Hook::Empty,
                    Hook::Empty,
                );

                unsafe {
                    libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                        hook_id.0,
                        Some(libafl_qemu_sys::libafl_jit_trace_block_single),
                    );
                }
            } else {
                emulator_modules.blocks(
                    Hook::Function(gen_hashed_block_ids::<ET, S>),
                    Hook::Empty,
                    Hook::Raw(trace_block_transition_single),
                );
            }
        }
    }

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

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });

pub fn gen_unique_edge_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageModule>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(src) && !h.must_instrument(dest) {
                return None;
            }
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

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
            let nxt = (id as usize + 1) & (EDGES_MAP_SIZE_MAX - 1);
            unsafe {
                MAX_EDGES_FOUND = max(MAX_EDGES_FOUND, nxt);
            }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = (id + 1) & (EDGES_MAP_SIZE_MAX as u64 - 1);
            unsafe {
                MAX_EDGES_FOUND = meta.current_id as usize;
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

pub fn gen_hashed_edge_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageChildModule>() {
        #[cfg(emulation_mode = "usermode")]
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(src, paging_id) && !h.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }

    let id = hash_me(src as u64) ^ hash_me(dest as u64);
    let nxt = (id as usize + 1) & (EDGES_MAP_SIZE_MAX - 1);

    unsafe {
        MAX_EDGES_FOUND = nxt;
    }

    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(id)
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

pub fn gen_hashed_block_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageClassicModule>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(pc, paging_id) {
                return None;
            }
        }
    }

    let id = hash_me(pc as u64);
    let nxt = (id as usize + 1) & (EDGES_MAP_SIZE_MAX - 1);

    unsafe {
        MAX_EDGES_FOUND = nxt;
    }

    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(id)
}

pub extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_SIZE_MAX - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_SIZE_MAX - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}
