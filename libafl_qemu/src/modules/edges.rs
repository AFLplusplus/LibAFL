use std::{cell::UnsafeCell, cmp::max, fmt::Debug};

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

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

pub type CollidingEdgeCoverageModule<AF, PF> = EdgeCoverageModule<AF, PF, EdgeCoverageChildVariant>;

pub trait EdgeCoverageVariant<AF, PF>: 'static + Debug {
    const DO_SIDE_EFFECTS: bool = true;

    fn jit_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("JIT hitcount is not supported.")
    }

    fn jit_no_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("JIT no hitcount is not supported.")
    }

    fn fn_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("Func hitcount is not supported.")
    }

    fn fn_no_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("Func no hitcount is not supported.")
    }
}

#[derive(Debug)]
pub struct EdgeCoverageFullVariant;
impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageFullVariant {
    fn jit_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
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
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
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
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
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
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_single),
        );
    }
}

#[derive(Debug)]
pub struct EdgeCoverageClassicVariant;
impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageClassicVariant {
    const DO_SIDE_EFFECTS: bool = false;

    fn jit_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
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

    fn jit_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
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

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_hitcount),
        );
    }

    fn fn_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_single),
        );
    }
}

#[derive(Debug)]
pub struct EdgeCoverageChildVariant;
impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageChildVariant {
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

#[derive(Debug)]
pub struct EdgeCoverageModuleBuilder<AF, PF, V> {
    variant: V,
    address_filter: AF,
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
}

#[derive(Debug)]
pub struct EdgeCoverageModule<AF, PF, V> {
    variant: V,
    address_filter: AF,
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
}

impl Default
    for EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant>
{
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

impl EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant> {
    #[must_use]
    pub fn builder(
    ) -> EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant> {
        EdgeCoverageModuleBuilder::default()
    }
}

impl<AF, PF, V> EdgeCoverageModuleBuilder<AF, PF, V> {
    pub fn new(
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

    pub fn build(self) -> EdgeCoverageModule<AF, PF, V> {
        EdgeCoverageModule::new(
            self.address_filter,
            self.page_filter,
            self.variant,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn variant<V2>(self, variant: V2) -> EdgeCoverageModuleBuilder<AF, PF, V2> {
        EdgeCoverageModuleBuilder::new(
            variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn address_filter<AF2>(self, address_filter: AF2) -> EdgeCoverageModuleBuilder<AF2, PF, V> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    pub fn page_filter<PF2>(self, page_filter: PF2) -> EdgeCoverageModuleBuilder<AF, PF2, V> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            page_filter,
            self.use_hitcounts,
            self.use_jit,
        )
    }

    #[must_use]
    pub fn hitcounts(self, use_hitcounts: bool) -> EdgeCoverageModuleBuilder<AF, PF, V> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            use_hitcounts,
            self.use_jit,
        )
    }

    #[must_use]
    pub fn jit(self, use_jit: bool) -> EdgeCoverageModuleBuilder<AF, PF, V> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            use_jit,
        )
    }
}

impl<AF, PF, V> EdgeCoverageModule<AF, PF, V> {
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

impl<AF, PF, V> EdgeCoverageModule<AF, PF, V>
where
    AF: AddressFilter,
    PF: PageFilter,
{
    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

impl<S, AF, PF, V> EmulatorModule<S> for EdgeCoverageModule<AF, PF, V>
where
    AF: AddressFilter + 'static,
    PF: PageFilter + 'static,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF> + 'static,
{
    type ModuleAddressFilter = AF;
    #[cfg(emulation_mode = "systemmode")]
    type ModulePageFilter = PF;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
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

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.address_filter
    }

    #[cfg(emulation_mode = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter {
        &self.page_filter
    }

    #[cfg(emulation_mode = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        &mut self.page_filter
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });
pub fn gen_unique_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
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

pub fn gen_hashed_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
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

    let id = hash_me(src) ^ hash_me(dest);
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

pub fn gen_hashed_block_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(h) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !h.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let page_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !h.must_instrument(pc, page_id) {
                return None;
            }
        }
    }

    let id = hash_me(pc);
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
