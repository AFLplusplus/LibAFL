use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::Input, state::HasMetadata};
pub use libafl_targets::{
    edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_PTR_SIZE, EDGES_MAP_SIZE, MAX_EDGES_NUM,
};
use serde::{Deserialize, Serialize};
use std::{cell::UnsafeCell, cmp::max, pin::Pin};

use crate::{
    emu::Emulator,
    helper::{hash_me, QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(u64, u64), u64>,
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

libafl::impl_serdeany!(QemuEdgesMapMetadata);

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
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuEdgeCoverageHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<I, S> QemuHelper<I, S> for QemuEdgeCoverageHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init_hooks<'a, QT>(&self, hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        hooks.edge_generation(gen_unique_edge_ids::<I, QT, S>);
        if self.use_hitcounts {
            hooks.emulator().set_exec_edge_hook(trace_edge_hitcount);
        } else {
            hooks.emulator().set_exec_edge_hook(trace_edge_single);
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
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuEdgeCoverageChildHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<I, S> QemuHelper<I, S> for QemuEdgeCoverageChildHelper
where
    I: Input,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_hooks<'a, QT>(&self, hooks: Pin<&QemuHooks<'a, I, QT, S>>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        hooks.edge_generation(gen_hashed_edge_ids::<I, QT, S>);
        if self.use_hitcounts {
            hooks.emulator().set_exec_edge_hook(trace_edge_hitcount_ptr);
        } else {
            hooks.emulator().set_exec_edge_hook(trace_edge_single_ptr);
        }
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = UnsafeCell::new(0));

pub fn gen_unique_edge_ids<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    state: Option<&mut S>,
    src: u64,
    dest: u64,
) -> Option<u64>
where
    S: HasMetadata,
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if let Some(h) = helpers.match_first_type::<QemuEdgeCoverageHelper>() {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    if state.metadata().get::<QemuEdgesMapMetadata>().is_none() {
        state.add_metadata(QemuEdgesMapMetadata::new());
    }
    let meta = state
        .metadata_mut()
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
            Some(id as u64)
        }
    }
}

pub extern "C" fn trace_edge_hitcount(id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single(id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub fn gen_hashed_edge_ids<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: Option<&mut S>,
    src: u64,
    dest: u64,
) -> Option<u64>
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if let Some(h) = helpers.match_first_type::<QemuEdgeCoverageChildHelper>() {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    Some((hash_me(src) ^ hash_me(dest)) & (unsafe { EDGES_MAP_PTR_SIZE } as u64 - 1))
}

pub extern "C" fn trace_edge_hitcount_ptr(id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single_ptr(id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

pub fn gen_addr_block_ids<I, QT, S>(
    _emulator: &Emulator,
    _helpers: &mut QT,
    _state: Option<&mut S>,
    pc: u64,
) -> Option<u64> {
    Some(pc)
}

pub fn gen_hashed_block_ids<I, QT, S>(
    _emulator: &Emulator,
    _helpers: &mut QT,
    _state: Option<&mut S>,
    pc: u64,
) -> Option<u64> {
    Some(hash_me(pc))
}

pub extern "C" fn trace_block_transition_hitcount(id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_SIZE - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub extern "C" fn trace_block_transition_single(id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_SIZE - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}
