use hashbrown::HashMap;
use libafl::{inputs::UsesInput, state::HasMetadata};
pub use libafl_targets::{
    cmplog::__libafl_targets_cmplog_instructions, CmpLogMap, CmpLogObserver, CMPLOG_MAP,
    CMPLOG_MAP_H, CMPLOG_MAP_PTR, CMPLOG_MAP_SIZE, CMPLOG_MAP_W,
};
use serde::{Deserialize, Serialize};

use crate::{
    helper::{hash_me, QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    GuestAddr,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuCmpsMapMetadata {
    pub map: HashMap<u64, u64>,
    pub current_id: u64,
}

impl QemuCmpsMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

libafl::impl_serdeany!(QemuCmpsMapMetadata);

#[derive(Debug)]
pub struct QemuCmpLogHelper {
    filter: QemuInstrumentationFilter,
}

impl QemuCmpLogHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self { filter }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuCmpLogHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<S> QemuHelper<S> for QemuCmpLogHelper
where
    S: UsesInput + HasMetadata,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.cmps_raw(
            Some(gen_unique_cmp_ids::<QT, S>),
            Some(trace_cmp1_cmplog),
            Some(trace_cmp2_cmplog),
            Some(trace_cmp4_cmplog),
            Some(trace_cmp8_cmplog),
        );
    }
}

#[derive(Debug)]
pub struct QemuCmpLogChildHelper {
    filter: QemuInstrumentationFilter,
}

impl QemuCmpLogChildHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self { filter }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuCmpLogChildHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl<S> QemuHelper<S> for QemuCmpLogChildHelper
where
    S: UsesInput,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.cmps_raw(
            Some(gen_hashed_cmp_ids::<QT, S>),
            Some(trace_cmp1_cmplog),
            Some(trace_cmp2_cmplog),
            Some(trace_cmp4_cmplog),
            Some(trace_cmp8_cmplog),
        );
    }
}

pub fn gen_unique_cmp_ids<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
    _size: usize,
) -> Option<u64>
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks.match_helper_mut::<QemuCmpLogHelper>() {
        if !h.must_instrument(pc.into()) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_cmp_ids hook works only for in-process fuzzing");
    if state.metadata().get::<QemuCmpsMapMetadata>().is_none() {
        state.add_metadata(QemuCmpsMapMetadata::new());
    }
    let meta = state
        .metadata_mut()
        .get_mut::<QemuCmpsMapMetadata>()
        .unwrap();
    let id = meta.current_id as usize;

    Some(*meta.map.entry(pc.into()).or_insert_with(|| {
        meta.current_id = ((id + 1) & (CMPLOG_MAP_W - 1)) as u64;
        id as u64
    }))
}

pub fn gen_hashed_cmp_ids<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _size: usize,
) -> Option<u64>
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks.match_helper_mut::<QemuCmpLogChildHelper>() {
        if !h.must_instrument(pc.into()) {
            return None;
        }
    }
    Some(hash_me(pc.into()) & (CMPLOG_MAP_W as u64 - 1))
}

pub extern "C" fn trace_cmp1_cmplog(id: u64, v0: u8, v1: u8, _data: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 1, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp2_cmplog(id: u64, v0: u16, v1: u16, _data: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 2, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp4_cmplog(id: u64, v0: u32, v1: u32, _data: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 4, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp8_cmplog(id: u64, v0: u64, v1: u64, _data: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 8, v0, v1);
    }
}
