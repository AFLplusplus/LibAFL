use core::cmp::max;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use libafl::state::HasMetadata;
pub use libafl_targets::{
    cmplog::__libafl_targets_cmplog_instructions, CmpLogObserver, CMPLOG_MAP, CMPLOG_MAP_W,
    EDGES_MAP, EDGES_MAP_SIZE, MAX_EDGES_NUM,
};

#[derive(Default, Serialize, Deserialize)]
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

#[derive(Default, Serialize, Deserialize)]
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

pub fn gen_unique_edge_ids<S>(state: &mut S, src: u64, dest: u64) -> Option<u64>
where
    S: HasMetadata,
{
    if state.metadata().get::<QemuEdgesMapMetadata>().is_none() {
        state.add_metadata(QemuEdgesMapMetadata::new());
    }
    let meta = state
        .metadata_mut()
        .get_mut::<QemuEdgesMapMetadata>()
        .unwrap();
    let id = max(meta.current_id as usize, unsafe { MAX_EDGES_NUM });
    if meta.map.contains_key(&(src, dest)) {
        Some(*meta.map.get(&(src, dest)).unwrap())
    } else {
        meta.current_id = ((id + 1) & (EDGES_MAP_SIZE - 1)) as u64;
        unsafe {
            MAX_EDGES_NUM = meta.current_id as usize;
        }
        Some(id as u64)
    }
}

pub extern "C" fn trace_edge_hitcount(id: u64) {
    unsafe {
        EDGES_MAP[id as usize] += 1;
    }
}

pub extern "C" fn trace_edge_single(id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub fn gen_unique_cmp_ids<S>(state: &mut S, pc: u64, _size: usize) -> Option<u64>
where
    S: HasMetadata,
{
    if state.metadata().get::<QemuCmpsMapMetadata>().is_none() {
        state.add_metadata(QemuCmpsMapMetadata::new());
    }
    let meta = state
        .metadata_mut()
        .get_mut::<QemuCmpsMapMetadata>()
        .unwrap();
    let id = meta.current_id as usize;
    if meta.map.contains_key(&pc) {
        Some(*meta.map.get(&pc).unwrap())
    } else {
        meta.current_id = ((id + 1) & (CMPLOG_MAP_W - 1)) as u64;
        Some(id as u64)
    }
}

pub extern "C" fn trace_cmp1_cmplog(id: u64, v0: u8, v1: u8) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 1, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp2_cmplog(id: u64, v0: u16, v1: u16) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 2, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp4_cmplog(id: u64, v0: u32, v1: u32) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 4, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp8_cmplog(id: u64, v0: u64, v1: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 8, v0, v1);
    }
}
