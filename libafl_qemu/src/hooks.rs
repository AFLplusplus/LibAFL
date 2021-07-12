use core::cmp::max;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use libafl::state::HasMetadata;
pub use libafl_targets::{
    cmplog::__libafl_targets_cmplog_instructions, CMPLOG_MAP_W, EDGES_MAP, EDGES_MAP_SIZE,
    MAX_EDGES_NUM,
};

#[derive(Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(u64, u64), u32>,
    pub current_id: u32,
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
    pub map: HashMap<u64, u32>,
    pub current_id: u32,
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

pub fn gen_unique_edges_id<S>(state: &mut S, src: u64, dest: u64) -> Option<u32>
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
    if !meta.map.contains_key(&(src, dest)) {
        meta.current_id = ((id + 1) & (EDGES_MAP_SIZE - 1)) as u32;
        unsafe { MAX_EDGES_NUM = meta.current_id as usize };
        Some(id as u32)
    } else {
        Some(*meta.map.get(&(src, dest)).unwrap())
    }
}

pub extern "C" fn exec_log_hitcount(id: u32) {
    unsafe { EDGES_MAP[id as usize] += 1 };
}

pub extern "C" fn exec_log_single(id: u32) {
    unsafe { EDGES_MAP[id as usize] = 1 };
}

pub fn gen_unique_cmps_id<S>(state: &mut S, addr: u64, _size: usize) -> Option<u32>
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
    if !meta.map.contains_key(&addr) {
        meta.current_id = ((id + 1) & (CMPLOG_MAP_W - 1)) as u32;
        Some(id as u32)
    } else {
        Some(*meta.map.get(&addr).unwrap())
    }
}

pub extern "C" fn trace_cmp1_cmplog(id: u32, v0: u8, v1: u8) {
    unsafe { __libafl_targets_cmplog_instructions(id as usize, 1, v0 as u64, v1 as u64) }
}

pub extern "C" fn trace_cmp2_cmplog(id: u32, v0: u16, v1: u16) {
    unsafe { __libafl_targets_cmplog_instructions(id as usize, 2, v0 as u64, v1 as u64) }
}

pub extern "C" fn trace_cmp4_cmplog(id: u32, v0: u32, v1: u32) {
    unsafe { __libafl_targets_cmplog_instructions(id as usize, 4, v0 as u64, v1 as u64) }
}

pub extern "C" fn trace_cmp8_cmplog(id: u32, v0: u64, v1: u64) {
    unsafe { __libafl_targets_cmplog_instructions(id as usize, 8, v0, v1) }
}
