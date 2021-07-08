use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use libafl::state::HasMetadata;
pub use libafl_targets::{EDGES_MAP, EDGES_MAP_SIZE, MAX_EDGES_NUM};

/// A testcase metadata saying if a testcase is favored
#[derive(Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(u64, u64), u32>,
}

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

libafl::impl_serdeany!(QemuEdgesMapMetadata);

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
    Some(*meta.map.entry((src, dest)).or_insert_with(|| unsafe {
        let id = MAX_EDGES_NUM;
        MAX_EDGES_NUM = (MAX_EDGES_NUM + 1) & (EDGES_MAP_SIZE - 1);
        id as u32
    }))
}

pub extern "C" fn exec_log_hitcount(id: u32) {
    unsafe { EDGES_MAP[id as usize] += 1 };
}

pub extern "C" fn exec_log_single(id: u32) {
    unsafe { EDGES_MAP[id as usize] = 1 };
}
