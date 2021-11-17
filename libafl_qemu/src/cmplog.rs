use hashbrown::{hash_map::Entry, HashMap};
use libafl::{executors::ExitKind, inputs::Input, observers::ObserversTuple, state::HasMetadata};
pub use libafl_targets::{
    cmplog::__libafl_targets_cmplog_instructions, CmpLogObserver, CMPLOG_MAP, CMPLOG_MAP_W,
};
use serde::{Deserialize, Serialize};

use crate::{
    emu,
    executor::QemuExecutor,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
};

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

pub struct QemuCmpLogHelper {
    filter: QemuInstrumentationFilter,
}

impl QemuCmpLogHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            filter: QemuInstrumentationFilter::None,
        }
    }

    #[must_use]
    pub fn with_instrumentation_filter(filter: QemuInstrumentationFilter) -> Self {
        Self { filter }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl Default for QemuCmpLogHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> QemuHelper<I, S> for QemuCmpLogHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        executor.hook_cmp_generation(gen_unique_cmp_ids::<I, QT, S>);
        emu::set_exec_cmp8_hook(trace_cmp8_cmplog);
        emu::set_exec_cmp4_hook(trace_cmp4_cmplog);
        emu::set_exec_cmp2_hook(trace_cmp2_cmplog);
        emu::set_exec_cmp1_hook(trace_cmp1_cmplog);
    }
}

pub fn gen_unique_cmp_ids<I, QT, S>(
    helpers: &mut QT,
    state: &mut S,
    pc: u64,
    _size: usize,
) -> Option<u64>
where
    S: HasMetadata,
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if let Some(h) = helpers.match_first_type::<QemuCmpLogHelper>() {
        if !h.must_instrument(pc) {
            return None;
        }
    }
    if state.metadata().get::<QemuCmpsMapMetadata>().is_none() {
        state.add_metadata(QemuCmpsMapMetadata::new());
    }
    let meta = state
        .metadata_mut()
        .get_mut::<QemuCmpsMapMetadata>()
        .unwrap();
    let id = meta.current_id as usize;

    Some(*meta.map.entry(pc).or_insert_with(|| {
        meta.current_id = ((id + 1) & (CMPLOG_MAP_W - 1)) as u64;
        id as u64
    }))
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
