use std::{collections::HashSet, path::PathBuf, sync::Mutex};

use hashbrown::{hash_map::Entry, HashMap};
use lazy_static::lazy_static;
use libafl::{inputs::Input, state::HasMetadata};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;

use crate::{
    blocks::pc2basicblock,
    emu::GuestAddr,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    Emulator,
};

lazy_static! {
    static ref DRCOV_IDS: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());
    static ref DRCOV_MAP: Mutex<HashMap<GuestAddr, u64>> = Mutex::new(HashMap::new());
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuDrCovMetadata {
    pub current_id: u64,
}

impl QemuDrCovMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self { current_id: 0 }
    }
}

libafl::impl_serdeany!(QemuDrCovMetadata);

#[derive(Debug)]
pub struct QemuDrCovHelper {
    filter: QemuInstrumentationFilter,
    filename: PathBuf,
    drcov_len: usize,
}

impl QemuDrCovHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter, filename: PathBuf) -> Self {
        Self {
            filter,
            filename,
            drcov_len: 0,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: u64) -> bool {
        self.filter.allowed(addr)
    }
}

impl<S> QemuHelper<S> for QemuDrCovHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks_raw(Some(gen_unique_block_ids::<I, QT, S>), Some(trace_block));
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &I) {}

    fn post_exec(&mut self, emulator: &Emulator, _input: &I) {
        if DRCOV_IDS.lock().unwrap().len() > self.drcov_len {
            println!("New DrCov lenght = {}", DRCOV_IDS.lock().unwrap().len());
            let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
            for id in DRCOV_IDS.lock().unwrap().iter() {
                for (pc, idm) in DRCOV_MAP.lock().unwrap().iter() {
                    if *idm == *id {
                        let block = pc2basicblock(*pc, &emulator);
                        let mut block_len = 0;
                        for instr in &block {
                            block_len += instr.insn_len;
                        }
                        block_len -= &block.last().unwrap().insn_len;
                        drcov_vec
                            .push(DrCovBasicBlock::new(*pc as usize, *pc as usize + block_len));
                    }
                }
            }

            let mut rangemap = RangeMap::<usize, (u16, String)>::new();
            rangemap.insert(
                (GuestAddr::MIN as usize)..(GuestAddr::MAX as usize),
                (0, "test".to_string()),
            );
            DrCovWriter::new(&rangemap)
                .write(&self.filename, &drcov_vec)
                .expect("Failed to write coverage file");
        }
        self.drcov_len = DRCOV_IDS.lock().unwrap().len();
    }
}

pub fn gen_unique_block_ids<I, QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: HasMetadata,
    I: Input,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks.helpers().match_first_type::<QemuDrCovHelper>() {
        if !h.must_instrument(pc.into()) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing");
    if state.metadata().get::<QemuDrCovMetadata>().is_none() {
        state.add_metadata(QemuDrCovMetadata::new());
    }
    let meta = state.metadata_mut().get_mut::<QemuDrCovMetadata>().unwrap();

    match DRCOV_MAP.lock().unwrap().entry(pc) {
        Entry::Occupied(e) => {
            let id = *e.get();
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = id + 1;
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

pub extern "C" fn trace_block(id: u64, _data: u64) {
    DRCOV_IDS.lock().unwrap().insert(id);
}
