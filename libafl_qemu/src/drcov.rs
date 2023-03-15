use std::{path::PathBuf, sync::Mutex};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{
    executors::ExitKind, inputs::UsesInput, observers::ObserversTuple, state::HasMetadata,
};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};

use crate::{
    blocks::pc2basicblock,
    emu::GuestAddr,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    Emulator,
};

static DRCOV_IDS: Mutex<Option<Vec<u64>>> = Mutex::new(None);
static DRCOV_MAP: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);

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
    module_mapping: RangeMap<usize, (u16, String)>,
    filename: PathBuf,
    full_trace: bool,
    drcov_len: usize,
}

impl QemuDrCovHelper {
    #[must_use]
    #[allow(clippy::let_underscore_untyped)]
    pub fn new(
        filter: QemuInstrumentationFilter,
        module_mapping: RangeMap<usize, (u16, String)>,
        filename: PathBuf,
        full_trace: bool,
    ) -> Self {
        if full_trace {
            let _ = DRCOV_IDS.lock().unwrap().insert(vec![]);
        }
        let _ = DRCOV_MAP.lock().unwrap().insert(HashMap::new());
        Self {
            filter,
            module_mapping,
            filename,
            full_trace,
            drcov_len: 0,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }
}

impl<S> QemuHelper<S> for QemuDrCovHelper
where
    S: UsesInput + HasMetadata,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks(
            Some(gen_unique_block_ids::<QT, S>),
            Some(exec_trace_block::<QT, S>),
        );
    }

    fn pre_exec(&mut self, _emulator: &Emulator, _input: &S::Input) {}

    fn post_exec<OT>(
        &mut self,
        emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        if self.full_trace {
            if DRCOV_IDS.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                for id in DRCOV_IDS.lock().unwrap().as_ref().unwrap().iter() {
                    'pcs_full: for (pc, idm) in DRCOV_MAP.lock().unwrap().as_ref().unwrap().iter() {
                        let mut module_found = false;
                        for module in self.module_mapping.iter() {
                            let (range, (_, _)) = module;
                            if *pc >= range.start.try_into().unwrap()
                                && *pc <= range.end.try_into().unwrap()
                            {
                                module_found = true;
                                break;
                            }
                        }
                        if !module_found {
                            continue 'pcs_full;
                        }
                        if *idm == *id {
                            #[cfg(cpu_target = "arm")]
                            let mode = if pc & 1 == 1 {
                                Some(capstone::arch::arm::ArchMode::Thumb.into())
                            } else {
                                Some(capstone::arch::arm::ArchMode::Arm.into())
                            };
                            #[cfg(not(cpu_target = "arm"))]
                            let mode = None;

                            match pc2basicblock(*pc, emulator, mode) {
                                Ok(block) => {
                                    let mut block_len = 0;
                                    for instr in &block {
                                        block_len += instr.insn_len;
                                    }
                                    drcov_vec.push(DrCovBasicBlock::new(
                                        *pc as usize,
                                        *pc as usize + block_len,
                                    ));
                                }
                                Err(r) => log::info!("{r:#?}"),
                            }
                        }
                    }
                }

                DrCovWriter::new(&self.module_mapping)
                    .write(&self.filename, &drcov_vec)
                    .expect("Failed to write coverage file");
            }
            self.drcov_len = DRCOV_IDS.lock().unwrap().as_ref().unwrap().len();
        } else {
            if DRCOV_MAP.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                'pcs: for (pc, _) in DRCOV_MAP.lock().unwrap().as_ref().unwrap().iter() {
                    let mut module_found = false;
                    for module in self.module_mapping.iter() {
                        let (range, (_, _)) = module;
                        if *pc >= range.start.try_into().unwrap()
                            && *pc <= range.end.try_into().unwrap()
                        {
                            module_found = true;
                            break;
                        }
                    }
                    if !module_found {
                        continue 'pcs;
                    }

                    #[cfg(cpu_target = "arm")]
                    let mode = if pc & 1 == 1 {
                        Some(capstone::arch::arm::ArchMode::Thumb.into())
                    } else {
                        Some(capstone::arch::arm::ArchMode::Arm.into())
                    };
                    #[cfg(not(cpu_target = "arm"))]
                    let mode = None;

                    match pc2basicblock(*pc, emulator, mode) {
                        Ok(block) => {
                            let mut block_len = 0;
                            for instr in &block {
                                block_len += instr.insn_len;
                            }
                            drcov_vec
                                .push(DrCovBasicBlock::new(*pc as usize, *pc as usize + block_len));
                        }
                        Err(r) => log::info!("{r:#?}"),
                    }
                }

                DrCovWriter::new(&self.module_mapping)
                    .write(&self.filename, &drcov_vec)
                    .expect("Failed to write coverage file");
            }
            self.drcov_len = DRCOV_MAP.lock().unwrap().as_ref().unwrap().len();
        }
    }
}

pub fn gen_unique_block_ids<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let drcov_helper = hooks
        .helpers()
        .match_first_type::<QemuDrCovHelper>()
        .unwrap();
    if !drcov_helper.must_instrument(pc) {
        return None;
    }

    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing");
    if state
        .metadata_map_mut()
        .get_mut::<QemuDrCovMetadata>()
        .is_none()
    {
        state.add_metadata(QemuDrCovMetadata::new());
    }
    let meta = state
        .metadata_map_mut()
        .get_mut::<QemuDrCovMetadata>()
        .unwrap();

    match DRCOV_MAP.lock().unwrap().as_mut().unwrap().entry(pc) {
        Entry::Occupied(e) => {
            let id = *e.get();
            if drcov_helper.full_trace {
                Some(id)
            } else {
                None
            }
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = id + 1;
            if drcov_helper.full_trace {
                // GuestAddress is u32 for 32 bit guests
                #[allow(clippy::unnecessary_cast)]
                Some(id as u64)
            } else {
                None
            }
        }
    }
}

pub fn exec_trace_block<QT, S>(hooks: &mut QemuHooks<'_, QT, S>, _state: Option<&mut S>, id: u64)
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if hooks
        .helpers()
        .match_first_type::<QemuDrCovHelper>()
        .unwrap()
        .full_trace
    {
        DRCOV_IDS.lock().unwrap().as_mut().unwrap().push(id);
    }
}
