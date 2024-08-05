use std::{path::PathBuf, sync::Mutex};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple, HasMetadata};
use libafl_qemu_sys::{GuestAddr, GuestUsize};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};

use crate::{
    emu::EmulatorModules,
    modules::{
        EmulatorModule, EmulatorModuleTuple, HasInstrumentationFilter, IsFilter,
        QemuInstrumentationAddressRangeFilter,
    },
    qemu::Hook,
};

static DRCOV_IDS: Mutex<Option<Vec<u64>>> = Mutex::new(None);
static DRCOV_MAP: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);
static DRCOV_LENGTHS: Mutex<Option<HashMap<GuestAddr, GuestUsize>>> = Mutex::new(None);

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DrCovMetadata {
    pub current_id: u64,
}

impl DrCovMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self { current_id: 0 }
    }
}

libafl_bolts::impl_serdeany!(DrCovMetadata);

#[derive(Debug)]
pub struct DrCovModule {
    filter: QemuInstrumentationAddressRangeFilter,
    module_mapping: RangeMap<usize, (u16, String)>,
    filename: PathBuf,
    full_trace: bool,
    drcov_len: usize,
}

impl DrCovModule {
    #[must_use]
    #[allow(clippy::let_underscore_untyped)]
    pub fn new(
        filter: QemuInstrumentationAddressRangeFilter,
        filename: PathBuf,
        full_trace: bool,
    ) -> Self {
        if full_trace {
            let _ = DRCOV_IDS.lock().unwrap().insert(vec![]);
        }
        let _ = DRCOV_MAP.lock().unwrap().insert(HashMap::new());
        let _ = DRCOV_LENGTHS.lock().unwrap().insert(HashMap::new());
        Self {
            filter,
            module_mapping: RangeMap::new(),
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

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for DrCovModule {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.filter
    }
}

impl<S> EmulatorModule<S> for DrCovModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    fn init_module<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.blocks(
            Hook::Function(gen_unique_block_ids::<ET, S>),
            Hook::Function(gen_block_lengths::<ET, S>),
            Hook::Function(exec_trace_block::<ET, S>),
        );
    }

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        let qemu = emulator_modules.qemu();

        for (i, (r, p)) in qemu
            .mappings()
            .filter_map(|m| {
                m.path()
                    .map(|p| ((m.start() as usize)..(m.end() as usize), p.to_string()))
                    .filter(|(_, p)| !p.is_empty())
            })
            .enumerate()
        {
            self.module_mapping.insert(r, (i as u16, p));
        }
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        let lengths_opt = DRCOV_LENGTHS.lock().unwrap();
        let lengths = lengths_opt.as_ref().unwrap();
        if self.full_trace {
            if DRCOV_IDS.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                for id in DRCOV_IDS.lock().unwrap().as_ref().unwrap() {
                    'pcs_full: for (pc, idm) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
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
                            match lengths.get(pc) {
                                Some(block_length) => {
                                    drcov_vec.push(DrCovBasicBlock::new(
                                        *pc as usize,
                                        *pc as usize + *block_length as usize,
                                    ));
                                }
                                None => {
                                    log::info!("Failed to find block length for: {pc:}");
                                }
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
                'pcs: for (pc, _) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
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
                    match lengths.get(pc) {
                        Some(block_length) => {
                            drcov_vec.push(DrCovBasicBlock::new(
                                *pc as usize,
                                *pc as usize + *block_length as usize,
                            ));
                        }
                        None => {
                            log::info!("Failed to find block length for: {pc:}");
                        }
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

pub fn gen_unique_block_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let drcov_module = emulator_modules.get::<DrCovModule>().unwrap();
    if !drcov_module.must_instrument(pc) {
        return None;
    }

    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing");
    if state
        .metadata_map_mut()
        .get_mut::<DrCovMetadata>()
        .is_none()
    {
        state.add_metadata(DrCovMetadata::new());
    }
    let meta = state.metadata_map_mut().get_mut::<DrCovMetadata>().unwrap();

    match DRCOV_MAP.lock().unwrap().as_mut().unwrap().entry(pc) {
        Entry::Occupied(e) => {
            let id = *e.get();
            if drcov_module.full_trace {
                Some(id)
            } else {
                None
            }
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = id + 1;
            if drcov_module.full_trace {
                // GuestAddress is u32 for 32 bit guests
                #[allow(clippy::unnecessary_cast)]
                Some(id as u64)
            } else {
                None
            }
        }
    }
}

pub fn gen_block_lengths<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    block_length: GuestUsize,
) where
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let drcov_module = emulator_modules.get::<DrCovModule>().unwrap();
    if !drcov_module.must_instrument(pc) {
        return;
    }
    DRCOV_LENGTHS
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(pc, block_length);
}

pub fn exec_trace_block<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    id: u64,
) where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata,
{
    if emulator_modules.get::<DrCovModule>().unwrap().full_trace {
        DRCOV_IDS.lock().unwrap().as_mut().unwrap().push(id);
    }
}
