#[cfg(feature = "usermode")]
use std::{
    cmp::{max, min},
    ops::Range,
};
use std::{path::PathBuf, sync::Mutex};

use hashbrown::{HashMap, hash_map::Entry};
use libafl::{HasMetadata, executors::ExitKind, observers::ObserversTuple};
use libafl_qemu_sys::{GuestAddr, GuestUsize};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};

use super::utils::filters::HasAddressFilter;
#[cfg(feature = "systemmode")]
use crate::modules::utils::filters::{HasPageFilter, NOP_PAGE_FILTER, NopPageFilter};
use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple, utils::filters::NopAddressFilter,
    },
    qemu::Hook,
};

/// Trace of `block_id`s met at runtime
static DRCOV_IDS: Mutex<Option<Vec<u64>>> = Mutex::new(None);

///Map of `pc` -> `block_id`
static DRCOV_MAP: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);

/// Map of `pc` -> `block_len`
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
pub struct DrCovModuleBuilder<F> {
    filter: Option<F>,
    module_mapping: Option<RangeMap<u64, (u16, String)>>,
    filename: Option<PathBuf>,
    full_trace: bool,
}

impl<F> DrCovModuleBuilder<F>
where
    F: AddressFilter,
{
    pub fn build(self) -> DrCovModule<F> {
        DrCovModule::new(
            self.filter.unwrap(),
            self.filename.unwrap(),
            self.module_mapping,
            self.full_trace,
        )
    }

    pub fn filter<F2>(self, filter: F2) -> DrCovModuleBuilder<F2> {
        DrCovModuleBuilder {
            filter: Some(filter),
            module_mapping: self.module_mapping,
            filename: self.filename,
            full_trace: self.full_trace,
        }
    }

    #[must_use]
    pub fn module_mapping(self, module_mapping: RangeMap<u64, (u16, String)>) -> Self {
        Self {
            filter: self.filter,
            module_mapping: Some(module_mapping),
            filename: self.filename,
            full_trace: self.full_trace,
        }
    }

    #[must_use]
    pub fn filename(self, filename: PathBuf) -> Self {
        Self {
            filter: self.filter,
            module_mapping: self.module_mapping,
            filename: Some(filename),
            full_trace: self.full_trace,
        }
    }

    #[must_use]
    pub fn full_trace(self, full_trace: bool) -> Self {
        Self {
            filter: self.filter,
            module_mapping: self.module_mapping,
            filename: self.filename,
            full_trace,
        }
    }
}

#[derive(Debug)]
pub struct DrCovModule<F> {
    filter: F,
    module_mapping: Option<RangeMap<u64, (u16, String)>>,
    filename: PathBuf,
    full_trace: bool,
    drcov_len: usize,
}

pub fn gen_unique_block_ids<ET, F, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    F: AddressFilter,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    let drcov_module = emulator_modules.get::<DrCovModule<F>>().unwrap();
    if !drcov_module.must_instrument(pc) {
        return None;
    }

    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing. Is the Executor initialized?");
    if state
        .metadata_map_mut()
        .get_mut::<DrCovMetadata>()
        .is_none()
    {
        state.add_metadata(DrCovMetadata::new());
    }

    let meta = state.metadata_map_mut().get_mut::<DrCovMetadata>().unwrap();

    match DRCOV_MAP.lock().unwrap().as_mut().unwrap().entry(pc) {
        Entry::Occupied(entry) => {
            let id = *entry.get();
            Some(id)
        }
        Entry::Vacant(entry) => {
            let id = meta.current_id;

            entry.insert(id);
            meta.current_id = id + 1;

            #[expect(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
pub fn gen_block_lengths<ET, F, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    block_length: GuestUsize,
) where
    ET: EmulatorModuleTuple<I, S>,
    F: AddressFilter,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    let drcov_module = emulator_modules.get::<DrCovModule<F>>().unwrap();
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

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
pub fn exec_trace_block<ET, F, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
) where
    ET: EmulatorModuleTuple<I, S>,
    F: AddressFilter,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    DRCOV_IDS.lock().unwrap().as_mut().unwrap().push(id);
}

impl<F, I, S> EmulatorModule<I, S> for DrCovModule<F>
where
    F: AddressFilter,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    #[cfg(feature = "usermode")]
    fn first_exec<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.full_trace {
            emulator_modules.blocks(
                Hook::Function(gen_unique_block_ids::<ET, F, I, S>),
                Hook::Function(gen_block_lengths::<ET, F, I, S>),
                Hook::Function(exec_trace_block::<ET, F, I, S>),
            );
        } else {
            emulator_modules.blocks(
                Hook::Function(gen_unique_block_ids::<ET, F, I, S>),
                Hook::Function(gen_block_lengths::<ET, F, I, S>),
                Hook::Empty,
            );
        }

        if self.module_mapping.is_none() {
            log::info!("Auto-filling module mapping for DrCov module from QEMU mapping.");

            let mut module_range_map: RangeMap<u64, (u16, String)> = RangeMap::new();
            let mut module_path_map: HashMap<String, (Range<u64>, u16)> = HashMap::default();

            // We are building a mapping of
            // Path -> pc_start..pc_end, where pc_start is the smallest pc for the path and pc_end the biggest pc.
            let mut i = 0;
            for ((map_start, map_end), map_path) in qemu.mappings().filter_map(|m| {
                m.path().filter(|p| !p.is_empty()).map(|p| {
                    (
                        (
                            u64::try_from(m.start()).unwrap(),
                            u64::try_from(m.end()).unwrap(),
                        ),
                        p.to_string(),
                    )
                })
            }) {
                // Check if path is already present
                match module_path_map.entry(map_path) {
                    Entry::Occupied(mut entry) => {
                        // If present, try to widen the range if necessary
                        let (range, _) = entry.get_mut();
                        range.start = min(range.start, map_start);
                        range.end = max(range.end, map_end);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert((map_start..map_end, i));
                        i += 1;
                    }
                }
                // module_mapping.insert(r, (i as u16, p));
            }

            // Now, we can reorder the data by building a RangeMap and consume the old map.
            for (path, (range, id)) in module_path_map {
                module_range_map.insert(range, (id, path));
            }

            // Split ranges larger than 4GiB into smaller ranges, as Drcov max
            // module size is 4GiB. This also suffices to give each range a
            // unique id. (Before this loop, any larger ranges split into many
            // by smaller ranges retain the same id, which isn't unique.)
            let mut split_module_range_map: RangeMap<u64, (u16, String)> = RangeMap::new();
            let mut i = 0;
            for (range, (_, path)) in module_range_map {
                let mut range_start = range.start;
                let range_end = range.end;
                while range_end - range_start - 1 > u64::from(u32::MAX) {
                    let range_end_short =
                        (range_start + u64::from(u32::MAX) + 1) & !u64::from(u32::MAX);
                    split_module_range_map.insert(
                        Range {
                            start: range_start,
                            end: range_end_short,
                        },
                        (i, path.clone()),
                    );
                    i += 1;
                    range_start = range_end_short;
                }
                split_module_range_map.insert(
                    Range {
                        start: range_start,
                        end: range_end,
                    },
                    (i, path.clone()),
                );
                i += 1;
            }

            self.module_mapping = Some(RangeMap::<u64, (u16, String)>::from_iter(
                split_module_range_map,
            ));
        } else {
            log::info!("Using user-provided module mapping for DrCov module.");
        }
    }

    #[cfg(feature = "systemmode")]
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        assert!(
            self.module_mapping.is_some(),
            "DrCov should have a module mapping already set."
        );

        if self.full_trace {
            emulator_modules.blocks(
                Hook::Function(gen_unique_block_ids::<ET, F, I, S>),
                Hook::Function(gen_block_lengths::<ET, F, I, S>),
                Hook::Function(exec_trace_block::<ET, F, I, S>),
            );
        } else {
            emulator_modules.blocks(
                Hook::Function(gen_unique_block_ids::<ET, F, I, S>),
                Hook::Function(gen_block_lengths::<ET, F, I, S>),
                Hook::Empty,
            );
        };
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        self.flush();
    }

    unsafe fn on_crash(&mut self) {
        self.flush();
    }

    unsafe fn on_timeout(&mut self) {
        self.flush();
    }
}

impl DrCovModule<NopAddressFilter> {
    #[must_use]
    pub fn builder() -> DrCovModuleBuilder<NopAddressFilter> {
        DrCovModuleBuilder {
            filter: Some(NopAddressFilter),
            module_mapping: None,
            full_trace: false,
            filename: None,
        }
    }
}

impl<F> DrCovModule<F> {
    #[must_use]
    pub fn new(
        filter: F,
        filename: PathBuf,
        module_mapping: Option<RangeMap<u64, (u16, String)>>,
        full_trace: bool,
    ) -> Self {
        if full_trace {
            *DRCOV_IDS.lock().unwrap() = Some(vec![]);
        }

        *DRCOV_MAP.lock().unwrap() = Some(HashMap::new());
        *DRCOV_LENGTHS.lock().unwrap() = Some(HashMap::new());

        Self {
            filter,
            module_mapping,
            filename,
            full_trace,
            drcov_len: 0,
        }
    }

    pub fn flush(&mut self) {
        let lengths_opt = DRCOV_LENGTHS.lock().unwrap();
        let lengths = lengths_opt.as_ref().unwrap();
        if self.full_trace {
            if DRCOV_IDS.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                for id in DRCOV_IDS.lock().unwrap().as_ref().unwrap() {
                    'pcs_full: for (pc, idm) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
                        let mut module_found = false;
                        // # Safety
                        //
                        // Module mapping is already set. It's checked or filled when the module is first run.
                        unsafe {
                            for module in self.module_mapping.as_ref().unwrap_unchecked().iter() {
                                let (range, (_, _)) = module;
                                if range.contains(&u64::try_from(*pc).unwrap()) {
                                    module_found = true;
                                    break;
                                }
                            }
                        }
                        if !module_found {
                            continue 'pcs_full;
                        }
                        if *idm == *id {
                            #[expect(clippy::unnecessary_cast)] // for GuestAddr -> u64
                            match lengths.get(pc) {
                                Some(block_length) => {
                                    drcov_vec.push(DrCovBasicBlock::new(
                                        *pc as u64,
                                        *pc as u64 + *block_length as u64,
                                    ));
                                }
                                None => {
                                    log::info!("Failed to find block length for: {pc:}");
                                }
                            }
                        }
                    }
                }

                // # Safety
                //
                // Module mapping is already set. It's checked or filled when the module is first run.
                unsafe {
                    DrCovWriter::new(self.module_mapping.as_ref().unwrap_unchecked())
                        .write(&self.filename, &drcov_vec)
                        .expect("Failed to write coverage file");
                }
            }
            self.drcov_len = DRCOV_IDS.lock().unwrap().as_ref().unwrap().len();
        } else {
            if DRCOV_MAP.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                'pcs: for (pc, _) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
                    let mut module_found = false;
                    // # Safety
                    //
                    // Module mapping is already set. It's checked or filled when the module is first run.
                    unsafe {
                        for module in self.module_mapping.as_ref().unwrap_unchecked().iter() {
                            let (range, (_, _)) = module;
                            if *pc >= range.start.try_into().unwrap()
                                && *pc <= range.end.try_into().unwrap()
                            {
                                module_found = true;
                                break;
                            }
                        }
                    }
                    if !module_found {
                        continue 'pcs;
                    }

                    #[expect(clippy::unnecessary_cast)] // for GuestAddr -> u64
                    match lengths.get(pc) {
                        Some(block_length) => {
                            drcov_vec.push(DrCovBasicBlock::new(
                                u64::try_from(*pc).unwrap(),
                                u64::try_from(*pc).unwrap() as u64
                                    + u64::try_from(*block_length).unwrap(),
                            ));
                        }
                        None => {
                            log::info!("Failed to find block length for: {pc:}");
                        }
                    }
                }

                // # Safety
                //
                // Module mapping is already set. It's checked or filled when the module is first run.
                unsafe {
                    DrCovWriter::new(self.module_mapping.as_ref().unwrap_unchecked())
                        .write(&self.filename, &drcov_vec)
                        .expect("Failed to write coverage file");
                }
            }
            self.drcov_len = DRCOV_MAP.lock().unwrap().as_ref().unwrap().len();
        }
    }
}

impl<F> DrCovModule<F>
where
    F: AddressFilter,
{
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(&addr)
    }
}

impl<F> HasAddressFilter for DrCovModule<F>
where
    F: AddressFilter,
{
    type AddressFilter = F;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.filter
    }
}

#[cfg(feature = "systemmode")]
impl<F> HasPageFilter for DrCovModule<F> {
    type PageFilter = NopPageFilter;

    fn page_filter(&self) -> &Self::PageFilter {
        &NopPageFilter
    }

    fn page_filter_mut(&mut self) -> &mut Self::PageFilter {
        unsafe { (&raw mut NOP_PAGE_FILTER).as_mut().unwrap().get_mut() }
    }
}
