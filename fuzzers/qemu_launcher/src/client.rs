use {
    crate::{instance::Instance, options::FuzzerOptions},
    libafl::{
        corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
        events::LlmpRestartingEventManager,
        inputs::BytesInput,
        state::StdState,
        Error,
    },
    libafl_bolts::{
        core_affinity::CoreId, rands::StdRand, shmem::StdShMemProvider, tuples::tuple_list,
    },
    libafl_qemu::{
        asan::{init_with_asan, QemuAsanHelper},
        cmplog::QemuCmpLogHelper,
        drcov::QemuDrCovHelper,
        edges::QemuEdgeCoverageHelper,
        elf::EasyElf,
        ArchExtras, Emulator, GuestAddr, QemuInstrumentationFilter,
    },
    rangemap::RangeMap,
    std::{env, ops::Range, path::PathBuf},
};

pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub type ClientRangeMap = RangeMap<usize, (u16, String)>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl<'a> Client<'a> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    fn get_args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    fn get_env(&self) -> Result<Vec<(String, String)>, Error> {
        let env = env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>();
        Ok(env)
    }

    fn get_start_pc(emu: &Emulator) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    fn get_range_map(emu: &Emulator) -> Result<ClientRangeMap, Error> {
        Ok(emu
            .mappings()
            .filter_map(|m| {
                println!(
                    "Mapping: 0x{:016x}-0x{:016x}, {}",
                    m.start(),
                    m.end(),
                    m.path().unwrap_or("<EMPTY>")
                );
                m.path()
                    .map(|p| ((m.start() as usize)..(m.end() as usize), p.to_string()))
                    .filter(|(_, p)| !p.is_empty())
            })
            .enumerate()
            .fold(
                RangeMap::<usize, (u16, String)>::new(),
                |mut rm, (i, (r, p))| {
                    rm.insert(r, (i as u16, p));
                    rm
                },
            ))
    }

    fn get_coverage_filter(&self, emu: &Emulator) -> Result<QemuInstrumentationFilter, Error> {
        if let Some(includes) = &self.options.include {
            let rules = includes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationFilter::AllowList(rules))
        } else if let Some(excludes) = &self.options.exclude {
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationFilter::DenyList(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", emu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(QemuInstrumentationFilter::AllowList(vec![range]))
        }
    }

    pub fn run(
        &self,
        state: Option<ClientState>,
        mgr: LlmpRestartingEventManager<ClientState, StdShMemProvider>,
        core_id: CoreId,
    ) -> Result<(), Error> {
        let mut args = self.get_args()?;
        println!("ARGS: {:#?}", args);

        let mut env = self.get_env()?;
        println!("ENV: {:#?}", env);

        let emu = {
            if self.options.is_asan_core(core_id) {
                init_with_asan(&mut args, &mut env)?
            } else {
                Emulator::new(&args, &env)?
            }
        };

        let start_pc = Self::get_start_pc(&emu)?;
        println!("start_pc @ {start_pc:#x}");

        emu.set_breakpoint(start_pc);
        unsafe { emu.run() };
        emu.remove_breakpoint(start_pc);

        let ret_addr: GuestAddr = emu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:}")))?;
        println!("ret_addr = {ret_addr:#x}");
        emu.set_breakpoint(ret_addr);

        let rangemap = Self::get_range_map(&emu)?;

        let is_asan = self.options.is_asan_core(core_id);
        let is_cmplog = self.options.is_cmplog_core(core_id);

        let edge_coverage_helper = QemuEdgeCoverageHelper::new(self.get_coverage_filter(&emu)?);

        if is_asan && is_cmplog {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuCmpLogHelper::default(),
                QemuDrCovHelper::new(
                    self.get_coverage_filter(&emu)?,
                    rangemap,
                    PathBuf::from(&self.options.coverage),
                    false,
                ),
                QemuAsanHelper::default(),
            );
            Instance::builder()
                .options(&self.options)
                .emu(&emu)
                .mgr(mgr)
                .core_id(core_id)
                .build()
                .run(helpers, state)
        } else if is_asan {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuDrCovHelper::new(
                    self.get_coverage_filter(&emu)?,
                    rangemap,
                    PathBuf::from(&self.options.coverage),
                    false,
                ),
                QemuAsanHelper::default(),
            );
            Instance::builder()
                .options(&self.options)
                .emu(&emu)
                .mgr(mgr)
                .core_id(core_id)
                .build()
                .run(helpers, state)
        } else if is_cmplog {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuCmpLogHelper::default(),
                QemuDrCovHelper::new(
                    self.get_coverage_filter(&emu)?,
                    rangemap,
                    PathBuf::from(&self.options.coverage),
                    false,
                ),
            );
            Instance::builder()
                .options(&self.options)
                .emu(&emu)
                .mgr(mgr)
                .core_id(core_id)
                .build()
                .run(helpers, state)
        } else {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuDrCovHelper::new(
                    self.get_coverage_filter(&emu)?,
                    rangemap,
                    PathBuf::from(&self.options.coverage),
                    false,
                ),
            );
            Instance::builder()
                .options(&self.options)
                .emu(&emu)
                .mgr(mgr)
                .core_id(core_id)
                .build()
                .run(helpers, state)
        }
    }
}
