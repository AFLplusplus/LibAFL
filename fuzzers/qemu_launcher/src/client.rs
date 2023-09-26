use std::{env, ops::Range};

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::LlmpRestartingEventManager,
    inputs::BytesInput,
    state::StdState,
    Error,
};
use libafl_bolts::{
    core_affinity::CoreId, rands::StdRand, shmem::StdShMemProvider, tuples::tuple_list,
};
use libafl_qemu::{
    asan::{init_with_asan, QemuAsanHelper},
    cmplog::QemuCmpLogHelper,
    edges::QemuEdgeCoverageHelper,
    elf::EasyElf,
    ArchExtras, Emulator, GuestAddr, QemuInstrumentationFilter,
};

use crate::{instance::Instance, options::FuzzerOptions};

pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl<'a> Client<'a> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    fn env(&self) -> Result<Vec<(String, String)>, Error> {
        let env = env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>();
        Ok(env)
    }

    fn start_pc(emu: &Emulator) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    fn coverage_filter(&self, emu: &Emulator) -> Result<QemuInstrumentationFilter, Error> {
        /* Conversion is required on 32-bit targets, but not on 64-bit ones */
        if let Some(includes) = &self.options.include {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = includes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationFilter::AllowList(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
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
        let mut args = self.args()?;
        log::debug!("ARGS: {:#?}", args);

        let mut env = self.env()?;
        log::debug!("ENV: {:#?}", env);

        let emu = {
            if self.options.is_asan_core(core_id) {
                init_with_asan(&mut args, &mut env)?
            } else {
                Emulator::new(&args, &env)?
            }
        };

        let start_pc = Self::start_pc(&emu)?;
        log::debug!("start_pc @ {start_pc:#x}");

        emu.entry_break(start_pc);

        let ret_addr: GuestAddr = emu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:}")))?;
        log::debug!("ret_addr = {ret_addr:#x}");
        emu.set_breakpoint(ret_addr);

        let is_asan = self.options.is_asan_core(core_id);
        let is_cmplog = self.options.is_cmplog_core(core_id);

        let edge_coverage_helper = QemuEdgeCoverageHelper::new(self.coverage_filter(&emu)?);

        let instance = Instance::builder()
            .options(self.options)
            .emu(&emu)
            .mgr(mgr)
            .core_id(core_id);
        if is_asan && is_cmplog {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuCmpLogHelper::default(),
                QemuAsanHelper::default(),
            );
            instance.build().run(helpers, state)
        } else if is_asan {
            let helpers = tuple_list!(edge_coverage_helper, QemuAsanHelper::default(),);
            instance.build().run(helpers, state)
        } else if is_cmplog {
            let helpers = tuple_list!(edge_coverage_helper, QemuCmpLogHelper::default(),);
            instance.build().run(helpers, state)
        } else {
            let helpers = tuple_list!(edge_coverage_helper,);
            instance.build().run(helpers, state)
        }
    }
}
