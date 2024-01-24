use std::{env, ops::Range};

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    inputs::BytesInput,
    monitors::Monitor,
    state::StdState,
    Error,
};
use libafl_bolts::{core_affinity::CoreId, rands::StdRand, tuples::tuple_list};
#[cfg(feature = "injections")]
use libafl_qemu::injections::QemuInjectionHelper;
use libafl_qemu::{
    asan::{init_with_asan, QemuAsanHelper},
    cmplog::QemuCmpLogHelper,
    edges::QemuEdgeCoverageHelper,
    elf::EasyElf,
    ArchExtras, Emulator, GuestAddr, QemuInstrumentationAddressRangeFilter,
};

use crate::{
    instance::{ClientMgr, Instance},
    options::FuzzerOptions,
};

#[allow(clippy::module_name_repetitions)]
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

    #[allow(clippy::unused_self)] // Api should look the same as args above
    fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    fn start_pc(emu: &Emulator) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    #[allow(clippy::similar_names)] // elf != self
    fn coverage_filter(
        &self,
        emu: &Emulator,
    ) -> Result<QemuInstrumentationAddressRangeFilter, Error> {
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
            Ok(QemuInstrumentationAddressRangeFilter::AllowList(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationAddressRangeFilter::DenyList(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", emu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(QemuInstrumentationAddressRangeFilter::AllowList(vec![
                range,
            ]))
        }
    }

    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        core_id: CoreId,
    ) -> Result<(), Error> {
        let mut args = self.args()?;
        log::debug!("ARGS: {:#?}", args);

        let mut env = self.env();
        log::debug!("ENV: {:#?}", env);

        let (emu, mut asan) = {
            if self.options.is_asan_core(core_id) {
                let (emu, asan) = init_with_asan(&mut args, &mut env)?;
                (emu, Some(asan))
            } else {
                (Emulator::new(&args, &env)?, None)
            }
        };

        let start_pc = Self::start_pc(&emu)?;
        log::debug!("start_pc @ {start_pc:#x}");

        #[cfg(not(feature = "injections"))]
        let injection_helper = None;

        #[cfg(feature = "injections")]
        let injection_helper = self
            .options
            .injections
            .as_ref()
            .and_then(|injections_file| {
                let lower = injections_file.to_lowercase();
                if lower.ends_with("yaml") || lower.ends_with("yml") {
                    Some(QemuInjectionHelper::from_yaml(injections_file).unwrap())
                } else if lower.ends_with("toml") {
                    Some(QemuInjectionHelper::from_toml(injections_file).unwrap())
                } else {
                    None
                }
            });

        let extra_tokens = injection_helper.as_ref().map(|h| h.tokens.clone());

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
            .core_id(core_id)
            .extra_tokens(extra_tokens);

        if is_asan && is_cmplog {
            if let Some(injection_helper) = injection_helper {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_helper,
                        QemuCmpLogHelper::default(),
                        QemuAsanHelper::default(asan.take().unwrap()),
                        injection_helper,
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_helper,
                        QemuCmpLogHelper::default(),
                        QemuAsanHelper::default(asan.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_asan {
            if let Some(injection_helper) = injection_helper {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_helper,
                        QemuAsanHelper::default(asan.take().unwrap()),
                        injection_helper
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_helper,
                        QemuAsanHelper::default(asan.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_cmplog {
            if let Some(injection_helper) = injection_helper {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_helper,
                        QemuCmpLogHelper::default(),
                        injection_helper
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(edge_coverage_helper, QemuCmpLogHelper::default()),
                    state,
                )
            }
        } else if let Some(injection_helper) = injection_helper {
            instance
                .build()
                .run(tuple_list!(edge_coverage_helper, injection_helper), state)
        } else {
            instance
                .build()
                .run(tuple_list!(edge_coverage_helper), state)
        }
    }
}
