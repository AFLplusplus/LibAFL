use std::env;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::ClientDescription,
    inputs::BytesInput,
    monitors::Monitor,
    state::StdState,
    Error,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
#[cfg(feature = "injections")]
use libafl_qemu::modules::injections::InjectionModule;
use libafl_qemu::{
    modules::{
        asan::{init_qemu_with_asan, AsanModule},
        asan_guest::{init_qemu_with_asan_guest, AsanGuestModule},
        cmplog::CmpLogModule,
        DrCovModule,
    },
    Qemu,
};

use crate::{
    harness::Harness,
    instance::{ClientMgr, Instance},
    options::FuzzerOptions,
};

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl Client<'_> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    pub fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    #[allow(clippy::unused_self)] // Api should look the same as args above
    pub fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    #[allow(clippy::too_many_lines)]
    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        client_description: ClientDescription,
    ) -> Result<(), Error> {
        let core_id = client_description.core_id();
        let mut args = self.args()?;
        Harness::edit_args(&mut args);
        log::debug!("ARGS: {:#?}", args);

        let mut env = self.env();
        Harness::edit_env(&mut env);
        log::debug!("ENV: {:#?}", env);

        let is_asan = self.options.is_asan_core(core_id);
        let is_asan_guest = self.options.is_asan_guest_core(core_id);

        if is_asan && is_asan_guest {
            Err(Error::empty_optional("Multiple ASAN modes configured"))?;
        }

        let (qemu, mut asan, mut asan_lib) = {
            if is_asan {
                let (emu, asan) = init_qemu_with_asan(&mut args, &mut env)?;
                (emu, Some(asan), None)
            } else if is_asan_guest {
                let (emu, asan_lib) = init_qemu_with_asan_guest(&mut args, &mut env)?;
                (emu, None, Some(asan_lib))
            } else {
                (Qemu::init(&args)?, None, None)
            }
        };

        #[cfg(not(feature = "injections"))]
        let injection_module = None;

        #[cfg(feature = "injections")]
        let injection_module = self
            .options
            .injections
            .as_ref()
            .and_then(|injections_file| {
                let lower = injections_file.to_lowercase();
                if lower.ends_with("yaml") || lower.ends_with("yml") {
                    Some(InjectionModule::from_yaml(injections_file).unwrap())
                } else if lower.ends_with("toml") {
                    Some(InjectionModule::from_toml(injections_file).unwrap())
                } else {
                    None
                }
            });

        let harness = Harness::init(qemu).expect("Error setting up harness.");

        let is_cmplog = self.options.is_cmplog_core(core_id);

        let extra_tokens = injection_module
            .as_ref()
            .map(|h| h.tokens.clone())
            .unwrap_or_default();

        let instance_builder = Instance::builder()
            .options(self.options)
            .qemu(qemu)
            .harness(harness)
            .mgr(mgr)
            .client_description(client_description)
            .extra_tokens(extra_tokens);

        if self.options.rerun_input.is_some() && self.options.drcov.is_some() {
            // Special code path for re-running inputs with DrCov.
            // TODO: Add ASan support, injection support
            let drcov = self.options.drcov.as_ref().unwrap();
            let drcov = DrCovModule::builder()
                .filename(drcov.clone())
                .full_trace(true)
                .build();
            instance_builder.build().run(tuple_list!(drcov), state)
        } else if is_asan && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                        injection_module,
                    ),
                    state,
                )
            } else {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_asan_guest && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::default(qemu, &asan_lib.take().unwrap()),
                        injection_module
                    ),
                    state,
                )
            } else {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::default(qemu, &asan_lib.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_asan {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(AsanModule::default(asan.take().unwrap()), injection_module),
                    state,
                )
            } else {
                instance_builder.build().run(
                    tuple_list!(AsanModule::default(asan.take().unwrap()),),
                    state,
                )
            }
        } else if is_asan_guest {
            let modules = tuple_list!(AsanGuestModule::default(qemu, &asan_lib.take().unwrap()));
            instance_builder.build().run(modules, state)
        } else if is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(CmpLogModule::default(), injection_module),
                    state,
                )
            } else {
                instance_builder
                    .build()
                    .run(tuple_list!(CmpLogModule::default()), state)
            }
        } else if let Some(injection_module) = injection_module {
            instance_builder
                .build()
                .run(tuple_list!(injection_module), state)
        } else {
            instance_builder.build().run(tuple_list!(), state)
        }
    }
}
