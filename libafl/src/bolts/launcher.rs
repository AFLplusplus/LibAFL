//! The [`Launcher`] launches multiple fuzzer instances in parallel.
//! Thanks to it, we won't need a `for` loop in a shell script...
//!
//! To use multiple [`Launcher`]`s` for individual configurations,
//! we can set `spawn_broker` to `false` on all but one.
//!
//! To connect multiple nodes together via TCP, we can use the `remote_broker_addr`.
//! (this requires the `llmp_bind_public` compile-time feature for `LibAFL`).
//!
//! On `Unix` systems, the [`Launcher`] will use `fork` if the `fork` feature is used for `LibAFL`.
//! Else, it will start subsequent nodes with the same commandline, and will set special `env` variables accordingly.

use alloc::string::ToString;
#[cfg(feature = "std")]
use core::marker::PhantomData;
use core::{
    fmt::{self, Debug, Formatter},
    num::NonZeroUsize,
};
#[cfg(feature = "std")]
use std::net::SocketAddr;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use std::process::Stdio;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use std::{fs::File, os::unix::io::AsRawFd};

#[cfg(feature = "std")]
use serde::de::DeserializeOwned;
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

use super::core_affinity::CoreId;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use crate::bolts::{
    core_affinity::get_core_ids,
    os::{dup2, fork, ForkResult},
};
use crate::inputs::UsesInput;
#[cfg(feature = "std")]
use crate::{
    bolts::{core_affinity::Cores, shmem::ShMemProvider},
    events::{EventConfig, LlmpRestartingEventManager, ManagerKind, RestartingMgr},
    monitors::Monitor,
    state::{HasClientPerfMonitor, HasExecutions},
    Error,
};

/// The (internal) `env` that indicates we're running as client.
const _AFL_LAUNCHER_CLIENT: &str = "AFL_LAUNCHER_CLIENT";
/// Provides a Launcher, which can be used to launch a fuzzing run on a specified list of cores
#[cfg(feature = "std")]
#[derive(TypedBuilder)]
#[allow(clippy::type_complexity, missing_debug_implementations)]
pub struct Launcher<'a, CF, MT, S, SP>
where
    CF: FnOnce(Option<S>, LlmpRestartingEventManager<S, SP>, CoreId) -> Result<(), Error>,
    S::Input: 'a,
    MT: Monitor,
    SP: ShMemProvider + 'static,
    S: DeserializeOwned + UsesInput + 'a,
{
    /// The ShmemProvider to use
    shmem_provider: SP,
    /// The monitor instance to use
    monitor: MT,
    /// The configuration
    configuration: EventConfig,
    /// The 'main' function to run for each client forked. This probably shouldn't return
    #[builder(default, setter(strip_option))]
    run_client: Option<CF>,
    /// The broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a Cores,
    /// A file name to write all client output to
    #[builder(default = None)]
    stdout_file: Option<&'a str>,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    /// If this launcher should spawn a new `broker` on `[Self::broker_port]` (default).
    /// The reason you may not want this is, if you already have a [`Launcher`]
    /// with a different configuration (for the same target) running on this machine.
    /// Then, clients launched by this [`Launcher`] can connect to the original `broker`.
    #[builder(default = true)]
    spawn_broker: bool,
    /// Tell the manager to serialize or not the state on restart
    #[builder(default = true)]
    serialize_state: bool,
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<(&'a S, &'a SP)>,
}

impl<CF, MT, S, SP> Debug for Launcher<'_, CF, MT, S, SP>
where
    CF: FnOnce(Option<S>, LlmpRestartingEventManager<S, SP>, CoreId) -> Result<(), Error>,
    MT: Monitor + Clone,
    SP: ShMemProvider + 'static,
    S: DeserializeOwned + UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Launcher")
            .field("configuration", &self.configuration)
            .field("broker_port", &self.broker_port)
            .field("core", &self.cores)
            .field("spawn_broker", &self.spawn_broker)
            .field("remote_broker_addr", &self.remote_broker_addr)
            .field("stdout_file", &self.stdout_file)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl<'a, CF, MT, S, SP> Launcher<'a, CF, MT, S, SP>
where
    CF: FnOnce(Option<S>, LlmpRestartingEventManager<S, SP>, CoreId) -> Result<(), Error>,
    MT: Monitor + Clone,
    S: DeserializeOwned + UsesInput + HasExecutions + HasClientPerfMonitor,
    SP: ShMemProvider + 'static,
{
    /// Launch the broker and the clients and fuzz
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[allow(clippy::similar_names)]
    pub fn launch(&mut self) -> Result<(), Error> {
        if self.cores.ids.is_empty() {
            return Err(Error::illegal_argument(
                "No cores to spawn on given, cannot launch anything.",
            ));
        }

        if self.run_client.is_none() {
            return Err(Error::illegal_argument(
                "No client callback provided".to_string(),
            ));
        }

        let core_ids = get_core_ids().unwrap();
        let num_cores = core_ids.len();
        let mut handles = vec![];

        log::info!("spawning on cores: {:?}", self.cores);

        #[cfg(feature = "std")]
        let stdout_file = self
            .stdout_file
            .map(|filename| File::create(filename).unwrap());

        #[cfg(feature = "std")]
        let debug_output = std::env::var("LIBAFL_DEBUG_OUTPUT").is_ok();

        // Spawn clients
        let mut index = 0_u64;
        for (id, bind_to) in core_ids.iter().enumerate().take(num_cores) {
            if self.cores.ids.iter().any(|&x| x == id.into()) {
                index += 1;
                self.shmem_provider.pre_fork()?;
                match unsafe { fork() }? {
                    ForkResult::Parent(child) => {
                        self.shmem_provider.post_fork(false)?;
                        handles.push(child.pid);
                        #[cfg(feature = "std")]
                        log::info!("child spawned and bound to core {id}");
                    }
                    ForkResult::Child => {
                        log::info!("{:?} PostFork", unsafe { libc::getpid() });
                        self.shmem_provider.post_fork(true)?;

                        #[cfg(feature = "std")]
                        std::thread::sleep(std::time::Duration::from_millis(index * 10));

                        #[cfg(feature = "std")]
                        if !debug_output {
                            if let Some(file) = stdout_file {
                                dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                            }
                        }

                        // Fuzzer client. keeps retrying the connection to broker till the broker starts
                        let (state, mgr) = RestartingMgr::<MT, S, SP>::builder()
                            .shmem_provider(self.shmem_provider.clone())
                            .broker_port(self.broker_port)
                            .kind(ManagerKind::Client {
                                cpu_core: Some(*bind_to),
                            })
                            .configuration(self.configuration)
                            .serialize_state(self.serialize_state)
                            .build()
                            .launch()?;

                        return (self.run_client.take().unwrap())(state, mgr, *bind_to);
                    }
                };
            }
        }

        if self.spawn_broker {
            #[cfg(feature = "std")]
            log::info!("I am broker!!.");

            // TODO we don't want always a broker here, think about using different laucher process to spawn different configurations
            RestartingMgr::<MT, S, SP>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .monitor(Some(self.monitor.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .exit_cleanly_after(Some(NonZeroUsize::try_from(self.cores.ids.len()).unwrap()))
                .configuration(self.configuration)
                .serialize_state(self.serialize_state)
                .build()
                .launch()?;

            // Broker exited. kill all clients.
            for handle in &handles {
                unsafe {
                    libc::kill(*handle, libc::SIGINT);
                }
            }
        } else {
            for handle in &handles {
                let mut status = 0;
                log::info!("Not spawning broker (spawn_broker is false). Waiting for fuzzer children to exit...");
                unsafe {
                    libc::waitpid(*handle, &mut status, 0);
                    if status != 0 {
                        log::info!("Client with pid {handle} exited with status {status}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Launch the broker and the clients and fuzz
    #[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
    #[allow(unused_mut, clippy::match_wild_err_arm)]
    pub fn launch(&mut self) -> Result<(), Error> {
        use crate::bolts::core_affinity;

        let is_client = std::env::var(_AFL_LAUNCHER_CLIENT);

        let mut handles = match is_client {
            Ok(core_conf) => {
                let core_id = core_conf.parse()?;

                //todo: silence stdout and stderr for clients

                // the actual client. do the fuzzing
                let (state, mgr) = RestartingMgr::<MT, S, SP>::builder()
                    .shmem_provider(self.shmem_provider.clone())
                    .broker_port(self.broker_port)
                    .kind(ManagerKind::Client {
                        cpu_core: Some(CoreId(core_id)),
                    })
                    .configuration(self.configuration)
                    .serialize_state(self.serialize_state)
                    .build()
                    .launch()?;

                return (self.run_client.take().unwrap())(state, mgr, CoreId(core_id));
            }
            Err(std::env::VarError::NotPresent) => {
                // I am a broker
                // before going to the broker loop, spawn n clients

                #[cfg(windows)]
                if self.stdout_file.is_some() {
                    log::info!("Child process file stdio is not supported on Windows yet. Dumping to stdout instead...");
                }

                let core_ids = core_affinity::get_core_ids().unwrap();
                let num_cores = core_ids.len();
                let mut handles = vec![];

                log::info!("spawning on cores: {:?}", self.cores);

                //spawn clients
                for (id, _) in core_ids.iter().enumerate().take(num_cores) {
                    if self.cores.ids.iter().any(|&x| x == id.into()) {
                        let stdio = if self.stdout_file.is_some() {
                            Stdio::inherit()
                        } else {
                            Stdio::null()
                        };

                        std::env::set_var(_AFL_LAUNCHER_CLIENT, id.to_string());
                        let child = startable_self()?.stdout(stdio).spawn()?;
                        handles.push(child);
                    }
                }

                handles
            }
            Err(_) => panic!("Env variables are broken, received non-unicode!"),
        };

        // It's fine to check this after the client spawn loop - since we won't have spawned any clients...
        // Doing it later means one less check in each spawned process.
        if self.cores.ids.is_empty() {
            return Err(Error::illegal_argument(
                "No cores to spawn on given, cannot launch anything.",
            ));
        }

        if self.spawn_broker {
            #[cfg(feature = "std")]
            log::info!("I am broker!!.");

            RestartingMgr::<MT, S, SP>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .monitor(Some(self.monitor.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .exit_cleanly_after(Some(NonZeroUsize::try_from(self.cores.ids.len()).unwrap()))
                .configuration(self.configuration)
                .serialize_state(self.serialize_state)
                .build()
                .launch()?;

            //broker exited. kill all clients.
            for handle in &mut handles {
                handle.kill()?;
            }
        } else {
            log::info!("Not spawning broker (spawn_broker is false). Waiting for fuzzer children to exit...");
            for handle in &mut handles {
                let ecode = handle.wait()?;
                if !ecode.success() {
                    log::info!("Client with handle {handle:?} exited with {ecode:?}");
                }
            }
        }

        Ok(())
    }
}
