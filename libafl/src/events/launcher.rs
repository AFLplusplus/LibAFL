//! The [`Launcher`] launches multiple fuzzer instances in parallel.
//! Thanks to it, we won't need a `for` loop in a shell script...
//!
//! It will hide child output, unless the settings indicate otherwise, or the `LIBAFL_DEBUG_OUTPUT` env variable is set.
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
use core::time::Duration;
use core::{
    fmt::{self, Debug, Formatter},
    num::NonZeroUsize,
};
#[cfg(all(unix, feature = "std", feature = "fork"))]
use std::boxed::Box;
#[cfg(feature = "std")]
use std::net::SocketAddr;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use std::process::Stdio;
#[cfg(all(unix, feature = "std"))]
use std::{fs::File, os::unix::io::AsRawFd};

#[cfg(all(unix, feature = "std", feature = "fork"))]
use libafl_bolts::llmp::Brokers;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use libafl_bolts::llmp::LlmpBroker;
#[cfg(all(unix, feature = "std"))]
use libafl_bolts::os::dup2;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use libafl_bolts::os::startable_self;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use libafl_bolts::{
    core_affinity::get_core_ids,
    os::{fork, ForkResult},
};
use libafl_bolts::{
    core_affinity::{CoreId, Cores},
    shmem::ShMemProvider,
    tuples::{tuple_list, Handle},
};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

use super::EventManagerHooksTuple;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use super::StdLlmpEventHook;
#[cfg(all(unix, feature = "std", feature = "fork", feature = "multi_machine"))]
use crate::events::multi_machine::NodeDescriptor;
#[cfg(all(unix, feature = "std", feature = "fork", feature = "multi_machine"))]
use crate::events::multi_machine::TcpMultiMachineHooks;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use crate::events::{centralized::CentralizedEventManager, CentralizedLlmpHook};
#[cfg(all(unix, feature = "std", feature = "fork"))]
use crate::inputs::UsesInput;
use crate::observers::TimeObserver;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use crate::state::UsesState;
#[cfg(feature = "std")]
use crate::{
    events::{
        llmp::{LlmpRestartingEventManager, LlmpShouldSaveState, ManagerKind, RestartingMgr},
        EventConfig,
    },
    monitors::Monitor,
    state::{HasExecutions, State},
    Error,
};

/// The (internal) `env` that indicates we're running as client.
const _AFL_LAUNCHER_CLIENT: &str = "AFL_LAUNCHER_CLIENT";

/// The env variable to set in order to enable child output
#[cfg(all(feature = "fork", unix))]
const LIBAFL_DEBUG_OUTPUT: &str = "LIBAFL_DEBUG_OUTPUT";

/// Provides a [`Launcher`], which can be used to launch a fuzzing run on a specified list of cores
///
/// Will hide child output, unless the settings indicate otherwise, or the `LIBAFL_DEBUG_OUTPUT` env variable is set.
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    missing_debug_implementations,
    clippy::ignored_unit_patterns
)]
#[derive(TypedBuilder)]
pub struct Launcher<'a, CF, MT, SP> {
    /// The `ShmemProvider` to use
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
    #[cfg(all(unix, feature = "std"))]
    #[builder(default = None)]
    stdout_file: Option<&'a str>,
    /// The time in milliseconds to delay between child launches
    #[builder(default = 10)]
    launch_delay: u64,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[builder(setter(skip), default = None)]
    opened_stdout_file: Option<File>,
    /// A file name to write all client stderr output to. If not specified, output is sent to
    /// `stdout_file`.
    #[cfg(all(unix, feature = "std"))]
    #[builder(default = None)]
    stderr_file: Option<&'a str>,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[builder(setter(skip), default = None)]
    opened_stderr_file: Option<File>,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    /// The time observer for addaptive serialization
    #[builder(default = None)]
    time_ref: Option<Handle<TimeObserver>>,
    /// If this launcher should spawn a new `broker` on `[Self::broker_port]` (default).
    /// The reason you may not want this is, if you already have a [`Launcher`]
    /// with a different configuration (for the same target) running on this machine.
    /// Then, clients launched by this [`Launcher`] can connect to the original `broker`.
    #[builder(default = true)]
    spawn_broker: bool,
    /// Tell the manager to serialize or not the state on restart
    #[builder(default = LlmpShouldSaveState::OnRestart)]
    serialize_state: LlmpShouldSaveState,
}

impl<CF, MT, SP> Debug for Launcher<'_, CF, MT, SP> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("Launcher");
        dbg_struct
            .field("configuration", &self.configuration)
            .field("broker_port", &self.broker_port)
            .field("core", &self.cores)
            .field("spawn_broker", &self.spawn_broker)
            .field("remote_broker_addr", &self.remote_broker_addr);
        #[cfg(all(unix, feature = "std"))]
        {
            dbg_struct
                .field("stdout_file", &self.stdout_file)
                .field("stderr_file", &self.stderr_file);
        }

        dbg_struct.finish_non_exhaustive()
    }
}

impl<'a, CF, MT, SP> Launcher<'a, CF, MT, SP>
where
    MT: Monitor + Clone,
    SP: ShMemProvider,
{
    /// Launch the broker and the clients and fuzz
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    pub fn launch<S>(&mut self) -> Result<(), Error>
    where
        S: State + HasExecutions,
        CF: FnOnce(Option<S>, LlmpRestartingEventManager<(), S, SP>, CoreId) -> Result<(), Error>,
    {
        Self::launch_with_hooks(self, tuple_list!())
    }

    /// Launch the broker and the clients and fuzz
    #[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
    #[allow(unused_mut, clippy::match_wild_err_arm)]
    pub fn launch<S>(&mut self) -> Result<(), Error>
    where
        S: State + HasExecutions,
        CF: FnOnce(Option<S>, LlmpRestartingEventManager<(), S, SP>, CoreId) -> Result<(), Error>,
    {
        Self::launch_with_hooks(self, tuple_list!())
    }
}

#[cfg(feature = "std")]
impl<'a, CF, MT, SP> Launcher<'a, CF, MT, SP>
where
    MT: Monitor + Clone,
    SP: ShMemProvider,
{
    /// Launch the broker and the clients and fuzz with a user-supplied hook
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_lines)]
    pub fn launch_with_hooks<EMH, S>(&mut self, hooks: EMH) -> Result<(), Error>
    where
        S: State + HasExecutions,
        EMH: EventManagerHooksTuple<S> + Clone + Copy,
        CF: FnOnce(Option<S>, LlmpRestartingEventManager<EMH, S, SP>, CoreId) -> Result<(), Error>,
    {
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

        self.opened_stdout_file = self
            .stdout_file
            .map(|filename| File::create(filename).unwrap());
        self.opened_stderr_file = self
            .stderr_file
            .map(|filename| File::create(filename).unwrap());

        #[cfg(feature = "std")]
        let debug_output = std::env::var(LIBAFL_DEBUG_OUTPUT).is_ok();

        // Spawn clients
        let mut index = 0_u64;
        for (id, bind_to) in core_ids.iter().enumerate().take(num_cores) {
            if self.cores.ids.iter().any(|&x| x == id.into()) {
                index += 1;
                self.shmem_provider.pre_fork()?;
                // # Safety
                // Fork is safe in general, apart from potential side effects to the OS and other threads
                match unsafe { fork() }? {
                    ForkResult::Parent(child) => {
                        self.shmem_provider.post_fork(false)?;
                        handles.push(child.pid);
                        #[cfg(feature = "std")]
                        log::info!("child spawned and bound to core {id}");
                    }
                    ForkResult::Child => {
                        // # Safety
                        // A call to `getpid` is safe.
                        log::info!("{:?} PostFork", unsafe { libc::getpid() });
                        self.shmem_provider.post_fork(true)?;

                        #[cfg(feature = "std")]
                        std::thread::sleep(Duration::from_millis(index * self.launch_delay));

                        #[cfg(feature = "std")]
                        if !debug_output {
                            if let Some(file) = &self.opened_stdout_file {
                                dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                if let Some(stderr) = &self.opened_stderr_file {
                                    dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                                } else {
                                    dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                                }
                            }
                        }

                        // Fuzzer client. keeps retrying the connection to broker till the broker starts
                        let builder = RestartingMgr::<EMH, MT, S, SP>::builder()
                            .shmem_provider(self.shmem_provider.clone())
                            .broker_port(self.broker_port)
                            .kind(ManagerKind::Client {
                                cpu_core: Some(*bind_to),
                            })
                            .configuration(self.configuration)
                            .serialize_state(self.serialize_state)
                            .hooks(hooks);
                        let builder = builder.time_ref(self.time_ref.clone());
                        let (state, mgr) = builder.build().launch()?;

                        return (self.run_client.take().unwrap())(state, mgr, *bind_to);
                    }
                };
            }
        }

        if self.spawn_broker {
            #[cfg(feature = "std")]
            log::info!("I am broker!!.");

            // TODO we don't want always a broker here, think about using different laucher process to spawn different configurations
            let builder = RestartingMgr::<EMH, MT, S, SP>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .monitor(Some(self.monitor.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .exit_cleanly_after(Some(NonZeroUsize::try_from(self.cores.ids.len()).unwrap()))
                .configuration(self.configuration)
                .serialize_state(self.serialize_state)
                .hooks(hooks);

            let builder = builder.time_ref(self.time_ref.clone());

            builder.build().launch()?;

            // Broker exited. kill all clients.
            for handle in &handles {
                // # Safety
                // Normal libc call, no dereferences whatsoever
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
    pub fn launch_with_hooks<EMH, S>(&mut self, hooks: EMH) -> Result<(), Error>
    where
        S: State + HasExecutions,
        EMH: EventManagerHooksTuple<S> + Clone + Copy,
        CF: FnOnce(Option<S>, LlmpRestartingEventManager<EMH, S, SP>, CoreId) -> Result<(), Error>,
    {
        use libafl_bolts::core_affinity;

        let is_client = std::env::var(_AFL_LAUNCHER_CLIENT);

        let mut handles = match is_client {
            Ok(core_conf) => {
                let core_id = core_conf.parse()?;
                // the actual client. do the fuzzing

                let builder = RestartingMgr::<EMH, MT, S, SP>::builder()
                    .shmem_provider(self.shmem_provider.clone())
                    .broker_port(self.broker_port)
                    .kind(ManagerKind::Client {
                        cpu_core: Some(CoreId(core_id)),
                    })
                    .configuration(self.configuration)
                    .serialize_state(self.serialize_state)
                    .hooks(hooks);

                let builder = builder.time_ref(self.time_ref.clone());

                let (state, mgr) = builder.build().launch()?;

                return (self.run_client.take().unwrap())(state, mgr, CoreId(core_id));
            }
            Err(std::env::VarError::NotPresent) => {
                // I am a broker
                // before going to the broker loop, spawn n clients

                let core_ids = core_affinity::get_core_ids().unwrap();
                let num_cores = core_ids.len();
                let mut handles = vec![];

                log::info!("spawning on cores: {:?}", self.cores);

                let debug_output = std::env::var("LIBAFL_DEBUG_OUTPUT").is_ok();
                #[cfg(all(feature = "std", unix))]
                {
                    // Set own stdout and stderr as set by the user
                    if !debug_output {
                        let opened_stdout_file = self
                            .stdout_file
                            .map(|filename| File::create(filename).unwrap());
                        let opened_stderr_file = self
                            .stderr_file
                            .map(|filename| File::create(filename).unwrap());
                        if let Some(file) = opened_stdout_file {
                            dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                            if let Some(stderr) = opened_stderr_file {
                                dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                            } else {
                                dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                            }
                        }
                    }
                }
                //spawn clients
                for (id, _) in core_ids.iter().enumerate().take(num_cores) {
                    if self.cores.ids.iter().any(|&x| x == id.into()) {
                        // Forward own stdio to child processes, if requested by user
                        let (mut stdout, mut stderr) = (Stdio::null(), Stdio::null());
                        #[cfg(all(feature = "std", unix))]
                        {
                            if self.stdout_file.is_some() || self.stderr_file.is_some() {
                                stdout = Stdio::inherit();
                                stderr = Stdio::inherit();
                            };
                        }

                        #[cfg(feature = "std")]
                        std::thread::sleep(Duration::from_millis(id as u64 * self.launch_delay));

                        std::env::set_var(_AFL_LAUNCHER_CLIENT, id.to_string());
                        let mut child = startable_self()?;
                        let child = (if debug_output {
                            &mut child
                        } else {
                            child.stdout(stdout);
                            child.stderr(stderr)
                        })
                        .spawn()?;
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

            let builder = RestartingMgr::<EMH, MT, S, SP>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .monitor(Some(self.monitor.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .exit_cleanly_after(Some(NonZeroUsize::try_from(self.cores.ids.len()).unwrap()))
                .configuration(self.configuration)
                .serialize_state(self.serialize_state)
                .hooks(hooks);

            let builder = builder.time_ref(self.time_ref.clone());

            builder.build().launch()?;

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

/// Provides a Launcher, which can be used to launch a fuzzing run on a specified list of cores with a single main and multiple secondary nodes
/// This is for centralized, the 4th argument of the closure should mean if this is the main node.
#[cfg(all(unix, feature = "std", feature = "fork"))]
#[derive(TypedBuilder)]
#[allow(clippy::type_complexity, missing_debug_implementations)]
pub struct CentralizedLauncher<'a, CF, MF, MT, SP> {
    /// The `ShmemProvider` to use
    shmem_provider: SP,
    /// The monitor instance to use
    monitor: MT,
    /// The configuration
    configuration: EventConfig,
    /// Consider this testcase as interesting always if true
    #[builder(default = false)]
    always_interesting: bool,
    /// The 'main' function to run for each secondary client forked. This probably shouldn't return
    #[builder(default, setter(strip_option))]
    secondary_run_client: Option<CF>,
    /// The 'main' function to run for the main evaluator node.
    #[builder(default, setter(strip_option))]
    main_run_client: Option<MF>,
    /// The broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The centralized broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[builder(default = 1338_u16)]
    centralized_broker_port: u16,
    /// The time observer by which to adaptively serialize
    #[builder(default = None)]
    time_obs: Option<Handle<TimeObserver>>,
    /// The list of cores to run on
    cores: &'a Cores,
    /// A file name to write all client output to
    #[builder(default = None)]
    stdout_file: Option<&'a str>,
    /// The time in milliseconds to delay between child launches
    #[builder(default = 10)]
    launch_delay: u64,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[builder(setter(skip), default = None)]
    opened_stdout_file: Option<File>,
    /// A file name to write all client stderr output to. If not specified, output is sent to
    /// `stdout_file`.
    #[builder(default = None)]
    stderr_file: Option<&'a str>,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[builder(setter(skip), default = None)]
    opened_stderr_file: Option<File>,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
    #[cfg(feature = "multi_machine")]
    multi_machine_node_descriptor: NodeDescriptor<SocketAddr>,
    /// If this launcher should spawn a new `broker` on `[Self::broker_port]` (default).
    /// The reason you may not want this is, if you already have a [`Launcher`]
    /// with a different configuration (for the same target) running on this machine.
    /// Then, clients launched by this [`Launcher`] can connect to the original `broker`.
    #[builder(default = true)]
    spawn_broker: bool,
    /// Tell the manager to serialize or not the state on restart
    #[builder(default = LlmpShouldSaveState::OnRestart)]
    serialize_state: LlmpShouldSaveState,
}

#[cfg(all(unix, feature = "std", feature = "fork"))]
impl<CF, MF, MT, SP> Debug for CentralizedLauncher<'_, CF, MF, MT, SP> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Launcher")
            .field("configuration", &self.configuration)
            .field("broker_port", &self.broker_port)
            .field("core", &self.cores)
            .field("spawn_broker", &self.spawn_broker)
            .field("remote_broker_addr", &self.remote_broker_addr)
            .field("stdout_file", &self.stdout_file)
            .field("stderr_file", &self.stderr_file)
            .finish_non_exhaustive()
    }
}

/// The standard inner manager of centralized
pub type StdCentralizedInnerMgr<S, SP> = LlmpRestartingEventManager<(), S, SP>;

#[cfg(all(unix, feature = "std", feature = "fork"))]
impl<'a, CF, MF, MT, SP> CentralizedLauncher<'a, CF, MF, MT, SP>
where
    MT: Monitor + Clone + 'static,
    SP: ShMemProvider + 'static,
{
    /// Launch a standard Centralized-based fuzzer
    pub fn launch<S>(&mut self) -> Result<(), Error>
    where
        S: State,
        S::Input: Send + Sync + 'static,
        CF: FnOnce(
            Option<S>,
            CentralizedEventManager<StdCentralizedInnerMgr<S, SP>, (), S, SP>,
            CoreId,
        ) -> Result<(), Error>,
        MF: FnOnce(
            Option<S>,
            CentralizedEventManager<StdCentralizedInnerMgr<S, SP>, (), S, SP>,
            CoreId,
        ) -> Result<(), Error>,
    {
        let restarting_mgr_builder = |centralized_launcher: &Self, core_to_bind: CoreId| {
            // Fuzzer client. keeps retrying the connection to broker till the broker starts
            let builder = RestartingMgr::<(), MT, S, SP>::builder()
                .always_interesting(centralized_launcher.always_interesting)
                .shmem_provider(centralized_launcher.shmem_provider.clone())
                .broker_port(centralized_launcher.broker_port)
                .kind(ManagerKind::Client {
                    cpu_core: Some(core_to_bind),
                })
                .configuration(centralized_launcher.configuration)
                .serialize_state(centralized_launcher.serialize_state)
                .hooks(tuple_list!());

            let builder = builder.time_ref(centralized_launcher.time_obs.clone());

            builder.build().launch()
        };

        self.launch_generic(restarting_mgr_builder, restarting_mgr_builder)
    }
}

#[cfg(all(unix, feature = "std", feature = "fork"))]
impl<'a, CF, MF, MT, SP> CentralizedLauncher<'a, CF, MF, MT, SP>
where
    MT: Monitor + Clone + 'static,
    SP: ShMemProvider + 'static,
{
    /// Launch a Centralized-based fuzzer.
    /// - `main_inner_mgr_builder` will be called to build the inner manager of the main node.
    /// - `secondary_inner_mgr_builder` will be called to build the inner manager of the secondary nodes.
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_lines)]
    pub fn launch_generic<EM, EMB, S>(
        &mut self,
        main_inner_mgr_builder: EMB,
        secondary_inner_mgr_builder: EMB,
    ) -> Result<(), Error>
    where
        S: State,
        S::Input: Send + Sync + 'static,
        CF: FnOnce(Option<S>, CentralizedEventManager<EM, (), S, SP>, CoreId) -> Result<(), Error>,
        EM: UsesState<State = S>,
        EMB: FnOnce(&Self, CoreId) -> Result<(Option<S>, EM), Error>,
        MF: FnOnce(
            Option<S>,
            CentralizedEventManager<EM, (), S, SP>, // No broker_hooks for centralized EM
            CoreId,
        ) -> Result<(), Error>,
        <<EM as UsesState>::State as UsesInput>::Input: Send + Sync + 'static,
    {
        let mut main_inner_mgr_builder = Some(main_inner_mgr_builder);
        let mut secondary_inner_mgr_builder = Some(secondary_inner_mgr_builder);

        if self.cores.ids.is_empty() {
            return Err(Error::illegal_argument(
                "No cores to spawn on given, cannot launch anything.",
            ));
        }

        if self.secondary_run_client.is_none() {
            return Err(Error::illegal_argument(
                "No client callback provided".to_string(),
            ));
        }

        let core_ids = get_core_ids().unwrap();
        let num_cores = core_ids.len();
        let mut handles = vec![];

        log::debug!("spawning on cores: {:?}", self.cores);

        self.opened_stdout_file = self
            .stdout_file
            .map(|filename| File::create(filename).unwrap());
        self.opened_stderr_file = self
            .stderr_file
            .map(|filename| File::create(filename).unwrap());

        let debug_output = std::env::var(LIBAFL_DEBUG_OUTPUT).is_ok();

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

                        std::thread::sleep(Duration::from_millis(index * self.launch_delay));

                        if !debug_output {
                            if let Some(file) = &self.opened_stdout_file {
                                dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                if let Some(stderr) = &self.opened_stderr_file {
                                    dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                                } else {
                                    dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                                }
                            }
                        }

                        if index == 1 {
                            // Main client
                            log::debug!("Running main client on PID {}", std::process::id());
                            let (state, mgr) =
                                main_inner_mgr_builder.take().unwrap()(self, *bind_to)?;

                            let mut centralized_event_manager_builder =
                                CentralizedEventManager::builder();
                            centralized_event_manager_builder =
                                centralized_event_manager_builder.is_main(true);

                            let c_mgr = centralized_event_manager_builder.build_on_port(
                                mgr,
                                // tuple_list!(multi_machine_event_manager_hook.take().unwrap()),
                                tuple_list!(),
                                self.shmem_provider.clone(),
                                self.centralized_broker_port,
                                self.time_obs.clone(),
                            )?;

                            self.main_run_client.take().unwrap()(state, c_mgr, *bind_to)
                        } else {
                            // Secondary clients
                            log::debug!("Running secondary client on PID {}", std::process::id());
                            let (state, mgr) =
                                secondary_inner_mgr_builder.take().unwrap()(self, *bind_to)?;

                            let centralized_builder = CentralizedEventManager::builder();

                            let c_mgr = centralized_builder.build_on_port(
                                mgr,
                                tuple_list!(),
                                self.shmem_provider.clone(),
                                self.centralized_broker_port,
                                self.time_obs.clone(),
                            )?;

                            self.secondary_run_client.take().unwrap()(state, c_mgr, *bind_to)
                        }
                    }?,
                };
            }
        }

        #[cfg(feature = "multi_machine")]
        // Create this after forks, to avoid problems with tokio runtime

        // # Safety
        // The `multi_machine_receiver_hook` needs messages to outlive the receiver.
        // The underlying memory region for incoming messages lives longer than the async thread processing them.
        let TcpMultiMachineHooks {
            sender: multi_machine_sender_hook,
            receiver: multi_machine_receiver_hook,
        } = unsafe {
            TcpMultiMachineHooks::builder()
                .node_descriptor(self.multi_machine_node_descriptor.clone())
                .build::<<<EM as UsesState>::State as UsesInput>::Input>()?
        };

        let mut brokers = Brokers::new();

        // Add centralized broker
        brokers.add(Box::new({
            #[cfg(feature = "multi_machine")]
            let centralized_hooks = tuple_list!(
                CentralizedLlmpHook::<S::Input>::new()?,
                multi_machine_receiver_hook,
            );

            #[cfg(not(feature = "multi_machine"))]
            let centralized_hooks = tuple_list!(CentralizedLlmpHook::<S::Input>::new()?);

            // TODO switch to false after solving the bug
            LlmpBroker::with_keep_pages_attach_to_tcp(
                self.shmem_provider.clone(),
                centralized_hooks,
                self.centralized_broker_port,
                true,
            )?
        }));

        #[cfg(feature = "multi_machine")]
        assert!(
            self.spawn_broker,
            "Multi machine is not compatible with externally spawned brokers for now."
        );

        // If we should add another broker, add it to other brokers.
        if self.spawn_broker {
            log::info!("I am broker!!.");

            #[cfg(not(feature = "multi_machine"))]
            let llmp_hook =
                tuple_list!(StdLlmpEventHook::<S::Input, MT>::new(self.monitor.clone())?);

            #[cfg(feature = "multi_machine")]
            let llmp_hook = tuple_list!(
                StdLlmpEventHook::<S::Input, MT>::new(self.monitor.clone())?,
                multi_machine_sender_hook,
            );

            let mut broker = LlmpBroker::create_attach_to_tcp(
                self.shmem_provider.clone(),
                llmp_hook,
                self.broker_port,
            )?;

            if let Some(remote_broker_addr) = self.remote_broker_addr {
                log::info!("B2b: Connecting to {:?}", &remote_broker_addr);
                broker.inner_mut().connect_b2b(remote_broker_addr)?;
            };

            let exit_cleanly_after = NonZeroUsize::try_from(self.cores.ids.len()).unwrap();

            broker
                .inner_mut()
                .set_exit_cleanly_after(exit_cleanly_after);

            brokers.add(Box::new(broker));
        }

        log::debug!(
            "Brokers have been initialized on port {}.",
            std::process::id()
        );

        // Loop over all the brokers that should be polled
        brokers.loop_with_timeouts(Duration::from_secs(30), Some(Duration::from_millis(5)));

        #[cfg(feature = "llmp_debug")]
        log::info!("The last client quit. Exiting.");

        // Brokers exited. kill all clients.
        for handle in &handles {
            unsafe {
                libc::kill(*handle, libc::SIGINT);
            }
        }

        Err(Error::shutting_down())
    }
}
