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

#[cfg(unix)]
use alloc::boxed::Box;
use alloc::string::String;
use core::{
    fmt,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    num::NonZeroUsize,
    time::Duration,
};
use std::process::Stdio;
#[cfg(unix)]
use std::vec::Vec;

use libafl_bolts::{
    core_affinity::{CoreId, Cores, get_core_ids},
    os::startable_self,
    shmem::ShMemProvider,
    tuples::tuple_list,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(unix)]
use {
    crate::events::{CentralizedLlmpHook, StdLlmpEventHook, centralized::CentralizedEventManager},
    alloc::string::ToString,
    libafl_bolts::{
        llmp::{Broker, Brokers, LlmpBroker},
        os::{ForkResult, dup2, fork},
    },
    std::{fs::File, os::unix::io::AsRawFd},
};

#[cfg(feature = "tcp_manager")]
use crate::HasMetadata;
#[cfg(all(unix, feature = "multi_machine"))]
use crate::events::multi_machine::{NodeDescriptor, TcpMultiMachineHooks};
#[cfg(unix)]
use crate::inputs::Input;
#[cfg(feature = "tcp_manager")]
use crate::state::{HasCurrentTestcase, HasExecutions, HasImported, HasSolutions, Stoppable};
use crate::{
    Error,
    events::{
        EventConfig, EventManagerHooksTuple, LlmpRestartingEventManager, LlmpShouldSaveState,
        ManagerKind, RestartingMgr,
    },
    monitors::Monitor,
};

/// The (internal) `env` that indicates we're running as client.
const _AFL_LAUNCHER_CLIENT: &str = "AFL_LAUNCHER_CLIENT";

/// The env variable to set in order to enable child output
#[cfg(unix)]
const LIBAFL_DEBUG_OUTPUT: &str = "LIBAFL_DEBUG_OUTPUT";

/// Information about this client from the launcher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDescription {
    id: usize,
    overcommit_id: usize,
    core_id: CoreId,
}

impl ClientDescription {
    /// Create a [`ClientDescription`]
    #[must_use]
    pub fn new(id: usize, overcommit_id: usize, core_id: CoreId) -> Self {
        Self {
            id,
            overcommit_id,
            core_id,
        }
    }

    /// Id unique to all clients spawned by this launcher
    #[must_use]
    pub fn id(&self) -> usize {
        self.id
    }

    /// [`CoreId`] this client is bound to
    #[must_use]
    pub fn core_id(&self) -> CoreId {
        self.core_id
    }

    /// Incremental id unique for all clients on the same core
    #[must_use]
    pub fn overcommit_id(&self) -> usize {
        self.overcommit_id
    }

    /// Create a string representation safe for environment variables
    #[must_use]
    pub fn to_safe_string(&self) -> String {
        format!("{}_{}_{}", self.id, self.overcommit_id, self.core_id.0)
    }

    /// Parse the string created by [`Self::to_safe_string`].
    #[must_use]
    pub fn from_safe_string(input: &str) -> Self {
        let mut iter = input.split('_');
        let id = iter.next().unwrap().parse().unwrap();
        let overcommit_id = iter.next().unwrap().parse().unwrap();
        let core_id = iter.next().unwrap().parse::<usize>().unwrap().into();
        Self {
            id,
            overcommit_id,
            core_id,
        }
    }
}

/// Provides a [`Launcher`], which can be used to launch a fuzzing run on a specified list of cores
///
/// Will hide child output, unless the settings indicate otherwise, or the `LIBAFL_DEBUG_OUTPUT` env variable is set.
pub struct Launcher<'a, CF, MT, SP> {
    /// The `ShmemProvider` to use
    shmem_provider: SP,
    /// The monitor instance to use
    monitor: Option<MT>,
    /// The configuration
    configuration: EventConfig,
    /// The 'main' function to run for each client forked. This probably shouldn't return
    run_client: Option<CF>,
    /// The broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    broker_port: u16,
    /// The centralized broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    centralized_broker_port: u16,
    /// The list of cores to run on
    cores: &'a Cores,
    /// The number of clients to spawn on each core
    overcommit: usize,
    /// A file name to write all client output to
    #[cfg(unix)]
    stdout_file: Option<&'a str>,
    /// The time in milliseconds to delay between child launches
    launch_delay: u64,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(unix)]
    opened_stdout_file: Option<File>,
    /// A file name to write all client stderr output to. If not specified, output is sent to
    /// `stdout_file`.
    #[cfg(unix)]
    stderr_file: Option<&'a str>,
    /// The actual, opened, `stdout_file` - so that we keep it open until the end
    #[cfg(unix)]
    opened_stderr_file: Option<File>,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    remote_broker_addr: Option<SocketAddr>,
    #[cfg(feature = "multi_machine")]
    multi_machine_node_descriptor: NodeDescriptor<SocketAddr>,
    /// If this launcher should spawn a new `broker` on `[Self::broker_port]` (default).
    /// The reason you may not want this is, if you already have a [`Launcher`]
    /// with a different configuration (for the same target) running on this machine.
    /// Then, clients launched by this [`Launcher`] can connect to the original `broker`.
    spawn_broker: bool,
    /// Tell the manager to serialize or not the state on restart
    serialize_state: LlmpShouldSaveState,
    /// If this launcher should use `fork` to spawn a new instance. Otherwise it will try to re-launch the current process with exactly the same parameters.
    #[cfg(unix)]
    fork: bool,
}

impl<'a> Launcher<'a, (), (), ()> {
    /// The builder for the launcher
    #[must_use]
    pub fn builder() -> LauncherBuilder<'a, (), (), ()> {
        LauncherBuilder::new()
    }
}

/// The builder for the launcher
#[derive(Debug)]
pub struct LauncherBuilder<'a, CF, MT, SP> {
    shmem_provider: Option<SP>,
    monitor: Option<MT>,
    configuration: Option<EventConfig>,
    run_client: Option<CF>,
    broker_port: u16,
    centralized_broker_port: u16,
    cores: Option<&'a Cores>,
    overcommit: usize,
    #[cfg(unix)]
    stdout_file: Option<&'a str>,
    launch_delay: u64,
    #[cfg(unix)]
    stderr_file: Option<&'a str>,
    remote_broker_addr: Option<SocketAddr>,
    #[cfg(feature = "multi_machine")]
    multi_machine_node_descriptor: Option<NodeDescriptor<SocketAddr>>,
    spawn_broker: bool,
    serialize_state: LlmpShouldSaveState,
    #[cfg(unix)]
    fork: bool,
}

impl LauncherBuilder<'_, (), (), ()> {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            shmem_provider: None,
            monitor: None,
            configuration: None,
            run_client: None,
            broker_port: 1337,
            centralized_broker_port: 1338,
            cores: None,
            overcommit: 1,
            #[cfg(unix)]
            stdout_file: None,
            launch_delay: 10,
            #[cfg(unix)]
            stderr_file: None,
            remote_broker_addr: None,
            #[cfg(feature = "multi_machine")]
            multi_machine_node_descriptor: None,
            spawn_broker: true,
            serialize_state: LlmpShouldSaveState::OnRestart,
            #[cfg(unix)]
            fork: true,
        }
    }
}

impl Default for LauncherBuilder<'_, (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, CF, MT, SP> LauncherBuilder<'a, CF, MT, SP> {
    /// The `ShmemProvider` to use
    #[must_use]
    pub fn shmem_provider<NewSP>(
        self,
        shmem_provider: NewSP,
    ) -> LauncherBuilder<'a, CF, MT, NewSP> {
        LauncherBuilder {
            shmem_provider: Some(shmem_provider),
            monitor: self.monitor,
            configuration: self.configuration,
            run_client: self.run_client,
            broker_port: self.broker_port,
            centralized_broker_port: self.centralized_broker_port,
            cores: self.cores,
            overcommit: self.overcommit,
            #[cfg(unix)]
            stdout_file: self.stdout_file,
            launch_delay: self.launch_delay,
            #[cfg(unix)]
            stderr_file: self.stderr_file,
            remote_broker_addr: self.remote_broker_addr,
            #[cfg(feature = "multi_machine")]
            multi_machine_node_descriptor: self.multi_machine_node_descriptor,
            spawn_broker: self.spawn_broker,
            serialize_state: self.serialize_state,
            #[cfg(unix)]
            fork: self.fork,
        }
    }

    /// The monitor instance to use
    #[must_use]
    pub fn monitor<NewMT>(self, monitor: NewMT) -> LauncherBuilder<'a, CF, NewMT, SP> {
        LauncherBuilder {
            shmem_provider: self.shmem_provider,
            monitor: Some(monitor),
            configuration: self.configuration,
            run_client: self.run_client,
            broker_port: self.broker_port,
            centralized_broker_port: self.centralized_broker_port,
            cores: self.cores,
            overcommit: self.overcommit,
            #[cfg(unix)]
            stdout_file: self.stdout_file,
            launch_delay: self.launch_delay,
            #[cfg(unix)]
            stderr_file: self.stderr_file,
            remote_broker_addr: self.remote_broker_addr,
            #[cfg(feature = "multi_machine")]
            multi_machine_node_descriptor: self.multi_machine_node_descriptor,
            spawn_broker: self.spawn_broker,
            serialize_state: self.serialize_state,
            #[cfg(unix)]
            fork: self.fork,
        }
    }

    /// The configuration
    #[must_use]
    pub fn configuration(mut self, configuration: EventConfig) -> Self {
        self.configuration = Some(configuration);
        self
    }

    /// The 'main' function to run for each client forked. This probably shouldn't return
    #[must_use]
    pub fn run_client<NewCF>(self, run_client: NewCF) -> LauncherBuilder<'a, NewCF, MT, SP> {
        LauncherBuilder {
            shmem_provider: self.shmem_provider,
            monitor: self.monitor,
            configuration: self.configuration,
            run_client: Some(run_client),
            broker_port: self.broker_port,
            centralized_broker_port: self.centralized_broker_port,
            cores: self.cores,
            overcommit: self.overcommit,
            #[cfg(unix)]
            stdout_file: self.stdout_file,
            launch_delay: self.launch_delay,
            #[cfg(unix)]
            stderr_file: self.stderr_file,
            remote_broker_addr: self.remote_broker_addr,
            #[cfg(feature = "multi_machine")]
            multi_machine_node_descriptor: self.multi_machine_node_descriptor,
            spawn_broker: self.spawn_broker,
            serialize_state: self.serialize_state,
            #[cfg(unix)]
            fork: self.fork,
        }
    }

    /// The broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[must_use]
    pub fn broker_port(mut self, broker_port: u16) -> Self {
        self.broker_port = broker_port;
        self
    }

    /// The centralized broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[must_use]
    pub fn centralized_broker_port(mut self, centralized_broker_port: u16) -> Self {
        self.centralized_broker_port = centralized_broker_port;
        self
    }

    /// The list of cores to run on
    #[must_use]
    pub fn cores(mut self, cores: &'a Cores) -> Self {
        self.cores = Some(cores);
        self
    }

    /// The number of clients to spawn on each core
    #[must_use]
    pub fn overcommit(mut self, overcommit: usize) -> Self {
        self.overcommit = overcommit;
        self
    }

    /// A file name to write all client output to
    #[cfg(unix)]
    #[must_use]
    pub fn stdout_file(mut self, stdout_file: Option<&'a str>) -> Self {
        self.stdout_file = stdout_file;
        self
    }

    /// The time in milliseconds to delay between child launches
    #[must_use]
    pub fn launch_delay(mut self, launch_delay: u64) -> Self {
        self.launch_delay = launch_delay;
        self
    }

    /// A file name to write all client stderr output to. If not specified, output is sent to
    /// `stdout_file`.
    #[cfg(unix)]
    #[must_use]
    pub fn stderr_file(mut self, stderr_file: Option<&'a str>) -> Self {
        self.stderr_file = stderr_file;
        self
    }

    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[must_use]
    pub fn remote_broker_addr(mut self, remote_broker_addr: Option<SocketAddr>) -> Self {
        self.remote_broker_addr = remote_broker_addr;
        self
    }

    /// The node descriptor for multi-machine clusters
    #[cfg(feature = "multi_machine")]
    #[must_use]
    pub fn multi_machine_node_descriptor(
        mut self,
        multi_machine_node_descriptor: NodeDescriptor<SocketAddr>,
    ) -> Self {
        self.multi_machine_node_descriptor = Some(multi_machine_node_descriptor);
        self
    }

    /// If this launcher should spawn a new `broker` on `[Self::broker_port]` (default).
    #[must_use]
    pub fn spawn_broker(mut self, spawn_broker: bool) -> Self {
        self.spawn_broker = spawn_broker;
        self
    }

    /// Tell the manager to serialize or not the state on restart
    #[must_use]
    pub fn serialize_state(mut self, serialize_state: LlmpShouldSaveState) -> Self {
        self.serialize_state = serialize_state;
        self
    }

    /// If this launcher should use `fork` to spawn a new instance. Otherwise it will try to re-launch the current process with exactly the same parameters.
    #[cfg(unix)]
    #[must_use]
    pub fn fork(mut self, fork: bool) -> Self {
        self.fork = fork;
        self
    }

    /// Build the launcher
    pub fn build(self) -> Launcher<'a, CF, MT, SP> {
        Launcher::<CF, MT, SP> {
            shmem_provider: self.shmem_provider.expect("shmem_provider not set"),
            monitor: self.monitor,
            configuration: self.configuration.expect("configuration not set"),
            run_client: self.run_client,
            broker_port: self.broker_port,
            centralized_broker_port: self.centralized_broker_port,
            cores: self.cores.expect("cores not set"),
            overcommit: self.overcommit,
            #[cfg(unix)]
            stdout_file: self.stdout_file,
            launch_delay: self.launch_delay,
            #[cfg(unix)]
            opened_stdout_file: None,
            #[cfg(unix)]
            stderr_file: self.stderr_file,
            #[cfg(unix)]
            opened_stderr_file: None,
            remote_broker_addr: self.remote_broker_addr,
            #[cfg(feature = "multi_machine")]
            multi_machine_node_descriptor: self
                .multi_machine_node_descriptor
                .expect("multi_machine_node_descriptor not set"),
            spawn_broker: self.spawn_broker,
            serialize_state: self.serialize_state,
            #[cfg(unix)]
            fork: self.fork,
        }
    }
}

impl<CF, MT, SP> Debug for Launcher<'_, CF, MT, SP> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("Launcher");
        dbg_struct
            .field("configuration", &self.configuration)
            .field("broker_port", &self.broker_port)
            .field("centralized_broker_port", &self.centralized_broker_port)
            .field("core", &self.cores)
            .field("spawn_broker", &self.spawn_broker)
            .field("remote_broker_addr", &self.remote_broker_addr);
        #[cfg(unix)]
        {
            dbg_struct
                .field("stdout_file", &self.stdout_file)
                .field("stderr_file", &self.stderr_file);
        }

        dbg_struct.finish_non_exhaustive()
    }
}

impl<CF, MT, SP> Launcher<'_, CF, MT, SP>
where
    MT: Monitor,
    SP: ShMemProvider,
{
    /// Launch the broker and the clients and fuzz
    pub fn launch<I, S>(self) -> Result<(), Error>
    where
        CF: FnOnce(
            Option<S>,
            LlmpRestartingEventManager<(), I, S, SP::ShMem, SP>,
            ClientDescription,
        ) -> Result<(), Error>,
        I: DeserializeOwned,
        S: DeserializeOwned + Serialize,
    {
        Self::launch_with_hooks(self, tuple_list!())
    }

    /// Launch the broker and the clients and fuzz with a user-supplied hook
    pub fn launch_with_hooks<EMH, I, S>(self, hooks: EMH) -> Result<(), Error>
    where
        CF: FnOnce(
            Option<S>,
            LlmpRestartingEventManager<EMH, I, S, SP::ShMem, SP>,
            ClientDescription,
        ) -> Result<(), Error>,
        EMH: EventManagerHooksTuple<I, S> + Clone + Copy,
        I: DeserializeOwned,
        S: DeserializeOwned + Serialize,
    {
        let spawn_mgr = |launcher: &Self,
                         client_description: Option<ClientDescription>,
                         monitor: Option<MT>| {
            if let Some(client_description) = client_description {
                let builder = RestartingMgr::<EMH, I, MT, S, SP>::builder()
                    .shmem_provider(launcher.shmem_provider.clone())
                    .broker_port(launcher.broker_port)
                    .kind(ManagerKind::Client { client_description })
                    .configuration(launcher.configuration)
                    .serialize_state(launcher.serialize_state)
                    .hooks(hooks);
                #[cfg(unix)]
                let builder = builder.fork(launcher.fork);
                builder.build().launch()
            } else {
                let builder = RestartingMgr::<EMH, I, MT, S, SP>::builder()
                    .shmem_provider(launcher.shmem_provider.clone())
                    .monitor(monitor)
                    .broker_port(launcher.broker_port)
                    .kind(ManagerKind::Broker)
                    .remote_broker_addr(launcher.remote_broker_addr)
                    .exit_cleanly_after(Some(
                        NonZeroUsize::try_from(launcher.cores.ids.len()).unwrap(),
                    ))
                    .configuration(launcher.configuration)
                    .serialize_state(launcher.serialize_state)
                    .hooks(hooks);
                #[cfg(unix)]
                let builder = builder.fork(launcher.fork);

                builder.build().launch()
            }
        };

        self.launch_common(spawn_mgr)
    }

    /// Launch the broker and the clients and fuzz with a user-supplied hook
    #[cfg(feature = "tcp_manager")]
    #[expect(clippy::too_many_lines)]
    pub fn launch_tcp<EMH, I, S>(self, hooks: EMH) -> Result<(), Error>
    where
        CF: FnOnce(
            Option<S>,
            crate::events::tcp::TcpRestartingEventManager<EMH, I, S, SP::ShMem, SP>,
            ClientDescription,
        ) -> Result<(), Error>,
        EMH: EventManagerHooksTuple<I, S> + Clone + Copy,
        I: Input,
        S: DeserializeOwned
            + Serialize
            + HasExecutions
            + HasMetadata
            + HasImported
            + HasSolutions<I>
            + HasCurrentTestcase<I>
            + Stoppable,
        MT: Clone,
    {
        let spawn_mgr = |launcher: &Self,
                         client_description: Option<ClientDescription>,
                         monitor: Option<MT>| {
            if let Some(client_description) = client_description {
                let builder = crate::events::tcp::TcpRestartingMgr::<EMH, I, MT, S, SP>::builder()
                    .shmem_provider(launcher.shmem_provider.clone())
                    .broker_port(launcher.broker_port)
                    .kind(crate::events::tcp::TcpManagerKind::Client {
                        cpu_core: Some(client_description.core_id()),
                    })
                    .configuration(launcher.configuration)
                    .serialize_state(launcher.serialize_state.on_restart())
                    .hooks(hooks);
                #[cfg(unix)]
                let builder = builder.fork(launcher.fork);
                builder.build().launch()
            } else {
                let builder = crate::events::tcp::TcpRestartingMgr::<EMH, I, MT, S, SP>::builder()
                    .shmem_provider(launcher.shmem_provider.clone())
                    .monitor(monitor)
                    .broker_port(launcher.broker_port)
                    .kind(crate::events::tcp::TcpManagerKind::Broker)
                    .remote_broker_addr(launcher.remote_broker_addr)
                    .exit_cleanly_after(Some(
                        NonZeroUsize::try_from(launcher.cores.ids.len()).unwrap(),
                    ))
                    .configuration(launcher.configuration)
                    .serialize_state(launcher.serialize_state.on_restart())
                    .hooks(hooks);
                #[cfg(unix)]
                let builder = builder.fork(launcher.fork);
                builder.build().launch()
            }
        };

        self.launch_common(spawn_mgr)
    }

    #[expect(clippy::too_many_lines, clippy::match_wild_err_arm)]
    fn launch_common<EM, F, S>(mut self, spawn_mgr: F) -> Result<(), Error>
    where
        F: Fn(&Self, Option<ClientDescription>, Option<MT>) -> Result<(Option<S>, EM), Error>,
        CF: FnOnce(Option<S>, EM, ClientDescription) -> Result<(), Error>,
    {
        #[cfg(unix)]
        let use_fork = self.fork;
        #[cfg(not(unix))]
        let use_fork = false;

        if use_fork {
            #[cfg(unix)]
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

                let core_ids = get_core_ids()?;
                let mut handles = vec![];

                log::info!("spawning on cores: {:?}", self.cores);

                self.opened_stdout_file = self
                    .stdout_file
                    .map(|filename| File::create(filename).unwrap());
                self.opened_stderr_file = self
                    .stderr_file
                    .map(|filename| File::create(filename).unwrap());

                let debug_output = std::env::var(LIBAFL_DEBUG_OUTPUT).is_ok();

                // Spawn clients
                let mut index = 0_usize;
                for bind_to in core_ids {
                    if self.cores.ids.contains(&bind_to) {
                        for overcommit_id in 0..self.overcommit {
                            index += 1;
                            self.shmem_provider.pre_fork()?;
                            // # Safety
                            // Fork is safe in general, apart from potential side effects to the OS and other threads
                            match unsafe { fork() }? {
                                ForkResult::Parent(child) => {
                                    self.shmem_provider.post_fork(false)?;
                                    handles.push(child.pid);
                                    log::info!(
                                        "child spawned with id {index} and bound to core {bind_to:?}"
                                    );
                                }
                                ForkResult::Child => {
                                    // # Safety
                                    // A call to `getpid` is safe.
                                    log::info!("{:?} PostFork", unsafe { libc::getpid() });
                                    self.shmem_provider.post_fork(true)?;

                                    std::thread::sleep(Duration::from_millis(
                                        index as u64 * self.launch_delay,
                                    ));

                                    if !debug_output && let Some(file) = &self.opened_stdout_file {
                                        // # Safety
                                        // We assume the file descriptors are valid here
                                        unsafe {
                                            dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                            match &self.opened_stderr_file {
                                                Some(stderr) => {
                                                    dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                                                }
                                                _ => {
                                                    dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                                                }
                                            }
                                        }
                                    }

                                    let client_description =
                                        ClientDescription::new(index, overcommit_id, bind_to);

                                    let (state, mgr) =
                                        spawn_mgr(&self, Some(client_description.clone()), None)?;

                                    return (self.run_client.take().unwrap())(
                                        state,
                                        mgr,
                                        client_description,
                                    );
                                }
                            }
                        }
                    }
                }

                if self.spawn_broker {
                    log::info!("I am broker!!.");
                    let monitor = self.monitor.take();
                    spawn_mgr(&self, None, monitor)?;
                }

                Self::wait_for_pids(&handles, self.spawn_broker);
            }
            // This is the fork part for unix
            #[cfg(not(unix))]
            {
                unreachable!("Forking not supported");
            }
        } else {
            // spawn logic
            let is_client = std::env::var(_AFL_LAUNCHER_CLIENT);

            let mut handles = match is_client {
                Ok(core_conf) => {
                    let client_description = ClientDescription::from_safe_string(&core_conf);
                    // the actual client. do the fuzzing

                    let (state, mgr) = spawn_mgr(&self, Some(client_description.clone()), None)?;

                    return (self.run_client.take().unwrap())(state, mgr, client_description);
                }
                Err(std::env::VarError::NotPresent) => {
                    // I am a broker
                    // before going to the broker loop, spawn n clients

                    let core_ids = get_core_ids().unwrap();
                    let mut handles = vec![];

                    log::info!("spawning on cores: {:?}", self.cores);

                    let debug_output = std::env::var("LIBAFL_DEBUG_OUTPUT").is_ok();
                    #[cfg(unix)]
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
                                // # Safety
                                // We assume the file descriptors are valid here
                                unsafe {
                                    dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                    if let Some(stderr) = opened_stderr_file {
                                        dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                                    } else {
                                        dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                                    }
                                }
                            }
                        }
                    }
                    //spawn clients
                    let mut index = 0;
                    for core_id in core_ids {
                        if self.cores.ids.contains(&core_id) {
                            for overcommit_i in 0..self.overcommit {
                                index += 1;
                                // Forward own stdio to child processes, if requested by user
                                #[allow(unused_mut)] // mut only on certain cfgs
                                let (mut stdout, mut stderr) = (Stdio::null(), Stdio::null());
                                #[cfg(unix)]
                                {
                                    if self.stdout_file.is_some() || self.stderr_file.is_some() {
                                        stdout = Stdio::inherit();
                                        stderr = Stdio::inherit();
                                    }
                                }

                                std::thread::sleep(Duration::from_millis(
                                    core_id.0 as u64 * self.launch_delay,
                                ));

                                let client_description =
                                    ClientDescription::new(index, overcommit_i, core_id);
                                // # Safety
                                // This is set only once, in here, for the child.
                                unsafe {
                                    std::env::set_var(
                                        _AFL_LAUNCHER_CLIENT,
                                        client_description.to_safe_string(),
                                    );
                                }
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
                log::info!("I am broker!!.");
                let monitor = self.monitor.take();
                spawn_mgr(&self, None, monitor)?;
            }

            Self::wait_for_child_processes(&mut handles, self.spawn_broker);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn wait_for_pids(handles: &[i32], spawn_broker: bool) {
        if spawn_broker {
            // Broker exited. kill all clients and wait for them to avoid zombies.
            for handle in handles {
                // # Safety
                // Normal libc call, no dereferences whatsoever
                unsafe {
                    libc::kill(*handle, libc::SIGINT);
                }
            }
            // Wait for all children to avoid zombie processes
            for handle in handles {
                unsafe {
                    libc::waitpid(*handle, core::ptr::null_mut(), 0);
                }
            }
        } else {
            for handle in handles {
                let mut status = 0;
                log::info!(
                    "Not spawning broker (spawn_broker is false). Waiting for fuzzer children to exit..."
                );
                unsafe {
                    libc::waitpid(*handle, &raw mut status, 0);
                    if status != 0 {
                        log::info!("Client with pid {handle} exited with status {status}");
                    }
                }
            }
        }
    }

    fn wait_for_child_processes(handles: &mut [std::process::Child], spawn_broker: bool) {
        if spawn_broker {
            for handle in &mut *handles {
                let _ = handle.kill();
                let _ = handle.wait();
            }
        } else {
            for handle in &mut *handles {
                let ecode = handle.wait();
                if ecode.as_ref().is_ok_and(|e| !e.success()) {
                    log::info!("Client with handle {handle:?} exited with {ecode:?}");
                }
            }
        }
    }

    /// Launch the common broker logic
    #[cfg(unix)]
    pub fn launch_common_broker<I, S>(self, handles: Vec<libc::pid_t>) -> Result<(), Error>
    where
        I: Input + Send + Sync + 'static,
        S: DeserializeOwned + Serialize,
        MT: Monitor + Clone + 'static,
        SP: ShMemProvider + 'static,
    {
        // Create this after forks, to avoid problems with tokio runtime

        // # Safety
        // The `multi_machine_receiver_hook` needs messages to outlive the receiver.
        // The underlying memory region for incoming messages lives longer than the async thread processing them.
        #[cfg(feature = "multi_machine")]
        let TcpMultiMachineHooks {
            sender: multi_machine_sender_hook,
            receiver: multi_machine_receiver_hook,
        } = unsafe {
            TcpMultiMachineHooks::builder()
                .node_descriptor(self.multi_machine_node_descriptor.clone())
                .build::<I>()?
        };

        let mut brokers = Brokers::new();
        let exit_cleanly_after = NonZeroUsize::try_from(self.cores.ids.len()).unwrap();

        // Add centralized broker
        brokers.add(Box::new({
            #[cfg(feature = "multi_machine")]
            let centralized_hooks = tuple_list!(
                CentralizedLlmpHook::<I>::new()?,
                multi_machine_receiver_hook,
            );

            #[cfg(not(feature = "multi_machine"))]
            let centralized_hooks = tuple_list!(CentralizedLlmpHook::<I>::new()?);

            // TODO switch to false after solving the bug
            let mut broker = LlmpBroker::with_keep_pages_attach_to_tcp(
                self.shmem_provider.clone(),
                centralized_hooks,
                self.centralized_broker_port,
                true,
            )?;
            broker.set_exit_after(exit_cleanly_after);
            broker
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
            let llmp_hook = tuple_list!(StdLlmpEventHook::<I, MT>::new(
                self.monitor
                    .clone()
                    .expect("Monitor must be provided when spawning a broker")
            )?);

            #[cfg(feature = "multi_machine")]
            let llmp_hook = tuple_list!(
                StdLlmpEventHook::<I, MT>::new(
                    self.monitor
                        .clone()
                        .expect("Monitor must be provided when spawning a broker")
                )?,
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
            }

            broker.set_exit_after(exit_cleanly_after);

            brokers.add(Box::new(broker));
        }
        log::debug!("Broker has been initialized; pid {}.", std::process::id());

        // Loop over all the brokers that should be polled
        brokers.loop_with_timeouts(Duration::from_secs(30), Some(Duration::from_millis(5)));

        #[cfg(feature = "llmp_debug")]
        log::info!("The last client quit. Exiting.");

        // Brokers exited. kill all clients and wait for them to avoid zombies.
        for handle in &handles {
            unsafe {
                libc::kill(*handle, libc::SIGINT);
            }
        }
        // Wait for all children to avoid zombie processes
        for handle in &handles {
            unsafe {
                libc::waitpid(*handle, core::ptr::null_mut(), 0);
            }
        }

        Err(Error::shutting_down())
    }
}

/// The standard inner manager of centralized
#[cfg(unix)]
pub type StdCentralizedInnerMgr<I, S, SHM, SP> = LlmpRestartingEventManager<(), I, S, SHM, SP>;

/// A launcher for centralized fuzzing
#[cfg(unix)]
pub struct CentralizedLauncher<'a, CF, MF, MT, SP> {
    launcher: Launcher<'a, CF, MT, SP>,
    main_run_client: Option<MF>,
}

#[cfg(unix)]
impl<CF, MF, MT, SP> Debug for CentralizedLauncher<'_, CF, MF, MT, SP> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CentralizedLauncher")
            .field("launcher", &self.launcher)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl<'a> CentralizedLauncher<'a, (), (), (), ()> {
    /// Create a builder for [`CentralizedLauncher`]
    #[must_use]
    pub fn builder() -> CentralizedLauncherBuilder<'a, (), (), (), ()> {
        CentralizedLauncherBuilder::new()
    }
}

#[cfg(unix)]
impl<'a, CF, MF, MT, SP> CentralizedLauncher<'a, CF, MF, MT, SP>
where
    MT: Monitor + Clone + 'static,
    SP: ShMemProvider + 'static,
{
    /// Launch a Centralized-based fuzzer
    pub fn launch_centralized<I, S>(self) -> Result<(), Error>
    where
        I: Input + Send + Sync + 'static,
        S: DeserializeOwned + Serialize,
        CF: FnOnce(
            Option<S>,
            CentralizedEventManager<
                StdCentralizedInnerMgr<I, S, SP::ShMem, SP>,
                I,
                S,
                SP::ShMem,
                SP,
            >,
            ClientDescription,
        ) -> Result<(), Error>,
        MF: FnOnce(
            Option<S>,
            CentralizedEventManager<
                StdCentralizedInnerMgr<I, S, SP::ShMem, SP>,
                I,
                S,
                SP::ShMem,
                SP,
            >,
            ClientDescription,
        ) -> Result<(), Error>,
    {
        let restarting_mgr_builder =
            |launcher: &Launcher<'a, CF, MT, SP>, client_description: ClientDescription| {
                // Fuzzer client. keeps retrying the connection to broker till the broker starts
                let builder = RestartingMgr::<(), I, MT, S, SP>::builder()
                    .shmem_provider(launcher.shmem_provider.clone())
                    .broker_port(launcher.broker_port)
                    .kind(ManagerKind::Client { client_description })
                    .configuration(launcher.configuration)
                    .serialize_state(launcher.serialize_state)
                    .hooks(tuple_list!());
                #[cfg(unix)]
                let builder = builder.fork(launcher.fork);

                builder.build().launch()
            };

        self.launch_centralized_custom(restarting_mgr_builder, restarting_mgr_builder)
    }

    /// Launch a Centralized-based fuzzer.
    /// - `main_inner_mgr_builder` will be called to build the inner manager of the main node.
    /// - `secondary_inner_mgr_builder` will be called to build the inner manager of the secondary nodes.
    pub fn launch_centralized_custom<EM, EMB, I, S>(
        mut self,
        main_inner_mgr_builder: EMB,
        secondary_inner_mgr_builder: EMB,
    ) -> Result<(), Error>
    where
        I: Input + Send + Sync + 'static,
        S: DeserializeOwned + Serialize,
        CF: FnOnce(
            Option<S>,
            CentralizedEventManager<EM, I, S, SP::ShMem, SP>,
            ClientDescription,
        ) -> Result<(), Error>,
        EMB: FnOnce(&Launcher<'a, CF, MT, SP>, ClientDescription) -> Result<(Option<S>, EM), Error>,
        MF: FnOnce(
            Option<S>,
            CentralizedEventManager<EM, I, S, SP::ShMem, SP>, // No broker_hooks for centralized EM
            ClientDescription,
        ) -> Result<(), Error>,
    {
        if !self.launcher.fork {
            return Err(Error::illegal_argument(
                "CentralizedLauncher only supports fork-based spawning.",
            ));
        }

        let mut main_inner_mgr_builder = Some(main_inner_mgr_builder);
        let mut secondary_inner_mgr_builder = Some(secondary_inner_mgr_builder);

        if self.launcher.cores.ids.is_empty() {
            return Err(Error::illegal_argument(
                "No cores to spawn on given, cannot launch anything.",
            ));
        }

        if self.launcher.run_client.is_none() {
            return Err(Error::illegal_argument(
                "No client callback provided".to_string(),
            ));
        }

        let core_ids = get_core_ids().unwrap();
        let mut handles = vec![];

        log::debug!("spawning on cores: {:?}", self.launcher.cores);

        self.launcher.opened_stdout_file = self
            .launcher
            .stdout_file
            .map(|filename| File::create(filename).unwrap());
        self.launcher.opened_stderr_file = self
            .launcher
            .stderr_file
            .map(|filename| File::create(filename).unwrap());

        let debug_output = std::env::var(LIBAFL_DEBUG_OUTPUT).is_ok();

        // Force shmem server startup in the parent process before forking
        // This prevents a race condition where multiple children try to start the server.
        // We keep the shmem alive to ensure the server stays running.
        let _dummy_shmem = self.launcher.shmem_provider.clone().new_shmem(4096)?;

        // Spawn clients
        let mut index = 0_usize;
        for bind_to in core_ids {
            if self.launcher.cores.ids.contains(&bind_to) {
                for overcommit_id in 0..self.launcher.overcommit {
                    index += 1;
                    self.launcher.shmem_provider.pre_fork()?;
                    match unsafe { fork() }? {
                        ForkResult::Parent(child) => {
                            self.launcher.shmem_provider.post_fork(false)?;
                            handles.push(child.pid);
                            log::info!(
                                "child with client id {index} spawned and bound to core {bind_to:?}"
                            );
                        }
                        ForkResult::Child => {
                            log::info!("{:?} PostFork", unsafe { libc::getpid() });
                            self.launcher.shmem_provider.post_fork(true)?;

                            std::thread::sleep(Duration::from_millis(
                                index as u64 * self.launcher.launch_delay,
                            ));

                            if !debug_output && let Some(file) = &self.launcher.opened_stdout_file {
                                // # Safety
                                // We assume the file descriptors are valid here
                                unsafe {
                                    dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                                    match &self.launcher.opened_stderr_file {
                                        Some(stderr) => {
                                            dup2(stderr.as_raw_fd(), libc::STDERR_FILENO)?;
                                        }
                                        _ => {
                                            dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                                        }
                                    }
                                }
                            }

                            let client_description =
                                ClientDescription::new(index, overcommit_id, bind_to);

                            if index == 1 {
                                // Main client
                                log::debug!("Running main client on PID {}", std::process::id());
                                let (state, mgr) = main_inner_mgr_builder.take().unwrap()(
                                    &self.launcher,
                                    client_description.clone(),
                                )?;

                                let mut centralized_event_manager_builder =
                                    CentralizedEventManager::builder();
                                centralized_event_manager_builder =
                                    centralized_event_manager_builder.is_main(true);

                                let c_mgr = centralized_event_manager_builder.build_on_port(
                                    mgr,
                                    // tuple_list!(multi_machine_event_manager_hook.take().unwrap()),
                                    self.launcher.shmem_provider.clone(),
                                    self.launcher.centralized_broker_port,
                                )?;

                                self.main_run_client.take().unwrap()(
                                    state,
                                    c_mgr,
                                    client_description,
                                )?;
                                Err(Error::shutting_down())
                            } else {
                                // Secondary clients
                                log::debug!(
                                    "Running secondary client on PID {}",
                                    std::process::id()
                                );
                                let (state, mgr) = secondary_inner_mgr_builder.take().unwrap()(
                                    &self.launcher,
                                    client_description.clone(),
                                )?;

                                let centralized_builder = CentralizedEventManager::builder();

                                let c_mgr = centralized_builder.build_on_port(
                                    mgr,
                                    self.launcher.shmem_provider.clone(),
                                    self.launcher.centralized_broker_port,
                                )?;

                                self.launcher.run_client.take().unwrap()(
                                    state,
                                    c_mgr,
                                    client_description,
                                )?;
                                Err(Error::shutting_down())
                            }
                        }?,
                    }
                }
            }
        }

        self.launcher.launch_common_broker::<I, S>(handles)
    }
}

/// The builder for [`CentralizedLauncher`]
#[cfg(unix)]
#[derive(Debug)]
pub struct CentralizedLauncherBuilder<'a, CF, MF, MT, SP> {
    builder: LauncherBuilder<'a, CF, MT, SP>,
    main_run_client: Option<MF>,
}

#[cfg(unix)]
impl CentralizedLauncherBuilder<'_, (), (), (), ()> {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: LauncherBuilder::new(),
            main_run_client: None,
        }
    }
}

#[cfg(unix)]
impl<'a, CF, MF, MT, SP> CentralizedLauncherBuilder<'a, CF, MF, MT, SP> {
    /// The `ShmemProvider` to use
    #[must_use]
    pub fn shmem_provider<NewSP>(
        self,
        shmem_provider: NewSP,
    ) -> CentralizedLauncherBuilder<'a, CF, MF, MT, NewSP> {
        CentralizedLauncherBuilder {
            builder: self.builder.shmem_provider(shmem_provider),
            main_run_client: self.main_run_client,
        }
    }

    /// The monitor instance to use
    #[must_use]
    pub fn monitor<NewMT>(
        self,
        monitor: NewMT,
    ) -> CentralizedLauncherBuilder<'a, CF, MF, NewMT, SP> {
        CentralizedLauncherBuilder {
            builder: self.builder.monitor(monitor),
            main_run_client: self.main_run_client,
        }
    }

    /// The configuration
    #[must_use]
    pub fn configuration(self, configuration: EventConfig) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.configuration(configuration),
            main_run_client: self.main_run_client,
        }
    }

    /// The 'main' function to run for each client forked. This probably shouldn't return
    #[must_use]
    pub fn run_client<NewCF>(
        self,
        run_client: NewCF,
    ) -> CentralizedLauncherBuilder<'a, NewCF, MF, MT, SP> {
        CentralizedLauncherBuilder {
            builder: self.builder.run_client(run_client),
            main_run_client: self.main_run_client,
        }
    }

    /// The 'main' function to run for each client forked. This shouldn not return.
    #[must_use]
    pub fn secondary_run_client<NewCF>(
        self,
        run_client: NewCF,
    ) -> CentralizedLauncherBuilder<'a, NewCF, MF, MT, SP> {
        self.run_client(run_client)
    }

    /// The 'main' function to run for the main evaluator node.
    #[must_use]
    pub fn main_run_client<NewMF>(
        self,
        main_run_client: NewMF,
    ) -> CentralizedLauncherBuilder<'a, CF, NewMF, MT, SP> {
        CentralizedLauncherBuilder {
            builder: self.builder,
            main_run_client: Some(main_run_client),
        }
    }

    /// The broker port to use
    #[must_use]
    pub fn broker_port(self, broker_port: u16) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.broker_port(broker_port),
            main_run_client: self.main_run_client,
        }
    }

    /// The centralized broker port to use
    #[must_use]
    pub fn centralized_broker_port(self, centralized_broker_port: u16) -> Self {
        CentralizedLauncherBuilder {
            builder: self
                .builder
                .centralized_broker_port(centralized_broker_port),
            main_run_client: self.main_run_client,
        }
    }

    /// The list of cores to run on
    #[must_use]
    pub fn cores(self, cores: &'a Cores) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.cores(cores),
            main_run_client: self.main_run_client,
        }
    }

    /// The number of clients to spawn on each core
    #[must_use]
    pub fn overcommit(self, overcommit: usize) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.overcommit(overcommit),
            main_run_client: self.main_run_client,
        }
    }

    /// A file name to write all client output to
    #[must_use]
    pub fn stdout_file(self, stdout_file: Option<&'a str>) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.stdout_file(stdout_file),
            main_run_client: self.main_run_client,
        }
    }

    /// The time in milliseconds to delay between child launches
    #[must_use]
    pub fn launch_delay(self, launch_delay: u64) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.launch_delay(launch_delay),
            main_run_client: self.main_run_client,
        }
    }

    /// A file name to write all client stderr output to
    #[must_use]
    pub fn stderr_file(self, stderr_file: Option<&'a str>) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.stderr_file(stderr_file),
            main_run_client: self.main_run_client,
        }
    }

    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    #[must_use]
    pub fn remote_broker_addr(self, remote_broker_addr: Option<SocketAddr>) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.remote_broker_addr(remote_broker_addr),
            main_run_client: self.main_run_client,
        }
    }

    /// The node descriptor for multi-machine clusters
    #[cfg(feature = "multi_machine")]
    #[must_use]
    pub fn multi_machine_node_descriptor(
        self,
        multi_machine_node_descriptor: NodeDescriptor<SocketAddr>,
    ) -> Self {
        CentralizedLauncherBuilder {
            builder: self
                .builder
                .multi_machine_node_descriptor(multi_machine_node_descriptor),
            main_run_client: self.main_run_client,
        }
    }

    /// If this launcher should spawn a new `broker`
    #[must_use]
    pub fn spawn_broker(self, spawn_broker: bool) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.spawn_broker(spawn_broker),
            main_run_client: self.main_run_client,
        }
    }

    /// Tell the manager to serialize or not the state on restart
    #[must_use]
    pub fn serialize_state(self, serialize_state: LlmpShouldSaveState) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.serialize_state(serialize_state),
            main_run_client: self.main_run_client,
        }
    }

    /// If this launcher should use `fork` to spawn a new instance.
    #[must_use]
    pub fn fork(self, fork: bool) -> Self {
        CentralizedLauncherBuilder {
            builder: self.builder.fork(fork),
            main_run_client: self.main_run_client,
        }
    }

    /// Build the launcher
    pub fn build(self) -> CentralizedLauncher<'a, CF, MF, MT, SP> {
        CentralizedLauncher {
            launcher: self.builder.build(),
            main_run_client: self.main_run_client,
        }
    }
}
