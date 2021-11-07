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

#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use crate::bolts::os::startable_self;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use crate::bolts::os::{dup2, fork, ForkResult};
#[cfg(feature = "std")]
use crate::{
    bolts::shmem::ShMemProvider,
    events::{EventConfig, LlmpRestartingEventManager, ManagerKind, RestartingMgr},
    inputs::Input,
    observers::ObserversTuple,
    stats::Stats,
    Error,
};

#[cfg(feature = "std")]
use core::marker::PhantomData;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use core_affinity::CoreId;
#[cfg(feature = "std")]
use serde::de::DeserializeOwned;
#[cfg(feature = "std")]
use std::net::SocketAddr;
#[cfg(all(feature = "std", any(windows, not(feature = "fork"))))]
use std::process::Stdio;
#[cfg(all(unix, feature = "std", feature = "fork"))]
use std::{fs::File, os::unix::io::AsRawFd};
#[cfg(feature = "std")]
use typed_builder::TypedBuilder;

/// The (internal) `env` that indicates we're running as client.
const _AFL_LAUNCHER_CLIENT: &str = "AFL_LAUNCHER_CLIENT";
/// Provides a Launcher, which can be used to launch a fuzzing run on a specified list of cores
#[cfg(feature = "std")]
#[derive(TypedBuilder)]
#[allow(clippy::type_complexity)]
pub struct Launcher<'a, CF, I, OT, S, SP, ST>
where
    CF: FnOnce(Option<S>, LlmpRestartingEventManager<I, OT, S, SP>, usize) -> Result<(), Error>,
    I: Input + 'a,
    ST: Stats,
    SP: ShMemProvider + 'static,
    OT: ObserversTuple<I, S> + 'a,
    S: DeserializeOwned + 'a,
{
    /// The ShmemProvider to use
    shmem_provider: SP,
    /// The stats instance to use
    stats: ST,
    /// The configuration
    configuration: EventConfig,
    /// The 'main' function to run for each client forked. This probably shouldn't return
    #[builder(default, setter(strip_option))]
    run_client: Option<CF>,
    /// The broker port to use (or to attach to, in case [`Self::spawn_broker`] is `false`)
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a [usize],
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
    #[builder(setter(skip), default = PhantomData)]
    phantom_data: PhantomData<(&'a I, &'a OT, &'a S, &'a SP)>,
}

#[cfg(feature = "std")]
impl<'a, CF, I, OT, S, SP, ST> Launcher<'a, CF, I, OT, S, SP, ST>
where
    CF: FnOnce(Option<S>, LlmpRestartingEventManager<I, OT, S, SP>, usize) -> Result<(), Error>,
    I: Input,
    OT: ObserversTuple<I, S> + serde::de::DeserializeOwned,
    ST: Stats + Clone,
    SP: ShMemProvider + 'static,
    S: DeserializeOwned,
{
    /// Launch the broker and the clients and fuzz
    #[cfg(all(unix, feature = "std", feature = "fork"))]
    #[allow(clippy::similar_names)]
    pub fn launch(&mut self) -> Result<(), Error> {
        if self.run_client.is_none() {
            return Err(Error::IllegalArgument(
                "No client callback provided".to_string(),
            ));
        }

        let core_ids = core_affinity::get_core_ids().unwrap();
        let num_cores = core_ids.len();
        let mut handles = vec![];

        println!("spawning on cores: {:?}", self.cores);

        // Spawn clients
        let mut index = 0_u64;
        for (id, bind_to) in core_ids.iter().enumerate().take(num_cores) {
            if self.cores.iter().any(|&x| x == id) {
                index += 1;
                self.shmem_provider.pre_fork()?;
                match unsafe { fork() }? {
                    ForkResult::Parent(child) => {
                        self.shmem_provider.post_fork(false)?;
                        handles.push(child.pid);
                        #[cfg(feature = "std")]
                        println!("child spawned and bound to core {}", id);
                    }
                    ForkResult::Child => {
                        println!("{:?} PostFork", unsafe { libc::getpid() });
                        self.shmem_provider.post_fork(true)?;

                        #[cfg(feature = "std")]
                        std::thread::sleep(std::time::Duration::from_millis((index * 100) as u64));

                        #[cfg(feature = "std")]
                        if let Some(filename) = self.stdout_file {
                            let file = File::create(filename).unwrap();
                            dup2(file.as_raw_fd(), libc::STDOUT_FILENO)?;
                            dup2(file.as_raw_fd(), libc::STDERR_FILENO)?;
                        }
                        // Fuzzer client. keeps retrying the connection to broker till the broker starts
                        let (state, mgr) = RestartingMgr::<I, OT, S, SP, ST>::builder()
                            .shmem_provider(self.shmem_provider.clone())
                            .broker_port(self.broker_port)
                            .kind(ManagerKind::Client {
                                cpu_core: Some(*bind_to),
                            })
                            .configuration(self.configuration)
                            .build()
                            .launch()?;

                        (self.run_client.take().unwrap())(state, mgr, bind_to.id)
                            .expect("Client closure failed");
                        break;
                    }
                };
            }
        }

        if self.spawn_broker {
            #[cfg(feature = "std")]
            println!("I am broker!!.");

            // TODO we don't want always a broker here, think about using different laucher process to spawn different configurations
            RestartingMgr::<I, OT, S, SP, ST>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .stats(Some(self.stats.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .configuration(self.configuration)
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
                println!("Not spawning broker (spawn_broker is false). Waiting for fuzzer children to exit...");
                unsafe {
                    libc::waitpid(*handle, &mut status, 0);
                    if status != 0 {
                        println!("Client with pid {} exited with status {}", handle, status);
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
        let is_client = std::env::var(_AFL_LAUNCHER_CLIENT);

        let mut handles = match is_client {
            Ok(core_conf) => {
                let core_id = core_conf.parse()?;

                //todo: silence stdout and stderr for clients

                // the actual client. do the fuzzing
                let (state, mgr) = RestartingMgr::<I, OT, S, SP, ST>::builder()
                    .shmem_provider(self.shmem_provider.clone())
                    .broker_port(self.broker_port)
                    .kind(ManagerKind::Client {
                        cpu_core: Some(CoreId { id: core_id }),
                    })
                    .configuration(self.configuration)
                    .build()
                    .launch()?;

                (self.run_client.take().unwrap())(state, mgr, core_id)
                    .expect("Client closure failed");

                unreachable!("Fuzzer client code should never get here!");
            }
            Err(std::env::VarError::NotPresent) => {
                // I am a broker
                // before going to the broker loop, spawn n clients

                if self.stdout_file.is_some() {
                    println!("Child process file stdio is not supported on Windows yet. Dumping to stdout instead...");
                }

                let core_ids = core_affinity::get_core_ids().unwrap();
                let num_cores = core_ids.len();
                let mut handles = vec![];

                println!("spawning on cores: {:?}", self.cores);

                //spawn clients
                for (id, _) in core_ids.iter().enumerate().take(num_cores) {
                    if self.cores.iter().any(|&x| x == id) {
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

        if self.spawn_broker {
            #[cfg(feature = "std")]
            println!("I am broker!!.");

            RestartingMgr::<I, OT, S, SP, ST>::builder()
                .shmem_provider(self.shmem_provider.clone())
                .stats(Some(self.stats.clone()))
                .broker_port(self.broker_port)
                .kind(ManagerKind::Broker)
                .remote_broker_addr(self.remote_broker_addr)
                .configuration(self.configuration)
                .build()
                .launch()?;

            //broker exited. kill all clients.
            for handle in &mut handles {
                handle.kill()?;
            }
        } else {
            println!("Not spawning broker (spawn_broker is false). Waiting for fuzzer children to exit...");
            for handle in &mut handles {
                let ecode = handle.wait()?;
                if !ecode.success() {
                    println!("Client with handle {:?} exited with {:?}", handle, ecode);
                }
            }
        }

        Ok(())
    }
}
