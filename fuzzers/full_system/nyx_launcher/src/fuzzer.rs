use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, Write},
};

use clap::Parser;
use libafl::{
    events::{
        ClientDescription, EventConfig, Launcher, LlmpEventManagerBuilder, MonitorTypedEventManager,
    },
    monitors::{tui::TuiMonitor, Monitor, MultiMonitor},
    Error,
};
use libafl_bolts::{
    core_affinity::CoreId,
    current_time,
    llmp::LlmpBroker,
    shmem::{ShMemProvider, StdShMemProvider},
    staterestore::StateRestorer,
    tuples::tuple_list,
};
#[cfg(unix)]
use {
    nix::unistd::dup,
    std::os::unix::io::{AsRawFd, FromRawFd},
};

use crate::{client::Client, options::FuzzerOptions};

pub struct Fuzzer {
    options: FuzzerOptions,
}

impl Fuzzer {
    pub fn new() -> Fuzzer {
        let options = FuzzerOptions::parse();
        options.validate();
        Fuzzer { options }
    }

    pub fn fuzz(&self) -> Result<(), Error> {
        if self.options.tui {
            let monitor = TuiMonitor::builder()
                .title("Nyx Launcher")
                .version("0.14.1")
                .enhanced_graphics(true)
                .build();
            self.launch(monitor)
        } else {
            let log = self.options.log.as_ref().and_then(|l| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(l)
                    .ok()
                    .map(RefCell::new)
            });

            #[cfg(unix)]
            let stdout_cpy = RefCell::new(unsafe {
                let new_fd = dup(io::stdout().as_raw_fd()).unwrap();
                File::from_raw_fd(new_fd)
            });

            // The stats reporter for the broker
            let monitor = MultiMonitor::new(|s| {
                #[cfg(unix)]
                writeln!(stdout_cpy.borrow_mut(), "{s}").unwrap();
                #[cfg(windows)]
                println!("{s}");

                if let Some(log) = &log {
                    writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
                }
            });
            self.launch(monitor)
        }
    }

    fn launch<M>(&self, monitor: M) -> Result<(), Error>
    where
        M: Monitor + Clone,
    {
        // The shared memory allocator
        let mut shmem_provider = StdShMemProvider::new()?;

        /* If we are running in verbose, don't provide a replacement stdout, otherwise, use /dev/null */
        let stdout = if self.options.verbose {
            None
        } else {
            Some("/dev/null")
        };

        let client = Client::new(&self.options);

        if self.options.rerun_input.is_some() {
            // If we want to rerun a single input but we use a restarting mgr, we'll have to create a fake restarting mgr that doesn't actually restart.
            // It's not pretty but better than recompiling with simplemgr.

            // Just a random number, let's hope it's free :)
            let broker_port = 13120;
            let _fake_broker = LlmpBroker::create_attach_to_tcp(
                shmem_provider.clone(),
                tuple_list!(),
                broker_port,
            )
            .unwrap();

            // To rerun an input, instead of using a launcher, we create dummy parameters and run the client directly.
            return client.run(
                None,
                MonitorTypedEventManager::<_, M>::new(
                    LlmpEventManagerBuilder::builder().build_on_port(
                        shmem_provider.clone(),
                        broker_port,
                        EventConfig::AlwaysUnique,
                        None,
                        Some(StateRestorer::new(
                            shmem_provider.new_shmem(0x1000).unwrap(),
                        )),
                    )?,
                ),
                ClientDescription::new(0, 0, CoreId(0)),
            );
        }

        #[cfg(feature = "simplemgr")]
        return client.run(None, SimpleEventManager::new(monitor), CoreId(0));

        // Build and run a Launcher
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(self.options.port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(|s, m, c| client.run(s, MonitorTypedEventManager::<_, M>::new(m), c))
            .cores(&self.options.cores)
            .stdout_file(stdout)
            .stderr_file(stdout)
            .build()
            .launch()
        {
            Ok(()) => Ok(()),
            Err(Error::ShuttingDown) => {
                println!("Fuzzing stopped by user. Good bye.");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
