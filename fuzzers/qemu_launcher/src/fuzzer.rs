use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, Write},
};

use clap::Parser;
#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
#[cfg(not(feature = "simplemgr"))]
use libafl::events::{EventConfig, Launcher, MonitorTypedEventManager};
use libafl::{
    monitors::{
        tui::{ui::TuiUI, TuiMonitor},
        Monitor, MultiMonitor,
    },
    Error,
};
#[cfg(feature = "simplemgr")]
use libafl_bolts::core_affinity::CoreId;
use libafl_bolts::current_time;
#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
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
            let ui =
                TuiUI::with_version(String::from("QEMU Launcher"), String::from("0.10.1"), true);
            let monitor = TuiMonitor::new(ui);
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
                let new_fd = dup(io::stdout().as_raw_fd())?;
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
        #[cfg(not(feature = "simplemgr"))]
        let shmem_provider = StdShMemProvider::new()?;

        /* If we are running in verbose, don't provide a replacement stdout, otherwise, use /dev/null */
        #[cfg(not(feature = "simplemgr"))]
        let stdout = if self.options.verbose {
            None
        } else {
            Some("/dev/null")
        };

        let client = Client::new(&self.options);

        #[cfg(feature = "simplemgr")]
        return client.run(None, SimpleEventManager::new(monitor), CoreId(0));

        // Build and run a Launcher
        #[cfg(not(feature = "simplemgr"))]
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
