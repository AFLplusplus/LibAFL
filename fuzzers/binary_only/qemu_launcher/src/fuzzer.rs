#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, Write},
};

use clap::Parser;
#[cfg(not(feature = "simplemgr"))]
use libafl::events::{EventConfig, Launcher};
use libafl::{
    events::{ClientDescription, SimpleEventManager},
    monitors::{tui::TuiMonitor, Monitor, MultiMonitor},
    Error,
};
#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl_bolts::{core_affinity::CoreId, current_time};
#[cfg(unix)]
use libafl_bolts::{os::dup2, os::dup_and_mute_outputs};

use crate::{client::Client, options::FuzzerOptions};

pub struct Fuzzer {
    options: FuzzerOptions,
}

impl Fuzzer {
    pub fn new() -> Fuzzer {
        env_logger::init();
        let options = FuzzerOptions::parse();
        options.validate();
        Fuzzer { options }
    }

    pub fn fuzz(&self) -> Result<(), Error> {
        if self.options.tui {
            let monitor = TuiMonitor::builder()
                .title("QEMU Launcher")
                .version("0.13.1")
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
            let wrapped_stdout = {
                // We forward all outputs to dev/null, but keep a copy around for the fuzzer output.
                //
                // # Safety
                // stdout and stderr should still be open at this point in time.
                let (new_stdout, new_stderr) = unsafe { dup_and_mute_outputs()? };

                // If we are debugging, re-enable target stderror.
                if std::env::var("LIBAFL_FUZZBENCH_DEBUG").is_ok() {
                    // # Safety
                    // Nobody else uses the new stderror here.
                    unsafe {
                        dup2(new_stderr, io::stderr().as_raw_fd())?;
                    }
                }

                // # Safety
                // The new stdout is open at this point, and we will don't use it anywhere else.
                #[cfg(unix)]
                unsafe {
                    File::from_raw_fd(new_stdout)
                }
            };

            let stdout_cpy = RefCell::new(wrapped_stdout);

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

        if self.options.rerun_input.is_some() {
            return client.run(
                None,
                SimpleEventManager::new(monitor.clone()),
                ClientDescription::new(0, 0, CoreId(0)),
            );
        }

        #[cfg(feature = "simplemgr")]
        return client.run(
            None,
            SimpleEventManager::new(monitor.clone()),
            ClientDescription::new(0, 0, CoreId(0)),
        );

        // Build and run the Launcher / fuzzer.
        #[cfg(not(feature = "simplemgr"))]
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(self.options.port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(|s, m, c| client.run(s, m, c))
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
