//! Monitors that wrap a base monitor and also log to disk using different formats like `JSON` and `TOML`.

use alloc::{string::String, vec::Vec};
use core::time::Duration;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
};

use libafl_bolts::{current_time, format_duration_hms, ClientId};
use serde_json::json;

use crate::monitors::{ClientStats, Monitor, NopMonitor};

/// Wrap a monitor and log the current state of the monitor into a Toml file.
#[derive(Debug, Clone)]
pub struct OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
    update_interval: Duration,
}

impl<M> Monitor for OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    /// The client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn aggregate(&mut self, name: &str) {
        self.base.aggregate(name);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let cur_time = current_time();

        if cur_time - self.last_update >= self.update_interval {
            self.last_update = cur_time;

            let mut file = File::create(&self.filename).expect("Failed to open the Toml file");
            write!(
                &mut file,
                "# This Toml is generated using the OnDiskMonitor component of LibAFL

[global]
run_time = \"{}\"
clients = {}
corpus = {}
objectives = {}
executions = {}
exec_sec = {}
",
                format_duration_hms(&(cur_time - self.start_time())),
                self.client_stats_count(),
                self.corpus_size(),
                self.objective_size(),
                self.total_execs(),
                self.execs_per_sec()
            )
            .expect("Failed to write to the Toml file");

            for (i, client) in self.client_stats_mut().iter_mut().enumerate() {
                let exec_sec = client.execs_per_sec(cur_time);

                write!(
                    &mut file,
                    "
[client_{}]
corpus = {}
objectives = {}
executions = {}
exec_sec = {}
",
                    i, client.corpus_size, client.objective_size, client.executions, exec_sec
                )
                .expect("Failed to write to the Toml file");

                for (key, val) in &client.user_monitor {
                    let k: String = key
                        .chars()
                        .map(|c| if c.is_whitespace() { '_' } else { c })
                        .filter(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    writeln!(&mut file, "{k} = \"{val}\"")
                        .expect("Failed to write to the Toml file");
                }
            }

            drop(file);
        }

        self.base.display(event_msg, sender_id);
    }
}

impl<M> OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    /// Create new [`OnDiskTomlMonitor`]
    #[must_use]
    pub fn new<P>(filename: P, base: M) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::with_update_interval(filename, base, Duration::from_secs(60))
    }

    /// Create new [`OnDiskTomlMonitor`] with custom update interval
    #[must_use]
    pub fn with_update_interval<P>(filename: P, base: M, update_interval: Duration) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            base,
            filename: filename.into(),
            last_update: current_time() - update_interval,
            update_interval,
        }
    }
}

impl OnDiskTomlMonitor<NopMonitor> {
    /// Create new [`OnDiskTomlMonitor`] without a base
    #[must_use]
    pub fn nop<P>(filename: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::new(filename, NopMonitor::new())
    }
}

#[derive(Debug, Clone)]
/// Wraps a base monitor and continuously appends the current statistics to a Json lines file.
pub struct OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    base: M,
    path: PathBuf,
    /// A function that has the current runtime as argument and decides, whether a record should be logged
    log_record: F,
}

impl<F, M> OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    /// Create a new [`OnDiskJsonMonitor`]
    pub fn new<P>(filename: P, base: M, log_record: F) -> Self
    where
        P: Into<PathBuf>,
    {
        let path = filename.into();

        Self {
            base,
            path,
            log_record,
        }
    }
}

impl<F, M> Monitor for OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        if (self.log_record)(&mut self.base) {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)
                .expect("Failed to open logging file");

            let line = json!({
                "run_time": current_time() - self.base.start_time(),
                "clients": self.client_stats_count(),
                "corpus": self.base.corpus_size(),
                "objectives": self.base.objective_size(),
                "executions": self.base.total_execs(),
                "exec_sec": self.base.execs_per_sec(),
                "client_stats": self.client_stats(),
            });
            writeln!(&file, "{line}").expect("Unable to write Json to file");
        }
        self.base.display(event_msg, sender_id);
    }
}
