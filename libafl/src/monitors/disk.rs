//! Monitors that wrap a base one and log on disk

use alloc::{string::String, vec::Vec};
use core::time::Duration;
use serde_json::json;
use std::fs::OpenOptions;
use std::{fs::File, io::Write, path::PathBuf};

use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor, NopMonitor},
};

/// Wrap a monitor and log the current state of the monitor into a TOML file.
#[derive(Debug, Clone)]
pub struct OnDiskTOMLMonitor<M>
where
    M: Monitor,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
}

impl<M> Monitor for OnDiskTOMLMonitor<M>
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
    fn start_time(&mut self) -> Duration {
        self.base.start_time()
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let cur_time = current_time();

        if (cur_time - self.last_update).as_secs() >= 60 {
            self.last_update = cur_time;

            let mut file = File::create(&self.filename).expect("Failed to open the TOML file");
            write!(
                &mut file,
                "# This TOML is generated using the OnDiskMonitor component of LibAFL

[global]
run_time = \"{}\"
clients = {}
corpus = {}
objectives = {}
executions = {}
exec_sec = {}
",
                format_duration_hms(&(cur_time - self.start_time())),
                self.client_stats().len(),
                self.corpus_size(),
                self.objective_size(),
                self.total_execs(),
                self.execs_per_sec()
            )
            .expect("Failed to write to the TOML file");

            for (i, client) in self.client_stats_mut().iter_mut().skip(1).enumerate() {
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
                    i + 1,
                    client.corpus_size,
                    client.objective_size,
                    client.executions,
                    exec_sec
                )
                .expect("Failed to write to the TOML file");

                for (key, val) in &client.user_monitor {
                    let k: String = key
                        .chars()
                        .map(|c| if c.is_whitespace() { '_' } else { c })
                        .filter(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    writeln!(&mut file, "{} = \"{}\"", k, val)
                        .expect("Failed to write to the TOML file");
                }
            }

            drop(file);
        }

        self.base.display(event_msg, sender_id);
    }
}

impl<M> OnDiskTOMLMonitor<M>
where
    M: Monitor,
{
    /// Create new [`OnDiskTOMLMonitor`]
    #[must_use]
    pub fn new<P>(filename: P, base: M) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            base,
            filename: filename.into(),
            last_update: current_time(),
        }
    }
}

impl OnDiskTOMLMonitor<NopMonitor> {
    /// Create new [`OnDiskTOMLMonitor`] without a base
    #[must_use]
    pub fn nop<P>(filename: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::new(filename, NopMonitor::new())
    }
}

#[derive(Debug, Clone)]
/// Wraps a base monitor and continuously appends the current statistics to a JSON file
pub struct OnDiskJSONMonitor<M>
where
    M: Monitor,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
}

impl<M> OnDiskJSONMonitor<M>
where
    M: Monitor,
{
    /// Create a new [`OnDiskJSONMonitor`]
    pub fn new<P>(filename: P, base: M) -> Self
    where
        P: Into<PathBuf>,
    {
        let file = filename.into();
        if !file.exists() {
            File::create(&file).expect("Failed to create logging file");
        }

        Self {
            base,
            filename: file,
            last_update: current_time(),
        }
    }
}

impl<M> Monitor for OnDiskJSONMonitor<M>
where
    M: Monitor,
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    fn start_time(&mut self) -> Duration {
        self.base.start_time()
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let cur_time = current_time();
        if (cur_time - self.last_update).as_secs() >= 60 {
            let file = OpenOptions::new()
                .append(true)
                .open(&self.filename)
                .expect("Failed to open JSON file");
            let line = json!({
                "run_time": cur_time - self.base.start_time(),
                "clients": self.base.client_stats().len(),
                "corpus": self.base.corpus_size(),
                "objectives": self.base.objective_size(),
                "executions": self.base.total_execs(),
                "exec_sec": self.base.execs_per_sec(),
                "clients": &self.client_stats()[1..]
            });
            writeln!(&file, "{}", line).expect("Unable to write JSON to file");
            self.last_update = cur_time;
        }
        self.base.display(event_msg, sender_id);
    }
}
