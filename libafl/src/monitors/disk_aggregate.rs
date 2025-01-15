//! Monitors that log aggregated stats to disk.

use alloc::vec::Vec;
use core::{
    fmt::{Debug, Formatter},
    time::Duration,
};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

use libafl_bolts::{current_time, ClientId};
use serde_json::json;

use crate::monitors::{Aggregator, ClientStats, Monitor};

/// A monitor that wraps another monitor and logs aggregated stats to a JSON file.
#[derive(Clone)]
pub struct OnDiskJsonAggregateMonitor<M>
where
    M: Monitor,
{
    base: M,
    aggregator: Aggregator,
    json_path: PathBuf,
    last_update: Duration,
    update_interval: Duration,
}

impl<M> Debug for OnDiskJsonAggregateMonitor<M>
where
    M: Monitor + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnDiskJsonAggregateMonitor")
            .field("base", &self.base)
            .field("last_update", &self.last_update)
            .field("update_interval", &self.update_interval)
            .field("json_path", &self.json_path)
            .finish_non_exhaustive()
    }
}

impl<M> Monitor for OnDiskJsonAggregateMonitor<M>
where
    M: Monitor,
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    fn aggregate(&mut self, name: &str) {
        self.aggregator.aggregate(name, self.base.client_stats());
        self.base.aggregate(name);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        // First let the base monitor handle its display
        self.base.display(event_msg, sender_id);

        // Write JSON stats if update interval has elapsed
        let cur_time = current_time();
        if cur_time - self.last_update >= self.update_interval {
            self.last_update = cur_time;

            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.json_path)
                .expect("Failed to open JSON logging file");

            let mut json_value = json!({
                "run_time": (cur_time - self.start_time()).as_secs(),
                "clients": self.client_stats_count(),
                "corpus": self.corpus_size(),
                "objectives": self.objective_size(),
                "executions": self.total_execs(),
                "exec_sec": self.execs_per_sec(),
            });

            // Add all aggregated values directly to the root
            if let Some(obj) = json_value.as_object_mut() {
                obj.extend(
                    self.aggregator
                        .aggregated
                        .iter()
                        .map(|(k, v)| (k.clone(), json!(v))),
                );
            }

            writeln!(&file, "{json_value}").expect("Unable to write JSON to file");
        }
    }
}

impl<M> OnDiskJsonAggregateMonitor<M>
where
    M: Monitor,
{
    /// Creates a new [`OnDiskJsonAggregateMonitor`]
    pub fn new<P>(base: M, json_path: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::with_interval(json_path, base, Duration::from_secs(10))
    }

    /// Creates a new [`OnDiskJsonAggregateMonitor`] with custom update interval
    pub fn with_interval<P>(json_path: P, base: M, update_interval: Duration) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            base,
            aggregator: Aggregator::new(),
            json_path: json_path.into(),
            last_update: current_time() - update_interval,
            update_interval,
        }
    }
}
