//! The [`MultiMonitor`] displays both cumulative and per-client stats.

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{Debug, Formatter, Write},
    time::Duration,
};

use libafl_bolts::{current_time, format_duration_hms, ClientId};

use super::Aggregator;
use crate::monitors::{ClientStats, Monitor};

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct MultiMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    aggregator: Aggregator,
}

impl<F> Debug for MultiMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultiMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish_non_exhaustive()
    }
}

impl<F> Monitor for MultiMonitor<F>
where
    F: FnMut(&str),
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    fn aggregate(&mut self, name: &str) {
        self.aggregator.aggregate(name, &self.client_stats);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let sender = format!("#{}", sender_id.0);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{event_msg}{pad} {sender}");
        let mut global_fmt = format!(
            "[{}]  (GLOBAL) run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );
        for (key, val) in &self.aggregator.aggregated {
            write!(global_fmt, ", {key}: {val}").unwrap();
        }

        (self.print_fn)(&global_fmt);

        self.client_stats_insert(sender_id);
        let client = self.client_stats_mut_for(sender_id);
        let cur_time = current_time();
        let exec_sec = client.execs_per_sec_pretty(cur_time);

        let pad = " ".repeat(head.len());
        let mut fmt = format!(
            " {}   (CLIENT) corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            pad, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_monitor {
            write!(fmt, ", {key}: {val}").unwrap();
        }
        (self.print_fn)(&fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in self.client_stats.iter().filter(|x| x.enabled).enumerate() {
                let fmt = format!("Client {:03}:\n{}", i + 1, client.introspection_monitor);
                (self.print_fn)(&fmt);
            }

            // Separate the spacing just a bit
            (self.print_fn)("\n");
        }
    }
}

impl<F> MultiMonitor<F>
where
    F: FnMut(&str),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
            aggregator: Aggregator::new(),
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            aggregator: Aggregator::new(),
        }
    }
}
