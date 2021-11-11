//! Monitor to disply both cumulative and per-client monitor

use alloc::{string::String, vec::Vec};
use core::{time, time::Duration};

#[cfg(feature = "introspection")]
use alloc::string::ToString;

use crate::{
    bolts::current_time,
    monitors::{ClientStats, Monitor},
};

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone, Debug)]
pub struct MultiMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_monitor: Vec<ClientStats>,
}

impl<F> Monitor for MultiMonitor<F>
where
    F: FnMut(String),
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_monitor
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_monitor
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let sender = format!("#{}", sender_id);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{}{} {}", event_msg, pad, sender);
        let global_fmt = format!(
            "[{}]  (GLOBAL) clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(global_fmt);

        let client = self.client_stats_mut_for(sender_id);
        let cur_time = current_time();
        let exec_sec = client.execs_per_sec(cur_time);

        let pad = " ".repeat(head.len());
        let mut fmt = format!(
            " {}   (CLIENT) corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            pad, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_monitor {
            fmt += &format!(", {}: {}", key, val);
        }
        (self.print_fn)(fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in self.client_monitor.iter().skip(1).enumerate() {
                let fmt = format!("Client {:03}:\n{}", i + 1, client.introspection_monitor);
                (self.print_fn)(fmt);
            }

            // Separate the spacing just a bit
            (self.print_fn)("\n".to_string());
        }
    }
}

impl<F> MultiMonitor<F>
where
    F: FnMut(String),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            client_monitor: vec![],
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: time::Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_monitor: vec![],
        }
    }
}
