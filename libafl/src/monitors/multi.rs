//! The [`MultiMonitor`] displays both cumulative and per-client stats.

use alloc::string::String;
use core::{
    fmt::{Debug, Formatter, Write},
    time::Duration,
};

use libafl_bolts::{current_time, format_duration_hms, ClientId};

use crate::{monitors::Monitor, statistics::manager::ClientStatsManager};

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct MultiMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
}

impl<F> Debug for MultiMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultiMonitor").finish_non_exhaustive()
    }
}

impl<F> Monitor for MultiMonitor<F>
where
    F: FnMut(&str),
{
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
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
            format_duration_hms(&(current_time() - client_stats_manager.start_time())),
            client_stats_manager.client_stats_count(),
            client_stats_manager.corpus_size(),
            client_stats_manager.objective_size(),
            client_stats_manager.total_execs(),
            client_stats_manager.execs_per_sec_pretty()
        );
        for (key, val) in client_stats_manager.aggregated() {
            write!(global_fmt, ", {key}: {val}").unwrap();
        }

        (self.print_fn)(&global_fmt);

        client_stats_manager.client_stats_insert(sender_id);
        let cur_time = current_time();
        let exec_sec = client_stats_manager
            .update_client_stats_for(sender_id, |client| client.execs_per_sec_pretty(cur_time));
        let client = client_stats_manager.client_stats_for(sender_id);

        let pad = " ".repeat(head.len());
        let mut fmt = format!(
            " {}   (CLIENT) corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            pad, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_stats {
            write!(fmt, ", {key}: {val}").unwrap();
        }
        (self.print_fn)(&fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in client_stats_manager
                .client_stats()
                .iter()
                .filter(|x| x.enabled)
                .enumerate()
            {
                let fmt = format!("Client {:03}:\n{}", i + 1, client.introspection_stats);
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
        Self { print_fn }
    }

    /// Creates the monitor with a given `start_time`.
    #[deprecated(
        since = "0.16.0",
        note = "Please use new to create. start_time is useless here."
    )]
    pub fn with_time(print_fn: F, _start_time: Duration) -> Self {
        Self::new(print_fn)
    }
}
