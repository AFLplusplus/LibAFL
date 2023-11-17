//! Monitor to display both cumulative and per-client monitor

#[cfg(feature = "introspection")]
use alloc::string::ToString;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::{Debug, Formatter, Write},
    time::Duration,
};

use hashbrown::HashMap;
use libafl_bolts::{current_time, format_duration_hms, ClientId};

use crate::monitors::{Aggregator, ClientStats, Monitor, UserStats};

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct MultiMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    aggregated: HashMap<String, UserStats>,
}

impl<F> Debug for MultiMonitor<F>
where
    F: FnMut(String),
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
    F: FnMut(String),
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

    fn aggregate(&mut self, name: &String) {
        let mut gather = vec![];
        // gather can't be empty as we update before the call to aggregate()
        for stats in self.client_stats.iter() {
            if let Some(x) = stats.user_monitor.get(name) {
                gather.push(x);
            }
        }

        if let Some((&init, rest)) = gather.split_first() {
            if !init.is_numeric() {
                return;
            }
            let mut ret = init.clone();
            match init.aggregator() {
                Aggregator::None => {
                    // Nothing
                    return;
                }
                Aggregator::Avg => {
                    for item in rest {
                        if ret.stats_add(item).is_none() {
                            return;
                        }
                    }
                    ret.stats_div(gather.len());
                }
                Aggregator::Sum => {
                    for item in rest {
                        if ret.stats_add(item).is_none() {
                            return;
                        }
                    }
                }
                Aggregator::Min => {
                    for item in rest {
                        if ret.stats_min(item).is_none() {
                            return;
                        }
                    }
                }
                Aggregator::Max => {
                    for item in rest {
                        if ret.stats_max(item).is_none() {
                            return;
                        }
                    }
                }
            }
            self.aggregated.insert(name.clone(), ret);
        }
    }

    fn display(&mut self, event_msg: String, sender_id: ClientId) {
        let sender = format!("#{}", sender_id.0);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{event_msg}{pad} {sender}");
        let global_fmt = format!(
            "[{}]  (GLOBAL) run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );
        (self.print_fn)(global_fmt);

        self.client_stats_insert(sender_id);
        let client = self.client_stats_for(sender_id);
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
        (self.print_fn)(fmt);

        let mut aggregated_fmt = "(Aggregated): ".to_string();
        for (key, val) in &self.aggregated {
            write!(aggregated_fmt, "{key}: {val}").unwrap();
        }
        (self.print_fn)(aggregated_fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in self.client_stats.iter().skip(1).enumerate() {
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
            client_stats: vec![],
            aggregated: HashMap::new(),
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            aggregated: HashMap::new(),
        }
    }
}
