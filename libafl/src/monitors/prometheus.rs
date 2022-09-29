// ===== overview for prommon =====
// Need to run a prometheus server (can use precompiled binary or docker), which scrapes / stores data from the client. 
// It is configurable via a yaml file.

// Need the application to be instrumented with the Rust client library. Lets you define metrics, 
// then you expose them via an HTTP endpoint for the server to scrape.
// ^^ this file! ^^
// ====================


// imports
    // will need to use an HTTP library (tide?-- want something extremely lightweight)
    // will need the prometheus rust client lib : https://github.com/prometheus/client_rust

// check for introspection feature config
    // if so, do appropriate imports
    // alternatively: node exporter via prometheus?


// on each 'update', will need to keep track of prev metric value to take delta
    // with delta, add it to the counter / guage. Note that delta MUST be signed to account for decreases (only applicable to guages)
    // alternatively: does prometheus allow just a straight numeric update? rather than increment / decrement. Would save some cycles.
    // should have easy access to ClientStats vector.

// counters: runtime (sec), executions (int), objectives (size)
// guages: clients (int), corpus (size), execution rate (exec/sec)
    // NOTE: set() only available with guages (not counters).
        // - may have to just make everything a guage

// set up HTTP listener on /metrics, port 9090 (or just default)
    // example using tide: https://github.com/prometheus/client_rust/blob/master/examples/tide.rs

#[cfg(feature = "introspection")]
use alloc::string::ToString;
use alloc::{fmt::Debug, string::String, vec::Vec};
// use core::{fmt::Write, time::Duration};
use core::{fmt, time::Duration};
    
use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor},
};

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct PrometheusMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
}

impl<F> Debug for PrometheusMonitor<F>
where
    F: FnMut(String),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrometheusMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish()
    }
}

impl<F> Monitor for PrometheusMonitor<F>
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

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let fmt = format!(
            "[Prometheus] [{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            let fmt = format!(
                "Client {:03}:\n{}",
                sender_id, self.client_stats[sender_id as usize].introspection_monitor
            );
            (self.print_fn)(fmt);
            // might need to use this version? from multi.
            // for (i, client) in self.client_stats.iter().skip(1).enumerate() {
            //     let fmt = format!("Client {:03}:\n{}", i + 1, client.introspection_monitor);
            //     (self.print_fn)(fmt);
            // }

            // Separate the spacing just a bit
            (self.print_fn)(String::new());
        }
    }
}

impl<F> PrometheusMonitor<F>
where
    F: FnMut(String),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        // the function that is passed when initializing a new monitor in a fuzzer is "print_fn"
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
        }
    }
}