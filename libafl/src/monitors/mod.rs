//! Keep stats, and display them to the user. Usually used in a broker, or main node, of some sort.

pub mod multi;
pub use multi::MultiMonitor;

pub mod stats;

#[cfg(feature = "std")]
pub mod disk;
#[cfg(feature = "std")]
pub use disk::{OnDiskJsonMonitor, OnDiskTomlMonitor};

#[cfg(feature = "std")]
pub mod disk_aggregate;
#[cfg(feature = "std")]
pub use disk_aggregate::OnDiskJsonAggregateMonitor;

#[cfg(all(feature = "tui_monitor", feature = "std"))]
pub mod tui;
#[cfg(all(feature = "tui_monitor", feature = "std"))]
pub use tui::TuiMonitor;

#[cfg(all(feature = "prometheus_monitor", feature = "std"))]
pub mod prometheus;

use alloc::fmt::Debug;
#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{fmt, fmt::Write, time::Duration};

use libafl_bolts::ClientId;
#[cfg(all(feature = "prometheus_monitor", feature = "std"))]
pub use prometheus::PrometheusMonitor;

use crate::monitors::stats::ClientStatsManager;

/// The monitor trait keeps track of all the client's monitor, and offers methods to display them.
pub trait Monitor {
    /// Show the monitor to the user
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    );
}

/// Monitor that print exactly nothing.
/// Not good for debugging, very good for speed.
#[derive(Debug, Clone)]
pub struct NopMonitor {}

impl Monitor for NopMonitor {
    #[inline]
    fn display(
        &mut self,
        _client_stats_manager: &mut ClientStatsManager,
        _event_msg: &str,
        _sender_id: ClientId,
    ) {
    }
}

impl NopMonitor {
    /// Create new [`NopMonitor`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NopMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracking monitor during fuzzing that just prints to `stdout`.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct SimplePrintingMonitor {}

#[cfg(feature = "std")]
impl SimplePrintingMonitor {
    /// Create a new [`SimplePrintingMonitor`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "std")]
impl Monitor for SimplePrintingMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        let mut userstats = client_stats_manager.client_stats()[sender_id.0 as usize]
            .user_stats()
            .iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>();
        userstats.sort();
        let global_stats = client_stats_manager.global_stats();
        println!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}, {}",
            event_msg,
            sender_id.0,
            global_stats.run_time_pretty,
            global_stats.client_stats_count,
            global_stats.corpus_size,
            global_stats.objective_size,
            global_stats.total_execs,
            global_stats.execs_per_sec_pretty,
            userstats.join(", ")
        );

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            println!(
                "Client {:03}:\n{}",
                sender_id.0,
                client_stats_manager.client_stats()[sender_id.0 as usize].introspection_stats
            );
            // Separate the spacing just a bit
            println!();
        }
    }
}

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct SimpleMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
    print_user_monitor: bool,
}

impl<F> Debug for SimpleMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleMonitor").finish_non_exhaustive()
    }
}

impl<F> Monitor for SimpleMonitor<F>
where
    F: FnMut(&str),
{
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        let global_stats = client_stats_manager.global_stats();
        let mut fmt = format!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id.0,
            global_stats.run_time_pretty,
            global_stats.client_stats_count,
            global_stats.corpus_size,
            global_stats.objective_size,
            global_stats.total_execs,
            global_stats.execs_per_sec_pretty
        );

        if self.print_user_monitor {
            client_stats_manager.client_stats_insert(sender_id);
            let client = client_stats_manager.client_stats_for(sender_id);
            for (key, val) in client.user_stats() {
                write!(fmt, ", {key}: {val}").unwrap();
            }
        }

        (self.print_fn)(&fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            let fmt = format!(
                "Client {:03}:\n{}",
                sender_id.0,
                client_stats_manager.client_stats()[sender_id.0 as usize].introspection_stats
            );
            (self.print_fn)(&fmt);

            // Separate the spacing just a bit
            (self.print_fn)("");
        }
    }
}

impl<F> SimpleMonitor<F>
where
    F: FnMut(&str),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            print_user_monitor: false,
        }
    }

    /// Creates the monitor with a given `start_time`.
    #[deprecated(
        since = "0.16.0",
        note = "Please use new to create. start_time is useless here."
    )]
    pub fn with_time(print_fn: F, _start_time: Duration) -> Self {
        Self::new(print_fn)
    }

    /// Creates the monitor that also prints the user monitor
    pub fn with_user_monitor(print_fn: F) -> Self {
        Self {
            print_fn,
            print_user_monitor: true,
        }
    }
}

/// Start the timer
#[macro_export]
macro_rules! start_timer {
    ($state:expr) => {{
        // Start the timer
        #[cfg(feature = "introspection")]
        $state.introspection_stats_mut().start_timer();
    }};
}

/// Mark the elapsed time for the given feature
#[macro_export]
macro_rules! mark_feature_time {
    ($state:expr, $feature:expr) => {{
        // Mark the elapsed time for the given feature
        #[cfg(feature = "introspection")]
        $state.introspection_stats_mut().mark_feature_time($feature);
    }};
}

/// Mark the elapsed time for the given feature
#[macro_export]
macro_rules! mark_feedback_time {
    ($state:expr) => {{
        // Mark the elapsed time for the given feature
        #[cfg(feature = "introspection")]
        $state.introspection_stats_mut().mark_feedback_time();
    }};
}

// The client stats of first and second monitor will always be maintained
// to be consistent
/// A combined monitor consisting of multiple [`Monitor`]s.
#[derive(Debug, Clone)]
pub struct CombinedMonitor<A, B> {
    first: A,
    second: B,
}

impl<A: Monitor, B: Monitor> CombinedMonitor<A, B> {
    /// Create a new combined monitor
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: Monitor, B: Monitor> Monitor for CombinedMonitor<A, B> {
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        self.first
            .display(client_stats_manager, event_msg, sender_id);
        self.second
            .display(client_stats_manager, event_msg, sender_id);
    }
}

/// Variadic macro to create a chain of [`Monitor`]
#[macro_export]
macro_rules! combine_monitor {
    ( $last:expr ) => { $last };

    ( $last:expr, ) => { $last };

    ( $head:expr, $($tail:expr),+ $(,)?) => {
        // recursive call
        $crate::monitors::CombinedMonitor::new($head , $crate::combine_monitor!($($tail),+))
    };
}
