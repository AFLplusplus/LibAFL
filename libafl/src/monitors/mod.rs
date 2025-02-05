//! Keep stats, and display them to the user. Usually used in a broker, or main node, of some sort.

pub mod multi;
pub use multi::MultiMonitor;

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

use alloc::{fmt::Debug, vec::Vec};
use core::{fmt, fmt::Write, time::Duration};

use libafl_bolts::{current_time, format_duration_hms, ClientId};
#[cfg(all(feature = "prometheus_monitor", feature = "std"))]
pub use prometheus::PrometheusMonitor;

use crate::statistics::{manager::ClientStatsManager, ClientStats};

/// The monitor trait keeps track of all the client's monitor, and offers methods to display them.
pub trait Monitor {
    /// Creation time
    fn start_time(&self) -> Duration;

    /// Set creation time
    fn set_start_time(&mut self, time: Duration);

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
pub struct NopMonitor {
    start_time: Duration,
}

impl Monitor for NopMonitor {
    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

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
        Self {
            start_time: current_time(),
        }
    }
}

impl Default for NopMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracking monitor during fuzzing that just prints to `stdout`.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct SimplePrintingMonitor {
    start_time: Duration,
}

#[cfg(feature = "std")]
impl Default for SimplePrintingMonitor {
    fn default() -> Self {
        Self {
            start_time: current_time(),
        }
    }
}

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
    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        let mut userstats = client_stats_manager.client_stats()[sender_id.0 as usize]
            .user_stats
            .iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>();
        userstats.sort();
        println!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}, {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            client_stats_manager.client_stats_count(),
            client_stats_manager.corpus_size(),
            client_stats_manager.objective_size(),
            client_stats_manager.total_execs(),
            client_stats_manager.execs_per_sec_pretty(),
            userstats.join(", ")
        );

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            println!(
                "Client {:03}:\n{}",
                sender_id.0, self.client_stats[sender_id.0 as usize].introspection_monitor
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
    start_time: Duration,
    print_user_monitor: bool,
    client_stats: Vec<ClientStats>,
}

impl<F> Debug for SimpleMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish_non_exhaustive()
    }
}

impl<F> Monitor for SimpleMonitor<F>
where
    F: FnMut(&str),
{
    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        let mut fmt = format!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            client_stats_manager.client_stats_count(),
            client_stats_manager.corpus_size(),
            client_stats_manager.objective_size(),
            client_stats_manager.total_execs(),
            client_stats_manager.execs_per_sec_pretty()
        );

        if self.print_user_monitor {
            client_stats_manager.client_stats_insert(sender_id);
            let client = client_stats_manager.client_stats_for(sender_id);
            for (key, val) in &client.user_stats {
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
            start_time: current_time(),
            print_user_monitor: false,
            client_stats: vec![],
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            print_user_monitor: false,
            client_stats: vec![],
        }
    }

    /// Creates the monitor that also prints the user monitor
    pub fn with_user_monitor(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            print_user_monitor: true,
            client_stats: vec![],
        }
    }
}

/// Start the timer
#[macro_export]
macro_rules! start_timer {
    ($state:expr) => {{
        // Start the timer
        #[cfg(feature = "introspection")]
        $state.introspection_monitor_mut().start_timer();
    }};
}

/// Mark the elapsed time for the given feature
#[macro_export]
macro_rules! mark_feature_time {
    ($state:expr, $feature:expr) => {{
        // Mark the elapsed time for the given feature
        #[cfg(feature = "introspection")]
        $state
            .introspection_monitor_mut()
            .mark_feature_time($feature);
    }};
}

/// Mark the elapsed time for the given feature
#[macro_export]
macro_rules! mark_feedback_time {
    ($state:expr) => {{
        // Mark the elapsed time for the given feature
        #[cfg(feature = "introspection")]
        $state.introspection_monitor_mut().mark_feedback_time();
    }};
}

// The client stats of first and second monitor will always be maintained
// to be consistent
/// A combined monitor consisting of multiple [`Monitor`]s.
#[derive(Debug, Clone)]
pub struct CombinedMonitor<A, B> {
    first: A,
    second: B,
    start_time: Duration,
}

impl<A: Monitor, B: Monitor> CombinedMonitor<A, B> {
    /// Create a new combined monitor
    pub fn new(mut first: A, mut second: B) -> Self {
        let start_time = current_time();
        first.set_start_time(start_time);
        second.set_start_time(start_time);
        Self {
            first,
            second,
            start_time,
        }
    }
}

impl<A: Monitor, B: Monitor> Monitor for CombinedMonitor<A, B> {
    fn start_time(&self) -> Duration {
        self.start_time
    }

    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
        self.first.set_start_time(time);
        self.second.set_start_time(time);
    }

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
