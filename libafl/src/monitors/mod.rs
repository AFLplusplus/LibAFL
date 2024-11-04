//! Keep stats, and display them to the user. Usually used in a broker, or main node, of some sort.

pub mod multi;
pub use multi::MultiMonitor;

#[cfg(all(feature = "tui_monitor", feature = "std"))]
pub mod tui;

#[cfg(all(feature = "prometheus_monitor", feature = "std"))]
pub mod prometheus;
use alloc::string::ToString;

#[cfg(all(feature = "prometheus_monitor", feature = "std"))]
pub use prometheus::PrometheusMonitor;
#[cfg(feature = "std")]
pub mod disk;
use alloc::{borrow::Cow, fmt::Debug, string::String, vec::Vec};
use core::{fmt, fmt::Write, time::Duration};

#[cfg(feature = "std")]
pub use disk::{OnDiskJsonMonitor, OnDiskTomlMonitor};
use hashbrown::HashMap;
use libafl_bolts::{current_time, format_duration_hms, ClientId};
use serde::{Deserialize, Serialize};

#[cfg(feature = "afl_exec_sec")]
const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5; // 5 seconds

/// Definition of how we aggreate this across multiple clients
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AggregatorOps {
    /// Do nothing
    None,
    /// Add stats up
    Sum,
    /// Average stats out
    Avg,
    /// Get the min
    Min,
    /// Get the max
    Max,
}

/// The standard aggregator, plug this into the monitor to use
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Aggregator {
    // this struct could also have hashmap or vec for caching but for now i'll just keep it simple
    // for example to calculate the sum you don't have to iterate over all clients (obviously)
    aggregated: HashMap<String, UserStatsValue>,
}

impl Aggregator {
    /// constructor for this aggregator
    #[must_use]
    pub fn new() -> Self {
        Self {
            aggregated: HashMap::new(),
        }
    }

    /// takes the key and the ref to clients stats then aggregate them all.
    fn aggregate(&mut self, name: &str, client_stats: &[ClientStats]) {
        let mut gather = client_stats
            .iter()
            .filter_map(|client| client.user_monitor.get(name));

        let gather_count = gather.clone().count();

        let (mut init, op) = match gather.next() {
            Some(x) => (x.value().clone(), x.aggregator_op().clone()),
            _ => {
                return;
            }
        };

        for item in gather {
            match op {
                AggregatorOps::None => {
                    // Nothing
                    return;
                }
                AggregatorOps::Avg | AggregatorOps::Sum => {
                    init = match init.stats_add(item.value()) {
                        Some(x) => x,
                        _ => {
                            return;
                        }
                    };
                }
                AggregatorOps::Min => {
                    init = match init.stats_min(item.value()) {
                        Some(x) => x,
                        _ => {
                            return;
                        }
                    };
                }
                AggregatorOps::Max => {
                    init = match init.stats_max(item.value()) {
                        Some(x) => x,
                        _ => {
                            return;
                        }
                    };
                }
            }
        }

        if let AggregatorOps::Avg = op {
            // if avg then divide last.
            init = match init.stats_div(gather_count) {
                Some(x) => x,
                _ => {
                    return;
                }
            }
        }

        self.aggregated.insert(name.to_string(), init);
    }
}

/// user defined stats enum
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserStats {
    value: UserStatsValue,
    aggregator_op: AggregatorOps,
}

impl UserStats {
    /// Get the `AggregatorOps`
    #[must_use]
    pub fn aggregator_op(&self) -> &AggregatorOps {
        &self.aggregator_op
    }
    /// Get the actual value for the stats
    #[must_use]
    pub fn value(&self) -> &UserStatsValue {
        &self.value
    }
    /// Constructor
    #[must_use]
    pub fn new(value: UserStatsValue, aggregator_op: AggregatorOps) -> Self {
        Self {
            value,
            aggregator_op,
        }
    }
}

/// The actual value for the userstats
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserStatsValue {
    /// A numerical value
    Number(u64),
    /// A Float value
    Float(f64),
    /// A `String`
    String(Cow<'static, str>),
    /// A ratio of two values
    Ratio(u64, u64),
    /// Percent
    Percent(f64),
}

impl UserStatsValue {
    /// Check if this guy is numeric
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        match &self {
            Self::Number(_) | Self::Float(_) | Self::Ratio(_, _) | Self::Percent(_) => true,
            Self::String(_) => false,
        }
    }

    /// Divide by the number of elements
    #[allow(clippy::cast_precision_loss)]
    pub fn stats_div(&mut self, divisor: usize) -> Option<Self> {
        match self {
            Self::Number(x) => Some(Self::Float(*x as f64 / divisor as f64)),
            Self::Float(x) => Some(Self::Float(*x / divisor as f64)),
            Self::Percent(x) => Some(Self::Percent(*x / divisor as f64)),
            Self::Ratio(x, y) => Some(Self::Percent((*x as f64 / divisor as f64) / *y as f64)),
            Self::String(_) => None,
        }
    }

    /// min user stats with the other
    #[allow(clippy::cast_precision_loss)]
    pub fn stats_max(&mut self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Number(x), Self::Number(y)) => {
                if y > x {
                    Some(Self::Number(*y))
                } else {
                    Some(Self::Number(*x))
                }
            }
            (Self::Float(x), Self::Float(y)) => {
                if y > x {
                    Some(Self::Float(*y))
                } else {
                    Some(Self::Float(*x))
                }
            }
            (Self::Ratio(x, a), Self::Ratio(y, b)) => {
                let first = *x as f64 / *a as f64;
                let second = *y as f64 / *b as f64;
                if first > second {
                    Some(Self::Percent(first))
                } else {
                    Some(Self::Percent(second))
                }
            }
            (Self::Percent(x), Self::Percent(y)) => {
                if y > x {
                    Some(Self::Percent(*y))
                } else {
                    Some(Self::Percent(*x))
                }
            }
            _ => None,
        }
    }

    /// min user stats with the other
    #[allow(clippy::cast_precision_loss)]
    pub fn stats_min(&mut self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Number(x), Self::Number(y)) => {
                if y > x {
                    Some(Self::Number(*x))
                } else {
                    Some(Self::Number(*y))
                }
            }
            (Self::Float(x), Self::Float(y)) => {
                if y > x {
                    Some(Self::Float(*x))
                } else {
                    Some(Self::Float(*y))
                }
            }
            (Self::Ratio(x, a), Self::Ratio(y, b)) => {
                let first = *x as f64 / *a as f64;
                let second = *y as f64 / *b as f64;
                if first > second {
                    Some(Self::Percent(second))
                } else {
                    Some(Self::Percent(first))
                }
            }
            (Self::Percent(x), Self::Percent(y)) => {
                if y > x {
                    Some(Self::Percent(*x))
                } else {
                    Some(Self::Percent(*y))
                }
            }
            _ => None,
        }
    }

    /// add user stats with the other
    #[allow(clippy::cast_precision_loss)]
    pub fn stats_add(&mut self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Number(x), Self::Number(y)) => Some(Self::Number(*x + *y)),
            (Self::Float(x), Self::Float(y)) => Some(Self::Float(*x + *y)),
            (Self::Percent(x), Self::Percent(y)) => Some(Self::Percent(*x + *y)),
            (Self::Ratio(x, a), Self::Ratio(y, b)) => {
                let first = *x as f64 / *a as f64;
                let second = *y as f64 / *b as f64;
                Some(Self::Percent(first + second))
            }
            (Self::Percent(x), Self::Ratio(y, b)) => {
                let ratio = *y as f64 / *b as f64;
                Some(Self::Percent(*x + ratio))
            }
            (Self::Ratio(x, a), Self::Percent(y)) => {
                let ratio = *x as f64 / *a as f64;
                Some(Self::Percent(ratio + *y))
            }
            _ => None,
        }
    }
}

impl fmt::Display for UserStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

impl fmt::Display for UserStatsValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            UserStatsValue::Number(n) => write!(f, "{n}"),
            UserStatsValue::Float(n) => write!(f, "{}", prettify_float(*n)),
            UserStatsValue::Percent(n) => write!(f, "{:.3}%", n * 100.0),
            UserStatsValue::String(s) => write!(f, "{s}"),
            UserStatsValue::Ratio(a, b) => {
                if *b == 0 {
                    write!(f, "{a}/{b}")
                } else {
                    write!(f, "{a}/{b} ({}%)", a * 100 / b)
                }
            }
        }
    }
}

/// Prettifies float values for human-readable output
fn prettify_float(value: f64) -> String {
    let (value, suffix) = match value {
        value if value >= 1000000.0 => (value / 1000000.0, "M"),
        value if value >= 1000.0 => (value / 1000.0, "k"),
        value => (value, ""),
    };
    match value {
        value if value >= 1000000.0 => {
            format!("{value:.2}{suffix}")
        }
        value if value >= 1000.0 => {
            format!("{value:.1}{suffix}")
        }
        value if value >= 100.0 => {
            format!("{value:.1}{suffix}")
        }
        value if value >= 10.0 => {
            format!("{value:.2}{suffix}")
        }
        value => {
            format!("{value:.3}{suffix}")
        }
    }
}

/// A simple struct to keep track of client monitor
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStats {
    /// If this client is enabled. This is set to `true` the first time we see this client.
    pub enabled: bool,
    // monitor (maybe we need a separated struct?)
    /// The corpus size for this client
    pub corpus_size: u64,
    /// The time for the last update of the corpus size
    pub last_corpus_time: Duration,
    /// The total executions for this client
    pub executions: u64,
    /// The number of executions of the previous state in case a client decrease the number of execution (e.g when restarting without saving the state)
    pub prev_state_executions: u64,
    /// The size of the objectives corpus for this client
    pub objective_size: u64,
    /// The time for the last update of the objective size
    pub last_objective_time: Duration,
    /// The last reported executions for this client
    #[cfg(feature = "afl_exec_sec")]
    pub last_window_executions: u64,
    /// The last executions per sec
    #[cfg(feature = "afl_exec_sec")]
    pub last_execs_per_sec: f64,
    /// The last time we got this information
    pub last_window_time: Duration,
    /// the start time of the client
    pub start_time: Duration,
    /// User-defined monitor
    pub user_monitor: HashMap<Cow<'static, str>, UserStats>,
    /// Client performance statistics
    #[cfg(feature = "introspection")]
    pub introspection_monitor: ClientPerfMonitor,
}

impl ClientStats {
    /// We got new information about executions for this client, insert them.
    #[cfg(feature = "afl_exec_sec")]
    pub fn update_executions(&mut self, executions: u64, cur_time: Duration) {
        let diff = cur_time
            .checked_sub(self.last_window_time)
            .map_or(0, |d| d.as_secs());
        if diff > CLIENT_STATS_TIME_WINDOW_SECS {
            let _: f64 = self.execs_per_sec(cur_time);
            self.last_window_time = cur_time;
            self.last_window_executions = self.executions;
        }
        if self.executions > self.prev_state_executions + executions {
            // Something is strange here, sum the executions
            self.prev_state_executions = self.executions;
        }
        self.executions = self.prev_state_executions + executions;
    }

    /// We got a new information about executions for this client, insert them.
    #[cfg(not(feature = "afl_exec_sec"))]
    pub fn update_executions(&mut self, executions: u64, _cur_time: Duration) {
        if self.executions > self.prev_state_executions + executions {
            // Something is strange here, sum the executions
            self.prev_state_executions = self.executions;
        }
        self.executions = self.prev_state_executions + executions;
    }

    /// We got new information about corpus size for this client, insert them.
    pub fn update_corpus_size(&mut self, corpus_size: u64) {
        self.corpus_size = corpus_size;
        self.last_corpus_time = current_time();
    }

    /// We got a new information about objective corpus size for this client, insert them.
    pub fn update_objective_size(&mut self, objective_size: u64) {
        self.objective_size = objective_size;
    }

    /// Get the calculated executions per second for this client
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    #[cfg(feature = "afl_exec_sec")]
    pub fn execs_per_sec(&mut self, cur_time: Duration) -> f64 {
        if self.executions == 0 {
            return 0.0;
        }

        let elapsed = cur_time
            .checked_sub(self.last_window_time)
            .map_or(0.0, |d| d.as_secs_f64());
        if elapsed as u64 == 0 {
            return self.last_execs_per_sec;
        }

        let cur_avg = ((self.executions - self.last_window_executions) as f64) / elapsed;
        if self.last_window_executions == 0 {
            self.last_execs_per_sec = cur_avg;
            return self.last_execs_per_sec;
        }

        // If there is a dramatic (5x+) jump in speed, reset the indicator more quickly
        if cur_avg * 5.0 < self.last_execs_per_sec || cur_avg / 5.0 > self.last_execs_per_sec {
            self.last_execs_per_sec = cur_avg;
        }

        self.last_execs_per_sec =
            self.last_execs_per_sec * (1.0 - 1.0 / 16.0) + cur_avg * (1.0 / 16.0);
        self.last_execs_per_sec
    }

    /// Get the calculated executions per second for this client
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    #[cfg(not(feature = "afl_exec_sec"))]
    pub fn execs_per_sec(&mut self, cur_time: Duration) -> f64 {
        if self.executions == 0 {
            return 0.0;
        }

        let elapsed = cur_time
            .checked_sub(self.last_window_time)
            .map_or(0.0, |d| d.as_secs_f64());
        if elapsed as u64 == 0 {
            return 0.0;
        }

        (self.executions as f64) / elapsed
    }

    /// Executions per second
    fn execs_per_sec_pretty(&mut self, cur_time: Duration) -> String {
        prettify_float(self.execs_per_sec(cur_time))
    }

    /// Update the user-defined stat with name and value
    pub fn update_user_stats(
        &mut self,
        name: Cow<'static, str>,
        value: UserStats,
    ) -> Option<UserStats> {
        self.user_monitor.insert(name, value)
    }

    #[must_use]
    /// Get a user-defined stat using the name
    pub fn get_user_stats(&self, name: &str) -> Option<&UserStats> {
        self.user_monitor.get(name)
    }

    /// Update the current [`ClientPerfMonitor`] with the given [`ClientPerfMonitor`]
    #[cfg(feature = "introspection")]
    pub fn update_introspection_monitor(&mut self, introspection_monitor: ClientPerfMonitor) {
        self.introspection_monitor = introspection_monitor;
    }
}

/// The monitor trait keeps track of all the client's monitor, and offers methods to display them.
pub trait Monitor {
    /// The client monitor (mutable)
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats>;

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats];

    /// Creation time
    fn start_time(&self) -> Duration;

    /// Set creation time
    fn set_start_time(&mut self, time: Duration);

    /// Show the monitor to the user
    fn display(&mut self, event_msg: &str, sender_id: ClientId);

    /// Amount of elements in the corpus (combined for all children)
    fn corpus_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.corpus_size)
    }

    /// Count the number of enabled client stats
    fn client_stats_count(&self) -> usize {
        self.client_stats()
            .iter()
            .filter(|client| client.enabled)
            .count()
    }

    /// Amount of elements in the objectives (combined for all children)
    fn objective_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.objective_size)
    }

    /// Total executions
    #[inline]
    fn total_execs(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.executions)
    }

    /// Executions per second
    #[allow(clippy::cast_sign_loss)]
    #[inline]
    fn execs_per_sec(&mut self) -> f64 {
        let cur_time = current_time();
        self.client_stats_mut()
            .iter_mut()
            .fold(0.0, |acc, x| acc + x.execs_per_sec(cur_time))
    }

    /// Executions per second
    fn execs_per_sec_pretty(&mut self) -> String {
        prettify_float(self.execs_per_sec())
    }

    /// The client monitor for a specific id, creating new if it doesn't exist
    fn client_stats_insert(&mut self, client_id: ClientId) {
        let total_client_stat_count = self.client_stats().len();
        for _ in total_client_stat_count..=(client_id.0) as usize {
            self.client_stats_mut().push(ClientStats {
                enabled: false,
                last_window_time: Duration::from_secs(0),
                start_time: Duration::from_secs(0),
                ..ClientStats::default()
            });
        }
        let new_stat = self.client_stats_mut_for(client_id);
        if !new_stat.enabled {
            let timestamp = current_time();
            // I have never seen this man in my life
            new_stat.start_time = timestamp;
            new_stat.last_window_time = timestamp;
            new_stat.enabled = true;
        }
    }

    /// Get mutable reference to client stats
    fn client_stats_mut_for(&mut self, client_id: ClientId) -> &mut ClientStats {
        &mut self.client_stats_mut()[client_id.0 as usize]
    }

    /// Get immutable reference to client stats
    fn client_stats_for(&self, client_id: ClientId) -> &ClientStats {
        &self.client_stats()[client_id.0 as usize]
    }

    /// Aggregate the results in case there're multiple clients
    fn aggregate(&mut self, _name: &str) {}
}

/// Monitor that print exactly nothing.
/// Not good for debugging, very good for speed.
#[derive(Debug, Clone)]
pub struct NopMonitor {
    start_time: Duration,
    client_stats: Vec<ClientStats>,
}

impl Monitor for NopMonitor {
    /// The client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    #[inline]
    fn display(&mut self, _event_msg: &str, _sender_id: ClientId) {}
}

impl NopMonitor {
    /// Create new [`NopMonitor`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: current_time(),
            client_stats: vec![],
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
    client_stats: Vec<ClientStats>,
}

#[cfg(feature = "std")]
impl Default for SimplePrintingMonitor {
    fn default() -> Self {
        Self {
            start_time: current_time(),
            client_stats: Vec::new(),
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
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let mut userstats = self.client_stats()[sender_id.0 as usize]
            .user_monitor
            .iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>();
        userstats.sort();
        println!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}, {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty(),
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
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let mut fmt = format!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );

        if self.print_user_monitor {
            self.client_stats_insert(sender_id);
            let client = self.client_stats_mut_for(sender_id);
            for (key, val) in &client.user_monitor {
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
                sender_id.0, self.client_stats[sender_id.0 as usize].introspection_monitor
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

/// Client performance statistics
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientPerfMonitor {
    /// Starting counter (in clock cycles from `read_time_counter`)
    start_time: u64,

    /// Current counter in the fuzzer (in clock cycles from `read_time_counter`
    current_time: u64,

    /// Clock cycles spent in the scheduler
    scheduler: u64,

    /// Clock cycles spent in the manager
    manager: u64,

    /// Current stage index to write the next stage benchmark time
    curr_stage: u8,

    /// Flag to dictate this stage is in use. Used during printing to not print the empty
    /// stages if they are not in use.
    stages_used: Vec<bool>,

    /// Clock cycles spent in the the various features of each stage
    stages: Vec<[u64; PerfFeature::Count as usize]>,

    /// Clock cycles spent in each feedback mechanism of the fuzzer.
    feedbacks: HashMap<String, u64>,

    /// Current time set by `start_timer`
    timer_start: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Count the imported testcase from other nodes that came with observers
pub struct ScalabilityMonitor {
    /// Imported testcase received with observer
    pub testcase_with_observers: usize,
    /// Imported testcase received without observer
    pub testcase_without_observers: usize,
}

impl ScalabilityMonitor {
    /// Constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            testcase_with_observers: 0,
            testcase_without_observers: 0,
        }
    }
}

/// Various features that are measured for performance
#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
pub enum PerfFeature {
    /// Getting an input from the corpus
    GetInputFromCorpus = 0,

    /// Mutating the input
    Mutate = 1,

    /// Post-Exec Mutator callback
    MutatePostExec = 2,

    /// Actual time spent executing the target
    TargetExecution = 3,

    /// Time spent in `pre_exec`
    PreExec = 4,

    /// Time spent in `post_exec`
    PostExec = 5,

    /// Time spent in `observer` `pre_exec_all`
    PreExecObservers = 6,

    /// Time spent in `executor.observers_mut().post_exec_all`
    PostExecObservers = 7,

    /// Time spent getting the feedback from `is_interesting` from all feedbacks
    GetFeedbackInterestingAll = 8,

    /// Time spent getting the feedback from `is_interesting` from all objectives
    GetObjectivesInterestingAll = 9,

    /// Used as a counter to know how many elements are in [`PerfFeature`]. Must be the
    /// last value in the enum.
    Count, // !! No more values here since Count is last! !!
           // !! No more values here since Count is last! !!
}

// TryFromPrimitive requires `std` so these are implemented manually
impl From<PerfFeature> for usize {
    fn from(val: PerfFeature) -> usize {
        match val {
            PerfFeature::GetInputFromCorpus => PerfFeature::GetInputFromCorpus as usize,
            PerfFeature::Mutate => PerfFeature::Mutate as usize,
            PerfFeature::MutatePostExec => PerfFeature::MutatePostExec as usize,
            PerfFeature::TargetExecution => PerfFeature::TargetExecution as usize,
            PerfFeature::PreExec => PerfFeature::PreExec as usize,
            PerfFeature::PostExec => PerfFeature::PostExec as usize,
            PerfFeature::PreExecObservers => PerfFeature::PreExecObservers as usize,
            PerfFeature::PostExecObservers => PerfFeature::PostExecObservers as usize,
            PerfFeature::GetFeedbackInterestingAll => {
                PerfFeature::GetFeedbackInterestingAll as usize
            }
            PerfFeature::GetObjectivesInterestingAll => {
                PerfFeature::GetObjectivesInterestingAll as usize
            }
            PerfFeature::Count => PerfFeature::Count as usize,
        }
    }
}

// TryFromPrimitive requires `std` so these are implemented manually
impl From<usize> for PerfFeature {
    fn from(val: usize) -> PerfFeature {
        match val {
            0 => PerfFeature::GetInputFromCorpus,
            1 => PerfFeature::Mutate,
            2 => PerfFeature::MutatePostExec,
            3 => PerfFeature::TargetExecution,
            4 => PerfFeature::PreExec,
            5 => PerfFeature::PostExec,
            6 => PerfFeature::PreExecObservers,
            7 => PerfFeature::PostExecObservers,
            8 => PerfFeature::GetFeedbackInterestingAll,
            9 => PerfFeature::GetObjectivesInterestingAll,
            _ => panic!("Unknown PerfFeature: {val}"),
        }
    }
}

/// Number of features we can measure for performance
#[cfg(feature = "introspection")]
pub const NUM_PERF_FEATURES: usize = PerfFeature::Count as usize;

#[cfg(feature = "introspection")]
impl ClientPerfMonitor {
    /// Create a blank [`ClientPerfMonitor`] with the `start_time` and `current_time` with
    /// the current clock counter
    #[must_use]
    pub fn new() -> Self {
        let start_time = libafl_bolts::cpu::read_time_counter();

        Self {
            start_time,
            current_time: start_time,
            scheduler: 0,
            manager: 0,
            curr_stage: 0,
            stages: vec![],
            stages_used: vec![],
            feedbacks: HashMap::new(),
            timer_start: None,
        }
    }

    /// Set the current time with the given time
    #[inline]
    pub fn set_current_time(&mut self, time: u64) {
        self.current_time = time;
    }

    /// Start a timer with the current time counter
    #[inline]
    pub fn start_timer(&mut self) {
        self.timer_start = Some(libafl_bolts::cpu::read_time_counter());
    }

    /// Update the current [`ClientPerfMonitor`] with the given [`ClientPerfMonitor`]
    pub fn update(&mut self, monitor: &ClientPerfMonitor) {
        self.set_current_time(monitor.current_time);
        self.update_scheduler(monitor.scheduler);
        self.update_manager(monitor.manager);
        self.update_stages(&monitor.stages);
        self.update_feedbacks(&monitor.feedbacks);
    }

    /// Gets the elapsed time since the internal timer started. Resets the timer when
    /// finished execution.
    #[inline]
    fn mark_time(&mut self) -> u64 {
        match self.timer_start {
            None => {
                // Warning message if marking time without starting the timer first
                log::warn!("Attempted to `mark_time` without starting timer first.");

                // Return 0 for no time marked
                0
            }
            Some(timer_start) => {
                // Calculate the elapsed time
                let elapsed = libafl_bolts::cpu::read_time_counter() - timer_start;

                // Reset the timer
                self.timer_start = None;

                // Return the elapsed time
                elapsed
            }
        }
    }

    /// Update the time spent in the scheduler with the elapsed time that we have seen
    #[inline]
    pub fn mark_scheduler_time(&mut self) {
        // Get the current elapsed time
        let elapsed = self.mark_time();

        // Add the time to the scheduler stat
        self.update_scheduler(elapsed);
    }

    /// Update the time spent in the scheduler with the elapsed time that we have seen
    #[inline]
    pub fn mark_manager_time(&mut self) {
        // Get the current elapsed time
        let elapsed = self.mark_time();

        // Add the time the manager stat
        self.update_manager(elapsed);
    }

    /// Update the time spent in the given [`PerfFeature`] with the elapsed time that we have seen
    #[inline]
    pub fn mark_feature_time(&mut self, feature: PerfFeature) {
        // Get the current elapsed time
        let elapsed = self.mark_time();

        // Add the time the the given feature
        self.update_feature(feature, elapsed);
    }

    /// Add the given `time` to the `scheduler` monitor
    #[inline]
    pub fn update_scheduler(&mut self, time: u64) {
        self.scheduler = self
            .scheduler
            .checked_add(time)
            .expect("update_scheduler overflow");
    }

    /// Add the given `time` to the `manager` monitor
    #[inline]
    pub fn update_manager(&mut self, time: u64) {
        self.manager = self
            .manager
            .checked_add(time)
            .expect("update_manager overflow");
    }

    /// Update the total stage counter and increment the stage counter for the next stage
    #[inline]
    pub fn finish_stage(&mut self) {
        // Increment the stage to the next index. The check is only done if this were to
        // be used past the length of the `self.stages` buffer
        self.curr_stage += 1;
    }

    /// Reset the stage index counter to zero
    #[inline]
    pub fn reset_stage_index(&mut self) {
        self.curr_stage = 0;
    }

    /// Update the time spent in the feedback
    pub fn update_feedback(&mut self, name: &str, time: u64) {
        self.feedbacks.insert(
            name.into(),
            self.feedbacks
                .get(name)
                .unwrap_or(&0)
                .checked_add(time)
                .expect("update_feedback overflow"),
        );
    }

    /// Update the time spent in all the feedbacks
    pub fn update_feedbacks(&mut self, feedbacks: &HashMap<String, u64>) {
        for (key, value) in feedbacks {
            self.update_feedback(key, *value);
        }
    }

    /// Update the time spent in the stages
    pub fn update_stages(&mut self, stages: &[[u64; PerfFeature::Count as usize]]) {
        if self.stages.len() < stages.len() {
            self.stages
                .resize(stages.len(), [0; PerfFeature::Count as usize]);
            self.stages_used.resize(stages.len(), false);
        }
        for (stage_index, features) in stages.iter().enumerate() {
            for (feature_index, feature) in features.iter().enumerate() {
                self.stages[stage_index][feature_index] = self.stages[stage_index][feature_index]
                    .checked_add(*feature)
                    .expect("Stage overflow");
            }
        }
    }

    /// Update the given [`PerfFeature`] with the given `time`
    pub fn update_feature(&mut self, feature: PerfFeature, time: u64) {
        // Get the current stage index as `usize`
        let stage_index: usize = self.curr_stage.into();

        // Get the index of the given feature
        let feature_index: usize = feature.into();

        if stage_index >= self.stages.len() {
            self.stages
                .resize(stage_index + 1, [0; PerfFeature::Count as usize]);
            self.stages_used.resize(stage_index + 1, false);
        }

        // Update the given feature
        self.stages[stage_index][feature_index] = self.stages[stage_index][feature_index]
            .checked_add(time)
            .expect("Stage overflow");

        // Set that the current stage is being used
        self.stages_used[stage_index] = true;
    }

    /// The elapsed cycles (or time)
    #[must_use]
    pub fn elapsed_cycles(&self) -> u64 {
        self.current_time - self.start_time
    }

    /// The amount of cycles the `manager` did
    #[must_use]
    pub fn manager_cycles(&self) -> u64 {
        self.manager
    }

    /// The amount of cycles the `scheduler` did
    #[must_use]
    pub fn scheduler_cycles(&self) -> u64 {
        self.scheduler
    }

    /// Iterator over all used stages
    pub fn used_stages(
        &self,
    ) -> impl Iterator<Item = (usize, &[u64; PerfFeature::Count as usize])> {
        let used = self.stages_used.clone();
        self.stages
            .iter()
            .enumerate()
            .filter(move |(stage_index, _)| used[*stage_index])
    }

    /// A map of all `feedbacks`
    #[must_use]
    pub fn feedbacks(&self) -> &HashMap<String, u64> {
        &self.feedbacks
    }
}

#[cfg(feature = "introspection")]
impl fmt::Display for ClientPerfMonitor {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        // Calculate the elapsed time from the monitor
        let elapsed: f64 = self.elapsed_cycles() as f64;

        // Calculate the percentages for each benchmark
        let scheduler_percent = self.scheduler as f64 / elapsed;
        let manager_percent = self.manager as f64 / elapsed;

        // Calculate the remaining percentage that has not been benchmarked
        let mut other_percent = 1.0;
        other_percent -= scheduler_percent;
        other_percent -= manager_percent;

        // Create the formatted string
        writeln!(
            f,
            "  {scheduler_percent:6.4}: Scheduler\n  {manager_percent:6.4}: Manager"
        )?;

        // Calculate each stage
        // Make sure we only iterate over used stages
        for (stage_index, features) in self.used_stages() {
            // Write the stage header
            writeln!(f, "  Stage {stage_index}:")?;

            for (feature_index, feature) in features.iter().enumerate() {
                // Calculate this current stage's percentage
                let feature_percent = *feature as f64 / elapsed;

                // Ignore this feature if it isn't used
                if feature_percent == 0.0 {
                    continue;
                }

                // Update the other percent by removing this current percent
                other_percent -= feature_percent;

                // Get the actual feature from the feature index for printing its name
                let feature: PerfFeature = feature_index.into();

                // Write the percentage for this feature
                writeln!(f, "    {feature_percent:6.4}: {feature:?}")?;
            }
        }

        writeln!(f, "  Feedbacks:")?;

        for (feedback_name, feedback_time) in self.feedbacks() {
            // Calculate this current stage's percentage
            let feedback_percent = *feedback_time as f64 / elapsed;

            // Ignore this feedback if it isn't used
            if feedback_percent == 0.0 {
                continue;
            }

            // Update the other percent by removing this current percent
            other_percent -= feedback_percent;

            // Write the percentage for this feedback
            writeln!(f, "    {feedback_percent:6.4}: {feedback_name}")?;
        }

        write!(f, "  {other_percent:6.4}: Not Measured")?;

        Ok(())
    }
}

#[cfg(feature = "introspection")]
impl Default for ClientPerfMonitor {
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}
