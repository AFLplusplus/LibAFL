use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    vec::Vec,
};
use core::time::Duration;

use hashbrown::HashMap;
use libafl_bolts::current_time;

#[cfg(feature = "introspection")]
use crate::monitors::stats::perf_stats::{ClientPerfStats, PerfFeature};
pub use crate::monitors::stats::{
    ClientStats, EdgeCoverage, ItemGeometry, ProcessTiming, user_stats::UserStats,
};

/// The default time window for charts (10 minutes)
pub const DEFAULT_TIME_WINDOW: u64 = 60 * 10; // 10 min
const DEFAULT_LOGS_NUMBER: usize = 128;

/// A single status entry for timings
#[derive(Debug, Copy, Clone)]
pub struct TimedStat {
    /// The time
    pub time: Duration,
    /// The item
    pub item: f64,
}

/// Stats for timings
#[derive(Debug, Clone)]
pub struct TimedStats {
    /// Series of [`TimedStat`] entries
    pub series: VecDeque<TimedStat>,
    /// The time window to keep track of
    pub window: Duration,
}

impl TimedStats {
    /// Create a new [`TimedStats`] struct
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            series: VecDeque::new(),
            window,
        }
    }

    /// Add a stat datapoint
    pub fn add(&mut self, time: Duration, item: f64) {
        if self.series.is_empty() || (self.series.back().unwrap().item - item).abs() > f64::EPSILON
        {
            while self.series.front().is_some()
                && time
                    .checked_sub(self.series.front().unwrap().time)
                    .unwrap_or(self.window)
                    >= self.window
            {
                self.series.pop_front();
            }
            self.series.push_back(TimedStat { time, item });
        }
    }

    /// Add a stat datapoint for the `current_time`
    pub fn add_now(&mut self, item: f64) {
        let time = current_time();
        self.add(time, item);
    }

    /// Change the window duration
    pub fn update_window(&mut self, window: Duration) {
        let default_stat = TimedStat {
            time: Duration::from_secs(0),
            item: 0.0,
        };

        self.window = window;
        while !self.series.is_empty()
            && self
                .series
                .back()
                .unwrap_or(&default_stat)
                .time
                .checked_sub(self.series.front().unwrap_or(&default_stat).time)
                .unwrap_or(window)
                >= window
        {
            self.series.pop_front();
        }
    }
}

/// The context for a single client tracked in this [`TuiMonitor`]
#[derive(Debug, Default, Clone)]
pub struct ClientTuiContext {
    /// The client stats
    pub client_stats: ClientStats,

    /// Times for processing
    pub process_timing: ProcessTiming,
    /// The individual entry geometry
    pub item_geometry: Option<ItemGeometry>,
}

impl ClientTuiContext {
    /// Grab data for a single client
    pub fn grab_data(&mut self, client: &mut ClientStats) {
        self.process_timing = client.process_timing();
        self.item_geometry = client.item_geometry();
        self.client_stats = client.clone();
    }

    /// Get the number of cycles done
    #[must_use]
    pub fn cycles_done(&self) -> Option<u64> {
        #[cfg(feature = "std")]
        {
            if let Some(cycles) = self.client_stats.get_user_stats("cycles_done") {
                return cycles.value().as_u64();
            }

            self.client_stats.get_user_stats("AflStats").map(|s| {
                let json: serde_json::Value =
                    serde_json::from_str(&s.to_string()).unwrap_or(serde_json::json!({}));
                json["cycles_done"].as_u64().unwrap_or(0)
            })
        }
        #[cfg(not(feature = "std"))]
        None
    }

    /// Get the number of executions
    #[must_use]
    pub fn executions(&self) -> u64 {
        self.client_stats.executions()
    }

    /// Get the number of corpus items
    #[must_use]
    pub fn corpus(&self) -> u64 {
        self.client_stats.corpus_size()
    }

    /// Get the number of objectives found
    #[must_use]
    pub fn objectives(&self) -> u64 {
        self.client_stats.objective_size()
    }
}

/// The [`TuiContext`] for this [`TuiMonitor`]
#[derive(Debug, Clone)]
pub struct TuiContext {
    /// The graphs to display
    pub graphs: Vec<String>,

    /// Timed corpus size
    pub corpus_size_timed: TimedStats,
    /// Timed objective size
    pub objective_size_timed: TimedStats,
    /// Timed execs per sec
    pub execs_per_sec_timed: TimedStats,
    /// Timed custom user stats
    pub custom_timed: HashMap<String, TimedStats>,

    /// Clients stats
    pub clients: HashMap<usize, ClientTuiContext>,

    /// Logs from clients
    pub client_logs: VecDeque<String>,

    /// Total number of clients
    pub clients_num: usize,
    /// Total executions
    pub total_execs: u64,
    /// Start time
    pub start_time: Duration,

    /// Total map density
    pub total_map_density: String,
    /// Total solutions
    pub total_solutions: u64,
    /// Total corpus count
    pub total_corpus_count: u64,

    /// Total process timing
    pub total_process_timing: ProcessTiming,
    /// Total item geometry
    pub total_item_geometry: Option<ItemGeometry>,
}

impl TuiContext {
    /// Create a new TUI context
    #[must_use]
    pub fn new(start_time: Duration) -> Self {
        Self {
            graphs: vec!["corpus".into(), "objectives".into(), "exec/sec".into()],
            corpus_size_timed: TimedStats::new(Duration::from_secs(DEFAULT_TIME_WINDOW)),
            objective_size_timed: TimedStats::new(Duration::from_secs(DEFAULT_TIME_WINDOW)),
            execs_per_sec_timed: TimedStats::new(Duration::from_secs(DEFAULT_TIME_WINDOW)),
            custom_timed: HashMap::default(),

            clients: HashMap::default(),

            client_logs: VecDeque::with_capacity(DEFAULT_LOGS_NUMBER),

            clients_num: 0,
            total_execs: 0,
            start_time,

            total_map_density: "0%".to_string(),
            total_solutions: 0,
            total_corpus_count: 0,
            total_item_geometry: None,
            total_process_timing: ProcessTiming::new(),
        }
    }
}
