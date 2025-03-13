//! Client statistics manager

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{borrow::Cow, string::String, vec::Vec};
use core::time::Duration;

use hashbrown::HashMap;
use libafl_bolts::{ClientId, current_time, format_duration_hms};
#[cfg(feature = "std")]
use serde_json::Value;

use super::{ClientStats, EdgeCoverage, ProcessTiming, user_stats::UserStatsValue};
#[cfg(feature = "std")]
use super::{
    ItemGeometry,
    user_stats::{AggregatorOps, UserStats},
};

/// Manager of all client's statistics
#[derive(Debug)]
pub struct ClientStatsManager {
    client_stats: Vec<ClientStats>,
    /// Aggregated user stats value.
    ///
    /// This map is updated by event manager, and is read by monitors to display user-defined stats.
    pub(super) cached_aggregated_user_stats: HashMap<Cow<'static, str>, UserStatsValue>,
    /// Cached global stats.
    ///
    /// This will be erased to `None` every time a client is updated with crucial stats.
    cached_global_stats: Option<GlobalStats>,
    start_time: Duration,
}

impl ClientStatsManager {
    /// Create a new client stats manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_stats: vec![],
            cached_aggregated_user_stats: HashMap::new(),
            cached_global_stats: None,
            start_time: current_time(),
        }
    }

    /// Get all client stats
    #[must_use]
    pub fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// The client monitor for a specific id, creating new if it doesn't exist
    pub fn client_stats_insert(&mut self, client_id: ClientId) {
        let total_client_stat_count = self.client_stats().len();
        for _ in total_client_stat_count..=(client_id.0) as usize {
            self.client_stats.push(ClientStats {
                enabled: false,
                last_window_time: Duration::from_secs(0),
                start_time: Duration::from_secs(0),
                ..ClientStats::default()
            });
        }
        if total_client_stat_count <= client_id.0 as usize {
            // The client count changed!
            self.cached_global_stats = None;
        }
        self.update_client_stats_for(client_id, |new_stat| {
            if !new_stat.enabled {
                let timestamp = current_time();
                // I have never seen this man in my life
                new_stat.start_time = timestamp;
                new_stat.last_window_time = timestamp;
                new_stat.enabled = true;
                new_stat.stats_status.basic_stats_updated = true;
            }
        });
    }

    /// Update sepecific client stats.
    ///
    /// This will potentially clear the global stats cache.
    pub fn update_client_stats_for<T, F: FnOnce(&mut ClientStats) -> T>(
        &mut self,
        client_id: ClientId,
        update: F,
    ) -> T {
        let client_stat = &mut self.client_stats[client_id.0 as usize];
        client_stat.clear_stats_status();
        let res = update(client_stat);
        if client_stat.stats_status.basic_stats_updated {
            self.cached_global_stats = None;
        }
        res
    }

    /// Update all client stats. This will clear all previous client stats, and fill in the new client stats.
    ///
    /// This will clear global stats cache.
    pub fn update_all_client_stats(&mut self, new_client_stats: Vec<ClientStats>) {
        self.client_stats = new_client_stats;
        self.cached_global_stats = None;
    }

    /// Get immutable reference to client stats
    #[must_use]
    pub fn client_stats_for(&self, client_id: ClientId) -> &ClientStats {
        &self.client_stats()[client_id.0 as usize]
    }

    /// Aggregate user-defined stats
    #[allow(clippy::ptr_arg)]
    pub fn aggregate(&mut self, name: &Cow<'static, str>) {
        super::user_stats::aggregate_user_stats(self, name);
    }

    /// Get aggregated user-defined stats
    #[must_use]
    pub fn aggregated(&self) -> &HashMap<Cow<'static, str>, UserStatsValue> {
        &self.cached_aggregated_user_stats
    }
    /// Time this fuzzing run stated
    #[must_use]
    pub fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    pub fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    /// Get global stats.
    ///
    /// This global stats will be cached until the underlined client stats are modified.
    pub fn global_stats(&mut self) -> &GlobalStats {
        let global_stats = self.cached_global_stats.get_or_insert_with(|| GlobalStats {
            client_stats_count: self
                .client_stats
                .iter()
                .filter(|client| client.enabled)
                .count(),
            corpus_size: self
                .client_stats
                .iter()
                .fold(0_u64, |acc, x| acc + x.corpus_size),
            objective_size: self
                .client_stats
                .iter()
                .fold(0_u64, |acc, x| acc + x.objective_size),
            total_execs: self
                .client_stats
                .iter()
                .fold(0_u64, |acc, x| acc + x.executions),
            ..GlobalStats::default()
        });

        // Time-related data are always re-computed, since it is related with current time.
        let cur_time = current_time();
        global_stats.run_time = cur_time - self.start_time;
        global_stats.run_time_pretty = format_duration_hms(&global_stats.run_time);
        global_stats.execs_per_sec = self
            .client_stats
            .iter_mut()
            .fold(0.0, |acc, x| acc + x.execs_per_sec(cur_time));
        global_stats.execs_per_sec_pretty = super::prettify_float(global_stats.execs_per_sec);

        global_stats
    }

    /// Get process timing. `execs_per_sec_pretty` could be retrieved from `GlobalStats`.
    #[must_use]
    pub fn process_timing(&self, execs_per_sec_pretty: String) -> ProcessTiming {
        let mut total_process_timing = ProcessTiming::new();
        total_process_timing.exec_speed = execs_per_sec_pretty;
        if self.client_stats().len() > 1 {
            let mut new_path_time = Duration::default();
            let mut new_objectives_time = Duration::default();
            for client in self.client_stats().iter().filter(|client| client.enabled()) {
                new_path_time = client.last_corpus_time().max(new_path_time);
                new_objectives_time = client.last_objective_time().max(new_objectives_time);
            }
            if new_path_time > self.start_time() {
                total_process_timing.last_new_entry = new_path_time - self.start_time();
            }
            if new_objectives_time > self.start_time() {
                total_process_timing.last_saved_solution = new_objectives_time - self.start_time();
            }
        }
        total_process_timing
    }

    /// Get max edges coverage of all clients
    #[must_use]
    pub fn edges_coverage(&self) -> Option<EdgeCoverage> {
        self.client_stats()
            .iter()
            .filter(|client| client.enabled())
            .filter_map(ClientStats::edges_coverage)
            .max_by_key(
                |EdgeCoverage {
                     edges_hit,
                     edges_total,
                 }| { *edges_hit * 100 / *edges_total },
            )
    }

    /// Get item geometry
    #[expect(clippy::cast_precision_loss)]
    #[cfg(feature = "std")]
    #[must_use]
    pub fn item_geometry(&self) -> ItemGeometry {
        let mut total_item_geometry = ItemGeometry::new();
        if self.client_stats().len() < 2 {
            return total_item_geometry;
        }
        let mut ratio_a: u64 = 0;
        let mut ratio_b: u64 = 0;
        for client in self.client_stats().iter().filter(|client| client.enabled()) {
            let afl_stats = client
                .get_user_stats("AflStats")
                .map_or("None".to_string(), ToString::to_string);
            let stability = client.get_user_stats("stability").map_or(
                UserStats::new(UserStatsValue::Ratio(0, 100), AggregatorOps::Avg),
                Clone::clone,
            );

            if afl_stats != "None" {
                let default_json = serde_json::json!({
                    "pending": 0,
                    "pend_fav": 0,
                    "imported": 0,
                    "own_finds": 0,
                });
                let afl_stats_json: Value =
                    serde_json::from_str(afl_stats.as_str()).unwrap_or(default_json);
                total_item_geometry.pending +=
                    afl_stats_json["pending"].as_u64().unwrap_or_default();
                total_item_geometry.pend_fav +=
                    afl_stats_json["pend_fav"].as_u64().unwrap_or_default();
                total_item_geometry.own_finds +=
                    afl_stats_json["own_finds"].as_u64().unwrap_or_default();
                total_item_geometry.imported +=
                    afl_stats_json["imported"].as_u64().unwrap_or_default();
            }

            if let UserStatsValue::Ratio(a, b) = stability.value() {
                ratio_a += a;
                ratio_b += b;
            }
        }
        total_item_geometry.stability = if ratio_b == 0 {
            None
        } else {
            Some((ratio_a as f64) / (ratio_b as f64))
        };
        total_item_geometry
    }
}

impl Default for ClientStatsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global statistics which aggregates client stats.
#[derive(Debug, Default)]
pub struct GlobalStats {
    /// Run time since started
    pub run_time: Duration,
    /// Run time since started
    pub run_time_pretty: String,
    /// Count the number of enabled client stats
    pub client_stats_count: usize,
    /// Amount of elements in the corpus (combined for all children)
    pub corpus_size: u64,
    /// Amount of elements in the objectives (combined for all children)
    pub objective_size: u64,
    /// Total executions
    pub total_execs: u64,
    /// Executions per second
    pub execs_per_sec: f64,
    /// Executions per second
    pub execs_per_sec_pretty: String,
}
