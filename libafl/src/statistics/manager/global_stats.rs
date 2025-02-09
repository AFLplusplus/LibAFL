//! Global statistics available for Monitors to use

use alloc::string::{String, ToString};
use core::{cmp, time::Duration};

use libafl_bolts::{current_time, format_duration_hms};
#[cfg(feature = "std")]
use serde_json::Value;

use super::ClientStatsManager;
use crate::statistics::ProcessTiming;
#[cfg(feature = "std")]
use crate::statistics::{
    user_stats::{AggregatorOps, UserStats, UserStatsValue},
    ItemGeometry,
};

impl ClientStatsManager {
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
            run_time: Duration::ZERO,
            run_time_pretty: String::new(),
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
            execs_per_sec: 0.0,
            execs_per_sec_pretty: String::new(),
        });

        // Time-related data are always re-computed, since it is related with current time.
        let cur_time = current_time();
        global_stats.run_time = cur_time - self.start_time;
        global_stats.run_time_pretty = format_duration_hms(&global_stats.run_time);
        global_stats.execs_per_sec = self
            .client_stats
            .iter_mut()
            .fold(0.0, |acc, x| acc + x.execs_per_sec(cur_time));
        global_stats
            .execs_per_sec_pretty
            .push_str(&super::super::prettify_float(global_stats.execs_per_sec));

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

    /// Get map density
    #[must_use]
    pub fn map_density(&self) -> String {
        self.client_stats()
            .iter()
            .filter(|client| client.enabled())
            .filter_map(|client| client.get_user_stats("edges"))
            .map(ToString::to_string)
            .fold("0%".to_string(), cmp::max)
    }

    /// Get item geometry
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
        total_item_geometry.stability = format!("{}%", ratio_a * 100 / ratio_b);
        total_item_geometry
    }
}

/// Global statistics which aggregates client stats.
#[derive(Debug)]
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
