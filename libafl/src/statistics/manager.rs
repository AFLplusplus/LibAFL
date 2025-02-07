//! Client statistics manager

use alloc::{string::String, vec::Vec};
use core::time::Duration;

use hashbrown::HashMap;
use libafl_bolts::{current_time, ClientId};
use serde::{Deserialize, Serialize};

use super::{user_stats::UserStatsValue, ClientStats};

/// Manager of all client's statistics
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientStatsManager {
    client_stats: Vec<ClientStats>,
    /// Aggregated user stats value.
    ///
    /// This map is updated by event manager, and is read by monitors to display user-defined stats.
    pub(super) cached_aggregated_user_stats: HashMap<String, UserStatsValue>,
    start_time: Duration,
}

impl ClientStatsManager {
    /// Create a new client stats manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_stats: vec![],
            cached_aggregated_user_stats: HashMap::new(),
            start_time: current_time(),
        }
    }

    /// Time this fuzzing run stated
    pub fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Time this fuzzing run stated
    pub fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    /// Get all client stats
    #[must_use]
    pub fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Get all client stats
    pub fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// Amount of elements in the corpus (combined for all children)
    #[must_use]
    pub fn corpus_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.corpus_size)
    }

    /// Count the number of enabled client stats
    #[must_use]
    pub fn client_stats_count(&self) -> usize {
        self.client_stats()
            .iter()
            .filter(|client| client.enabled)
            .count()
    }

    /// Amount of elements in the objectives (combined for all children)
    #[must_use]
    pub fn objective_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.objective_size)
    }

    /// Total executions
    #[inline]
    #[must_use]
    pub fn total_execs(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.executions)
    }

    /// Executions per second
    #[inline]
    pub fn execs_per_sec(&mut self) -> f64 {
        let cur_time = current_time();
        self.client_stats_mut()
            .iter_mut()
            .fold(0.0, |acc, x| acc + x.execs_per_sec(cur_time))
    }

    /// Executions per second
    pub fn execs_per_sec_pretty(&mut self) -> String {
        super::prettify_float(self.execs_per_sec())
    }

    /// The client monitor for a specific id, creating new if it doesn't exist
    pub fn client_stats_insert(&mut self, client_id: ClientId) {
        let total_client_stat_count = self.client_stats().len();
        for _ in total_client_stat_count..=(client_id.0) as usize {
            self.client_stats_mut().push(ClientStats {
                enabled: false,
                last_window_time: Duration::from_secs(0),
                start_time: Duration::from_secs(0),
                ..ClientStats::default()
            });
        }
        self.update_client_stats_for(client_id, |new_stat| {
            if !new_stat.enabled {
                let timestamp = current_time();
                // I have never seen this man in my life
                new_stat.start_time = timestamp;
                new_stat.last_window_time = timestamp;
                new_stat.enabled = true;
            }
        });
    }

    /// Update sepecific client stats.
    pub fn update_client_stats_for<T, F: FnOnce(&mut ClientStats) -> T>(
        &mut self,
        client_id: ClientId,
        update: F,
    ) -> T {
        let client_stat = &mut self.client_stats_mut()[client_id.0 as usize];
        update(client_stat)
    }

    /// Update all client stats. This will clear all previous client stats, and fill in the new client stats.
    pub fn update_all_client_stats(&mut self, new_client_stats: Vec<ClientStats>) {
        *self.client_stats_mut() = new_client_stats;
    }

    /// Get immutable reference to client stats
    #[must_use]
    pub fn client_stats_for(&self, client_id: ClientId) -> &ClientStats {
        &self.client_stats()[client_id.0 as usize]
    }

    /// Aggregate user-defined stats
    pub fn aggregate(&mut self, name: &str) {
        super::user_stats::aggregate_user_stats(self, name);
    }

    /// Get aggregated user-defined stats
    #[must_use]
    pub fn aggregated(&self) -> &HashMap<String, UserStatsValue> {
        &self.cached_aggregated_user_stats
    }
}

impl Default for ClientStatsManager {
    fn default() -> Self {
        Self::new()
    }
}
