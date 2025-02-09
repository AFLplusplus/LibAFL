//! Client statistics manager

mod global_stats;
use alloc::{borrow::Cow, vec::Vec};
use core::time::Duration;

pub use global_stats::*;
use hashbrown::HashMap;
use libafl_bolts::{current_time, ClientId};

use super::{user_stats::UserStatsValue, ClientStats};

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
    pub fn aggregate(&mut self, name: Cow<'static, str>) {
        super::user_stats::aggregate_user_stats(self, name);
    }

    /// Get aggregated user-defined stats
    #[must_use]
    pub fn aggregated(&self) -> &HashMap<Cow<'static, str>, UserStatsValue> {
        &self.cached_aggregated_user_stats
    }
}

impl Default for ClientStatsManager {
    fn default() -> Self {
        Self::new()
    }
}
