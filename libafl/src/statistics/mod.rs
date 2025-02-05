//! Statistics used for Monitors to display.

pub mod manager;
#[cfg(feature = "introspection")]
pub mod perf_stats;
pub mod user_stats;

use alloc::{borrow::Cow, string::String};
use core::time::Duration;
use hashbrown::HashMap;
use libafl_bolts::current_time;
use serde::{Deserialize, Serialize};
use user_stats::UserStats;

#[cfg(feature = "afl_exec_sec")]
const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5; // 5 seconds

/// A simple struct to keep track of client statistics
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
    /// User-defined stats
    pub user_stats: HashMap<Cow<'static, str>, UserStats>,
    /// Client performance statistics
    #[cfg(feature = "introspection")]
    pub introspection_stats: perf_stats::ClientPerfStats,
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
    #[expect(clippy::cast_precision_loss, clippy::cast_sign_loss)]
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
    #[expect(clippy::cast_precision_loss, clippy::cast_sign_loss)]
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
    pub fn execs_per_sec_pretty(&mut self, cur_time: Duration) -> String {
        prettify_float(self.execs_per_sec(cur_time))
    }

    /// Update the user-defined stat with name and value
    pub fn update_user_stats(
        &mut self,
        name: Cow<'static, str>,
        value: UserStats,
    ) -> Option<UserStats> {
        self.user_stats.insert(name, value)
    }

    #[must_use]
    /// Get a user-defined stat using the name
    pub fn get_user_stats(&self, name: &str) -> Option<&UserStats> {
        self.user_stats.get(name)
    }

    /// Update the current [`ClientPerfMonitor`] with the given [`ClientPerfMonitor`]
    #[cfg(feature = "introspection")]
    pub fn update_introspection_monitor(&mut self, introspection_monitor: ClientPerfMonitor) {
        self.introspection_monitor = introspection_monitor;
    }
}

/// Prettifies float values for human-readable output
fn prettify_float(value: f64) -> String {
    let (value, suffix) = match value {
        value if value >= 1_000_000.0 => (value / 1_000_000.0, "M"),
        value if value >= 1_000.0 => (value / 1_000.0, "k"),
        value => (value, ""),
    };
    match value {
        value if value >= 1_000_000.0 => {
            format!("{value:.2}{suffix}")
        }
        value if value >= 1_000.0 => {
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
