//! Keep stats, and dispaly them to the user. Usually used in a broker, or main node, of some sort.

use alloc::{string::String, vec::Vec};
use core::{time, time::Duration};

use crate::utils::current_time;

const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5; // 5 seconds

/// A simple struct to keep track of client stats
#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    // stats (maybe we need a separated struct?)
    /// The corpus size for this client
    pub corpus_size: u64,
    /// The total executions for this client
    pub executions: u64,
    /// The size of the objectives corpus for this client
    pub objective_size: u64,
    /// The last reported executions for this client
    pub last_window_executions: u64,
    /// The last time we got this information
    pub last_window_time: time::Duration,
    /// The last executions per sec
    pub last_execs_per_sec: f32,
}

impl ClientStats {
    /// We got a new information about executions for this client, insert them.
    pub fn update_executions(&mut self, executions: u64, cur_time: time::Duration) {
        let diff = cur_time
            .checked_sub(self.last_window_time)
            .map_or(0, |d| d.as_secs());
        if diff > CLIENT_STATS_TIME_WINDOW_SECS {
            let _ = self.execs_per_sec(cur_time);
            self.last_window_time = cur_time;
            self.last_window_executions = self.executions;
        }
        self.executions = executions;
    }

    /// We got a new information about corpus size for this client, insert them.
    pub fn update_corpus_size(&mut self, corpus_size: u64) {
        self.corpus_size = corpus_size;
    }

    /// We got a new information about objective corpus size for this client, insert them.
    pub fn update_objective_size(&mut self, objective_size: u64) {
        self.objective_size = objective_size;
    }

    /// Get the calculated executions per second for this client
    pub fn execs_per_sec(&mut self, cur_time: time::Duration) -> u64 {
        if self.executions == 0 {
            return 0;
        }

        let elapsed = cur_time
            .checked_sub(self.last_window_time)
            .map_or(0, |d| d.as_secs());
        if elapsed == 0 {
            return self.last_execs_per_sec as u64;
        }

        let cur_avg = ((self.executions - self.last_window_executions) as f32) / (elapsed as f32);
        if self.last_window_executions == 0 {
            self.last_execs_per_sec = cur_avg;
            return self.last_execs_per_sec as u64;
        }

        // If there is a dramatic (5x+) jump in speed, reset the indicator more quickly
        if cur_avg * 5.0 < self.last_execs_per_sec || cur_avg / 5.0 > self.last_execs_per_sec {
            self.last_execs_per_sec = cur_avg;
        }

        self.last_execs_per_sec =
            self.last_execs_per_sec * (1.0 - 1.0 / 16.0) + cur_avg * (1.0 / 16.0);
        self.last_execs_per_sec as u64
    }
}

/// The stats trait keeps track of all the client's stats, and offers methods to dispaly them.
pub trait Stats {
    /// the client stats (mut)
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats>;

    /// the client stats
    fn client_stats(&self) -> &[ClientStats];

    /// creation time
    fn start_time(&mut self) -> time::Duration;

    /// show the stats to the user
    fn display(&mut self, event_msg: String);

    /// Amount of elements in the corpus (combined for all children)
    fn corpus_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.corpus_size)
    }

    /// Amount of elements in the objectives (combined for all children)
    fn objective_size(&self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.objective_size)
    }

    /// Total executions
    #[inline]
    fn total_execs(&mut self) -> u64 {
        self.client_stats()
            .iter()
            .fold(0_u64, |acc, x| acc + x.executions)
    }

    /// Executions per second
    #[inline]
    fn execs_per_sec(&mut self) -> u64 {
        let cur_time = current_time();
        self.client_stats_mut()
            .iter_mut()
            .fold(0_u64, |acc, x| acc + x.execs_per_sec(cur_time))
    }

    /// The client stats for a specific id, creating new if it doesn't exist
    fn client_stats_mut_for(&mut self, client_id: u32) -> &mut ClientStats {
        let client_stat_count = self.client_stats().len();
        for _ in client_stat_count..(client_id + 1) as usize {
            self.client_stats_mut().push(ClientStats {
                last_window_time: current_time(),
                ..Default::default()
            })
        }
        &mut self.client_stats_mut()[client_id as usize]
    }
}

#[derive(Clone, Debug)]
pub struct SimpleStats<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    corpus_size: usize,
    client_stats: Vec<ClientStats>,
}

impl<F> Stats for SimpleStats<F>
where
    F: FnMut(String),
{
    /// the client stats, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client stats
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String) {
        let fmt = format!(
            "[{}] clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(fmt);
    }
}

impl<F> SimpleStats<F>
where
    F: FnMut(String),
{
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            corpus_size: 0,
            client_stats: vec![],
        }
    }

    pub fn with_time(print_fn: F, start_time: time::Duration) -> Self {
        Self {
            print_fn,
            start_time,
            corpus_size: 0,
            client_stats: vec![],
        }
    }
}
