//! Keep stats, and dispaly them to the user. Usually used in a broker, or main node, of some sort.

pub mod multi;
pub use multi::MultiMonitor;

use serde::{Deserialize, Serialize};

use alloc::{string::String, vec::Vec};
use core::{fmt, time, time::Duration};

use hashbrown::HashMap;

#[cfg(feature = "introspection")]
use alloc::string::ToString;

use crate::bolts::{current_time, format_duration_hms};

const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5; // 5 seconds

/// User-defined stat types
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserStats {
    Number(u64),
    String(String),
    Ratio(u64, u64),
}

impl fmt::Display for UserStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserStats::Number(n) => write!(f, "{}", n),
            UserStats::String(s) => write!(f, "{}", s),
            UserStats::Ratio(a, b) => {
                if *b == 0 {
                    write!(f, "{}/{}", a, b)
                } else {
                    write!(f, "{}/{} ({}%)", a, b, a * 100 / b)
                }
            }
        }
    }
}

/// A simple struct to keep track of client monitor
#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    // monitor (maybe we need a separated struct?)
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
    /// User-defined monitor
    pub user_monitor: HashMap<String, UserStats>,
    /// Stability, and if we ever received a stability value
    pub stability: Option<f64>,
    /// Client performance statistics
    #[cfg(feature = "introspection")]
    pub introspection_monitor: ClientPerfMonitor,
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

    /// we got a new information about stability for this client, insert it.
    pub fn update_stability(&mut self, stability: f64) {
        self.stability = Some(stability);
    }

    /// Get the calculated executions per second for this client
    #[allow(clippy::cast_sign_loss, clippy::cast_precision_loss)]
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

    /// Update the user-defined stat with name and value
    pub fn update_user_stats(&mut self, name: String, value: UserStats) {
        self.user_monitor.insert(name, value);
    }

    /// Get a user-defined stat using the name
    pub fn get_user_stats(&mut self, name: &str) -> Option<&UserStats> {
        self.user_monitor.get(name)
    }

    /// Update the current [`ClientPerfMonitor`] with the given [`ClientPerfMonitor`]
    #[cfg(feature = "introspection")]
    pub fn update_introspection_monitor(&mut self, introspection_monitor: ClientPerfMonitor) {
        self.introspection_monitor = introspection_monitor;
    }
}

/// The monitor trait keeps track of all the client's monitor, and offers methods to dispaly them.
pub trait Monitor {
    /// the client monitor (mut)
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats>;

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats];

    /// creation time
    fn start_time(&mut self) -> time::Duration;

    /// show the monitor to the user
    fn display(&mut self, event_msg: String, sender_id: u32);

    /// Show the Stabiliity
    fn stability(&self) -> Option<f64> {
        let mut stability_total = 0_f64;
        let mut num = 0_usize;
        for stat in self.client_stats() {
            if let Some(stability) = stat.stability {
                stability_total += stability;
                num += 1;
            }
        }
        if num == 0 {
            return None;
        }
        return Some(stability_total / num as f64);
    }

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

    /// The client monitor for a specific id, creating new if it doesn't exist
    fn client_stats_mut_for(&mut self, client_id: u32) -> &mut ClientStats {
        let client_stat_count = self.client_stats().len();
        for _ in client_stat_count..(client_id + 1) as usize {
            self.client_stats_mut().push(ClientStats {
                last_window_time: current_time(),
                ..ClientStats::default()
            });
        }
        &mut self.client_stats_mut()[client_id as usize]
    }
}

/// Monitor that print exactly nothing.
/// Not good for debuging, very good for speed.
pub struct NopMonitor {
    start_time: Duration,
    client_stats: Vec<ClientStats>,
}

impl Monitor for NopMonitor {
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, _event_msg: String, _sender_id: u32) {}
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

/// Tracking monitor during fuzzing.
#[derive(Clone, Debug)]
pub struct SimpleMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
}

impl<F> Monitor for SimpleMonitor<F>
where
    F: FnMut(String),
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
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let fmt = format!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {},{} exec/sec: {}",
            event_msg,
            sender_id,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            if let Some(stability) = self.stability() {
                format!(", stability: {:.2}", stability)
            } else {
                "".to_string()
            },
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            let fmt = format!(
                "Client {:03}:\n{}",
                sender_id, self.client_stats[sender_id as usize].introspection_monitor
            );
            (self.print_fn)(fmt);

            // Separate the spacing just a bit
            (self.print_fn)("".to_string());
        }
    }
}

impl<F> SimpleMonitor<F>
where
    F: FnMut(String),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: time::Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
        }
    }
}

#[macro_export]
macro_rules! start_timer {
    ($state:expr) => {{
        // Start the timer
        #[cfg(feature = "introspection")]
        $state.introspection_monitor_mut().start_timer();
    }};
}

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
            _ => panic!("Unknown PerfFeature: {}", val),
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
        let start_time = crate::bolts::cpu::read_time_counter();

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
        self.timer_start = Some(crate::bolts::cpu::read_time_counter());
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
                #[cfg(feature = "std")]
                eprint!("Attempted to `mark_time` without starting timer first.");

                // Return 0 for no time marked
                0
            }
            Some(timer_start) => {
                // Calculate the elapsed time
                let elapsed = crate::bolts::cpu::read_time_counter() - timer_start;

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
        let stage_index: usize = self.curr_stage.try_into().unwrap();

        // Get the index of the given feature
        let feature_index: usize = feature.try_into().unwrap();

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
            .filter(move |(stage_index, _)| used[*stage_index as usize])
    }

    /// A map of all `feedbacks`
    #[must_use]
    pub fn feedbacks(&self) -> &HashMap<String, u64> {
        &self.feedbacks
    }
}

#[cfg(feature = "introspection")]
impl core::fmt::Display for ClientPerfMonitor {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
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
            "  {:6.4}: Scheduler\n  {:6.4}: Manager",
            scheduler_percent, manager_percent
        )?;

        // Calculate each stage
        // Make sure we only iterate over used stages
        for (stage_index, features) in self.used_stages() {
            // Write the stage header
            writeln!(f, "  Stage {}:", stage_index)?;

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
                writeln!(f, "    {:6.4}: {:?}", feature_percent, feature)?;
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
            writeln!(f, "    {:6.4}: {}", feedback_percent, feedback_name)?;
        }

        write!(f, "  {:6.4}: Not Measured", other_percent)?;

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
