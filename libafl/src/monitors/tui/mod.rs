//! Monitor based on ratatui

use alloc::{boxed::Box, string::ToString};
use std::{
    collections::VecDeque,
    fmt::Write as _,
    io::{self, BufRead, Write},
    panic,
    string::String,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
    vec::Vec,
};

use crossterm::{
    cursor::{EnableBlinking, Show},
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hashbrown::HashMap;
use libafl_bolts::{current_time, format_duration_hms, ClientId};
use ratatui::{backend::CrosstermBackend, Terminal};
use serde_json::Value;

#[cfg(feature = "introspection")]
use super::{ClientPerfMonitor, PerfFeature};
use crate::monitors::{Aggregator, AggregatorOps, ClientStats, Monitor, UserStats, UserStatsValue};

pub mod ui;
use ui::TuiUI;

const DEFAULT_TIME_WINDOW: u64 = 60 * 10; // 10 min
const DEFAULT_LOGS_NUMBER: usize = 128;

#[derive(Debug, Copy, Clone)]
pub struct TimedStat {
    pub time: Duration,
    pub item: u64,
}

#[derive(Debug, Clone)]
pub struct TimedStats {
    pub series: VecDeque<TimedStat>,
    pub window: Duration,
}

impl TimedStats {
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            series: VecDeque::new(),
            window,
        }
    }

    pub fn add(&mut self, time: Duration, item: u64) {
        if self.series.is_empty() || self.series.back().unwrap().item != item {
            if self.series.front().is_some()
                && time - self.series.front().unwrap().time > self.window
            {
                self.series.pop_front();
            }
            self.series.push_back(TimedStat { time, item });
        }
    }

    pub fn add_now(&mut self, item: u64) {
        if self.series.is_empty() || self.series[self.series.len() - 1].item != item {
            let time = current_time();
            if self.series.front().is_some()
                && time - self.series.front().unwrap().time > self.window
            {
                self.series.pop_front();
            }
            self.series.push_back(TimedStat { time, item });
        }
    }

    pub fn update_window(&mut self, window: Duration) {
        self.window = window;
        while !self.series.is_empty()
            && self.series.back().unwrap().time - self.series.front().unwrap().time > window
        {
            self.series.pop_front();
        }
    }
}

#[cfg(feature = "introspection")]
#[derive(Debug, Default, Clone)]
pub struct PerfTuiContext {
    pub scheduler: f64,
    pub manager: f64,
    pub unmeasured: f64,
    pub stages: Vec<Vec<(String, f64)>>,
    pub feedbacks: Vec<(String, f64)>,
}

#[cfg(feature = "introspection")]
impl PerfTuiContext {
    #[allow(clippy::cast_precision_loss)]
    pub fn grab_data(&mut self, m: &ClientPerfMonitor) {
        // Calculate the elapsed time from the monitor
        let elapsed: f64 = m.elapsed_cycles() as f64;

        // Calculate the percentages for each benchmark
        self.scheduler = m.scheduler_cycles() as f64 / elapsed;
        self.manager = m.manager_cycles() as f64 / elapsed;

        // Calculate the remaining percentage that has not been benchmarked
        let mut other_percent = 1.0;
        other_percent -= self.scheduler;
        other_percent -= self.manager;

        self.stages.clear();

        // Calculate each stage
        // Make sure we only iterate over used stages
        for (_stage_index, features) in m.used_stages() {
            let mut features_percentages = vec![];

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
                features_percentages.push((format!("{feature:?}"), feature_percent));
            }

            self.stages.push(features_percentages);
        }

        self.feedbacks.clear();

        for (feedback_name, feedback_time) in m.feedbacks() {
            // Calculate this current stage's percentage
            let feedback_percent = *feedback_time as f64 / elapsed;

            // Ignore this feedback if it isn't used
            if feedback_percent == 0.0 {
                continue;
            }

            // Update the other percent by removing this current percent
            other_percent -= feedback_percent;

            self.feedbacks
                .push((feedback_name.clone(), feedback_percent));
        }

        self.unmeasured = other_percent;
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProcessTiming {
    pub client_start_time: Duration,
    pub exec_speed: String,
    pub last_new_entry: Duration,
    pub last_saved_solution: Duration,
}

impl ProcessTiming {
    fn new() -> Self {
        Self {
            exec_speed: "0".to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ItemGeometry {
    pub pending: u64,
    pub pend_fav: u64,
    pub own_finds: u64,
    pub imported: u64,
    pub stability: String,
}

impl ItemGeometry {
    fn new() -> Self {
        Self {
            stability: "0%".to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ClientTuiContext {
    pub corpus: u64,
    pub objectives: u64,
    pub executions: u64,
    /// Float value formatted as String
    pub map_density: String,

    pub cycles_done: u64,

    pub process_timing: ProcessTiming,
    pub item_geometry: ItemGeometry,
    pub user_stats: HashMap<String, UserStats>,
}

impl ClientTuiContext {
    pub fn grab_data(&mut self, client: &ClientStats, exec_sec: String) {
        self.corpus = client.corpus_size;
        self.objectives = client.objective_size;
        self.executions = client.executions;
        self.process_timing.client_start_time = client.start_time;
        self.process_timing.last_new_entry = if client.last_corpus_time > client.start_time {
            client.last_corpus_time - client.start_time
        } else {
            Duration::default()
        };

        self.process_timing.last_saved_solution = if client.last_objective_time > client.start_time
        {
            client.last_objective_time - client.start_time
        } else {
            Duration::default()
        };

        self.process_timing.exec_speed = exec_sec;

        self.map_density = client
            .get_user_stats("edges")
            .map_or("0%".to_string(), ToString::to_string);

        let default_json = serde_json::json!({
            "pending": 0,
            "pend_fav": 0,
            "imported": 0,
            "own_finds": 0,
        });
        let afl_stats = client
            .get_user_stats("AflStats")
            .map_or(default_json.to_string(), ToString::to_string);

        let afl_stats_json: Value =
            serde_json::from_str(afl_stats.as_str()).unwrap_or(default_json);
        self.item_geometry.pending = afl_stats_json["pending"].as_u64().unwrap_or_default();
        self.item_geometry.pend_fav = afl_stats_json["pend_fav"].as_u64().unwrap_or_default();
        self.item_geometry.imported = afl_stats_json["imported"].as_u64().unwrap_or_default();
        self.item_geometry.own_finds = afl_stats_json["own_finds"].as_u64().unwrap_or_default();

        let stability = client
            .get_user_stats("stability")
            .map_or("0%".to_string(), ToString::to_string);
        self.item_geometry.stability = stability;

        for (key, val) in &client.user_monitor {
            self.user_stats.insert(key.clone(), val.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct TuiContext {
    pub graphs: Vec<String>,

    // TODO update the window using the UI key press events (+/-)
    pub corpus_size_timed: TimedStats,
    pub objective_size_timed: TimedStats,
    pub execs_per_sec_timed: TimedStats,

    #[cfg(feature = "introspection")]
    pub introspection: HashMap<usize, PerfTuiContext>,

    pub clients: HashMap<usize, ClientTuiContext>,

    pub client_logs: VecDeque<String>,

    pub clients_num: usize,
    pub total_execs: u64,
    pub start_time: Duration,

    pub total_map_density: String,
    pub total_solutions: u64,
    pub total_cycles_done: u64,
    pub total_corpus_count: u64,

    pub total_process_timing: ProcessTiming,
    pub total_item_geometry: ItemGeometry,
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

            #[cfg(feature = "introspection")]
            introspection: HashMap::default(),
            clients: HashMap::default(),

            client_logs: VecDeque::with_capacity(DEFAULT_LOGS_NUMBER),

            clients_num: 0,
            total_execs: 0,
            start_time,

            total_map_density: "0%".to_string(),
            total_solutions: 0,
            total_cycles_done: 0,
            total_corpus_count: 0,
            total_item_geometry: ItemGeometry::new(),
            total_process_timing: ProcessTiming::new(),
        }
    }
}

/// Tracking monitor during fuzzing and display with ratatui
#[derive(Debug, Clone)]
pub struct TuiMonitor {
    pub(crate) context: Arc<RwLock<TuiContext>>,

    start_time: Duration,
    client_stats: Vec<ClientStats>,
    aggregator: Aggregator,
}

impl Monitor for TuiMonitor {
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

    #[allow(clippy::cast_sign_loss)]
    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let cur_time = current_time();

        {
            // TODO implement floating-point support for TimedStat
            let execsec = self.execs_per_sec() as u64;
            let totalexec = self.total_execs();
            let run_time = cur_time - self.start_time;
            let total_process_timing = self.process_timing();

            let mut ctx = self.context.write().unwrap();
            ctx.total_process_timing = total_process_timing;
            ctx.corpus_size_timed.add(run_time, self.corpus_size());
            ctx.objective_size_timed
                .add(run_time, self.objective_size());
            ctx.execs_per_sec_timed.add(run_time, execsec);
            ctx.total_execs = totalexec;
            ctx.clients_num = self.client_stats.len();
            ctx.total_map_density = self.map_density();
            ctx.total_solutions = self.objective_size();
            ctx.total_cycles_done = 0;
            ctx.total_corpus_count = self.corpus_size();
            ctx.total_item_geometry = self.item_geometry();
        }

        self.client_stats_insert(sender_id);
        let client = self.client_stats_mut_for(sender_id);
        let exec_sec = client.execs_per_sec_pretty(cur_time);

        let sender = format!("#{}", sender_id.0);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{event_msg}{pad} {sender}");
        let mut fmt = format!(
            "[{}] corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_monitor {
            write!(fmt, ", {key}: {val}").unwrap();
        }
        for (key, val) in &self.aggregator.aggregated {
            write!(fmt, ", {key}: {val}").unwrap();
        }

        {
            let client = &self.client_stats()[sender_id.0 as usize];
            let mut ctx = self.context.write().unwrap();
            ctx.clients
                .entry(sender_id.0 as usize)
                .or_default()
                .grab_data(client, exec_sec);
            while ctx.client_logs.len() >= DEFAULT_LOGS_NUMBER {
                ctx.client_logs.pop_front();
            }
            ctx.client_logs.push_back(fmt);
        }

        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in self.client_stats.iter().skip(1).enumerate() {
                self.context
                    .write()
                    .unwrap()
                    .introspection
                    .entry(i + 1)
                    .or_default()
                    .grab_data(&client.introspection_monitor);
            }
        }
    }

    fn aggregate(&mut self, name: &str) {
        self.aggregator.aggregate(name, &self.client_stats);
    }
}

impl TuiMonitor {
    /// Creates the monitor
    #[must_use]
    pub fn new(tui_ui: TuiUI) -> Self {
        Self::with_time(tui_ui, current_time())
    }

    /// Creates the monitor with a given `start_time`.
    #[must_use]
    pub fn with_time(tui_ui: TuiUI, start_time: Duration) -> Self {
        let context = Arc::new(RwLock::new(TuiContext::new(start_time)));

        enable_raw_mode().unwrap();
        #[cfg(unix)]
        {
            use std::{
                fs::File,
                os::fd::{AsRawFd, FromRawFd},
            };

            let stdout = unsafe { libc::dup(io::stdout().as_raw_fd()) };
            let stdout = unsafe { File::from_raw_fd(stdout) };
            run_tui_thread(
                context.clone(),
                Duration::from_millis(250),
                tui_ui,
                move || stdout.try_clone().unwrap(),
            );
        }
        #[cfg(not(unix))]
        {
            run_tui_thread(
                context.clone(),
                Duration::from_millis(250),
                tui_ui,
                io::stdout,
            );
        }
        Self {
            context,
            start_time,
            client_stats: vec![],
            aggregator: Aggregator::new(),
        }
    }

    fn map_density(&self) -> String {
        if self.client_stats.len() < 2 {
            return "0%".to_string();
        }
        let mut max_map_density = self
            .client_stats()
            .get(1)
            .unwrap()
            .get_user_stats("edges")
            .map_or("0%".to_string(), ToString::to_string);

        for client in self.client_stats().iter().skip(2) {
            let client_map_density = client
                .get_user_stats("edges")
                .map_or(String::new(), ToString::to_string);
            if client_map_density > max_map_density {
                max_map_density = client_map_density;
            }
        }
        max_map_density
    }

    fn item_geometry(&self) -> ItemGeometry {
        let mut total_item_geometry = ItemGeometry::new();
        if self.client_stats.len() < 2 {
            return total_item_geometry;
        }
        let mut ratio_a: u64 = 0;
        let mut ratio_b: u64 = 0;
        for client in self.client_stats().iter().skip(1) {
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

    fn process_timing(&mut self) -> ProcessTiming {
        let mut total_process_timing = ProcessTiming::new();
        total_process_timing.exec_speed = self.execs_per_sec_pretty();
        if self.client_stats.len() > 1 {
            let mut new_path_time = Duration::default();
            let mut new_objectives_time = Duration::default();
            for client in self.client_stats().iter().skip(1) {
                new_path_time = client.last_corpus_time.max(new_path_time);
                new_objectives_time = client.last_objective_time.max(new_objectives_time);
            }
            if new_path_time > self.start_time {
                total_process_timing.last_new_entry = new_path_time - self.start_time;
            }
            if new_objectives_time > self.start_time {
                total_process_timing.last_saved_solution = new_objectives_time - self.start_time;
            }
        }
        total_process_timing
    }
}

fn run_tui_thread<W: Write + Send + Sync + 'static>(
    context: Arc<RwLock<TuiContext>>,
    tick_rate: Duration,
    tui_ui: TuiUI,
    stdout_provider: impl Send + Sync + 'static + Fn() -> W,
) {
    thread::spawn(move || -> io::Result<()> {
        // setup terminal
        let mut stdout = stdout_provider();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut ui = tui_ui;

        let mut last_tick = Instant::now();
        let mut cnt = 0;

        // Catching panics when the main thread dies
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            let mut stdout = stdout_provider();
            disable_raw_mode().unwrap();
            execute!(
                stdout,
                LeaveAlternateScreen,
                DisableMouseCapture,
                Show,
                EnableBlinking,
            )
            .unwrap();
            old_hook(panic_info);
        }));

        loop {
            // to avoid initial ui glitches
            if cnt < 8 {
                drop(terminal.clear());
                cnt += 1;
            }
            terminal.draw(|f| ui.draw(f, &context))?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char(c) => ui.on_key(c),
                        KeyCode::Left => ui.on_left(),
                        //KeyCode::Up => ui.on_up(),
                        KeyCode::Right => ui.on_right(),
                        //KeyCode::Down => ui.on_down(),
                        _ => {}
                    }
                }
            }
            if last_tick.elapsed() >= tick_rate {
                //context.on_tick();
                last_tick = Instant::now();
            }
            if ui.should_quit {
                // restore terminal
                disable_raw_mode()?;
                execute!(
                    terminal.backend_mut(),
                    LeaveAlternateScreen,
                    DisableMouseCapture
                )?;
                terminal.show_cursor()?;

                println!("\nPress Control-C to stop the fuzzers, otherwise press Enter to resume the visualization\n");

                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;

                // setup terminal
                let mut stdout = io::stdout();
                enable_raw_mode()?;
                execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

                cnt = 0;
                ui.should_quit = false;
            }
        }
    });
}
