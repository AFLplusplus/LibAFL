//! Monitor based on tui-rs

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use num_traits::PrimInt;
use std::{error::Error, io, io::BufRead, marker::Sync, time::Instant};
use tui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

use std::{
    cell::RefCell,
    cmp::{max, min},
    io::Stdout,
    string::String,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
    vec::Vec,
};

#[cfg(feature = "introspection")]
use alloc::string::ToString;

use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor},
};

mod ui;
use ui::TuiUI;

#[derive(Copy, Clone)]
pub struct TimedStat {
    pub time: Duration,
    pub item: u64,
}

impl Into<(f64, f64)> for TimedStat {
    fn into(self) -> (f64, f64) {
        ((self.time.as_secs()) as f64, self.item as f64)
    }
}

#[derive(Clone)]
pub struct TimedStats {
    pub series: Vec<TimedStat>,
    pub max: u64,
    pub min: u64,
}

impl TimedStats {
    pub fn new() -> Self {
        Self {
            series: vec![],
            max: u64::MIN,
            min: u64::MAX,
        }
    }

    pub fn add(&mut self, time: Duration, item: u64) {
        if self.series.is_empty() || self.series[self.series.len() - 1].item != item {
            self.series.push(TimedStat { time, item });
            self.max = max(self.max, item);
            self.min = min(self.min, item);
        }
    }

    pub fn add_now(&mut self, item: u64) {
        if self.series.is_empty() || self.series[self.series.len() - 1].item != item {
            self.series.push(TimedStat {
                time: current_time(),
                item,
            });
            self.max = max(self.max, item);
            self.min = min(self.min, item);
        }
    }
}

#[derive(Clone)]
pub struct TuiContext {
    pub title: String,
    pub enhanced_graphics: bool,
    pub charts_tab_idx: usize,
    pub show_logs: bool,
    pub should_quit: bool,

    pub graphs: Vec<String>,

    pub corpus_size_timed: TimedStats,
    pub objective_size_timed: TimedStats,
    pub execs_per_sec_timed: TimedStats,

    pub client_logs: Vec<String>,

    pub clients: usize, // TODO remove when implementing tabs
    pub total_execs: u64,
    pub start_time: Duration,
}

impl TuiContext {
    pub fn new(title: String, enhanced_graphics: bool, start_time: Duration) -> Self {
        Self {
            title,
            enhanced_graphics,
            charts_tab_idx: 0,
            show_logs: true,
            should_quit: false,

            graphs: vec!["corpus".into(), "objectives".into(), "exec/sec".into()],
            corpus_size_timed: TimedStats::new(),
            objective_size_timed: TimedStats::new(),
            execs_per_sec_timed: TimedStats::new(),
            client_logs: vec![],

            clients: 0,
            total_execs: 0,
            start_time,
        }
    }

    pub fn on_key(&mut self, c: char) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            't' => {
                //self.show_chart = !self.show_chart;
            }
            _ => {}
        }
    }
    
    pub fn on_up(&mut self) {
    }

    pub fn on_down(&mut self) {
    }

    pub fn on_right(&mut self) {
        self.charts_tab_idx = (self.charts_tab_idx + 1) % 3;
    }

    pub fn on_left(&mut self) {
        if self.charts_tab_idx > 0 {
            self.charts_tab_idx -= 1;
        } else {
            self.charts_tab_idx = 2;
        }
    }

}

/// Tracking monitor during fuzzing and display with tui-rs.
#[derive(Clone)]
pub struct TuiMonitor {
    pub context: Arc<RwLock<TuiContext>>,

    start_time: Duration,
    client_stats: Vec<ClientStats>,
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
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let cur_time = current_time();

        {
            let execsec = self.execs_per_sec();
            let totalexec = self.total_execs();
            let run_time = cur_time - self.start_time;

            let mut ctx = self.context.write().unwrap();
            ctx.corpus_size_timed.add(run_time, self.corpus_size());
            ctx.objective_size_timed
                .add(run_time, self.objective_size());
            ctx.execs_per_sec_timed.add(run_time, execsec);
            ctx.total_execs = totalexec;
            ctx.clients = self.client_stats.len();
        }

        let client = self.client_stats_mut_for(sender_id);
        let exec_sec = client.execs_per_sec(cur_time);

        let sender = format!("#{}", sender_id);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{}{} {}", event_msg, pad, sender);
        let mut fmt = format!(
            "[{}] corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_monitor {
            fmt += &format!(", {}: {}", key, val);
        }

        /*
        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            fmt += "\n";
            // Print the client performance monitor. Skip the Client 0 which is the broker
            for (i, client) in self.client_stats.iter().skip(1).enumerate() {
                fmt += &format!("Client {:03}:\n{}", i + 1, client.introspection_monitor);
            }
        }*/

        self.context.write().unwrap().client_logs.push(fmt);
    }
}

impl TuiMonitor {
    /// Creates the monitor
    pub fn new(title: String, enhanced_graphics: bool) -> Self {
        Self::with_time(title, enhanced_graphics, current_time())
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(title: String, enhanced_graphics: bool, start_time: Duration) -> Self {
        let context = Arc::new(RwLock::new(TuiContext::new(
            title,
            enhanced_graphics,
            start_time,
        )));
        run_tui_thread(context.clone(), Duration::from_millis(250));
        Self {
            context,
            start_time,
            client_stats: vec![],
        }
    }
}

fn run_tui_thread(context: Arc<RwLock<TuiContext>>, tick_rate: Duration) {
    thread::spawn(move || -> io::Result<()> {
        // setup terminal
        let mut stdout = io::stdout();
        enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        let mut ui = TuiUI::default();

        let mut last_tick = Instant::now();
        loop {
            terminal.draw(|f| ui.draw(f, &context))?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char(c) => context.write().unwrap().on_key(c),
                        KeyCode::Left => context.write().unwrap().on_left(),
                        //KeyCode::Up => context.write().unwrap().on_up(),
                        KeyCode::Right => context.write().unwrap().on_right(),
                        //KeyCode::Down => context.write().unwrap().on_down(),
                        _ => {}
                    }
                }
            }
            if last_tick.elapsed() >= tick_rate {
                //context.on_tick();
                last_tick = Instant::now();
            }
            if context.read().unwrap().should_quit {
                // restore terminal
                disable_raw_mode()?;
                execute!(
                    terminal.backend_mut(),
                    LeaveAlternateScreen,
                    DisableMouseCapture
                )?;
                terminal.show_cursor()?;

                println!("\nType Control-C to stop the fuzzers, otherwise press Enter to resume the visualization\n");

                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;

                // setup terminal
                let mut stdout = io::stdout();
                enable_raw_mode()?;
                execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

                context.write().unwrap().should_quit = false;
            }
        }

        Ok(())
    });
}
