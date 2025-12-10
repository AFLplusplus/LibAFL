use alloc::{string::String, sync::Arc, vec::Vec};
use std::sync::RwLock;

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

#[cfg(feature = "introspection")]
use super::widgets::draw_introspection_text;
use super::{
    layout::{split_client, split_main, split_overall, split_title, split_top},
    widgets::{
        draw_client_generic_text, draw_client_results_text, draw_item_geometry_text, draw_logs,
        draw_overall_generic_text, draw_process_timing_text, draw_time_chart,
    },
};
use crate::monitors::tui::TuiContext;

/// The UI for the TUI monitor
#[derive(Default, Debug)]
pub struct TuiUi {
    title: String,
    version: String,
    enhanced_graphics: bool,
    show_logs: bool,
    client_idx: usize,
    clients: Vec<usize>,
    charts_tab_idx: usize,
    graph_data: Vec<(f64, f64)>,

    /// If the UI should quit
    pub should_quit: bool,
}

fn next_larger(sorted: &[usize], value: usize) -> Option<usize> {
    if let Some(index) = sorted.iter().position(|x| *x > value) {
        return Some(index);
    }
    None
}

fn next_smaller(sorted: &[usize], value: usize) -> Option<usize> {
    if let Some(index) = sorted.iter().rposition(|x| *x < value) {
        return Some(index);
    }
    None
}

impl TuiUi {
    /// Create a new [`TuiUi`] with the given title and enhanced graphics flag
    #[must_use]
    pub fn new(title: String, enhanced_graphics: bool) -> Self {
        Self::with_version(title, String::from("default"), enhanced_graphics)
    }

    /// create a new [`TuiUi`] with a given `version` string.
    #[must_use]
    pub fn with_version(title: String, version: String, enhanced_graphics: bool) -> Self {
        Self {
            title,
            version,
            enhanced_graphics,
            show_logs: true,
            client_idx: 0,
            ..TuiUi::default()
        }
    }

    /// Handle a key event
    pub fn on_key(&mut self, c: char, app: &Arc<RwLock<TuiContext>>) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            'g' => {
                self.charts_tab_idx = (self.charts_tab_idx + 1) % 3;
            }
            't' => {
                self.show_logs = !self.show_logs;
            }
            '+' => {
                let mut ctx = app.write().unwrap();
                let w = ctx.corpus_size_timed.window * 2;
                ctx.corpus_size_timed.update_window(w);
                let w = ctx.objective_size_timed.window * 2;
                ctx.objective_size_timed.update_window(w);
                let w = ctx.execs_per_sec_timed.window * 2;
                ctx.execs_per_sec_timed.update_window(w);
            }
            '-' => {
                let mut ctx = app.write().unwrap();
                let w = ctx.corpus_size_timed.window / 2;
                ctx.corpus_size_timed.update_window(w);
                let w = ctx.objective_size_timed.window / 2;
                ctx.objective_size_timed.update_window(w);
                let w = ctx.execs_per_sec_timed.window / 2;
                ctx.execs_per_sec_timed.update_window(w);
            }
            _ => {}
        }
    }

    /// Move to the next client
    pub fn on_right(&mut self) {
        if let Some(idx) = next_larger(&self.clients, self.client_idx) {
            self.client_idx = self.clients[idx];
        }
    }

    /// Move to the previous client
    pub fn on_left(&mut self) {
        if let Some(idx) = next_smaller(&self.clients, self.client_idx) {
            self.client_idx = self.clients[idx];
        }
    }

    /// Draw the current TUI context
    pub fn draw(&mut self, f: &mut Frame, app: &Arc<RwLock<TuiContext>>) {
        let new = app.read().unwrap().clients_num;
        if new != self.clients.len() {
            // get the list of all clients
            let mut all: Vec<usize> = app.read().unwrap().clients.keys().copied().collect();
            all.sort_unstable();

            // move the current client to the first one
            if !all.is_empty() {
                self.client_idx = all[0];
            }

            // move the vector holding all clients ids
            self.clients = all;
        }

        let area = f.area();
        let body = split_main(area, self.show_logs, cfg!(feature = "introspection"));

        let top_body = body[0];
        let mid_body = body[1];

        self.draw_overall_ui(f, app, top_body);
        self.draw_client_ui(f, app, mid_body);

        if self.show_logs {
            let bottom_body = body[2];
            draw_logs(f, app, bottom_body);
        }
    }

    fn draw_overall_ui(&mut self, f: &mut Frame, app: &Arc<RwLock<TuiContext>>, area: Rect) {
        let overall_layout = split_overall(area);
        // split_overall now returns a single area (or we treat it as such)
        // split_top splits it into Left (Stats) and Right (Charts)
        let top_layout = split_top(overall_layout[0]);

        // LEFT COLUMN: Stats
        // We want to stack Title, Generic, ProcessTiming, ItemGeometry.

        // 1. Title (3 lines)
        let left_title_layout = split_title(top_layout[0]);
        let status_bar: String = format!("{} ({})", self.title, self.version.as_str());
        let text = vec![Line::from(Span::styled(
            &status_bar,
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ))];
        let block = Block::default().borders(Borders::ALL);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        f.render_widget(paragraph, left_title_layout[0]);

        // 2. Stats (Generic -> Process -> Item)
        // Available height in left_title_layout[1] is (Total - 3).
        // Standard: 21 - 3 = 18. Compact: 17 - 3 = 14.

        let stats_area = left_title_layout[1];
        let stats_height = stats_area.height;

        // We need to fit 3 items.
        // Generic: 4 lines.
        // Process: 5 or 7.
        // Item: Remaining.

        let p_height = if stats_height < 16 { 5 } else { 7 }; // If we have 14 lines, 14 < 16 -> 5. 4+5=9. Item gets 5. Total 14.
        let g_height = 4;

        let left_stats_layout = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(g_height),
                    Constraint::Length(p_height),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(stats_area);

        draw_overall_generic_text(f, app, left_stats_layout[0], self.clients.len());
        draw_process_timing_text(f, app, left_stats_layout[1], true, 0, &[]);
        draw_item_geometry_text(f, app, left_stats_layout[2], true, 0, &[]);

        // RIGHT COLUMN: Charts
        // We need tab titles for all graphs
        let ctx_read = app.read().unwrap();
        let tabs = Tabs::new(
            ctx_read
                .graphs
                .iter()
                .map(|g| Span::from(g.clone()))
                .collect::<Vec<Span>>(),
        )
        .block(
            Block::default()
                .title(Span::styled(
                    "charts",
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().fg(Color::LightYellow))
        .select(self.charts_tab_idx);

        let title_chart_layout = split_title(top_layout[1]);
        f.render_widget(tabs, title_chart_layout[0]);

        let chart_layout = title_chart_layout[1];
        let graph_name = ctx_read.graphs.get(self.charts_tab_idx).map(|s| s.as_str());

        // Drop lock before drawing charts if needed, but drawing takes &stats ref which is tied to ctx_read?
        // Actually draw_time_chart takes &TimedStats. If we hold ctx_read, it's fine.

        if let Some(name) = graph_name {
            match name {
                "corpus" => draw_time_chart(
                    "corpus chart",
                    "corpus size",
                    f,
                    chart_layout,
                    &ctx_read.corpus_size_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                ),
                "objectives" => draw_time_chart(
                    "objectives chart",
                    "objectives",
                    f,
                    chart_layout,
                    &ctx_read.objective_size_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                ),
                "exec/sec" => draw_time_chart(
                    "speed chart",
                    "exec/sec",
                    f,
                    chart_layout,
                    &ctx_read.execs_per_sec_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                ),
                custom_name => {
                    if let Some(stats) = ctx_read.custom_timed.get(custom_name) {
                        draw_time_chart(
                            custom_name,
                            custom_name,
                            f,
                            chart_layout,
                            stats,
                            &mut self.graph_data,
                            self.enhanced_graphics,
                        );
                    }
                }
            }
        }
    }

    fn draw_client_ui(&mut self, f: &mut Frame, app: &Arc<RwLock<TuiContext>>, area: Rect) {
        let client_block = Block::default()
            .title(Span::styled(
                format!(
                    "client #{}{}",
                    self.client_idx,
                    if self.clients.len() > 1 {
                        " (←/→ arrows to switch)"
                    } else {
                        ""
                    }
                ),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL);

        #[allow(unused_mut)] // cfg dependent
        let mut client_area = client_block.inner(area);
        f.render_widget(client_block, area);

        #[cfg(feature = "introspection")]
        {
            let client_layout = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Min(11), Constraint::Percentage(50)].as_ref())
                .split(client_area);
            client_area = client_layout[0];
            let introspection_layout = client_layout[1];
            draw_introspection_text(f, app, introspection_layout, self.client_idx);
        }

        let left_layout = split_client(client_area);
        let right_layout = left_layout[1];

        let left_top_layout = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(0)].as_ref())
            .split(left_layout[0]);
        let left_bottom_layout = left_top_layout[1];

        draw_client_generic_text(f, app, left_top_layout[0], self.client_idx);
        draw_process_timing_text(
            f,
            app,
            left_bottom_layout,
            false,
            self.client_idx,
            &self.clients,
        );

        let height = if right_layout.height < 12 { 5 } else { 7 };
        let right_top_layout = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(height), Constraint::Min(0)].as_ref())
            .split(right_layout);
        let right_bottom_layout = right_top_layout[1];

        draw_item_geometry_text(
            f,
            app,
            right_top_layout[0],
            false,
            self.client_idx,
            &self.clients,
        );
        draw_client_results_text(f, app, right_bottom_layout, self.client_idx);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    #[cfg(feature = "introspection")]
    use crate::monitors::tui::PerfTuiContext;
    use crate::monitors::tui::{String, TuiContext};

    #[test]
    fn test_ui_rendering() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), false);
        let context = Arc::new(RwLock::new(TuiContext::new(Duration::from_secs(0))));

        // Add some dummy client data to context if needed
        {
            let mut ctx = context.write().unwrap();
            ctx.total_execs = 1000;
            ctx.clients_num = 1;

            // Create a mock client
            let mut client = crate::monitors::stats::ClientStats::default();
            client.update_corpus_size(10);
            client.update_executions(100, Duration::from_secs(1));

            ctx.clients.entry(0).or_default().grab_data(&mut client);

            // Add introspection mock data if feature enabled
            #[cfg(feature = "introspection")]
            {}

            ctx.client_logs.push_back(String::from("Log message 1"));
            ctx.client_logs.push_back(String::from("Log message 2"));
        }

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Render multiple times to simulate loop
        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        // Simulate key press
        tui_ui.on_key('g', &context); // switch tabs
        tui_ui.on_right(); // switch clients

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        // Check if verify the buffer content includes our title
        let buffer = terminal.backend().buffer();

        // Basic verification
        let content = format!("{:?}", buffer);
        assert!(content.contains("Test Fuzzer"));
        assert!(content.contains("generic"));
        assert!(content.contains("clients"));
    }

    #[test]
    fn test_small_ui_rendering() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), false);
        let context = Arc::new(RwLock::new(TuiContext::new(Duration::from_secs(0))));

        {
            let mut ctx = context.write().unwrap();
            ctx.total_execs = 1000;
            ctx.clients_num = 1;
            ctx.client_logs.push_back(String::from("Log message 1"));
        }

        // Height 30, Fixed overhead is 21 (Top) + 13 (Client) = 34.
        // This means logs get 0 space (or negative if not handled).
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // Let's assert that "Log message 1" is present.
        if !content.contains("Log message 1") {
            panic!(
                "Logs are not visible on small screen! Content: \n{}",
                content
            );
        }
    }
}
