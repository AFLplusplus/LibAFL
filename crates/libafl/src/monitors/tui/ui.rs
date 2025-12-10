use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use std::sync::RwLock;

use libafl_bolts::current_time;
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
        draw_client_generic_text, draw_item_geometry_text, draw_logs, draw_overall_generic_text,
        draw_process_timing_text, draw_time_chart,
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
    is_narrow: bool,
    logs_wrap: bool,

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
            clients: vec![],
            charts_tab_idx: 0,
            graph_data: vec![],
            is_narrow: false,
            logs_wrap: false,
            should_quit: false,
        }
    }

    /// Handle a key event
    pub fn on_key(&mut self, c: char, app: &Arc<RwLock<TuiContext>>) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            'g' => {
                let ctx = app.read().unwrap();
                let params = ctx.graphs.len();
                if params > 0 {
                    if self.is_narrow {
                        // 0 = Generic, 1..=params = Charts
                        // Total items = params + 1
                        self.charts_tab_idx = (self.charts_tab_idx + 1) % (params + 1);
                    } else {
                        // Normal behavior
                        self.charts_tab_idx = (self.charts_tab_idx + 1) % params;
                    }
                }
            }
            't' => {
                self.show_logs = !self.show_logs;
            }
            'w' => {
                self.logs_wrap = !self.logs_wrap;
            }
            '+' => {
                let mut ctx = app.write().unwrap();
                let w = ctx.corpus_size_timed.window * 2;
                ctx.corpus_size_timed.update_window(w);
                let w = ctx.objective_size_timed.window * 2;
                ctx.objective_size_timed.update_window(w);
                let w = ctx.execs_per_sec_timed.window * 2;
                ctx.execs_per_sec_timed.update_window(w);
                for timer in ctx.custom_timed.values_mut() {
                    let w = timer.window * 2;
                    timer.update_window(w);
                }
            }
            '-' => {
                let mut ctx = app.write().unwrap();
                let w = ctx.corpus_size_timed.window / 2;
                ctx.corpus_size_timed.update_window(w);
                let w = ctx.objective_size_timed.window / 2;
                ctx.objective_size_timed.update_window(w);
                let w = ctx.execs_per_sec_timed.window / 2;
                ctx.execs_per_sec_timed.update_window(w);
                for timer in ctx.custom_timed.values_mut() {
                    let w = timer.window / 2;
                    timer.update_window(w);
                }
            }
            _ => {}
        }
    }

    const NARROW_WIDTH_THRESHOLD: u16 = 75;

    /// Move to the next client
    pub fn on_right(&mut self) {
        if let Some(idx) = next_larger(&self.clients, self.client_idx) {
            self.client_idx = self.clients[idx];
        } else if !self.clients.is_empty() {
            self.client_idx = self.clients[0];
        }
    }

    /// Move to the previous client
    pub fn on_left(&mut self) {
        if let Some(idx) = next_smaller(&self.clients, self.client_idx) {
            self.client_idx = self.clients[idx];
        } else if !self.clients.is_empty() {
            self.client_idx = *self.clients.last().unwrap();
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

        #[cfg(feature = "introspection")]
        let introspection = true;
        #[cfg(not(feature = "introspection"))]
        let introspection = false;

        let has_charts = !app.read().unwrap().graphs.is_empty();

        let area = f.area();
        // If transitioning to narrow mode, enable wrap and reset tabs to Overview.
        let new_is_narrow = area.width < Self::NARROW_WIDTH_THRESHOLD;
        if new_is_narrow && !self.is_narrow {
            self.show_logs = false;
            // Force reset to Overview tab
            self.charts_tab_idx = 0;
        }
        self.is_narrow = new_is_narrow;

        // Narrow Mode or Short Mode with Logs: Replace Client View with Logs
        // "Short" = height < 28 (approx)
        let is_short = area.height < 28;
        let replace_client_with_logs = (self.is_narrow || is_short) && self.show_logs;

        if replace_client_with_logs {
            // Use split_main to calculate Top height properly
            let body = split_main(area, true, introspection, has_charts);
            let top_body = body[0];
            // Logs take the rest
            let logs_area = Rect::new(
                area.x,
                top_body.bottom(),
                area.width,
                area.height.saturating_sub(top_body.height),
            );

            // In narrow mode, we removed the title of "Overview", preventing double headers.
            self.draw_overall_ui(f, app, top_body, has_charts);
            draw_logs(f, app, logs_area, self.logs_wrap);
        } else {
            let body = split_main(area, self.show_logs, introspection, has_charts);

            let top_body = body[0];
            let mid_body = body[1];

            self.draw_overall_ui(f, app, top_body, has_charts);
            self.draw_client_ui(f, app, mid_body, self.show_logs);

            if self.show_logs && body.len() > 2 {
                let bottom_body = body[2];
                draw_logs(f, app, bottom_body, self.logs_wrap);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_stats_column(
        &self,
        f: &mut Frame,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
        has_process_timing: bool,
        has_geometry: bool,
        is_narrow: bool,
    ) {
        let p_height = if has_process_timing { 6 } else { 0 };
        let g_height = 4; // Generic height

        let mut constraints = vec![Constraint::Length(g_height)];
        if has_process_timing {
            constraints.push(Constraint::Length(p_height));
        }
        constraints.push(Constraint::Min(0)); // Geometry or empty

        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints(constraints)
            .split(area);

        draw_overall_generic_text(
            f,
            app,
            chunks[0],
            if is_narrow { "" } else { "Overview" },
            self.clients.len(),
        );

        let mut next_idx = 1;
        if has_process_timing {
            draw_process_timing_text(
                f,
                app,
                chunks[next_idx],
                "General",
                true,
                self.client_idx,
                &self.clients,
            );
            next_idx += 1;
        }

        if has_geometry {
            if let Some(chunk) = chunks.get(next_idx) {
                draw_item_geometry_text(f, app, *chunk, true, self.client_idx, &self.clients);
            }
        }
    }

    #[allow(deprecated)]
    fn draw_overall_ui(
        &mut self,
        f: &mut Frame,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
        has_charts: bool,
    ) {
        let overall_layout = split_overall(area);
        // split_overall now returns a single area (or we treat it as such)

        let ctx_read = app.read().unwrap();

        let (chart_layout, graph_name) = if self.is_narrow {
            // NARROW MODE
            // 0 = Generic Stats
            // 1.. = Charts

            // Prepare Tabs
            let mut tab_titles = vec![Span::from("Overview")];
            tab_titles.extend(ctx_read.graphs.iter().map(|g| Span::from(g.clone())));

            let tabs = Tabs::new(tab_titles)
                .block(
                    Block::default()
                        .title(Span::styled(
                            &self.title,
                            Style::default()
                                .fg(Color::LightMagenta)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .title(
                            ratatui::widgets::block::Title::from(Span::styled(
                                " `g` for next ",
                                Style::default()
                                    .fg(Color::LightCyan)
                                    .add_modifier(Modifier::BOLD),
                            ))
                            .alignment(Alignment::Right),
                        )
                        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT),
                )
                .highlight_style(Style::default().fg(Color::LightYellow))
                .select(self.charts_tab_idx);

            // We split the top area into [Tabs, Content]
            let layout_parts = split_title(overall_layout[0]);
            f.render_widget(tabs, layout_parts[0]);

            let content_area = layout_parts[1];

            if self.charts_tab_idx == 0 {
                // RENDER STATS (Generic, Timing, Geometry) in content_area
                let (has_process_timing, has_geometry) = {
                    let has_geometry = ctx_read.total_item_geometry.is_some();
                    let has_timing = if let Some(client) = ctx_read.clients.get(&0) {
                        client.process_timing.exec_speed != "0/sec"
                    } else {
                        false
                    };
                    (has_timing, has_geometry)
                };
                drop(ctx_read);

                self.draw_stats_column(
                    f,
                    app,
                    content_area,
                    has_process_timing,
                    has_geometry,
                    true,
                );

                (None, None)
            } else {
                // TAB > 0: Chart
                let graph_idx = self.charts_tab_idx - 1;
                let name = ctx_read.graphs.get(graph_idx).map(|s| s.to_string());
                drop(ctx_read);

                (Some(content_area), name)
            }
        } else {
            // NORMAL MODE
            drop(ctx_read);

            let top_layout = if !has_charts {
                vec![overall_layout[0]]
            } else {
                split_top(overall_layout[0])
            };

            // LEFT COLUMN: Stats
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

            let (has_process_timing, has_geometry) = {
                let ctx = app.read().unwrap();
                let has_geometry = ctx.total_item_geometry.is_some();
                let has_timing = if let Some(client) = ctx.clients.get(&0) {
                    client.process_timing.exec_speed != "0/sec"
                } else {
                    false
                };
                (has_timing, has_geometry)
            };

            self.draw_stats_column(
                f,
                app,
                left_title_layout[1],
                has_process_timing,
                has_geometry,
                false,
            );

            if !has_charts {
                return;
            }

            // RIGHT COLUMN: Charts
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
                        "charts (`g` for next)",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT),
            )
            .highlight_style(Style::default().fg(Color::LightYellow))
            .select(self.charts_tab_idx);

            let title_chart_layout = split_title(top_layout[1]);
            f.render_widget(tabs, title_chart_layout[0]);

            let chart_layout = title_chart_layout[1];

            let idx = if self.charts_tab_idx >= ctx_read.graphs.len() {
                0
            } else {
                self.charts_tab_idx
            };

            let graph_name = ctx_read.graphs.get(idx).map(|s| s.to_string());
            drop(ctx_read);

            (Some(chart_layout), graph_name)
        };

        if let (Some(layout), Some(name)) = (chart_layout, graph_name) {
            let ctx_read = app.read().unwrap();
            let run_time = current_time().saturating_sub(ctx_read.start_time);
            match name.as_str() {
                "corpus" => draw_time_chart(
                    "",
                    "corpus size",
                    f,
                    layout,
                    &ctx_read.corpus_size_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                    run_time,
                ),
                "objectives" => draw_time_chart(
                    "",
                    "objectives",
                    f,
                    layout,
                    &ctx_read.objective_size_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                    run_time,
                ),
                "exec/sec" => draw_time_chart(
                    "",
                    "exec/sec",
                    f,
                    layout,
                    &ctx_read.execs_per_sec_timed,
                    &mut self.graph_data,
                    self.enhanced_graphics,
                    run_time,
                ),
                custom_name => {
                    if let Some(stats) = ctx_read.custom_timed.get(custom_name) {
                        draw_time_chart(
                            "",
                            custom_name,
                            f,
                            layout,
                            stats,
                            &mut self.graph_data,
                            self.enhanced_graphics,
                            run_time,
                        );
                    }
                }
            }
        }
    }

    #[allow(deprecated)]
    fn draw_client_ui(
        &mut self,
        f: &mut Frame,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
        show_logs: bool,
    ) {
        let mut client_block = Block::default()
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

        if !show_logs {
            use ratatui::widgets::block::Title;
            client_block = client_block.title(
                Title::from(Span::styled(
                    "`t` for logs, `q` to quit",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Right),
            );
        }

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

        let narrow = area.width < Self::NARROW_WIDTH_THRESHOLD;

        let (has_process_timing, has_geometry) = {
            let ctx = app.read().unwrap();
            let has_geometry = if let Some(client) = ctx.clients.get(&self.client_idx) {
                client.item_geometry.is_some()
            } else {
                false
            };

            let has_timing = if let Some(client) = ctx.clients.get(&self.client_idx) {
                client.process_timing.exec_speed != "0/sec"
            } else {
                false
            };
            (has_timing, has_geometry)
        };

        if narrow {
            let mut constraints = vec![
                Constraint::Length(6), // Generic
            ];
            if has_process_timing {
                constraints.push(Constraint::Length(6));
            }
            constraints.push(Constraint::Min(0)); // Geometry/Empty

            let client_layout = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints(constraints)
                .split(client_area);

            draw_client_generic_text(f, app, client_layout[0], "Overview", self.client_idx);

            let mut next_idx = 1;
            if has_process_timing {
                draw_process_timing_text(
                    f,
                    app,
                    client_layout[next_idx],
                    "General",
                    false,
                    self.client_idx,
                    &self.clients,
                );
                next_idx += 1;
            }

            if has_geometry {
                if let Some(chunk) = client_layout.get(next_idx) {
                    draw_item_geometry_text(f, app, *chunk, false, self.client_idx, &self.clients);
                }
            }
        } else {
            let left_layout = split_client(client_area);
            let right_layout_area = left_layout[1];

            // Left Column: Generic only
            // Limit height to 6 to match Right Column (General) and avoid big blanks
            let left_constraints = vec![Constraint::Length(6), Constraint::Min(0)];
            let left_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints(left_constraints)
                .split(left_layout[0]);

            draw_client_generic_text(f, app, left_chunks[0], "Overview", self.client_idx);

            // Right Column: Process Timing + Item Geometry (optional)
            // If !has_process_timing, just Geometry or empty

            let mut right_constraints = vec![];
            if has_process_timing {
                right_constraints.push(Constraint::Length(6));
            }
            right_constraints.push(Constraint::Min(0));

            let right_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints(right_constraints)
                .split(right_layout_area);

            let mut next_idx = 0;
            if has_process_timing {
                draw_process_timing_text(
                    f,
                    app,
                    right_chunks[next_idx],
                    "General",
                    false,
                    self.client_idx,
                    &self.clients,
                );
                next_idx += 1;
            }

            if has_geometry {
                if let Some(chunk) = right_chunks.get(next_idx) {
                    draw_item_geometry_text(f, app, *chunk, false, self.client_idx, &self.clients);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    #[cfg(feature = "introspection")]
    use crate::monitors::tui::PerfTuiContext;
    use crate::monitors::tui::{ClientTuiContext, ItemGeometry, String, TuiContext};

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
        assert!(content.contains("Overview"));
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

    #[test]
    fn test_item_geometry_visibility() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), false);
        // Start time 0
        let mut ctx_struct = TuiContext::new(Duration::from_secs(0));
        // Ensure total_item_geometry is None initially
        ctx_struct.total_item_geometry = None;
        let context = Arc::new(RwLock::new(ctx_struct));

        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Case 1: No Item Geometry (default is None)
        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);
        assert!(
            !content.contains("item geometry"),
            "Item Geometry should be hidden when None"
        );

        // Case 2: With Item Geometry
        {
            let mut ctx = context.write().unwrap();
            ctx.total_item_geometry = Some(ItemGeometry::new());
        }

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);
        assert!(
            content.contains("item geometry"),
            "Item Geometry should be visible when Some"
        );
    }

    #[test]
    fn test_narrow_layout() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), true); // Show logs enabled
        let mut ctx_struct = TuiContext::new(Duration::from_secs(0));

        // Add a client with process timing data
        let mut client = ClientTuiContext::default();
        client.process_timing.exec_speed = "100/sec".into();
        ctx_struct.clients.insert(0, client);

        ctx_struct
            .client_logs
            .push_back(String::from("Log message 1"));
        let context = Arc::new(RwLock::new(ctx_struct));

        // Width 60 (< 75)
        let backend = TestBackend::new(60, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // 1. Charts should be hidden (no "charts" title, but "view" tabs might be present)
        // With new logic, we show "view (...)" tabs.
        // We assert that "charts" block title is NOT present.
        assert!(
            !content.contains("charts (`g` for next)"),
            "Charts block should be hidden on narrow screen"
        );

        // 2. Logs SHOULD be HIDDEN initially due to auto-hide on narrow transition
        assert!(
            !content.contains("clients logs"),
            "Logs should be auto-hidden on narrow screen transition"
        );

        // 3. Toggle logs ON
        tui_ui.on_key('t', &context);

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // 4. Logs SHOULD be VISIBLE now
        assert!(
            content.contains("clients logs"),
            "Logs should be visible on narrow screen after toggle"
        );
        assert!(
            content.contains("Log message 1"),
            "Log content should be visible on narrow screen"
        );

        // 3. Client View should be HIDDEN
        assert!(
            !content.contains("client #0"),
            "Client View should be hidden/replaced by logs"
        );

        // 4. Stats should be visible (Generic tab)
        assert!(
            content.contains("Overview"),
            "Overview tab/stats should be visible"
        );

        // Test toggling logs off
        tui_ui.on_key('t', &context); // Toggle off

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // Now Logs hidden, Client View visible
        assert!(
            !content.contains("clients logs"),
            "Logs should be hidden when toggled off"
        );
        assert!(
            content.contains("client #0"),
            "Client View should be visible when logs hidden"
        );
    }

    #[test]
    fn test_logs_scrolling() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), true);
        let mut ctx_struct = TuiContext::new(Duration::from_secs(0));

        // Add 20 logs
        for i in 0..20 {
            ctx_struct.client_logs.push_back(format!("Log message {i}"));
        }
        let context = Arc::new(RwLock::new(ctx_struct));

        // Create terminal with height that fits limited logs
        // Height 24: Top=17? Mid=6? Logs=Remaining?
        // split_main: if 24 available -> available=19.
        // 19-6=13 for Top?
        // Wait, logs_min=5. available = 24-5 = 19.
        // split_main logic for 19: (13, 6).
        // Actual logs height = 24 - 13 - 6 = 5.
        // 5 lines total for logs. 2 borders. 3 content lines.
        // So we expect 3 logs.

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                tui_ui.draw(f, &context);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        // We expect the LATEST logs (19, 18, 17)
        assert!(
            content.contains("Log message 19"),
            "Log 19 should be visible"
        );
        assert!(
            content.contains("Log message 18"),
            "Log 18 should be visible"
        );

        // We expect OLDEST logs to be hidden
        assert!(!content.contains("Log message 0"), "Log 0 should be hidden");
        assert!(!content.contains("Log message 5"), "Log 5 should be hidden");
    }

    #[test]
    fn test_client_navigation() {
        // Setup mock data
        let mut tui_ui = TuiUi::new("Test Fuzzer".into(), true);
        let mut ctx_struct = TuiContext::new(Duration::from_secs(0));

        // Add 2 clients with distinct data
        let mut c0 = ClientTuiContext::default();
        c0.client_stats.update_corpus_size(123);
        ctx_struct.clients.insert(0, c0);

        let mut c1 = ClientTuiContext::default();
        c1.client_stats.update_corpus_size(456);
        ctx_struct.clients.insert(1, c1);

        ctx_struct.clients_num = 2; // Sync clients_num to prevent draw reset

        let context = Arc::new(RwLock::new(ctx_struct));

        // Initial state
        tui_ui.clients = vec![0, 1]; // Manually sync clients list for test (usually done in draw)
        assert_eq!(tui_ui.client_idx, 0);

        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Check Initial Client (0) Data
        terminal.draw(|f| tui_ui.draw(f, &context)).unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);
        assert!(
            content.contains("123"),
            "Client 0 data (123) should be visible initially. Content: {}",
            content
        );
        assert!(
            !content.contains("456"),
            "Client 1 data (456) should NOT be visible initially. Content: {}",
            content
        );
        assert!(
            content.contains("client #0"),
            "Client #0 title should be visible"
        );

        // Test Navigation Logic
        tui_ui.on_right();
        assert_eq!(
            tui_ui.client_idx, 1,
            "Right arrow should move to next client"
        );

        // Check Client 1 Data
        terminal.draw(|f| tui_ui.draw(f, &context)).unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);
        assert!(
            content.contains("456"),
            "Client 1 data (456) should be visible after navigation. Content: {}",
            content
        );
        assert!(
            !content.contains("123"),
            "Client 0 data (123) should NOT be visible after navigation. Content: {}",
            content
        );
        assert!(
            content.contains("client #1"),
            "Client #1 title should be visible"
        );

        tui_ui.on_right();
        assert_eq!(
            tui_ui.client_idx, 0,
            "Right arrow at end should wrap to first"
        );

        tui_ui.on_left();
        assert_eq!(
            tui_ui.client_idx, 1,
            "Left arrow at start should wrap to last"
        );

        tui_ui.on_left();
        assert_eq!(
            tui_ui.client_idx, 0,
            "Left arrow should move to previous client"
        );

        // Test Display (Arrows Hint)
        terminal.draw(|f| tui_ui.draw(f, &context)).unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        assert!(
            content.contains("arrows to switch"),
            "Arrows hint should be visible when multiple clients exist. Content: {}",
            content
        );

        // Test Display (No Hint for Single Client)
        {
            let mut ctx = context.write().unwrap();
            ctx.clients.remove(&1);
        }
        // Force sync clients in UI
        tui_ui.clients = vec![0];

        terminal.draw(|f| tui_ui.draw(f, &context)).unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        assert!(
            !content.contains("arrows to switch"),
            "Arrows hint should be hidden when only one client exists. Content: {}",
            content
        );

        // Test Log Hint when logs hidden
        tui_ui.show_logs = false;
        terminal.draw(|f| tui_ui.draw(f, &context)).unwrap();
        let buffer = terminal.backend().buffer();
        let content = format!("{:?}", buffer);

        assert!(
            content.contains("`q` to quit"),
            "Quit hint should be visible when logs are hidden"
        );
        assert!(
            content.contains("`t` for logs"),
            "Logs hint should be visible when logs are hidden"
        );
    }
}
