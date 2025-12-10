use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::time::Duration;
use std::sync::RwLock;

use libafl_bolts::{current_time, format_big_number};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

use super::{
    layout::{split_client, split_main, split_overall, split_title, split_top},
    widgets::{
        MultiTimeChartOptions, TimeChartOptions, draw_item_geometry_text, draw_key_value_block,
        draw_logs, draw_multi_time_chart, draw_process_timing_text, draw_time_chart,
        draw_user_stats,
    },
};
use crate::monitors::{
    stats::{
        ProcessTiming, TimedStat,
        user_stats::{PlotConfig, UserStatsValue},
    },
    tui::{ItemGeometry, TuiContext},
};

/// The UI for the TUI monitor
#[derive(Default, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct TuiUi {
    title: String,
    version: String,
    enhanced_graphics: bool,
    show_logs: bool,
    client_idx: usize,
    clients: Vec<usize>,
    charts_tab_idx: usize,
    graph_data: Vec<(f64, f64)>,
    multi_graph_data: Vec<Vec<(f64, f64)>>,
    is_narrow: bool,
    logs_wrap: bool,
    /// Cached tabs for lock-free navigation
    tabs: Vec<String>,

    /// If the UI should quit
    pub should_quit: bool,
    /// If the UI should refresh
    pub(crate) should_refresh: bool,
    user_stats_scroll: usize,
    pub(crate) user_stats_page_size: usize,
}

#[derive(Debug)]
struct GenericStats {
    labels: Vec<(Span<'static>, String)>,
}

#[derive(Debug)]
struct PreparedFrameData {
    // Overall
    generic_stats: GenericStats,
    total_timing: Option<(ProcessTiming, Duration)>,
    total_geometry: Option<ItemGeometry>,

    // Client
    client_idx: usize,
    client_generic_stats: GenericStats,
    client_timing: Option<(ProcessTiming, Duration)>,
    client_geometry: Option<ItemGeometry>,
    client_user_stats: Vec<(Span<'static>, String)>,

    // Logs
    logs: Vec<String>,

    // Charts
    tabs: Vec<String>,
    active_chart: Option<ChartKind>,
}

#[derive(Debug)]
enum ChartKind {
    Single {
        name: String,
        series: Vec<TimedStat>,
        window: Duration,
        run_time: Duration,
    },
    Multi {
        name: String,
        series: Vec<(String, Vec<TimedStat>, Duration, Style)>,
        run_time: Duration,
    },
}

fn next_larger(sorted: &[usize], value: usize) -> Option<usize> {
    sorted.iter().position(|x| *x > value).map(|i| sorted[i])
}

fn next_smaller(sorted: &[usize], value: usize) -> Option<usize> {
    sorted.iter().rposition(|x| *x < value).map(|i| sorted[i])
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
            multi_graph_data: vec![],
            is_narrow: false,
            logs_wrap: false,
            tabs: vec!["Overview".to_string()],
            should_quit: false,
            should_refresh: false,
            user_stats_scroll: 0,
            user_stats_page_size: 10,
        }
    }

    fn get_tabs(ctx: &TuiContext) -> Vec<String> {
        let mut tabs = vec!["Overview".to_string()];
        for g in &ctx.graphs {
            if !ctx.plot_configs.contains_key(g) {
                tabs.push(g.clone());
            }
        }
        if !ctx.plot_configs.is_empty() {
            tabs.push("User Stats".to_string());
        }
        tabs
    }

    /// Prepare all data needed for the frame in a single "Lock" scope
    fn prepare_data(&mut self, app: &Arc<RwLock<TuiContext>>) -> PreparedFrameData {
        let mut ctx = app.read().unwrap();
        // Check if clients list changed
        if ctx.clients_num != self.clients.len() {
            drop(ctx);
            ctx = app.read().unwrap();

            let mut all: Vec<usize> = ctx.clients.keys().copied().collect();
            all.sort_unstable();
            if !all.is_empty() && !all.contains(&self.client_idx) {
                self.client_idx = all[0];
            }
            self.clients = all;
        }

        let run_time = current_time().saturating_sub(ctx.start_time);

        // 1. Overall Stats
        let generic_stats = GenericStats {
            labels: vec![
                (Span::raw("clients"), format!("{}", ctx.clients.len())),
                (Span::raw("total execs"), format_big_number(ctx.total_execs)),
                (
                    Span::raw("solutions"),
                    format_big_number(ctx.total_solutions),
                ),
                (
                    Span::raw("corpus count"),
                    format_big_number(ctx.total_corpus_count),
                ),
            ],
        };

        let total_timing_data = if ctx.total_process_timing.exec_speed != "0/sec" {
            Some(&ctx.total_process_timing)
        } else if let Some(client) = ctx.clients.get(&0) {
            if client.process_timing.exec_speed != "0/sec" {
                Some(&client.process_timing)
            } else {
                None
            }
        } else {
            None
        };

        let total_timing = total_timing_data.map(|t| (t.clone(), run_time));

        let total_geometry = ctx.total_item_geometry.clone();

        // 2. Client Stats
        let (client_generic_stats, client_timing, client_geometry, client_user_stats) =
            if let Some(client) = ctx.clients.get(&self.client_idx) {
                let timing = if client.process_timing.exec_speed != "0/sec" {
                    Some((
                        client.process_timing.clone(),
                        current_time().saturating_sub(client.process_timing.client_start_time),
                    ))
                } else {
                    None
                };

                let generic = GenericStats {
                    labels: vec![
                        (
                            Span::raw("corpus count"),
                            format_big_number(client.client_stats.corpus_size()),
                        ),
                        (
                            Span::raw("total execs"),
                            format_big_number(client.client_stats.executions()),
                        ),
                        (
                            Span::raw("cycles done"),
                            client
                                .cycles_done()
                                .map_or(String::new(), |c| c.to_string()),
                        ),
                        (
                            Span::raw("solutions"),
                            format_big_number(client.client_stats.objective_size()),
                        ),
                    ],
                };

                // Format user stats
                let mut keys: Vec<_> = client.client_stats.user_stats().keys().collect();
                keys.sort();
                let user_stats_vec = keys
                    .into_iter()
                    .map(|k| {
                        let val = client.client_stats.user_stats().get(k).unwrap();
                        let val_str = match val.value() {
                            UserStatsValue::Number(n) => format_big_number(*n),
                            UserStatsValue::Float(f) => format!("{f:.2}"),
                            UserStatsValue::String(s) => s.to_string(),
                            UserStatsValue::Ratio(a, b) => {
                                if *b == 0 {
                                    "0/0".into()
                                } else {
                                    #[allow(clippy::cast_precision_loss)]
                                    let percentage = (*a as f64 / *b as f64) * 100.0;
                                    format!("{a}/{b} ({percentage:.2}%)")
                                }
                            }
                            UserStatsValue::Percent(p) => format!("{:.2}%", p * 100.0),
                        };

                        let style = match val.plot_config() {
                            PlotConfig::None => Style::default(),
                            PlotConfig::Color(r, g, b) => Style::default().fg(Color::Rgb(r, g, b)),
                            PlotConfig::SimpleColor(c) => Style::default().fg(Color::Indexed(c)),
                        };

                        (Span::styled(k.to_string(), style), val_str)
                    })
                    .collect();

                (
                    generic,
                    timing,
                    client.item_geometry.clone(),
                    user_stats_vec,
                )
            } else {
                (GenericStats { labels: vec![] }, None, None, vec![])
            };

        // 3. Logs
        let logs: Vec<String> = ctx.client_logs.iter().cloned().collect();

        // 4. Charts
        let tabs = Self::get_tabs(&ctx);
        if self.charts_tab_idx >= tabs.len() {
            self.charts_tab_idx = 0;
        }

        let mut active_chart = None;
        if tabs.len() > 1 {
            // If tab_idx is 0 (Overview), we default to the first chart (index 1) for the right pane in wide mode.
            // In narrow mode, this might not be used, but it's safe to compute.
            let chart_idx = if self.charts_tab_idx == 0 {
                1
            } else {
                self.charts_tab_idx
            };

            if chart_idx < tabs.len() {
                let key = &tabs[chart_idx];
                let run_time = current_time().saturating_sub(ctx.start_time);

                active_chart = match key.as_str() {
                    "Overview" => None, // Should not happen if we start at 1
                    "User Stats" => {
                        let mut series = vec![];
                        for (key, config) in &ctx.plot_configs {
                            if let Some(stats) = ctx.custom_timed.get(key.as_str()) {
                                let style = match config {
                                    PlotConfig::Color(r, g, b) => {
                                        Style::default().fg(Color::Rgb(*r, *g, *b))
                                    }
                                    PlotConfig::SimpleColor(c) => {
                                        Style::default().fg(Color::Indexed(*c))
                                    }
                                    PlotConfig::None => Style::default(),
                                };
                                series.push((
                                    key.clone(),
                                    stats.series.clone().into(),
                                    stats.window,
                                    style,
                                ));
                            }
                        }
                        series.sort_by(|a, b| a.0.cmp(&b.0));
                        Some(ChartKind::Multi {
                            name: "User Stats".to_string(),
                            series,
                            run_time,
                        })
                    }
                    "corpus" => Some(ChartKind::Single {
                        name: "corpus".to_string(),
                        series: ctx.corpus_size_timed.series.clone().into(),
                        window: ctx.corpus_size_timed.window,
                        run_time,
                    }),
                    "objectives" => Some(ChartKind::Single {
                        name: "objectives".to_string(),
                        series: ctx.objective_size_timed.series.clone().into(),
                        window: ctx.objective_size_timed.window,
                        run_time,
                    }),
                    "exec/sec" => Some(ChartKind::Single {
                        name: "exec/sec".to_string(),
                        series: ctx.execs_per_sec_timed.series.clone().into(),
                        window: ctx.execs_per_sec_timed.window,
                        run_time,
                    }),
                    custom => ctx.custom_timed.get(custom).map(|stats| ChartKind::Single {
                        name: custom.to_string(),
                        series: stats.series.clone().into(),
                        window: stats.window,
                        run_time,
                    }),
                };
            }
        } else {
            active_chart = None;
        }

        PreparedFrameData {
            generic_stats,
            total_timing,
            total_geometry,
            client_idx: self.client_idx,
            client_generic_stats,
            client_timing,
            client_geometry,
            client_user_stats,
            logs,
            tabs,
            active_chart,
        }
    }

    /// Handle a key event
    pub fn on_key(&mut self, c: char, app: &Arc<RwLock<TuiContext>>) {
        match c {
            'q' => self.should_quit = true,
            'r' => self.should_refresh = true,
            'g' => {
                if !self.tabs.is_empty() {
                    self.charts_tab_idx = (self.charts_tab_idx + 1) % self.tabs.len();
                    // In wide mode, index 0 (Overview) and index 1 (First Chart) show the same thing on the right pane.
                    // So we skip 0 to prevent "double press" feeling.
                    if !self.is_narrow && self.charts_tab_idx == 0 && self.tabs.len() > 1 {
                        self.charts_tab_idx = 1;
                    }
                }
            }
            'G' => {
                if !self.tabs.is_empty() {
                    self.charts_tab_idx =
                        (self.charts_tab_idx + self.tabs.len() - 1) % self.tabs.len();
                    // In wide mode, skip 0 when going backwards too
                    if !self.is_narrow && self.charts_tab_idx == 0 && self.tabs.len() > 1 {
                        self.charts_tab_idx = self.tabs.len() - 1;
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
                ctx.objective_size_timed.update_window(w);
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
                ctx.objective_size_timed.update_window(w);
                ctx.execs_per_sec_timed.update_window(w);
                for timer in ctx.custom_timed.values_mut() {
                    let w = timer.window / 2;
                    timer.update_window(w);
                }
            }
            'u' => {
                let ctx = app.read().unwrap();
                if let Some(client) = ctx.clients.get(&self.client_idx) {
                    let total = client.client_stats.user_stats().len();
                    if total > 0 {
                        self.user_stats_scroll += self.user_stats_page_size;
                        if self.user_stats_scroll >= total {
                            self.user_stats_scroll = 0;
                        }
                    }
                }
            }
            'U' => {
                let ctx = app.read().unwrap();
                if let Some(client) = ctx.clients.get(&self.client_idx) {
                    let total = client.client_stats.user_stats().len();
                    if total > 0 {
                        if self.user_stats_scroll == 0 {
                            let remainder = total % self.user_stats_page_size;
                            if remainder == 0 {
                                self.user_stats_scroll =
                                    total.saturating_sub(self.user_stats_page_size);
                            } else {
                                self.user_stats_scroll = total - remainder;
                            }
                        } else {
                            self.user_stats_scroll = self
                                .user_stats_scroll
                                .saturating_sub(self.user_stats_page_size);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    const NARROW_WIDTH_THRESHOLD: u16 = 75;

    /// Move to the next client
    pub fn on_right(&mut self) {
        if let Some(idx) = next_larger(&self.clients, self.client_idx) {
            self.client_idx = idx; // next_larger returns explicit client ID in revised version
        } else if !self.clients.is_empty() {
            self.client_idx = self.clients[0];
        }
    }

    /// Move to the previous client
    pub fn on_left(&mut self) {
        if let Some(idx) = next_smaller(&self.clients, self.client_idx) {
            self.client_idx = idx; // next_smaller returns explicit client ID
        } else if !self.clients.is_empty() {
            self.client_idx = *self.clients.last().unwrap();
        }
    }

    /// Draw the current TUI context
    pub fn draw(&mut self, f: &mut Frame, app: &Arc<RwLock<TuiContext>>) {
        let prepared = self.prepare_data(app);
        self.tabs.clone_from(&prepared.tabs);

        #[cfg(feature = "introspection")]
        let introspection = true;
        #[cfg(not(feature = "introspection"))]
        let introspection = false;

        let has_charts = prepared.tabs.len() > 1;

        let area = f.area();
        let new_is_narrow = area.width < Self::NARROW_WIDTH_THRESHOLD;
        if new_is_narrow && !self.is_narrow {
            self.show_logs = false;
            self.charts_tab_idx = 0;
        } else if !new_is_narrow && self.charts_tab_idx == 0 && self.tabs.len() > 1 {
            self.charts_tab_idx = 1;
        }
        self.is_narrow = new_is_narrow;

        let is_short = area.height < 28;
        let replace_client_with_logs = (self.is_narrow || is_short) && self.show_logs;

        if replace_client_with_logs {
            let body = split_main(area, true, introspection, has_charts);
            let top_body = body[0];
            let logs_area = Rect::new(
                area.x,
                top_body.bottom(),
                area.width,
                area.height.saturating_sub(top_body.height),
            );

            self.draw_overall_ui(f, top_body, has_charts, &prepared);
            draw_logs(f, logs_area, &prepared.logs, self.logs_wrap);
        } else {
            let body = split_main(area, self.show_logs, introspection, has_charts);
            let top_body = body[0];
            let mid_body = body[1];

            self.draw_overall_ui(f, top_body, has_charts, &prepared);
            self.draw_client_ui(f, mid_body, self.show_logs, &prepared);

            if self.show_logs && body.len() > 2 {
                draw_logs(f, body[2], &prepared.logs, self.logs_wrap);
            }
        }
    }

    fn calculate_tab_window(&self, titles: &[String], max_width: usize) -> (usize, usize, usize) {
        Self::calculate_tab_window_for_index(titles, max_width, self.charts_tab_idx)
    }

    fn calculate_tab_window_for_index(
        titles: &[String],
        max_width: usize,
        selected_idx: usize,
    ) -> (usize, usize, usize) {
        let tab_count = titles.len();
        if tab_count == 0 {
            return (0, 0, 0);
        }
        let selected_idx = selected_idx.min(tab_count - 1);
        let get_width = |i: usize| -> usize {
            if i >= titles.len() {
                0
            } else {
                titles[i].chars().count() + 3
            }
        };

        let mut start = selected_idx;
        let mut end = selected_idx + 1;
        let mut current_width = get_width(selected_idx);

        loop {
            let mut changed = false;
            if start > 0 {
                let w = get_width(start - 1);
                if current_width + w <= max_width {
                    start -= 1;
                    current_width += w;
                    changed = true;
                }
            }
            if end < tab_count {
                let w = get_width(end);
                if current_width + w <= max_width {
                    end += 1;
                    current_width += w;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        (start, end, selected_idx.saturating_sub(start))
    }

    fn draw_overall_ui(
        &mut self,
        f: &mut Frame,
        area: Rect,
        has_charts: bool,
        data: &PreparedFrameData,
    ) {
        let overall_layout = split_overall(area);
        let (tab_area, content_area) = split_title(overall_layout);

        if self.is_narrow {
            let available_width = area.width.saturating_sub(4) as usize;
            let (start, end, selected) = self.calculate_tab_window(&data.tabs, available_width);
            let visible_titles: Vec<Span> = data.tabs[start..end]
                .iter()
                .map(|s| Span::from(s.clone()))
                .collect();

            let tabs_widget = Tabs::new(visible_titles)
                .block(
                    Block::default()
                        .title(Span::styled(
                            &self.title,
                            Style::default()
                                .fg(Color::LightMagenta)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .title_top(
                            Line::from(Span::styled(
                                " G/g ",
                                Style::default()
                                    .fg(Color::LightCyan)
                                    .add_modifier(Modifier::BOLD),
                            ))
                            .alignment(Alignment::Right),
                        )
                        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT),
                )
                .highlight_style(Style::default().fg(Color::LightYellow))
                .select(selected);
            f.render_widget(tabs_widget, tab_area);

            if self.charts_tab_idx == 0 {
                Self::draw_stats_column(f, content_area, data, true);
            } else {
                self.draw_chart(f, content_area, data);
            }
        } else {
            let (left_col, right_col) = if has_charts {
                split_top(overall_layout)
            } else {
                (overall_layout, Rect::default())
            };

            let has_charts = data.tabs.len() > 1;
            // In wide mode (implied here), we always want to show a chart if available, even if selected index is 0 (Overview)
            // If charts_tab_idx is 0, we default to the first chart (index 1 in tabs list)
            // We override active_chart calculation in prepare_data or handle it here?
            // Actually, prepare_data should handle it. But we need to check if prepare_data did it.

            // ... (previous code)

            // Correction for prepare_data (apply logic changes via prepare_data change, here we just use what we have)
            // But we need to fix the visual "selected" index.

            let (left_title, left_stats) = split_title(left_col);
            let status_bar = format!("{} ({})", self.title, self.version);
            let p = Paragraph::new(Line::from(Span::styled(
                status_bar,
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            )))
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center);
            f.render_widget(p, left_title);

            Self::draw_stats_column(f, left_stats, data, false);

            if !has_charts || data.tabs.len() <= 1 {
                return;
            }

            let chart_titles: Vec<String> = data.tabs[1..].to_vec();
            let available_width = right_col.width.saturating_sub(4) as usize;
            // calculated window needs correct selected index relative to chart_titles
            // charts_tab_idx 0 (Overview) -> Select 0 (First Chart)
            // charts_tab_idx 1 (First Chart) -> Select 0 (First Chart)
            // charts_tab_idx 2 (Second Chart) -> Select 1 (Second Chart)
            let visual_selected_idx = self.charts_tab_idx.saturating_sub(1);

            // We need a helper that takes explicit selected index, or modify calculate_tab_window to take it?
            // Existing calculate_tab_window uses self.charts_tab_idx. We should probably modify it to take a param.
            // Or temporarily fake self.charts_tab_idx? No, that requires mut self.

            // Let's modify calculate_tab_window to take the selected index.
            let (start, end, selected) = Self::calculate_tab_window_for_index(
                &chart_titles,
                available_width,
                visual_selected_idx,
            );

            let visible_titles: Vec<Span> = chart_titles[start..end]
                .iter()
                .map(|s| Span::from(s.clone()))
                .collect();

            let tabs_widget = Tabs::new(visible_titles)
                .block(
                    Block::default()
                        .title(Span::styled(
                            "charts",
                            Style::default()
                                .fg(Color::LightCyan)
                                .add_modifier(Modifier::BOLD),
                        ))
                        .title_top(
                            Line::from(Span::styled(
                                format!(
                                    " {}/{} (switch g/G) ",
                                    self.charts_tab_idx.max(1),
                                    data.tabs.len().saturating_sub(1)
                                ),
                                Style::default()
                                    .fg(Color::LightCyan)
                                    .add_modifier(Modifier::BOLD),
                            ))
                            .alignment(Alignment::Right),
                        )
                        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT),
                )
                .highlight_style(Style::default().fg(Color::LightYellow))
                .select(selected);

            let (right_title, right_chart) = split_title(right_col);
            f.render_widget(tabs_widget, right_title);

            self.draw_chart(f, right_chart, data);
        }
    }

    fn draw_stats_column(f: &mut Frame, area: Rect, data: &PreparedFrameData, is_narrow: bool) {
        let has_timing = data.total_timing.is_some();
        let mut constraints = vec![Constraint::Length(4)];
        if has_timing {
            constraints.push(Constraint::Length(6));
        }
        constraints.push(Constraint::Min(0));

        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints(constraints)
            .split(area);

        let title = if is_narrow { "" } else { "Overview" };
        draw_key_value_block(
            f,
            chunks[0],
            title,
            data.generic_stats.labels.clone(),
            &[
                Constraint::Length(10),
                Constraint::Min(5),
                Constraint::Length(14),
                Constraint::Min(5),
            ],
        );

        let mut next_idx = 1;
        if let Some((timing, run_time)) = &data.total_timing {
            draw_process_timing_text(f, chunks[next_idx], "General", timing, *run_time);
            next_idx += 1;
        }

        if let (Some(geometry), Some(chunk)) = (&data.total_geometry, chunks.get(next_idx)) {
            draw_item_geometry_text(f, *chunk, geometry);
        }
    }

    fn draw_chart(&mut self, f: &mut Frame, area: Rect, data: &PreparedFrameData) {
        if let Some(chart) = &data.active_chart {
            match chart {
                ChartKind::Single {
                    name,
                    series,
                    window,
                    run_time,
                } => {
                    draw_time_chart(
                        f,
                        area,
                        TimeChartOptions {
                            title: "",
                            y_name: name,
                            stats: series,
                            window: *window,
                            graph_data: &mut self.graph_data,
                            enhanced_graphics: self.enhanced_graphics,
                            current_time: *run_time,
                            preset_y_range: None,
                        },
                    );
                }
                ChartKind::Multi {
                    name,
                    series,
                    run_time,
                } => {
                    let series_refs: Vec<(&str, &[TimedStat], Duration, Style)> = series
                        .iter()
                        .map(|(n, s, w, st)| (n.as_str(), s.as_slice(), *w, *st))
                        .collect();
                    if self.multi_graph_data.len() < series.len() {
                        self.multi_graph_data.resize(series.len(), vec![]);
                    }
                    draw_multi_time_chart(
                        f,
                        area,
                        MultiTimeChartOptions {
                            title: name,
                            y_name: "value",
                            series: series_refs,
                            graph_data: &mut self.multi_graph_data,
                            enhanced_graphics: self.enhanced_graphics,
                            current_time: *run_time,
                            preset_y_range: None,
                        },
                    );
                }
            }
        }
    }

    fn draw_client_ui(
        &mut self,
        f: &mut Frame,
        area: Rect,
        show_logs: bool,
        data: &PreparedFrameData,
    ) {
        let title = format!(
            "client #{}{}",
            data.client_idx,
            if self.clients.len() > 1 {
                " (←/→ arrows to switch)"
            } else {
                ""
            }
        );
        let mut block = Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL);

        if !show_logs {
            block = block.title(
                Line::from(Span::styled(
                    "`t` for logs, `q` to quit",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Right),
            );
        }

        let client_area = block.inner(area);
        f.render_widget(block, area);

        // Split client area
        let (left, right) = split_client(client_area);

        // Left: Generic + User Stats
        // Limit height for generic to matching General (6)
        let left_chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(0)])
            .split(left);

        draw_key_value_block(
            f,
            left_chunks[0],
            "Overview",
            data.client_generic_stats.labels.clone(),
            &[Constraint::Length(20), Constraint::Min(5)],
        );

        self.user_stats_page_size = draw_user_stats(
            f,
            left_chunks[1],
            self.client_idx,
            &data.client_user_stats,
            self.user_stats_scroll,
        );

        // Right: Timing + Geometry
        let mut right_constraints = vec![];
        if data.client_timing.is_some() {
            right_constraints.push(Constraint::Length(6));
        }
        right_constraints.push(Constraint::Min(0));

        let right_chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints(right_constraints)
            .split(right);

        let mut next_idx = 0;
        if let Some((timing, run_time)) = &data.client_timing {
            draw_process_timing_text(f, right_chunks[next_idx], "General", timing, *run_time);
            next_idx += 1;
        }

        if let (Some(geometry), Some(chunk)) = (&data.client_geometry, right_chunks.get(next_idx)) {
            draw_item_geometry_text(f, *chunk, geometry);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::monitors::tui::TuiContext;

    #[test]
    fn test_ui_render_lock_pattern() {
        let mut tui_ui = TuiUi::new("Test".into(), false);
        // Start time 0
        let ctx = Arc::new(RwLock::new(TuiContext::new(Duration::from_secs(0))));

        // Just verify it doesn't deadlock or panic
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Render once
        terminal.draw(|f| tui_ui.draw(f, &ctx)).unwrap();
    }

    #[test]
    fn test_logs_visibility() {
        let mut tui_ui = TuiUi::new("Test".into(), true); // show logs
        let mut ctx_struct = TuiContext::new(Duration::from_secs(0));
        ctx_struct.client_logs.push_back("Test log".into());
        let ctx = Arc::new(RwLock::new(ctx_struct));

        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| tui_ui.draw(f, &ctx)).unwrap();

        let buffer = terminal.backend().buffer();
        let content = format!("{buffer:?}");
        assert!(content.contains("Test log"), "Logs should be visible");
    }
}
