use alloc::{string::ToString, vec::Vec};
use std::{
    cmp::{max, min},
    sync::{Arc, RwLock},
};

use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, List, ListItem, Paragraph, Row, Table, Tabs,
    },
    Frame,
};

use super::{
    current_time, format_duration_hms, Duration, ItemGeometry, ProcessTiming, String, TimedStats,
    TuiContext,
};

#[derive(Default, Debug)]
pub struct TuiUI {
    title: String,
    version: String,
    enhanced_graphics: bool,
    show_logs: bool,
    clients_idx: usize,
    clients: usize,
    charts_tab_idx: usize,
    graph_data: Vec<(f64, f64)>,

    pub should_quit: bool,
}

impl TuiUI {
    #[must_use]
    pub fn new(title: String, enhanced_graphics: bool) -> Self {
        Self::with_version(title, String::from("default"), enhanced_graphics)
    }

    // create the TuiUI with a given `version`.
    #[must_use]
    pub fn with_version(title: String, version: String, enhanced_graphics: bool) -> Self {
        Self {
            title,
            version,
            enhanced_graphics,
            show_logs: true,
            clients_idx: 1,
            ..TuiUI::default()
        }
    }
    pub fn on_key(&mut self, c: char) {
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
            _ => {}
        }
    }

    //pub fn on_up(&mut self) {}

    //pub fn on_down(&mut self) {}

    pub fn on_right(&mut self) {
        if self.clients != 0 {
            // clients_idx never 0
            if self.clients - 1 != 0 {
                // except for when it is ;)
                self.clients_idx = 1 + self.clients_idx % (self.clients - 1);
            }
        }
    }

    pub fn on_left(&mut self) {
        if self.clients != 0 {
            // clients_idx never 0
            if self.clients_idx == 1 {
                self.clients_idx = self.clients - 1;
            } else if self.clients - 1 != 0 {
                // don't wanna be dividing by 0
                self.clients_idx = 1 + (self.clients_idx - 2) % (self.clients - 1);
            }
        }
    }

    pub fn draw<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>)
    where
        B: Backend,
    {
        self.clients = app.read().unwrap().clients_num;

        let body = Layout::default()
            .constraints(if self.show_logs {
                if cfg!(feature = "introspection") {
                    [
                        Constraint::Percentage(41),
                        Constraint::Percentage(44),
                        Constraint::Percentage(15),
                    ]
                    .as_ref()
                } else {
                    [
                        Constraint::Percentage(41),
                        Constraint::Percentage(27),
                        Constraint::Percentage(32),
                    ]
                    .as_ref()
                }
            } else {
                [Constraint::Percentage(50), Constraint::Percentage(50)].as_ref()
            })
            .split(f.size());
        let top_body = body[0];
        let mid_body = body[1];

        self.draw_overall_ui(f, app, top_body);
        self.draw_client_ui(f, app, mid_body);

        if self.show_logs {
            let bottom_body = body[2];
            self.draw_logs(f, app, bottom_body);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn draw_overall_ui<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let top_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(16), Constraint::Min(0)].as_ref())
            .split(area);
        let bottom_layout = top_layout[1];

        let left_top_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
            .split(top_layout[0]);

        let right_top_layout = left_top_layout[1];

        let title_layout = Layout::default()
            .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
            .split(left_top_layout[0]);

        let mut status_bar: String = self.title.clone();
        status_bar = status_bar + " (" + self.version.as_str() + ")";

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
        f.render_widget(paragraph, title_layout[0]);

        let process_timting_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(0)].as_ref())
            .split(title_layout[1]);
        self.draw_process_timing_text(f, app, process_timting_layout[0], true);

        let path_geometry_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(0)].as_ref())
            .split(process_timting_layout[1]);
        self.draw_item_geometry_text(f, app, path_geometry_layout[0], true);

        let title_chart_layout = Layout::default()
            .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
            .split(right_top_layout);
        let titles = vec![
            Line::from(Span::styled(
                "speed",
                Style::default().fg(Color::LightGreen),
            )),
            Line::from(Span::styled(
                "corpus",
                Style::default().fg(Color::LightGreen),
            )),
            Line::from(Span::styled(
                "objectives (`g` switch)",
                Style::default().fg(Color::LightGreen),
            )),
        ];
        let tabs = Tabs::new(titles)
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
        f.render_widget(tabs, title_chart_layout[0]);

        let chart_layout = title_chart_layout[1];

        match self.charts_tab_idx {
            0 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "speed chart",
                    "exec/sec",
                    f,
                    chart_layout,
                    &ctx.execs_per_sec_timed,
                );
            }
            1 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "corpus size",
                    f,
                    chart_layout,
                    &ctx.corpus_size_timed,
                );
            }
            2 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "objectives",
                    f,
                    chart_layout,
                    &ctx.objective_size_timed,
                );
            }
            _ => {}
        }
        self.draw_overall_generic_text(f, app, bottom_layout);
    }

    fn draw_client_ui<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let client_block = Block::default()
            .title(Span::styled(
                format!("client #{} (l/r arrows to switch)", self.clients_idx),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL);
        let client_area = client_block.inner(area);
        f.render_widget(client_block, area);

        #[cfg(feature = "introspection")]
        {
            let introspection_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(11), Constraint::Min(0)].as_ref())
                .split(client_area)[1];
            self.draw_introspection_text(f, app, introspection_layout);
        }

        let left_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(client_area);
        let right_layout = left_layout[1];

        let left_top_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Length(0)].as_ref())
            .split(left_layout[0]);
        let left_bottom_layout = left_top_layout[1];
        self.draw_process_timing_text(f, app, left_top_layout[0], false);
        self.draw_client_generic_text(f, app, left_bottom_layout);

        let right_top_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Length(0)].as_ref())
            .split(right_layout);
        let right_bottom_layout = right_top_layout[1];
        self.draw_item_geometry_text(f, app, right_top_layout[0], false);
        self.draw_client_results_text(f, app, right_bottom_layout);
    }

    #[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
    fn draw_time_chart<B>(
        &mut self,
        title: &str,
        y_name: &str,
        f: &mut Frame<B>,
        area: Rect,
        stats: &TimedStats,
    ) where
        B: Backend,
    {
        if stats.series.is_empty() {
            return;
        }
        let start = stats.series.front().unwrap().time;
        let end = stats.series.back().unwrap().time;
        let min_lbl_x = format_duration_hms(&start);
        let med_lbl_x = format_duration_hms(&((end - start) / 2));
        let max_lbl_x = format_duration_hms(&end);

        let x_labels = vec![
            Span::styled(min_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(med_lbl_x),
            Span::styled(max_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
        ];

        let max_x = u64::from(area.width);
        let window = end - start;
        let time_unit = if max_x > window.as_secs() {
            0 // millis / 10
        } else if max_x > window.as_secs() * 60 {
            1 // secs
        } else {
            2 // min
        };
        let convert_time = |d: &Duration| -> u64 {
            if time_unit == 0 {
                (d.as_millis() / 10) as u64
            } else if time_unit == 1 {
                d.as_secs()
            } else {
                d.as_secs() * 60
            }
        };
        let window_unit = convert_time(&window);
        if window_unit == 0 {
            return;
        }

        let to_x = |d: &Duration| (convert_time(d) - convert_time(&start)) * max_x / window_unit;

        self.graph_data.clear();

        let mut max_y = u64::MIN;
        let mut min_y = u64::MAX;
        let mut prev = (0, 0);
        for ts in &stats.series {
            let x = to_x(&ts.time);
            if x > prev.0 + 1 && x < max_x {
                for v in (prev.0 + 1)..x {
                    self.graph_data.push((v as f64, prev.1 as f64));
                }
            }
            prev = (x, ts.item);
            self.graph_data.push((x as f64, ts.item as f64));
            max_y = max(ts.item, max_y);
            min_y = min(ts.item, min_y);
        }
        if max_x > prev.0 + 1 {
            for v in (prev.0 + 1)..max_x {
                self.graph_data.push((v as f64, prev.1 as f64));
            }
        }

        //log::trace!("max_x: {}, len: {}", max_x, self.graph_data.len());

        let datasets = vec![Dataset::default()
            //.name("data")
            .marker(if self.enhanced_graphics {
                symbols::Marker::Braille
            } else {
                symbols::Marker::Dot
            })
            .style(
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD),
            )
            .data(&self.graph_data)];
        let chart = Chart::new(datasets)
            .block(
                Block::default()
                    .title(Span::styled(
                        title,
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .x_axis(
                Axis::default()
                    .title("time")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.0, max_x as f64])
                    .labels(x_labels),
            )
            .y_axis(
                Axis::default()
                    .title(y_name)
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_y as f64, max_y as f64])
                    .labels(vec![
                        Span::styled(
                            format!("{min_y}"),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("{}", (max_y - min_y) / 2)),
                        Span::styled(
                            format!("{max_y}"),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ]),
            );
        f.render_widget(chart, area);
    }

    fn draw_item_geometry_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
        is_overall: bool,
    ) where
        B: Backend,
    {
        let item_geometry: ItemGeometry = if is_overall {
            app.read().unwrap().total_item_geometry.clone()
        } else if self.clients < 2 {
            ItemGeometry::new()
        } else {
            app.read()
                .unwrap()
                .clients
                .get(&self.clients_idx)
                .unwrap()
                .item_geometry
                .clone()
        };

        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("pending")),
                Cell::from(Span::raw(format!("{}", item_geometry.pending))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("pend fav")),
                Cell::from(Span::raw(format!("{}", item_geometry.pend_fav))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("own finds")),
                Cell::from(Span::raw(format!("{}", item_geometry.own_finds))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("imported")),
                Cell::from(Span::raw(format!("{}", item_geometry.imported))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("stability")),
                Cell::from(Span::raw(item_geometry.stability)),
            ]),
        ];

        let chunks = Layout::default()
            .constraints(
                [
                    Constraint::Length(2 + items.len() as u16),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(area);

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "item geometry",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, chunks[0]);
    }

    fn draw_process_timing_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
        is_overall: bool,
    ) where
        B: Backend,
    {
        let tup: (Duration, ProcessTiming) = if is_overall {
            let tui_context = app.read().unwrap();
            (
                tui_context.start_time,
                tui_context.total_process_timing.clone(),
            )
        } else if self.clients < 2 {
            (current_time(), ProcessTiming::new())
        } else {
            let client = app
                .read()
                .unwrap()
                .clients
                .get(&self.clients_idx)
                .unwrap()
                .clone();
            (
                client.process_timing.client_start_time,
                client.process_timing,
            )
        };
        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("run time")),
                Cell::from(Span::raw(format_duration_hms(&(current_time() - tup.0)))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("exec speed")),
                Cell::from(Span::raw(tup.1.exec_speed)),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("last new entry")),
                Cell::from(Span::raw(format_duration_hms(&(tup.1.last_new_entry)))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("last solution")),
                Cell::from(Span::raw(format_duration_hms(&(tup.1.last_saved_solution)))),
            ]),
        ];

        let chunks = Layout::default()
            .constraints(
                [
                    Constraint::Length(2 + items.len() as u16),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(area);

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "process timing",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, chunks[0]);
    }

    fn draw_overall_generic_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
    ) where
        B: Backend,
    {
        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("clients")),
                Cell::from(Span::raw(format!("{}", self.clients))),
                Cell::from(Span::raw("total execs")),
                Cell::from(Span::raw(format!("{}", app.read().unwrap().total_execs))),
                Cell::from(Span::raw("map density")),
                Cell::from(Span::raw(app.read().unwrap().total_map_density.to_string())),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("solutions")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read().unwrap().total_solutions
                ))),
                Cell::from(Span::raw("cycle done")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read().unwrap().total_cycles_done
                ))),
                Cell::from(Span::raw("corpus count")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read().unwrap().total_corpus_count
                ))),
            ]),
        ];

        let chunks = Layout::default()
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(area);

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "generic",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[
                Constraint::Percentage(15),
                Constraint::Percentage(16),
                Constraint::Percentage(15),
                Constraint::Percentage(16),
                Constraint::Percentage(15),
                Constraint::Percentage(27),
            ]);
        f.render_widget(table, chunks[0]);
    }

    fn draw_client_results_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
    ) where
        B: Backend,
    {
        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("cycles done")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read()
                        .unwrap()
                        .clients
                        .get(&self.clients_idx)
                        .map_or(0, |x| x.cycles_done)
                ))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("solutions")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read()
                        .unwrap()
                        .clients
                        .get(&self.clients_idx)
                        .map_or(0, |x| x.objectives)
                ))),
            ]),
        ];

        let chunks = Layout::default()
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(area);

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "overall results",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, chunks[0]);
    }

    fn draw_client_generic_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
    ) where
        B: Backend,
    {
        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("corpus count")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read()
                        .unwrap()
                        .clients
                        .get(&self.clients_idx)
                        .map_or(0, |x| x.corpus)
                ))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("total execs")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read()
                        .unwrap()
                        .clients
                        .get(&self.clients_idx)
                        .map_or(0, |x| x.executions)
                ))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("map density")),
                Cell::from(Span::raw(
                    app.read()
                        .unwrap()
                        .clients
                        .get(&self.clients_idx)
                        .map_or("0%".to_string(), |x| x.map_density.to_string()),
                )),
            ]),
        ];

        let chunks = Layout::default()
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(area);

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "generic",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, chunks[0]);
    }

    #[cfg(feature = "introspection")]
    fn draw_introspection_text<B>(
        &mut self,
        f: &mut Frame<B>,
        app: &Arc<RwLock<TuiContext>>,
        area: Rect,
    ) where
        B: Backend,
    {
        let mut items = vec![];
        {
            let ctx = app.read().unwrap();
            if let Some(client) = ctx.introspection.get(&self.clients_idx) {
                items.push(Row::new(vec![
                    Cell::from(Span::raw("scheduler")),
                    Cell::from(Span::raw(format!("{:.2}%", client.scheduler * 100.0))),
                ]));
                items.push(Row::new(vec![
                    Cell::from(Span::raw("manager")),
                    Cell::from(Span::raw(format!("{:.2}%", client.manager * 100.0))),
                ]));
                for i in 0..client.stages.len() {
                    items.push(Row::new(vec![
                        Cell::from(Span::raw(format!("stage {i}"))),
                        Cell::from(Span::raw("")),
                    ]));

                    for (key, val) in &client.stages[i] {
                        items.push(Row::new(vec![
                            Cell::from(Span::raw(key.clone())),
                            Cell::from(Span::raw(format!("{:.2}%", val * 100.0))),
                        ]));
                    }
                }
                for (key, val) in &client.feedbacks {
                    items.push(Row::new(vec![
                        Cell::from(Span::raw(key.clone())),
                        Cell::from(Span::raw(format!("{:.2}%", val * 100.0))),
                    ]));
                }
                items.push(Row::new(vec![
                    Cell::from(Span::raw("not measured")),
                    Cell::from(Span::raw(format!("{:.2}%", client.unmeasured * 100.0))),
                ]));
            };
        }

        let table = Table::new(items)
            .block(
                Block::default()
                    .title(Span::styled(
                        "introspection",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, area);
    }
    #[allow(clippy::unused_self)]
    fn draw_logs<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let app = app.read().unwrap();
        let logs: Vec<ListItem> = app
            .client_logs
            .iter()
            .map(|msg| ListItem::new(Span::raw(msg)))
            .collect();
        let logs = List::new(logs).block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                "clients logs (`t` to show/hide)",
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        f.render_widget(logs, area);
    }
}
