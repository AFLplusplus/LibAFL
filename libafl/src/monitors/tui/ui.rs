use super::{current_time, format_duration_hms, Duration, String, TimedStats, TuiContext};

use alloc::vec::Vec;
use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Span, Spans},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, List, ListItem, Paragraph, Row, Table, Tabs,
    },
    Frame,
};

use std::{
    cmp::{max, min},
    sync::{Arc, RwLock},
};

#[derive(Default)]
pub struct TuiUI {
    title: String,
    enhanced_graphics: bool,
    show_logs: bool,
    clients_idx: usize,
    clients: usize,
    charts_tab_idx: usize,
    graph_data: Vec<(f64, f64)>,

    pub should_quit: bool,
}

impl TuiUI {
    pub fn new(title: String, enhanced_graphics: bool) -> Self {
        Self {
            title,
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
            self.clients_idx = 1 + self.clients_idx % (self.clients - 1);
        }
    }

    pub fn on_left(&mut self) {
        if self.clients != 0 {
            // clients_idx never 0
            if self.clients_idx == 1 {
                self.clients_idx = self.clients - 1;
            } else {
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
                [Constraint::Percentage(50), Constraint::Percentage(50)].as_ref()
            } else {
                [Constraint::Percentage(100)].as_ref()
            })
            .split(f.size());

        let top_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(body[0]);

        let left_layout = Layout::default()
            .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
            .split(top_layout[0]);

        let text = vec![Spans::from(Span::styled(
            &self.title,
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ))];
        let block = Block::default().borders(Borders::ALL);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center); //.wrap(Wrap { trim: true });
        f.render_widget(paragraph, left_layout[0]);

        self.draw_text(f, app, left_layout[1]);

        let right_layout = Layout::default()
            .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
            .split(top_layout[1]);
        let titles = vec![
            Spans::from(Span::styled(
                "speed",
                Style::default().fg(Color::LightGreen),
            )),
            Spans::from(Span::styled(
                "corpus",
                Style::default().fg(Color::LightGreen),
            )),
            Spans::from(Span::styled(
                "objectives",
                Style::default().fg(Color::LightGreen),
            )),
        ];
        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .title(Span::styled(
                        "charts (`g` switch)",
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().fg(Color::LightYellow))
            .select(self.charts_tab_idx);
        f.render_widget(tabs, right_layout[0]);

        match self.charts_tab_idx {
            0 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "speed chart",
                    "exec/sec",
                    f,
                    right_layout[1],
                    &ctx.execs_per_sec_timed,
                );
            }
            1 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "corpus size",
                    f,
                    right_layout[1],
                    &ctx.corpus_size_timed,
                );
            }
            2 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "objectives",
                    f,
                    right_layout[1],
                    &ctx.objective_size_timed,
                );
            }
            _ => {}
        }

        if self.show_logs {
            self.draw_logs(f, app, body[1]);
        }
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

        //println!("max_x: {}, len: {}", max_x, self.graph_data.len());

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
                            format!("{}", min_y),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("{}", (max_y - min_y) / 2)),
                        Span::styled(
                            format!("{}", max_y),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ]),
            );
        f.render_widget(chart, area);
    }

    #[allow(clippy::too_many_lines)]
    fn draw_text<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let items = vec![
            Row::new(vec![
                Cell::from(Span::raw("run time")),
                Cell::from(Span::raw(format_duration_hms(
                    &(current_time() - app.read().unwrap().start_time),
                ))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("clients")),
                Cell::from(Span::raw(format!("{}", self.clients))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("executions")),
                Cell::from(Span::raw(format!("{}", app.read().unwrap().total_execs))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("exec/sec")),
                Cell::from(Span::raw(format!(
                    "{}",
                    app.read()
                        .unwrap()
                        .execs_per_sec_timed
                        .series
                        .back()
                        .map_or(0, |x| x.item)
                ))),
            ]),
        ];

        let chunks = Layout::default()
            .constraints(
                [
                    Constraint::Length(2 + items.len() as u16),
                    Constraint::Min(8),
                ]
                .as_ref(),
            )
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

        let client_block = Block::default()
            .title(Span::styled(
                format!("client #{} (l/r arrows to switch)", self.clients_idx),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL);
        let client_area = client_block.inner(chunks[1]);
        f.render_widget(client_block, chunks[1]);

        let mut client_items = vec![];
        {
            let ctx = app.read().unwrap();
            if let Some(client) = ctx.clients.get(&self.clients_idx) {
                client_items.push(Row::new(vec![
                    Cell::from(Span::raw("executions")),
                    Cell::from(Span::raw(format!("{}", client.executions))),
                ]));
                client_items.push(Row::new(vec![
                    Cell::from(Span::raw("exec/sec")),
                    Cell::from(Span::raw(format!("{}", client.exec_sec))),
                ]));
                client_items.push(Row::new(vec![
                    Cell::from(Span::raw("corpus")),
                    Cell::from(Span::raw(format!("{}", client.corpus))),
                ]));
                client_items.push(Row::new(vec![
                    Cell::from(Span::raw("objectives")),
                    Cell::from(Span::raw(format!("{}", client.objectives))),
                ]));
                for (key, val) in &client.user_stats {
                    client_items.push(Row::new(vec![
                        Cell::from(Span::raw(key.clone())),
                        Cell::from(Span::raw(format!("{}", val.clone()))),
                    ]));
                }
            };
        }

        #[cfg(feature = "introspection")]
        let client_chunks = Layout::default()
            .constraints(
                [
                    Constraint::Length(client_items.len() as u16),
                    Constraint::Min(4),
                ]
                .as_ref(),
            )
            .split(client_area);
        #[cfg(not(feature = "introspection"))]
        let client_chunks = Layout::default()
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(client_area);

        let table = Table::new(client_items)
            .block(Block::default())
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, client_chunks[0]);

        #[cfg(feature = "introspection")]
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
                            Cell::from(Span::raw(format!("stage {}", i))),
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
            f.render_widget(table, client_chunks[1]);
        }
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
