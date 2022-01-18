use super::*;

use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Span, Spans},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, List, ListItem, ListState, Paragraph, Row,
        Table, Tabs,
    },
    Frame,
};

use std::sync::{Arc, RwLock};

/*
pub fn next<T>(state: &mut ListState, items: &[T]) {
    let i = match state.selected() {
        Some(i) => {
            if i >= items.len() - 1 {
                0
            } else {
                i + 1
            }
        }
        None => 0,
    };
    state.select(Some(i));
}

pub fn previous<T>(state: &mut ListState, items: &[T]) {
    let i = match state.selected() {
        Some(i) => {
            if i == 0 {
                items.len() - 1
            } else {
                i - 1
            }
        }
        None => 0,
    };
    state.select(Some(i));
}
*/

#[derive(Default)]
pub struct TuiUI {
    title: String,
    enhanced_graphics: bool,
    show_logs: bool,
    clients_idx: usize,
    clients: usize,
    charts_tab_idx: usize,

    pub should_quit: bool,
    pub client_logs: ListState,
}

impl TuiUI {
    pub fn new(title: String, enhanced_graphics: bool) -> Self {
        Self {
            title,
            enhanced_graphics,
            show_logs: true,
            clients_idx: 1,
            ..Default::default()
        }
    }

    pub fn on_key(&mut self, c: char) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            'n' => {
                // never 0
                self.clients_idx = 1 + self.clients_idx % (self.clients - 1);
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
        self.charts_tab_idx = (self.charts_tab_idx + 1) % 3;
    }

    pub fn on_left(&mut self) {
        if self.charts_tab_idx > 0 {
            self.charts_tab_idx -= 1;
        } else {
            self.charts_tab_idx = 2;
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
                        "charts (l/r arrows to switch)",
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
        let (min_x, max_x, min_y, max_y, min_lbl_x, med_lbl_x, max_lbl_x) =
            if stats.series.is_empty() {
                (0, 0, 0, 0, "n/a".into(), "n/a".into(), "n/a".into())
            } else {
                let end = stats.series[stats.series.len() - 1].time;
                let start = end.saturating_sub(Duration::from_secs(5 * 60));
                (
                    start.as_secs(),
                    end.as_secs(),
                    stats.min,
                    stats.max,
                    format_duration_hms(&start),
                    format_duration_hms(&((end - start) / 2)),
                    format_duration_hms(&end),
                )
            };

        let x_labels = vec![
            Span::styled(min_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(med_lbl_x),
            Span::styled(max_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
        ];

        let mut data = vec![];
        let mut prev = (min_x, 0);
        for ts in &stats.series {
            let t = ts.time.as_secs();
            if t > prev.0 + 1 {
                for v in prev.0 + 1..t {
                    data.push((v as f64, prev.1 as f64));
                }
            }
            prev = (t, ts.item);
            data.push((t as f64, ts.item as f64));
        }
        if max_x > prev.0 + 1 {
            for v in prev.0 + 1..max_x {
                data.push((v as f64, prev.1 as f64));
            }
        }

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
            .data(&data)];
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
                    .bounds([min_x as f64, max_x as f64])
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
                        Span::raw("0"),
                        Span::styled(
                            format!("{}", max_y),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ]),
            );
        f.render_widget(chart, area);
    }

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
                        .last()
                        .map(|x| x.item)
                        .unwrap_or(0)
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
                format!("client #{} (`n` to switch)", self.clients_idx),
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
        let sel = if logs.is_empty() {
            None
        } else {
            Some(logs.len() - 1)
        };
        let logs = List::new(logs).block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                "clients logs (`t` to show/hide)",
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        f.render_stateful_widget(logs, area, &mut self.client_logs);
        self.client_logs.select(sel);
    }
}
