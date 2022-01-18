use super::*;

use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Span, Spans},
    widgets::canvas::{Canvas, Line, Map, MapResolution, Rectangle},
    widgets::{
        Axis, BarChart, Block, Borders, Cell, Chart, Dataset, Gauge, LineGauge, List, ListItem,
        ListState, Paragraph, Row, Sparkline, Table, Tabs, Wrap,
    },
    Frame,
};

use std::sync::{Arc, RwLock};

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

#[derive(Default)]
pub struct TuiUI {
    pub graphs: ListState,
    pub client_logs: ListState,
}

impl TuiUI {
    pub fn draw<B: Backend>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>) {
        let chunks = Layout::default()
            .constraints([Constraint::Min(0)].as_ref())
            .split(f.size());
        self.draw_general_tab(f, app, chunks[0]);
    }

    fn draw_general_tab<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let chunks = Layout::default()
            .constraints(
                [
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ]
                .as_ref(),
            )
            .split(area);
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(chunks[0]);
        let enhanced_graphics = app.read().unwrap().enhanced_graphics; // TODO move this value in self

        self.draw_text(f, app, top_chunks[0]);
        
        let tab_chunks = Layout::default()
            .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
            .split(top_chunks[1]);
        let titles = vec![
            Spans::from(Span::styled("speed", Style::default().fg(Color::Green))),
            Spans::from(Span::styled("corpus", Style::default().fg(Color::Green))),
            Spans::from(Span::styled("objectives", Style::default().fg(Color::Green))),
        ];
        let idx = app.read().unwrap().charts_tab_idx;
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("charts"))
            .highlight_style(Style::default().fg(Color::Yellow))
            .select(idx);
        f.render_widget(tabs, tab_chunks[0]);
        match idx {
            0 => {
                  let ctx = app.read().unwrap();
                  self.draw_time_chart(
                      "speed chart",
                      "exec/sec",
                      f,
                      tab_chunks[1],
                      enhanced_graphics,
                      &ctx.execs_per_sec_timed,
                      ctx.start_time,
                  );
              }
            1 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "corpus size",
                    f,
                    tab_chunks[1],
                    enhanced_graphics,
                    &ctx.corpus_size_timed,
                    ctx.start_time,
                );
            }
            2 => {
                let ctx = app.read().unwrap();
                self.draw_time_chart(
                    "corpus chart",
                    "objectives",
                    f,
                    tab_chunks[1],
                    enhanced_graphics,
                    &ctx.objective_size_timed,
                    ctx.start_time,
                );
            }
            _ => {}
        }

        self.draw_logs(f, app, chunks[1]);
    }

    fn draw_time_chart<B>(
        &mut self,
        title: &str,
        y_name: &str,
        f: &mut Frame<B>,
        area: Rect,
        enhanced_graphics: bool,
        stats: &TimedStats,
        start_time: Duration,
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
                    // stats.series[0].time.as_secs(),
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
            .name("data")
            .marker(if enhanced_graphics {
                symbols::Marker::Braille
            } else {
                symbols::Marker::Dot
            })
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .data(&data)];
        let chart = Chart::new(datasets)
            .block(
                Block::default()
                    .title(Span::styled(
                        title,
                        Style::default(), //.fg(Color::Cyan)
                                          //.add_modifier(Modifier::BOLD)
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
                Cell::from(Span::raw(format!("{}", app.read().unwrap().clients))),
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

        #[cfg(feature = "introspection")]
        let chunks = Layout::default()
            .constraints(
                [
                    Constraint::Length(2 * items.len() as u16),
                    Constraint::Min(8),
                ]
                .as_ref(),
            )
            .split(area);
        #[cfg(not(feature = "introspection"))]
        let chunks = Layout::default()
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(area);

        /*let items: Vec<Row> = colors
        .iter()
        .map(|c| {
            let cells = vec![
                Cell::from(Span::raw(format!("{:?}: ", c))),
                Cell::from(Span::styled("Foreground", Style::default().fg(*c))),
                Cell::from(Span::styled("Background", Style::default().bg(*c))),
            ];
            Row::new(cells)
        })
        .collect();*/
        let table = Table::new(items)
            .block(Block::default().title("generic").borders(Borders::ALL))
            .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
        f.render_widget(table, chunks[0]);

        #[cfg(feature = "introspection")]
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
                    Cell::from(Span::raw(format!("{}", app.read().unwrap().clients))),
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

            let table = Table::new(items)
                .block(
                    Block::default()
                        .title("introspection")
                        .borders(Borders::ALL),
                )
                .widths(&[Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
            f.render_widget(table, chunks[1]);
        }
    }

    fn draw_logs<B>(&mut self, f: &mut Frame<B>, app: &Arc<RwLock<TuiContext>>, area: Rect)
    where
        B: Backend,
    {
        let info_style = Style::default().fg(Color::Blue);
        let warning_style = Style::default().fg(Color::Yellow);
        let error_style = Style::default().fg(Color::Magenta);
        let critical_style = Style::default().fg(Color::Red);
        let app = app.read().unwrap();
        let logs: Vec<ListItem> = app
            .client_logs
            .iter()
            .map(|msg| {
                /*let s = match level {
                    "ERROR" => error_style,
                    "CRITICAL" => critical_style,
                    "WARNING" => warning_style,
                    _ => info_style,
                };
                let content = vec![Spans::from(vec![
                    Span::styled(format!("{:<9}", info_style), s),
                    Span::raw(msg),
                ])];*/
                ListItem::new(Span::raw(msg))
            })
            .collect();
        let sel = if logs.is_empty() {
            None
        } else {
            Some(logs.len() - 1)
        };
        let logs =
            List::new(logs).block(Block::default().borders(Borders::ALL).title("clients logs"));
        f.render_stateful_widget(logs, area, &mut self.client_logs);
        self.client_logs.select(sel);
    }
}
