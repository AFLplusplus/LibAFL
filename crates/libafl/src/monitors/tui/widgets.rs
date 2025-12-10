use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::time::Duration;
use std::sync::RwLock;

use libafl_bolts::{current_time, format_big_number, format_duration};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, List, ListItem, Row, Table, block::Title,
    },
};

use crate::monitors::tui::{ItemGeometry, ProcessTiming, TimedStats, TuiContext};

/// Draw the time chart with the given stats
#[expect(clippy::too_many_lines, clippy::cast_precision_loss)]
pub fn draw_time_chart(
    title: &str,
    y_name: &str,
    f: &mut Frame,
    area: Rect,
    stats: &TimedStats,
    graph_data: &mut Vec<(f64, f64)>,
    enhanced_graphics: bool,
    current_time: Duration,
) {
    // if stats.series.is_empty() {
    //     return;
    // }
    let last_stat_time = stats.series.back().map(|s| s.time).unwrap_or(current_time);
    let end = last_stat_time.max(current_time);
    let start = end.saturating_sub(stats.window);

    // Ensure we have at least some window to avoid division by zero
    let window = if start == end {
        Duration::from_secs(1)
    } else {
        end.saturating_sub(start)
    };

    let min_lbl_x = format_duration(&start);
    let med_lbl_x = format_duration(&(window / 2));
    let max_lbl_x = format_duration(&end);

    let x_labels = vec![
        Span::styled(min_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(med_lbl_x),
        Span::styled(max_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
    ];

    let max_x = u64::from(area.width);

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

    let window_unit = convert_time(&window).max(1); // Ensure non-zero

    let to_x =
        |d: &Duration| (convert_time(d).saturating_sub(convert_time(&start))) * max_x / window_unit;

    graph_data.clear();

    // Initialize bounds
    let mut max_y: Option<f64> = None;
    let mut min_y: Option<f64> = None;

    // Find the starting index efficiently
    let (s1, s2) = stats.series.as_slices();
    let idx1 = s1.partition_point(|x| x.time < start);
    let start_index = if idx1 == s1.len() {
        s1.len() + s2.partition_point(|x| x.time < start)
    } else {
        idx1
    }
    .saturating_sub(1); // Include one point before start for continuity

    let mut prev = (0, 0.0);
    // Initialize with first visible point (or the one just before)
    if let Some(first) = stats.series.get(start_index) {
        prev = (to_x(&first.time), first.item);
    }

    for ts in stats.series.iter().skip(start_index) {
        let x = to_x(&ts.time);

        // Update bounds for ALL points to ensure auto-scaling covers spikes even if not drawn
        max_y = Some(max_y.map_or(ts.item, |m| m.max(ts.item)));
        min_y = Some(min_y.map_or(ts.item, |m| m.min(ts.item)));

        if x > prev.0 || graph_data.is_empty() {
            if x > prev.0 + 1 && !graph_data.is_empty() {
                // Fill gap
                for v in (prev.0 + 1)..x {
                    graph_data.push((v as f64, prev.1));
                }
            }
            graph_data.push((x as f64, ts.item));
            prev = (x, ts.item);
        } else {
            // Same X coordinate, update last point to latest value
            if let Some(last) = graph_data.last_mut() {
                last.1 = ts.item;
            }
            prev.1 = ts.item;
        }
    }

    // Extrapolate to current time (end)
    let end_x = to_x(&end);
    if end_x > prev.0 {
        for v in (prev.0 + 1)..=end_x.min(max_x) {
            graph_data.push((v as f64, prev.1));
        }
        // Ensure the last point is exactly at end_x/current value
        // Use prev.1 as the value since we are extrapolating flat line
    }

    // Ensure reasonable bounds if empty or flat
    let min_y = min_y.unwrap_or(0.0);
    let mut max_y = max_y.unwrap_or(0.0);

    if (min_y - max_y).abs() < f64::EPSILON {
        max_y = min_y + 2.0;
    }
    if max_x > prev.0 + 1 {
        for v in (prev.0 + 1)..max_x {
            graph_data.push((v as f64, prev.1));
        }
    }

    let datasets = vec![
        Dataset::default()
            .marker(if enhanced_graphics {
                symbols::Marker::Braille
            } else {
                symbols::Marker::Dot
            })
            .style(
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD),
            )
            .data(graph_data),
    ];
    let mut block = Block::default().borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT);
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let chart = Chart::new(datasets)
        .block(block)
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
                .bounds([min_y, max_y])
                .labels(vec![
                    Span::styled(
                        format!("{min_y:.2}"),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{:.2}", (max_y - min_y) / 2.0 + min_y)),
                    Span::styled(
                        format!("{max_y:.2}"),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
        );
    f.render_widget(chart, area);
}

/// Draw the geometry information of the fuzzing items (testcases)
pub fn draw_item_geometry_text(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    is_overall: bool,
    client_idx: usize,
    clients_list: &[usize],
) {
    let tui_context = app.read().unwrap();
    let empty_geometry: ItemGeometry = ItemGeometry::new();
    let item_geometry: &ItemGeometry = if is_overall {
        tui_context
            .total_item_geometry
            .as_ref()
            .unwrap_or(&empty_geometry)
    } else if clients_list.is_empty() {
        &empty_geometry
    } else {
        let clients = &tui_context.clients;
        let client = clients.get(&client_idx);
        if let Some(client) = client {
            client.item_geometry.as_ref().unwrap_or(&empty_geometry)
        } else {
            &empty_geometry
        }
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
            Cell::from(Span::raw(format!(
                "{:.2}%",
                item_geometry.stability.unwrap_or(0.0) * 100.0
            ))),
        ]),
    ];

    let table = Table::default()
        .rows(items)
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
        .widths([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
    f.render_widget(table, area);
}

/// Draw the process timing information
pub fn draw_process_timing_text(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    title: &str,
    is_overall: bool,
    client_idx: usize,
    clients_list: &[usize],
) {
    let tui_context = app.read().unwrap();
    let empty_timing: ProcessTiming = ProcessTiming::new();
    let tup: (Duration, &ProcessTiming) = if is_overall {
        (tui_context.start_time, &tui_context.total_process_timing)
    } else if clients_list.is_empty() {
        (current_time(), &empty_timing)
    } else {
        let clients = &tui_context.clients;
        let client = clients.get(&client_idx);
        let client = client.as_ref();
        if let Some(client) = client {
            (
                client.process_timing.client_start_time,
                &client.process_timing,
            )
        } else {
            log::warn!("Client {client_idx} was `None`. Race condition?");
            (current_time(), &empty_timing)
        }
    };
    let items = vec![
        Row::new(vec![
            Cell::from(Span::raw("run time")),
            Cell::from(Span::raw(format_duration(
                &current_time().saturating_sub(tup.0),
            ))),
        ]),
        Row::new(vec![
            Cell::from(Span::raw("exec speed")),
            Cell::from(Span::raw(&tup.1.exec_speed)),
        ]),
        Row::new(vec![
            Cell::from(Span::raw("last new entry")),
            Cell::from(Span::raw(format_duration(&(tup.1.last_new_entry)))),
        ]),
        Row::new(vec![
            Cell::from(Span::raw("last solution")),
            Cell::from(Span::raw(format_duration(&(tup.1.last_saved_solution)))),
        ]),
    ];

    let mut block = Block::default().borders(Borders::ALL);
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let table = Table::default()
        .rows(items)
        .block(block)
        .widths([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
    f.render_widget(table, area);
}

/// Draw the overall/generic stats (clients count, corpus size, etc.)
pub fn draw_overall_generic_text(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    title: &str,
    clients_len: usize,
) {
    let items = {
        let app = app.read().unwrap();
        vec![
            Row::new(vec![
                Cell::from(Span::raw("clients")),
                Cell::from(Span::raw(format!("{clients_len}"))),
                Cell::from(Span::raw("total execs")),
                Cell::from(Span::raw(
                    format_big_number(app.total_execs)
                        .split_once('(')
                        .map(|(a, _)| a.trim().to_string())
                        .unwrap_or_else(|| format_big_number(app.total_execs)),
                )),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("solutions")),
                Cell::from(Span::raw(format_big_number(app.total_solutions))),
                Cell::from(Span::raw("corpus count")),
                Cell::from(Span::raw(format_big_number(app.total_corpus_count))),
            ]),
        ]
    };

    let mut block = Block::default().borders(if title.is_empty() {
        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
    } else {
        Borders::ALL
    });
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let table = Table::default().rows(items).block(block).widths([
        Constraint::Percentage(30),
        Constraint::Percentage(20),
        Constraint::Percentage(30),
        Constraint::Percentage(20),
    ]);
    f.render_widget(table, area);
}

/// Draw the generic stats for a client (corpus, executions)
pub fn draw_client_generic_text(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    title: &str,
    client_idx: usize,
) {
    let items = {
        let app = app.read().unwrap();
        let mut rows = vec![
            Row::new(vec![
                Cell::from(Span::raw("corpus count")),
                Cell::from(Span::raw(format_big_number(
                    app.clients
                        .get(&client_idx)
                        .map_or(0, |x| x.client_stats.corpus_size()),
                ))),
            ]),
            Row::new(vec![
                Cell::from(Span::raw("total execs")),
                Cell::from(Span::raw(format_big_number(
                    app.clients
                        .get(&client_idx)
                        .map_or(0, |x| x.client_stats.executions()),
                ))),
            ]),
        ];

        if let Some(client) = app.clients.get(&client_idx) {
            if let Some(cycles) = client.cycles_done() {
                rows.push(Row::new(vec![
                    Cell::from(Span::raw("cycles done")),
                    Cell::from(Span::raw(format!("{cycles}"))),
                ]));
            }
            rows.push(Row::new(vec![
                Cell::from(Span::raw("solutions")),
                Cell::from(Span::raw(format!(
                    "{}",
                    client.client_stats.objective_size()
                ))),
            ]));
        }
        rows
    };

    let mut block = Block::default().borders(Borders::ALL);
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let table = Table::default()
        .rows(items)
        .block(block)
        .widths([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
    f.render_widget(table, area);
}

/// Draw introspection stats (scheduler, manager, stages)
#[cfg(feature = "introspection")]
pub fn draw_introspection_text(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    client_idx: usize,
) {
    let mut items = vec![];
    {
        let ctx = app.read().unwrap();
        if let Some(client) = ctx.clients.get(&client_idx) {
            let m = &client.client_stats.introspection_stats;
            // Calculate the elapsed time from the monitor
            let elapsed: f64 = m.elapsed_cycles() as f64;

            // Calculate the percentages for each benchmark
            let scheduler = m.scheduler_cycles() as f64 / elapsed;
            let manager = m.manager_cycles() as f64 / elapsed;

            // Calculate the remaining percentage that has not been benchmarked
            let mut other_percent = 1.0;
            other_percent -= scheduler;
            other_percent -= manager;

            items.push(Row::new(vec![
                Cell::from(Span::raw("scheduler")),
                Cell::from(Span::raw(format!("{:.2}%", scheduler * 100.0))),
            ]));
            items.push(Row::new(vec![
                Cell::from(Span::raw("manager")),
                Cell::from(Span::raw(format!("{:.2}%", manager * 100.0))),
            ]));

            // Calculate each stage
            // Make sure we only iterate over used stages
            for (stage_index, features) in m.used_stages() {
                items.push(Row::new(vec![
                    Cell::from(Span::raw(format!("stage {stage_index}"))),
                    Cell::from(Span::raw("")),
                ]));

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
                    let feature: crate::monitors::stats::perf_stats::PerfFeature =
                        feature_index.into();
                    items.push(Row::new(vec![
                        Cell::from(Span::raw(format!("{feature:?}"))),
                        Cell::from(Span::raw(format!("{:.2}%", feature_percent * 100.0))),
                    ]));
                }
            }

            for (feedback_name, feedback_time) in m.feedbacks() {
                // Calculate this current stage's percentage
                let feedback_percent = *feedback_time as f64 / elapsed;

                // Ignore this feedback if it isn't used
                if feedback_percent == 0.0 {
                    continue;
                }

                // Update the other percent by removing this current percent
                other_percent -= feedback_percent;

                items.push(Row::new(vec![
                    Cell::from(Span::raw(feedback_name.clone())),
                    Cell::from(Span::raw(format!("{:.2}%", feedback_percent * 100.0))),
                ]));
            }

            items.push(Row::new(vec![
                Cell::from(Span::raw("not measured")),
                Cell::from(Span::raw(format!("{:.2}%", other_percent * 100.0))),
            ]));
        }
    }

    let table = Table::default()
        .rows(items)
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
        .widths([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]);
    f.render_widget(table, area);
}

/// Draw the client logs
#[allow(deprecated)]
pub fn draw_logs(f: &mut Frame, app: &Arc<RwLock<TuiContext>>, area: Rect, enable_wrap: bool) {
    let app = app.read().unwrap();
    let num_lines = area.height.saturating_sub(2) as usize;

    let mut logs: Vec<ListItem> = vec![];

    if enable_wrap {
        let width = area.width.saturating_sub(2) as usize;
        if width > 0 {
            // Process logs in reverse to fill from bottom
            for msg in app.client_logs.iter().rev() {
                let mut lines = vec![];
                let chars: Vec<char> = msg.chars().collect();
                if chars.len() <= width {
                    lines.push(msg.clone());
                } else {
                    let mut first = true;
                    // Char-based wrapping
                    let mut i = 0;
                    while i < chars.len() {
                        let limit = if first {
                            width
                        } else {
                            width.saturating_sub(2)
                        };
                        let chunk_len = std::cmp::min(limit, chars.len() - i);
                        let chunk: String = chars[i..i + chunk_len].iter().collect();

                        if first {
                            lines.push(chunk);
                            first = false;
                        } else {
                            lines.push(format!("  {}", chunk));
                        }
                        i += chunk_len;
                    }
                }

                // Add lines to logs (which is filling reversed)
                for line in lines.into_iter().rev() {
                    logs.push(ListItem::new(Span::raw(line)));
                    if logs.len() >= num_lines {
                        break;
                    }
                }
                if logs.len() >= num_lines {
                    break;
                }
            }
            logs.reverse();
        }
    } else {
        let start_index = app.client_logs.len().saturating_sub(num_lines);
        logs = app
            .client_logs
            .range(start_index..)
            .map(|msg| ListItem::new(Span::raw(msg)))
            .collect();
    }

    let logs = List::new(logs).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                "clients logs (`t` to show/hide, `w` to wrap)",
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .title(
                Title::from(Span::styled(
                    "`q` to quit",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Right),
            )
            .title(
                Title::from(Span::styled(
                    if enable_wrap { "wrapped" } else { "raw" },
                    Style::default().fg(Color::DarkGray),
                ))
                .position(ratatui::widgets::block::Position::Bottom)
                .alignment(Alignment::Right),
            ),
    );
    f.render_widget(logs, area);
}
