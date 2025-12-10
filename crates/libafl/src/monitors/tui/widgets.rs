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

use crate::monitors::{
    stats::user_stats::UserStatsValue,
    tui::{ItemGeometry, ProcessTiming, TimedStats, TuiContext},
};

/// Options for drawing a time chart
#[derive(Debug)]
pub struct TimeChartOptions<'a> {
    /// The title of the chart
    pub title: &'a str,
    /// The name of the Y-axis
    pub y_name: &'a str,
    /// The stats to plot
    pub stats: &'a TimedStats,
    /// A buffer to hold the graph data (to avoid allocations)
    pub graph_data: &'a mut Vec<(f64, f64)>,
    /// Whether to use enhanced graphics (Braille) or not
    pub enhanced_graphics: bool,
    /// The current running time
    pub current_time: Duration,
    /// Optional preset range for Y axis (min, max). Data outside this range will expand it.
    pub preset_y_range: Option<(f64, f64)>,
}

/// Draw the time chart with the given stats
#[expect(clippy::too_many_lines, clippy::cast_precision_loss)]
/// Options for drawing a time chart with multiple series
#[derive(Debug)]
pub struct MultiTimeChartOptions<'a> {
    /// The title of the chart
    pub title: &'a str,
    /// The name of the Y-axis
    pub y_name: &'a str,
    /// The stats to plot: (Name, Stats, Style)
    pub series: Vec<(&'a str, &'a TimedStats, Style)>,
    /// Buffers to hold the graph data (to avoid allocations). Must match series length.
    pub graph_data: &'a mut Vec<Vec<(f64, f64)>>,
    /// Whether to use enhanced graphics (Braille) or not
    pub enhanced_graphics: bool,
    /// The current running time
    pub current_time: Duration,
    /// Optional preset range for Y axis (min, max). Data outside this range will expand it.
    pub preset_y_range: Option<(f64, f64)>,
}

/// Draw the time chart with the given stats
#[expect(clippy::too_many_lines, clippy::cast_precision_loss)]
pub fn draw_time_chart(f: &mut Frame, area: Rect, options: TimeChartOptions) {
    let TimeChartOptions {
        title,
        y_name,
        stats,
        graph_data,
        enhanced_graphics,
        current_time,
        preset_y_range,
    } = options;

    // Create a temporary buffer for the single series
    let mut temp_data = vec![];
    core::mem::swap(graph_data, &mut temp_data);
    let mut buffers = vec![temp_data];

    let multi_options = MultiTimeChartOptions {
        title,
        y_name,
        series: vec![(
            "",
            stats,
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        )],
        graph_data: &mut buffers,
        enhanced_graphics,
        current_time,
        preset_y_range,
    };

    draw_multi_time_chart(f, area, multi_options);

    // Restore buffer
    core::mem::swap(graph_data, &mut buffers[0]);
}

/// Draw a time chart with multiple series
#[expect(clippy::too_many_lines, clippy::cast_precision_loss)]
pub fn draw_multi_time_chart(f: &mut Frame, area: Rect, options: MultiTimeChartOptions) {
    let MultiTimeChartOptions {
        title,
        y_name,
        series,
        graph_data,
        enhanced_graphics,
        current_time,
        preset_y_range,
    } = options;

    if series.is_empty() {
        return;
    }

    // Determine common window and global min/max
    // We assume all stats have roughly similar window settings, or we just use the first/max.
    // Let's use the first one for window calculation for now, or max window?
    // Usually they are all default window.
    let window = series[0].1.window;

    let end = current_time;
    let start = end.saturating_sub(window);

    // Calculate time unit and X conversion
    let max_x = u64::from(area.width);

    let window_dur = if start == end {
        Duration::from_secs(1)
    } else {
        end.saturating_sub(start)
    };

    let time_unit = if max_x > window_dur.as_secs() {
        0 // millis / 10
    } else if max_x > window_dur.as_secs() * 60 {
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

    let window_unit = convert_time(&window_dur).max(1);
    let to_x =
        |d: &Duration| (convert_time(d).saturating_sub(convert_time(&start))) * max_x / window_unit;

    // Process each series
    let mut global_min_y: Option<f64> = None;
    let mut global_max_y: Option<f64> = None;

    for (idx, (_, stats, _)) in series.iter().enumerate() {
        if idx >= graph_data.len() {
            break; // Should not happen if caller provides correct buffers
        }
        let data = &mut graph_data[idx];
        data.clear();

        let (s1, s2) = stats.series.as_slices();
        let idx1 = s1.partition_point(|x| x.time < start);
        let start_index = if idx1 == s1.len() {
            s1.len() + s2.partition_point(|x| x.time < start)
        } else {
            idx1
        }
        .saturating_sub(1);

        let mut prev = (0, 0.0);
        if let Some(first) = stats.series.get(start_index) {
            prev = (to_x(&first.time), first.item);
        }

        for ts in stats.series.iter().skip(start_index) {
            let x = to_x(&ts.time);

            global_max_y = Some(global_max_y.map_or(ts.item, |m| m.max(ts.item)));
            global_min_y = Some(global_min_y.map_or(ts.item, |m| m.min(ts.item)));

            if x > prev.0 || data.is_empty() {
                if x > prev.0 + 1 && !data.is_empty() {
                    for v in (prev.0 + 1)..x {
                        data.push((v as f64, prev.1));
                    }
                }
                data.push((x as f64, ts.item));
                prev = (x, ts.item);
            } else {
                if let Some(last) = data.last_mut() {
                    last.1 = ts.item;
                }
                prev.1 = ts.item;
            }
        }

        // Extrapolate
        let end_x = to_x(&end);
        if end_x > prev.0 {
            for v in (prev.0 + 1)..=end_x.min(max_x) {
                data.push((v as f64, prev.1));
            }
        }
        if max_x > prev.0 + 1 {
            for v in (prev.0 + 1)..max_x {
                data.push((v as f64, prev.1));
            }
        }
    }

    if let Some((p_min, p_max)) = preset_y_range {
        global_min_y = Some(global_min_y.map_or(p_min, |m| m.min(p_min)));
        global_max_y = Some(global_max_y.map_or(p_max, |m| m.max(p_max)));
    }

    let min_y = global_min_y.unwrap_or(0.0);
    let mut max_y = global_max_y.unwrap_or(0.0);

    if preset_y_range.is_none() && min_y >= 0.0 {
        max_y = max_y.max(1.0);
    }
    if (min_y - max_y).abs() < f64::EPSILON {
        max_y = min_y + 1.0;
    }

    // Create Datasets
    let datasets: Vec<Dataset> = series
        .iter()
        .enumerate()
        .map(|(idx, (name, _, style))| {
            Dataset::default()
                .name(*name)
                .marker(if enhanced_graphics {
                    symbols::Marker::Braille
                } else {
                    symbols::Marker::Dot
                })
                .style(*style)
                .data(&graph_data[idx])
        })
        .collect();

    let mut block = Block::default().borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT);
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let min_lbl_x = format_duration(&start);
    let med_lbl_x = format_duration(&(window_dur / 2));
    let max_lbl_x = format_duration(&end);
    let x_labels = vec![
        Span::styled(min_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(med_lbl_x),
        Span::styled(max_lbl_x, Style::default().add_modifier(Modifier::BOLD)),
    ];

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

/// Generic helper to draw a simple Key-Value table
pub fn draw_info_table<'a, I>(
    f: &mut Frame,
    area: Rect,
    title: &str,
    data: I,
    constraints: &[Constraint],
) where
    I: IntoIterator<Item = (Span<'a>, String)>,
{
    let rows = data
        .into_iter()
        .map(|(k, v)| Row::new([Cell::from(k), Cell::from(Span::raw(v))]));

    let mut block = Block::default().borders(Borders::ALL);
    if !title.is_empty() {
        block = block.title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let table = Table::default().rows(rows).block(block).widths(constraints);
    f.render_widget(table, area);
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
        match client {
            Some(client) => client.item_geometry.as_ref().unwrap_or(&empty_geometry),
            None => &empty_geometry,
        }
    };

    let data = [
        (Span::raw("pending"), format!("{}", item_geometry.pending)),
        (Span::raw("pend fav"), format!("{}", item_geometry.pend_fav)),
        (
            Span::raw("own finds"),
            format!("{}", item_geometry.own_finds),
        ),
        (Span::raw("imported"), format!("{}", item_geometry.imported)),
        (
            Span::raw("stability"),
            format!("{:.2}%", item_geometry.stability.unwrap_or(0.0) * 100.0),
        ),
    ];

    draw_info_table(
        f,
        area,
        "item geometry",
        data,
        &[Constraint::Length(20), Constraint::Min(5)],
    );
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

    let data = [
        (
            Span::raw("run time"),
            format_duration(&current_time().saturating_sub(tup.0)),
        ),
        (Span::raw("exec speed"), tup.1.exec_speed.clone()),
        (
            Span::raw("last new entry"),
            format_duration(&(tup.1.last_new_entry)),
        ),
        (
            Span::raw("last solution"),
            format_duration(&(tup.1.last_saved_solution)),
        ),
    ];

    draw_info_table(
        f,
        area,
        title,
        data,
        &[Constraint::Length(24), Constraint::Min(5)],
    );
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
                        .map_or_else(
                            || format_big_number(app.total_execs),
                            |(a, _)| a.trim().to_string(),
                        ),
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
        Constraint::Length(10), // "clients" + padding
        Constraint::Min(5),
        Constraint::Length(14), // "total execs" + padding
        Constraint::Min(5),
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
    let data = {
        let app = app.read().unwrap();
        let mut rows = vec![
            (
                Span::raw("corpus count"),
                format_big_number(
                    app.clients
                        .get(&client_idx)
                        .map_or(0, |x| x.client_stats.corpus_size()),
                ),
            ),
            (
                Span::raw("total execs"),
                format_big_number(
                    app.clients
                        .get(&client_idx)
                        .map_or(0, |x| x.client_stats.executions()),
                ),
            ),
        ];

        if let Some(client) = app.clients.get(&client_idx) {
            if let Some(cycles) = client.cycles_done() {
                rows.push((Span::raw("cycles done"), format!("{cycles}")));
            }
            rows.push((
                Span::raw("solutions"),
                format!("{}", client.client_stats.objective_size()),
            ));
        }
        rows
    };

    draw_info_table(
        f,
        area,
        title,
        data,
        &[Constraint::Length(20), Constraint::Min(5)],
    );
}

/// Draw introspection stats (scheduler, manager, stages)
// draw_introspection_text removed, using UserStats instead

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
                    // Space-aware word wrapping
                    let mut i = 0;
                    while i < chars.len() {
                        let limit = if first {
                            width
                        } else {
                            width.saturating_sub(2)
                        };

                        let remaining = chars.len() - i;
                        if remaining <= limit {
                            // Fits entirely
                            let chunk: String = chars[i..].iter().collect();
                            if first {
                                lines.push(chunk);
                                // first = false; // Unused as we break immediately
                            } else {
                                lines.push(format!("  {chunk}"));
                            }
                            break;
                        }

                        // Need to split
                        let mut split_idx = limit;
                        // finding the last space within the limit
                        if let Some(pos) =
                            chars[i..i + limit].iter().rposition(|c| c.is_whitespace())
                        {
                            if pos > 0 {
                                // avoid splitting at 0 if possible
                                split_idx = pos + 1; // include space in the previous line, or split after it
                            }
                        }

                        let chunk_len = core::cmp::min(split_idx, remaining);
                        let chunk: String = chars[i..i + chunk_len].iter().collect();

                        if first {
                            lines.push(chunk);
                            first = false;
                        } else {
                            lines.push(format!("  {chunk}"));
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
                    if enable_wrap { "wrapped" } else { "raw" },
                    Style::default().fg(Color::DarkGray),
                ))
                .alignment(Alignment::Right),
            )
            .title(
                Title::from(Span::styled(
                    "`q` to quit",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ))
                .position(ratatui::widgets::block::Position::Bottom)
                .alignment(Alignment::Right),
            ),
    );
    f.render_widget(logs, area);
}

/// Draw the user stats
pub fn draw_user_stats(
    f: &mut Frame,
    app: &Arc<RwLock<TuiContext>>,
    area: Rect,
    client_idx: usize,
    scroll: usize,
) -> usize {
    use crate::monitors::stats::user_stats::PlotConfig;

    let app = app.read().unwrap();

    if let Some(client) = app.clients.get(&client_idx) {
        let mut keys: Vec<_> = client.client_stats.user_stats().keys().collect();
        keys.sort();

        let total_stats = keys.len();
        // Title + Borders = 2
        let max_items = area.height.saturating_sub(2) as usize;

        if total_stats == 0 {
            return max_items;
        }

        let start_idx = if scroll >= total_stats { 0 } else { scroll };

        let visible_keys = keys.iter().skip(start_idx).take(max_items).map(|k| {
            let val = client.client_stats.user_stats().get(*k).unwrap();
            let val_str = match val.value() {
                UserStatsValue::Number(n) => format_big_number(*n),
                UserStatsValue::Float(f) => format!("{f:.2}"),
                UserStatsValue::String(s) => s.to_string(),
                UserStatsValue::Ratio(a, b) => {
                    if *b == 0 {
                        "0/0".into()
                    } else {
                        format!("{a}/{b} ({:.2}%)", (*a as f64 / *b as f64) * 100.0)
                    }
                }
                UserStatsValue::Percent(p) => format!("{:.2}%", p * 100.0),
            };

            let style = match val.plot_config() {
                PlotConfig::None => Style::default(),
                PlotConfig::Color(r, g, b) => Style::default().fg(Color::Rgb(r, g, b)),
                PlotConfig::SimpleColor(c) => Style::default().fg(Color::Indexed(c)),
            };

            (Span::styled(k.as_ref(), style), val_str)
        });

        let end_idx = (start_idx + max_items).min(total_stats);
        let nav_hint = match (start_idx > 0, total_stats > start_idx + max_items) {
            (true, true) => " (u/U)",
            (true, false) => " (U)",
            (false, true) => " (u)",
            (false, false) => "",
        };

        let title = format!(
            "User Stats {}-{}/{}{}",
            start_idx + 1,
            end_idx,
            total_stats,
            nav_hint
        );

        draw_info_table(
            f,
            area,
            &title,
            visible_keys,
            &[Constraint::Percentage(70), Constraint::Percentage(30)],
        );
        return max_items;
    }
    0
}
