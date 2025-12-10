use alloc::vec::Vec;

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Splits the main area into top (overall), middle (client), and bottom (logs)
#[must_use]
pub fn split_main(area: Rect, show_logs: bool, introspection: bool, has_charts: bool) -> Vec<Rect> {
    if show_logs {
        if introspection {
            // Introspection mode
            Layout::default()
                .constraints(
                    [
                        Constraint::Percentage(41),
                        Constraint::Percentage(44),
                        Constraint::Percentage(15),
                    ]
                    .as_ref(),
                )
                .split(area)
                .to_vec()
        } else {
            // Normal mode
            // We want to ensure at least 5 lines for logs.
            let logs_min = 5;
            let available = area.height.saturating_sub(logs_min);

            // Standard: Top 21 + Mid 6 = 27.
            // Compact target: Top 17 + Mid 6 = 23.
            // If no charts, Top can be smaller (just Stats).
            // Stats: Generic(4) + Process(6) + borders = ~12?
            // Let's rely on has_charts to reduce Top.
            // If has_charts, we use 15 (Standard) instead of 21 to give logs more space.
            let default_top = if has_charts { 15 } else { 12 };
            let compact_top = if has_charts { 15 } else { 12 };

            let (top_len, mid_len) = if available >= (default_top + 6) {
                (default_top, 6) // Standard
            } else if available >= (compact_top + 6) {
                (compact_top, 6) // Compact
            } else {
                // Squeeze mode
                // Try to keep Top at compact_top if possible, squeeze Mid.
                if available > compact_top {
                    (compact_top, available - compact_top)
                } else {
                    (available.saturating_sub(6).max(1), 6)
                }
            };

            // Adjust if calculations went wrong compared to actual height?
            // `available` was based on height - 5.
            // So top_len + mid_len <= height - 5.

            Layout::default()
                .constraints(
                    [
                        Constraint::Length(top_len),
                        Constraint::Length(mid_len),
                        Constraint::Min(logs_min), // prioritize logs at end
                    ]
                    .as_ref(),
                )
                .split(area)
                .to_vec()
        }
    } else {
        Layout::default()
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(area)
            .to_vec()
    }
}

/// Splits the overall stats area into top stats and bottom
#[must_use]
pub fn split_overall(area: Rect) -> Vec<Rect> {
    // We used to split into Top/Bottom, but now we want to use the whole area
    // effectively as one block for columns, or just return the area as is?
    // The UI code expects a list of rects.
    // Let's just return the area split into one, or keep the function for compatibility but it returns [area].
    // Actually, `split_main` reserves 17 lines for this area.
    // We can just return [area] from here?
    // But `ratatui::layout::split` returns Vec<Rect>.
    vec![area]
}

/// Splits the top area into left (stats) and right (charts)
#[must_use]
pub fn split_top(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area)
        .to_vec()
}

/// Splits the area to reserve space for a title
#[must_use]
pub fn split_title(area: Rect) -> Vec<Rect> {
    Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(area)
        .to_vec()
}

/// Splits the process timing area
#[must_use]
pub fn split_process_timing(area: Rect) -> Vec<Rect> {
    // If area is compact, we might want fewer lines for process timing
    let height = if area.height < 15 {
        4 // Compact: 3 lines content + borders? No, borders take 2. 
    // If we want to hide stuff, we need to be careful.
    // Let's say 4 lines: 2 borders + 2 content lines.
    } else {
        7 // Standard
    };

    Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(height), Constraint::Min(0)].as_ref())
        .split(area)
        .to_vec()
}

/// Splits the client area into left and right columns
#[must_use]
pub fn split_client(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area)
        .to_vec()
}
