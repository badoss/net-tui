//! Live capture screen: status header, filter chips, packet table, detail pane.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Sparkline, Table, TableState, Wrap};

use super::theme;
use crate::app::{App, Focus, Status, proto_index};
use crate::packet::{ALL_PROTOS, Packet};

const HINTS: &[(&str, &str)] = &[
    ("↑/↓", "move"),
    ("enter", "detail"),
    ("/", "filter"),
    ("F", "builder"),
    ("f", "bpf"),
    ("space", "follow"),
    ("p", "pause"),
    ("c", "clear"),
    ("w", "save"),
    ("esc", "interfaces"),
    ("?", "help"),
];

const COLUMNS: [(&str, Constraint); 7] = [
    ("No.", Constraint::Length(8)),
    ("Time", Constraint::Length(13)),
    ("Source", Constraint::Length(26)),
    ("Destination", Constraint::Length(26)),
    ("Proto", Constraint::Length(6)),
    ("Len", Constraint::Length(7)),
    ("Info", Constraint::Min(20)),
];

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, chips, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, app, header);
    draw_chips(frame, app, chips);

    let (table_area, detail_area) = if app.show_detail {
        let [top, bottom] =
            Layout::vertical([Constraint::Min(4), Constraint::Percentage(45)]).areas(body);
        (top, Some(bottom))
    } else {
        (body, None)
    };

    // A capture that never started has nothing to tabulate; the error text
    // (which carries the sudo remedy) is the only useful thing to show.
    match (&app.status, app.packets_len()) {
        (Status::Error(message), 0) => draw_error(frame, &message.clone(), table_area),
        _ => draw_table(frame, app, table_area),
    }

    if let Some(area) = detail_area {
        super::detail::draw(frame, app, area);
    }
    super::draw_footer(frame, app, footer, HINTS);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let device = app.device_name().unwrap_or("—").to_string();
    let block = super::block(&format!("net-tui · {device}"), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [info, graph] =
        Layout::horizontal([Constraint::Min(40), Constraint::Length(26)]).areas(inner);

    let (badge, badge_color) = match (&app.status, app.paused) {
        (Status::Running, true) => ("PAUSED", theme::WARN),
        (Status::Running, false) => ("LIVE", theme::OK),
        (Status::Error(_), _) => ("ERROR", theme::ERROR),
        (status, _) => (status.label(), theme::MUTED),
    };

    let link_name = app
        .linktype
        .get_name()
        .unwrap_or_else(|_| format!("DLT {}", app.linktype.0));

    let mut first = vec![
        Span::styled(
            format!(" {badge} "),
            Style::new()
                .fg(theme::SELECTION)
                .bg(badge_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {link_name}"), Style::new().fg(theme::MUTED)),
        Span::styled("   bpf: ", Style::new().fg(theme::MUTED)),
    ];
    if app.bpf.is_empty() {
        first.push(Span::styled("(none)", Style::new().fg(theme::MUTED)));
    } else {
        first.push(Span::styled(app.bpf.clone(), Style::new().fg(theme::WARN)));
    }
    if !app.follow {
        first.push(Span::styled(
            "   scroll-locked",
            Style::new().fg(theme::WARN),
        ));
    }

    let counters = &app.counters;
    let kernel_dropped = counters.driver.total();
    let dropped = kernel_dropped + counters.ui_dropped;
    // Which side is losing packets changes the fix (bigger buffer vs. a
    // narrower filter), so break the total down once it is non-zero.
    let dropped_text = if dropped == 0 {
        "  dropped 0".to_string()
    } else {
        format!(
            "  dropped {dropped} (kernel {kernel_dropped}, ui {})",
            counters.ui_dropped
        )
    };
    let second = Line::from(vec![
        Span::styled(
            format!("{} pkts", super::human_count(counters.total)),
            Style::new().fg(theme::TEXT),
        ),
        Span::styled(
            format!("  {}", super::human_bytes(counters.bytes)),
            Style::new().fg(theme::MUTED),
        ),
        Span::styled(
            format!("  {} pps", counters.pps),
            Style::new().fg(theme::ACCENT),
        ),
        Span::styled(
            format!("  {}/s", super::human_bytes(counters.bps)),
            Style::new().fg(theme::ACCENT),
        ),
        Span::styled(
            format!("  showing {}", super::human_count(app.view_len() as u64)),
            Style::new().fg(theme::MUTED),
        ),
        Span::styled(
            dropped_text,
            Style::new().fg(if dropped > 0 {
                theme::ERROR
            } else {
                theme::MUTED
            }),
        ),
    ]);

    frame.render_widget(Paragraph::new(vec![Line::from(first), second]), info);

    let history: Vec<u64> = counters.history.iter().copied().collect();
    if !history.is_empty() {
        let [label_area, spark_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(graph);
        frame.render_widget(
            Paragraph::new(Span::styled("packets/sec", Style::new().fg(theme::MUTED)))
                .alignment(Alignment::Right),
            label_area,
        );
        frame.render_widget(
            Sparkline::default()
                .data(history)
                .style(Style::new().fg(theme::ACCENT)),
            spark_area,
        );
    }
}

fn draw_chips(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(" show ", Style::new().fg(theme::MUTED))];
    for proto in ALL_PROTOS {
        let enabled = app.proto_enabled[proto_index(proto)];
        let style = if enabled {
            Style::new()
                .fg(theme::proto_color(proto))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme::MUTED).add_modifier(Modifier::DIM)
        };
        spans.push(Span::styled(
            format!("{}{} ", if enabled { "✓" } else { "✗" }, proto.label()),
            style,
        ));
        spans.push(Span::styled(
            format!("({})  ", proto.hotkey()),
            Style::new().fg(theme::MUTED).add_modifier(Modifier::DIM),
        ));
    }
    let spec_summary = app.display_spec.summary();
    if !spec_summary.is_empty() {
        spans.push(Span::styled("  where: ", Style::new().fg(theme::MUTED)));
        spans.push(Span::styled(
            spec_summary,
            Style::new().fg(theme::WARN).add_modifier(Modifier::BOLD),
        ));
    }
    if !app.display_filter.is_empty() {
        spans.push(Span::styled("  match: ", Style::new().fg(theme::MUTED)));
        spans.push(Span::styled(
            app.display_filter.clone(),
            Style::new().fg(theme::WARN).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_error(frame: &mut Frame, message: &str, area: Rect) {
    let block = super::block("Capture failed", false).border_style(Style::new().fg(theme::ERROR));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(message.to_string())
            .style(Style::new().fg(theme::ERROR))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Table;
    let title = format!("Packets  {}/{}", app.view_len(), app.packets_len());
    let block = super::block(&title, focused);
    let inner = block.inner(area);
    // One row of the inner area is the header.
    let visible_rows = inner.height.saturating_sub(1) as usize;
    app.table_height = visible_rows.max(1);

    let total = app.view_len();
    let offset = window_offset(
        app.table_offset,
        app.table_state.selected(),
        total,
        app.table_height,
    );
    app.table_offset = offset;

    // Only the on-screen window is formatted; the ring behind it can hold tens
    // of thousands of packets without affecting frame cost.
    let rows: Vec<Row> = (offset..(offset + app.table_height).min(total))
        .filter_map(|i| app.visible_at(i))
        .map(packet_row)
        .collect();

    let header = Row::new(
        COLUMNS
            .iter()
            .map(|(name, _)| Cell::from(*name))
            .collect::<Vec<_>>(),
    )
    .style(Style::new().fg(theme::MUTED).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, COLUMNS.map(|(_, width)| width))
        .header(header)
        .block(block)
        .column_spacing(1)
        .row_highlight_style(
            Style::new()
                .bg(theme::SELECTION)
                .add_modifier(Modifier::BOLD),
        );

    // The table only knows about the window, so translate the selection into
    // window-local coordinates and pin its own offset to the top.
    let mut local = TableState::default();
    local.select(
        app.table_state
            .selected()
            .and_then(|s| s.checked_sub(offset))
            .filter(|&row| row < app.table_height),
    );
    frame.render_stateful_widget(table, area, &mut local);

    if total == 0 {
        let hint = if app.packets_len() == 0 {
            "Waiting for packets…"
        } else {
            "No packets match the current filters. Press n to reset."
        };
        frame.render_widget(
            Paragraph::new(hint).style(Style::new().fg(theme::MUTED)),
            Rect {
                y: inner.y + 1,
                height: 1.min(inner.height.saturating_sub(1)),
                ..inner
            },
        );
    }
}

/// Scrolls the window the minimum distance needed to keep `selected` visible.
fn window_offset(previous: usize, selected: Option<usize>, total: usize, height: usize) -> usize {
    if total <= height {
        return 0;
    }
    let max_offset = total - height;
    let mut offset = previous.min(max_offset);
    if let Some(row) = selected {
        if row < offset {
            offset = row;
        } else if row >= offset + height {
            offset = row + 1 - height;
        }
    }
    offset
}

fn packet_row(pkt: &Packet) -> Row<'static> {
    let proto_style = Style::new().fg(theme::proto_color(pkt.proto));
    Row::new(vec![
        Cell::from(Line::from(pkt.no.to_string()).alignment(Alignment::Right))
            .style(Style::new().fg(theme::MUTED)),
        Cell::from(pkt.ts.format("%H:%M:%S%.3f").to_string()).style(Style::new().fg(theme::MUTED)),
        Cell::from(pkt.src.display()).style(Style::new().fg(theme::TEXT)),
        Cell::from(pkt.dst.display()).style(Style::new().fg(theme::TEXT)),
        Cell::from(pkt.proto.label()).style(proto_style.add_modifier(Modifier::BOLD)),
        Cell::from(Line::from(pkt.wire_len.to_string()).alignment(Alignment::Right))
            .style(Style::new().fg(theme::MUTED)),
        Cell::from(pkt.info.clone()).style(proto_style),
    ])
}

#[cfg(test)]
mod tests {
    use super::window_offset;

    #[test]
    fn window_stays_at_top_when_everything_fits() {
        assert_eq!(window_offset(0, Some(3), 5, 10), 0);
        assert_eq!(window_offset(7, Some(3), 5, 10), 0);
    }

    #[test]
    fn window_follows_the_selection_by_the_minimum_distance() {
        // Selection below the window scrolls down just enough.
        assert_eq!(window_offset(0, Some(12), 100, 10), 3);
        // Selection above the window scrolls up to it.
        assert_eq!(window_offset(20, Some(5), 100, 10), 5);
        // Selection already inside the window leaves it alone.
        assert_eq!(window_offset(10, Some(15), 100, 10), 10);
    }

    #[test]
    fn window_is_clamped_when_the_list_shrinks() {
        assert_eq!(window_offset(500, None, 100, 10), 90);
    }
}
