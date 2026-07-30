//! What is listening on this machine.
//!
//! The point of difference from netstat is the exposure column: the thing
//! people actually want to know is which ports are reachable from off the box,
//! and that is exactly what a list of raw bind addresses makes you work out.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::theme;
use crate::app::App;
use crate::sockets::{Exposure, Listener};

const HINTS: &[(&str, &str)] = &[
    ("↑/↓", "move"),
    ("/", "filter"),
    ("r", "refresh"),
    ("n", "clear filter"),
    ("esc", "menu"),
    ("?", "help"),
    ("q", "quit"),
];

const COLUMNS: [(&str, Constraint); 7] = [
    ("Proto", Constraint::Length(6)),
    ("Port", Constraint::Length(7)),
    ("Service", Constraint::Length(10)),
    ("Reachable from", Constraint::Length(15)),
    ("Bound to", Constraint::Length(24)),
    ("Conns", Constraint::Length(6)),
    ("Process", Constraint::Min(24)),
];

const fn exposure_color(exposure: Exposure) -> ratatui::style::Color {
    match exposure {
        Exposure::Everywhere => theme::ERROR,
        Exposure::Interface => theme::WARN,
        Exposure::Local => theme::OK,
    }
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, detail, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, app, header);
    match &app.listeners_error {
        Some(message) => draw_error(frame, &message.clone(), body),
        None => draw_table(frame, app, body),
    }
    draw_detail(frame, app, detail);
    super::draw_footer(frame, app, footer, HINTS);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let block = super::block("Ports and services", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // The counts are the summary someone reads first: how much of this machine
    // is actually reachable from outside.
    let mut everywhere = 0usize;
    let mut interface = 0usize;
    let mut local = 0usize;
    for listener in &app.listeners {
        match listener.exposure {
            Exposure::Everywhere => everywhere += 1,
            Exposure::Interface => interface += 1,
            Exposure::Local => local += 1,
        }
    }

    let mut spans = vec![
        Span::styled(
            format!("{everywhere} reachable from anywhere"),
            Style::new()
                .fg(exposure_color(Exposure::Everywhere))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   ", Style::new()),
        Span::styled(
            format!("{interface} on this network"),
            Style::new().fg(exposure_color(Exposure::Interface)),
        ),
        Span::styled("   ", Style::new()),
        Span::styled(
            format!("{local} local only"),
            Style::new().fg(exposure_color(Exposure::Local)),
        ),
    ];
    if !app.ports_query.is_empty() {
        spans.push(Span::styled("   filter: ", Style::new().fg(theme::MUTED)));
        spans.push(Span::styled(
            app.ports_query.clone(),
            Style::new().fg(theme::WARN).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn draw_error(frame: &mut Frame, message: &str, area: Rect) {
    let block = super::block("Unavailable", false).border_style(Style::new().fg(theme::WARN));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(message.to_string())
            .style(Style::new().fg(theme::WARN))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = format!(
        "Listening  {}/{}",
        app.ports_view.len(),
        app.listeners.len()
    );
    let block = super::block(&title, true);
    let inner = block.inner(area);
    app.ports_height = inner.height.saturating_sub(1).max(1) as usize;

    let rows: Vec<Row> = (0..app.ports_view.len())
        .filter_map(|row| app.listener_at(row))
        .map(listener_row)
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

    frame.render_stateful_widget(table, area, &mut app.ports_state);

    if app.ports_view.is_empty() {
        let hint = if app.listeners.is_empty() {
            "Nothing is listening, or /proc could not be read. Press r to refresh."
        } else {
            "No listener matches the filter. Press n to clear it."
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

/// Spells out the selected row, since the table truncates the command line and
/// has no room for the owning user.
fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let Some(listener) = app.selected_listener() else {
        return;
    };

    let owner = listener
        .user
        .clone()
        .unwrap_or_else(|| format!("uid {}", listener.uid));
    let endpoint = if listener.addr.is_ipv6() {
        format!("[{}]:{}", listener.addr, listener.port)
    } else {
        format!("{}:{}", listener.addr, listener.port)
    };

    let first = Line::from(vec![
        Span::styled(" ", Style::new()),
        Span::styled(
            listener.transport.label(listener.ipv6).to_string(),
            Style::new().fg(theme::MUTED),
        ),
        Span::styled(format!("  {endpoint}"), Style::new().fg(theme::TEXT)),
        Span::styled("  reachable from ", Style::new().fg(theme::MUTED)),
        Span::styled(
            listener.exposure.label().to_string(),
            Style::new()
                .fg(exposure_color(listener.exposure))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  as {owner}"), Style::new().fg(theme::MUTED)),
    ]);

    let second = Line::from(vec![
        Span::styled(" ", Style::new()),
        Span::styled(listener.describe_process(), Style::new().fg(theme::ACCENT)),
    ]);

    frame.render_widget(Paragraph::new(vec![first, second]), area);
}

fn listener_row(listener: &Listener) -> Row<'static> {
    let exposure = exposure_color(listener.exposure);
    let connections = if listener.connections == 0 {
        "—".to_string()
    } else {
        listener.connections.to_string()
    };

    Row::new(vec![
        Cell::from(listener.transport.label(listener.ipv6)).style(Style::new().fg(theme::MUTED)),
        Cell::from(Line::from(listener.port.to_string()).alignment(Alignment::Right))
            .style(Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD)),
        Cell::from(listener.service.unwrap_or("—")).style(Style::new().fg(theme::ACCENT)),
        Cell::from(listener.exposure.label())
            .style(Style::new().fg(exposure).add_modifier(Modifier::BOLD)),
        Cell::from(listener.addr.to_string()).style(Style::new().fg(theme::MUTED)),
        Cell::from(Line::from(connections).alignment(Alignment::Right)).style(Style::new().fg(
            if listener.connections > 0 {
                theme::OK
            } else {
                theme::MUTED
            },
        )),
        Cell::from(listener.describe_process()).style(Style::new().fg(theme::TEXT)),
    ])
}
