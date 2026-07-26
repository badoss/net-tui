//! Interface picker.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph};

use super::theme;
use crate::app::{App, DeviceEntry};

const HINTS: &[(&str, &str)] = &[
    ("↑/↓", "select"),
    ("enter", "capture"),
    ("/", "find"),
    ("F", "filter builder"),
    ("r", "refresh"),
    ("?", "help"),
    ("q", "quit"),
];

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, app, header);
    draw_list(frame, app, body);
    super::draw_footer(frame, app, footer, HINTS);
}

fn draw_header(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = super::block("net-tui", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut spans = vec![
        Span::styled(
            "Select an interface to capture",
            Style::new().fg(theme::TEXT),
        ),
        Span::styled(
            format!("   {} found", app.devices.len()),
            Style::new().fg(theme::MUTED),
        ),
    ];
    if !app.bpf.is_empty() {
        spans.push(Span::styled("   bpf: ", Style::new().fg(theme::MUTED)));
        spans.push(Span::styled(app.bpf.clone(), Style::new().fg(theme::WARN)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn draw_list(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let title = if app.device_query.is_empty() {
        "Interfaces".to_string()
    } else {
        format!("Interfaces  (matching \"{}\")", app.device_query)
    };
    let block = super::block(&title, true);

    if app.device_view.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("No interfaces match. Press / to change the search, r to refresh.")
                .style(Style::new().fg(theme::MUTED)),
            inner,
        );
        return;
    }

    let name_width = app
        .device_view
        .iter()
        .map(|&i| app.devices[i].name.chars().count())
        .max()
        .unwrap_or(8)
        .clamp(6, 20);

    let items: Vec<ListItem> = app
        .device_view
        .iter()
        .map(|&i| ListItem::new(device_line(&app.devices[i], name_width)))
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::new()
                .bg(theme::SELECTION)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌");

    frame.render_stateful_widget(list, area, &mut app.device_state);
}

fn device_line(dev: &DeviceEntry, name_width: usize) -> Line<'static> {
    // An interface with an address and a running link is the one most likely
    // to have traffic, so it gets the strongest marker.
    let (dot, dot_color) = match (dev.running && !dev.addresses.is_empty(), dev.up) {
        (true, _) => ("●", theme::OK),
        (false, true) => ("●", theme::WARN),
        (false, false) => ("○", theme::MUTED),
    };

    let addresses = if dev.addresses.is_empty() {
        "—".to_string()
    } else {
        dev.addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut tags = Vec::new();
    if dev.loopback {
        tags.push("loopback");
    }
    if dev.wireless {
        tags.push("wireless");
    }
    if !dev.up {
        tags.push("down");
    }

    let mut spans = vec![
        Span::styled(format!(" {dot} "), Style::new().fg(dot_color)),
        Span::styled(
            format!("{:<width$}  ", dev.name, width = name_width),
            Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(addresses, Style::new().fg(theme::ACCENT)),
    ];

    if let Some(desc) = &dev.desc {
        spans.push(Span::styled(
            format!("  {desc}"),
            Style::new().fg(theme::MUTED),
        ));
    }
    if !tags.is_empty() {
        spans.push(Span::styled(
            format!("  [{}]", tags.join(", ")),
            Style::new().fg(theme::MUTED),
        ));
    }

    Line::from(spans)
}
