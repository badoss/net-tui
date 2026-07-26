//! Filter builder modal and its observed-values picker.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

use super::theme;
use crate::app::App;
use crate::builder::{Builder, FIELDS, Field};
use crate::filter::FilterTarget;

const WIDTH: u16 = 78;
const LABEL_WIDTH: usize = 14;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let Some(builder) = app.builder.as_ref() else {
        return;
    };

    let preview = preview_lines(builder);
    // Field rows, a blank spacer, the preview, another spacer, and the hints.
    let height = FIELDS.len() as u16 + preview.len() as u16 + 5;
    let area = super::centered(frame.area(), WIDTH, height);
    super::clear_and_render(frame, area);

    let block = super::block("Filter builder", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [fields_area, preview_area, hints_area] = Layout::vertical([
        Constraint::Length(FIELDS.len() as u16 + 1),
        Constraint::Length(preview.len() as u16 + 1),
        Constraint::Length(1),
    ])
    .areas(inner);

    frame.render_widget(Paragraph::new(field_lines(builder)), fields_area);
    frame.render_widget(
        Paragraph::new(preview).wrap(Wrap { trim: false }),
        preview_area,
    );
    frame.render_widget(Paragraph::new(hint_line(builder)), hints_area);

    place_cursor(frame, builder, fields_area);

    if builder.picker.is_some() {
        draw_picker(frame, app);
    }
}

fn field_lines(builder: &Builder) -> Vec<Line<'static>> {
    FIELDS
        .iter()
        .map(|&field| {
            let focused = field == builder.focused();
            let raw = builder.value_of(field);
            let (value, value_style) = if raw.trim().is_empty() {
                (
                    "any".to_string(),
                    Style::new().fg(theme::MUTED).add_modifier(Modifier::DIM),
                )
            } else {
                (raw, Style::new().fg(theme::TEXT))
            };

            Line::from(vec![
                Span::styled(
                    if focused { "  ▌ " } else { "    " },
                    Style::new().fg(theme::ACCENT),
                ),
                Span::styled(
                    format!("{:<LABEL_WIDTH$}", field.label()),
                    Style::new().fg(if focused { theme::ACCENT } else { theme::MUTED }),
                ),
                Span::styled(
                    format!("{value:<30}"),
                    if focused {
                        value_style.add_modifier(Modifier::BOLD)
                    } else {
                        value_style
                    },
                ),
                Span::styled(
                    if focused { field.hint() } else { "" },
                    Style::new().fg(theme::MUTED).add_modifier(Modifier::DIM),
                ),
            ])
        })
        .collect()
}

fn preview_lines(builder: &Builder) -> Vec<Line<'static>> {
    if let Some(error) = &builder.error {
        return vec![
            Line::default(),
            Line::from(Span::styled(
                format!("  {error}"),
                Style::new().fg(theme::ERROR),
            )),
        ];
    }

    let spec = builder.current_spec();
    let (label, body, style) = match builder.target {
        FilterTarget::Capture => match spec.to_bpf() {
            Ok(bpf) if bpf.is_empty() => (
                "BPF",
                "(empty — captures everything)".to_string(),
                Style::new().fg(theme::MUTED),
            ),
            Ok(bpf) => ("BPF", bpf, Style::new().fg(theme::OK)),
            Err(message) => ("BPF", message, Style::new().fg(theme::ERROR)),
        },
        FilterTarget::Display => {
            let summary = spec.summary();
            if summary.is_empty() {
                (
                    "Match",
                    "(empty — shows everything)".to_string(),
                    Style::new().fg(theme::MUTED),
                )
            } else {
                ("Match", summary, Style::new().fg(theme::OK))
            }
        }
    };

    vec![
        Line::default(),
        Line::from(vec![
            Span::styled(format!("  {label:<6}"), Style::new().fg(theme::MUTED)),
            Span::styled(body, style),
        ]),
    ]
}

fn hint_line(builder: &Builder) -> Line<'static> {
    let mut hints = vec![("↑↓", "field")];
    if builder.focused().is_text() {
        hints.push(("ctrl+p", "pick from traffic"));
    } else {
        hints.push(("←→", "change"));
    }
    hints.push(("enter", "apply"));
    hints.push(("esc", "cancel"));

    let mut spans = Vec::new();
    for (key, label) in hints {
        spans.push(Span::styled(
            format!("  {key} "),
            Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(label, Style::new().fg(theme::MUTED)));
    }
    Line::from(spans)
}

/// Puts the terminal caret where the user is typing, so text entry behaves
/// like the other prompts.
fn place_cursor(frame: &mut Frame, builder: &Builder, fields_area: Rect) {
    if !builder.focused().is_text() || builder.picker.is_some() {
        return;
    }
    let row = FIELDS
        .iter()
        .position(|&f| f == builder.focused())
        .unwrap_or(0) as u16;
    let column = 4 + LABEL_WIDTH + builder.input.cursor_chars();

    if let Ok(column) = u16::try_from(column)
        && column < fields_area.width
        && row < fields_area.height
    {
        frame.set_cursor_position((fields_area.x + column, fields_area.y + row));
    }
}

fn draw_picker(frame: &mut Frame, app: &mut App) {
    let Some(builder) = app.builder.as_mut() else {
        return;
    };
    let Some(picker) = builder.picker.as_mut() else {
        return;
    };

    let title = match picker.field {
        Field::Source => "Sources seen",
        Field::Destination => "Destinations seen",
        Field::Port => "Ports seen",
        _ => "Values seen",
    };

    let rows = picker.values.len().clamp(1, 14) as u16;
    let area = super::centered(frame.area(), 46, rows + 2);
    super::clear_and_render(frame, area);

    let block = super::block(title, true);

    if picker.values.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("Nothing captured yet — type a value instead.")
                .style(Style::new().fg(theme::MUTED))
                .wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }

    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = picker
        .values
        .iter()
        .map(|(value, count)| {
            let count = super::human_count(*count);
            let gap = width.saturating_sub(value.chars().count() + count.chars().count());
            ListItem::new(Line::from(vec![
                Span::styled(value.clone(), Style::new().fg(theme::TEXT)),
                Span::raw(" ".repeat(gap)),
                Span::styled(count, Style::new().fg(theme::MUTED)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::new()
                .bg(theme::SELECTION)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌");

    frame.render_stateful_widget(list, area, &mut picker.state);
}
