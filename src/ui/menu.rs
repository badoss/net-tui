//! Opening menu.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme;
use crate::app::{App, MENU_ITEMS};

const HINTS: &[(&str, &str)] = &[
    ("↑/↓", "select"),
    ("enter", "open"),
    ("1-2", "jump"),
    ("?", "help"),
    ("q", "quit"),
];

pub fn draw(frame: &mut Frame, app: &App) {
    let [body, footer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());

    // Two lines per entry plus a blank between, inside the border.
    let height = (MENU_ITEMS.len() * 3 + 2) as u16;
    let area = super::centered(body, 76, height);

    let block = super::block("net-tui", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::with_capacity(MENU_ITEMS.len() * 3);
    for (index, item) in MENU_ITEMS.iter().enumerate() {
        let selected = index == app.menu_index;
        lines.push(Line::from(vec![
            Span::styled(
                if selected { "  ▌ " } else { "    " },
                Style::new().fg(theme::ACCENT),
            ),
            Span::styled(
                format!("{}  ", index + 1),
                Style::new().fg(theme::MUTED).add_modifier(Modifier::DIM),
            ),
            Span::styled(
                item.title().to_string(),
                if selected {
                    Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(theme::TEXT)
                },
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("       {}", item.description()),
            Style::new().fg(theme::MUTED),
        )));
        lines.push(Line::default());
    }

    frame.render_widget(Paragraph::new(lines), inner);
    super::draw_footer(frame, app, footer, HINTS);
}
