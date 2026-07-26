//! Keybinding overlay.

use ratatui::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme;
use crate::app::Screen;

type Entry = (&'static str, &'static str);

const MONITOR_KEYS: &[Entry] = &[
    ("", "Navigation"),
    ("↑ ↓ / k j", "move selection"),
    ("PgUp PgDn", "move a page"),
    ("g / G", "first / newest packet"),
    ("space", "follow newest packet on/off"),
    ("tab", "switch focus between list and detail"),
    ("enter / d", "show or hide the detail pane"),
    ("", ""),
    ("", "Filtering"),
    ("F", "filter builder — source, destination, proto, port"),
    ("/", "display filter, applied as you type"),
    ("f", "capture filter in tcpdump (BPF) syntax"),
    ("t u i a o", "toggle TCP / UDP / ICMP / ARP / other"),
    ("n", "reset every filter"),
    ("", ""),
    ("", "Capture"),
    ("p", "freeze the list, keep counting traffic"),
    ("c", "clear the buffer"),
    ("w", "write displayed packets to a .pcap file"),
    ("ctrl+r", "restart capture on this interface"),
    ("esc", "back to the interface list"),
    ("q / ctrl+c", "quit"),
];

const DEVICE_KEYS: &[Entry] = &[
    ("", "Interfaces"),
    ("↑ ↓ / k j", "move selection"),
    ("enter", "start capturing"),
    ("/", "search by name, description or address"),
    ("F", "filter builder — source, destination, proto, port"),
    ("f", "set the capture filter before starting"),
    ("r", "rescan interfaces"),
    ("q / esc", "quit"),
];

const FILTER_HELP: &[Entry] = &[
    ("", "Filter builder (F)"),
    ("↑ ↓", "move between fields"),
    ("← →", "change protocol, port side, target"),
    ("ctrl+p", "pick a value seen in the capture"),
    ("enter", "apply · esc cancels"),
    ("", ""),
    ("", "Display filter"),
    ("dns", "substring match over every shown column"),
    ("tcp 443", "all terms must match"),
    ("!arp", "leading ! excludes"),
    ("", ""),
    ("", "Capture filter (BPF)"),
    ("tcp port 443", "compiled by libpcap, like tcpdump"),
    ("host 10.0.0.1", "changing it restarts the capture"),
    ("udp and not port 53", "invalid filters are rejected safely"),
];

pub fn draw(frame: &mut Frame, screen: Screen) {
    let keys = match screen {
        Screen::Devices => DEVICE_KEYS,
        Screen::Monitor => MONITOR_KEYS,
    };

    let mut lines: Vec<Line> = keys.iter().map(entry_line).collect();
    if screen == Screen::Monitor {
        lines.push(Line::default());
        lines.extend(FILTER_HELP.iter().map(entry_line));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "  press any key to close",
        Style::new().fg(theme::MUTED).add_modifier(Modifier::ITALIC),
    )));

    let width = 64;
    let height = lines.len() as u16 + 2;
    let area = super::centered(frame.area(), width, height);
    super::clear_and_render(frame, area);

    let block = super::block("Help", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), inner);
}

fn entry_line((key, description): &Entry) -> Line<'static> {
    if key.is_empty() {
        // A blank key marks a section heading, or a spacer when both are blank.
        return Line::from(Span::styled(
            format!(" {description}"),
            Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(vec![
        Span::styled(format!("  {key:<22}"), Style::new().fg(theme::WARN)),
        Span::styled((*description).to_string(), Style::new().fg(theme::TEXT)),
    ])
}
