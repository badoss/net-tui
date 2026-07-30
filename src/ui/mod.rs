//! Rendering. One module per screen, plus widgets shared between them.

mod builder;
mod detail;
mod devices;
mod help;
mod menu;
mod monitor;
mod ports;
pub mod theme;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use crate::app::{App, Prompt, Screen};

pub fn draw(frame: &mut Frame, app: &mut App) {
    match app.screen {
        Screen::Menu => menu::draw(frame, app),
        Screen::Devices => devices::draw(frame, app),
        Screen::Monitor => monitor::draw(frame, app),
        Screen::Ports => ports::draw(frame, app),
    }
    // The builder sits above the screen but below help, so `?` is always
    // reachable and always readable.
    if app.builder.is_some() {
        builder::draw(frame, app);
    }
    if app.show_help {
        help::draw(frame, app.screen);
    }
}

/// Renders the footer: an active prompt takes precedence, then a toast, then
/// the key hints for the current screen.
fn draw_footer(frame: &mut Frame, app: &App, area: Rect, hints: &[(&str, &str)]) {
    if app.prompt != Prompt::None {
        let prefix = format!(" {}: ", app.prompt.title());
        let line = Line::from(vec![
            Span::styled(
                prefix.clone(),
                Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(app.input.value().to_string(), Style::new().fg(theme::TEXT)),
        ]);
        frame.render_widget(Paragraph::new(line), area);

        let caret = prefix.chars().count() + app.input.cursor_chars();
        if let Ok(offset) = u16::try_from(caret)
            && offset < area.width
        {
            frame.set_cursor_position((area.x + offset, area.y));
        }
        return;
    }

    if let Some(toast) = &app.toast {
        let color = if toast.is_error {
            theme::ERROR
        } else {
            theme::OK
        };
        // Toasts carry multi-line remediation text; the footer shows the first
        // line and the rest stays available in the help-free error panel.
        let first = toast.text.lines().next().unwrap_or_default();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ● ", Style::new().fg(color)),
                Span::styled(first.to_string(), Style::new().fg(color)),
            ])),
            area,
        );
        return;
    }

    frame.render_widget(Paragraph::new(hint_line(hints)), area);
}

fn hint_line(hints: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::with_capacity(hints.len() * 3);
    for (key, label) in hints {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            (*label).to_string(),
            Style::new().fg(theme::MUTED),
        ));
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        theme::ACCENT
    } else {
        theme::BORDER
    };
    Block::bordered()
        .border_style(Style::new().fg(border))
        .title_top(Span::styled(
            format!(" {title} "),
            Style::new()
                .fg(if focused { theme::ACCENT } else { theme::TEXT })
                .add_modifier(Modifier::BOLD),
        ))
}

/// Centers a fixed-size popup inside `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(row);
    cell
}

fn clear_and_render(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn human_count(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::app::Status;
    use crate::packet::{Endpoint, Packet, Proto};

    fn endpoint(ip: &str, port: Option<u16>) -> Endpoint {
        Endpoint {
            ip: Some(ip.parse::<IpAddr>().unwrap()),
            port,
            mac: None,
        }
    }

    fn sample_app() -> App {
        let mut app = App::new(1000, 65535, false);
        app.screen = Screen::Monitor;
        app.status = Status::Running;

        let flows = [
            (
                Proto::Tcp,
                "172.20.10.2",
                Some(51820),
                "142.250.66.78",
                Some(443),
                "[SYN] HTTPS  Seq=0 Win=65535 Len=0",
            ),
            (
                Proto::Tcp,
                "142.250.66.78",
                Some(443),
                "172.20.10.2",
                Some(51820),
                "[SYN, ACK] HTTPS  Seq=0 Ack=1 Win=65535 Len=0",
            ),
            (
                Proto::Udp,
                "172.20.10.2",
                Some(53124),
                "1.1.1.1",
                Some(53),
                "DNS  Len=41",
            ),
            // ICMP has no ports, so the endpoints render as bare addresses.
            (
                Proto::Icmp,
                "172.20.10.2",
                None,
                "8.8.8.8",
                None,
                "Echo request  (type=8 code=0)",
            ),
        ];

        for (i, (proto, src, sport, dst, dport, info)) in flows.into_iter().enumerate() {
            let mut pkt = Packet::for_test(
                i as u64 + 1,
                proto,
                &format!("{proto:?} {src} {dst} {info}").to_lowercase(),
            );
            pkt.src = endpoint(src, sport);
            pkt.dst = endpoint(dst, dport);
            pkt.info = info.to_string();
            pkt.wire_len = 74 + i as u32 * 20;
            app.push_for_test(pkt);
        }
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn press(app: &mut App, codes: &[KeyCode]) {
        for &code in codes {
            app.on_key(key(code));
        }
    }

    fn type_text(app: &mut App, text: &str) {
        for ch in text.chars() {
            app.on_key(key(KeyCode::Char(ch)));
        }
    }

    #[test]
    fn the_builder_opens_with_every_field_and_a_live_bpf_preview() {
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        type_text(&mut app, "172.20.10.2");

        let screen = render(&mut app, 110, 26);
        assert!(screen.contains("Filter builder"), "{screen}");
        for label in [
            "Source",
            "Destination",
            "Protocol",
            "Port",
            "Port side",
            "Apply to",
        ] {
            assert!(screen.contains(label), "missing {label} in {screen}");
        }
        assert!(screen.contains("src host 172.20.10.2"), "{screen}");
        assert!(screen.contains("capture (BPF, restarts)"), "{screen}");
    }

    #[test]
    fn applying_to_display_filters_the_table_without_restarting() {
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        // Port field, then a value, then switch the target to display.
        press(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Down]);
        type_text(&mut app, "53");
        press(
            &mut app,
            &[KeyCode::Down, KeyCode::Down, KeyCode::Right, KeyCode::Enter],
        );

        assert!(app.builder.is_none(), "applying should close the builder");
        assert_eq!(app.view_len(), 1);

        let screen = render(&mut app, 130, 22);
        assert!(screen.contains("where: port 53"), "{screen}");
        assert!(screen.contains("DNS  Len=41"), "{screen}");
        assert!(!screen.contains("[SYN, ACK]"), "{screen}");
    }

    #[test]
    fn applying_to_capture_sets_the_bpf_filter() {
        // Regression: validation used to call pcap_setfilter on a dead handle,
        // which libpcap refuses, so *every* apply to the capture target failed
        // with "A filter cannot be set on a pcap_open_dead pcap_t" and no
        // filter was ever installed.
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        type_text(&mut app, "58.8.7.80");
        press(&mut app, &[KeyCode::Enter]);

        assert!(
            app.builder.is_none(),
            "a valid spec should close the builder"
        );
        assert_eq!(app.bpf, "src host 58.8.7.80");
        assert_eq!(app.capture_spec.source, "58.8.7.80");
    }

    #[test]
    fn applying_to_capture_combines_every_field() {
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        type_text(&mut app, "58.8.7.80");
        press(&mut app, &[KeyCode::Down]);
        type_text(&mut app, "159.223.35.210");
        // Protocol -> TCP, then the port field.
        press(&mut app, &[KeyCode::Down, KeyCode::Right, KeyCode::Down]);
        type_text(&mut app, "22");
        press(&mut app, &[KeyCode::Enter]);

        assert!(
            app.builder.is_none(),
            "{:?}",
            app.toast.as_ref().map(|t| &t.text)
        );
        assert_eq!(
            app.bpf,
            "src host 58.8.7.80 and dst host 159.223.35.210 and tcp and port 22"
        );
    }

    #[test]
    fn an_impossible_capture_spec_keeps_the_builder_open_with_the_reason() {
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        type_text(&mut app, "not-an-ip");
        press(&mut app, &[KeyCode::Enter]);

        assert!(
            app.builder.is_some(),
            "a rejected spec must not close the builder"
        );
        assert_eq!(app.bpf, "", "the running capture filter must be untouched");
        let screen = render(&mut app, 110, 26);
        assert!(screen.contains("must be an IP address"), "{screen}");
    }

    #[test]
    fn the_picker_lists_addresses_actually_seen_with_their_counts() {
        let mut app = sample_app();
        press(&mut app, &[KeyCode::Char('F')]);
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));

        let screen = render(&mut app, 110, 26);
        assert!(screen.contains("Sources seen"), "{screen}");
        // 172.20.10.2 is the source of three of the four sample packets.
        assert!(screen.contains("172.20.10.2"), "{screen}");
        assert!(screen.contains("142.250.66.78"), "{screen}");

        press(&mut app, &[KeyCode::Enter]);
        assert!(app.builder.as_ref().unwrap().picker.is_none());
        assert_eq!(app.builder.as_ref().unwrap().spec.source, "172.20.10.2");
    }

    fn render(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn monitor_table_shows_each_captured_flow() {
        let mut app = sample_app();
        let screen = render(&mut app, 150, 22);

        assert!(screen.contains("172.20.10.2:51820"), "{screen}");
        assert!(screen.contains("142.250.66.78:443"), "{screen}");
        assert!(screen.contains("[SYN, ACK] HTTPS"), "{screen}");
        assert!(screen.contains("DNS  Len=41"), "{screen}");
        assert!(screen.contains("Echo request"), "{screen}");
        // ICMP endpoints carry no port, so no stray ":0" should appear.
        assert!(screen.contains("8.8.8.8  "), "{screen}");
        assert!(!screen.contains(":0 "), "{screen}");
        assert!(screen.contains("Packets  4/4"), "{screen}");
        assert!(screen.contains("LIVE"), "{screen}");
    }

    #[test]
    fn protocol_toggles_and_display_filter_narrow_the_table() {
        let mut app = sample_app();
        app.display_filter = "dns".to_string();
        app.rebuild_view_for_test();

        let screen = render(&mut app, 150, 22);
        assert!(screen.contains("DNS  Len=41"), "{screen}");
        assert!(!screen.contains("[SYN, ACK]"), "{screen}");
        assert!(screen.contains("Packets  1/4"), "{screen}");
        assert!(screen.contains("match: dns"), "{screen}");
    }

    #[test]
    fn detail_pane_decodes_the_selected_packet() {
        let mut app = sample_app();
        app.show_detail = true;
        let screen = render(&mut app, 150, 30);

        assert!(screen.contains("Frame"), "{screen}");
        assert!(screen.contains("Wire length"), "{screen}");
        // The synthetic bytes are all zero, so the hex pane should show them.
        assert!(screen.contains("00 00 00 00"), "{screen}");
    }

    #[test]
    fn an_empty_filtered_view_explains_itself_instead_of_going_blank() {
        let mut app = sample_app();
        app.display_filter = "nothing-matches-this".to_string();
        app.rebuild_view_for_test();

        let screen = render(&mut app, 150, 22);
        assert!(screen.contains("No packets match"), "{screen}");
    }

    #[test]
    fn byte_sizes_switch_units_at_1024() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3 / 2), "1.5 MB");
    }

    #[test]
    fn counts_stay_exact_below_ten_thousand() {
        assert_eq!(human_count(9_999), "9999");
        assert_eq!(human_count(12_345), "12.3k");
        assert_eq!(human_count(2_500_000), "2.5M");
    }
}
