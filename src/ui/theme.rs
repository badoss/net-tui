//! Shared palette. Truecolor values with readable fallbacks on dark terminals.

use ratatui::style::Color;

use crate::packet::Proto;

pub const ACCENT: Color = Color::Rgb(122, 162, 247);
pub const OK: Color = Color::Rgb(158, 206, 106);
pub const WARN: Color = Color::Rgb(224, 175, 104);
pub const ERROR: Color = Color::Rgb(247, 118, 142);
pub const MUTED: Color = Color::Rgb(105, 114, 145);
pub const BORDER: Color = Color::Rgb(65, 72, 104);
pub const TEXT: Color = Color::Rgb(192, 202, 245);
pub const SELECTION: Color = Color::Rgb(41, 51, 86);

pub const fn proto_color(proto: Proto) -> Color {
    match proto {
        Proto::Tcp => Color::Rgb(125, 207, 255),
        Proto::Udp => OK,
        Proto::Icmp => Color::Rgb(187, 154, 247),
        Proto::Arp => WARN,
        Proto::Other => MUTED,
    }
}
