//! Detail pane: decoded header fields beside a hex dump of the captured bytes.

use std::fmt::Write as _;

use etherparse::{LinkSlice, NetSlice, TransportSlice};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme;
use crate::app::{App, Focus};
use crate::packet::{MAX_STORED_BYTES, Packet, format_mac, slice_packet};

/// Columns needed to render 16 bytes per row: offset, hex, gutter, ASCII.
const WIDE_HEX_COLUMNS: u16 = 6 + 16 * 3 + 1 + 2 + 16;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Detail;
    let block = super::block("Detail  ·  tab to focus, ↑/↓ to scroll", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(pkt) = app.selected_packet() else {
        frame.render_widget(
            Paragraph::new("Select a packet to inspect it.").style(Style::new().fg(theme::MUTED)),
            inner,
        );
        return;
    };

    let [fields_area, hex_area] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)])
            .spacing(1)
            .areas(inner);

    let scroll = (app.detail_scroll, 0);
    frame.render_widget(Paragraph::new(field_lines(pkt)).scroll(scroll), fields_area);

    let per_line = if hex_area.width >= WIDE_HEX_COLUMNS {
        16
    } else {
        8
    };
    frame.render_widget(
        Paragraph::new(hex_lines(&pkt.bytes, per_line)).scroll(scroll),
        hex_area,
    );
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
    ))
}

fn field(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<16}"), Style::new().fg(theme::MUTED)),
        Span::styled(value.into(), Style::new().fg(theme::TEXT)),
    ])
}

fn field_lines(pkt: &Packet) -> Vec<Line<'static>> {
    let mut lines = vec![section("Frame")];
    lines.push(field("Number", pkt.no.to_string()));
    lines.push(field(
        "Captured",
        pkt.ts.format("%Y-%m-%d %H:%M:%S%.6f %z").to_string(),
    ));
    lines.push(field("Wire length", format!("{} bytes", pkt.wire_len)));
    lines.push(field("Captured len", format!("{} bytes", pkt.cap_len)));
    if pkt.cap_len as usize > pkt.bytes.len() {
        lines.push(field(
            "Stored",
            format!(
                "{} bytes (truncated to {MAX_STORED_BYTES})",
                pkt.bytes.len()
            ),
        ));
    }
    lines.push(field(
        "Link type",
        pkt.linktype
            .get_name()
            .unwrap_or_else(|_| format!("DLT {}", pkt.linktype.0)),
    ));

    let Some(sliced) = slice_packet(&pkt.bytes, pkt.linktype) else {
        lines.push(Line::default());
        lines.push(section("Payload"));
        lines.push(field("Decode", "not recognised at this link type"));
        return lines;
    };

    if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
        lines.push(Line::default());
        lines.push(section("Ethernet II"));
        lines.push(field("Source", format_mac(&eth.source())));
        lines.push(field("Destination", format_mac(&eth.destination())));
        lines.push(field("EtherType", format!("0x{:04x}", eth.ether_type().0)));
    }

    match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let header = ip.header();
            lines.push(Line::default());
            lines.push(section("IPv4"));
            lines.push(field("Source", header.source_addr().to_string()));
            lines.push(field("Destination", header.destination_addr().to_string()));
            lines.push(field("TTL", header.ttl().to_string()));
            lines.push(field("Protocol", header.protocol().0.to_string()));
            lines.push(field("Total length", header.total_len().to_string()));
            lines.push(field("Identification", header.identification().to_string()));
            let mut flags = Vec::new();
            if header.dont_fragment() {
                flags.push("DF");
            }
            if header.more_fragments() {
                flags.push("MF");
            }
            lines.push(field(
                "Flags",
                if flags.is_empty() {
                    "none".to_string()
                } else {
                    flags.join(", ")
                },
            ));
        }
        Some(NetSlice::Ipv6(ip)) => {
            let header = ip.header();
            lines.push(Line::default());
            lines.push(section("IPv6"));
            lines.push(field("Source", header.source_addr().to_string()));
            lines.push(field("Destination", header.destination_addr().to_string()));
            lines.push(field("Hop limit", header.hop_limit().to_string()));
            lines.push(field("Next header", header.next_header().0.to_string()));
            lines.push(field("Payload length", header.payload_length().to_string()));
        }
        Some(NetSlice::Arp(arp)) => {
            lines.push(Line::default());
            lines.push(section("ARP"));
            lines.push(field("Operation", arp.operation().0.to_string()));
            lines.push(field("Sender HW", hex_join(arp.sender_hw_addr())));
            lines.push(field("Sender proto", dotted(arp.sender_protocol_addr())));
            lines.push(field("Target HW", hex_join(arp.target_hw_addr())));
            lines.push(field("Target proto", dotted(arp.target_protocol_addr())));
        }
        None => {}
    }

    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            lines.push(Line::default());
            lines.push(section("TCP"));
            lines.push(field("Source port", tcp.source_port().to_string()));
            lines.push(field("Dest port", tcp.destination_port().to_string()));
            lines.push(field("Sequence", tcp.sequence_number().to_string()));
            lines.push(field(
                "Acknowledgment",
                tcp.acknowledgment_number().to_string(),
            ));
            lines.push(field("Window", tcp.window_size().to_string()));
            lines.push(field("Checksum", format!("0x{:04x}", tcp.checksum())));
            lines.push(field(
                "Header length",
                format!("{} bytes", tcp.data_offset() as usize * 4),
            ));
            lines.push(field("Payload", format!("{} bytes", tcp.payload().len())));
            lines.push(field("Flags", pkt.info.clone()));
        }
        Some(TransportSlice::Udp(udp)) => {
            lines.push(Line::default());
            lines.push(section("UDP"));
            lines.push(field("Source port", udp.source_port().to_string()));
            lines.push(field("Dest port", udp.destination_port().to_string()));
            lines.push(field("Length", udp.length().to_string()));
            lines.push(field("Checksum", format!("0x{:04x}", udp.checksum())));
            lines.push(field("Payload", format!("{} bytes", udp.payload().len())));
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            lines.push(Line::default());
            lines.push(section("ICMPv4"));
            lines.push(field("Type", icmp.type_u8().to_string()));
            lines.push(field("Code", icmp.code_u8().to_string()));
            lines.push(field("Checksum", format!("0x{:04x}", icmp.checksum())));
            lines.push(field("Payload", format!("{} bytes", icmp.payload().len())));
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            lines.push(Line::default());
            lines.push(section("ICMPv6"));
            lines.push(field("Type", icmp.type_u8().to_string()));
            lines.push(field("Code", icmp.code_u8().to_string()));
            lines.push(field("Payload", format!("{} bytes", icmp.payload().len())));
        }
        Some(TransportSlice::Igmp(_)) | None => {}
    }

    lines
}

fn hex_join(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02x}");
    }
    if out.is_empty() {
        out.push('—');
    }
    out
}

fn dotted(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        _ => hex_join(bytes),
    }
}

fn hex_lines(bytes: &[u8], per_line: usize) -> Vec<Line<'static>> {
    if bytes.is_empty() {
        return vec![Line::from(Span::styled(
            "no bytes captured",
            Style::new().fg(theme::MUTED),
        ))];
    }

    bytes
        .chunks(per_line)
        .enumerate()
        .map(|(row, chunk)| {
            let mut hex = String::with_capacity(per_line * 3 + 1);
            for (i, byte) in chunk.iter().enumerate() {
                // Extra gap at the halfway point keeps long rows scannable.
                if i > 0 && i % 8 == 0 {
                    hex.push(' ');
                }
                let _ = write!(hex, "{byte:02x} ");
            }
            let padding =
                (per_line - chunk.len()) * 3 + usize::from(chunk.len() <= 8 && per_line > 8);
            for _ in 0..padding {
                hex.push(' ');
            }

            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            Line::from(vec![
                Span::styled(
                    format!("{:04x}  ", row * per_line),
                    Style::new().fg(theme::MUTED),
                ),
                Span::styled(hex, Style::new().fg(theme::TEXT)),
                Span::styled(" ", Style::new()),
                Span::styled(ascii, Style::new().fg(theme::ACCENT)),
            ])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_pads_the_short_final_row_so_ascii_stays_aligned() {
        let lines = hex_lines(&[0x41, 0x42, 0x43], 16);
        assert_eq!(lines.len(), 1);
        let rendered: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(rendered.starts_with("0000  41 42 43 "), "{rendered:?}");
        assert!(rendered.ends_with("ABC"), "{rendered:?}");
    }

    #[test]
    fn non_printable_bytes_render_as_dots() {
        let lines = hex_lines(&[0x00, 0x7f, 0x41], 16);
        let rendered: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(rendered.ends_with("..A"), "{rendered:?}");
    }

    #[test]
    fn empty_payload_reports_instead_of_rendering_nothing() {
        let lines = hex_lines(&[], 16);
        assert_eq!(lines.len(), 1);
    }
}
