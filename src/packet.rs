//! Decoding of raw capture bytes into the record the UI renders and filters on.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Local, TimeZone};
use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap::Linktype;

/// Per-packet cap on the bytes retained for the hex view. Bounds worst-case
/// memory to `MAX_STORED_BYTES * <ring capacity>`.
pub const MAX_STORED_BYTES: usize = 4096;

/// Allowance for a packet's two owned strings, `info` and `search`. The longest
/// summary the decoder produces is a TCP line with every flag and counter,
/// which lands near 90 characters; `search` adds the endpoints and MACs on top.
const STRING_ALLOWANCE: usize = 256;

/// Worst-case heap footprint of one retained packet, used to size the ring
/// against a memory budget. Derived from the type rather than written down, so
/// it cannot drift as fields are added.
pub const WORST_CASE_PACKET_BYTES: usize =
    size_of::<Packet>() + MAX_STORED_BYTES + STRING_ALLOWANCE;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Other,
}

pub const ALL_PROTOS: [Proto; 5] = [
    Proto::Tcp,
    Proto::Udp,
    Proto::Icmp,
    Proto::Arp,
    Proto::Other,
];

impl Proto {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Arp => "ARP",
            Self::Other => "OTHER",
        }
    }

    /// Key that toggles this protocol in the monitor view.
    pub const fn hotkey(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Udp => 'u',
            Self::Icmp => 'i',
            Self::Arp => 'a',
            Self::Other => 'o',
        }
    }
}

/// One end of a conversation. `ip` is absent for non-IP traffic, in which case
/// the MAC is what gets displayed.
#[derive(Clone, Copy, Default)]
pub struct Endpoint {
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub mac: Option<[u8; 6]>,
}

impl Endpoint {
    fn write_to(&self, out: &mut String) {
        match (self.ip, self.mac) {
            (Some(ip), _) => {
                if ip.is_ipv6() {
                    let _ = write!(out, "[{ip}]");
                } else {
                    let _ = write!(out, "{ip}");
                }
            }
            (None, Some(mac)) => out.push_str(&format_mac(&mac)),
            (None, None) => out.push('?'),
        }
        if let Some(port) = self.port {
            let _ = write!(out, ":{port}");
        }
    }

    pub fn display(&self) -> String {
        let mut s = String::with_capacity(24);
        self.write_to(&mut s);
        s
    }
}

#[derive(Clone)]
pub struct Packet {
    /// Monotonic capture sequence number, starting at 1.
    pub no: u64,
    pub ts: DateTime<Local>,
    /// Length on the wire, which may exceed the bytes actually captured.
    pub wire_len: u32,
    pub cap_len: u32,
    pub proto: Proto,
    pub src: Endpoint,
    pub dst: Endpoint,
    /// Protocol summary shown in the table's rightmost column.
    pub info: String,
    /// Lowercased concatenation of every displayed field, so the display filter
    /// is a single substring test instead of a per-frame re-format.
    search: String,
    pub linktype: Linktype,
    pub bytes: Vec<u8>,
}

impl Packet {
    /// Minimal packet for tests that only exercise buffering and filtering.
    #[cfg(test)]
    pub(crate) fn for_test(no: u64, proto: Proto, search: &str) -> Self {
        Self {
            no,
            ts: Local::now(),
            wire_len: 64,
            cap_len: 64,
            proto,
            src: Endpoint::default(),
            dst: Endpoint::default(),
            info: String::new(),
            search: search.to_string(),
            linktype: Linktype::ETHERNET,
            bytes: vec![0; 64],
        }
    }

    /// True when every whitespace-separated term in `query` matches. A term
    /// prefixed with `!` must *not* appear. `query` must already be lowercase.
    pub fn matches(&self, query: &str) -> bool {
        query
            .split_whitespace()
            .all(|term| match term.strip_prefix('!') {
                Some("") => true,
                Some(neg) => !self.search.contains(neg),
                None => self.search.contains(term),
            })
    }
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Splits raw link-layer bytes according to the capture's link type.
///
/// `DLT_NULL`/`DLT_LOOP` (loopback and utun devices on macOS) prefix a 4-byte
/// address family that carries no information we display, so it is skipped and
/// the IP version nibble drives the rest of the decode.
pub fn slice_packet(bytes: &[u8], linktype: Linktype) -> Option<SlicedPacket<'_>> {
    if linktype == Linktype::ETHERNET || linktype == Linktype::ETHERNET_MPACKET {
        SlicedPacket::from_ethernet(bytes).ok()
    } else if linktype == Linktype::NULL || linktype == Linktype::LOOP {
        bytes.get(4..).and_then(|ip| SlicedPacket::from_ip(ip).ok())
    } else if linktype == Linktype::RAW || linktype == Linktype::IPV4 {
        SlicedPacket::from_ip(bytes).ok()
    } else if linktype == Linktype::LINUX_SLL {
        SlicedPacket::from_linux_sll(bytes).ok()
    } else {
        SlicedPacket::from_ethernet(bytes)
            .ok()
            .or_else(|| SlicedPacket::from_ip(bytes).ok())
    }
}

pub fn decode(no: u64, header: &pcap::PacketHeader, data: &[u8], linktype: Linktype) -> Packet {
    // `timeval` field widths vary by platform, so convert rather than cast.
    let micros = u32::try_from(header.ts.tv_usec).unwrap_or(0);
    let ts = Local
        .timestamp_opt(header.ts.tv_sec as _, micros.saturating_mul(1_000))
        .single()
        .unwrap_or_else(Local::now);

    let mut pkt = Packet {
        no,
        ts,
        wire_len: header.len,
        cap_len: header.caplen,
        proto: Proto::Other,
        src: Endpoint::default(),
        dst: Endpoint::default(),
        info: String::new(),
        search: String::new(),
        linktype,
        bytes: data[..data.len().min(MAX_STORED_BYTES)].to_vec(),
    };

    match slice_packet(data, linktype) {
        Some(sliced) => fill_from_slice(&mut pkt, &sliced),
        None => pkt.info = format!("Undecoded {} bytes", data.len()),
    }

    pkt.search = build_search_key(&pkt);
    pkt
}

fn fill_from_slice(pkt: &mut Packet, sliced: &SlicedPacket<'_>) {
    if let Some(LinkSlice::Ethernet2(eth)) = &sliced.link {
        pkt.src.mac = Some(eth.source());
        pkt.dst.mac = Some(eth.destination());
    }

    match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            pkt.src.ip = Some(IpAddr::V4(ip.header().source_addr()));
            pkt.dst.ip = Some(IpAddr::V4(ip.header().destination_addr()));
        }
        Some(NetSlice::Ipv6(ip)) => {
            pkt.src.ip = Some(IpAddr::V6(ip.header().source_addr()));
            pkt.dst.ip = Some(IpAddr::V6(ip.header().destination_addr()));
        }
        Some(NetSlice::Arp(arp)) => {
            pkt.proto = Proto::Arp;
            pkt.src.ip = ip_from_bytes(arp.sender_protocol_addr());
            pkt.dst.ip = ip_from_bytes(arp.target_protocol_addr());
            pkt.info = describe_arp(arp);
            return;
        }
        None => {}
    }

    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            pkt.proto = Proto::Tcp;
            pkt.src.port = Some(tcp.source_port());
            pkt.dst.port = Some(tcp.destination_port());
            pkt.info = describe_tcp(tcp);
        }
        Some(TransportSlice::Udp(udp)) => {
            pkt.proto = Proto::Udp;
            pkt.src.port = Some(udp.source_port());
            pkt.dst.port = Some(udp.destination_port());
            let payload = udp.length().saturating_sub(8);
            pkt.info = match service_name(udp.source_port(), udp.destination_port()) {
                Some(svc) => format!("{svc}  Len={payload}"),
                None => format!("Len={payload}"),
            };
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            pkt.proto = Proto::Icmp;
            pkt.info = describe_icmpv4(icmp.type_u8(), icmp.code_u8());
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            pkt.proto = Proto::Icmp;
            pkt.info = describe_icmpv6(icmp.type_u8(), icmp.code_u8());
        }
        Some(TransportSlice::Igmp(_)) => {
            pkt.proto = Proto::Other;
            pkt.info = "IGMP".to_string();
        }
        None => {
            if pkt.info.is_empty() {
                pkt.info = match &sliced.net {
                    Some(NetSlice::Ipv4(ip)) => {
                        format!("IPv4 proto={}", ip.payload_ip_number().0)
                    }
                    Some(NetSlice::Ipv6(ip)) => {
                        format!("IPv6 next={}", ip.header().next_header().0)
                    }
                    _ => describe_link(sliced),
                };
            }
        }
    }
}

fn describe_link(sliced: &SlicedPacket<'_>) -> String {
    match &sliced.link {
        Some(LinkSlice::Ethernet2(eth)) => {
            format!("Ethernet ethertype=0x{:04x}", eth.ether_type().0)
        }
        _ => "Non-IP frame".to_string(),
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn describe_arp(arp: &etherparse::ArpPacketSlice<'_>) -> String {
    let sender_ip = ip_from_bytes(arp.sender_protocol_addr());
    let target_ip = ip_from_bytes(arp.target_protocol_addr());
    let sender_hw = arp.sender_hw_addr();

    match arp.operation() {
        etherparse::ArpOperation::REQUEST => match (target_ip, sender_ip) {
            (Some(t), Some(s)) => format!("Who has {t}?  Tell {s}"),
            _ => "ARP request".to_string(),
        },
        etherparse::ArpOperation::REPLY => match sender_ip {
            Some(s) if sender_hw.len() == 6 => {
                let mac: [u8; 6] = sender_hw.try_into().unwrap_or_default();
                format!("{s} is at {}", format_mac(&mac))
            }
            Some(s) => format!("{s} is at ?"),
            None => "ARP reply".to_string(),
        },
        other => format!("ARP opcode={}", other.0),
    }
}

fn describe_tcp(tcp: &etherparse::TcpSlice<'_>) -> String {
    let mut flags = String::with_capacity(24);
    for (set, name) in [
        (tcp.syn(), "SYN"),
        (tcp.ack(), "ACK"),
        (tcp.psh(), "PSH"),
        (tcp.fin(), "FIN"),
        (tcp.rst(), "RST"),
        (tcp.urg(), "URG"),
        (tcp.ece(), "ECE"),
        (tcp.cwr(), "CWR"),
    ] {
        if set {
            if !flags.is_empty() {
                flags.push_str(", ");
            }
            flags.push_str(name);
        }
    }
    if flags.is_empty() {
        flags.push_str("NONE");
    }

    let payload_len = tcp.payload().len();
    let mut info = format!("[{flags}]");
    if let Some(svc) = service_name(tcp.source_port(), tcp.destination_port()) {
        let _ = write!(info, " {svc}");
    }
    let _ = write!(info, "  Seq={}", tcp.sequence_number());
    if tcp.ack() {
        let _ = write!(info, " Ack={}", tcp.acknowledgment_number());
    }
    let _ = write!(info, " Win={} Len={payload_len}", tcp.window_size());
    info
}

fn describe_icmpv4(ty: u8, code: u8) -> String {
    let name = match (ty, code) {
        (0, _) => "Echo reply",
        (3, 0) => "Destination net unreachable",
        (3, 1) => "Destination host unreachable",
        (3, 3) => "Destination port unreachable",
        (3, 4) => "Fragmentation needed",
        (3, _) => "Destination unreachable",
        (5, _) => "Redirect",
        (8, _) => "Echo request",
        (11, 0) => "TTL exceeded in transit",
        (11, _) => "Time exceeded",
        _ => return format!("ICMP type={ty} code={code}"),
    };
    format!("{name}  (type={ty} code={code})")
}

fn describe_icmpv6(ty: u8, code: u8) -> String {
    let name = match ty {
        1 => "Destination unreachable",
        2 => "Packet too big",
        3 => "Time exceeded",
        128 => "Echo request",
        129 => "Echo reply",
        133 => "Router solicitation",
        134 => "Router advertisement",
        135 => "Neighbor solicitation",
        136 => "Neighbor advertisement",
        _ => return format!("ICMPv6 type={ty} code={code}"),
    };
    format!("{name}  (type={ty} code={code})")
}

/// Well-known ports worth naming in the summary column. Deliberately short —
/// the point is to make common traffic scannable, not to mirror /etc/services.
const SERVICES: &[(u16, &str)] = &[
    (20, "FTP-DATA"),
    (21, "FTP"),
    (22, "SSH"),
    (23, "TELNET"),
    (25, "SMTP"),
    (53, "DNS"),
    (67, "DHCP"),
    (68, "DHCP"),
    (69, "TFTP"),
    (80, "HTTP"),
    (110, "POP3"),
    (123, "NTP"),
    (137, "NETBIOS"),
    (143, "IMAP"),
    (161, "SNMP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (500, "ISAKMP"),
    (514, "SYSLOG"),
    (587, "SMTP"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1194, "OPENVPN"),
    (1433, "MSSQL"),
    (1521, "ORACLE"),
    (3306, "MYSQL"),
    (3389, "RDP"),
    (5353, "MDNS"),
    (5432, "POSTGRES"),
    (5672, "AMQP"),
    (6379, "REDIS"),
    (8080, "HTTP-ALT"),
    (8443, "HTTPS-ALT"),
    (9200, "ELASTIC"),
    (27017, "MONGODB"),
];

fn lookup_service(port: u16) -> Option<&'static str> {
    SERVICES
        .binary_search_by_key(&port, |(p, _)| *p)
        .ok()
        .map(|i| SERVICES[i].1)
}

/// Names the conversation after whichever side is the well-known port. When
/// both are known the lower port wins, since that is conventionally the server.
fn service_name(src: u16, dst: u16) -> Option<&'static str> {
    match (lookup_service(src), lookup_service(dst)) {
        (Some(a), Some(b)) => Some(if src <= dst { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn build_search_key(pkt: &Packet) -> String {
    let mut key = String::with_capacity(96);
    key.push_str(pkt.proto.label());
    key.push(' ');
    pkt.src.write_to(&mut key);
    key.push(' ');
    pkt.dst.write_to(&mut key);
    if let Some(mac) = pkt.src.mac {
        key.push(' ');
        key.push_str(&format_mac(&mac));
    }
    if let Some(mac) = pkt.dst.mac {
        key.push(' ');
        key.push_str(&format_mac(&mac));
    }
    key.push(' ');
    key.push_str(&pkt.info);
    key.make_ascii_lowercase();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_table_is_sorted_for_binary_search() {
        assert!(SERVICES.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn lower_port_wins_when_both_sides_are_well_known() {
        assert_eq!(service_name(443, 80), Some("HTTP"));
        assert_eq!(service_name(80, 443), Some("HTTP"));
        assert_eq!(service_name(51000, 443), Some("HTTPS"));
        assert_eq!(service_name(51000, 51001), None);
    }

    fn probe(search: &str) -> Packet {
        Packet {
            no: 1,
            ts: Local::now(),
            wire_len: 0,
            cap_len: 0,
            proto: Proto::Tcp,
            src: Endpoint::default(),
            dst: Endpoint::default(),
            info: String::new(),
            search: search.to_string(),
            linktype: Linktype::ETHERNET,
            bytes: Vec::new(),
        }
    }

    #[test]
    fn display_filter_ands_terms_and_honours_negation() {
        let pkt = probe("tcp 192.168.1.5:443 10.0.0.2:51234 [syn, ack]");
        assert!(pkt.matches(""));
        assert!(pkt.matches("tcp 443"));
        assert!(pkt.matches("tcp !udp"));
        assert!(!pkt.matches("tcp !443"));
        assert!(!pkt.matches("udp"));
        // A bare "!" is not a filter; it should not exclude everything.
        assert!(pkt.matches("!"));
    }

    #[test]
    fn endpoint_brackets_ipv6_so_the_port_stays_readable() {
        let ep = Endpoint {
            ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: Some(443),
            mac: None,
        };
        assert_eq!(ep.display(), "[::1]:443");
    }

    #[test]
    fn endpoint_falls_back_to_mac_for_non_ip_frames() {
        let ep = Endpoint {
            ip: None,
            port: None,
            mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        };
        assert_eq!(ep.display(), "de:ad:be:ef:00:01");
    }
}
