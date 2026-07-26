//! Structured traffic selector: source, destination, protocol and port.
//!
//! One spec drives two very different mechanisms. Compiled to BPF it becomes a
//! capture filter the kernel applies before packets are copied to userspace;
//! evaluated directly it becomes a display filter over packets already held in
//! the ring. The two are deliberately not identical — see [`FilterSpec::to_bpf`].

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::packet::{Packet, Proto};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PortSide {
    #[default]
    Either,
    Source,
    Destination,
}

impl PortSide {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Either => "either",
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Either => Self::Source,
            Self::Source => Self::Destination,
            Self::Destination => Self::Either,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Either => Self::Destination,
            Self::Source => Self::Either,
            Self::Destination => Self::Source,
        }
    }
}

/// Where an applied spec takes effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FilterTarget {
    /// Compiled to BPF and pushed into libpcap. Discards traffic before it is
    /// copied, so it is the only option that prevents drops — but changing it
    /// restarts the capture and clears the buffer.
    #[default]
    Capture,
    /// Evaluated against the packets already captured. Instant and reversible.
    Display,
}

impl FilterTarget {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Capture => "capture (BPF, restarts)",
            Self::Display => "display (instant)",
        }
    }

    pub const fn toggled(self) -> Self {
        match self {
            Self::Capture => Self::Display,
            Self::Display => Self::Capture,
        }
    }
}

/// Empty fields mean "any". A spec where every field is empty matches
/// everything and compiles to an empty BPF program.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct FilterSpec {
    pub source: String,
    pub destination: String,
    pub protocol: Option<Proto>,
    pub port: String,
    pub port_side: PortSide,
}

impl FilterSpec {
    pub fn is_empty(&self) -> bool {
        self.source.trim().is_empty()
            && self.destination.trim().is_empty()
            && self.protocol.is_none()
            && self.port.trim().is_empty()
    }

    /// Compiles to a tcpdump-syntax expression.
    ///
    /// Host fields must be literal IP addresses. libpcap would happily accept a
    /// hostname and resolve it, but that resolution happens synchronously while
    /// compiling, which would stall the UI on a slow or unreachable DNS server.
    /// Hostnames remain available through the raw BPF prompt.
    pub fn to_bpf(&self) -> Result<String, String> {
        let mut parts: Vec<String> = Vec::new();

        for (value, keyword, label) in [
            (self.source.trim(), "src host", "Source"),
            (self.destination.trim(), "dst host", "Destination"),
        ] {
            if value.is_empty() {
                continue;
            }
            if value.parse::<IpAddr>().is_err() {
                return Err(format!(
                    "{label} must be an IP address for a capture filter (got \"{value}\"). \
                     Use the display target for partial matches, or the f prompt for hostnames."
                ));
            }
            parts.push(format!("{keyword} {value}"));
        }

        if let Some(proto) = self.protocol {
            parts.push(bpf_protocol(proto).to_string());
        }

        let port = self.port.trim();
        if !port.is_empty() {
            let number = port
                .parse::<u16>()
                .map_err(|_| format!("Port must be a number from 0 to 65535 (got \"{port}\")"))?;
            // ARP and ICMP have no ports, so libpcap rejects the combination.
            // Catching it here explains why, instead of surfacing a bare
            // "syntax error" from the compiler.
            if matches!(self.protocol, Some(Proto::Arp | Proto::Icmp)) {
                return Err(format!(
                    "{} has no ports — clear the port, or change the protocol.",
                    self.protocol.expect("matched above").label()
                ));
            }
            parts.push(match self.port_side {
                PortSide::Either => format!("port {number}"),
                PortSide::Source => format!("src port {number}"),
                PortSide::Destination => format!("dst port {number}"),
            });
        }

        Ok(parts.join(" and "))
    }

    /// Evaluates the spec against an already-captured packet.
    ///
    /// Host fields accept a partial address here: anything that is not a valid
    /// IP is matched as a substring, so `10.0.` selects a subnet.
    pub fn matches(&self, pkt: &Packet) -> bool {
        if let Some(proto) = self.protocol
            && pkt.proto != proto
        {
            return false;
        }

        if !host_matches(self.source.trim(), pkt.src.ip) {
            return false;
        }
        if !host_matches(self.destination.trim(), pkt.dst.ip) {
            return false;
        }

        let port = self.port.trim();
        if !port.is_empty() {
            let Ok(number) = port.parse::<u16>() else {
                // An in-progress number should not blank the table.
                return true;
            };
            let matched = match self.port_side {
                PortSide::Either => pkt.src.port == Some(number) || pkt.dst.port == Some(number),
                PortSide::Source => pkt.src.port == Some(number),
                PortSide::Destination => pkt.dst.port == Some(number),
            };
            if !matched {
                return false;
            }
        }

        true
    }

    /// One-line rendering of the active constraints, for the status bar.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        let mut push = |text: String| {
            if !out.is_empty() {
                out.push_str(" · ");
            }
            out.push_str(&text);
        };

        if !self.source.trim().is_empty() {
            push(format!("src {}", self.source.trim()));
        }
        if !self.destination.trim().is_empty() {
            push(format!("dst {}", self.destination.trim()));
        }
        if let Some(proto) = self.protocol {
            push(proto.label().to_string());
        }
        if !self.port.trim().is_empty() {
            let side = match self.port_side {
                PortSide::Either => "port",
                PortSide::Source => "src port",
                PortSide::Destination => "dst port",
            };
            push(format!("{side} {}", self.port.trim()));
        }
        out
    }
}

fn host_matches(pattern: &str, addr: Option<IpAddr>) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let Some(addr) = addr else {
        return false;
    };
    match pattern.parse::<IpAddr>() {
        Ok(exact) => addr == exact,
        Err(_) => {
            let mut rendered = String::with_capacity(46);
            let _ = write!(rendered, "{addr}");
            rendered.contains(pattern)
        }
    }
}

const fn bpf_protocol(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => "icmp or icmp6",
        Proto::Arp => "arp",
        // "Other" is defined by what it is not, so exclude the named ones.
        Proto::Other => "not tcp and not udp and not icmp and not icmp6 and not arp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Endpoint;

    fn spec(source: &str, destination: &str, protocol: Option<Proto>, port: &str) -> FilterSpec {
        FilterSpec {
            source: source.to_string(),
            destination: destination.to_string(),
            protocol,
            port: port.to_string(),
            port_side: PortSide::Either,
        }
    }

    fn packet(
        src: &str,
        sport: Option<u16>,
        dst: &str,
        dport: Option<u16>,
        proto: Proto,
    ) -> Packet {
        let mut pkt = Packet::for_test(1, proto, "");
        pkt.src = Endpoint {
            ip: Some(src.parse().unwrap()),
            port: sport,
            mac: None,
        };
        pkt.dst = Endpoint {
            ip: Some(dst.parse().unwrap()),
            port: dport,
            mac: None,
        };
        pkt
    }

    #[test]
    fn an_empty_spec_compiles_to_an_empty_program() {
        assert_eq!(FilterSpec::default().to_bpf().unwrap(), "");
        assert!(FilterSpec::default().is_empty());
    }

    #[test]
    fn fields_are_joined_with_and_in_tcpdump_syntax() {
        let built = spec("10.0.0.1", "1.1.1.1", Some(Proto::Tcp), "443")
            .to_bpf()
            .unwrap();
        assert_eq!(
            built,
            "src host 10.0.0.1 and dst host 1.1.1.1 and tcp and port 443"
        );
    }

    #[test]
    fn port_side_selects_the_bpf_qualifier() {
        let mut s = spec("", "", None, "53");
        s.port_side = PortSide::Source;
        assert_eq!(s.to_bpf().unwrap(), "src port 53");
        s.port_side = PortSide::Destination;
        assert_eq!(s.to_bpf().unwrap(), "dst port 53");
    }

    #[test]
    fn hostnames_are_refused_for_capture_filters() {
        let err = spec("github.com", "", None, "").to_bpf().unwrap_err();
        assert!(err.contains("must be an IP address"), "{err}");
    }

    #[test]
    fn a_port_on_a_portless_protocol_is_explained_not_passed_to_libpcap() {
        let err = spec("", "", Some(Proto::Arp), "80").to_bpf().unwrap_err();
        assert!(err.contains("no ports"), "{err}");
        let err = spec("", "", Some(Proto::Icmp), "80").to_bpf().unwrap_err();
        assert!(err.contains("no ports"), "{err}");
    }

    #[test]
    fn a_non_numeric_port_is_rejected_before_compiling() {
        let err = spec("", "", None, "https").to_bpf().unwrap_err();
        assert!(err.contains("must be a number"), "{err}");
    }

    #[test]
    fn display_matching_requires_every_set_field() {
        let pkt = packet("10.0.0.5", Some(51820), "1.1.1.1", Some(443), Proto::Tcp);

        assert!(spec("", "", None, "").matches(&pkt));
        assert!(spec("10.0.0.5", "", None, "").matches(&pkt));
        assert!(spec("10.0.0.5", "1.1.1.1", Some(Proto::Tcp), "443").matches(&pkt));
        assert!(!spec("10.0.0.6", "", None, "").matches(&pkt));
        assert!(!spec("", "", Some(Proto::Udp), "").matches(&pkt));
        assert!(!spec("", "", None, "80").matches(&pkt));
    }

    #[test]
    fn a_partial_host_matches_a_subnet_on_the_display_side() {
        let pkt = packet("10.0.0.5", Some(1), "192.168.1.9", Some(2), Proto::Udp);
        assert!(spec("10.0.", "", None, "").matches(&pkt));
        assert!(spec("", "192.168.", None, "").matches(&pkt));
        assert!(!spec("10.1.", "", None, "").matches(&pkt));
    }

    #[test]
    fn a_half_typed_port_keeps_the_table_visible() {
        let pkt = packet("10.0.0.5", Some(51820), "1.1.1.1", Some(443), Proto::Tcp);
        // "4" is a valid u16 that matches nothing; "4x" is mid-edit and must
        // not blank the view.
        assert!(!spec("", "", None, "4").matches(&pkt));
        assert!(spec("", "", None, "4x").matches(&pkt));
    }

    #[test]
    fn port_side_narrows_display_matching_to_one_direction() {
        let pkt = packet("10.0.0.5", Some(51820), "1.1.1.1", Some(443), Proto::Tcp);
        let mut s = spec("", "", None, "443");
        s.port_side = PortSide::Destination;
        assert!(s.matches(&pkt));
        s.port_side = PortSide::Source;
        assert!(!s.matches(&pkt));
    }

    #[test]
    fn summary_lists_only_the_constrained_fields() {
        assert_eq!(FilterSpec::default().summary(), "");
        let mut s = spec("10.0.0.1", "", Some(Proto::Tcp), "443");
        s.port_side = PortSide::Destination;
        assert_eq!(s.summary(), "src 10.0.0.1 · TCP · dst port 443");
    }
}
