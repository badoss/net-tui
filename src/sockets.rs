//! What is listening on this machine, read straight from `/proc`.
//!
//! No dependencies: the four `/proc/net/{tcp,tcp6,udp,udp6}` tables give the
//! sockets, `/proc/*/fd` maps a socket inode to the process holding it, and
//! `/etc/passwd` turns a uid into a name. Parsing is kept free of filesystem
//! access so it can be tested anywhere, while the reading is Linux-only.
//!
//! Off Linux only the parsing compiles in, exercised by the tests rather than
//! by `collect`, so its helpers would otherwise read as dead code.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP state values as printed by the kernel.
const TCP_LISTEN: u8 = 0x0A;
const TCP_ESTABLISHED: u8 = 0x01;

/// Longest command line kept, so one pathological process cannot dominate.
const MAX_COMMAND_LEN: usize = 160;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn label(self, ipv6: bool) -> &'static str {
        match (self, ipv6) {
            (Self::Tcp, false) => "tcp",
            (Self::Tcp, true) => "tcp6",
            (Self::Udp, false) => "udp",
            (Self::Udp, true) => "udp6",
        }
    }
}

/// How far a bound socket can be reached from. This is the question netstat
/// makes you work out yourself, so it is ranked and shown as a column.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Exposure {
    /// Loopback only: nothing outside this machine can connect.
    Local,
    /// One specific address, so only the network on that interface.
    Interface,
    /// Every address — anything that can route here can connect.
    Everywhere,
}

impl Exposure {
    fn of(addr: IpAddr) -> Self {
        if addr.is_unspecified() {
            Self::Everywhere
        } else if addr.is_loopback() {
            Self::Local
        } else {
            Self::Interface
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local only",
            Self::Interface => "this network",
            Self::Everywhere => "anywhere",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Listener {
    pub transport: Transport,
    pub ipv6: bool,
    pub addr: IpAddr,
    pub port: u16,
    pub exposure: Exposure,
    /// Well-known name for the port, when there is one.
    pub service: Option<&'static str>,
    pub pid: Option<u32>,
    /// Short process name from `/proc/<pid>/comm`.
    pub process: Option<String>,
    /// Full command line, which usually says far more than the process name.
    pub command: Option<String>,
    pub user: Option<String>,
    pub uid: u32,
    /// Established connections currently on this port.
    pub connections: usize,
    /// Lowercased haystack for the screen's filter.
    search: String,
}

impl Listener {
    pub fn matches(&self, query: &str) -> bool {
        query
            .split_whitespace()
            .all(|term| match term.strip_prefix('!') {
                Some("") => true,
                Some(negated) => !self.search.contains(negated),
                None => self.search.contains(term),
            })
    }

    /// What to show in the "process" column, preferring the command line.
    pub fn describe_process(&self) -> String {
        match (&self.command, &self.process, self.pid) {
            (Some(command), _, Some(pid)) => format!("{command}  ({pid})"),
            (None, Some(name), Some(pid)) => format!("{name}  ({pid})"),
            (None, None, Some(pid)) => format!("pid {pid}"),
            // Without privileges the socket's owner cannot be identified.
            _ => "—".to_string(),
        }
    }
}

/// One row of a `/proc/net/*` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    state: u8,
    uid: u32,
    inode: u64,
}

/// Parses a `/proc/net/{tcp,udp}[6]` table. Unknown or short lines are skipped
/// rather than failing the whole read: the format has gained trailing columns
/// over the years and may gain more.
fn parse_table(text: &str, ipv6: bool) -> Vec<Row> {
    text.lines()
        .skip(1) // header
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _sl = fields.next()?;
            let local = parse_endpoint(fields.next()?, ipv6)?;
            let remote = parse_endpoint(fields.next()?, ipv6)?;
            let state = u8::from_str_radix(fields.next()?, 16).ok()?;
            // tx_queue:rx_queue, tr:tm->when, retrnsmt
            let _ = fields.next()?;
            let _ = fields.next()?;
            let _ = fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            let _timeout = fields.next()?;
            let inode = fields.next()?.parse().ok()?;
            Some(Row {
                local,
                remote,
                state,
                uid,
                inode,
            })
        })
        .collect()
}

/// `ADDRESS:PORT` where both sides are hex and the address words are written
/// little-endian, e.g. `0100007F:2328` is 127.0.0.1:9000.
fn parse_endpoint(field: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let addr = if ipv6 {
        if addr.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for (word, chunk) in addr.as_bytes().chunks(8).enumerate() {
            let text = std::str::from_utf8(chunk).ok()?;
            let value = u32::from_str_radix(text, 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        if addr.len() != 8 {
            return None;
        }
        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr, 16).ok()?.to_le_bytes(),
        ))
    };
    Some((addr, port))
}

/// True for a socket that is accepting or receiving rather than connected out.
/// TCP says so explicitly; UDP has no listen state, so a socket with no peer is
/// the closest equivalent.
fn is_bound_for_input(row: &Row, transport: Transport) -> bool {
    match transport {
        Transport::Tcp => row.state == TCP_LISTEN,
        Transport::Udp => row.remote.1 == 0,
    }
}

fn build_search(listener: &Listener) -> String {
    let mut key = String::with_capacity(128);
    key.push_str(listener.transport.label(listener.ipv6));
    let _ = write!(key, " {} {}", listener.addr, listener.port);
    if let Some(service) = listener.service {
        let _ = write!(key, " {service}");
    }
    if let Some(process) = &listener.process {
        let _ = write!(key, " {process}");
    }
    if let Some(command) = &listener.command {
        let _ = write!(key, " {command}");
    }
    if let Some(user) = &listener.user {
        let _ = write!(key, " {user}");
    }
    let _ = write!(key, " {}", listener.exposure.label());
    key.make_ascii_lowercase();
    key
}

/// Sorts the most exposed, then the most connected, then by port, so whatever
/// is most worth noticing is at the top.
fn sort_listeners(listeners: &mut [Listener]) {
    listeners.sort_by(|a, b| {
        b.exposure
            .cmp(&a.exposure)
            .then_with(|| b.connections.cmp(&a.connections))
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.transport.label(a.ipv6).cmp(b.transport.label(b.ipv6)))
    });
}

#[cfg(target_os = "linux")]
pub fn collect() -> Result<Vec<Listener>, String> {
    use std::fs;

    let tables = [
        ("/proc/net/tcp", Transport::Tcp, false),
        ("/proc/net/tcp6", Transport::Tcp, true),
        ("/proc/net/udp", Transport::Udp, false),
        ("/proc/net/udp6", Transport::Udp, true),
    ];

    let mut bound: Vec<(Row, Transport, bool)> = Vec::new();
    let mut established_ports: HashMap<u16, usize> = HashMap::new();
    let mut read_any = false;

    for (path, transport, ipv6) in tables {
        // A missing table just means the protocol is unavailable, e.g. IPv6
        // disabled — not a reason to fail.
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        read_any = true;
        for row in parse_table(&text, ipv6) {
            if is_bound_for_input(&row, transport) {
                bound.push((row, transport, ipv6));
            } else if transport == Transport::Tcp && row.state == TCP_ESTABLISHED {
                *established_ports.entry(row.local.1).or_default() += 1;
            }
        }
    }

    if !read_any {
        return Err("cannot read /proc/net — is /proc mounted?".to_string());
    }

    let wanted: HashSet<u64> = bound.iter().map(|(row, ..)| row.inode).collect();
    let owners = socket_owners(&wanted);
    let users = passwd_names();

    let mut listeners: Vec<Listener> = bound
        .into_iter()
        .map(|(row, transport, ipv6)| {
            let (addr, port) = row.local;
            let pid = owners.get(&row.inode).copied();
            let mut listener = Listener {
                transport,
                ipv6,
                addr,
                port,
                exposure: Exposure::of(addr),
                service: crate::packet::service_for_port(port),
                pid,
                process: pid.and_then(process_name),
                command: pid.and_then(process_command),
                user: users.get(&row.uid).cloned(),
                uid: row.uid,
                connections: established_ports.get(&port).copied().unwrap_or(0),
                search: String::new(),
            };
            listener.search = build_search(&listener);
            listener
        })
        .collect();

    sort_listeners(&mut listeners);
    Ok(listeners)
}

#[cfg(not(target_os = "linux"))]
pub fn collect() -> Result<Vec<Listener>, String> {
    Err(format!(
        "Listing listening sockets needs /proc, which {} does not have.\n\
         This screen works on Linux; packet capture works here as usual.",
        std::env::consts::OS
    ))
}

/// Maps socket inodes to the pid holding them by walking `/proc/*/fd`.
///
/// Without privileges only this user's processes are readable, so some sockets
/// end up unattributed. That is reported as a dash rather than an error.
#[cfg(target_os = "linux")]
fn socket_owners(wanted: &HashSet<u64>) -> HashMap<u64, u32> {
    use std::fs;

    let mut found = HashMap::with_capacity(wanted.len());
    if wanted.is_empty() {
        return found;
    }

    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };

    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = parse_socket_link(&target.to_string_lossy())
                && wanted.contains(&inode)
            {
                found.insert(inode, pid);
                // Stop as soon as every socket is attributed; on a busy host
                // this saves most of the readlink calls.
                if found.len() == wanted.len() {
                    return found;
                }
            }
        }
    }
    found
}

/// `socket:[1038868]` -> `1038868`.
fn parse_socket_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn process_name(pid: u32) -> Option<String> {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(target_os = "linux")]
fn process_command(pid: u32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    Some(format_cmdline(&raw)).filter(|command| !command.is_empty())
}

/// `/proc/<pid>/cmdline` separates arguments with NULs and may end with one.
fn format_cmdline(raw: &str) -> String {
    let mut command = raw
        .split('\0')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if command.chars().count() > MAX_COMMAND_LEN {
        command = command.chars().take(MAX_COMMAND_LEN - 1).collect();
        command.push('…');
    }
    command
}

#[cfg(target_os = "linux")]
fn passwd_names() -> HashMap<u32, String> {
    let Ok(text) = std::fs::read_to_string("/etc/passwd") else {
        return HashMap::new();
    };
    parse_passwd(&text)
}

fn parse_passwd(text: &str) -> HashMap<u32, String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let uid: u32 = fields.next()?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from a Debian container running two http.server instances, one
    /// bound to 0.0.0.0:8080 and one to 127.0.0.1:9000.
    const TCP_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1035988 1 0000000038cb3731 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1038868 1 000000002380aa1f 100 0 0 10 0
";

    #[test]
    fn hex_endpoints_decode_little_endian() {
        assert_eq!(
            parse_endpoint("0100007F:2328", false),
            Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000))
        );
        assert_eq!(
            parse_endpoint("00000000:1F90", false),
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080))
        );
        assert_eq!(
            parse_endpoint("00000000000000000000000000000000:0050", true),
            Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80))
        );
        assert_eq!(
            parse_endpoint("00000000000000000000000001000000:0016", true),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 22))
        );
    }

    #[test]
    fn malformed_endpoints_are_rejected_rather_than_guessed() {
        assert_eq!(parse_endpoint("0100007F", false), None);
        assert_eq!(parse_endpoint("zzzzzzzz:2328", false), None);
        assert_eq!(parse_endpoint("0100007:2328", false), None, "too short");
        assert_eq!(parse_endpoint("0100007F:2328", true), None, "not 32 chars");
    }

    #[test]
    fn a_real_proc_net_tcp_table_parses() {
        let rows = parse_table(TCP_SAMPLE, false);
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].local.1, 9000);
        assert_eq!(rows[0].state, TCP_LISTEN);
        assert_eq!(rows[0].uid, 0);
        assert_eq!(rows[0].inode, 1_035_988);

        assert_eq!(rows[1].local, (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080));
        assert_eq!(rows[1].inode, 1_038_868);
    }

    #[test]
    fn an_empty_table_with_only_a_header_yields_nothing() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        assert!(parse_table(header, true).is_empty());
    }

    #[test]
    fn exposure_ranks_wide_binds_above_loopback() {
        assert_eq!(
            Exposure::of(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Exposure::Everywhere
        );
        assert_eq!(
            Exposure::of(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Exposure::Local
        );
        assert_eq!(
            Exposure::of(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Exposure::Interface
        );
        assert_eq!(
            Exposure::of(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Exposure::Everywhere
        );
        assert_eq!(
            Exposure::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Exposure::Local
        );
        assert!(Exposure::Everywhere > Exposure::Interface);
        assert!(Exposure::Interface > Exposure::Local);
    }

    #[test]
    fn udp_counts_as_bound_only_without_a_peer() {
        let mut row = parse_table(TCP_SAMPLE, false)[0];
        row.state = 0x07; // UDP sockets report CLOSE
        assert!(is_bound_for_input(&row, Transport::Udp));
        row.remote.1 = 53;
        assert!(!is_bound_for_input(&row, Transport::Udp));
    }

    #[test]
    fn tcp_counts_as_bound_only_in_listen() {
        let mut row = parse_table(TCP_SAMPLE, false)[0];
        assert!(is_bound_for_input(&row, Transport::Tcp));
        row.state = TCP_ESTABLISHED;
        assert!(!is_bound_for_input(&row, Transport::Tcp));
    }

    #[test]
    fn socket_links_are_recognised() {
        assert_eq!(parse_socket_link("socket:[1038868]"), Some(1_038_868));
        assert_eq!(parse_socket_link("/dev/null"), None);
        assert_eq!(parse_socket_link("socket:[]"), None);
        assert_eq!(parse_socket_link("anon_inode:[eventpoll]"), None);
    }

    #[test]
    fn cmdline_nul_separators_become_spaces() {
        assert_eq!(
            format_cmdline("python3\0-m\0http.server\08080\0"),
            "python3 -m http.server 8080"
        );
        assert_eq!(format_cmdline(""), "");
        let long = format_cmdline(&"x".repeat(500));
        assert_eq!(long.chars().count(), MAX_COMMAND_LEN);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn passwd_maps_uids_to_names() {
        let users = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             bad-line\n",
        );
        assert_eq!(users.get(&0).map(String::as_str), Some("root"));
        assert_eq!(users.get(&1).map(String::as_str), Some("daemon"));
        assert_eq!(users.len(), 2, "the malformed line must be skipped");
    }

    fn listener(port: u16, addr: IpAddr, connections: usize) -> Listener {
        let mut l = Listener {
            transport: Transport::Tcp,
            ipv6: false,
            addr,
            port,
            exposure: Exposure::of(addr),
            service: crate::packet::service_for_port(port),
            pid: Some(1),
            process: Some("thing".to_string()),
            command: Some("thing --serve".to_string()),
            user: Some("root".to_string()),
            uid: 0,
            connections,
            search: String::new(),
        };
        l.search = build_search(&l);
        l
    }

    #[test]
    fn the_most_exposed_socket_sorts_first() {
        let mut listeners = vec![
            listener(9000, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            listener(8080, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 0),
            listener(443, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 2),
            listener(22, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7),
        ];
        sort_listeners(&mut listeners);
        let order: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        // Wide binds first, busiest of those first, loopback last.
        assert_eq!(order, [22, 443, 8080, 9000]);
    }

    #[test]
    fn the_filter_searches_service_process_and_exposure() {
        let l = listener(443, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(l.matches(""));
        assert!(l.matches("https"), "well-known service name");
        assert!(l.matches("anywhere"), "exposure wording");
        assert!(l.matches("thing"));
        assert!(l.matches("443 tcp"));
        assert!(!l.matches("nginx"));
        assert!(l.matches("!nginx"));
        assert!(!l.matches("https !443"));
    }

    #[test]
    fn a_process_without_a_readable_owner_still_describes_itself() {
        let mut l = listener(22, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(l.describe_process().contains("thing --serve"));
        l.command = None;
        assert!(l.describe_process().contains("thing"));
        l.process = None;
        assert_eq!(l.describe_process(), "pid 1");
        l.pid = None;
        assert_eq!(l.describe_process(), "—");
    }
}
