//! Application state and key handling.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use chrono::Local;
use pcap::Linktype;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::{ListState, TableState};

use crate::builder::{self, Builder, Field, Picker};
use crate::capture::{CaptureConfig, CaptureEvent, CaptureHandle, DriverStats, validate_bpf};
use crate::filter::{FilterSpec, FilterTarget};
use crate::input::LineInput;
use crate::packet::{ALL_PROTOS, Packet, Proto};
use crate::sockets::{self, Listener};

/// Seconds of packets-per-second history kept for the header sparkline.
const HISTORY_LEN: usize = 120;

const TOAST_TTL: Duration = Duration::from_secs(4);

/// Upper bound on packets drained per frame, so a traffic burst cannot starve
/// input handling and redraws.
const DRAIN_BUDGET: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Entry point, unless an interface was named on the command line.
    Menu,
    Devices,
    Monitor,
    Ports,
}

/// What the opening menu offers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Capture,
    Ports,
}

pub const MENU_ITEMS: [MenuItem; 2] = [MenuItem::Capture, MenuItem::Ports];

impl MenuItem {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Capture => "Capture traffic",
            Self::Ports => "Ports and services",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Capture => "Watch live packets on an interface, with filters and a hex view",
            Self::Ports => "What is listening on this machine, and how exposed each port is",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Table,
    Detail,
}

/// Which prompt, if any, is consuming keystrokes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    None,
    DeviceSearch,
    Bpf,
    Display,
    SavePath,
    PortSearch,
}

impl Prompt {
    pub fn title(self) -> &'static str {
        match self {
            Self::None => "",
            Self::DeviceSearch => "Find interface",
            Self::Bpf => "Capture filter (BPF)",
            Self::Display => "Display filter",
            Self::SavePath => "Save displayed packets to",
            Self::PortSearch => "Find port, service or process",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Status {
    Idle,
    Starting,
    Running,
    Stopped,
    Error(String),
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Starting => "STARTING",
            Self::Running => "LIVE",
            Self::Stopped => "STOPPED",
            Self::Error(_) => "ERROR",
        }
    }
}

pub struct Toast {
    pub text: String,
    pub is_error: bool,
    created: Instant,
}

impl Toast {
    pub fn expired(&self) -> bool {
        self.created.elapsed() > TOAST_TTL
    }
}

pub struct DeviceEntry {
    pub name: String,
    pub desc: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub wireless: bool,
    search: String,
}

impl DeviceEntry {
    fn from(dev: pcap::Device) -> Self {
        let addresses: Vec<IpAddr> = dev.addresses.iter().map(|a| a.addr).collect();
        let mut search = format!("{} {}", dev.name, dev.desc.clone().unwrap_or_default());
        for addr in &addresses {
            search.push(' ');
            search.push_str(&addr.to_string());
        }
        search.make_ascii_lowercase();
        Self {
            up: dev.flags.is_up(),
            running: dev.flags.is_running(),
            loopback: dev.flags.is_loopback(),
            wireless: dev.flags.is_wireless(),
            name: dev.name,
            desc: dev.desc,
            addresses,
            search,
        }
    }

    /// Interfaces likely to be carrying traffic sort first, so the default
    /// selection is usually the one the user wants. A routable address is the
    /// strongest signal: link-local-only devices such as `awdl0` are up and
    /// running on macOS but are rarely what someone wants to watch.
    fn rank(&self) -> (bool, bool, bool, bool) {
        (
            self.addresses.iter().any(is_routable),
            !self.addresses.is_empty(),
            self.running,
            !self.loopback,
        )
    }
}

/// True for addresses that can carry traffic beyond this link.
fn is_routable(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            // `Ipv6Addr::is_unicast_link_local` is still unstable, so match
            // the fe80::/10 prefix directly.
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !v6.is_loopback() && !v6.is_unspecified() && !link_local
        }
    }
}

#[derive(Default)]
pub struct Counters {
    pub total: u64,
    pub bytes: u64,
    pub per_proto: [u64; ALL_PROTOS.len()],
    pub driver: DriverStats,
    pub ui_dropped: u64,
    pub pps: u64,
    pub bps: u64,
    pub history: VecDeque<u64>,
    second_packets: u64,
    second_bytes: u64,
    last_tick: Option<Instant>,
}

impl Counters {
    fn record(&mut self, pkt: &Packet) {
        self.total += 1;
        self.bytes += u64::from(pkt.wire_len);
        self.per_proto[proto_index(pkt.proto)] += 1;
        self.second_packets += 1;
        self.second_bytes += u64::from(pkt.wire_len);
    }

    fn tick(&mut self) {
        let last = *self.last_tick.get_or_insert_with(Instant::now);
        if last.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_tick = Some(Instant::now());
        self.pps = self.second_packets;
        self.bps = self.second_bytes;
        self.second_packets = 0;
        self.second_bytes = 0;
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(self.pps);
    }

    fn reset(&mut self) {
        let history = std::mem::take(&mut self.history);
        *self = Self {
            history,
            ..Self::default()
        };
    }
}

pub fn proto_index(proto: Proto) -> usize {
    match proto {
        Proto::Tcp => 0,
        Proto::Udp => 1,
        Proto::Icmp => 2,
        Proto::Arp => 3,
        Proto::Other => 4,
    }
}

pub struct App {
    pub screen: Screen,
    pub focus: Focus,
    pub prompt: Prompt,
    pub input: LineInput,
    pub should_quit: bool,
    pub show_help: bool,

    pub devices: Vec<DeviceEntry>,
    pub device_view: Vec<usize>,
    pub device_state: ListState,
    pub device_query: String,

    capture: Option<CaptureHandle>,
    pub status: Status,
    pub linktype: Linktype,
    pub bpf: String,
    pub snaplen: i32,
    pub promiscuous: bool,

    /// Ring of decoded packets, oldest first. `no` is contiguous across it.
    packets: VecDeque<Packet>,
    /// Packet numbers passing the display filter, in capture order.
    view: VecDeque<u64>,
    pub capacity: usize,
    pub table_state: TableState,
    /// First view row rendered. Owned here rather than by `TableState` because
    /// the table is only handed the on-screen window of rows.
    pub table_offset: usize,

    pub display_filter: String,
    /// Structured selector applied to packets already in the ring.
    pub display_spec: FilterSpec,
    /// Structured selector that produced the active `bpf` string.
    pub capture_spec: FilterSpec,
    /// The filter builder, present only while it is open.
    pub builder: Option<Builder>,
    pub proto_enabled: [bool; ALL_PROTOS.len()],
    pub follow: bool,
    pub paused: bool,
    pub show_detail: bool,
    pub detail_scroll: u16,

    /// Listening sockets, refreshed on demand rather than per frame — reading
    /// them walks every process's file descriptors.
    pub listeners: Vec<Listener>,
    pub listeners_error: Option<String>,
    pub ports_view: Vec<usize>,
    pub ports_state: TableState,
    pub ports_query: String,
    pub ports_height: usize,
    pub menu_index: usize,

    pub counters: Counters,
    pub toast: Option<Toast>,
    /// Rows the packet table last rendered, used for page-sized movement.
    pub table_height: usize,
}

impl App {
    pub fn new(capacity: usize, snaplen: i32, promiscuous: bool) -> Self {
        let mut app = Self {
            screen: Screen::Menu,
            focus: Focus::Table,
            prompt: Prompt::None,
            input: LineInput::default(),
            should_quit: false,
            show_help: false,
            devices: Vec::new(),
            device_view: Vec::new(),
            device_state: ListState::default(),
            device_query: String::new(),
            capture: None,
            status: Status::Idle,
            linktype: Linktype::ETHERNET,
            bpf: String::new(),
            snaplen,
            promiscuous,
            packets: VecDeque::new(),
            view: VecDeque::new(),
            capacity,
            table_state: TableState::default(),
            table_offset: 0,
            display_filter: String::new(),
            display_spec: FilterSpec::default(),
            capture_spec: FilterSpec::default(),
            builder: None,
            proto_enabled: [true; ALL_PROTOS.len()],
            follow: true,
            paused: false,
            show_detail: false,
            detail_scroll: 0,
            listeners: Vec::new(),
            listeners_error: None,
            ports_view: Vec::new(),
            ports_state: TableState::default(),
            ports_query: String::new(),
            ports_height: 1,
            menu_index: 0,
            counters: Counters::default(),
            toast: None,
            table_height: 1,
        };
        app.refresh_devices();
        app
    }

    // ---- devices -------------------------------------------------------

    pub fn refresh_devices(&mut self) {
        match pcap::Device::list() {
            Ok(list) => {
                let mut entries: Vec<DeviceEntry> =
                    list.into_iter().map(DeviceEntry::from).collect();
                entries.sort_by(|a, b| b.rank().cmp(&a.rank()).then_with(|| a.name.cmp(&b.name)));
                self.devices = entries;
                self.rebuild_device_view();
            }
            Err(err) => self.error(format!("Cannot list interfaces: {err}")),
        }
    }

    fn rebuild_device_view(&mut self) {
        let query = self.device_query.to_lowercase();
        self.device_view = self
            .devices
            .iter()
            .enumerate()
            .filter(|(_, d)| query.is_empty() || d.search.contains(&query))
            .map(|(i, _)| i)
            .collect();

        let selected = match self.device_view.len() {
            0 => None,
            len => Some(self.device_state.selected().unwrap_or(0).min(len - 1)),
        };
        self.device_state.select(selected);
    }

    pub fn selected_device(&self) -> Option<&DeviceEntry> {
        let row = self.device_state.selected()?;
        self.device_view.get(row).map(|&i| &self.devices[i])
    }

    /// Selects `name` in the device list and begins capturing on it.
    pub fn start_on_named_device(&mut self, name: &str) {
        match self.devices.iter().position(|d| d.name == name) {
            Some(index) => {
                if let Some(row) = self.device_view.iter().position(|&i| i == index) {
                    self.device_state.select(Some(row));
                }
                self.start_capture(name.to_string());
            }
            None => self.error(format!("Interface '{name}' not found")),
        }
    }

    // ---- capture lifecycle ---------------------------------------------

    pub fn device_name(&self) -> Option<&str> {
        self.capture.as_ref().map(|c| c.config().device.as_str())
    }

    fn start_capture(&mut self, device: String) {
        self.stop_capture();
        self.clear_packets();
        self.counters.reset();

        let mut config = CaptureConfig::new(device);
        config.bpf = self.bpf.clone();
        config.snaplen = self.snaplen;
        config.promiscuous = self.promiscuous;

        self.capture = Some(CaptureHandle::spawn(config));
        self.status = Status::Starting;
        self.screen = Screen::Monitor;
        self.focus = Focus::Table;
    }

    fn stop_capture(&mut self) {
        if let Some(mut handle) = self.capture.take() {
            handle.stop();
        }
    }

    fn restart_capture(&mut self) {
        match self.device_name().map(str::to_string) {
            Some(device) => self.start_capture(device),
            None => self.error("No interface selected".to_string()),
        }
    }

    // ---- packet buffer --------------------------------------------------

    pub fn packets_len(&self) -> usize {
        self.packets.len()
    }

    pub fn view_len(&self) -> usize {
        self.view.len()
    }

    /// Packets are numbered contiguously from the front of the ring, so a
    /// packet number maps to an index in constant time.
    fn index_of(&self, no: u64) -> Option<usize> {
        let first = self.packets.front()?.no;
        let index = usize::try_from(no.checked_sub(first)?).ok()?;
        (index < self.packets.len()).then_some(index)
    }

    fn packet_by_no(&self, no: u64) -> Option<&Packet> {
        self.index_of(no).and_then(|i| self.packets.get(i))
    }

    /// Visible packets in display order.
    pub fn visible(&self) -> impl Iterator<Item = &Packet> {
        self.view.iter().filter_map(|&no| self.packet_by_no(no))
    }

    pub fn visible_at(&self, row: usize) -> Option<&Packet> {
        self.view.get(row).and_then(|&no| self.packet_by_no(no))
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        self.table_state.selected().and_then(|r| self.visible_at(r))
    }

    fn passes(&self, pkt: &Packet) -> bool {
        self.proto_enabled[proto_index(pkt.proto)]
            && self.display_spec.matches(pkt)
            && pkt.matches(&self.display_filter)
    }

    fn push_packet(&mut self, pkt: Packet) {
        if self.packets.len() == self.capacity
            && let Some(evicted) = self.packets.pop_front()
            && self.view.front() == Some(&evicted.no)
        {
            self.view.pop_front();
            // Every view row shifted down by one; keep the cursor on the same
            // packet rather than letting it drift up the list.
            if let Some(row) = self.table_state.selected() {
                self.table_state.select(Some(row.saturating_sub(1)));
            }
        }

        let no = pkt.no;
        let visible = self.passes(&pkt);
        self.packets.push_back(pkt);
        if visible {
            self.view.push_back(no);
        }
        if self.follow {
            self.select_last();
        }
    }

    /// Feeds a packet through the normal buffering path.
    #[cfg(test)]
    pub(crate) fn push_for_test(&mut self, pkt: Packet) {
        self.counters.record(&pkt);
        self.push_packet(pkt);
    }

    #[cfg(test)]
    pub(crate) fn rebuild_view_for_test(&mut self) {
        self.rebuild_view();
    }

    fn rebuild_view(&mut self) {
        let anchor = self.selected_packet().map(|p| p.no);
        let rebuilt: VecDeque<u64> = self
            .packets
            .iter()
            .filter(|p| self.passes(p))
            .map(|p| p.no)
            .collect();
        self.view = rebuilt;

        if self.follow {
            self.select_last();
            return;
        }
        // Keep the cursor on the anchored packet if it survived the filter,
        // otherwise on the next visible packet after it.
        let row = anchor.and_then(|no| {
            self.view
                .iter()
                .position(|&v| v >= no)
                .or_else(|| self.view.len().checked_sub(1))
        });
        self.table_state
            .select(row.filter(|_| !self.view.is_empty()));
    }

    fn clear_packets(&mut self) {
        self.packets.clear();
        self.view.clear();
        self.table_state.select(None);
        self.detail_scroll = 0;
    }

    // ---- event pump ------------------------------------------------------

    /// Moves capture events into app state. Called once per frame.
    pub fn drain_capture(&mut self) {
        let mut budget = DRAIN_BUDGET;
        while budget > 0 {
            let Some(capture) = self.capture.as_ref() else {
                break;
            };
            match capture.try_recv() {
                Ok(CaptureEvent::Started { linktype }) => {
                    self.linktype = linktype;
                    self.status = Status::Running;
                }
                Ok(CaptureEvent::Packet(pkt)) => {
                    self.counters.record(&pkt);
                    // While paused the rates keep updating but the list is
                    // frozen, so what is on screen stays inspectable.
                    if !self.paused {
                        self.push_packet(*pkt);
                    }
                    budget -= 1;
                }
                Ok(CaptureEvent::Stats(stats)) => self.counters.driver = stats,
                Ok(CaptureEvent::Error(message)) => {
                    self.status = Status::Error(message.clone());
                    self.error(message);
                }
                Ok(CaptureEvent::Stopped) => {
                    if !matches!(self.status, Status::Error(_)) {
                        self.status = Status::Stopped;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if let Some(capture) = self.capture.as_ref() {
            self.counters.ui_dropped = capture.ui_dropped();
        }
        self.counters.tick();
        if self.toast.as_ref().is_some_and(Toast::expired) {
            self.toast = None;
        }
    }

    // ---- feedback --------------------------------------------------------

    /// Surfaces a startup message in the footer. Set before any capture starts,
    /// so a failure to open the requested interface still takes precedence.
    pub fn notice(&mut self, text: String) {
        self.info(text);
    }

    fn info(&mut self, text: String) {
        self.toast = Some(Toast {
            text,
            is_error: false,
            created: Instant::now(),
        });
    }

    fn error(&mut self, text: String) {
        self.toast = Some(Toast {
            text,
            is_error: true,
            created: Instant::now(),
        });
    }

    // ---- movement --------------------------------------------------------

    fn select_last(&mut self) {
        let last = self.view.len().checked_sub(1);
        self.table_state.select(last);
    }

    fn move_selection(&mut self, delta: isize) {
        if self.view.is_empty() {
            self.table_state.select(None);
            return;
        }
        let last = self.view.len() - 1;
        let current = self.table_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, last as isize) as usize;
        self.table_state.select(Some(next));
        // Moving off the newest packet means the user wants to read history.
        self.follow = next == last;
        self.detail_scroll = 0;
    }

    fn scroll_detail(&mut self, delta: i32) {
        let next = i32::from(self.detail_scroll) + delta;
        self.detail_scroll = next.max(0).min(u16::MAX.into()) as u16;
    }

    // ---- key handling ----------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }

        if self.builder.is_some() {
            self.on_builder_key(key);
            return;
        }

        if self.prompt != Prompt::None {
            self.on_prompt_key(key, ctrl);
            return;
        }

        if self.show_help {
            // Any key dismisses help, so it never traps the user.
            self.show_help = false;
            if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc) {
                return;
            }
        }

        match self.screen {
            Screen::Menu => self.on_menu_key(key),
            Screen::Devices => self.on_devices_key(key),
            Screen::Monitor => self.on_monitor_key(key, ctrl),
            Screen::Ports => self.on_ports_key(key),
        }
    }

    fn on_prompt_key(&mut self, key: KeyEvent, ctrl: bool) {
        match key.code {
            KeyCode::Esc => {
                // Abandoning the display filter must also undo its live effect.
                let prompt = self.prompt;
                self.prompt = Prompt::None;
                self.input.clear();
                if prompt == Prompt::Display && !self.display_filter.is_empty() {
                    self.display_filter.clear();
                    self.rebuild_view();
                }
                if prompt == Prompt::PortSearch && !self.ports_query.is_empty() {
                    self.ports_query.clear();
                    self.rebuild_ports_view();
                }
            }
            KeyCode::Enter => self.commit_prompt(),
            KeyCode::Backspace => {
                self.input.backspace();
                self.on_prompt_edit();
            }
            KeyCode::Delete => {
                self.input.delete();
                self.on_prompt_edit();
            }
            KeyCode::Left => self.input.left(),
            KeyCode::Right => self.input.right(),
            KeyCode::Home => self.input.home(),
            KeyCode::End => self.input.end(),
            KeyCode::Char('w') if ctrl => {
                self.input.delete_word();
                self.on_prompt_edit();
            }
            KeyCode::Char('u') if ctrl => {
                self.input.delete_to_start();
                self.on_prompt_edit();
            }
            KeyCode::Char(ch) if !ctrl => {
                self.input.insert(ch);
                self.on_prompt_edit();
            }
            _ => {}
        }
    }

    /// Prompts that can be applied without restarting capture update as the
    /// user types; the rest wait for Enter.
    fn on_prompt_edit(&mut self) {
        match self.prompt {
            Prompt::DeviceSearch => {
                self.device_query = self.input.value().to_string();
                self.rebuild_device_view();
            }
            Prompt::Display => {
                self.display_filter = self.input.value().to_lowercase();
                self.rebuild_view();
            }
            Prompt::PortSearch => {
                self.ports_query = self.input.value().to_string();
                self.rebuild_ports_view();
            }
            _ => {}
        }
    }

    fn commit_prompt(&mut self) {
        let value = self.input.value().to_string();
        let prompt = self.prompt;
        self.prompt = Prompt::None;
        self.input.clear();

        match prompt {
            Prompt::None => {}
            Prompt::DeviceSearch | Prompt::Display | Prompt::PortSearch => {}
            Prompt::Bpf => {
                // Compile first so a typo reports an error instead of killing
                // a working capture.
                match validate_bpf(self.linktype, &value) {
                    Ok(()) => {
                        self.bpf = value.trim().to_string();
                        if self.capture.is_some() {
                            self.restart_capture();
                        }
                    }
                    Err(message) => self.error(message),
                }
            }
            Prompt::SavePath => match self.save_pcap(&value) {
                Ok(count) => self.info(format!("Wrote {count} packets to {value}")),
                Err(err) => self.error(format!("Save failed: {err}")),
            },
        }
    }

    fn open_prompt(&mut self, prompt: Prompt, initial: &str) {
        self.prompt = prompt;
        self.input = LineInput::with_value(initial);
    }

    // ---- listening sockets -----------------------------------------------

    /// Re-reads `/proc`. Deliberately explicit rather than periodic: attributing
    /// sockets to processes walks every process's file descriptors, which is far
    /// too much work to repeat per frame.
    pub fn refresh_listeners(&mut self) {
        match sockets::collect() {
            Ok(listeners) => {
                self.listeners = listeners;
                self.listeners_error = None;
            }
            Err(message) => {
                self.listeners.clear();
                self.listeners_error = Some(message);
            }
        }
        self.rebuild_ports_view();
    }

    fn rebuild_ports_view(&mut self) {
        let query = self.ports_query.to_lowercase();
        self.ports_view = self
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, listener)| listener.matches(&query))
            .map(|(index, _)| index)
            .collect();

        let selected = match self.ports_view.len() {
            0 => None,
            len => Some(self.ports_state.selected().unwrap_or(0).min(len - 1)),
        };
        self.ports_state.select(selected);
    }

    pub fn selected_listener(&self) -> Option<&Listener> {
        let row = self.ports_state.selected()?;
        self.ports_view.get(row).map(|&i| &self.listeners[i])
    }

    pub fn listener_at(&self, row: usize) -> Option<&Listener> {
        self.ports_view.get(row).map(|&i| &self.listeners[i])
    }

    fn move_ports(&mut self, delta: isize) {
        if self.ports_view.is_empty() {
            self.ports_state.select(None);
            return;
        }
        let last = self.ports_view.len() as isize - 1;
        let current = self.ports_state.selected().unwrap_or(0) as isize;
        self.ports_state
            .select(Some(current.saturating_add(delta).clamp(0, last) as usize));
    }

    // ---- filter builder --------------------------------------------------

    /// Opens the builder on whichever spec is already in force, so it reads as
    /// an edit of the current filter rather than a blank form.
    fn open_builder(&mut self) {
        let (spec, target) = if self.display_spec.is_empty() && !self.capture_spec.is_empty() {
            (self.capture_spec.clone(), FilterTarget::Capture)
        } else if !self.display_spec.is_empty() {
            (self.display_spec.clone(), FilterTarget::Display)
        } else {
            (FilterSpec::default(), FilterTarget::Capture)
        };
        self.builder = Some(Builder::new(spec, target));
    }

    fn on_builder_key(&mut self, key: KeyEvent) {
        let Some(builder) = self.builder.as_mut() else {
            return;
        };
        match builder.on_key(key) {
            builder::Action::None => {}
            builder::Action::Close => self.builder = None,
            builder::Action::Apply => self.apply_builder(),
            builder::Action::RequestValues(field) => {
                let values = self.observed_values(field);
                if let Some(builder) = self.builder.as_mut() {
                    builder.picker = Some(Picker::new(field, values));
                }
            }
        }
    }

    fn apply_builder(&mut self) {
        let Some((spec, target)) = self.builder.as_ref().map(|b| (b.current_spec(), b.target))
        else {
            return;
        };

        match target {
            FilterTarget::Display => {
                self.display_spec = spec;
                self.builder = None;
                self.rebuild_view();
                self.info("Display filter applied".to_string());
            }
            FilterTarget::Capture => {
                // Compile and validate before touching the running capture, so
                // a rejected spec leaves the builder open with the reason.
                match spec
                    .to_bpf()
                    .and_then(|bpf| validate_bpf(self.linktype, &bpf).map(|()| bpf))
                {
                    Ok(bpf) => {
                        self.capture_spec = spec;
                        self.bpf = bpf;
                        self.builder = None;
                        if self.capture.is_some() {
                            self.restart_capture();
                        }
                    }
                    Err(message) => {
                        if let Some(builder) = self.builder.as_mut() {
                            builder.error = Some(message);
                        }
                    }
                }
            }
        }
    }

    /// Values of `field` seen in the buffer, most frequent first, so the picker
    /// offers what is actually on this network rather than a blank prompt.
    fn observed_values(&self, field: Field) -> Vec<(String, u64)> {
        use std::collections::HashMap;

        let mut counts: HashMap<String, u64> = HashMap::new();
        for pkt in &self.packets {
            match field {
                Field::Source => {
                    if let Some(ip) = pkt.src.ip {
                        *counts.entry(ip.to_string()).or_default() += 1;
                    }
                }
                Field::Destination => {
                    if let Some(ip) = pkt.dst.ip {
                        *counts.entry(ip.to_string()).or_default() += 1;
                    }
                }
                Field::Port => {
                    for port in [pkt.src.port, pkt.dst.port].into_iter().flatten() {
                        *counts.entry(port.to_string()).or_default() += 1;
                    }
                }
                Field::Protocol | Field::PortSide | Field::Target => {}
            }
        }

        let mut values: Vec<(String, u64)> = counts.into_iter().collect();
        values.sort_by(|(a_value, a_count), (b_value, b_count)| {
            b_count.cmp(a_count).then_with(|| {
                // Ports must order numerically, or 9 would follow 10.
                match (a_value.parse::<u64>(), b_value.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => a_value.cmp(b_value),
                }
            })
        });
        values.truncate(200);
        values
    }

    fn activate_menu_item(&mut self) {
        match MENU_ITEMS[self.menu_index] {
            MenuItem::Capture => self.screen = Screen::Devices,
            MenuItem::Ports => {
                self.screen = Screen::Ports;
                self.refresh_listeners();
            }
        }
    }

    fn on_menu_key(&mut self, key: KeyEvent) {
        let last = MENU_ITEMS.len() - 1;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_menu_item(),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.menu_index = (self.menu_index + 1).min(last);
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.menu_index = self.menu_index.saturating_sub(1);
            }
            // The number keys make the menu skippable once it is familiar.
            KeyCode::Char(ch) if ch.is_ascii_digit() => {
                let index = ch.to_digit(10).unwrap_or(0) as usize;
                if (1..=MENU_ITEMS.len()).contains(&index) {
                    self.menu_index = index - 1;
                    self.activate_menu_item();
                }
            }
            _ => {}
        }
    }

    fn on_ports_key(&mut self, key: KeyEvent) {
        let page = self.ports_height.max(1) as isize;
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => self.screen = Screen::Menu,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('r') => {
                self.refresh_listeners();
                match &self.listeners_error {
                    Some(_) => {}
                    None => {
                        let count = self.listeners.len();
                        self.info(format!("{count} listening sockets"));
                    }
                }
            }
            KeyCode::Char('/') => self.open_prompt(Prompt::PortSearch, &self.ports_query.clone()),
            KeyCode::Char('n') => {
                self.ports_query.clear();
                self.rebuild_ports_view();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_ports(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_ports(-1),
            KeyCode::PageDown => self.move_ports(page),
            KeyCode::PageUp => self.move_ports(-page),
            KeyCode::Home | KeyCode::Char('g') => self.move_ports(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_ports(isize::MAX / 2),
            _ => {}
        }
    }

    fn on_devices_key(&mut self, key: KeyEvent) {
        let len = self.device_view.len();
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => self.screen = Screen::Menu,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('r') => {
                self.refresh_devices();
                self.info(format!("{} interfaces", self.devices.len()));
            }
            KeyCode::Char('/') => {
                let current = self.device_query.clone();
                self.open_prompt(Prompt::DeviceSearch, &current);
            }
            KeyCode::Char('f') => self.open_prompt(Prompt::Bpf, &self.bpf.clone()),
            KeyCode::Char('F') => self.open_builder(),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(name) = self.selected_device().map(|d| d.name.clone()) {
                    self.start_capture(name);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_device(1, len),
            KeyCode::Up | KeyCode::Char('k') => self.move_device(-1, len),
            KeyCode::PageDown => self.move_device(10, len),
            KeyCode::PageUp => self.move_device(-10, len),
            KeyCode::Home | KeyCode::Char('g') => self.move_device(isize::MIN / 2, len),
            KeyCode::End | KeyCode::Char('G') => self.move_device(isize::MAX / 2, len),
            _ => {}
        }
    }

    fn move_device(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.device_state.select(None);
            return;
        }
        let current = self.device_state.selected().unwrap_or(0) as isize;
        let next = current.saturating_add(delta).clamp(0, len as isize - 1);
        self.device_state.select(Some(next as usize));
    }

    fn on_monitor_key(&mut self, key: KeyEvent, ctrl: bool) {
        let page = self.table_height.max(1) as isize;

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => {
                self.stop_capture();
                self.status = Status::Idle;
                self.screen = Screen::Devices;
            }
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Tab if self.show_detail => {
                self.focus = match self.focus {
                    Focus::Table => Focus::Detail,
                    Focus::Detail => Focus::Table,
                };
            }
            KeyCode::Enter | KeyCode::Char('d') => {
                self.show_detail = !self.show_detail;
                self.detail_scroll = 0;
                if !self.show_detail {
                    self.focus = Focus::Table;
                }
            }
            KeyCode::Char('/') => self.open_prompt(Prompt::Display, &self.display_filter.clone()),
            KeyCode::Char('f') => self.open_prompt(Prompt::Bpf, &self.bpf.clone()),
            KeyCode::Char('F') => self.open_builder(),
            KeyCode::Char('w') => {
                let default = format!("capture-{}.pcap", Local::now().format("%Y%m%d-%H%M%S"));
                self.open_prompt(Prompt::SavePath, &default);
            }
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                let state = if self.paused { "paused" } else { "resumed" };
                self.info(format!("Capture display {state}"));
            }
            KeyCode::Char('c') => {
                self.clear_packets();
                self.info("Cleared buffer".to_string());
            }
            KeyCode::Char('r') if ctrl => self.restart_capture(),
            KeyCode::Char(' ') => {
                self.follow = !self.follow;
                if self.follow {
                    self.select_last();
                }
            }
            KeyCode::Char('n') => {
                // Only the display-side filters; clearing the capture filter
                // would restart the capture, which reset should not do.
                self.proto_enabled = [true; ALL_PROTOS.len()];
                self.display_filter.clear();
                self.display_spec = FilterSpec::default();
                self.rebuild_view();
                self.info("Display filters reset".to_string());
            }
            KeyCode::Char(ch) if ALL_PROTOS.iter().any(|p| p.hotkey() == ch) => {
                let index = ALL_PROTOS
                    .iter()
                    .position(|p| p.hotkey() == ch)
                    .expect("hotkey matched above");
                self.proto_enabled[index] = !self.proto_enabled[index];
                self.rebuild_view();
            }
            KeyCode::Down | KeyCode::Char('j') => self.scroll_focused(1, page),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_focused(-1, page),
            KeyCode::PageDown => self.scroll_focused(page, page),
            KeyCode::PageUp => self.scroll_focused(-page, page),
            KeyCode::Home | KeyCode::Char('g') => match self.focus {
                Focus::Table => {
                    self.follow = false;
                    self.table_state
                        .select((!self.view.is_empty()).then_some(0));
                    self.detail_scroll = 0;
                }
                Focus::Detail => self.detail_scroll = 0,
            },
            KeyCode::End | KeyCode::Char('G') => match self.focus {
                Focus::Table => {
                    self.follow = true;
                    self.select_last();
                    self.detail_scroll = 0;
                }
                Focus::Detail => self.scroll_detail(page as i32),
            },
            _ => {}
        }
    }

    fn scroll_focused(&mut self, delta: isize, _page: isize) {
        match self.focus {
            Focus::Table => self.move_selection(delta),
            Focus::Detail => self.scroll_detail(delta as i32),
        }
    }

    // ---- export ----------------------------------------------------------

    /// Writes the currently displayed packets to a pcap file. Only the bytes
    /// retained for the hex view are written, so `caplen` reflects the copy on
    /// disk rather than the original capture length.
    fn save_pcap(&self, path: &str) -> anyhow::Result<usize> {
        let path = path.trim();
        anyhow::ensure!(!path.is_empty(), "no path given");

        let dead = pcap::Capture::dead(self.linktype)?;
        let mut savefile = dead.savefile(path)?;
        let mut written = 0usize;

        for pkt in self.visible() {
            let header = pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: pkt.ts.timestamp() as _,
                    tv_usec: pkt.ts.timestamp_subsec_micros() as _,
                },
                caplen: pkt.bytes.len() as u32,
                len: pkt.wire_len,
            };
            savefile.write(&pcap::Packet::new(&header, &pkt.bytes));
            written += 1;
        }

        savefile.flush()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, addresses: &[&str], running: bool, loopback: bool) -> DeviceEntry {
        DeviceEntry {
            name: name.to_string(),
            desc: None,
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            up: true,
            running,
            loopback,
            wireless: false,
            search: name.to_string(),
        }
    }

    #[test]
    fn link_local_and_loopback_addresses_are_not_routable() {
        assert!(is_routable(&"172.20.10.2".parse().unwrap()));
        assert!(is_routable(&"2001:db8::1".parse().unwrap()));
        assert!(!is_routable(&"127.0.0.1".parse().unwrap()));
        assert!(!is_routable(&"169.254.1.1".parse().unwrap()));
        assert!(!is_routable(&"fe80::1".parse().unwrap()));
        assert!(!is_routable(&"::1".parse().unwrap()));
    }

    #[test]
    fn the_interface_with_a_routable_address_sorts_first() {
        let mut devices = [
            device("awdl0", &["fe80::81:5eff:fe73:b2ba"], true, false),
            device("lo0", &["127.0.0.1", "::1"], true, true),
            device("gif0", &[], false, false),
            device(
                "en0",
                &["fe80::51:f1a5:2d2c:faee", "172.20.10.2"],
                true,
                false,
            ),
        ];
        devices.sort_by(|a, b| b.rank().cmp(&a.rank()).then_with(|| a.name.cmp(&b.name)));

        let order: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(order, ["en0", "awdl0", "lo0", "gif0"]);
    }

    #[test]
    fn packet_numbers_map_onto_ring_indices_after_eviction() {
        let mut app = App::new(3, 65535, false);
        app.devices.clear();
        app.device_view.clear();

        for no in 1..=5 {
            app.push_packet(fake_packet(no));
        }

        // Capacity is 3, so packets 1 and 2 were evicted.
        assert_eq!(app.packets_len(), 3);
        assert_eq!(app.view_len(), 3);
        assert!(app.packet_by_no(2).is_none());
        assert_eq!(app.packet_by_no(3).map(|p| p.no), Some(3));
        assert_eq!(app.packet_by_no(5).map(|p| p.no), Some(5));
        assert!(app.packet_by_no(6).is_none());
        // Following keeps the cursor pinned to the newest packet.
        assert_eq!(app.selected_packet().map(|p| p.no), Some(5));
    }

    #[test]
    fn filtering_out_every_packet_clears_the_selection() {
        let mut app = App::new(10, 65535, false);
        for no in 1..=4 {
            app.push_packet(fake_packet(no));
        }
        assert_eq!(app.view_len(), 4);

        app.proto_enabled[proto_index(Proto::Tcp)] = false;
        app.rebuild_view();
        assert_eq!(app.view_len(), 0);
        assert_eq!(app.table_state.selected(), None);

        app.proto_enabled[proto_index(Proto::Tcp)] = true;
        app.rebuild_view();
        assert_eq!(app.view_len(), 4);
        assert_eq!(app.selected_packet().map(|p| p.no), Some(4));
    }

    fn fake_packet(no: u64) -> Packet {
        Packet::for_test(no, Proto::Tcp, &format!("tcp packet {no}"))
    }
}
