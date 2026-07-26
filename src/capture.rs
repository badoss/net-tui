//! Background live-capture thread and the channel it feeds the UI through.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pcap::{Capture, Linktype};

use crate::packet::{self, Packet};

/// Bound on the in-flight queue between the capture thread and the UI. Once
/// full the capture thread discards rather than blocks, so a slow terminal
/// stalls the display instead of the kernel's BPF buffer.
const CHANNEL_CAPACITY: usize = 8192;

/// How long `next_packet` waits before returning so the loop can observe the
/// stop flag. Also bounds how long shutdown takes.
const POLL_TIMEOUT_MS: i32 = 200;

const STATS_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub device: String,
    /// tcpdump-syntax filter compiled by libpcap. Empty means capture everything.
    pub bpf: String,
    pub snaplen: i32,
    pub promiscuous: bool,
    pub buffer_size: i32,
}

impl CaptureConfig {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            bpf: String::new(),
            snaplen: 65535,
            promiscuous: false,
            buffer_size: 4 * 1024 * 1024,
        }
    }
}

/// Drop counters libpcap maintains for the live handle. Packet totals are
/// tracked by the app itself, so only the losses are mirrored here.
#[derive(Clone, Copy, Default, Debug)]
pub struct DriverStats {
    /// Dropped because the kernel capture buffer filled up.
    pub kernel_dropped: u32,
    /// Dropped by the network interface before libpcap saw them.
    pub if_dropped: u32,
}

impl DriverStats {
    pub fn total(self) -> u64 {
        u64::from(self.kernel_dropped) + u64::from(self.if_dropped)
    }
}

pub enum CaptureEvent {
    Started {
        linktype: Linktype,
    },
    Packet(Box<Packet>),
    Stats(DriverStats),
    /// Capture could not start, or died mid-run. Carries a message already
    /// phrased for display.
    Error(String),
    Stopped,
}

pub struct CaptureHandle {
    rx: Receiver<CaptureEvent>,
    stop: Arc<AtomicBool>,
    /// Packets the capture thread dropped because the UI queue was full.
    ui_dropped: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
    config: CaptureConfig,
}

impl CaptureHandle {
    pub fn spawn(config: CaptureConfig) -> Self {
        let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let ui_dropped = Arc::new(AtomicU64::new(0));

        let thread = thread::Builder::new()
            .name("net-tui-capture".to_string())
            .spawn({
                let config = config.clone();
                let stop = Arc::clone(&stop);
                let ui_dropped = Arc::clone(&ui_dropped);
                move || run(config, tx, stop, ui_dropped)
            })
            .expect("spawn capture thread");

        Self {
            rx,
            stop,
            ui_dropped,
            thread: Some(thread),
            config,
        }
    }

    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    pub fn ui_dropped(&self) -> u64 {
        self.ui_dropped.load(Ordering::Relaxed)
    }

    pub fn try_recv(&self) -> Result<CaptureEvent, TryRecvError> {
        self.rx.try_recv()
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return;
        };
        // The capture thread signs off with a blocking send. If the queue were
        // full at that moment and we simply joined, it would wait for room
        // that only this thread can free — so keep draining until it exits.
        // Bounded by POLL_TIMEOUT_MS, the longest `next_packet` can block.
        while !thread.is_finished() {
            while self.rx.try_recv().is_ok() {}
            thread::sleep(Duration::from_millis(1));
        }
        let _ = thread.join();
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Compiles `bpf` against a throwaway handle so a typo can be reported without
/// tearing down a capture that is currently working.
pub fn validate_bpf(linktype: Linktype, bpf: &str) -> Result<(), String> {
    if bpf.trim().is_empty() {
        return Ok(());
    }
    let mut dead = Capture::dead(linktype).map_err(|e| e.to_string())?;
    dead.filter(bpf, true).map_err(friendly_error)
}

fn run(
    config: CaptureConfig,
    tx: SyncSender<CaptureEvent>,
    stop: Arc<AtomicBool>,
    ui_dropped: Arc<AtomicU64>,
) {
    let mut cap = match open(&config) {
        Ok(cap) => cap,
        Err(err) => {
            let _ = tx.send(CaptureEvent::Error(err));
            let _ = tx.send(CaptureEvent::Stopped);
            return;
        }
    };

    let linktype = cap.get_datalink();
    if tx.send(CaptureEvent::Started { linktype }).is_err() {
        return;
    }

    let mut seq: u64 = 0;
    let mut last_stats = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(raw) => {
                seq += 1;
                let decoded = packet::decode(seq, raw.header, raw.data, linktype);
                match tx.try_send(CaptureEvent::Packet(Box::new(decoded))) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        ui_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(pcap::Error::NoMorePackets) => break,
            Err(err) => {
                let _ = tx.send(CaptureEvent::Error(friendly_error(err)));
                break;
            }
        }

        if last_stats.elapsed() >= STATS_INTERVAL {
            last_stats = Instant::now();
            if let Ok(stat) = cap.stats() {
                let _ = tx.try_send(CaptureEvent::Stats(DriverStats {
                    kernel_dropped: stat.dropped,
                    if_dropped: stat.if_dropped,
                }));
            }
        }
    }

    let _ = tx.send(CaptureEvent::Stopped);
}

fn open(config: &CaptureConfig) -> Result<Capture<pcap::Active>, String> {
    let mut cap = Capture::from_device(config.device.as_str())
        .map_err(friendly_error)?
        .snaplen(config.snaplen)
        .promisc(config.promiscuous)
        .immediate_mode(true)
        .buffer_size(config.buffer_size)
        .timeout(POLL_TIMEOUT_MS)
        .open()
        .map_err(friendly_error)?;

    if !config.bpf.trim().is_empty() {
        cap.filter(&config.bpf, true)
            .map_err(|e| format!("invalid filter: {}", friendly_error(e)))?;
    }

    Ok(cap)
}

/// Turns libpcap's raw text into something actionable. The permission case is
/// by far the most common first-run failure on macOS, where `/dev/bpf*` is
/// root-owned, so it gets an explicit remedy.
fn friendly_error(err: pcap::Error) -> String {
    let text = err.to_string();
    if text.to_lowercase().contains("permission denied") {
        return format!(
            "{text}\n\nCapturing needs access to /dev/bpf*. Either run with sudo:\n  \
             sudo net-tui\nor grant the admin group persistent access:\n  \
             sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*"
        );
    }
    text
}
