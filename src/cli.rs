//! Command-line arguments.

use clap::Parser;

use crate::packet::WORST_CASE_PACKET_BYTES;

/// Floor on the ring, small enough to fit any budget yet still useful.
const MIN_BUFFER: usize = 100;

/// Budget bounds in MiB. The ceiling is a sanity limit rather than a
/// recommendation — the ring is resident memory, not a cache.
const MIN_MEMORY_MB: usize = 8;
const MAX_MEMORY_MB: usize = 32 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "net-tui",
    version,
    about = "Terminal UI for live TCP/UDP traffic capture on local interfaces",
    after_help = "Capturing requires access to /dev/bpf* on macOS and CAP_NET_RAW on Linux.\n\
                  Run with sudo, or grant persistent access:\n  \
                  sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*"
)]
pub struct Args {
    /// Interface to start capturing on. Without it, net-tui opens the picker.
    #[arg(short, long, value_name = "NAME")]
    pub interface: Option<String>,

    /// Capture filter in tcpdump (BPF) syntax, e.g. "tcp port 443".
    #[arg(short, long, value_name = "BPF", default_value = "")]
    pub filter: String,

    /// Packets held in memory. Older packets are discarded first. Reduced if it
    /// would exceed --memory.
    #[arg(short = 'b', long, value_name = "N", default_value_t = 5_000)]
    pub buffer: usize,

    /// Memory budget for the packet buffer, in MiB.
    #[arg(short = 'm', long, value_name = "MB", default_value_t = 512)]
    pub memory: usize,

    /// Bytes captured per packet.
    #[arg(short, long, value_name = "BYTES", default_value_t = 65_535)]
    pub snaplen: i32,

    /// Capture packets not addressed to this host.
    #[arg(short, long)]
    pub promiscuous: bool,

    /// Print the available interfaces and exit.
    #[arg(short, long)]
    pub list: bool,
}

impl Args {
    /// Clamps the arguments and reports anything that had to be changed.
    ///
    /// The buffer is bounded by memory rather than by a bare packet count: a
    /// retained packet costs up to `WORST_CASE_PACKET_BYTES`, so a count that
    /// looks harmless can be gigabytes. Silently accepting it would trade a
    /// clear message now for an OOM kill later.
    pub fn validated(mut self) -> (Self, Option<String>) {
        self.snaplen = self.snaplen.clamp(64, 262_144);
        self.memory = self.memory.clamp(MIN_MEMORY_MB, MAX_MEMORY_MB);

        let affordable = (self.memory * 1024 * 1024 / WORST_CASE_PACKET_BYTES).max(MIN_BUFFER);
        let requested = self.buffer.max(MIN_BUFFER);
        self.buffer = requested.min(affordable);

        let notice = (self.buffer < requested).then(|| {
            format!(
                "Buffer reduced from {requested} to {} packets to stay within {} MiB \
                 (worst case {} KiB per packet). Raise it with --memory.",
                self.buffer,
                self.memory,
                WORST_CASE_PACKET_BYTES / 1024,
            )
        });

        (self, notice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(buffer: usize, memory: usize) -> Args {
        Args {
            interface: None,
            filter: String::new(),
            buffer,
            memory,
            snaplen: 65_535,
            promiscuous: false,
            list: false,
        }
    }

    #[test]
    fn a_buffer_that_fits_is_left_alone() {
        let (args, notice) = args(5_000, 512).validated();
        assert_eq!(args.buffer, 5_000);
        assert!(notice.is_none());
        assert!(args.buffer * WORST_CASE_PACKET_BYTES < 512 * 1024 * 1024);
    }

    #[test]
    fn an_oversized_buffer_is_reduced_to_the_budget_and_explained() {
        // The old clamp allowed a million packets, which is gigabytes.
        let (args, notice) = args(1_000_000, 512).validated();
        assert!(args.buffer < 1_000_000);
        assert!(args.buffer * WORST_CASE_PACKET_BYTES <= 512 * 1024 * 1024);
        let notice = notice.expect("a reduction must be reported");
        assert!(notice.contains("1000000"), "{notice}");
        assert!(notice.contains("--memory"), "{notice}");
    }

    #[test]
    fn a_larger_budget_allows_a_larger_buffer() {
        let (small, _) = args(1_000_000, 64).validated();
        let (large, _) = args(1_000_000, 2048).validated();
        assert!(large.buffer > small.buffer);
        assert!(large.buffer * WORST_CASE_PACKET_BYTES <= 2048 * 1024 * 1024);
    }

    #[test]
    fn the_floor_survives_an_absurdly_small_budget() {
        // A budget too small for even the floor still has to produce a usable
        // app rather than a zero-length ring.
        let (args, _) = args(1, 1).validated();
        assert_eq!(args.buffer, MIN_BUFFER);
        assert_eq!(args.memory, MIN_MEMORY_MB);
    }

    #[test]
    fn snaplen_stays_within_what_libpcap_accepts() {
        let (low, _) = args(100, 512).validated();
        assert_eq!(low.snaplen, 65_535);
        let mut a = args(100, 512);
        a.snaplen = 10;
        assert_eq!(a.validated().0.snaplen, 64);
        let mut a = args(100, 512);
        a.snaplen = 999_999;
        assert_eq!(a.validated().0.snaplen, 262_144);
    }
}
