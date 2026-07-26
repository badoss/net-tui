//! Command-line arguments.

use clap::Parser;

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

    /// Packets held in memory. Older packets are discarded first.
    #[arg(short = 'b', long, value_name = "N", default_value_t = 5_000)]
    pub buffer: usize,

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
    pub fn validated(mut self) -> Self {
        self.buffer = self.buffer.clamp(100, 1_000_000);
        self.snaplen = self.snaplen.clamp(64, 262_144);
        self
    }
}
