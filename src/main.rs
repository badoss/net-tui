//! net-tui — live TCP/UDP traffic viewer for local interfaces.

mod app;
mod builder;
mod capture;
mod cli;
mod filter;
mod input;
mod packet;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::app::App;
use crate::cli::Args;

/// Upper bound on redraw rate. Input is polled far more often than this so
/// keystrokes stay responsive under heavy traffic.
const FRAME_INTERVAL: Duration = Duration::from_millis(50);

const INPUT_POLL: Duration = Duration::from_millis(10);

fn main() -> Result<()> {
    let (args, notice) = Args::parse().validated();

    if args.list {
        return list_interfaces();
    }

    let mut app = App::new(args.buffer, args.snaplen, args.promiscuous);
    app.bpf = args.filter.clone();
    if let Some(notice) = notice {
        app.notice(notice);
    }
    // After the notice, so that failing to open the requested interface
    // replaces it — an error the user must act on outranks a clamp report.
    if let Some(interface) = &args.interface {
        app.start_on_named_device(interface);
    }

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    let mut last_frame = Instant::now() - FRAME_INTERVAL;

    while !app.should_quit {
        app.drain_capture();

        if last_frame.elapsed() >= FRAME_INTERVAL {
            last_frame = Instant::now();
            terminal.draw(|frame| ui::draw(frame, app))?;
        }

        if event::poll(INPUT_POLL)? {
            match event::read()? {
                // Windows terminals emit both press and release; only act once.
                Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key),
                Event::Resize(_, _) => {
                    last_frame = Instant::now() - FRAME_INTERVAL;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn list_interfaces() -> Result<()> {
    use io::Write as _;

    let mut out = io::stdout().lock();
    for device in pcap::Device::list()? {
        let addresses: Vec<String> = device
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        writeln!(
            out,
            "{:<12} {:<40} {}",
            device.name,
            if addresses.is_empty() {
                "-".to_string()
            } else {
                addresses.join(", ")
            },
            device.desc.unwrap_or_default()
        )?;
    }
    Ok(())
}
