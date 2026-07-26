# net-tui

A terminal UI for watching live TCP/UDP traffic on your machine's network
interfaces. Pick an interface, narrow the traffic down with a filter, and read
the decoded packets — without leaving the terminal.

Built with [ratatui](https://ratatui.rs/) and libpcap.

## Features

- **Interface picker** listing every local device with its addresses and link
  state. Interfaces with a routable address sort first, so the one you want is
  usually already selected.
- **Live decode** of Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP, with a
  Wireshark-style summary column (TCP flags, sequence numbers, service names).
- **Filter builder** — pick source, destination, protocol and port from a form
  instead of writing BPF by hand, filling any field from the addresses and
  ports actually seen on the wire.
- **Two independent filters**: a capture filter compiled by libpcap, and a
  display filter applied as you type.
- **Per-protocol toggles** to hide whole classes of traffic with one key.
- **Detail pane** with the decoded header fields beside a hex dump.
- **Live counters** — packets, bytes, packets/sec, throughput, and drop counts
  broken down by kernel vs. UI — plus a packets/sec sparkline.
- **Export** the packets currently on screen to a `.pcap` file for Wireshark.

## Screenshots

Interface picker:

```
┌ net-tui ──────────────────────────────────────────────────────────────────────┐
│Select an interface to capture   21 found                                      │
└───────────────────────────────────────────────────────────────────────────────┘
┌ Interfaces ───────────────────────────────────────────────────────────────────┐
│▌ ● en0      fe80::51:f1a5:2d2c:faee, 172.20.10.2  [wireless]                  │
│  ● awdl0    fe80::81:5eff:fe73:b2ba  [wireless]                               │
│  ● llw0     fe80::81:5eff:fe73:b2ba                                           │
│  ● utun0    fe80::63a0:5791:68ff:9d17                                         │
│  ● lo0      127.0.0.1, ::1, fe80::1  [loopback]                               │
│  ● bridge0  —                                                                 │
│  ○ gif0     —  [down]                                                         │
└───────────────────────────────────────────────────────────────────────────────┘
 ↑/↓ select  enter capture  / find  F filter builder  r refresh  ? help  q quit
```

Capture screen, detail pane open (rendered with sample packets):

```
┌ net-tui · en0 ───────────────────────────────────────────────────────────────────────────────────────┐
│ LIVE   EN10MB   bpf: (none)                                                              packets/sec │
│4 pkts  416 B  0 pps  0 B/s  showing 4  dropped 0                                     ▂▃▅▂▁▃▇▅▃▂▁▂▄▃▂ │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
 show ✓TCP (t)  ✓UDP (u)  ✓ICMP (i)  ✓ARP (a)  ✓OTHER (o)
┌ Packets  4/4 ────────────────────────────────────────────────────────────────────────────────────────┐
│No.      Time          Source                Destination           Proto  Len     Info                │
│       1 11:28:14.963  172.20.10.2:51820     142.250.66.78:443      TCP         74 [SYN] HTTPS  Seq=0  │
│       2 11:28:14.963  142.250.66.78:443     172.20.10.2:51820      TCP         94 [SYN, ACK] HTTPS    │
│       3 11:28:14.963  172.20.10.2:53124     1.1.1.1:53             UDP        114 DNS  Len=41         │
│       4 11:28:14.963  172.20.10.2           8.8.8.8                ICMP       134 Echo request        │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Detail  ·  tab to focus, ↑/↓ to scroll ──────────────────────────────────────────────────────────────┐
│Frame                                          0000  45 00 00 3c 1c 46 40 00  E..<.F@.                │
│  Number          4                            0008  40 06 b1 e6 c0 a8 00 68  @......h                │
│  Captured        2026-07-26 11:28:14.963833   0010  c0 a8 00 01 00 50 c9 4a  .....P.J                │
│  Wire length     134 bytes                    0018  00 00 00 00 a0 02 ff ff  ........                │
│  Link type       EN10MB                                                                              │
│Ethernet II                                                                                           │
│  Source          00:1a:2b:3c:4d:5e                                                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
 ↑/↓ move  enter detail  / filter  F builder  f bpf  space follow  p pause  c clear  w save  esc interfaces  ? help
```

Filter builder (`F`), with the value picker open on the port field:

```
┌ Filter builder ────────────────────────────────────────────────────────────┐
│    Source        172.20.10.2                                               │
│    Destination   any                                                       │
│    Protocol   ┌ Ports seen ────────────────────────────────┐               │
│  ▌ Port       │▌443                                      2 │               │
│    Port side  │ 51820                                    2 │               │
│    Apply to   │ 53                                       1 │               │
│               │ 53124                                    1 │               │
│               └────────────────────────────────────────────┘               │
│  BPF   src host 172.20.10.2 and tcp and port 443                           │
│                                                                            │
│  ↑↓ field  ctrl+p pick from traffic  enter apply  esc cancel               │
└────────────────────────────────────────────────────────────────────────────┘
```

## Install

### Linux — one line

```sh
curl -fsSL https://raw.githubusercontent.com/badoss/net-tui/main/install.sh | sh
```

The script picks the right format for your system — `.deb` where apt is
available, `.rpm` where dnf or yum is, and a plain binary otherwise — verifies
the download against the release's `SHA256SUMS`, and installs it. Pass
`--method binary` to skip the package manager, `--version vX.Y.Z` to pin a
release, or `--help` for the rest.

### Linux — download a package

Grab the file for your architecture from the
[latest release](https://github.com/badoss/net-tui/releases/latest):

```sh
sudo apt install ./net-tui_*_amd64.deb     # Debian, Ubuntu
sudo dnf install ./net-tui-*.x86_64.rpm    # Fedora, RHEL, Rocky, Alma
```

**One package covers every distribution.** The binary inside is statically
linked against musl and libpcap, so it declares no dependencies — not libpcap,
not even libc. That matters more than it sounds: Ubuntu 24.04 renamed
`libpcap0.8` to `libpcap0.8t64` for the 64-bit `time_t` transition, so a
conventionally linked package would need building once per distribution.

The trade-off is that a libpcap security fix arrives in a net-tui release
rather than through `apt upgrade`.

### Build from source

Needs Rust 1.85 or newer (the crate uses edition 2024) and libpcap headers —
`libpcap-dev` on Debian and Ubuntu, `libpcap-devel` on Fedora. libpcap ships
with macOS.

```sh
cargo build --release
./target/release/net-tui
```

## Permissions

Packet capture needs privileged access to the network stack, so `net-tui` will
not see any traffic when run as a normal user. It detects this and shows the
remedy on screen rather than failing silently.

**macOS** — capture goes through `/dev/bpf*`, which is root-owned. There is no
macOS package; build from source and run:

```sh
sudo ./target/release/net-tui
```

To avoid `sudo` every time, grant the `admin` group access. Note that this
lets any admin user on the machine sniff traffic, and macOS recreates the
devices on reboot:

```sh
sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
```

**Linux** — either run under `sudo`, or grant the binary the two capabilities
it needs so it can run unprivileged:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v net-tui)"
```

The packages deliberately do not do this for you. `CAP_NET_RAW` lets *any* user
on the machine read traffic from every interface, which is the administrator's
decision to make — tcpdump ships the same way.

## Usage

```
net-tui [OPTIONS]

  -i, --interface <NAME>   Interface to start capturing on. Without it, net-tui
                           opens the picker.
  -f, --filter <BPF>       Capture filter in tcpdump syntax, e.g. "tcp port 443"
  -b, --buffer <N>         Packets held in memory [default: 5000]
  -s, --snaplen <BYTES>    Bytes captured per packet [default: 65535]
  -p, --promiscuous        Capture packets not addressed to this host
  -l, --list               Print the available interfaces and exit
```

Start on a specific interface with a filter already applied:

```sh
sudo net-tui -i en0 -f "tcp port 443"
```

## Filtering

### The filter builder

`F` opens a form for the four things you usually want to select on:

| Field | Accepts |
|---|---|
| Source | An IP address. On the display target, a partial one like `10.0.` selects a subnet. |
| Destination | Same. |
| Protocol | `any`, TCP, UDP, ICMP, ARP or other. `←` `→` cycles. |
| Port | `0`–`65535`. |
| Port side | Whether the port must be the source, the destination, or `either`. |
| Apply to | Whether the result becomes a capture filter or a display filter. |

`↑` `↓` move between fields, `←` `→` change the ones that cycle, `enter`
applies and `esc` cancels. The line at the bottom shows the compiled BPF as you
type, so the form doubles as a way to learn the syntax.

**`ctrl+p` fills a field from real traffic.** Instead of typing an address, it
opens a list of every source, destination or port seen in the buffer, ordered
by how many packets carried it. This is the fastest way to answer "what is this
machine talking to, and can I watch just that".

A spec that cannot work is explained rather than passed to libpcap — a
hostname where an address is required, a port on ARP, a port that is not a
number. Nothing is applied until it compiles, so a bad entry never disturbs a
running capture.

### Capture vs. display

There are two filters and they do different jobs. Getting them mixed up is the
usual source of confusion, so:

| | Capture filter (`f`) | Display filter (`/`) |
|---|---|---|
| Syntax | tcpdump / BPF | plain substring terms |
| Applied | in the kernel, before capture | to packets already in the buffer |
| Cost | free — filtered traffic is never copied | none, but the packets were already captured |
| Changing it | restarts the capture, clearing the buffer | instant, non-destructive |

**Capture filter** uses the same syntax as `tcpdump`, compiled by libpcap:

```
tcp port 443
host 10.0.0.1 and not port 22
udp and not port 53
```

An invalid filter is rejected before the running capture is touched, so a typo
costs you nothing.

Use a capture filter when you are on a busy link. It is the only filter that
prevents drops, because filtered traffic never reaches userspace at all.

**Display filter** matches against everything shown in a row — protocol,
addresses, ports, MACs, and the summary text:

```
dns              a single term
tcp 443          every term must match
!arp             a leading ! excludes
tcp !ack         combine both
```

**Protocol toggles** — `t`, `u`, `i`, `a`, `o` switch TCP, UDP, ICMP, ARP and
everything else on and off. `n` clears the display-side filters at once.

## Keys

### Interface picker

| Key | Action |
|---|---|
| `↑` `↓` / `k` `j` | Move selection |
| `enter` | Start capturing |
| `/` | Search by name, description or address |
| `F` | Filter builder — source, destination, protocol, port |
| `f` | Set the capture filter before starting |
| `r` | Rescan interfaces |
| `?` | Help |
| `q` / `esc` | Quit |

### Capture screen

| Key | Action |
|---|---|
| `↑` `↓` / `k` `j` | Move selection |
| `PgUp` `PgDn` | Move a page |
| `g` / `G` | First / newest packet |
| `space` | Follow newest packet on/off |
| `enter` / `d` | Show or hide the detail pane |
| `tab` | Switch focus between the list and the detail pane |
| `F` | Filter builder — source, destination, protocol, port |
| `/` | Display filter |
| `f` | Capture filter (raw BPF) |
| `t` `u` `i` `a` `o` | Toggle TCP / UDP / ICMP / ARP / other |
| `n` | Reset the display filters |
| `p` | Freeze the list, keep counting traffic |
| `c` | Clear the buffer |
| `w` | Write displayed packets to a `.pcap` file |
| `ctrl+r` | Restart capture on this interface |
| `esc` | Back to the interface list |
| `q` / `ctrl+c` | Quit |

In any prompt: `enter` accepts, `esc` cancels, `ctrl+w` deletes a word,
`ctrl+u` clears to the start. In the builder, `ctrl+p` opens the value picker
for the focused field.

`n` clears the display-side filters only. Clearing the capture filter would
restart the capture and drop the buffer, so that stays an explicit action.

## Reading the counters

`dropped` splits into two numbers once it goes above zero, because the fix
differs:

- **kernel** — libpcap could not keep up and the kernel discarded packets.
  Narrow the capture filter, or raise the buffer size.
- **ui** — packets were decoded but the terminal could not render them fast
  enough. Narrow the filter, or use a faster terminal.

Pausing with `p` freezes the packet list but leaves the counters running, so
you can read a frozen screen while still seeing whether traffic continues.

## Saving captures

`w` writes the packets currently displayed — after both filters — to a `.pcap`
file that Wireshark and `tcpdump` can read.

Only the first 4 KB of each packet is retained in memory, so packets larger
than that are truncated in the export. The `Detail` pane flags any packet this
applies to.

## How it works

A dedicated thread owns the libpcap handle and decodes packets, passing them to
the UI over a bounded channel. Decoding off the UI thread keeps redraws
responsive, and the bound means a slow terminal degrades into counted drops
rather than unbounded memory growth.

Packets live in a fixed-capacity ring. The display filter maintains a parallel
list of packet numbers rather than copying packets, and because numbering is
contiguous a number maps to a ring index by subtraction. Only the rows actually
on screen are formatted each frame, so buffer size does not affect frame cost.

## Development

```sh
cargo test
cargo clippy --all-targets
```

The UI is covered by tests that render real frames through ratatui's
`TestBackend` and assert on the resulting screen, so layout and filtering can
be verified without a network or root access.

### Building the Linux packages

`packaging/Dockerfile` produces the `.deb`, `.rpm` and tarball for one
architecture. CI runs exactly this file, so local builds cannot drift from
released ones:

```sh
docker buildx build --platform linux/amd64 \
  --file packaging/Dockerfile --target artifacts \
  --output type=local,dest=dist .
```

Pushing a `v*` tag runs it on a native runner per architecture and publishes
the results, with checksums, to a GitHub release. CI installs the packages on
Debian 11 and 12, Ubuntu 22.04 and 24.04, AlmaLinux 8 and 9 and Fedora on every
pull request, because a package that builds but will not install is not a
working package.

## License

MIT — see [LICENSE](LICENSE).
