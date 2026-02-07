# wireguard-quic

A fork of [wireguard-go](https://git.zx2c4.com/wireguard-go) with QUIC-over-raw-TCP transport for bypassing Deep Packet Inspection (DPI).

## What is this?

wireguard-quic wraps WireGuard traffic inside QUIC streams carried over raw TCP sockets, making it indistinguishable from normal HTTPS/HTTP3 web traffic to DPI systems.

The transport stack:

```
WireGuard Packet
      |
  QUIC Stream (TLS 1.3, h3 ALPN)
      |
  Raw TCP Packets (crafted headers, bypasses OS TCP stack)
      |
  Network — DPI sees normal HTTPS traffic
```

## Features

- **DPI bypass** — Traffic appears as standard HTTPS/HTTP3 on port 443
- **Raw TCP injection** — Bypasses OS TCP stack, crafts realistic TCP headers
- **TLS 1.3 encryption** — Full QUIC with h3 ALPN on top of WireGuard encryption
- **Multi-stream QUIC** — Multiple QUIC connections with multiple streams each for throughput
- **Auto-detection** — Automatically detects network interface, IP, and gateway MAC
- **Cross-platform** — Linux (AF_PACKET), macOS (libpcap), Windows (Npcap)
- **Config file driven** — INI-format config at `/etc/wireguard/<interface>.quictcp.conf`

## Quick Start

### Build

Requires [Go](https://go.dev/) 1.24+.

```bash
# Linux (static binary, no CGO)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o wireguard-quic-linux-amd64 -ldflags="-s -w"

# macOS
go build -o wireguard-quic-darwin-amd64

# Or use make
make
```

### Server (Linux)

1. Create `/etc/wireguard/wg0.quictcp.conf`:

```ini
[QuicTcp]
Enabled = true
Key = <shared-secret>
IsServer = true
LocalPort = 443
AutoDetect = true
Backend = afpacket
```

2. Block RST packets and start:

```bash
sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
sudo wireguard-quic wg0
```

3. Configure WireGuard as usual with `wg setconf`.

### Client (macOS/Linux)

1. Create `/etc/wireguard/wg0.quictcp.conf`:

```ini
[QuicTcp]
Enabled = true
Key = <shared-secret>
Server = your.server.ip:443
AutoDetect = true
LocalPort = 0
```

2. Start:

```bash
sudo wireguard-quic wg0
```

Or use the helper script for one-command setup:

```bash
sudo wgq-quick up wg0      # start (background)
sudo wgq-quick -f up wg0   # start (foreground with logs)
sudo wgq-quick down wg0    # stop
```

## Configuration

QUIC-TCP is configured via INI files or environment variables. See [QUICTCP-USAGE.md](QUICTCP-USAGE.md) for the full reference, and [configs/](configs/) for sample configurations.

### Config file locations (searched in order)

1. `WG_QUICTCP_CONFIG` environment variable
2. `/etc/wireguard/<interface>.quictcp.conf`
3. `/etc/wireguard/<interface>.quictcp`
4. `~/.config/wireguard/<interface>.quictcp.conf`

## Requirements

- **Root/Administrator privileges** — Required for raw socket access
- **Linux**: No external dependencies (uses AF_PACKET)
- **macOS**: libpcap (included with macOS)
- **Windows**: [Npcap](https://npcap.com/)
- **Server-side**: Must block RST packets on the QUIC-TCP port

## Platform Notes

### Linux
Uses AF_PACKET for zero-dependency raw socket access. For standard WireGuard without DPI bypass, use the kernel module instead — see [wireguard.com/install](https://www.wireguard.com/install/).

### macOS
Uses utun driver. Interface names must be `utun[0-9]+` or `utun` for kernel auto-assignment.

### Windows
Uses Npcap for raw socket access. For standard WireGuard, use the [Windows app](https://git.zx2c4.com/wireguard-windows/about/).

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
