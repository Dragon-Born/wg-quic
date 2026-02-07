# QUIC-over-Raw-TCP DPI Bypass

This document describes how to use the QUIC-over-raw-TCP transport mode to bypass Deep Packet Inspection (DPI) systems.

## Overview

When enabled, wireguard-quic will transport packets using:
1. **Raw TCP sockets** - Bypasses OS TCP stack, crafts realistic TCP headers
2. **QUIC protocol** - Makes traffic look like HTTP/3 (HTTPS)
3. **TLS 1.3** - Full encryption with h3 ALPN

This combination makes WireGuard traffic indistinguishable from normal HTTPS/HTTP3 web browsing to DPI systems.

## Requirements

- **Root/Administrator privileges** - Required for raw socket access
- **libpcap** - On Linux/macOS (or Npcap on Windows)
- **Server-side iptables** - Must block RST packets (see below)

## Configuration Methods

You can configure QUIC-TCP using either:
1. **Config File** (recommended) - `/etc/wireguard/<interface>.quictcp.conf`
2. **Environment Variables** - Set before running wireguard-go

## Quick Start with Config File (Recommended)

### Client Configuration

Create `/etc/wireguard/wg0.quictcp.conf`:

```ini
[QuicTcp]
Enabled = true
Key = your-shared-secret-key
Server = vpn.example.com:443
AutoDetect = true
LocalPort = 443
```

Then run:
```bash
sudo wireguard-quic wg0
```

### Server Configuration

Create `/etc/wireguard/wg0.quictcp.conf`:

```ini
[QuicTcp]
Enabled = true
Key = your-shared-secret-key
IsServer = true
AutoDetect = true
LocalPort = 443
```

Then run:
```bash
# Block RST packets first (REQUIRED)
sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP

sudo wireguard-quic wg0
```

## Quick Start with Environment Variables

### Client Configuration

```bash
export WG_QUICTCP_ENABLED=true
export WG_QUICTCP_AUTO_DETECT=true
export WG_QUICTCP_KEY="your-shared-secret-key"
export WG_QUICTCP_SERVER="vpn.example.com:443"

sudo wireguard-quic wg0
```

### Server Configuration

```bash
export WG_QUICTCP_ENABLED=true
export WG_QUICTCP_AUTO_DETECT=true
export WG_QUICTCP_KEY="your-shared-secret-key"
export WG_QUICTCP_IS_SERVER=true
export WG_QUICTCP_LOCAL_PORT=443

sudo wireguard-quic wg0
```

## Config File Format

The config file uses INI format with a `[QuicTcp]` section:

```ini
[QuicTcp]
# Enable QUIC-TCP mode (required)
Enabled = true

# Shared secret for TLS certificates (required)
# Must be the same on client and server
Key = your-shared-secret-key

# Server address (required for client mode)
Server = vpn.example.com:443

# Server mode (set to true on server)
IsServer = false

# Auto-detect network settings
AutoDetect = true

# Or configure manually:
# Interface = eth0
# LocalIP = 192.168.1.100
# RouterMAC = aa:bb:cc:dd:ee:ff

# Local port (default: 443)
LocalPort = 443

# Backend: auto, pcap, or afpacket
Backend = auto

# Socket buffer size (bytes)
SocketBuffer = 4194304

# TCP flags to cycle
TCPFlags = PA, A

# ALPN protocol (h3 = HTTP/3)
ALPN = h3

# Connection idle timeout
IdleTimeout = 30s
```

### Config File Locations

The config file is searched in this order:
1. `WG_QUICTCP_CONFIG` environment variable
2. `/etc/wireguard/<interface>.quictcp.conf`
3. `/etc/wireguard/<interface>.quictcp`
4. `~/.config/wireguard/<interface>.quictcp.conf`

### Generate Example Config

You can generate an example config file programmatically:
```go
import "golang.zx2c4.com/wireguard/quictcp"
quictcp.WriteExampleConfig("/etc/wireguard/wg0.quictcp.conf")
```

## Server-Side iptables (REQUIRED)

The server's kernel will send RST packets for TCP packets without connection state. You **MUST** block these:

```bash
# Block outgoing RST packets on port 443
sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP

# Make it persistent (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4
```

## Environment Variables

### Required
| Variable | Description |
|----------|-------------|
| `WG_QUICTCP_ENABLED=true` | Enable QUIC-TCP mode |
| `WG_QUICTCP_KEY` | Shared secret for TLS certificates |
| `WG_QUICTCP_SERVER` | Server address (client mode only) |

### Network Configuration
| Variable | Description |
|----------|-------------|
| `WG_QUICTCP_AUTO_DETECT=true` | Auto-detect network settings |
| `WG_QUICTCP_INTERFACE` | Network interface (e.g., eth0) |
| `WG_QUICTCP_LOCAL_IP` | Local IP address |
| `WG_QUICTCP_LOCAL_PORT` | Local port (default: 443) |
| `WG_QUICTCP_ROUTER_MAC` | Gateway MAC address |

### Mode Selection
| Variable | Description |
|----------|-------------|
| `WG_QUICTCP_IS_SERVER=true` | Run in server mode |

### Optional Tuning
| Variable | Default | Description |
|----------|---------|-------------|
| `WG_QUICTCP_BACKEND` | auto | Backend: auto, pcap, afpacket |
| `WG_QUICTCP_SOCKET_BUFFER` | 4194304 | Socket buffer size (bytes) |
| `WG_QUICTCP_TCP_FLAGS` | PA,A | TCP flags to cycle |
| `WG_QUICTCP_ALPN` | h3 | ALPN protocol for HTTP/3 mimicry |
| `WG_QUICTCP_IDLE_TIMEOUT` | 30s | Connection idle timeout |

## Manual Network Configuration

If auto-detect doesn't work, configure manually:

```bash
# Find your interface
ip link show

# Find your local IP
ip addr show eth0

# Find gateway IP
ip route | grep default

# Find gateway MAC (after pinging gateway)
ping -c 1 192.168.1.1
arp -a | grep 192.168.1.1

# Configure
export WG_QUICTCP_INTERFACE=eth0
export WG_QUICTCP_LOCAL_IP=192.168.1.100
export WG_QUICTCP_ROUTER_MAC=aa:bb:cc:dd:ee:ff
```

## How It Works

```
Client                                           Server
  │                                                │
  │  WireGuard Packet                              │
  │       │                                        │
  │       ▼                                        │
  │  ┌─────────┐                                   │
  │  │  QUIC   │ ◄── TLS 1.3 + h3 ALPN            │
  │  │ Stream  │                                   │
  │  └────┬────┘                                   │
  │       ▼                                        │
  │  ┌─────────┐     Looks like                    │
  │  │Raw TCP  │ ──────────────────────────────────┼──► DPI sees HTTPS
  │  │Packets  │     HTTP/3 traffic                │
  │  └────┬────┘                                   │
  │       ▼                                        │
  └───[ Network ]──────────────────────────────────┘
```

## Troubleshooting

### "Permission denied"
Run with `sudo` - raw sockets require root privileges.

### No packets received
1. Check BPF filter is working: `sudo tcpdump -i eth0 tcp port 443`
2. Verify gateway MAC is correct: `arp -a`

### Connection refused / timeout
Server-side: ensure iptables RST rule is applied.

### High CPU usage
Increase socket buffer: `WG_QUICTCP_SOCKET_BUFFER=16777216` (16MB)

### Debugging
```bash
# Enable verbose logging
export LOG_LEVEL=verbose

# Capture packets
sudo tcpdump -i eth0 -nn -X 'tcp port 443'
```

## Security Notes

1. **Shared Key**: The `WG_QUICTCP_KEY` generates deterministic TLS certificates. Both client and server derive identical certificates, eliminating certificate distribution.

2. **Double Encryption**: Traffic is encrypted by both WireGuard and TLS 1.3.

3. **Root Required**: Raw socket access requires elevated privileges. This is unavoidable for DPI bypass.

4. **Port 443**: Using port 443 is recommended as it's the standard HTTPS port and least likely to be blocked.
