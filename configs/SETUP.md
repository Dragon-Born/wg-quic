# WireGuard QUIC-TCP Setup Guide

This guide covers setting up wireguard-quic with QUIC-over-raw-TCP for DPI bypass.

## Server Setup (Linux)

### 1. Upload files to server

```bash
scp wireguard-quic-linux-amd64 root@<server-ip>:/usr/local/bin/wireguard-quic
scp configs/server/wg0.conf root@<server-ip>:/etc/wireguard/
scp configs/server/wg0.quictcp.conf root@<server-ip>:/etc/wireguard/
```

### 2. SSH to server and set up

```bash
ssh root@<server-ip>

# Make binary executable
chmod +x /usr/local/bin/wireguard-quic

# Set permissions on config files
chmod 600 /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.quictcp.conf

# Enable IP forwarding (if not already)
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
sysctl -p

# Stop existing WireGuard if running
wg-quick down wg0 2>/dev/null || true
```

### 3. Start WireGuard with QUIC-TCP

```bash
# First, add the RST block rule (CRITICAL!)
iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP

# Create the TUN interface manually
ip tuntap add dev wg0 mode tun
ip addr add 10.0.0.1/24 dev wg0
ip addr add fd00::1/64 dev wg0
ip link set wg0 up

# Start wireguard-quic
/usr/local/bin/wireguard-quic wg0

# Configure WireGuard
wg setconf wg0 /etc/wireguard/wg0.conf

# Set up NAT and forwarding
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I FORWARD -i eth0 -o wg0 -j ACCEPT
iptables -I FORWARD -i wg0 -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 4. Create systemd service (optional)

```bash
cat > /etc/systemd/system/wireguard-quic.service << 'EOF'
[Unit]
Description=WireGuard QUIC-TCP
After=network.target

[Service]
Type=simple
ExecStartPre=/sbin/iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
ExecStartPre=/sbin/ip tuntap add dev wg0 mode tun || true
ExecStartPre=/sbin/ip addr add 10.0.0.1/24 dev wg0 || true
ExecStartPre=/sbin/ip addr add fd00::1/64 dev wg0 || true
ExecStartPre=/sbin/ip link set wg0 up
ExecStart=/usr/local/bin/wireguard-quic -f wg0
ExecStartPost=/bin/sleep 1
ExecStartPost=/usr/bin/wg setconf wg0 /etc/wireguard/wg0.conf
ExecStartPost=/sbin/iptables -I INPUT -p tcp --dport 443 -j ACCEPT
ExecStartPost=/sbin/iptables -I FORWARD -i eth0 -o wg0 -j ACCEPT
ExecStartPost=/sbin/iptables -I FORWARD -i wg0 -j ACCEPT
ExecStartPost=/sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ExecStopPost=/sbin/iptables -D OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wireguard-quic
systemctl start wireguard-quic
```

## Client Setup (macOS)

### 1. Install the binary

```bash
sudo cp wireguard-quic-darwin-amd64 /usr/local/bin/wireguard-quic
sudo chmod +x /usr/local/bin/wireguard-quic

# Copy config files
sudo mkdir -p /etc/wireguard
sudo cp configs/client/wg0.conf /etc/wireguard/
sudo cp configs/client/wg0.quictcp.conf /etc/wireguard/
sudo chmod 600 /etc/wireguard/wg0.*
```

### 2. Start WireGuard

```bash
# Start wireguard-quic (requires root for raw sockets)
sudo /usr/local/bin/wireguard-quic wg0

# In another terminal, configure WireGuard
sudo wg setconf wg0 /etc/wireguard/wg0.conf

# Set up routing (optional - for full tunnel)
sudo route add -net 0.0.0.0/1 -interface wg0
sudo route add -net 128.0.0.0/1 -interface wg0
```

### 3. Alternative: Use wgq-quick

```bash
# One-command setup (handles interface, routing, DNS, RST blocking)
sudo wgq-quick up wg0

# Foreground mode (shows logs, Ctrl+C to stop)
sudo wgq-quick -f up wg0

# Tear down
sudo wgq-quick down wg0
```

### 4. Alternative: Use environment variables

If config file doesn't work, use environment variables:

```bash
export WG_QUICTCP_ENABLED=true
export WG_QUICTCP_KEY="<your-shared-secret-base64>"
export WG_QUICTCP_SERVER="<server-ip>:443"
export WG_QUICTCP_AUTO_DETECT=true

sudo -E /usr/local/bin/wireguard-quic wg0
sudo wg setconf wg0 /etc/wireguard/wg0.conf
```

## Verification

### Check server is listening

```bash
# On server
ss -tlnp | grep 443
# Should see wireguard-quic listening

# Check iptables rules
iptables -L OUTPUT -n | grep RST
# Should see: DROP tcp -- 0.0.0.0/0 0.0.0.0/0 tcp spt:443 flags:0x04/0x04
```

### Check client connection

```bash
# On client
ping 10.0.0.1
# Should get response from server

# Check WireGuard status
sudo wg show
```

## Troubleshooting

### "Permission denied" on client
- Run with `sudo` - raw sockets require root

### Connection timeout
1. Check server RST rule: `iptables -L OUTPUT -n | grep RST`
2. Check server is listening: `ss -tlnp | grep 443`
3. Check firewall allows port 443

### "afpacket: operation not permitted"
- Ensure running as root
- Check CAP_NET_RAW capability

### Auto-detect fails
Configure manually in the .quictcp.conf file:
```ini
Interface = eth0  # or en0 on macOS
LocalIP = <your-ip>
RouterMAC = <gateway-mac>  # Get with: arp -a | grep gateway
```

## Security Notes

1. **Shared Key**: The `Key` in quictcp.conf generates TLS certificates. Keep it secret!
2. **Port 443**: Using HTTPS port makes traffic look like normal web browsing
3. **Double Encryption**: Traffic is encrypted by both WireGuard AND TLS 1.3
