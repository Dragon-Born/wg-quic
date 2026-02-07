/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/rawtcp"
)

// Environment variable names
const (
	EnvEnabled      = "WG_QUICTCP_ENABLED"
	EnvInterface    = "WG_QUICTCP_INTERFACE"
	EnvLocalIP      = "WG_QUICTCP_LOCAL_IP"
	EnvLocalPort    = "WG_QUICTCP_LOCAL_PORT"
	EnvRouterMAC    = "WG_QUICTCP_ROUTER_MAC"
	EnvKey          = "WG_QUICTCP_KEY"
	EnvServer       = "WG_QUICTCP_SERVER"
	EnvIsServer     = "WG_QUICTCP_IS_SERVER"
	EnvBackend      = "WG_QUICTCP_BACKEND"
	EnvSocketBuffer = "WG_QUICTCP_SOCKET_BUFFER"
	EnvTCPFlags     = "WG_QUICTCP_TCP_FLAGS"
	EnvALPN         = "WG_QUICTCP_ALPN"
	EnvIdleTimeout  = "WG_QUICTCP_IDLE_TIMEOUT"
	EnvAutoDetect   = "WG_QUICTCP_AUTO_DETECT"
	EnvNumStreams   = "WG_QUICTCP_NUM_STREAMS"
	EnvNumConns     = "WG_QUICTCP_NUM_CONNS"
)

// EnvConfig holds configuration loaded from environment variables.
type EnvConfig struct {
	Enabled    bool
	RawConfig  *rawtcp.Config
	QUICConfig *QUICConfig
	IsServer   bool
	ServerAddr *net.UDPAddr
}

// IsEnabled checks if QUIC-TCP mode is enabled via environment or config file.
func IsEnabled() bool {
	// Check environment variable
	if strings.ToLower(os.Getenv(EnvEnabled)) == "true" || os.Getenv(EnvEnabled) == "1" {
		return true
	}

	// Check if a config file exists (will be parsed later)
	if os.Getenv("WG_QUICTCP_CONFIG") != "" {
		return true
	}

	return false
}

// IsEnabledForInterface checks if QUIC-TCP is enabled for a specific interface.
func IsEnabledForInterface(interfaceName string) bool {
	if IsEnabled() {
		return true
	}

	// Check if a config file exists for this interface
	if FindConfigFile(interfaceName) != "" {
		return true
	}

	return false
}

// LoadConfig loads configuration from config file or environment variables.
// It first tries to load from a config file, then falls back to environment variables.
func LoadConfig(interfaceName string) (*EnvConfig, error) {
	// Try config file first
	if configPath := FindConfigFile(interfaceName); configPath != "" {
		cfg, err := LoadConfigFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("config file error: %w", err)
		}
		if cfg != nil {
			return cfg, nil
		}
	}

	// Fall back to environment variables
	return LoadFromEnv()
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() (*EnvConfig, error) {
	if !IsEnabled() {
		return nil, nil
	}

	cfg := &EnvConfig{
		Enabled:    true,
		RawConfig:  rawtcp.DefaultConfig(),
		QUICConfig: DefaultQUICConfig(),
	}

	// Check if auto-detect is enabled
	if strings.ToLower(os.Getenv(EnvAutoDetect)) == "true" || os.Getenv(EnvAutoDetect) == "1" {
		detected, err := rawtcp.DetectNetworkConfig()
		if err != nil {
			return nil, fmt.Errorf("auto-detect failed: %w", err)
		}
		cfg.RawConfig = detected
	}

	// Interface
	if v := os.Getenv(EnvInterface); v != "" {
		cfg.RawConfig.Interface = v
		// Also get MAC address from interface
		iface, err := net.InterfaceByName(v)
		if err == nil && iface.HardwareAddr != nil {
			cfg.RawConfig.LocalMAC = iface.HardwareAddr
		}
	}

	// Local IP
	if v := os.Getenv(EnvLocalIP); v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvLocalIP, v)
		}
		if ip.To4() != nil {
			cfg.RawConfig.LocalIPv4 = ip.To4()
		} else {
			cfg.RawConfig.LocalIPv6 = ip
		}
	}

	// Local Port
	if v := os.Getenv(EnvLocalPort); v != "" {
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvLocalPort, v)
		}
		cfg.RawConfig.LocalPort = uint16(port)
	}

	// Router MAC
	if v := os.Getenv(EnvRouterMAC); v != "" {
		mac, err := net.ParseMAC(v)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvRouterMAC, v)
		}
		cfg.RawConfig.RouterMAC = mac
	}

	// Backend
	if v := os.Getenv(EnvBackend); v != "" {
		cfg.RawConfig.Backend = v
	}

	// Socket Buffer
	if v := os.Getenv(EnvSocketBuffer); v != "" {
		size, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvSocketBuffer, v)
		}
		cfg.RawConfig.SocketBuffer = int(size)
	}

	// TCP Flags
	if v := os.Getenv(EnvTCPFlags); v != "" {
		flagStrs := strings.Split(v, ",")
		flags, err := rawtcp.ParseTCPFlagsList(flagStrs)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", EnvTCPFlags, err)
		}
		cfg.RawConfig.TCPFlags = flags
	}

	// QUIC Key (required)
	if v := os.Getenv(EnvKey); v != "" {
		cfg.QUICConfig.Key = v
	} else {
		return nil, fmt.Errorf("%s is required when QUIC-TCP is enabled", EnvKey)
	}

	// ALPN
	if v := os.Getenv(EnvALPN); v != "" {
		cfg.QUICConfig.ALPN = v
	}

	// NumStreams
	if v := os.Getenv(EnvNumStreams); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvNumStreams, v)
		}
		cfg.QUICConfig.NumStreams = n
	}

	// NumConns
	if v := os.Getenv(EnvNumConns); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvNumConns, v)
		}
		cfg.QUICConfig.NumConns = n
	}

	// Idle Timeout
	if v := os.Getenv(EnvIdleTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %s", EnvIdleTimeout, v)
		}
		cfg.QUICConfig.IdleTimeout = d
	}

	// Is Server
	cfg.IsServer = strings.ToLower(os.Getenv(EnvIsServer)) == "true" ||
		os.Getenv(EnvIsServer) == "1"
	cfg.RawConfig.IsServer = cfg.IsServer // Propagate to RawConfig for validation

	// Server Address (for client mode)
	if !cfg.IsServer {
		if v := os.Getenv(EnvServer); v != "" {
			addr, err := net.ResolveUDPAddr("udp", v)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %s", EnvServer, v)
			}
			cfg.ServerAddr = addr
		} else {
			return nil, fmt.Errorf("%s is required in client mode", EnvServer)
		}
	}

	// Validate configurations
	if err := cfg.RawConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid raw TCP config: %w", err)
	}
	if err := cfg.QUICConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}

	return cfg, nil
}

// PrintEnvHelp prints environment variable help to stderr.
func PrintEnvHelp() {
	help := `
QUIC-over-Raw-TCP Environment Variables:

Required:
  WG_QUICTCP_ENABLED=true       Enable QUIC-TCP mode
  WG_QUICTCP_KEY=<secret>       Shared secret for TLS certificates

Network Configuration (auto-detected if WG_QUICTCP_AUTO_DETECT=true):
  WG_QUICTCP_INTERFACE=eth0     Network interface name
  WG_QUICTCP_LOCAL_IP=x.x.x.x   Local IP address
  WG_QUICTCP_LOCAL_PORT=443     Local port (default: 443)
  WG_QUICTCP_ROUTER_MAC=aa:bb:cc:dd:ee:ff  Gateway MAC address

Mode:
  WG_QUICTCP_IS_SERVER=false    Server mode (true) or client mode (false)
  WG_QUICTCP_SERVER=host:port   Server address (client mode only)

Optional:
  WG_QUICTCP_AUTO_DETECT=true   Auto-detect network settings
  WG_QUICTCP_BACKEND=auto       Backend: auto, pcap, afpacket
  WG_QUICTCP_SOCKET_BUFFER=4194304  Socket buffer size (bytes)
  WG_QUICTCP_TCP_FLAGS=PA,A     TCP flags to cycle through
  WG_QUICTCP_ALPN=h3            ALPN protocol (default: h3 for HTTP/3)
  WG_QUICTCP_IDLE_TIMEOUT=30s   Connection idle timeout
  WG_QUICTCP_NUM_STREAMS=64     Total parallel QUIC streams
  WG_QUICTCP_NUM_CONNS=4        Number of parallel QUIC connections

Example (Client):
  export WG_QUICTCP_ENABLED=true
  export WG_QUICTCP_AUTO_DETECT=true
  export WG_QUICTCP_KEY=my-secret-key
  export WG_QUICTCP_SERVER=vpn.example.com:443

Example (Server):
  export WG_QUICTCP_ENABLED=true
  export WG_QUICTCP_AUTO_DETECT=true
  export WG_QUICTCP_KEY=my-secret-key
  export WG_QUICTCP_IS_SERVER=true
  export WG_QUICTCP_LOCAL_PORT=443
`
	fmt.Fprintln(os.Stderr, help)
}
