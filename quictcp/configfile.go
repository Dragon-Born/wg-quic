/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/rawtcp"
)

// ConfigFile represents a QUIC-TCP configuration file.
// The file format is INI-style:
//
//	[QuicTcp]
//	Enabled = true
//	Key = shared-secret
//	Server = vpn.example.com:443
//	...
type ConfigFile struct {
	path string
}

// Config file keys (case-insensitive)
const (
	cfgKeyEnabled      = "enabled"
	cfgKeyInterface    = "interface"
	cfgKeyLocalIP      = "localip"
	cfgKeyLocalPort    = "localport"
	cfgKeyRouterMAC    = "routermac"
	cfgKeyKey          = "key"
	cfgKeyServer       = "server"
	cfgKeyIsServer     = "isserver"
	cfgKeyBackend      = "backend"
	cfgKeySocketBuffer = "socketbuffer"
	cfgKeyTCPFlags     = "tcpflags"
	cfgKeyALPN         = "alpn"
	cfgKeyIdleTimeout  = "idletimeout"
	cfgKeyAutoDetect   = "autodetect"
	cfgKeyNumStreams   = "numstreams"
	cfgKeyNumConns     = "numconns"
)

// DefaultConfigPaths returns the default paths to look for config files.
func DefaultConfigPaths(interfaceName string) []string {
	return []string{
		fmt.Sprintf("/etc/wireguard/%s.quictcp.conf", interfaceName),
		fmt.Sprintf("/etc/wireguard/%s.quictcp", interfaceName),
		filepath.Join(os.Getenv("HOME"), ".config", "wireguard", fmt.Sprintf("%s.quictcp.conf", interfaceName)),
	}
}

// FindConfigFile looks for a config file in default locations.
func FindConfigFile(interfaceName string) string {
	// Check environment variable first
	if path := os.Getenv("WG_QUICTCP_CONFIG"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Check default paths
	for _, path := range DefaultConfigPaths(interfaceName) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// LoadConfigFile loads QUIC-TCP configuration from a file.
// Returns nil if the file doesn't exist or QUIC-TCP is not enabled.
func LoadConfigFile(path string) (*EnvConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	cfg := &EnvConfig{
		RawConfig:  rawtcp.DefaultConfig(),
		QUICConfig: DefaultQUICConfig(),
	}

	scanner := bufio.NewScanner(file)
	inSection := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.Trim(line, "[]"))
			inSection = section == "quictcp" || section == "quic-tcp" || section == "quic"
			continue
		}

		// Only process lines in the [QuicTcp] section
		if !inSection {
			continue
		}

		// Parse key=value
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: invalid format (expected key=value)", lineNum)
		}

		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		// Remove quotes if present
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}

		if err := applyConfigValue(cfg, key, value); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// If not enabled, return nil
	if !cfg.Enabled {
		return nil, nil
	}

	// Apply auto-detection if enabled
	if cfg.RawConfig.Interface == "" && cfg.RawConfig.LocalIPv4 == nil {
		// Auto-detect was not explicitly set, try it
		detected, err := rawtcp.DetectNetworkConfig()
		if err == nil {
			if cfg.RawConfig.Interface == "" {
				cfg.RawConfig.Interface = detected.Interface
				cfg.RawConfig.LocalMAC = detected.LocalMAC
			}
			if cfg.RawConfig.LocalIPv4 == nil {
				cfg.RawConfig.LocalIPv4 = detected.LocalIPv4
			}
			if cfg.RawConfig.RouterMAC == nil {
				cfg.RawConfig.RouterMAC = detected.RouterMAC
			}
		}
	}

	// Validate
	if err := cfg.RawConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid raw TCP config: %w", err)
	}
	if err := cfg.QUICConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}

	// Check required fields for client mode
	if !cfg.IsServer && cfg.ServerAddr == nil {
		return nil, fmt.Errorf("Server is required in client mode")
	}

	return cfg, nil
}

func applyConfigValue(cfg *EnvConfig, key, value string) error {
	switch key {
	case cfgKeyEnabled:
		cfg.Enabled = parseBool(value)

	case cfgKeyInterface:
		cfg.RawConfig.Interface = value
		// Also get MAC address from interface
		if iface, err := net.InterfaceByName(value); err == nil && iface.HardwareAddr != nil {
			cfg.RawConfig.LocalMAC = iface.HardwareAddr
		}

	case cfgKeyLocalIP:
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", value)
		}
		if ip.To4() != nil {
			cfg.RawConfig.LocalIPv4 = ip.To4()
		} else {
			cfg.RawConfig.LocalIPv6 = ip
		}

	case cfgKeyLocalPort:
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port: %s", value)
		}
		cfg.RawConfig.LocalPort = uint16(port)

	case cfgKeyRouterMAC:
		mac, err := net.ParseMAC(value)
		if err != nil {
			return fmt.Errorf("invalid MAC address: %s", value)
		}
		cfg.RawConfig.RouterMAC = mac

	case cfgKeyKey:
		cfg.QUICConfig.Key = value

	case cfgKeyServer:
		addr, err := net.ResolveUDPAddr("udp", value)
		if err != nil {
			return fmt.Errorf("invalid server address: %s", value)
		}
		cfg.ServerAddr = addr

	case cfgKeyIsServer:
		cfg.IsServer = parseBool(value)
		cfg.RawConfig.IsServer = cfg.IsServer // Propagate to RawConfig for validation

	case cfgKeyBackend:
		cfg.RawConfig.Backend = value

	case cfgKeySocketBuffer:
		size, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid socket buffer size: %s", value)
		}
		cfg.RawConfig.SocketBuffer = int(size)

	case cfgKeyTCPFlags:
		flagStrs := strings.Split(value, ",")
		for i := range flagStrs {
			flagStrs[i] = strings.TrimSpace(flagStrs[i])
		}
		flags, err := rawtcp.ParseTCPFlagsList(flagStrs)
		if err != nil {
			return fmt.Errorf("invalid TCP flags: %w", err)
		}
		cfg.RawConfig.TCPFlags = flags

	case cfgKeyALPN:
		cfg.QUICConfig.ALPN = value

	case cfgKeyIdleTimeout:
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid idle timeout: %s", value)
		}
		cfg.QUICConfig.IdleTimeout = d

	case cfgKeyNumStreams:
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid number of streams: %s", value)
		}
		cfg.QUICConfig.NumStreams = n

	case cfgKeyNumConns:
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid number of connections: %s", value)
		}
		cfg.QUICConfig.NumConns = n

	case cfgKeyAutoDetect:
		if parseBool(value) {
			detected, err := rawtcp.DetectNetworkConfig()
			if err != nil {
				return fmt.Errorf("auto-detect failed: %w", err)
			}
			cfg.RawConfig.Interface = detected.Interface
			cfg.RawConfig.LocalMAC = detected.LocalMAC
			cfg.RawConfig.LocalIPv4 = detected.LocalIPv4
			cfg.RawConfig.LocalIPv6 = detected.LocalIPv6
			cfg.RawConfig.RouterMAC = detected.RouterMAC
		}

	default:
		// Ignore unknown keys for forward compatibility
	}

	return nil
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "yes" || s == "1" || s == "on"
}

// WriteExampleConfig writes an example config file to the given path.
func WriteExampleConfig(path string) error {
	example := `# QUIC-over-Raw-TCP Configuration
# Place this file at /etc/wireguard/<interface>.quictcp.conf
# Or set WG_QUICTCP_CONFIG environment variable

[QuicTcp]
# Enable QUIC-TCP mode (required)
Enabled = true

# Shared secret for TLS certificate generation (required)
# Both client and server must use the same key
Key = your-shared-secret-here

# Server address (required for client mode)
# Server = vpn.example.com:443

# Server mode (set to true on the server)
# IsServer = false

# Auto-detect network settings (interface, local IP, gateway MAC)
# Set to true to auto-detect, or configure manually below
AutoDetect = true

# Network interface (e.g., eth0, en0)
# Interface = eth0

# Local IP address
# LocalIP = 192.168.1.100

# Local port (default: 443, recommended for DPI evasion)
LocalPort = 443

# Gateway/router MAC address (required for packet injection)
# RouterMAC = aa:bb:cc:dd:ee:ff

# Backend: auto, pcap, or afpacket (Linux only)
# Backend = auto

# Socket buffer size in bytes (default: 4MB)
# SocketBuffer = 4194304

# TCP flags to cycle through (default: PA = PSH+ACK)
# TCPFlags = PA, A

# ALPN protocol (default: h3 for HTTP/3 mimicry)
# ALPN = h3

# Connection idle timeout (default: 30s)
# IdleTimeout = 30s

# Number of parallel QUIC streams total (default: 64)
# Distributed evenly across connections. Must match on client and server.
# NumStreams = 64

# Number of parallel QUIC connections (default: 4)
# Each connection has independent congestion control for higher throughput.
# Must match on client and server.
# NumConns = 4
`
	return os.WriteFile(path, []byte(example), 0600)
}
