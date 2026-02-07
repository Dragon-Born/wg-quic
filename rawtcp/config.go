/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// randIntn returns a random int in [0, n).
func randIntn(n int) int {
	var b [4]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:])) % n
}

// Config holds raw TCP socket configuration.
type Config struct {
	// Interface is the network interface name (e.g., "eth0", "en0").
	Interface string

	// GUID is the Windows Npcap device GUID (Windows only).
	GUID string

	// LocalIPv4 is the local IPv4 address.
	LocalIPv4 net.IP

	// LocalIPv6 is the local IPv6 address (optional).
	LocalIPv6 net.IP

	// LocalPort is the local port for raw TCP.
	// For server: the listening port (e.g., 443).
	// For client: the source port (0 = ephemeral, auto-assigned).
	LocalPort uint16

	// ServerPort is the server's port we're connecting to (client mode only).
	// Used for BPF filter to capture server responses.
	// Default: 443.
	ServerPort uint16

	// IsServer indicates whether this is server mode.
	// Server mode: listen on LocalPort, filter on dst port LocalPort.
	// Client mode: use ephemeral source port, filter on src port ServerPort.
	IsServer bool

	// RouterMAC is the gateway/router MAC address (required for injection).
	RouterMAC net.HardwareAddr

	// RouterMACv6 is the IPv6 gateway MAC (optional, defaults to RouterMAC).
	RouterMACv6 net.HardwareAddr

	// LocalMAC is the local interface MAC address.
	LocalMAC net.HardwareAddr

	// SocketBuffer is the pcap/AF_PACKET buffer size in bytes.
	// Default: 4MB for client, 16MB for server.
	SocketBuffer int

	// TCPFlags is the list of TCP flag combinations to cycle through.
	// Default: ["PA"] (PSH+ACK, standard data packets).
	TCPFlags []TCPFlags

	// Backend specifies the capture backend: "auto", "pcap", "afpacket".
	// Default: "auto" (tries AF_PACKET first on Linux, then pcap).
	Backend string
}

// TCPFlags represents a combination of TCP flags.
type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

// ParseTCPFlags parses a string like "PA" into TCPFlags.
func ParseTCPFlags(s string) (TCPFlags, error) {
	var f TCPFlags
	for _, ch := range s {
		switch ch {
		case 'F':
			f.FIN = true
		case 'S':
			f.SYN = true
		case 'R':
			f.RST = true
		case 'P':
			f.PSH = true
		case 'A':
			f.ACK = true
		case 'U':
			f.URG = true
		case 'E':
			f.ECE = true
		case 'C':
			f.CWR = true
		case 'N':
			f.NS = true
		default:
			return f, fmt.Errorf("invalid TCP flag '%c'", ch)
		}
	}
	return f, nil
}

// ParseTCPFlagsList parses a comma-separated list of flag strings.
func ParseTCPFlagsList(flags []string) ([]TCPFlags, error) {
	result := make([]TCPFlags, 0, len(flags))
	for _, s := range flags {
		f, err := ParseTCPFlags(s)
		if err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, nil
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		SocketBuffer: 4 * 1024 * 1024,                    // 4MB
		TCPFlags:     []TCPFlags{{PSH: true, ACK: true}}, // PA
		Backend:      "auto",
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Interface == "" && c.GUID == "" {
		return fmt.Errorf("either Interface or GUID must be specified")
	}
	if c.LocalIPv4 == nil && c.LocalIPv6 == nil {
		return fmt.Errorf("at least one of LocalIPv4 or LocalIPv6 must be specified")
	}
	// For client mode (IsServer=false): auto-assign ephemeral port if not specified
	// For server mode: LocalPort is required
	if c.LocalPort == 0 {
		if c.IsServer {
			return fmt.Errorf("LocalPort must be specified for server mode")
		}
		// Client mode: assign random ephemeral port (32768-65535)
		c.LocalPort = uint16(32768 + randIntn(32768))
	}
	if c.RouterMAC == nil {
		return fmt.Errorf("RouterMAC must be specified")
	}
	if c.LocalMAC == nil {
		return fmt.Errorf("LocalMAC must be specified")
	}
	return nil
}
