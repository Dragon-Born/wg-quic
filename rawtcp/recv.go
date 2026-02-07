/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// RecvHandle captures incoming TCP packets and extracts payloads.
type RecvHandle struct {
	handle RawHandle

	// Reusable layer storage for efficient parsing.
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// NewRecvHandle creates a new receive handle for packet capture.
func NewRecvHandle(cfg *Config, handle RawHandle) (*RecvHandle, error) {
	// Set direction to incoming only.
	if err := handle.SetDirection(DirectionIn); err != nil {
		// Non-fatal on some platforms.
	}

	// Set BPF filter based on mode:
	// Both modes filter by DESTINATION port (our local port)
	// This ensures we only capture packets meant for us, not all port 443 traffic
	// Server: captures incoming client requests to our port
	// Client: captures server responses to our ephemeral port
	filter := fmt.Sprintf("tcp and dst port %d", cfg.LocalPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	h := &RecvHandle{
		handle:  handle,
		decoded: make([]gopacket.LayerType, 0, 4),
	}

	// Create efficient layer parser.
	h.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&h.eth, &h.ipv4, &h.ipv6, &h.tcp,
	)
	h.parser.IgnoreUnsupported = true

	return h, nil
}

// Read reads the next packet and returns the payload and source address.
// Returns (nil, addr, nil) for packets with no payload (e.g., ACKs).
// NOTE: The returned payload and srcIP are references to internal buffers that will be
// overwritten on the next call. Callers must copy the data if they need to retain it.
func (h *RecvHandle) Read() (payload []byte, srcIP net.IP, srcPort uint16, err error) {
	data, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}

	h.decoded = h.decoded[:0]
	h.parser.DecodeLayers(data, &h.decoded)

	// Extract source IP from parsed layers.
	var parsedSrcIP net.IP
	for _, typ := range h.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			parsedSrcIP = h.ipv4.SrcIP
		case layers.LayerTypeIPv6:
			parsedSrcIP = h.ipv6.SrcIP
		case layers.LayerTypeTCP:
			srcPort = uint16(h.tcp.SrcPort)
		}
	}

	// Make a copy of the source IP to prevent corruption when the next packet is parsed.
	if parsedSrcIP != nil {
		srcIP = make(net.IP, len(parsedSrcIP))
		copy(srcIP, parsedSrcIP)
	}

	return h.tcp.Payload, srcIP, srcPort, nil
}

func formatTCPFlags(tcp *layers.TCP) string {
	var s string
	if tcp.SYN {
		s += "S"
	}
	if tcp.ACK {
		s += "A"
	}
	if tcp.PSH {
		s += "P"
	}
	if tcp.FIN {
		s += "F"
	}
	if tcp.RST {
		s += "R"
	}
	if s == "" {
		s = "."
	}
	return s
}

// ReadCopy is like Read but returns a copy of the payload.
func (h *RecvHandle) ReadCopy() (payload []byte, srcIP net.IP, srcPort uint16, err error) {
	p, ip, port, err := h.Read()
	if err != nil {
		return nil, nil, 0, err
	}

	if len(p) > 0 {
		payload = make([]byte, len(p))
		copy(payload, p)
	}

	// Make a copy of IP too since it references internal buffer
	if ip != nil {
		srcIP = make(net.IP, len(ip))
		copy(srcIP, ip)
	}

	return payload, srcIP, port, nil
}

// Close releases resources.
func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}

// Stats returns capture statistics.
func (h *RecvHandle) Stats() (*CaptureStats, error) {
	return h.handle.Stats()
}
