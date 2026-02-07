/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"time"
)

// Direction specifies which direction of packets to capture.
type Direction int

const (
	DirectionIn    Direction = iota // Capture incoming packets only
	DirectionOut                    // Capture outgoing packets only
	DirectionInOut                  // Capture both directions
)

// CaptureInfo contains metadata about a captured packet.
type CaptureInfo struct {
	// Timestamp is the time the packet was captured.
	Timestamp time.Time
	// CaptureLength is the number of bytes captured.
	CaptureLength int
	// Length is the original packet length.
	Length int
}

// RawHandle abstracts raw packet capture backends (pcap or AF_PACKET).
type RawHandle interface {
	// ZeroCopyReadPacketData reads a packet without copying.
	// The returned slice is only valid until the next read.
	ZeroCopyReadPacketData() ([]byte, CaptureInfo, error)

	// ReadPacketData reads a packet and returns a copy.
	ReadPacketData() ([]byte, CaptureInfo, error)

	// WritePacketData writes a raw packet to the network.
	WritePacketData(data []byte) error

	// SetBPFFilter sets a BPF filter on the handle.
	SetBPFFilter(filter string) error

	// SetDirection sets which direction of packets to capture.
	SetDirection(dir Direction) error

	// Close releases resources.
	Close()

	// Stats returns capture statistics.
	Stats() (*CaptureStats, error)
}

// CaptureStats contains packet capture statistics.
type CaptureStats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsIfDropped uint64
}
