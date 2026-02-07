//go:build !linux || cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// PcapHandle wraps a pcap handle for raw packet capture/injection.
type PcapHandle struct {
	handle *pcap.Handle
	closed atomic.Bool
}

// NewPcapHandle creates a new pcap-based raw handle.
func NewPcapHandle(cfg *Config) (*PcapHandle, error) {
	var deviceName string

	if runtime.GOOS == "windows" && cfg.GUID != "" {
		// Windows uses device GUID
		deviceName = "\\Device\\NPF_" + cfg.GUID
	} else {
		deviceName = cfg.Interface
	}

	// Set snapshot length to capture full packets
	const snapLen = 65535

	// Set promiscuous mode to capture all packets
	const promisc = true

	// Set timeout for reads - this is a poll timeout, not an error condition.
	// We use a short timeout so we can check for close and retry.
	const timeout = 100 * time.Millisecond

	// Create inactive handle first to set buffer size before activation
	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive handle on %s: %w", deviceName, err)
	}

	if err := inactive.SetSnapLen(snapLen); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("failed to set snap length: %w", err)
	}

	if err := inactive.SetPromisc(promisc); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("failed to set promiscuous mode: %w", err)
	}

	if err := inactive.SetTimeout(timeout); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("failed to set timeout: %w", err)
	}

	// Enable immediate mode for low latency (important for QUIC handshake)
	if err := inactive.SetImmediateMode(true); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("failed to set immediate mode: %w", err)
	}

	// Set buffer size if specified
	if cfg.SocketBuffer > 0 {
		if err := inactive.SetBufferSize(cfg.SocketBuffer); err != nil {
			inactive.CleanUp()
			return nil, fmt.Errorf("failed to set buffer size: %w", err)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("failed to activate pcap handle: %w", err)
	}

	return &PcapHandle{handle: handle}, nil
}

// isPcapTimeout checks if the error is a pcap timeout (not a real error).
func isPcapTimeout(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// pcap returns "Timeout Expired" on macOS/BSD, other variants on Linux
	return strings.Contains(errStr, "Timeout") ||
		strings.Contains(errStr, "timeout") ||
		errStr == "read timeout"
}

// ZeroCopyReadPacketData reads a packet without copying.
// This function blocks until a packet is available or the handle is closed.
// Pcap timeouts are handled internally by retrying.
func (h *PcapHandle) ZeroCopyReadPacketData() ([]byte, CaptureInfo, error) {
	for {
		if h.closed.Load() {
			return nil, CaptureInfo{}, fmt.Errorf("handle closed")
		}

		data, ci, err := h.handle.ZeroCopyReadPacketData()
		if err != nil {
			// Timeout is not an error - just means no packet available yet.
			// Retry the read.
			if isPcapTimeout(err) {
				continue
			}
			return nil, CaptureInfo{}, err
		}

		info := CaptureInfo{
			Timestamp:     ci.Timestamp,
			CaptureLength: ci.CaptureLength,
			Length:        ci.Length,
		}

		return data, info, nil
	}
}

// ReadPacketData reads a packet and returns a copy.
// This function blocks until a packet is available or the handle is closed.
func (h *PcapHandle) ReadPacketData() ([]byte, CaptureInfo, error) {
	for {
		if h.closed.Load() {
			return nil, CaptureInfo{}, fmt.Errorf("handle closed")
		}

		data, ci, err := h.handle.ReadPacketData()
		if err != nil {
			// Timeout is not an error - just means no packet available yet.
			if isPcapTimeout(err) {
				continue
			}
			return nil, CaptureInfo{}, err
		}

		info := CaptureInfo{
			Timestamp:     ci.Timestamp,
			CaptureLength: ci.CaptureLength,
			Length:        ci.Length,
		}

		return data, info, nil
	}
}

// WritePacketData writes a raw packet to the network.
func (h *PcapHandle) WritePacketData(data []byte) error {
	return h.handle.WritePacketData(data)
}

// SetBPFFilter sets a BPF filter on the handle.
func (h *PcapHandle) SetBPFFilter(filter string) error {
	return h.handle.SetBPFFilter(filter)
}

// SetDirection sets which direction of packets to capture.
func (h *PcapHandle) SetDirection(dir Direction) error {
	var pcapDir pcap.Direction
	switch dir {
	case DirectionIn:
		pcapDir = pcap.DirectionIn
	case DirectionOut:
		pcapDir = pcap.DirectionOut
	case DirectionInOut:
		pcapDir = pcap.DirectionInOut
	default:
		return fmt.Errorf("invalid direction: %d", dir)
	}
	return h.handle.SetDirection(pcapDir)
}

// Close releases resources.
func (h *PcapHandle) Close() {
	h.closed.Store(true)
	if h.handle != nil {
		h.handle.Close()
	}
}

// Stats returns capture statistics.
func (h *PcapHandle) Stats() (*CaptureStats, error) {
	stats, err := h.handle.Stats()
	if err != nil {
		return nil, err
	}
	return &CaptureStats{
		PacketsReceived:  uint64(stats.PacketsReceived),
		PacketsDropped:   uint64(stats.PacketsDropped),
		PacketsIfDropped: uint64(stats.PacketsIfDropped),
	}, nil
}

// Verify interface compliance
var _ RawHandle = (*PcapHandle)(nil)
