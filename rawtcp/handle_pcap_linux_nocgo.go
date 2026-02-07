//go:build linux && !cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import "fmt"

// PcapHandle is not available on Linux without CGO.
// Use AF_PACKET backend instead.
type PcapHandle struct{}

// NewPcapHandle returns an error on Linux without CGO.
// The AF_PACKET backend should be used instead.
func NewPcapHandle(cfg *Config) (*PcapHandle, error) {
	return nil, fmt.Errorf("pcap is not available without CGO on Linux; use afpacket backend or set Backend=afpacket")
}

func (h *PcapHandle) ZeroCopyReadPacketData() ([]byte, CaptureInfo, error) {
	return nil, CaptureInfo{}, fmt.Errorf("pcap not available")
}

func (h *PcapHandle) ReadPacketData() ([]byte, CaptureInfo, error) {
	return nil, CaptureInfo{}, fmt.Errorf("pcap not available")
}

func (h *PcapHandle) WritePacketData(data []byte) error {
	return fmt.Errorf("pcap not available")
}

func (h *PcapHandle) SetBPFFilter(filter string) error {
	return fmt.Errorf("pcap not available")
}

func (h *PcapHandle) SetDirection(dir Direction) error {
	return fmt.Errorf("pcap not available")
}

func (h *PcapHandle) Close() {}

func (h *PcapHandle) Stats() (*CaptureStats, error) {
	return nil, fmt.Errorf("pcap not available")
}

// Verify interface compliance
var _ RawHandle = (*PcapHandle)(nil)
