//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import "fmt"

// AFPacketHandle is not available on non-Linux platforms.
type AFPacketHandle struct{}

// NewAFPacketHandle returns an error on non-Linux platforms.
func NewAFPacketHandle(cfg *Config) (*AFPacketHandle, error) {
	return nil, fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) ZeroCopyReadPacketData() ([]byte, CaptureInfo, error) {
	return nil, CaptureInfo{}, fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) ReadPacketData() ([]byte, CaptureInfo, error) {
	return nil, CaptureInfo{}, fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) WritePacketData(data []byte) error {
	return fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) SetBPFFilter(filter string) error {
	return fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) SetDirection(dir Direction) error {
	return fmt.Errorf("AF_PACKET is only supported on Linux")
}

func (h *AFPacketHandle) Close() {}

func (h *AFPacketHandle) Stats() (*CaptureStats, error) {
	return nil, fmt.Errorf("AF_PACKET is only supported on Linux")
}
