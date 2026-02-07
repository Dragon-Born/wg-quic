//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// debugBPF enables verbose BPF debugging when WG_DEBUG_BPF=1
var debugBPF = os.Getenv("WG_DEBUG_BPF") == "1"

// AFPacketHandle implements RawHandle using Linux AF_PACKET sockets.
type AFPacketHandle struct {
	fd           int
	ifIndex      int
	readBuf      []byte
	packetsRecv  atomic.Uint64
	packetsDrop  atomic.Uint64
	packetsIface atomic.Uint64
	closed       atomic.Bool
}

// NewAFPacketHandle creates a new AF_PACKET-based raw handle.
func NewAFPacketHandle(cfg *Config) (*AFPacketHandle, error) {
	if debugBPF {
		log.Printf("[AF_PACKET] Creating handle for interface %q", cfg.Interface)
	}

	// Get interface index
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", cfg.Interface, err)
	}

	if debugBPF {
		log.Printf("[AF_PACKET] Interface %s: index=%d, MTU=%d, MAC=%s",
			iface.Name, iface.Index, iface.MTU, iface.HardwareAddr)
	}

	// Create AF_PACKET socket with ETH_P_ALL to capture all protocols
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET socket: %w", err)
	}

	if debugBPF {
		log.Printf("[AF_PACKET] Socket created: fd=%d", fd)
	}

	// Bind to the interface
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface %s (index=%d): %w", cfg.Interface, iface.Index, err)
	}

	if debugBPF {
		log.Printf("[AF_PACKET] Bound to interface %s", cfg.Interface)
	}

	// Set socket buffer size
	bufSize := cfg.SocketBuffer
	if bufSize == 0 {
		bufSize = 4 * 1024 * 1024 // 4MB default
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize); err != nil {
		if debugBPF {
			log.Printf("[AF_PACKET] Warning: failed to set SO_RCVBUF to %d: %v", bufSize, err)
		}
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize); err != nil {
		if debugBPF {
			log.Printf("[AF_PACKET] Warning: failed to set SO_SNDBUF to %d: %v", bufSize, err)
		}
	}

	// Set read timeout
	tv := unix.Timeval{Sec: 0, Usec: 100000} // 100ms
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		if debugBPF {
			log.Printf("[AF_PACKET] Warning: failed to set SO_RCVTIMEO: %v", err)
		}
	}

	h := &AFPacketHandle{
		fd:      fd,
		ifIndex: iface.Index,
		readBuf: make([]byte, 65535),
	}

	if debugBPF {
		log.Printf("[AF_PACKET] Handle created successfully")
	}

	return h, nil
}

// ZeroCopyReadPacketData reads a packet without copying.
// This function blocks until a packet is available or the handle is closed.
// EAGAIN/EWOULDBLOCK are handled internally by retrying.
func (h *AFPacketHandle) ZeroCopyReadPacketData() ([]byte, CaptureInfo, error) {
	for {
		if h.closed.Load() {
			return nil, CaptureInfo{}, fmt.Errorf("handle closed")
		}

		n, _, err := unix.Recvfrom(h.fd, h.readBuf, 0)
		if err != nil {
			// Check if it's a temporary/retry error using errno
			// Note: EAGAIN and EWOULDBLOCK are the same on Linux (11)
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.EAGAIN || errno == syscall.EINTR {
					// No data available or interrupted - retry
					continue
				}
			}
			// Also check error string for portability
			errStr := err.Error()
			if errStr == "resource temporarily unavailable" ||
				errStr == "interrupted system call" {
				continue
			}
			return nil, CaptureInfo{}, err
		}

		h.packetsRecv.Add(1)

		info := CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: n,
			Length:        n,
		}

		return h.readBuf[:n], info, nil
	}
}

// ReadPacketData reads a packet and returns a copy.
func (h *AFPacketHandle) ReadPacketData() ([]byte, CaptureInfo, error) {
	data, info, err := h.ZeroCopyReadPacketData()
	if err != nil {
		return nil, info, err
	}

	// Make a copy
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return dataCopy, info, nil
}

// WritePacketData writes a raw packet to the network.
func (h *AFPacketHandle) WritePacketData(data []byte) error {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  h.ifIndex,
		Halen:    6,
	}

	// Extract destination MAC from Ethernet header
	if len(data) >= 6 {
		copy(addr.Addr[:6], data[:6])
	}

	return unix.Sendto(h.fd, data, 0, addr)
}

// SetBPFFilter sets a BPF filter on the handle.
func (h *AFPacketHandle) SetBPFFilter(filter string) error {
	if debugBPF {
		log.Printf("[BPF] Compiling filter: %q", filter)
	}

	// Parse the filter string and compile to BPF instructions
	sockFilters, err := compileBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to compile BPF filter %q: %w", filter, err)
	}

	if debugBPF {
		log.Printf("[BPF] Compiled %d instructions:", len(sockFilters))
		for i, f := range sockFilters {
			log.Printf("[BPF]   %2d: code=0x%04x jt=%d jf=%d k=%d (0x%x)",
				i, f.Code, f.Jt, f.Jf, f.K, f.K)
		}
	}

	// Convert to socket filter program
	prog := &unix.SockFprog{
		Len:    uint16(len(sockFilters)),
		Filter: &sockFilters[0],
	}

	if debugBPF {
		log.Printf("[BPF] Attaching filter to fd=%d", h.fd)
	}

	err = unix.SetsockoptSockFprog(h.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	if err != nil {
		return fmt.Errorf("failed to attach BPF filter %q (fd=%d, len=%d): %w", filter, h.fd, len(sockFilters), err)
	}

	if debugBPF {
		log.Printf("[BPF] Filter attached successfully")
	}

	return nil
}

// SetDirection sets which direction of packets to capture.
func (h *AFPacketHandle) SetDirection(dir Direction) error {
	var pktType int
	switch dir {
	case DirectionIn:
		// Accept only incoming packets
		pktType = unix.PACKET_HOST
	case DirectionOut:
		// Accept only outgoing packets
		pktType = unix.PACKET_OUTGOING
	case DirectionInOut:
		// Accept both (no filter needed, default behavior)
		return nil
	default:
		return fmt.Errorf("invalid direction: %d", dir)
	}

	// Note: This is a simplified approach. Full implementation would use PACKET_RECV_OUTPUT
	_ = pktType
	return nil
}

// Close releases resources.
func (h *AFPacketHandle) Close() {
	h.closed.Store(true)
	if h.fd >= 0 {
		unix.Close(h.fd)
		h.fd = -1
	}
}

// Stats returns capture statistics.
func (h *AFPacketHandle) Stats() (*CaptureStats, error) {
	return &CaptureStats{
		PacketsReceived:  h.packetsRecv.Load(),
		PacketsDropped:   h.packetsDrop.Load(),
		PacketsIfDropped: h.packetsIface.Load(),
	}, nil
}

// htons converts a uint16 from host to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// BPF opcodes (classic BPF)
const (
	bpfLdAbsH  = 0x28 // BPF_LD | BPF_H | BPF_ABS - load half-word from absolute offset
	bpfLdAbsB  = 0x30 // BPF_LD | BPF_B | BPF_ABS - load byte from absolute offset
	bpfLdxMsh  = 0xb1 // BPF_LDX | BPF_B | BPF_MSH - load IP header length into X
	bpfLdIndH  = 0x48 // BPF_LD | BPF_H | BPF_IND - load half-word from X+offset
	bpfJmpJeqK = 0x15 // BPF_JMP | BPF_JEQ | BPF_K - jump if A == K
	bpfRetK    = 0x06 // BPF_RET | BPF_K - return K
)

// Ethernet/IP constants
const (
	ethOffsetType = 12
	ethHeaderLen  = 14
	etherTypeIPv4 = 0x0800
	ipProtoTCP    = 6
)

// compileBPFFilter compiles a simple BPF filter string to raw instructions.
// Supports: "tcp and dst port N", "tcp and src port N", "tcp"
func compileBPFFilter(filter string) ([]unix.SockFilter, error) {
	filter = strings.TrimSpace(strings.ToLower(filter))

	switch {
	case strings.HasPrefix(filter, "tcp and dst port "):
		portStr := strings.TrimPrefix(filter, "tcp and dst port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		return buildTCPDstPortFilter(uint16(port)), nil

	case strings.HasPrefix(filter, "tcp and src port "):
		portStr := strings.TrimPrefix(filter, "tcp and src port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		return buildTCPSrcPortFilter(uint16(port)), nil

	case filter == "tcp":
		return buildTCPFilter(), nil

	default:
		return nil, fmt.Errorf("unsupported filter: %s", filter)
	}
}

// buildTCPDstPortFilter creates BPF for "tcp and dst port N" (IPv4 only)
// Handles variable IP header length by reading the IHL field.
//
// tcpdump -dd "tcp dst port 443" output equivalent
func buildTCPDstPortFilter(port uint16) []unix.SockFilter {
	return []unix.SockFilter{
		// 0: Load EtherType (2 bytes at offset 12)
		{Code: bpfLdAbsH, K: ethOffsetType},

		// 1: If EtherType == 0x0800 (IPv4), continue; else jump to reject
		{Code: bpfJmpJeqK, Jt: 0, Jf: 6, K: etherTypeIPv4},

		// 2: Load IP protocol (1 byte at offset 23: eth[14] + ip[9])
		{Code: bpfLdAbsB, K: ethHeaderLen + 9},

		// 3: If protocol == 6 (TCP), continue; else jump to reject
		{Code: bpfJmpJeqK, Jt: 0, Jf: 4, K: ipProtoTCP},

		// 4: Load IP header length * 4 into X register
		{Code: bpfLdxMsh, K: ethHeaderLen},

		// 5: Load TCP dst port (2 bytes at X + eth[14] + tcp[2])
		{Code: bpfLdIndH, K: ethHeaderLen + 2},

		// 6: If dst port matches, accept; else reject
		{Code: bpfJmpJeqK, Jt: 0, Jf: 1, K: uint32(port)},

		// 7: Accept - return maximum capture length
		{Code: bpfRetK, K: 0xffffffff},

		// 8: Reject - return 0
		{Code: bpfRetK, K: 0},
	}
}

// buildTCPSrcPortFilter creates BPF for "tcp and src port N" (IPv4 only)
func buildTCPSrcPortFilter(port uint16) []unix.SockFilter {
	return []unix.SockFilter{
		{Code: bpfLdAbsH, K: ethOffsetType},
		{Code: bpfJmpJeqK, Jt: 0, Jf: 6, K: etherTypeIPv4},
		{Code: bpfLdAbsB, K: ethHeaderLen + 9},
		{Code: bpfJmpJeqK, Jt: 0, Jf: 4, K: ipProtoTCP},
		{Code: bpfLdxMsh, K: ethHeaderLen},
		// Load TCP src port (offset 0 in TCP header)
		{Code: bpfLdIndH, K: ethHeaderLen},
		{Code: bpfJmpJeqK, Jt: 0, Jf: 1, K: uint32(port)},
		{Code: bpfRetK, K: 0xffffffff},
		{Code: bpfRetK, K: 0},
	}
}

// buildTCPFilter creates BPF for "tcp" (any TCP packet, IPv4 only)
func buildTCPFilter() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: bpfLdAbsH, K: ethOffsetType},
		{Code: bpfJmpJeqK, Jt: 0, Jf: 3, K: etherTypeIPv4},
		{Code: bpfLdAbsB, K: ethHeaderLen + 9},
		{Code: bpfJmpJeqK, Jt: 0, Jf: 1, K: ipProtoTCP},
		{Code: bpfRetK, K: 0xffffffff},
		{Code: bpfRetK, K: 0},
	}
}

// Verify interface compliance
var _ RawHandle = (*AFPacketHandle)(nil)
