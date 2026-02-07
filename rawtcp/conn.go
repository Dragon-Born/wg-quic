/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// PacketConn implements packet-based I/O over raw TCP sockets.
// It provides a net.PacketConn-like interface for WireGuard.
type PacketConn struct {
	cfg           *Config
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	localAddr     *net.UDPAddr
	readDeadline  atomic.Int64
	writeDeadline atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

// NewPacketConn creates a new raw TCP packet connection.
func NewPacketConn(ctx context.Context, cfg *Config) (*PacketConn, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[CONN] Creating new PacketConn (interface=%s, localPort=%d, backend=%s)",
			cfg.Interface, cfg.LocalPort, cfg.Backend)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create send handle
	if debug {
		log.Printf("[CONN] Creating send raw handle...")
	}
	sendRawHandle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send raw handle: %w", err)
	}
	if debug {
		log.Printf("[CONN] Send raw handle created")
	}

	sendHandle, err := NewSendHandle(cfg, sendRawHandle)
	if err != nil {
		sendRawHandle.Close()
		return nil, fmt.Errorf("failed to create send handle: %w", err)
	}
	if debug {
		log.Printf("[CONN] Send handle created")
	}

	// Create recv handle
	if debug {
		log.Printf("[CONN] Creating recv raw handle...")
	}
	recvRawHandle, err := newHandle(cfg)
	if err != nil {
		sendHandle.Close()
		return nil, fmt.Errorf("failed to create recv raw handle: %w", err)
	}
	if debug {
		log.Printf("[CONN] Recv raw handle created")
	}

	recvHandle, err := NewRecvHandle(cfg, recvRawHandle)
	if err != nil {
		sendHandle.Close()
		recvRawHandle.Close()
		return nil, fmt.Errorf("failed to create recv handle: %w", err)
	}
	if debug {
		log.Printf("[CONN] Recv handle created")
	}

	// Build local address for WireGuard.
	var localAddr *net.UDPAddr
	if cfg.LocalIPv4 != nil {
		localAddr = &net.UDPAddr{IP: cfg.LocalIPv4, Port: int(cfg.LocalPort)}
	} else if cfg.LocalIPv6 != nil {
		localAddr = &net.UDPAddr{IP: cfg.LocalIPv6, Port: int(cfg.LocalPort)}
	}

	if debug {
		log.Printf("[CONN] PacketConn created successfully (localAddr=%v)", localAddr)
	}

	ctx, cancel := context.WithCancel(ctx)
	return &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		localAddr:  localAddr,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// newHandle creates a new RawHandle using the configured backend.
func newHandle(cfg *Config) (RawHandle, error) {
	backend := cfg.Backend
	if backend == "" {
		backend = "auto"
	}

	switch backend {
	case "pcap":
		return NewPcapHandle(cfg)

	case "afpacket":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("afpacket backend is only supported on Linux")
		}
		return NewAFPacketHandle(cfg)

	case "auto":
		// On Linux, try AF_PACKET first (works without CGO), then fall back to pcap
		if runtime.GOOS == "linux" {
			handle, err := NewAFPacketHandle(cfg)
			if err == nil {
				return handle, nil
			}
			// Try pcap as fallback (requires CGO)
			pcapHandle, pcapErr := NewPcapHandle(cfg)
			if pcapErr == nil {
				return pcapHandle, nil
			}
			// Return the AF_PACKET error as it's preferred
			return nil, fmt.Errorf("afpacket: %v; pcap: %v", err, pcapErr)
		}
		// On non-Linux, use pcap
		return NewPcapHandle(cfg)

	default:
		return nil, fmt.Errorf("unknown backend: %s", backend)
	}
}

// ReadFrom reads a packet and returns the payload and source address.
func (c *PacketConn) ReadFrom(buf []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	default:
	}

	if err := c.checkDeadline(&c.readDeadline); err != nil {
		return 0, nil, err
	}

	payload, srcIP, srcPort, err := c.recvHandle.Read()
	if err != nil {
		return 0, nil, err
	}

	// Skip empty packets (ACKs, etc.)
	if len(payload) == 0 {
		return c.ReadFrom(buf)
	}

	n = copy(buf, payload)

	// srcIP is already a copy made by RecvHandle.Read(), safe to use directly
	addr = &net.UDPAddr{IP: srcIP, Port: int(srcPort)}

	return n, addr, nil
}

// WriteTo sends a packet to the specified address.
func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}

	if err := c.checkDeadline(&c.writeDeadline); err != nil {
		return 0, err
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("invalid address type: %T", addr)
	}

	if err := c.sendHandle.Write(data, udpAddr.IP, uint16(udpAddr.Port)); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Close closes the connection.
func (c *PacketConn) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	c.cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if c.sendHandle != nil {
			c.sendHandle.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if c.recvHandle != nil {
			c.recvHandle.Close()
		}
	}()
	wg.Wait()

	return nil
}

// LocalAddr returns the local address.
func (c *PacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

// SetDeadline sets read and write deadlines.
func (c *PacketConn) SetDeadline(t time.Time) error {
	ns := deadlineToNano(t)
	c.readDeadline.Store(ns)
	c.writeDeadline.Store(ns)
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(deadlineToNano(t))
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(deadlineToNano(t))
	return nil
}

func (c *PacketConn) checkDeadline(dl *atomic.Int64) error {
	d := dl.Load()
	if d != 0 && time.Now().UnixNano() >= d {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func deadlineToNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// Verify interface compliance
var _ net.PacketConn = (*PacketConn)(nil)
