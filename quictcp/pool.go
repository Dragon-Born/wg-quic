/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// ConnPool manages multiple QUIC connections with independent congestion control.
// Each connection has its own congestion window, so N connections provide N× the
// effective throughput capacity of a single connection. Sends are distributed
// round-robin across live connections.
type ConnPool struct {
	mu       sync.RWMutex
	conns    []*Conn
	writeIdx atomic.Uint64
	closeCh  chan struct{}
	closed   bool
}

// NewConnPool creates an empty ConnPool. Use AddConn to add connections,
// or use DialPool for client-side pool creation.
func NewConnPool() *ConnPool {
	return &ConnPool{
		closeCh: make(chan struct{}),
	}
}

// DialPool creates N independent QUIC connections over a shared raw TCP PacketConn.
// Each connection has NumStreams/NumConns streams and its own congestion window.
func DialPool(ctx context.Context, addr net.Addr, cfg *QUICConfig, pConn net.PacketConn) (*ConnPool, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("expected *net.UDPAddr, got %T", addr)
	}

	numConns := cfg.NumConns
	if numConns <= 0 {
		numConns = 4
	}
	streamsPerConn := cfg.NumStreams / numConns
	if streamsPerConn < 1 {
		streamsPerConn = 1
	}

	if debug {
		log.Printf("[QUIC-POOL] Dialing %d connections × %d streams to %v", numConns, streamsPerConn, addr)
	}

	// Single transport shared by all connections (multiplexes by QUIC connection ID)
	tr := &quic.Transport{Conn: pConn}

	pool := &ConnPool{
		conns:   make([]*Conn, 0, numConns),
		closeCh: make(chan struct{}),
	}

	for i := range numConns {
		conn, err := dialConn(ctx, tr, udpAddr, cfg, streamsPerConn)
		if err != nil {
			if debug {
				log.Printf("[QUIC-POOL] Failed to dial connection %d: %v", i, err)
			}
			pool.Close()
			return nil, fmt.Errorf("failed to dial connection %d: %w", i, err)
		}
		pool.conns = append(pool.conns, conn)
		if debug {
			log.Printf("[QUIC-POOL] Connection %d/%d established (%d streams)", i+1, numConns, streamsPerConn)
		}
	}

	if debug {
		log.Printf("[QUIC-POOL] Pool ready: %d connections × %d streams = %d total streams",
			numConns, streamsPerConn, numConns*streamsPerConn)
	}

	return pool, nil
}

// AddConn adds a connection to the pool, pruning any dead connections.
// Used by the server side to accumulate connections from the same client.
func (p *ConnPool) AddConn(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Allocate new slice so concurrent SendDatagramBatch snapshots
	// of the old p.conns remain valid (they point to the old backing array).
	alive := make([]*Conn, 0, len(p.conns)+1)
	for _, existing := range p.conns {
		if !existing.IsClosed() {
			alive = append(alive, existing)
		}
	}
	p.conns = append(alive, c)
}

// SendDatagramBatch sends multiple packets over a single connection (round-robin).
// Skips closed connections automatically.
func (p *ConnPool) SendDatagramBatch(packets [][]byte) error {
	// Snapshot the slice header under lock. This is safe because:
	// - The Conn pointers are stable (never freed while in use)
	// - AddConn may replace p.conns, but our snapshot remains valid
	p.mu.RLock()
	conns := p.conns
	p.mu.RUnlock()

	n := len(conns)
	if n == 0 {
		return net.ErrClosed
	}

	base := p.writeIdx.Add(1) - 1
	for attempts := range n {
		conn := conns[(base+uint64(attempts))%uint64(n)]

		if conn.IsClosed() {
			continue
		}

		if err := conn.SendDatagramBatch(packets); err == nil {
			return nil
		}
	}
	return net.ErrClosed
}

// Conns returns the current slice of connections.
// Used by the bind layer to set up per-connection read loops.
func (p *ConnPool) Conns() []*Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Conn, len(p.conns))
	copy(result, p.conns)
	return result
}

// NumConns returns the number of connections in the pool.
func (p *ConnPool) NumConns() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

// RemoteAddr returns the remote address of the first connection, or nil.
func (p *ConnPool) RemoteAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.conns) == 0 {
		return nil
	}
	return p.conns[0].RemoteAddr()
}

// IsClosed returns true if the pool has been closed.
func (p *ConnPool) IsClosed() bool {
	select {
	case <-p.closeCh:
		return true
	default:
		return false
	}
}

// Close closes all connections in the pool.
func (p *ConnPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closeCh)

	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
	return nil
}
