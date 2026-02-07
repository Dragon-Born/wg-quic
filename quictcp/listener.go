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
	"time"

	"github.com/quic-go/quic-go"
)

// Listener wraps a QUIC listener for server mode.
type Listener struct {
	pConn      net.PacketConn
	tr         *quic.Transport
	listener   *quic.Listener
	numStreams int

	mu      sync.Mutex
	clients map[string]*Conn // Track connections by remote address
}

// Listen creates a QUIC listener over the raw TCP PacketConn.
func Listen(cfg *QUICConfig, pConn net.PacketConn) (*Listener, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[QUIC-LIS] Creating QUIC listener...")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}

	tlsConf, err := BuildTLSConfig(cfg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	quicConf := buildQUICConfig(cfg)

	if debug {
		log.Printf("[QUIC-LIS] TLS config built (ALPN=%v), creating transport...", tlsConf.NextProtos)
	}

	tr := &quic.Transport{Conn: pConn}
	l, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	if debug {
		log.Printf("[QUIC-LIS] QUIC listener created successfully on %v", l.Addr())
	}

	numStreams := cfg.NumStreams
	if numStreams <= 0 {
		numStreams = 64
	}
	numConns := cfg.NumConns
	if numConns <= 0 {
		numConns = 4
	}
	streamsPerConn := numStreams / numConns
	if streamsPerConn < 1 {
		streamsPerConn = 1
	}

	if debug {
		log.Printf("[QUIC-LIS] Expecting %d streams per connection (%d total / %d conns)",
			streamsPerConn, numStreams, numConns)
	}

	return &Listener{
		pConn:      pConn,
		tr:         tr,
		listener:   l,
		numStreams:  streamsPerConn,
		clients:    make(map[string]*Conn),
	}, nil
}

// Accept accepts a new QUIC connection and waits for the client to open a stream.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[QUIC-LIS] Accept: waiting for incoming QUIC connection...")
	}

	qConn, err := l.listener.Accept(ctx)
	if err != nil {
		if debug {
			log.Printf("[QUIC-LIS] Accept: error: %v", err)
		}
		return nil, fmt.Errorf("failed to accept QUIC connection: %w", err)
	}

	if debug {
		log.Printf("[QUIC-LIS] Accept: QUIC connection accepted from %v, waiting for %d streams...", qConn.RemoteAddr(), l.numStreams)
	}

	// Accept bidirectional streams (streamsPerConn = NumStreams / NumConns)
	streams := make([]*quic.Stream, l.numStreams)
	for i := range l.numStreams {
		streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		stream, err := qConn.AcceptStream(streamCtx)
		cancel()
		if err != nil {
			if debug {
				log.Printf("[QUIC-LIS] Accept: failed to accept stream %d: %v", i, err)
			}
			qConn.CloseWithError(1, "failed to accept streams")
			return nil, fmt.Errorf("failed to accept stream %d: %w", i, err)
		}
		streams[i] = stream
		if debug {
			log.Printf("[QUIC-LIS] Accept: stream %d accepted (ID=%d) from %v", i, stream.StreamID(), qConn.RemoteAddr())
		}
	}

	// Create Conn using all streams
	conn := newConnFromStreams(qConn, streams)

	if debug {
		state := qConn.ConnectionState()
		log.Printf("[QUIC-LIS] Accept: connection ready from %v (stream mode, datagrams=%v)",
			qConn.RemoteAddr(), state.SupportsDatagrams.Local && state.SupportsDatagrams.Remote)
	}

	// Track the connection
	l.mu.Lock()
	l.clients[qConn.RemoteAddr().String()] = conn
	l.mu.Unlock()

	return conn, nil
}

// GetConn returns an existing connection by remote address, or nil if not found.
func (l *Listener) GetConn(remoteAddr string) *Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.clients[remoteAddr]
}

// RemoveConn removes a connection from tracking.
func (l *Listener) RemoveConn(remoteAddr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, remoteAddr)
}

// Close closes the listener and all connections.
func (l *Listener) Close() error {
	l.mu.Lock()
	for addr, conn := range l.clients {
		conn.Close()
		delete(l.clients, addr)
	}
	l.mu.Unlock()

	if l.listener != nil {
		l.listener.Close()
	}
	if l.tr != nil {
		l.tr.Close()
	}
	// Note: We don't close pConn here as it may be managed externally
	return nil
}

// Addr returns the listener's address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// ConnCount returns the number of active connections.
func (l *Listener) ConnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}
