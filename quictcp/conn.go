/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// maxPacketSize is the maximum WireGuard packet size
	maxPacketSize = 65535

	// lengthPrefixSize is the size of the length prefix (2 bytes)
	lengthPrefixSize = 2

	// recvChanSize is the buffer size for the internal receive channel
	recvChanSize = 512
)

// streamSlot holds a QUIC stream with its own write synchronization.
// Each slot has an independent mutex and write buffer so that writes
// to different streams never contend with each other.
type streamSlot struct {
	stream   *quic.Stream
	mu       sync.Mutex
	writeBuf []byte
}

// Conn wraps a single QUIC connection for WireGuard transport.
// Uses multiple parallel bidirectional streams to avoid head-of-line blocking.
// Writes are distributed round-robin across streams; reads from all streams
// are multiplexed into a single channel by dedicated goroutines.
//
// For multi-connection parallelism (separate congestion windows), use ConnPool.
type Conn struct {
	qConn *quic.Conn

	// Multi-stream for parallel data transfer (avoids HOL blocking)
	slots    []streamSlot
	writeIdx atomic.Uint64 // Round-robin counter for write distribution

	// Internal receive channel (fed by per-stream read goroutines)
	recvCh    chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
}

// Dial creates a single QUIC connection over the raw TCP PacketConn.
// For better throughput, use DialPool which creates multiple connections
// with independent congestion control.
func Dial(ctx context.Context, addr net.Addr, cfg *QUICConfig, pConn net.PacketConn) (*Conn, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("expected *net.UDPAddr, got %T", addr)
	}

	tr := &quic.Transport{Conn: pConn}
	numStreams := cfg.NumStreams
	if numStreams <= 0 {
		numStreams = 64
	}

	return dialConn(ctx, tr, udpAddr, cfg, numStreams)
}

// dialConn dials a single QUIC connection on the given transport, opens
// numStreams bidirectional streams, writes init markers, and starts readLoops.
func dialConn(ctx context.Context, tr *quic.Transport, addr *net.UDPAddr, cfg *QUICConfig, numStreams int) (*Conn, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[QUIC] Dialing to %v (ALPN=%s, streams=%d)", addr, cfg.ALPN, numStreams)
	}

	tlsConf, err := BuildTLSConfig(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	quicConf := buildQUICConfig(cfg)

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	qConn, err := tr.Dial(dialCtx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QUIC: %w", err)
	}

	if debug {
		log.Printf("[QUIC] QUIC connection established, opening %d streams...", numStreams)
	}

	// Open N bidirectional streams for parallel data transfer
	slots := make([]streamSlot, numStreams)
	for i := range numStreams {
		stream, err := qConn.OpenStreamSync(ctx)
		if err != nil {
			qConn.CloseWithError(1, "failed to open stream")
			return nil, fmt.Errorf("failed to open stream %d: %w", i, err)
		}
		slots[i] = streamSlot{
			stream:   stream,
			writeBuf: make([]byte, 0, 1500+lengthPrefixSize),
		}
	}

	// Write init markers on all streams so the server's AcceptStream
	// sees them immediately. Without this, QUIC only signals a stream
	// to the remote when data is written, causing a deadlock where the
	// server blocks waiting for streams that the client never writes to.
	var initMarker [lengthPrefixSize]byte // zero-length packet
	for i := range slots {
		if _, err := slots[i].stream.Write(initMarker[:]); err != nil {
			qConn.CloseWithError(1, "failed to init stream")
			return nil, fmt.Errorf("failed to init stream %d: %w", i, err)
		}
	}

	if debug {
		log.Printf("[QUIC] Init markers written on all %d streams", numStreams)
	}

	conn := &Conn{
		qConn:   qConn,
		slots:   slots,
		recvCh:  make(chan []byte, recvChanSize),
		closeCh: make(chan struct{}),
	}

	// Start per-stream read goroutines
	for i := range slots {
		go conn.readLoop(i)
	}

	if debug {
		log.Printf("[QUIC] Connection ready (%d streams)", numStreams)
	}

	return conn, nil
}

// newConnFromStreams creates a Conn from an accepted QUIC connection and streams.
// Used by the server/listener side.
func newConnFromStreams(qConn *quic.Conn, streams []*quic.Stream) *Conn {
	slots := make([]streamSlot, len(streams))
	for i, s := range streams {
		slots[i] = streamSlot{
			stream:   s,
			writeBuf: make([]byte, 0, 1500+lengthPrefixSize),
		}
	}

	conn := &Conn{
		qConn:   qConn,
		slots:   slots,
		recvCh:  make(chan []byte, recvChanSize),
		closeCh: make(chan struct{}),
	}

	// Start per-stream read goroutines
	for i := range slots {
		go conn.readLoop(i)
	}

	return conn
}

// readLoop reads packets from a single stream and feeds them to the receive channel.
// One goroutine per stream enables parallel reads, avoiding head-of-line blocking.
func (c *Conn) readLoop(idx int) {
	stream := c.slots[idx].stream
	for {
		select {
		case <-c.closeCh:
			return
		default:
		}

		// Read length prefix (2 bytes)
		var lenBuf [lengthPrefixSize]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return
		}

		length := binary.BigEndian.Uint16(lenBuf[:])
		if length == 0 {
			continue // Skip init marker / keepalive
		}
		if length > maxPacketSize {
			return
		}

		// Read payload
		data := make([]byte, length)
		if _, err := io.ReadFull(stream, data); err != nil {
			return
		}

		select {
		case c.recvCh <- data:
		case <-c.closeCh:
			return
		}
	}
}

func buildQUICConfig(cfg *QUICConfig) *quic.Config {
	keepAlive := cfg.KeepAlivePeriod
	if keepAlive <= 0 {
		keepAlive = cfg.IdleTimeout / 3
	}

	return &quic.Config{
		MaxIncomingStreams:             int64(cfg.MaxStreams),
		MaxIdleTimeout:                 cfg.IdleTimeout,
		KeepAlivePeriod:                keepAlive,
		Allow0RTT:                      cfg.Enable0RTT,
		EnableDatagrams:                true, // Keep enabled for compatibility
		InitialStreamReceiveWindow:     cfg.InitialStreamWindow,
		MaxStreamReceiveWindow:         cfg.MaxStreamWindow,
		InitialConnectionReceiveWindow: cfg.InitialConnWindow,
		MaxConnectionReceiveWindow:     cfg.MaxConnWindow,
	}
}

// SendDatagram sends data over a QUIC stream (round-robin across streams).
func (c *Conn) SendDatagram(data []byte) error {
	if len(data) > maxPacketSize {
		return fmt.Errorf("packet too large: %d > %d", len(data), maxPacketSize)
	}

	// Round-robin stream selection
	idx := c.writeIdx.Add(1) - 1
	slot := &c.slots[idx%uint64(len(c.slots))]

	slot.mu.Lock()
	defer slot.mu.Unlock()

	// Coalesce length prefix + data into single write
	needed := lengthPrefixSize + len(data)
	if cap(slot.writeBuf) < needed {
		slot.writeBuf = make([]byte, needed)
	}
	buf := slot.writeBuf[:needed]
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[lengthPrefixSize:], data)

	if _, err := slot.stream.Write(buf); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

// ReceiveDatagram receives data from any QUIC stream.
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.recvCh:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeCh:
		return nil, fmt.Errorf("connection closed")
	case <-c.qConn.Context().Done():
		return nil, fmt.Errorf("QUIC connection closed")
	}
}

// SendDatagramBatch sends multiple packets efficiently over one stream.
// Coalesces all length prefixes + payloads into a single write.
func (c *Conn) SendDatagramBatch(packets [][]byte) error {
	// Pick one stream for the whole batch (round-robin)
	idx := c.writeIdx.Add(1) - 1
	slot := &c.slots[idx%uint64(len(c.slots))]

	slot.mu.Lock()
	defer slot.mu.Unlock()

	// Calculate total size needed
	totalSize := 0
	for _, data := range packets {
		if len(data) > maxPacketSize {
			return fmt.Errorf("packet too large: %d > %d", len(data), maxPacketSize)
		}
		totalSize += lengthPrefixSize + len(data)
	}

	// Grow buffer if needed
	if cap(slot.writeBuf) < totalSize {
		slot.writeBuf = make([]byte, totalSize)
	}
	buf := slot.writeBuf[:totalSize]

	// Build coalesced buffer: [len1][data1][len2][data2]...
	offset := 0
	for _, data := range packets {
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(data)))
		offset += lengthPrefixSize
		copy(buf[offset:], data)
		offset += len(data)
	}

	// Single write for all packets
	if _, err := slot.stream.Write(buf); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

// Close closes the QUIC connection and all streams.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)

		// Close all streams
		for i := range c.slots {
			if c.slots[i].stream != nil {
				c.slots[i].stream.Close()
			}
		}

		// Close QUIC connection
		if c.qConn != nil {
			c.qConn.CloseWithError(0, "close")
		}
	})
	return nil
}

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr {
	return c.qConn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.qConn.RemoteAddr()
}

// ConnectionState returns the QUIC connection state.
func (c *Conn) ConnectionState() *quic.ConnectionState {
	state := c.qConn.ConnectionState()
	return &state
}

// Context returns the connection's context, which is canceled when closed.
func (c *Conn) Context() context.Context {
	return c.qConn.Context()
}

// IsClosed returns true if the connection has been closed.
func (c *Conn) IsClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
	}
	select {
	case <-c.qConn.Context().Done():
		return true
	default:
		return false
	}
}
