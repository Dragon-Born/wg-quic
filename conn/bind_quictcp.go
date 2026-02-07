/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/quictcp"
	"golang.zx2c4.com/wireguard/rawtcp"
)

// receivedPacket represents a packet received from a client connection pool.
type receivedPacket struct {
	data []byte
	pool *quictcp.ConnPool
	addr *net.UDPAddr
}

// QUICTCPBind implements Bind using QUIC over raw TCP.
// Uses multiple QUIC connections (ConnPool) for independent congestion control.
type QUICTCPBind struct {
	mu         sync.Mutex
	rawCfg     *rawtcp.Config
	quicCfg    *quictcp.QUICConfig
	rawConn    *rawtcp.PacketConn
	quicPool   *quictcp.ConnPool // Client mode: pool of connections to server
	quicLis    *quictcp.Listener // Server mode
	isServer   bool
	serverAddr *net.UDPAddr
	closed     bool

	// Connection pool management for server mode (one pool per remote client)
	connMu  sync.RWMutex
	clients map[string]*quictcp.ConnPool

	// Channel for receiving packets (both client and server mode)
	receiveChan chan receivedPacket
	closeChan   chan struct{} // Signals permanent shutdown
	pauseChan   chan struct{} // Signals soft-close (receive should return error)
}

// NewQUICTCPBind creates a new QUIC-over-raw-TCP bind.
func NewQUICTCPBind(rawCfg *rawtcp.Config, quicCfg *quictcp.QUICConfig, isServer bool, serverAddr *net.UDPAddr) *QUICTCPBind {
	// Set IsServer on raw config (for BPF filter direction).
	rawCfg.IsServer = isServer

	// For client mode, set ServerPort from serverAddr (for BPF filter: src port).
	if !isServer && serverAddr != nil {
		rawCfg.ServerPort = uint16(serverAddr.Port)
	}

	return &QUICTCPBind{
		rawCfg:      rawCfg,
		quicCfg:     quicCfg,
		isServer:    isServer,
		serverAddr:  serverAddr,
		clients:     make(map[string]*quictcp.ConnPool),
		receiveChan: make(chan receivedPacket, 256),
		closeChan:   make(chan struct{}),
		pauseChan:   make(chan struct{}),
	}
}

func (b *QUICTCPBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[BIND] Open called (port=%d, isServer=%v)", port, b.isServer)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset closed flag - important for reopen after soft-Close
	b.closed = false

	// Reinitialize pauseChan if it was closed (soft-close case)
	select {
	case <-b.pauseChan:
		b.pauseChan = make(chan struct{})
	default:
	}

	// Reinitialize closeChan if it was closed (hard-close case)
	select {
	case <-b.closeChan:
		b.receiveChan = make(chan receivedPacket, 256)
		b.closeChan = make(chan struct{})
	default:
	}

	// If already open (e.g., after a soft-close), reuse existing connection
	if b.rawConn != nil {
		if debug {
			log.Printf("[BIND] Open: already open, reusing existing connection")
		}
		if b.isServer {
			if debug {
				log.Printf("[BIND] Open: restarting acceptLoop goroutine")
			}
			go b.acceptLoop()
			return []ReceiveFunc{b.serverReceive}, b.rawCfg.LocalPort, nil
		}
		return []ReceiveFunc{b.clientReceive}, b.rawCfg.LocalPort, nil
	}

	// Set port in config.
	if port != 0 {
		b.rawCfg.LocalPort = port
	}

	// Create raw TCP PacketConn.
	rawConn, err := rawtcp.NewPacketConn(context.Background(), b.rawCfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create raw TCP connection: %w", err)
	}
	b.rawConn = rawConn

	if b.isServer {
		if debug {
			log.Printf("[BIND] Open: server mode, creating QUIC listener...")
		}

		lis, err := quictcp.Listen(b.quicCfg, rawConn)
		if err != nil {
			rawConn.Close()
			b.rawConn = nil
			return nil, 0, fmt.Errorf("failed to create QUIC listener: %w", err)
		}
		b.quicLis = lis

		if debug {
			log.Printf("[BIND] Open: QUIC listener created, starting acceptLoop...")
		}

		go b.acceptLoop()

		recv := func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
			return b.serverReceive(packets, sizes, eps)
		}

		if debug {
			log.Printf("[BIND] Open: server mode setup complete, port=%d", b.rawCfg.LocalPort)
		}
		return []ReceiveFunc{recv}, b.rawCfg.LocalPort, nil
	}

	if debug {
		log.Printf("[BIND] Open: client mode, dialing QUIC pool to %v...", b.serverAddr)
	}

	// Client: dial pool of QUIC connections to server.
	pool, err := quictcp.DialPool(context.Background(), b.serverAddr, b.quicCfg, rawConn)
	if err != nil {
		rawConn.Close()
		b.rawConn = nil
		return nil, 0, fmt.Errorf("failed to dial QUIC pool: %w", err)
	}
	b.quicPool = pool

	if debug {
		log.Printf("[BIND] Open: QUIC pool established (%d connections)", pool.NumConns())
	}

	// Start read goroutines for each connection in the pool
	for _, conn := range pool.Conns() {
		go b.connReadLoop(conn, pool, nil)
	}

	recv := func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		return b.clientReceive(packets, sizes, eps)
	}
	return []ReceiveFunc{recv}, b.rawCfg.LocalPort, nil
}

func (b *QUICTCPBind) acceptLoop() {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	for {
		b.mu.Lock()
		lis := b.quicLis
		closed := b.closed
		b.mu.Unlock()

		if closed || lis == nil {
			return
		}

		if debug {
			log.Printf("[BIND] acceptLoop: waiting for connection...")
		}

		conn, err := lis.Accept(context.Background())
		if err != nil {
			if debug {
				log.Printf("[BIND] acceptLoop: Accept error: %v", err)
			}
			continue
		}

		remoteAddrStr := conn.RemoteAddr().String()
		var udpAddr *net.UDPAddr
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			udpAddr = addr
		}

		// Find or create pool for this remote address
		b.connMu.Lock()
		pool, exists := b.clients[remoteAddrStr]
		if !exists {
			pool = quictcp.NewConnPool()
			b.clients[remoteAddrStr] = pool
		}
		pool.AddConn(conn)
		poolSize := pool.NumConns()
		b.connMu.Unlock()

		if debug {
			log.Printf("[BIND] acceptLoop: accepted connection from %v (pool now has %d conns)",
				conn.RemoteAddr(), poolSize)
		}

		// Start read goroutine for this connection
		go b.connReadLoop(conn, pool, udpAddr)
	}
}

// connReadLoop reads packets from a single Conn and feeds them to receiveChan.
// The pool reference is stored in each receivedPacket for send-side round-robin.
func (b *QUICTCPBind) connReadLoop(conn *quictcp.Conn, pool *quictcp.ConnPool, addr *net.UDPAddr) {
	// For client mode, derive addr from conn
	if addr == nil {
		if udpAddr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			addr = udpAddr
		}
	}

	for {
		select {
		case <-b.closeChan:
			return
		default:
		}

		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}

		select {
		case b.receiveChan <- receivedPacket{data: data, pool: pool, addr: addr}:
		case <-b.closeChan:
			return
		}
	}
}

// batchReceive blocks on the first packet, then drains up to len(packets)
// additional ready packets without blocking.
func (b *QUICTCPBind) batchReceive(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	var pkt receivedPacket
	select {
	case pkt = <-b.receiveChan:
	case <-b.pauseChan:
		return 0, net.ErrClosed
	case <-b.closeChan:
		return 0, net.ErrClosed
	}

	sizes[0] = copy(packets[0], pkt.data)
	eps[0] = &QUICTCPEndpoint{addr: pkt.addr, pool: pkt.pool}
	count := 1

	for count < len(packets) {
		select {
		case pkt = <-b.receiveChan:
			sizes[count] = copy(packets[count], pkt.data)
			eps[count] = &QUICTCPEndpoint{addr: pkt.addr, pool: pkt.pool}
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (b *QUICTCPBind) clientReceive(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	return b.batchReceive(packets, sizes, eps)
}

func (b *QUICTCPBind) serverReceive(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	return b.batchReceive(packets, sizes, eps)
}

func (b *QUICTCPBind) Send(bufs [][]byte, endpoint Endpoint) error {
	ep, ok := endpoint.(*QUICTCPEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}

	var pool *quictcp.ConnPool
	if b.isServer {
		// Server mode: look up pool by remote address
		b.connMu.RLock()
		if ep.addr != nil {
			pool = b.clients[ep.addr.String()]
		}
		b.connMu.RUnlock()

		// Fallback to endpoint's pool reference
		if pool == nil && ep.pool != nil && !ep.pool.IsClosed() {
			pool = ep.pool
		}
	} else {
		// Client mode: use the pool
		b.mu.Lock()
		pool = b.quicPool
		b.mu.Unlock()
	}

	if pool == nil {
		return net.ErrClosed
	}

	return pool.SendDatagramBatch(bufs)
}

func (b *QUICTCPBind) Close() error {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[BIND] Close called (isServer=%v)", b.isServer)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Server soft-close: signal receive to return error but keep everything alive
	if b.isServer && b.quicLis != nil {
		if debug {
			log.Printf("[BIND] Close: server mode soft-close")
		}
		b.closed = true
		select {
		case <-b.pauseChan:
		default:
			close(b.pauseChan)
		}
		return nil
	}

	b.closed = true
	close(b.closeChan)

	// Close all client pools
	b.connMu.Lock()
	numClients := len(b.clients)
	for addr, pool := range b.clients {
		pool.Close()
		delete(b.clients, addr)
	}
	b.connMu.Unlock()

	if debug {
		log.Printf("[BIND] Close: closed %d client pools", numClients)
	}

	if b.quicPool != nil {
		b.quicPool.Close()
		b.quicPool = nil
	}
	if b.quicLis != nil {
		b.quicLis.Close()
		b.quicLis = nil
	}
	if b.rawConn != nil {
		b.rawConn.Close()
		b.rawConn = nil
	}

	if debug {
		log.Printf("[BIND] Close: complete")
	}

	return nil
}

// HardClose closes everything - call this when the process is shutting down.
func (b *QUICTCPBind) HardClose() error {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[BIND] HardClose called")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true

	select {
	case <-b.closeChan:
	default:
		close(b.closeChan)
	}

	b.connMu.Lock()
	for addr, pool := range b.clients {
		pool.Close()
		delete(b.clients, addr)
	}
	b.connMu.Unlock()

	if b.quicPool != nil {
		b.quicPool.Close()
		b.quicPool = nil
	}
	if b.quicLis != nil {
		b.quicLis.Close()
		b.quicLis = nil
	}
	if b.rawConn != nil {
		b.rawConn.Close()
		b.rawConn = nil
	}

	if debug {
		log.Printf("[BIND] HardClose: complete")
	}

	return nil
}

func (b *QUICTCPBind) SetMark(mark uint32) error {
	return nil
}

func (b *QUICTCPBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &QUICTCPEndpoint{addr: addr}, nil
}

func (b *QUICTCPBind) BatchSize() int {
	return 64
}

// QUICTCPEndpoint implements Endpoint for QUIC-over-TCP.
type QUICTCPEndpoint struct {
	addr *net.UDPAddr
	pool *quictcp.ConnPool // Pool for round-robin sends
}

func (e *QUICTCPEndpoint) ClearSrc() {}

func (e *QUICTCPEndpoint) SrcToString() string {
	return ""
}

func (e *QUICTCPEndpoint) DstToString() string {
	if e.addr == nil {
		return ""
	}
	return e.addr.String()
}

func (e *QUICTCPEndpoint) DstToBytes() []byte {
	if e.addr == nil {
		return nil
	}
	b, _ := e.addr.AddrPort().MarshalBinary()
	return b
}

func (e *QUICTCPEndpoint) DstIP() netip.Addr {
	if e.addr == nil {
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(e.addr.IP)
	return addr
}

func (e *QUICTCPEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// Verify interface compliance
var (
	_ Bind     = (*QUICTCPBind)(nil)
	_ Endpoint = (*QUICTCPEndpoint)(nil)
)
