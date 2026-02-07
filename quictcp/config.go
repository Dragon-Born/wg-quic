/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"fmt"
	"time"
)

// QUICConfig holds QUIC-specific configuration.
type QUICConfig struct {
	// Key is the shared secret for deterministic TLS certificate generation.
	// Both client and server derive identical certificates from this key.
	// REQUIRED.
	Key string

	// ALPN is the Application-Layer Protocol Negotiation identifier.
	// Default: "h3" (HTTP/3) - makes traffic look like browser HTTPS.
	// Other options: "h2" (HTTP/2), custom strings.
	ALPN string

	// MaxStreams is the maximum number of concurrent streams.
	// Default: 256. Range: 1-65535.
	MaxStreams int

	// IdleTimeout is how long a connection can be idle before closing.
	// Default: 30s. Range: 1s-5m.
	IdleTimeout time.Duration

	// CertFile and KeyFile allow using custom TLS certificates.
	// If empty, deterministic certificates are generated from Key.
	CertFile string
	KeyFile  string

	// Flow control windows for high-throughput optimization.
	// Larger windows = higher throughput but more memory.
	InitialStreamWindow uint64 // Default: 4MB
	MaxStreamWindow     uint64 // Default: 8MB
	InitialConnWindow   uint64 // Default: 8MB
	MaxConnWindow       uint64 // Default: 16MB

	// KeepAlivePeriod is how often to send keep-alive packets.
	// Default: IdleTimeout / 3
	KeepAlivePeriod time.Duration

	// Enable0RTT enables 0-RTT connection resumption for faster reconnects.
	// Default: true
	Enable0RTT bool

	// NumStreams is the total number of parallel QUIC streams for data transfer.
	// Streams are distributed evenly across connections (NumStreams / NumConns per conn).
	// Multiple streams avoid head-of-line blocking within each connection.
	// Both client and server must use the same value.
	// Default: 64. Range: 1-256.
	NumStreams int

	// NumConns is the number of parallel QUIC connections.
	// Each connection has independent congestion control, so multiple connections
	// multiply the effective congestion window and throughput capacity.
	// Both client and server must use the same value.
	// Default: 4. Range: 1-8.
	NumConns int
}

// DefaultQUICConfig returns sensible defaults optimized for high throughput.
// Flow control windows match paqet's proven configuration.
func DefaultQUICConfig() *QUICConfig {
	return &QUICConfig{
		ALPN:                "h3",
		MaxStreams:          256,
		IdleTimeout:         30 * time.Second,
		InitialStreamWindow: 4 * 1024 * 1024,  // 4MB - matches paqet
		MaxStreamWindow:     8 * 1024 * 1024,  // 8MB - matches paqet
		InitialConnWindow:   8 * 1024 * 1024,  // 8MB - matches paqet
		MaxConnWindow:       16 * 1024 * 1024, // 16MB - matches paqet
		Enable0RTT:          true,
		NumStreams:          64,
		NumConns:            4,
	}
}

// Validate checks if the configuration is valid.
func (c *QUICConfig) Validate() error {
	if c.Key == "" && (c.CertFile == "" || c.KeyFile == "") {
		return fmt.Errorf("either Key or CertFile/KeyFile must be specified")
	}
	if c.ALPN == "" {
		c.ALPN = "h3"
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 256
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.KeepAlivePeriod <= 0 {
		c.KeepAlivePeriod = c.IdleTimeout / 3
	}
	if c.InitialStreamWindow == 0 {
		c.InitialStreamWindow = 4 * 1024 * 1024 // 4MB
	}
	if c.MaxStreamWindow == 0 {
		c.MaxStreamWindow = 8 * 1024 * 1024 // 8MB
	}
	if c.InitialConnWindow == 0 {
		c.InitialConnWindow = 8 * 1024 * 1024 // 8MB
	}
	if c.MaxConnWindow == 0 {
		c.MaxConnWindow = 16 * 1024 * 1024 // 16MB
	}
	if c.NumConns <= 0 {
		c.NumConns = 4
	}
	if c.NumConns > 8 {
		c.NumConns = 8
	}
	if c.NumStreams <= 0 {
		c.NumStreams = 64
	}
	if c.NumStreams > 256 {
		c.NumStreams = 256
	}
	// Ensure at least 1 stream per connection
	if c.NumStreams < c.NumConns {
		c.NumStreams = c.NumConns
	}
	return nil
}
