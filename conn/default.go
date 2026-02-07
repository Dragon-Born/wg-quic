//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"log"
	"os"

	"golang.zx2c4.com/wireguard/quictcp"
)

// InterfaceName can be set before calling NewDefaultBind to enable
// interface-specific config file loading (e.g., /etc/wireguard/wg0.quictcp.conf).
// If empty, only environment variables and WG_QUICTCP_CONFIG are checked.
var InterfaceName string

// NewDefaultBind returns the appropriate Bind implementation.
// If QUIC-TCP is enabled (via config file or environment), returns a QUIC-over-raw-TCP bind.
// Otherwise, returns the standard UDP bind.
func NewDefaultBind() Bind {
	return NewDefaultBindForInterface(InterfaceName)
}

// NewDefaultBindForInterface returns the appropriate Bind for a specific interface.
// It checks for config files at /etc/wireguard/<interface>.quictcp.conf first,
// then falls back to environment variables.
func NewDefaultBindForInterface(interfaceName string) Bind {
	debug := os.Getenv("LOG_LEVEL") == "verbose" || os.Getenv("LOG_LEVEL") == "debug" || os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[BIND] NewDefaultBindForInterface called with interface=%q", interfaceName)
	}

	// Check if QUIC-TCP is enabled for this interface
	if interfaceName != "" && !quictcp.IsEnabledForInterface(interfaceName) {
		if debug {
			log.Printf("[BIND] QUIC-TCP not enabled for interface %q, using standard UDP", interfaceName)
		}
		return NewStdNetBind()
	} else if interfaceName == "" && !quictcp.IsEnabled() {
		if debug {
			log.Printf("[BIND] QUIC-TCP not enabled (no interface name), using standard UDP")
		}
		return NewStdNetBind()
	}

	if debug {
		log.Printf("[BIND] QUIC-TCP enabled, loading config...")
	}

	// Load configuration
	cfg, err := quictcp.LoadConfig(interfaceName)
	if err != nil {
		log.Printf("QUIC-TCP config error: %v", err)
		log.Printf("Falling back to standard UDP bind")
		quictcp.PrintEnvHelp()
		return NewStdNetBind()
	}

	if cfg == nil {
		if debug {
			log.Printf("[BIND] Config returned nil, using standard UDP")
		}
		return NewStdNetBind()
	}

	// Log that we're using QUIC-TCP mode
	if debug {
		log.Printf("[BIND] Using QUIC-over-raw-TCP bind (DPI bypass mode)")
		if cfg.IsServer {
			log.Printf("[BIND]   Mode: Server on port %d", cfg.RawConfig.LocalPort)
		} else {
			log.Printf("[BIND]   Mode: Client connecting to %s", cfg.ServerAddr)
		}
		log.Printf("[BIND]   Interface: %s", cfg.RawConfig.Interface)
		log.Printf("[BIND]   LocalIP: %v", cfg.RawConfig.LocalIPv4)
		log.Printf("[BIND]   RouterMAC: %v", cfg.RawConfig.RouterMAC)
		log.Printf("[BIND]   ALPN: %s", cfg.QUICConfig.ALPN)
	}

	if debug {
		log.Printf("[BIND] Creating QUIC-TCP bind...")
	}

	return NewQUICTCPBind(cfg.RawConfig, cfg.QUICConfig, cfg.IsServer, cfg.ServerAddr)
}
