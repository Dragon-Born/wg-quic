/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package quictcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

// BuildTLSConfig creates a TLS configuration for QUIC.
// If CertFile/KeyFile are provided, they are used directly.
// Otherwise, a deterministic self-signed certificate is derived from the shared key.
func BuildTLSConfig(cfg *QUICConfig, isServer bool) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		// Use provided certificate files.
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
	} else {
		// Generate deterministic certificate from shared key.
		cert, err = deterministicCert(cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to generate deterministic certificate: %w", err)
		}
	}

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{cfg.ALPN}, // "h3" for HTTP/3 mimicry
		InsecureSkipVerify: true,               // We verify via shared key, not CA
		MinVersion:         tls.VersionTLS13,   // QUIC requires TLS 1.3
	}

	if isServer {
		tlsConf.ClientAuth = tls.NoClientCert
	}

	return tlsConf, nil
}

// deterministicCert generates a deterministic ECDSA certificate from a shared key.
// Both client and server derive the SAME cert from the SAME key.
// This eliminates certificate distribution while maintaining TLS security.
// NOTE: Uses "paqet-quic-cert:" prefix for compatibility with paqet servers.
func deterministicCert(key string) (tls.Certificate, error) {
	// Derive deterministic private key scalar from shared key.
	// The prefix ensures different keys produce different certs.
	// Uses "paqet-quic-cert:" for compatibility with paqet protocol.
	seed := sha256.Sum256([]byte("paqet-quic-cert:" + key))

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(seed[:])

	// Ensure d is in valid range [1, N-1] for the curve.
	d.Mod(d, new(big.Int).Sub(curve.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	// Create private key.
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	// Use deterministic reader for certificate creation.
	// This ensures signing produces identical results on client and server.
	deterministicReader := &deterministicRand{data: append([]byte{}, seed[:]...)}

	// Create certificate template.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"}, // Minimal SAN
	}

	// Self-sign the certificate.
	certDER, err := x509.CreateCertificate(deterministicReader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM format.
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// deterministicRand produces deterministic output from a seed by repeatedly hashing.
// This ensures certificate signing is reproducible.
type deterministicRand struct {
	data []byte
	pos  int
}

func (d *deterministicRand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if d.pos >= len(d.data) {
			h := sha256.Sum256(d.data)
			d.data = h[:]
			d.pos = 0
		}
		copied := copy(p[n:], d.data[d.pos:])
		d.pos += copied
		n += copied
	}
	return n, nil
}

var _ io.Reader = (*deterministicRand)(nil)
