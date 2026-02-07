/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"encoding/binary"
	"fmt"
	rand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// SendHandle crafts and injects raw TCP packets.
type SendHandle struct {
	// Atomic counter for sequence number progression (hot path).
	seqCounter uint32
	_pad       [60]byte // Pad to 64-byte cache line to avoid false sharing.

	// Read-only config (set once at init).
	tos       uint8
	ttl       uint8
	srcPort   uint16
	baseSeq   uint32
	baseTS    uint32
	startTime time.Time

	// Network handles and addresses.
	handle      RawHandle
	srcIPv4     net.IP
	srcIPv4RMAC net.HardwareAddr // Router MAC for IPv4
	srcIPv6     net.IP
	srcIPv6RMAC net.HardwareAddr // Router MAC for IPv6
	srcMAC      net.HardwareAddr

	// TCP options (pre-built for performance).
	synOptions []layers.TCPOption
	ackOptions []layers.TCPOption

	// TCP flag cycling.
	tcpFlags  []TCPFlags
	flagIndex uint32

	// Object pools to reduce allocations.
	ethPool  sync.Pool
	ipv4Pool sync.Pool
	ipv6Pool sync.Pool
	tcpPool  sync.Pool
	bufPool  sync.Pool
}

// NewSendHandle creates a new send handle for packet injection.
func NewSendHandle(cfg *Config, handle RawHandle) (*SendHandle, error) {
	// Set direction to outgoing only (we don't read from this handle).
	if err := handle.SetDirection(DirectionOut); err != nil {
		// Non-fatal on some platforms (Windows).
	}

	// Pre-build TCP options for SYN packets.
	synOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}, // MSS 1460
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	}

	// Pre-build TCP options for ACK/data packets.
	ackOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
	}

	// Randomize fingerprint values at creation time.
	tosChoices := []uint8{0x00, 0x10, 0x08}
	tos := tosChoices[randRange(0, len(tosChoices)-1)]
	ttl := uint8(randRange(60, 68))

	tcpFlags := cfg.TCPFlags
	if len(tcpFlags) == 0 {
		tcpFlags = []TCPFlags{{PSH: true, ACK: true}}
	}

	localMAC := cfg.LocalMAC
	if localMAC == nil {
		localMAC = make(net.HardwareAddr, 6)
	}

	sh := &SendHandle{
		handle:      handle,
		srcPort:     cfg.LocalPort,
		srcIPv4:     cfg.LocalIPv4,
		srcIPv4RMAC: cfg.RouterMAC,
		srcIPv6:     cfg.LocalIPv6,
		srcIPv6RMAC: cfg.RouterMACv6,
		srcMAC:      localMAC,
		synOptions:  synOptions,
		ackOptions:  ackOptions,
		tcpFlags:    tcpFlags,
		tos:         tos,
		ttl:         ttl,
		baseSeq:     randUint32(),
		baseTS:      randUint32(),
		startTime:   time.Now(),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{
					SrcMAC:       localMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any { return &layers.IPv4{} },
		},
		ipv6Pool: sync.Pool{
			New: func() any { return &layers.IPv6{} },
		},
		tcpPool: sync.Pool{
			New: func() any { return &layers.TCP{} },
		},
		bufPool: sync.Pool{
			New: func() any { return gopacket.NewSerializeBuffer() },
		},
	}

	if sh.srcIPv6RMAC == nil {
		sh.srcIPv6RMAC = sh.srcIPv4RMAC
	}

	return sh, nil
}

// Write sends a packet to the specified destination.
func (h *SendHandle) Write(payload []byte, dstIP net.IP, dstPort uint16) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	// Get next TCP flags in cycle.
	flags := h.nextFlags()

	// Build TCP header with realistic values.
	tcpLayer := h.buildTCPHeader(dstPort, flags, len(payload))
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	isIPv4 := dstIP.To4() != nil

	if isIPv4 {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RMAC
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RMAC
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	ethLayer.SrcMAC = h.srcMAC

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return fmt.Errorf("failed to serialize packet: %w", err)
	}

	return h.handle.WritePacketData(buf.Bytes())
}

func formatFlags(f TCPFlags) string {
	var s string
	if f.SYN {
		s += "S"
	}
	if f.ACK {
		s += "A"
	}
	if f.PSH {
		s += "P"
	}
	if f.FIN {
		s += "F"
	}
	if f.RST {
		s += "R"
	}
	if s == "" {
		s = "."
	}
	return s
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      h.tos,
		TTL:      h.ttl,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP.To4(),
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: h.tos,
		HopLimit:     h.ttl,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f TCPFlags, payloadLen int) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)

	counter := atomic.AddUint32(&h.seqCounter, 1)

	// Compute realistic TCP timestamp from real elapsed time.
	elapsed := time.Since(h.startTime)
	tsVal := h.baseTS + uint32(elapsed.Milliseconds()) + uint32(randRange(0, 9))

	// Randomized window size in realistic range.
	window := uint16(randRange(64240, 65535))

	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN,
		SYN:     f.SYN,
		RST:     f.RST,
		PSH:     f.PSH,
		ACK:     f.ACK,
		URG:     f.URG,
		ECE:     f.ECE,
		CWR:     f.CWR,
		NS:      f.NS,
		Window:  window,
	}

	if f.SYN {
		// SYN packet: random sequence, zero ack.
		binary.BigEndian.PutUint32(h.synOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(h.synOptions[2].OptionData[4:8], 0)
		tcp.Options = h.synOptions
		tcp.Seq = randUint32()
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		// Data packet: progressive sequence, realistic timestamps.
		tsEcr := tsVal - uint32(randRange(50, 250))
		binary.BigEndian.PutUint32(h.ackOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(h.ackOptions[2].OptionData[4:8], tsEcr)
		tcp.Options = h.ackOptions

		// Simulate MSS-sized segments: base + counter * 1460.
		seq := h.baseSeq + counter*1460
		tcp.Seq = seq
		tcp.Ack = seq - uint32(randRange(0, 1023)) + 1400
	}

	return tcp
}

func (h *SendHandle) nextFlags() TCPFlags {
	if len(h.tcpFlags) == 0 {
		return TCPFlags{PSH: true, ACK: true}
	}
	idx := atomic.AddUint32(&h.flagIndex, 1) - 1
	return h.tcpFlags[idx%uint32(len(h.tcpFlags))]
}

// Close releases resources.
func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}

// Helper functions for randomization.

func randUint32() uint32 {
	return rand.Uint32()
}

func randRange(lo, hi int) int {
	if lo >= hi {
		return lo
	}
	return lo + rand.IntN(hi-lo+1)
}
