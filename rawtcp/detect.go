/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package rawtcp

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DetectNetworkConfig auto-detects network settings for the default route.
func DetectNetworkConfig() (*Config, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	if debug {
		log.Printf("[DETECT] Starting network auto-detection")
	}

	cfg := DefaultConfig()

	// Find default interface and gateway
	if debug {
		log.Printf("[DETECT] Getting default route...")
	}
	iface, gateway, err := getDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	if debug {
		log.Printf("[DETECT] Found interface=%s, gateway=%v", iface.Name, gateway)
	}

	cfg.Interface = iface.Name
	cfg.LocalMAC = iface.HardwareAddr

	// Find local IP on this interface
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				cfg.LocalIPv4 = ip4
			} else if ipnet.IP.To16() != nil && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
				cfg.LocalIPv6 = ipnet.IP
			}
		}
	}

	if debug {
		log.Printf("[DETECT] Local IP: %v", cfg.LocalIPv4)
	}

	if cfg.LocalIPv4 == nil && cfg.LocalIPv6 == nil {
		return nil, fmt.Errorf("no suitable IP address found on interface %s", iface.Name)
	}

	// Resolve gateway MAC via ARP
	if gateway != nil {
		if debug {
			log.Printf("[DETECT] Resolving MAC for gateway %s...", gateway)
		}
		cfg.RouterMAC, err = resolveMAC(gateway.String())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve gateway MAC: %w", err)
		}
		if debug {
			log.Printf("[DETECT] Gateway MAC: %s", cfg.RouterMAC)
		}
	}

	if debug {
		log.Printf("[DETECT] Auto-detection complete")
	}

	return cfg, nil
}

// getDefaultRoute returns the default network interface and gateway IP.
func getDefaultRoute() (*net.Interface, net.IP, error) {
	switch runtime.GOOS {
	case "linux":
		return getDefaultRouteLinux()
	case "darwin":
		return getDefaultRouteDarwin()
	default:
		return nil, nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func getDefaultRouteLinux() (*net.Interface, net.IP, error) {
	// Read /proc/net/route
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		ifaceName := fields[0]
		destination := fields[1]
		gateway := fields[2]
		flags := fields[3]

		// Look for default route (destination 00000000)
		if destination != "00000000" {
			continue
		}

		// Check if route is up and has gateway (flags & 0x0003)
		if flags == "0" || flags == "1" {
			continue
		}

		// Parse gateway IP (little-endian hex)
		gatewayIP, err := parseHexIP(gateway)
		if err != nil {
			continue
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			continue
		}

		return iface, gatewayIP, nil
	}

	return nil, nil, fmt.Errorf("no default route found")
}

func getDefaultRouteDarwin() (*net.Interface, net.IP, error) {
	// Use netstat -rn to get routing table
	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}

	type routeEntry struct {
		iface   *net.Interface
		gateway net.IP
	}

	var routes []routeEntry

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Look for default route
		if fields[0] != "default" {
			continue
		}

		gateway := net.ParseIP(fields[1])
		ifaceName := fields[3]

		// Handle interface name like "en0" or with percentage like "en0%utun1"
		if idx := strings.Index(ifaceName, "%"); idx != -1 {
			ifaceName = ifaceName[:idx]
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			continue
		}

		routes = append(routes, routeEntry{iface: iface, gateway: gateway})
	}

	if len(routes) == 0 {
		return nil, nil, fmt.Errorf("no default route found")
	}

	// Prefer physical interfaces (en*) over tunnel interfaces (utun*, tun*)
	for _, r := range routes {
		if strings.HasPrefix(r.iface.Name, "en") {
			return r.iface, r.gateway, nil
		}
	}

	// Fall back to first route if no physical interface found
	return routes[0].iface, routes[0].gateway, nil
}

// parseHexIP parses a little-endian hex IP address from /proc/net/route.
func parseHexIP(s string) (net.IP, error) {
	if len(s) != 8 {
		return nil, fmt.Errorf("invalid hex IP length")
	}

	var ip [4]byte
	for i := 0; i < 4; i++ {
		var b byte
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02X", &b)
		if err != nil {
			return nil, err
		}
		ip[3-i] = b // Reverse byte order (little-endian to big-endian)
	}

	return net.IPv4(ip[0], ip[1], ip[2], ip[3]), nil
}

// resolveMAC resolves the MAC address for an IP address using ARP.
func resolveMAC(ip string) (net.HardwareAddr, error) {
	switch runtime.GOOS {
	case "linux":
		return resolveMACLinux(ip)
	case "darwin":
		return resolveMACDarwin(ip)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func resolveMACLinux(ip string) (net.HardwareAddr, error) {
	// Read /proc/net/arp
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		if fields[0] == ip {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				continue
			}
			// Skip incomplete entries (00:00:00:00:00:00)
			if mac.String() == "00:00:00:00:00:00" {
				continue
			}
			return mac, nil
		}
	}

	// If not in cache, try to ping to populate ARP cache
	exec.Command("ping", "-c", "1", "-W", "1", ip).Run()

	// Try again
	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		if fields[0] == ip {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				continue
			}
			if mac.String() != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}

	return nil, fmt.Errorf("MAC address not found for %s", ip)
}

func resolveMACDarwin(ip string) (net.HardwareAddr, error) {
	debug := os.Getenv("WG_DEBUG_BPF") == "1"

	// Use arp -a to list all entries, then search
	if debug {
		log.Printf("[DETECT] Running arp -n %s...", ip)
	}
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("arp command failed: %w", err)
	}

	// Parse output lines like: "? (10.10.10.1) at 48:a9:8a:b0:bb:d on en0 ifscope [ethernet]"
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Check if this line contains our IP
		if !strings.Contains(line, "("+ip+")") {
			continue
		}

		if debug {
			log.Printf("[DETECT] Found ARP entry: %s", line)
		}

		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "at" && i+1 < len(fields) {
				macStr := fields[i+1]
				// Skip incomplete entries
				if macStr == "(incomplete)" {
					continue
				}
				// Normalize MAC address - macOS abbreviates single hex digits
				// e.g., "48:a9:8a:b0:bb:d" should be "48:a9:8a:b0:bb:0d"
				macStr = normalizeMACAddress(macStr)
				if debug {
					log.Printf("[DETECT] Normalized MAC: %s", macStr)
				}
				mac, err := net.ParseMAC(macStr)
				if err == nil {
					return mac, nil
				}
				if debug {
					log.Printf("[DETECT] MAC parse error: %v", err)
				}
			}
		}
	}

	return nil, fmt.Errorf("MAC address not found for %s (check: arp -a | grep %s)", ip, ip)
}

// normalizeMACAddress pads single-digit hex values with leading zeros.
// macOS arp output abbreviates "0d" as "d", which net.ParseMAC doesn't handle.
func normalizeMACAddress(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return mac
	}
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":")
}
