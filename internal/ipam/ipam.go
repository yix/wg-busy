package ipam

import (
	"fmt"
	"net"
	"strings"
)

// NextAvailableIP returns the next unallocated host address from the server's
// first IPv4 pool (or first IPv6 pool when IPv6-only) as a /32 or /128 CIDR.
// Both serverAddress and each usedIPs value may be comma-separated CIDR lists.
func NextAvailableIP(serverAddress string, usedIPs []string) (string, error) {
	serverIP, ipNet, err := allocationNetwork(serverAddress)
	if err != nil {
		return "", err
	}

	used := make(map[string]bool)
	used[serverIP.String()] = true

	// Exclude network and broadcast addresses.
	networkAddr := ipNet.IP
	prefixBits := 128
	if ip4 := networkAddr.To4(); ip4 != nil {
		networkAddr = ip4
		prefixBits = 32
		used[networkAddr.String()] = true
		used[broadcastAddress(ipNet).String()] = true
	}

	for _, value := range usedIPs {
		for _, cidr := range strings.Split(value, ",") {
			cidr = strings.TrimSpace(cidr)
			ip, _, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				ip = net.ParseIP(cidr)
			}
			if ip != nil {
				used[ip.String()] = true
			}
		}
	}

	ip := nextIP(networkAddr)
	for ipNet.Contains(ip) {
		if !used[ip.String()] {
			return fmt.Sprintf("%s/%d", ip.String(), prefixBits), nil
		}
		ip = nextIP(ip)
	}

	return "", fmt.Errorf("no available IPs in subnet %s", ipNet.String())
}

func allocationNetwork(addresses string) (net.IP, *net.IPNet, error) {
	var firstIP net.IP
	var firstNet *net.IPNet
	for _, value := range strings.Split(addresses, ",") {
		ip, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		if firstNet == nil {
			firstIP, firstNet = ip, network
		}
		// Preserve the established behavior for dual-stack servers by preferring
		// their IPv4 pool regardless of address-list ordering.
		if ip.To4() != nil {
			return ip, network, nil
		}
	}
	if firstNet != nil {
		return firstIP, firstNet, nil
	}
	return nil, nil, fmt.Errorf("invalid server address %q", addresses)
}

func nextIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		ip = ip.To16()
	}
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			return next
		}
	}
	return nil
}

func broadcastAddress(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := n.Mask
	broadcast := make(net.IP, 4)
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}
