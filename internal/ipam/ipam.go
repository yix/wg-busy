package ipam

import (
	"fmt"
	"math/big"
	"net"
)

// NextAvailableIP returns the next unallocated IP within the server's subnet as a /32 CIDR.
// serverAddress: e.g. "10.0.0.1/24"
// usedIPs: list of CIDRs already assigned, e.g. ["10.0.0.2/32", "10.0.0.3/32"]
func NextAvailableIP(serverAddress string, usedIPs []string) (string, error) {
	serverIP, ipNet, err := net.ParseCIDR(serverAddress)
	if err != nil {
		return "", fmt.Errorf("invalid server address: %w", err)
	}

	used := make(map[string]bool)
	used[serverIP.String()] = true

	// Exclude network and broadcast addresses.
	networkAddr := ipNet.IP.To4()
	if networkAddr != nil {
		used[networkAddr.String()] = true
		used[broadcastAddress(ipNet).String()] = true
	}

	for _, cidr := range usedIPs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			ip = net.ParseIP(cidr)
		}
		if ip != nil {
			used[ip.String()] = true
		}
	}

	ip := nextIP(networkAddr)
	for ipNet.Contains(ip) {
		if !used[ip.String()] {
			return fmt.Sprintf("%s/32", ip.String()), nil
		}
		ip = nextIP(ip)
	}

	return "", fmt.Errorf("no available IPs in subnet %s", ipNet.String())
}

func nextIP(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	i := big.NewInt(0).SetBytes(ip4)
	i.Add(i, big.NewInt(1))
	b := i.Bytes()
	result := make(net.IP, 4)
	copy(result[4-len(b):], b)
	return result
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
