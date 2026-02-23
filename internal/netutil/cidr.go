package netutil

import (
	"fmt"
	"net"
	"strings"
)

// ExpandTargets takes a CIDR range and a set of ports, and returns a list
// of base URLs (scheme://host:port) to scan.
func ExpandTargets(cidr string, portsStr string, scheme string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Maybe it's a single IP, not a CIDR.
		ip = net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR or IP: %q", cidr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipnet = &net.IPNet{IP: ip, Mask: mask}
	}

	ports := parsePorts(portsStr)
	if len(ports) == 0 {
		if scheme == "https" {
			ports = []string{"443"}
		} else {
			ports = []string{"80"}
		}
	}

	var urls []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		// Skip network and broadcast addresses for /24 and larger.
		ones, bits := ipnet.Mask.Size()
		if bits-ones > 1 {
			if ip.Equal(ipnet.IP) {
				continue // network address
			}
			bcast := broadcastAddr(ipnet)
			if ip.Equal(bcast) {
				continue // broadcast address
			}
		}

		for _, port := range ports {
			host := ip.String()
			// Skip default port in URL for cleanliness.
			if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
				urls = append(urls, fmt.Sprintf("%s://%s", scheme, host))
			} else {
				urls = append(urls, fmt.Sprintf("%s://%s:%s", scheme, host, port))
			}
		}
	}

	return urls, nil
}

func parsePorts(s string) []string {
	if s == "" {
		return nil
	}
	var ports []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			ports = append(ports, p)
		}
	}
	return ports
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func broadcastAddr(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	for i := range ip {
		ip[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip
}
