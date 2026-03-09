package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// State contains the detected interface and local IPv6 prefix.
//
// Prefix is stored as 4 fully expanded lowercase hextets:
//
//	2a01:04f8:0123:0456
//
// PrefixParts stores the same prefix split into four elements for easier
// comparison and rewriting.
type State struct {
	Dev         string
	Prefix      string
	PrefixParts [4]string
}

// HasPrefix reports whether prefix detection succeeded.
func (s *State) HasPrefix() bool {
	return s.Prefix != ""
}

// ifaceCandidate is used to rank candidate interfaces.
type ifaceCandidate struct {
	Name     string
	Priority int
}

// DetectState tries to determine the preferred interface and a matching global
// IPv6 prefix. Failure is tolerated; an empty state is returned in that case.
func DetectState() State {
	dev, _ := PickIPv6Dev()
	prefix, parts, _ := GetIPv6PrefixFromDev(dev)

	return State{
		Dev:         dev,
		Prefix:      prefix,
		PrefixParts: parts,
	}
}

// PickIPv6Dev chooses the first UP Ethernet-like interface, otherwise the first
// UP Wi-Fi-like interface.
//
// Heuristics:
//
//	Ethernet-like: name starts with "eth" or "en"
//	Wi-Fi-like:    name starts with "wlp" or "wl"
func PickIPv6Dev() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}

	var candidates []ifaceCandidate

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {

			continue
		}

		name := strings.ToLower(iface.Name)

		switch {
		case strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "en"):
			candidates = append(candidates, ifaceCandidate{Name: iface.Name, Priority: 0})
		case strings.HasPrefix(name, "wlp"), strings.HasPrefix(name, "wl"):
			candidates = append(candidates, ifaceCandidate{Name: iface.Name, Priority: 1})
		}
	}

	if len(candidates) == 0 {
		return "", errors.New("no UP Ethernet or Wi-Fi interface found")
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].Name < candidates[j].Name
	})

	return candidates[0].Name, nil
}

// GetIPv6PrefixFromDev returns the first 4 hextets of the first usable global
// IPv6 address found on the given device.
func GetIPv6PrefixFromDev(dev string) (string, [4]string, error) {
	var zero [4]string

	if dev == "" {
		return "", zero, errors.New("empty device name")
	}

	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return "", zero, fmt.Errorf("finding interface %q: %w", dev, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", zero, fmt.Errorf("reading addresses for %q: %w", dev, err)
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.To4() != nil {
			continue
		}
		if !IsGlobalishIPv6(ip) {
			continue
		}

		expanded := ExpandIPv6(ip)
		parts := strings.Split(expanded, ":")
		if len(parts) != 8 {
			continue
		}

		var prefixParts [4]string
		copy(prefixParts[:], parts[:4])

		return strings.Join(parts[:4], ":"), prefixParts, nil
	}

	return "", zero, errors.New("no matching global IPv6 address found")
}

// IsGlobalishIPv6 filters out special/local IPv6 addresses that should not be
// treated as globally routable addresses for this use case.
func IsGlobalishIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}

	expanded := strings.ToLower(ExpandIPv6(ip))

	// Link-local fe80::/10
	if strings.HasPrefix(expanded, "fe8") ||
		strings.HasPrefix(expanded, "fe9") ||
		strings.HasPrefix(expanded, "fea") ||
		strings.HasPrefix(expanded, "feb") {
		return false
	}

	// Unique local fc00::/7
	if strings.HasPrefix(expanded, "fc") || strings.HasPrefix(expanded, "fd") {
		return false
	}

	return true
}

// ExpandIPv6 converts an IPv6 address to its fully expanded 8-hextet lowercase
// representation.
func ExpandIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%02x%02x", ip[i], ip[i+1]))
	}
	return strings.Join(parts, ":")
}

// ObscuringEnabled mirrors the original shell logic:
//
//	if dontObscureIPv6 is set and non-empty, obscuring is disabled.
func ObscuringEnabled() bool {
	return os.Getenv("dontObscureIPv6") == ""
}
