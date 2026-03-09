package main

import (
	"io"
	"net"
	"sort"
	"strings"
)

// ObscuredPrefixString constructs the obscured 4-hextet prefix.
//
// Example:
//
//	2a01:04f8:0123:0456
//
// becomes:
//
//	3fff:0abc:0def:0456
func ObscuredPrefixString(parts [4]string) string {
	return strings.Join([]string{"3fff", "0abc", "0def", parts[3]}, ":")
}

// ObscureIPv6Text scans text for IPv6-like tokens and rewrites only addresses
// whose first 4 hextets match the detected prefix.
func ObscureIPv6Text(s string, state State) string {
	if !state.HasPrefix() {
		return s
	}

	var out strings.Builder
	out.Grow(len(s))

	for i := 0; i < len(s); {
		if isIPv6ishChar(s[i]) {
			start := i
			for i < len(s) && isIPv6ishChar(s[i]) {
				i++
			}
			token := s[start:i]
			out.WriteString(rewriteIPv6ishToken(token, state))
			continue
		}

		out.WriteByte(s[i])
		i++
	}

	return out.String()
}

// StreamObscure rewrites matching IPv6 addresses while streaming from r to w.
func StreamObscure(r io.Reader, w io.Writer, state State) error {
	if !ObscuringEnabled() || !state.HasPrefix() {
		_, err := io.Copy(w, r)
		return err
	}

	buf := make([]byte, 1024) // Smaller buffer for more frequent flushes
	var carry string

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := carry + string(buf[:n])

			// We only want to process up to the last non-IPv6ish character
			// to ensure we don't break a potential IPv6 address in half.
			flush, rest := splitStreamingChunk(chunk)
			carry = rest

			if flush != "" {
				if _, writeErr := io.WriteString(w, ObscureIPv6Text(flush, state)); writeErr != nil {
					return writeErr
				}
			}
		}

		if err == io.EOF {
			// Final flush of remaining carry
			if carry != "" {
				if _, writeErr := io.WriteString(w, ObscureIPv6Text(carry, state)); writeErr != nil {
					return writeErr
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func splitStreamingChunk(s string) (string, string) {
	// If the chunk is very long, force a flush even if it looks like a partial token.
	// This prevents the "carry" buffer from growing indefinitely.
	if len(s) > 2048 {
		return s, ""
	}

	// Otherwise, keep the existing logic:
	for i := len(s) - 1; i >= 0; i-- {
		if !isIPv6ishChar(s[i]) {
			return s[:i+1], s[i+1:]
		}
	}
	return "", s
}

// isIPv6ishChar identifies characters that may occur in an IPv6-containing
// token.
func isIPv6ishChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	case c >= 'g' && c <= 'z':
		return false
	case c >= 'G' && c <= 'Z':
		return false
	}

	switch c {
	case ':', '.', '%', '/', '[', ']', '-', '_':
		return true
	default:
		return false
	}
}

// rewriteIPv6ishToken attempts to find IPv6 substrings inside a token and
// rewrite only those that match the local prefix.
func rewriteIPv6ishToken(token string, state State) string {
	if strings.Count(token, ":") < 2 {
		return token
	}

	var out strings.Builder
	out.Grow(len(token))

	for i := 0; i < len(token); {
		if !canStartIPv6(token[i]) {
			out.WriteByte(token[i])
			i++
			continue
		}

		if matched, end, rendered := longestMatchingIPv6At(token, i, state); matched {
			out.WriteString(rendered)
			i = end
			continue
		}

		out.WriteByte(token[i])
		i++
	}

	return out.String()
}

func canStartIPv6(c byte) bool {
	return c == '[' || isHexDigit(c)
}

func isHexDigit(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	default:
		return false
	}
}

func longestMatchingIPv6At(token string, start int, state State) (matched bool, end int, rendered string) {
	if start >= len(token) {
		return false, 0, ""
	}

	maxEnd := scanIPv6CandidateEnd(token, start)
	if maxEnd-start < 2 {
		return false, 0, ""
	}

	for end = maxEnd; end > start+1; end-- {
		sub := token[start:end]
		ip, cidr, zone, bracket, ok := parseEmbeddedIPv6(sub)
		if !ok {
			continue
		}
		if !IsGlobalishIPv6(ip) || !MatchesPrefix(ip, state.PrefixParts) {
			continue
		}
		return true, end, RenderObscuredIPv6(ip, cidr, zone, bracket)
	}

	return false, 0, ""
}

func scanIPv6CandidateEnd(token string, start int) int {
	end := start
	for end < len(token) {
		c := token[end]
		if c == '-' || c == '_' {
			break
		}
		if !isIPv6ishChar(c) {
			break
		}
		end++
	}
	return end
}

// parseEmbeddedIPv6 parses a substring that may represent:
//   - bare IPv6
//   - bracketed IPv6
//   - IPv6 with CIDR suffix
//   - IPv6 with zone suffix
func parseEmbeddedIPv6(s string) (ip net.IP, cidr string, zone string, bracket bool, ok bool) {
	bracket = len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']'
	if bracket {
		s = s[1 : len(s)-1]
	}

	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		cidr = s[slash:]
		s = s[:slash]
	}

	if pct := strings.IndexByte(s, '%'); pct >= 0 {
		zone = s[pct:]
		s = s[:pct]
	}

	if strings.Count(s, ":") < 2 {
		return nil, "", "", false, false
	}

	parsed := net.ParseIP(s)
	if parsed == nil || parsed.To4() != nil {
		return nil, "", "", false, false
	}

	return parsed, cidr, zone, bracket, true
}

// MatchesPrefix reports whether the first 4 expanded hextets of ip match the
// given prefix parts.
func MatchesPrefix(ip net.IP, prefixParts [4]string) bool {
	expanded := ExpandIPv6(ip)
	if expanded == "" {
		return false
	}

	start := 0
	for i, prefixPart := range prefixParts {
		end := start + 4
		if end > len(expanded) {
			return false
		}
		if !strings.EqualFold(expanded[start:end], prefixPart) {
			return false
		}
		if i < 3 {
			if end >= len(expanded) || expanded[end] != ':' {
				return false
			}
			start = end + 1
		}
	}
	return true
}

// RenderObscuredIPv6 rewrites the first three hextets, preserves the 4th,
// and keeps the rest of the address unchanged.
func RenderObscuredIPv6(ip net.IP, cidr string, zone string, bracket bool) string {
	expanded := ExpandIPv6(ip)
	parts := strings.Split(expanded, ":")
	if len(parts) != 8 {
		return formatAddress(ip.String(), cidr, zone, bracket)
	}

	parts[0] = "3fff"
	parts[1] = "0abc"
	parts[2] = "0def"

	newIP, ok := parseExpandedIPv6(parts)
	if !ok {
		return formatAddress(ip.String(), cidr, zone, bracket)
	}

	return formatAddress(newIP.String(), cidr, zone, bracket)
}

// parseExpandedIPv6 parses exactly 8 explicit hextets into a net.IP value.
func parseExpandedIPv6(parts []string) (net.IP, bool) {
	if len(parts) != 8 {
		return nil, false
	}

	ip := net.ParseIP(strings.Join(parts, ":"))
	if ip == nil || ip.To4() != nil {
		return nil, false
	}
	return ip, true
}

// formatAddress reconstructs the address, optionally re-adding brackets, zone,
// and CIDR suffix.
func formatAddress(ip string, cidr string, zone string, bracket bool) string {
	if bracket {
		return "[" + ip + "]" + zone + cidr
	}
	return ip + zone + cidr
}
