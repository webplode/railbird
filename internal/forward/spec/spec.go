// Package spec owns the dependency-neutral forward specification parser.
package spec

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Forward describes a single listen-port to target mapping.
type Forward struct {
	ListenPort string
	Target     string
}

// Parse parses and validates a non-empty comma-separated forward list.
func Parse(s string) ([]Forward, error) {
	items := strings.Split(s, ",")
	out := make([]Forward, 0, len(items))
	listeners := make(map[string]int, len(items))

	for i, raw := range items {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, fmt.Errorf("forward entry %d is empty", i+1)
		}

		listenPort, target := "", item
		before, after, explicitListener := strings.Cut(item, "=")
		if explicitListener {
			listenPort = strings.TrimSpace(before)
			target = strings.TrimSpace(after)
			if strings.Contains(target, "=") {
				return nil, fmt.Errorf("forward entry %d has invalid syntax", i+1)
			}
		}

		if target == "" {
			return nil, fmt.Errorf("forward entry %d has an empty target", i+1)
		}
		targetHost, targetPort, err := net.SplitHostPort(target)
		if err != nil || targetHost == "" || !validHost(targetHost) {
			return nil, fmt.Errorf("forward entry %d has an invalid target address", i+1)
		}
		targetPort, err = normalizePort(targetPort)
		if err != nil {
			return nil, fmt.Errorf("forward entry %d target port: %w", i+1, err)
		}
		if !explicitListener {
			listenPort = targetPort
		}
		listenPort, err = normalizePort(listenPort)
		if err != nil {
			return nil, fmt.Errorf("forward entry %d listen port: %w", i+1, err)
		}
		if previous, exists := listeners[listenPort]; exists {
			return nil, fmt.Errorf("forward entries %d and %d use duplicate listen port %s", previous, i+1, listenPort)
		}
		listeners[listenPort] = i + 1
		out = append(out, Forward{ListenPort: listenPort, Target: net.JoinHostPort(targetHost, targetPort)})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no forwards configured")
	}
	return out, nil
}

func normalizePort(port string) (string, error) {
	if port == "" {
		return "", fmt.Errorf("is empty")
	}
	if !asciiDigits(port) {
		return "", fmt.Errorf("must be numeric and between 1 and 65535")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("must be numeric and between 1 and 65535")
	}
	return strconv.Itoa(n), nil
}

func asciiDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func validHost(host string) bool {
	if ipHost, zone, hasZone := strings.Cut(host, "%"); hasZone {
		return zone != "" && !strings.ContainsAny(zone, "[]:%") && net.ParseIP(ipHost) != nil
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
