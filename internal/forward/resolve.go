package forward

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/dns"
)

// HostResolver resolves hostnames for egress mesh dials.
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]net.IP, error)
}

// ResolveEgressTarget turns host:port into ip:port when host is not a literal IP.
func ResolveEgressTarget(ctx context.Context, target string, mode config.Mode, res HostResolver) (string, error) {
	if mode != config.ModeEgress || res == nil {
		return target, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, err
	}
	if net.ParseIP(host) != nil {
		return target, nil
	}
	ips, err := res.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	log.Printf("dns-over-tcp: %s -> %s (for :%s)", host, ips[0], port)
	return net.JoinHostPort(ips[0].String(), port), nil
}

// NewTCPResolver builds a DNS-over-TCP resolver when enabled.
func NewTCPResolver(enabled bool, server string, dial dns.Dialer) HostResolver {
	if !enabled || strings.TrimSpace(server) == "" || dial == nil {
		return nil
	}
	return &dns.Resolver{Server: server, Dial: dial}
}