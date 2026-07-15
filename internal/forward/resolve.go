package forward

import (
	"context"
	"errors"
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

// ResolveEgressTargets turns host:port into every resolved ip:port target in
// resolver order. Hostnames in egress mode are deliberately rejected when no
// approved resolver is configured; railbird must never fall back to host DNS.
func ResolveEgressTargets(ctx context.Context, target string, mode config.Mode, res HostResolver) ([]string, error) {
	if mode != config.ModeEgress {
		return []string{target}, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: invalid address")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	if res == nil {
		return nil, fmt.Errorf("resolve target=%s: no approved egress resolver configured", redactedTarget(target))
	}
	ips, err := res.LookupHost(ctx, host)
	if err != nil {
		var responseErr *dns.ResponseError
		if errors.As(err, &responseErr) {
			return nil, &safeNetworkError{
				prefix: fmt.Sprintf("resolve target=%s", redactedTarget(target)),
				class:  fmt.Sprintf("dns response code=%d", responseErr.RCode),
				cause:  err,
			}
		}
		return nil, redactNetworkError(fmt.Sprintf("resolve target=%s", redactedTarget(target)), err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve target=%s: resolver returned no addresses", redactedTarget(target))
	}

	seen := make(map[string]struct{}, len(ips))
	targets := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		value := ip.String()
		if value == "<nil>" || value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		targets = append(targets, net.JoinHostPort(value, port))
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("resolve target=%s: resolver returned no usable addresses", redactedTarget(target))
	}
	log.Printf("dns-over-tcp target=%s answers=%d", redactedTarget(target), len(targets))
	return targets, nil
}

// ResolveEgressTarget is retained for compatibility. New dialing code should
// use ResolveEgressTargets so it can attempt every returned address.
func ResolveEgressTarget(ctx context.Context, target string, mode config.Mode, res HostResolver) (string, error) {
	targets, err := ResolveEgressTargets(ctx, target, mode, res)
	if err != nil {
		return "", err
	}
	return targets[0], nil
}

// NewTCPResolver builds a DNS-over-TCP resolver when enabled.
func NewTCPResolver(enabled bool, server string, dial dns.Dialer) HostResolver {
	if !enabled || strings.TrimSpace(server) == "" || dial == nil {
		return nil
	}
	return &dns.Resolver{Server: server, Dial: dial}
}
