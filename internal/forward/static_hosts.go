package forward

import (
	"context"
	"net"
	"strings"
)

// ParseStaticHosts parses NB_STATIC_HOSTS: comma-separated host=ip entries.
func ParseStaticHosts(raw string) map[string]net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	m := make(map[string]net.IP)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, ipStr, ok := strings.Cut(part, "=")
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		ipStr = strings.TrimSpace(ipStr)
		if !ok || host == "" || ipStr == "" {
			continue
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			m[host] = ip
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

type staticResolver struct {
	hosts map[string]net.IP
	next  HostResolver
}

func (s *staticResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	key := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip, ok := s.hosts[key]; ok {
		return []net.IP{ip}, nil
	}
	if s.next == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return s.next.LookupHost(ctx, host)
}

// ChainResolver static map first, then optional DNS-over-TCP.
func ChainResolver(static map[string]net.IP, next HostResolver) HostResolver {
	if len(static) == 0 {
		return next
	}
	return &staticResolver{hosts: static, next: next}
}