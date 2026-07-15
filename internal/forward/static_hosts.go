package forward

import (
	"context"
	"net"
	"strings"
)

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
