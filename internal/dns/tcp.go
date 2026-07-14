// Package dns provides DNS-over-TCP resolution via a custom dialer (NetBird mesh).
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Dialer opens TCP connections (e.g. NetBird embed.Client.Dial).
type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver resolves hostnames using DNS-over-TCP to server (default VPC resolver).
type Resolver struct {
	Server string
	Dial   Dialer
	Cache  sync.Map // string -> cacheEntry
}

type cacheEntry struct {
	ips []net.IP
	exp time.Time
}

// LookupHost returns IP addresses for name using DNS-over-TCP over Dial.
func (r *Resolver) LookupHost(ctx context.Context, name string) ([]net.IP, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, fmt.Errorf("empty name")
	}
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}
	if v, ok := r.Cache.Load(name); ok {
		e := v.(cacheEntry)
		if time.Now().Before(e.exp) && len(e.ips) > 0 {
			return e.ips, nil
		}
	}
	ips, ttl, err := r.exchange(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", name)
	}
	ttl = clampTTL(ttl)
	r.Cache.Store(name, cacheEntry{ips: ips, exp: time.Now().Add(ttl)})
	return ips, nil
}

func clampTTL(ttl time.Duration) time.Duration {
	const min, max = 30 * time.Second, 10 * time.Minute
	if ttl < min {
		return min
	}
	if ttl > max {
		return max
	}
	return ttl
}

func (r *Resolver) exchange(ctx context.Context, name string) ([]net.IP, time.Duration, error) {
	conn, err := r.Dial.Dial(ctx, "tcp", r.Server)
	if err != nil {
		return nil, 0, fmt.Errorf("dns tcp dial %s: %w", r.Server, err)
	}
	defer conn.Close()

	dc := &dns.Conn{Conn: conn}
	cur := dns.Fqdn(name)
	var minTTL uint32 = 60

	for hop := 0; hop < 8; hop++ {
		ips, cname, ttl, err := r.queryConn(ctx, dc, cur, dns.TypeA)
		if err != nil {
			return nil, 0, err
		}
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
		if len(ips) > 0 {
			return ips, time.Duration(minTTL) * time.Second, nil
		}
		ips, cname2, ttl, err := r.queryConn(ctx, dc, cur, dns.TypeAAAA)
		if err != nil {
			return nil, 0, err
		}
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
		if len(ips) > 0 {
			return ips, time.Duration(minTTL) * time.Second, nil
		}
		next := cname
		if next == "" {
			next = cname2
		}
		if next == "" {
			return nil, 0, fmt.Errorf("no A/AAAA for %q", name)
		}
		cur = next
	}
	return nil, 0, fmt.Errorf("cname chain too long for %q", name)
}

func (r *Resolver) queryConn(ctx context.Context, dc *dns.Conn, name string, qtype uint16) ([]net.IP, string, uint32, error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}

	client := dns.Client{Net: "tcp", Timeout: 15 * time.Second}
	in, _, err := client.ExchangeWithConnContext(ctx, m, dc)
	if err != nil {
		return nil, "", 0, err
	}
	if in == nil {
		return nil, "", 0, fmt.Errorf("empty dns response")
	}
	if rc := in.Rcode; rc != dns.RcodeSuccess {
		return nil, "", 0, fmt.Errorf("dns %s", dns.RcodeToString[rc])
	}

	var ips []net.IP
	var cname string
	var minTTL uint32 = 3600
	for _, rr := range in.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		case *dns.CNAME:
			cname = v.Target
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		}
	}
	return ips, cname, minTTL, nil
}