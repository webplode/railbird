package netbird

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jratienza65/railbird/internal/dns"
	"github.com/netbirdio/netbird/client/embed"
)

// ProbeDNSOverTCP resolves name via TCP to resolver using mesh Dial.
func ProbeDNSOverTCP(ctx context.Context, c *embed.Client, resolver, name string) {
	resolver = strings.TrimSpace(resolver)
	name = strings.TrimSpace(name)
	if resolver == "" || name == "" {
		return
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	r := &dns.Resolver{Server: resolver, Dial: c}
	log.Printf("dns-over-tcp probe: %s via %s (after mesh route delay)", name, resolver)
	select {
	case <-time.After(12 * time.Second):
	case <-ctx.Done():
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ips, err := r.LookupHost(dctx, name)
	if err != nil {
		log.Printf("dns-over-tcp probe %s: FAIL %v", name, err)
		return
	}
	log.Printf("dns-over-tcp probe %s: OK %v", name, ips)
}