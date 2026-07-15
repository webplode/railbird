// Package dns provides DNS-over-TCP resolution via a custom dialer (NetBird mesh).
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	defaultQueryTimeout = 5 * time.Second
	defaultMaxTTL       = 10 * time.Minute
	maxCNAMEHops        = 8
)

// Dialer opens TCP connections (for example embed.Client.Dial).
type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver resolves hostnames using DNS-over-TCP to Server through Dial.
// Cache is exported only for compatibility with the original implementation;
// callers should treat its contents as opaque.
type Resolver struct {
	Server       string
	Dial         Dialer
	QueryTimeout time.Duration
	MaxTTL       time.Duration
	Cache        sync.Map // normalized name -> cacheEntry

	mu       sync.Mutex
	inflight map[string]*lookupCall
	now      func() time.Time
}

type cacheEntry struct {
	ips []net.IP
	exp time.Time
}

type lookupCall struct {
	done chan struct{}
	ips  []net.IP
	err  error
}

// ResponseError reports a valid DNS response with a non-success RCODE.
type ResponseError struct {
	Name  string
	RCode int
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("dns %s for %q", mdns.RcodeToString[e.RCode], e.Name)
}

// LookupHost returns all A and AAAA addresses for name in deterministic
// resolver order. Concurrent cold lookups for the same normalized name share
// one exchange. Positive answers are cached no longer than their authoritative
// TTL; TTL zero deliberately disables caching.
func (r *Resolver) LookupHost(ctx context.Context, name string) ([]net.IP, error) {
	name = normalizeName(name)
	if name == "" {
		return nil, fmt.Errorf("empty name")
	}
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{cloneIP(ip)}, nil
	}

	if ips, ok := r.cached(name, r.clock()()); ok {
		return ips, nil
	}

	call, leader := r.acquireLookup(name)
	if !leader {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			return cloneIPs(call.ips), call.err
		}
	}
	// A caller can miss the cache, be descheduled, then acquire leadership
	// after the previous leader has populated the cache and removed its
	// in-flight entry. Re-check after leadership acquisition to close that
	// window without issuing a duplicate mesh DNS exchange.
	if ips, ok := r.cached(name, r.clock()()); ok {
		r.finishLookup(name, call, ips, nil)
		return ips, nil
	}

	ips, ttl, err := r.exchange(ctx, name)
	if err == nil && len(ips) == 0 {
		err = fmt.Errorf("no addresses for %q", name)
	}
	if err == nil {
		ttl = clampTTLWithMax(ttl, r.maximumTTL())
		if ttl > 0 {
			r.Cache.Store(name, cacheEntry{
				ips: cloneIPs(ips),
				exp: r.clock()().Add(ttl),
			})
		}
	}
	r.finishLookup(name, call, ips, err)
	return cloneIPs(ips), err
}

func (r *Resolver) cached(name string, now time.Time) ([]net.IP, bool) {
	v, ok := r.Cache.Load(name)
	if !ok {
		return nil, false
	}
	e, valid := v.(cacheEntry)
	if valid && len(e.ips) > 0 && now.Before(e.exp) {
		return cloneIPs(e.ips), true
	}
	r.Cache.Delete(name)
	return nil, false
}

func (r *Resolver) acquireLookup(name string) (*lookupCall, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight == nil {
		r.inflight = make(map[string]*lookupCall)
	}
	if call, ok := r.inflight[name]; ok {
		return call, false
	}
	call := &lookupCall{done: make(chan struct{})}
	r.inflight[name] = call
	return call, true
}

func (r *Resolver) finishLookup(name string, call *lookupCall, ips []net.IP, err error) {
	r.mu.Lock()
	call.ips = cloneIPs(ips)
	call.err = err
	delete(r.inflight, name)
	close(call.done)
	r.mu.Unlock()
}

func (r *Resolver) clock() func() time.Time {
	if r.now != nil {
		return r.now
	}
	return time.Now
}

func (r *Resolver) queryTimeout() time.Duration {
	if r.QueryTimeout > 0 {
		return r.QueryTimeout
	}
	return defaultQueryTimeout
}

func (r *Resolver) maximumTTL() time.Duration {
	if r.MaxTTL > 0 {
		return r.MaxTTL
	}
	return defaultMaxTTL
}

// clampTTL keeps the historical helper name while removing the unsafe 30s
// floor. Short authoritative TTLs must remain short for RDS failover.
func clampTTL(ttl time.Duration) time.Duration {
	return clampTTLWithMax(ttl, defaultMaxTTL)
}

func clampTTLWithMax(ttl, max time.Duration) time.Duration {
	if ttl <= 0 {
		return 0
	}
	if max > 0 && ttl > max {
		return max
	}
	return ttl
}

func (r *Resolver) exchange(ctx context.Context, name string) ([]net.IP, time.Duration, error) {
	if r.Dial == nil {
		return nil, 0, fmt.Errorf("dns tcp dialer is nil")
	}
	server := strings.TrimSpace(r.Server)
	if server == "" {
		return nil, 0, fmt.Errorf("dns tcp server is empty")
	}
	conn, err := r.Dial.Dial(ctx, "tcp", server)
	if err != nil {
		return nil, 0, fmt.Errorf("dns tcp dial %s: %w", server, err)
	}
	defer conn.Close()

	dc := &mdns.Conn{Conn: conn}
	cur := mdns.Fqdn(name)
	seen := map[string]struct{}{normalizeFQDN(cur): {}}
	var minTTL time.Duration
	var ttlSet bool

	for hop := 0; hop < maxCNAMEHops; hop++ {
		a, err := r.queryConn(ctx, dc, cur, mdns.TypeA)
		if err != nil {
			return nil, 0, err
		}
		aaaa, err := r.queryConn(ctx, dc, cur, mdns.TypeAAAA)
		if err != nil {
			return nil, 0, err
		}

		minTTL, ttlSet = mergeTTL(minTTL, ttlSet, a.ttl, a.ttlSet)
		minTTL, ttlSet = mergeTTL(minTTL, ttlSet, aaaa.ttl, aaaa.ttlSet)
		ips := append(cloneIPs(a.ips), cloneIPs(aaaa.ips)...)
		if len(ips) > 0 {
			if !ttlSet {
				return nil, 0, fmt.Errorf("dns response for %q has addresses without TTL", name)
			}
			return ips, minTTL, nil
		}

		next, err := selectNextCNAME(a.next, aaaa.next)
		if err != nil {
			return nil, 0, fmt.Errorf("resolve %q: %w", name, err)
		}
		if next == "" {
			return nil, 0, fmt.Errorf("no A/AAAA for %q", name)
		}
		key := normalizeFQDN(next)
		if _, ok := seen[key]; ok {
			return nil, 0, fmt.Errorf("cname loop for %q", name)
		}
		seen[key] = struct{}{}
		cur = mdns.Fqdn(next)
	}
	return nil, 0, fmt.Errorf("cname chain too long for %q", name)
}

type queryResult struct {
	ips    []net.IP
	next   string
	ttl    time.Duration
	ttlSet bool
}

func (r *Resolver) queryConn(ctx context.Context, dc *mdns.Conn, name string, qtype uint16) (queryResult, error) {
	qname := mdns.Fqdn(name)
	m := new(mdns.Msg)
	m.Id = mdns.Id()
	m.RecursionDesired = true
	m.Question = []mdns.Question{{Name: qname, Qtype: qtype, Qclass: mdns.ClassINET}}

	qctx, cancel := context.WithTimeout(ctx, r.queryTimeout())
	defer cancel()
	client := mdns.Client{Net: "tcp", Timeout: r.queryTimeout()}
	exchangeDone := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-qctx.Done():
			// miekg/dns does not interrupt an in-flight read on an existing
			// connection when only the context is cancelled. Forcing the
			// deadline wakes that read; synchronization below prevents this
			// watcher from racing with deadline reset before connection reuse.
			_ = dc.Conn.SetDeadline(time.Now())
		case <-exchangeDone:
		}
		close(watchDone)
	}()
	in, _, err := client.ExchangeWithConnContext(qctx, m, dc)
	close(exchangeDone)
	<-watchDone
	if clearErr := dc.Conn.SetDeadline(time.Time{}); err == nil && clearErr != nil {
		err = fmt.Errorf("reset dns tcp deadline: %w", clearErr)
	}
	if err != nil {
		if qctx.Err() != nil {
			err = qctx.Err()
		}
		return queryResult{}, fmt.Errorf("dns %s query %s: %w", mdns.TypeToString[qtype], qname, err)
	}
	if err := validateResponse(m, in); err != nil {
		return queryResult{}, err
	}
	if in.Rcode != mdns.RcodeSuccess {
		return queryResult{}, &ResponseError{Name: normalizeName(qname), RCode: in.Rcode}
	}
	return parseAnswer(qname, qtype, in.Answer)
}

func validateResponse(req, resp *mdns.Msg) error {
	if resp == nil {
		return fmt.Errorf("empty dns response")
	}
	if !resp.Response {
		return fmt.Errorf("dns message is not a response")
	}
	if resp.Id != req.Id {
		return fmt.Errorf("dns response id mismatch")
	}
	if len(resp.Question) != 1 || len(req.Question) != 1 {
		return fmt.Errorf("dns response question count mismatch")
	}
	want, got := req.Question[0], resp.Question[0]
	if normalizeFQDN(want.Name) != normalizeFQDN(got.Name) || want.Qtype != got.Qtype || want.Qclass != got.Qclass {
		return fmt.Errorf("dns response question mismatch")
	}
	return nil
}

func parseAnswer(qname string, qtype uint16, answers []mdns.RR) (queryResult, error) {
	cnames := make(map[string]*mdns.CNAME)
	for _, rr := range answers {
		cname, ok := rr.(*mdns.CNAME)
		if !ok {
			continue
		}
		owner := normalizeFQDN(cname.Hdr.Name)
		if previous, exists := cnames[owner]; exists && normalizeFQDN(previous.Target) != normalizeFQDN(cname.Target) {
			return queryResult{}, fmt.Errorf("conflicting cname targets for %s", cname.Hdr.Name)
		}
		cnames[owner] = cname
	}

	allowed := map[string]struct{}{normalizeFQDN(qname): {}}
	cur := normalizeFQDN(qname)
	var result queryResult
	for hop := 0; hop < maxCNAMEHops; hop++ {
		cname, ok := cnames[cur]
		if !ok {
			break
		}
		result.ttl, result.ttlSet = mergeTTL(result.ttl, result.ttlSet, time.Duration(cname.Hdr.Ttl)*time.Second, true)
		next := normalizeFQDN(cname.Target)
		if _, exists := allowed[next]; exists {
			return queryResult{}, fmt.Errorf("cname loop in response for %s", qname)
		}
		allowed[next] = struct{}{}
		result.next = mdns.Fqdn(cname.Target)
		cur = next
	}
	if cname, ok := cnames[cur]; ok && cname != nil {
		return queryResult{}, fmt.Errorf("cname chain too long in response for %s", qname)
	}

	for _, rr := range answers {
		var ip net.IP
		switch value := rr.(type) {
		case *mdns.A:
			if qtype != mdns.TypeA {
				return queryResult{}, fmt.Errorf("dns response contains mismatched A answer")
			}
			ip = value.A
		case *mdns.AAAA:
			if qtype != mdns.TypeAAAA {
				return queryResult{}, fmt.Errorf("dns response contains mismatched AAAA answer")
			}
			ip = value.AAAA
		default:
			continue
		}
		if _, ok := allowed[normalizeFQDN(rr.Header().Name)]; !ok {
			return queryResult{}, fmt.Errorf("dns response contains unrelated address answer")
		}
		if ip == nil {
			return queryResult{}, fmt.Errorf("dns response contains empty address")
		}
		result.ips = append(result.ips, cloneIP(ip))
		result.ttl, result.ttlSet = mergeTTL(result.ttl, result.ttlSet, time.Duration(rr.Header().Ttl)*time.Second, true)
	}
	return result, nil
}

func selectNextCNAME(a, b string) (string, error) {
	if a == "" {
		return b, nil
	}
	if b == "" {
		return a, nil
	}
	if normalizeFQDN(a) != normalizeFQDN(b) {
		return "", fmt.Errorf("cname targets for A and AAAA disagree")
	}
	return a, nil
}

func mergeTTL(current time.Duration, currentSet bool, candidate time.Duration, candidateSet bool) (time.Duration, bool) {
	if !candidateSet {
		return current, currentSet
	}
	if !currentSet || candidate < current {
		return candidate, true
	}
	return current, true
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func normalizeFQDN(name string) string {
	return strings.ToLower(mdns.Fqdn(strings.TrimSpace(name)))
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func cloneIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, len(ips))
	for i := range ips {
		out[i] = cloneIP(ips[i])
	}
	return out
}
