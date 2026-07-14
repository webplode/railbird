// Package dns provides DNS-over-TCP resolution via a custom dialer (NetBird mesh).
package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
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
	const maxCNAMEFollow = 8
	cur := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for hop := 0; hop < maxCNAMEFollow; hop++ {
		for _, qtype := range []uint16{1, 28} { // A, AAAA
			ips, cnames, ttl, err := r.query(ctx, buildQuery(cur, qtype))
			if err != nil {
				return nil, 0, err
			}
			if len(ips) > 0 {
				return ips, ttl, nil
			}
			if len(cnames) > 0 {
				cur = cnames[0]
				break
			}
			if qtype == 28 {
				return nil, 0, fmt.Errorf("no A/AAAA for %q", name)
			}
		}
		if hop == maxCNAMEFollow-1 {
			return nil, 0, fmt.Errorf("cname loop for %q", name)
		}
	}
	return nil, 0, fmt.Errorf("no addresses for %q", name)
}

func (r *Resolver) query(ctx context.Context, msg []byte) ([]net.IP, []string, time.Duration, error) {
	conn, err := r.Dial.Dial(ctx, "tcp", r.Server)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("dns tcp dial %s: %w", r.Server, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline(ctx, 10*time.Second))

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, nil, 0, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, nil, 0, err
	}

	if _, err := conn.Read(lenBuf[:]); err != nil {
		return nil, nil, 0, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 65535 {
		return nil, nil, 0, fmt.Errorf("invalid dns response length %d", n)
	}
	buf := make([]byte, n)
	if _, err := readFull(conn, buf); err != nil {
		return nil, nil, 0, err
	}
	return parseAnswers(buf)
}

func rcodeString(rcode int) string {
	switch rcode {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func deadline(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func buildQuery(name string, qtype uint16) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0x1234)
	buf[2] = 0x01 // RD
	binary.BigEndian.PutUint16(buf[4:6], 1)

	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			continue
		}
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0)
	buf = append(buf, 0, byte(qtype>>8), byte(qtype), 0, 0x01)
	// EDNS0 OPT — VPC Route 53 often expects this
	binary.BigEndian.PutUint16(buf[10:12], 1)
	buf = append(buf, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
	return buf
}

func parseAnswers(msg []byte) ([]net.IP, []string, time.Duration, error) {
	if len(msg) < 12 {
		return nil, nil, 0, fmt.Errorf("short dns message")
	}
	rcode := int(msg[3] & 0x0f)
	if rcode != 0 {
		return nil, nil, 0, fmt.Errorf("dns %s (%d)", rcodeString(rcode), rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, nil, 0, err
		}
		off += 4
	}
	var ips []net.IP
	var cnames []string
	var minTTL uint32 = ^uint32(0)
	for i := 0; i < an; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, nil, 0, err
		}
		if off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			break
		}
		rdata := msg[off : off+rdlen]
		off += rdlen
		if ttl < minTTL {
			minTTL = ttl
		}
		switch typ {
		case 1:
			if len(rdata) == 4 {
				ips = append(ips, net.IP(rdata))
			}
		case 28:
			if len(rdata) == 16 {
				ips = append(ips, net.IP(rdata))
			}
		case 5:
			if c, err := readNameAt(msg, off-rdlen); err == nil && c != "" {
				cnames = append(cnames, strings.TrimSuffix(strings.ToLower(c), "."))
			}
		}
	}
	if minTTL == ^uint32(0) {
		minTTL = 60
	}
	return ips, cnames, time.Duration(minTTL) * time.Second, nil
}

func readNameAt(msg []byte, off int) (string, error) {
	var labels []string
	for jumps := 0; off < len(msg) && jumps < 20; jumps++ {
		l := int(msg[off])
		off++
		if l == 0 {
			return strings.Join(labels, "."), nil
		}
		if l&0xc0 == 0xc0 {
			if off >= len(msg) {
				return "", fmt.Errorf("bad compression")
			}
			off = (int(l&0x3f) << 8) | int(msg[off])
			continue
		}
		if off+l > len(msg) {
			return "", fmt.Errorf("label out of range")
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return "", fmt.Errorf("name too long")
}

func skipName(msg []byte, off int) (int, error) {
	if off >= len(msg) {
		return off, fmt.Errorf("name out of range")
	}
	for {
		if off >= len(msg) {
			return off, fmt.Errorf("name out of range")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			return off, nil
		}
		if l&0xc0 == 0xc0 {
			off++
			return off, nil
		}
		off += l
	}
}