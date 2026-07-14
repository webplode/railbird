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
	msg := buildQuery(name, 1) // A
	ips, ttl, err := r.query(ctx, msg)
	if err == nil && len(ips) > 0 {
		return ips, ttl, nil
	}
	msg = buildQuery(name, 28) // AAAA
	ips, ttl, err2 := r.query(ctx, msg)
	if err2 != nil {
		if err != nil {
			return nil, 0, err
		}
		return nil, 0, err2
	}
	return ips, ttl, nil
}

func (r *Resolver) query(ctx context.Context, msg []byte) ([]net.IP, time.Duration, error) {
	conn, err := r.Dial.Dial(ctx, "tcp", r.Server)
	if err != nil {
		return nil, 0, fmt.Errorf("dns tcp dial %s: %w", r.Server, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline(ctx, 10*time.Second))

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, 0, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, 0, err
	}

	if _, err := conn.Read(lenBuf[:]); err != nil {
		return nil, 0, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 65535 {
		return nil, 0, fmt.Errorf("invalid dns response length %d", n)
	}
	buf := make([]byte, n)
	if _, err := readFull(conn, buf); err != nil {
		return nil, 0, err
	}
	return parseAnswers(buf)
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
	// header 12 bytes, ID=0x1234, RD=1
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0x1234)
	buf[2] = 0x01 // flags: recursion desired
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT

	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			continue
		}
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0)
	buf = append(buf, 0, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0, 0x01) // IN class
	return buf
}

func parseAnswers(msg []byte) ([]net.IP, time.Duration, error) {
	if len(msg) < 12 {
		return nil, 0, fmt.Errorf("short dns message")
	}
	rcode := msg[3] & 0x0f
	if rcode != 0 {
		return nil, 0, fmt.Errorf("dns rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, 0, err
		}
		off += 4 // type + class
	}
	var ips []net.IP
	var minTTL uint32 = ^uint32(0)
	for i := 0; i < an; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, 0, err
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
		case 1: // A
			if len(rdata) == 4 {
				ips = append(ips, net.IP(rdata))
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				ips = append(ips, net.IP(rdata))
			}
		case 5: // CNAME — skip; follow-up queries would need another round
		}
	}
	if minTTL == ^uint32(0) {
		minTTL = 60
	}
	return ips, time.Duration(minTTL) * time.Second, nil
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