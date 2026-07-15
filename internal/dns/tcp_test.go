package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

type fakeDial struct {
	onDial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (f *fakeDial) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return f.onDial(ctx, network, address)
}

type pipeDNSDialer struct {
	dials   atomic.Int64
	handler func(*mdns.Msg) *mdns.Msg
	gate    <-chan struct{}
	started chan struct{}
	once    sync.Once
}

func (d *pipeDNSDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	if d.started != nil {
		d.once.Do(func() { close(d.started) })
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		dc := &mdns.Conn{Conn: server}
		for {
			req, err := dc.ReadMsg()
			if err != nil {
				return
			}
			if d.gate != nil {
				select {
				case <-d.gate:
				case <-ctx.Done():
					return
				}
			}
			resp := d.handler(req)
			if resp == nil {
				return
			}
			if err := dc.WriteMsg(resp); err != nil {
				return
			}
		}
	}()
	return client, nil
}

func TestLookupHost_IPPassthrough(t *testing.T) {
	r := &Resolver{
		Server: "10.32.0.2:53",
		Dial: &fakeDial{onDial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("literal IP must not dial DNS")
			return nil, errors.New("unexpected dial")
		}},
	}
	ips, err := r.LookupHost(context.Background(), "10.32.12.242")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.32.12.242" {
		t.Fatalf("got %v %v", ips, err)
	}
}

func TestClampTTL(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero disables cache", in: 0, want: 0},
		{name: "short authoritative ttl preserved", in: time.Second, want: time.Second},
		{name: "normal authoritative ttl preserved", in: 5 * time.Minute, want: 5 * time.Minute},
		{name: "maximum capped", in: 20 * time.Minute, want: 10 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampTTL(tc.in); got != tc.want {
				t.Fatalf("clampTTL(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestLookupHostReturnsAllAAndAAAAInOrder(t *testing.T) {
	dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		switch req.Question[0].Qtype {
		case mdns.TypeA:
			resp.Answer = []mdns.RR{
				&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.1")},
				&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.2")},
			}
		case mdns.TypeAAAA:
			resp.Answer = []mdns.RR{
				&mdns.AAAA{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("fd00::1")},
			}
		}
		return resp
	}}
	r := &Resolver{Server: "10.32.0.2:53", Dial: dialer}
	ips, err := r.LookupHost(context.Background(), "db.internal")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "fd00::1"}
	if len(ips) != len(want) {
		t.Fatalf("addresses = %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i].String() != want[i] {
			t.Fatalf("addresses[%d] = %s, want %s", i, ips[i], want[i])
		}
	}
}

func TestLookupHostFollowsCNAMEAndUsesMinimumTTL(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Unix(100, 0)
	dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if q.Name == "alias.internal." {
			resp.Answer = []mdns.RR{&mdns.CNAME{
				Hdr:    mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 2},
				Target: "db.internal.",
			}}
			return resp
		}
		if q.Qtype == mdns.TypeA {
			resp.Answer = []mdns.RR{&mdns.A{
				Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
				A:   net.ParseIP("10.0.0.9"),
			}}
		}
		return resp
	}}
	r := &Resolver{
		Server: "10.32.0.2:53",
		Dial:   dialer,
		now: func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			return now
		},
	}
	if _, err := r.LookupHost(context.Background(), "alias.internal"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("dials after first lookup = %d, want 1", got)
	}
	nowMu.Lock()
	now = now.Add(time.Second)
	nowMu.Unlock()
	if _, err := r.LookupHost(context.Background(), "alias.internal"); err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("dials before CNAME TTL expiry = %d, want 1", got)
	}
	nowMu.Lock()
	now = now.Add(2 * time.Second)
	nowMu.Unlock()
	if _, err := r.LookupHost(context.Background(), "alias.internal"); err != nil {
		t.Fatalf("refreshed lookup: %v", err)
	}
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("dials after CNAME TTL expiry = %d, want 2", got)
	}
}

func TestLookupHostRejectsRCodesAndMismatchedResponses(t *testing.T) {
	t.Run("nxdomain", func(t *testing.T) {
		dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
			resp := new(mdns.Msg)
			resp.SetRcode(req, mdns.RcodeNameError)
			return resp
		}}
		_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "missing.internal")
		var responseErr *ResponseError
		if !errors.As(err, &responseErr) || responseErr.RCode != mdns.RcodeNameError {
			t.Fatalf("error = %v, want NXDOMAIN ResponseError", err)
		}
	})

	t.Run("servfail", func(t *testing.T) {
		dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
			resp := new(mdns.Msg)
			resp.SetRcode(req, mdns.RcodeServerFailure)
			return resp
		}}
		_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "db.internal")
		var responseErr *ResponseError
		if !errors.As(err, &responseErr) || responseErr.RCode != mdns.RcodeServerFailure {
			t.Fatalf("error = %v, want SERVFAIL ResponseError", err)
		}
	})

	t.Run("question mismatch", func(t *testing.T) {
		dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Question[0].Name = "other.internal."
			return resp
		}}
		_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "db.internal")
		if err == nil || !stringsContains(err.Error(), "question mismatch") {
			t.Fatalf("error = %v, want question mismatch", err)
		}
	})
}

func TestLookupHostRejectsNoDataResponse(t *testing.T) {
	dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp
	}}

	_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "empty.internal")
	if err == nil || !stringsContains(err.Error(), "no A/AAAA") {
		t.Fatalf("error = %v, want no-data rejection", err)
	}
}

func TestLookupHostRejectsMalformedDNSMessage(t *testing.T) {
	dialer := &fakeDial{onDial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var length [2]byte
			if _, err := io.ReadFull(server, length[:]); err != nil {
				return
			}
			request := make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(server, request); err != nil {
				return
			}
			_, _ = server.Write([]byte{0, 3, 0xff, 0x00, 0xff})
		}()
		return client, nil
	}}

	_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "db.internal")
	if err == nil {
		t.Fatal("malformed DNS response unexpectedly succeeded")
	}
}

func TestLookupHostRejectsInvalidResponseEnvelope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(req, resp *mdns.Msg)
		want   string
	}{
		{name: "not a response", mutate: func(_, resp *mdns.Msg) { resp.Response = false }, want: "not a response"},
		{name: "id mismatch", mutate: func(_, resp *mdns.Msg) { resp.Id++ }, want: "id mismatch"},
		{name: "missing question", mutate: func(_, resp *mdns.Msg) { resp.Question = nil }, want: "question count mismatch"},
		{name: "type mismatch", mutate: func(_, resp *mdns.Msg) { resp.Question[0].Qtype = mdns.TypeMX }, want: "question mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
				resp := new(mdns.Msg)
				resp.SetReply(req)
				tc.mutate(req, resp)
				return resp
			}}
			_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "db.internal")
			if err == nil || !stringsContains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLookupHostRejectsCNAMECycle(t *testing.T) {
	dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		target := "alias.internal."
		if req.Question[0].Name == target {
			target = "db.internal."
		}
		resp.Answer = []mdns.RR{&mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
			Target: target,
		}}
		return resp
	}}

	_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "db.internal")
	if err == nil || !stringsContains(err.Error(), "cname loop") {
		t.Fatalf("error = %v, want CNAME loop rejection", err)
	}
}

func TestLookupHostRejectsCNAMEChainBeyondDepthLimit(t *testing.T) {
	dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		var index int
		_, _ = fmt.Sscanf(req.Question[0].Name, "node-%d.internal.", &index)
		resp.Answer = []mdns.RR{&mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("node-%d.internal.", index+1),
		}}
		return resp
	}}

	_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(context.Background(), "node-0.internal")
	if err == nil || !stringsContains(err.Error(), "chain too long") {
		t.Fatalf("error = %v, want CNAME depth rejection", err)
	}
}

func TestLookupHostReturnsPromptlyWhenContextIsCancelled(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{})
	dialer := &fakeDial{onDial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			dc := &mdns.Conn{Conn: server}
			req, err := dc.ReadMsg()
			if err != nil {
				return
			}
			close(started)
			<-gate
			resp := new(mdns.Msg)
			resp.SetReply(req)
			_ = dc.WriteMsg(resp)
		}()
		return client, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&Resolver{Server: "10.32.0.2:53", Dial: dialer}).LookupHost(ctx, "db.internal")
		done <- err
	}()
	awaitTestSignal(t, started, "DNS request")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not return after cancellation")
	}
	close(gate)
}

func TestLookupHostHonorsAuthoritativeCacheTTLBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  uint32
	}{
		{name: "zero is not cached", ttl: 0},
		{name: "one second expires", ttl: 1},
		{name: "five minutes expires", ttl: 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1_000, 0)
			dialer := &pipeDNSDialer{handler: func(req *mdns.Msg) *mdns.Msg {
				resp := new(mdns.Msg)
				resp.SetReply(req)
				if req.Question[0].Qtype == mdns.TypeA {
					resp.Answer = []mdns.RR{&mdns.A{
						Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: tc.ttl},
						A:   net.ParseIP("10.0.0.7"),
					}}
				}
				return resp
			}}
			r := &Resolver{Server: "10.32.0.2:53", Dial: dialer, now: func() time.Time { return now }}
			if _, err := r.LookupHost(context.Background(), "db.internal"); err != nil {
				t.Fatalf("first lookup: %v", err)
			}
			if tc.ttl > 0 {
				now = now.Add(time.Duration(tc.ttl)*time.Second - time.Nanosecond)
				if _, err := r.LookupHost(context.Background(), "db.internal"); err != nil {
					t.Fatalf("lookup before expiry: %v", err)
				}
				if got := dialer.dials.Load(); got != 1 {
					t.Fatalf("dials before expiry = %d, want 1", got)
				}
				now = now.Add(time.Nanosecond)
			}
			if _, err := r.LookupHost(context.Background(), "db.internal"); err != nil {
				t.Fatalf("lookup at expiry: %v", err)
			}
			if got := dialer.dials.Load(); got != 2 {
				t.Fatalf("dials after expiry = %d, want 2", got)
			}
		})
	}
}

func TestLookupHostCoalescesConcurrentMissesAndCopiesResults(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{})
	dialer := &pipeDNSDialer{
		gate:    gate,
		started: started,
		handler: func(req *mdns.Msg) *mdns.Msg {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			if req.Question[0].Qtype == mdns.TypeA {
				resp.Answer = []mdns.RR{&mdns.A{
					Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.0.0.10"),
				}}
			}
			return resp
		},
	}
	r := &Resolver{Server: "10.32.0.2:53", Dial: dialer}

	const callers = 20
	start := make(chan struct{})
	results := make(chan []net.IP, callers)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			ips, err := r.LookupHost(context.Background(), "db.internal")
			results <- ips
			errs <- err
		}()
	}
	close(start)
	awaitTestSignal(t, started, "cold DNS exchange")
	close(gate)

	var first []net.IP
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		ips := <-results
		if len(ips) != 1 || ips[0].String() != "10.0.0.10" {
			t.Fatalf("lookup %d addresses = %v", i, ips)
		}
		if i == 0 {
			first = ips
		} else if &ips[0][0] == &first[0][0] {
			t.Fatalf("lookup %d received shared mutable IP storage", i)
		}
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("cold concurrent dials = %d, want 1", got)
	}
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func awaitTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
