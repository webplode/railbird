package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

type fakeDial struct {
	onDial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (f *fakeDial) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return f.onDial(ctx, network, address)
}

func TestLookupHost_IPPassthrough(t *testing.T) {
	r := &Resolver{Server: "10.32.0.2:53", Dial: &fakeDial{}}
	ips, err := r.LookupHost(context.Background(), "10.32.12.242")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.32.12.242" {
		t.Fatalf("got %v %v", ips, err)
	}
}

func TestParseAnswers_A(t *testing.T) {
	// header: 1 question, 1 answer; question "x.com"; answer CNAME-style ptr + A
	resp := []byte{
		0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
		1, 'x', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 32, 12, 242,
	}
	ips, _, ttl, err := parseAnswers(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "10.32.12.242" {
		t.Fatalf("ips=%v", ips)
	}
	if ttl != 60*time.Second {
		t.Fatalf("ttl=%v", ttl)
	}
}

func TestBuildQuery(t *testing.T) {
	q := buildQuery("a.b.com", 1)
	if len(q) < 20 {
		t.Fatalf("short query %d", len(q))
	}
}