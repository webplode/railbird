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

func TestClampTTL(t *testing.T) {
	if clampTTL(1*time.Second) != 30*time.Second {
		t.Fatal("min ttl")
	}
	if clampTTL(20*time.Minute) != 10*time.Minute {
		t.Fatal("max ttl")
	}
}