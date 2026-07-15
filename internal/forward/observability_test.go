package forward

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

func TestRedactedTargetHidesInternalInventoryAndKeepsCorrelation(t *testing.T) {
	const target = "private-db.internal:5432"
	redacted := redactedTarget(target)
	if strings.Contains(redacted, "private-db.internal") || !strings.HasSuffix(redacted, ":5432") {
		t.Fatalf("redacted target = %q", redacted)
	}
	if redacted != redactedTarget("PRIVATE-DB.INTERNAL.:5432") {
		t.Fatalf("equivalent hosts produced different correlation keys")
	}
	if got := redactedTarget("10.32.4.9:5432"); strings.Contains(got, "10.32.4.9") {
		t.Fatalf("literal IP leaked from redacted target: %q", got)
	}
}

func TestSafeNetworkErrorHidesAddressesAndPreservesClassification(t *testing.T) {
	cause := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("10.32.4.9"), Port: 5432},
		Err:  syscall.ECONNREFUSED,
	}
	err := redactNetworkError("attempt=1/1", cause)
	if strings.Contains(err.Error(), "10.32.4.9") {
		t.Fatalf("safe error leaked target address: %v", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || networkFailureClass(err) != "connection refused" {
		t.Fatalf("safe error lost classification: %v", err)
	}
	if got := networkFailureClass(nil); got != "ok" {
		t.Fatalf("nil failure class = %q", got)
	}
}

func TestDialTargetFailureFormattingDoesNotExposeHostnameOrResolvedIP(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.32.4.9")}, nil
	})
	mesh := &sequenceMesh{dial: func(context.Context, string) (net.Conn, error) {
		return nil, &net.OpError{
			Op:   "dial",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.ParseIP("10.32.4.9"), Port: 5432},
			Err:  syscall.ECONNREFUSED,
		}
	}}

	_, err := DialTarget(context.Background(), mesh, "private-db.internal:5432", config.ModeEgress, resolver, DialOptions{
		AttemptTimeout: time.Second,
		TotalTimeout:   time.Second,
	})
	if err == nil {
		t.Fatal("DialTarget unexpectedly succeeded")
	}
	for _, sensitive := range []string{"private-db.internal", "10.32.4.9"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("DialTarget error exposed %q: %v", sensitive, err)
		}
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("DialTarget error lost root classification: %v", err)
	}
}
