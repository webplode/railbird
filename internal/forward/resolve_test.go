package forward

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

type resolverFunc func(context.Context, string) ([]net.IP, error)

func (f resolverFunc) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	return f(ctx, host)
}

type sequenceMesh struct {
	mu       sync.Mutex
	attempts []string
	dial     func(context.Context, string) (net.Conn, error)
}

func (m *sequenceMesh) ListenTCP(string) (net.Listener, error) {
	return nil, errors.New("unexpected listen")
}

func (m *sequenceMesh) Dial(ctx context.Context, _ string, address string) (net.Conn, error) {
	m.mu.Lock()
	m.attempts = append(m.attempts, address)
	m.mu.Unlock()
	return m.dial(ctx, address)
}

func (m *sequenceMesh) recordedAttempts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.attempts...)
}

func TestResolveEgressTargetsRequiresApprovedResolverForHostname(t *testing.T) {
	_, err := ResolveEgressTargets(context.Background(), "db.internal:5432", config.ModeEgress, nil)
	if err == nil {
		t.Fatal("hostname without approved resolver unexpectedly succeeded")
	}
	targets, err := ResolveEgressTargets(context.Background(), "10.0.0.4:5432", config.ModeEgress, nil)
	if err != nil || !reflect.DeepEqual(targets, []string{"10.0.0.4:5432"}) {
		t.Fatalf("literal target = %v, %v", targets, err)
	}
}

func TestDialTargetTriesAllResolvedAddressesInOrder(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, nil
	})
	mesh := &sequenceMesh{dial: func(_ context.Context, address string) (net.Conn, error) {
		if address == "192.0.2.1:5432" {
			return nil, errors.New("first unavailable")
		}
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	conn, err := DialTarget(context.Background(), mesh, "db.internal:5432", config.ModeEgress, resolver, DialOptions{
		AttemptTimeout: 100 * time.Millisecond,
		TotalTimeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	_ = conn.Close()
	want := []string{"192.0.2.1:5432", "192.0.2.2:5432"}
	if got := mesh.recordedAttempts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
}

func TestDialTargetHonorsAttemptAndTotalBudgets(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")}, nil
	})
	mesh := &sequenceMesh{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}

	start := time.Now()
	_, err := DialTarget(context.Background(), mesh, "db.internal:5432", config.ModeEgress, resolver, DialOptions{
		AttemptTimeout: 20 * time.Millisecond,
		TotalTimeout:   45 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("DialTarget unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("DialTarget exceeded total budget: %s", elapsed)
	}
	if got := len(mesh.recordedAttempts()); got < 2 || got > 3 {
		t.Fatalf("attempt count = %d, want 2..3", got)
	}
}

func TestDialTargetContinuesAfterAttemptTimeoutAndUsesSecondAddress(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, nil
	})
	firstCancelled := make(chan error, 1)
	mesh := &sequenceMesh{dial: func(ctx context.Context, address string) (net.Conn, error) {
		if address == "192.0.2.1:5432" {
			<-ctx.Done()
			firstCancelled <- ctx.Err()
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	conn, err := DialTarget(context.Background(), mesh, "db.internal:5432", config.ModeEgress, resolver, DialOptions{
		AttemptTimeout: 10 * time.Millisecond,
		TotalTimeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	_ = conn.Close()
	if err := <-firstCancelled; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first attempt error = %v, want deadline exceeded", err)
	}
	want := []string{"192.0.2.1:5432", "192.0.2.2:5432"}
	if got := mesh.recordedAttempts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
}

func TestDialTargetCancelsInFlightAttempt(t *testing.T) {
	started := make(chan struct{})
	exited := make(chan error, 1)
	mesh := &sequenceMesh{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		exited <- ctx.Err()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := DialTarget(ctx, mesh, "192.0.2.1:5432", config.ModeEgress, nil, DialOptions{
			AttemptTimeout: time.Second,
			TotalTimeout:   time.Second,
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dial attempt")
	}
	cancel()
	select {
	case err := <-exited:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial context error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial attempt did not exit after cancellation")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialTarget error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialTarget did not return after cancellation")
	}
}

func TestResolveEgressTargetsRejectsEmptyResolverResult(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return nil, nil })
	_, err := ResolveEgressTargets(context.Background(), "db.internal:5432", config.ModeEgress, resolver)
	if err == nil {
		t.Fatal("empty resolver result unexpectedly succeeded")
	}
}
