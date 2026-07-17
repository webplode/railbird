package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

// fakeMesh is a loopback implementation of MeshClient used by e2e tests.
//
// ListenTCP and Dial both go over 127.0.0.1, so the runner code paths run
// unchanged but no NetBird mesh, management server, or setup key is
// required.
type fakeMesh struct {
	dials     atomic.Int64
	listeners atomic.Int64
}

func (m *fakeMesh) ListenTCP(address string) (net.Listener, error) {
	m.listeners.Add(1)
	if strings.HasPrefix(address, ":") {
		return net.Listen("tcp", "127.0.0.1"+address)
	}
	return net.Listen("tcp", address)
}

func (m *fakeMesh) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	m.dials.Add(1)
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// tcpEchoServer accepts TCP connections on a random loopback port and echoes
// every byte back. Returns the bound address; cleanup is registered on t.
func tcpEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// freePort returns a TCP port that was free at the moment of the call.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	return port
}

// waitDial retries Dial until it succeeds or the deadline elapses, masking
// the race between starting Run in a goroutine and the listener becoming
// bindable.
func waitDial(t *testing.T, addr string, timeout time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			return c
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitDial %s: %v", addr, lastErr)
	return nil
}

// roundTrip writes payload, reads back len(payload) bytes, and verifies
// they match.
func roundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

// runAsync starts Run in a goroutine and returns a channel that closes when
// it returns.
func runAsync(ctx context.Context, c MeshClient, f Forward, mode config.Mode) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Run(ctx, c, f, mode, nil)
	}()
	return done
}

// errStub is a sentinel for tests that inject controlled failures.
var errStub = errors.New("stub failure")
