package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

type fixedDialMesh struct {
	conn   net.Conn
	dialed chan struct{}
}

func (m *fixedDialMesh) ListenTCP(string) (net.Listener, error) {
	return nil, errors.New("unexpected listen")
}

func (m *fixedDialMesh) Dial(context.Context, string, string) (net.Conn, error) {
	close(m.dialed)
	return m.conn, nil
}

type deadlineRecordingConn struct {
	net.Conn
	deadlines atomic.Int64
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.deadlines.Add(1)
	return c.Conn.SetDeadline(deadline)
}

func TestProxyLeavesQuietSessionOpenWhenIdleTimeoutDisabled(t *testing.T) {
	proxyInput, client := net.Pipe()
	proxyOutput, target := net.Pipe()
	input := &deadlineRecordingConn{Conn: proxyInput}
	output := &deadlineRecordingConn{Conn: proxyOutput}
	t.Cleanup(func() {
		_ = client.Close()
		_ = target.Close()
	})
	mesh := &fixedDialMesh{conn: output, dialed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Proxy(ctx, mesh, input, "192.0.2.1:5432", config.ModeEgress, nil, ProxyOptions{
			Dial: DialOptions{AttemptTimeout: time.Second, TotalTimeout: time.Second},
		})
	}()
	awaitSignal(t, mesh.dialed, "proxy target dial")

	if got := input.deadlines.Load(); got != 0 {
		t.Fatalf("input deadline updates = %d, want 0", got)
	}
	if got := output.deadlines.Load(); got != 0 {
		t.Fatalf("output deadline updates = %d, want 0", got)
	}
	select {
	case err := <-done:
		t.Fatalf("quiet session closed with idle timeout disabled: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Proxy error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Proxy did not converge after cancellation")
	}
}

func TestProxyClosesInactiveSessionWhenIdleTimeoutEnabled(t *testing.T) {
	proxyInput, client := net.Pipe()
	proxyOutput, target := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = target.Close()
	})
	mesh := &fixedDialMesh{conn: proxyOutput, dialed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Proxy(context.Background(), mesh, proxyInput, "192.0.2.1:5432", config.ModeEgress, nil, ProxyOptions{
			Dial:        DialOptions{AttemptTimeout: time.Second, TotalTimeout: time.Second},
			IdleTimeout: 20 * time.Millisecond,
		})
	}()
	awaitSignal(t, mesh.dialed, "proxy target dial")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("inactive session closed without reporting its timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("inactive session remained open past idle timeout")
	}
}

func TestProxyActiveTrafficRefreshesIdleDeadline(t *testing.T) {
	proxyInput, client := net.Pipe()
	proxyOutput, target := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = target.Close()
	})
	mesh := &fixedDialMesh{conn: proxyOutput, dialed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Proxy(context.Background(), mesh, proxyInput, "192.0.2.1:5432", config.ModeEgress, nil, ProxyOptions{
			Dial:        DialOptions{AttemptTimeout: time.Second, TotalTimeout: time.Second},
			IdleTimeout: 150 * time.Millisecond,
		})
	}()
	awaitSignal(t, mesh.dialed, "proxy target dial")

	for i := 0; i < 5; i++ {
		if _, err := client.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("active write %d: %v", i, err)
		}
		var got [1]byte
		if _, err := io.ReadFull(target, got[:]); err != nil {
			t.Fatalf("target read %d: %v", i, err)
		}
		if got[0] != byte(i) {
			t.Fatalf("target byte %d = %d", i, got[0])
		}
		time.Sleep(40 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("active session closed before traffic stopped: %v", err)
	default:
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session remained open after active traffic stopped")
	}
}

func TestProxyConvergesAfterBothPeersHalfClose(t *testing.T) {
	proxyInput, client := newTCPConnPair(t)
	proxyOutput, target := newTCPConnPair(t)
	mesh := &fixedDialMesh{conn: proxyOutput, dialed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Proxy(context.Background(), mesh, proxyInput, "192.0.2.1:5432", config.ModeEgress, nil, ProxyOptions{
			Dial: DialOptions{AttemptTimeout: time.Second, TotalTimeout: time.Second},
		})
	}()
	awaitSignal(t, mesh.dialed, "proxy target dial")

	request := []byte("request")
	if _, err := client.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	if got, err := io.ReadAll(target); err != nil || string(got) != string(request) {
		t.Fatalf("target read = %q, %v; want %q", got, err, request)
	}

	response := []byte("response")
	if _, err := target.Write(response); err != nil {
		t.Fatalf("target write: %v", err)
	}
	if err := target.CloseWrite(); err != nil {
		t.Fatalf("target CloseWrite: %v", err)
	}
	if got, err := io.ReadAll(client); err != nil || string(got) != string(response) {
		t.Fatalf("client read = %q, %v; want %q", got, err, response)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Proxy after half-closes: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Proxy did not converge after both peers half-closed")
	}
}

func newTCPConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dial: %v", err)
	}
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = clientConn.Close()
		t.Fatalf("accept: %v", err)
	case <-time.After(time.Second):
		_ = clientConn.Close()
		t.Fatal("timed out accepting TCP test connection")
	}
	_ = listener.Close()
	client := clientConn.(*net.TCPConn)
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server, client
}
