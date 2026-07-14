package forward

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

// In egress mode, Run binds a plain local TCP listener and dials the target
// via the mesh. With fakeMesh the "mesh dial" is a loopback Dial, so data
// should round-trip from the test client to the echo server unchanged.
func TestE2E_EgressForward(t *testing.T) {
	echoAddr := tcpEchoServer(t)
	listenPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mesh := &fakeMesh{}
	done := runAsync(ctx, mesh, Forward{ListenPort: listenPort, Target: echoAddr}, config.ModeEgress)

	conn := waitDial(t, "127.0.0.1:"+listenPort, 2*time.Second)
	defer conn.Close()
	roundTrip(t, conn, []byte("hello egress\n"))

	if got := mesh.dials.Load(); got != 1 {
		t.Fatalf("egress should dial via mesh once, got %d", got)
	}
	if got := mesh.listeners.Load(); got != 0 {
		t.Fatalf("egress should not call ListenTCP, got %d", got)
	}

	conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}
}

// In ingress mode, Run binds the listener via MeshClient.ListenTCP and dials
// the target with a plain net.Dialer.
func TestE2E_IngressForward(t *testing.T) {
	echoAddr := tcpEchoServer(t)
	listenPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mesh := &fakeMesh{}
	done := runAsync(ctx, mesh, Forward{ListenPort: listenPort, Target: echoAddr}, config.ModeIngress)

	conn := waitDial(t, "127.0.0.1:"+listenPort, 2*time.Second)
	defer conn.Close()
	roundTrip(t, conn, []byte("hello ingress\n"))

	if got := mesh.listeners.Load(); got != 1 {
		t.Fatalf("ingress should ListenTCP via mesh once, got %d", got)
	}
	if got := mesh.dials.Load(); got != 0 {
		t.Fatalf("ingress should not call mesh Dial, got %d", got)
	}

	conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}
}

// Many concurrent clients should each see clean echo round-trips: the proxy
// must spawn an independent goroutine per accepted conn (not serialize them).
func TestE2E_ConcurrentClients(t *testing.T) {
	echoAddr := tcpEchoServer(t)
	listenPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := runAsync(ctx, &fakeMesh{}, Forward{ListenPort: listenPort, Target: echoAddr}, config.ModeEgress)

	waitDial(t, "127.0.0.1:"+listenPort, 2*time.Second).Close()

	const N = 8
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			conn, err := net.Dial("tcp", "127.0.0.1:"+listenPort)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			payload := []byte{byte(i), 'x', '\n'}
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- err
				return
			}
			if buf[0] != byte(i) {
				errs <- errStub
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return")
	}
}

// Cancelling the parent context must close the listener and unwind Run,
// even with no active client connections.
func TestE2E_CancelStopsListener(t *testing.T) {
	listenPort := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, &fakeMesh{}, Forward{ListenPort: listenPort, Target: "127.0.0.1:1"}, config.ModeEgress)

	c := waitDial(t, "127.0.0.1:"+listenPort, time.Second)
	c.Close()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}

	if c2, err := net.DialTimeout("tcp", "127.0.0.1:"+listenPort, 200*time.Millisecond); err == nil {
		c2.Close()
		t.Fatalf("listener still accepting after cancel")
	}
}
