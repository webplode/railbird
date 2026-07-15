package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
)

func TestBindAllClosesEarlierListenersWhenLaterBindFails(t *testing.T) {
	first := newScriptedListener()
	thirdBindCalls := atomic.Int64{}

	_, err := BindAll([]ListenerBinding{
		{
			Name: "first",
			Bind: func() (net.Listener, error) { return first, nil },
		},
		{
			Name: "second",
			Bind: func() (net.Listener, error) { return nil, errStub },
		},
		{
			Name: "third",
			Bind: func() (net.Listener, error) {
				thirdBindCalls.Add(1)
				return newScriptedListener(), nil
			},
		},
	}, ListenerGroupOptions{})

	if !errors.Is(err, errStub) {
		t.Fatalf("BindAll error = %v, want wrapped %v", err, errStub)
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("first listener remained open after second bind failed")
	}
	if got := thirdBindCalls.Load(); got != 0 {
		t.Fatalf("third bind calls = %d, want 0", got)
	}
}

func TestListenerGroupRejectsAcceptedConnectionWhileAdmissionClosed(t *testing.T) {
	listener := newScriptedListener()
	accepted, _ := newTrackedPipe(t)
	var targetDials atomic.Int64
	var proxyBytes atomic.Int64

	group, err := BindAll([]ListenerBinding{{
		Name: "db",
		Bind: func() (net.Listener, error) { return listener, nil },
		Handle: func(context.Context, net.Conn) {
			targetDials.Add(1)
			proxyBytes.Add(1)
		},
	}}, ListenerGroupOptions{})
	if err != nil {
		t.Fatalf("BindAll: %v", err)
	}
	t.Cleanup(func() { _ = group.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := serveGroup(group, ctx)
	awaitSignal(t, group.Started(), "all accept loops to start")

	acceptedByLoop := make(chan struct{})
	go func() {
		listener.yield(accepted, nil)
		close(acceptedByLoop)
	}()
	awaitSignal(t, acceptedByLoop, "scripted connection to be accepted")
	awaitSignal(t, accepted.closed, "closed-admission connection rejection")

	if got := targetDials.Load(); got != 0 {
		t.Fatalf("target dial count = %d, want 0", got)
	}
	if got := proxyBytes.Load(); got != 0 {
		t.Fatalf("proxy bytes = %d, want 0", got)
	}

	cancel()
	if err := awaitServeResult(t, serveDone); err != nil {
		t.Fatalf("Serve after context cancellation = %v, want nil", err)
	}
}

func TestListenerGroupDoesNotOpenAdmissionBeforeEveryLoopStarts(t *testing.T) {
	fast := newScriptedListener()
	slow := newScriptedListener()
	slowHookEntered := make(chan struct{})
	releaseSlowHook := make(chan struct{})
	var releaseSlowOnce sync.Once
	releaseSlow := func() { releaseSlowOnce.Do(func() { close(releaseSlowHook) }) }
	t.Cleanup(releaseSlow)

	group, err := BindAll([]ListenerBinding{
		{Name: "fast", Bind: func() (net.Listener, error) { return fast, nil }},
		{Name: "slow", Bind: func() (net.Listener, error) { return slow, nil }},
	}, ListenerGroupOptions{
		BeforeLoopStarted: func(name string) {
			if name != "slow" {
				return
			}
			close(slowHookEntered)
			<-releaseSlowHook
		},
	})
	if err != nil {
		t.Fatalf("BindAll: %v", err)
	}
	t.Cleanup(func() { _ = group.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := serveGroup(group, ctx)
	awaitSignal(t, slowHookEntered, "slow loop start hook")

	select {
	case <-group.Started():
		t.Fatal("all-loop barrier opened while slow loop was paused")
	default:
	}
	if err := group.OpenAdmission(); !errors.Is(err, ErrLoopsNotStarted) {
		t.Fatalf("OpenAdmission before loop barrier = %v, want %v", err, ErrLoopsNotStarted)
	}
	if group.Admitting() {
		t.Fatal("admission opened before every loop started")
	}

	releaseSlow()
	awaitSignal(t, group.Started(), "all-loop barrier")
	if err := group.OpenAdmission(); err != nil {
		t.Fatalf("OpenAdmission after loop barrier: %v", err)
	}
	if !group.Admitting() {
		t.Fatal("admission remained closed after successful OpenAdmission")
	}

	cancel()
	if err := awaitServeResult(t, serveDone); err != nil {
		t.Fatalf("Serve after context cancellation = %v, want nil", err)
	}
}

func TestListenerGroupReturnsUnexpectedAcceptErrorAndClosesSiblings(t *testing.T) {
	failing := newScriptedListener()
	sibling := newScriptedListener()

	group, err := BindAll([]ListenerBinding{
		{Name: "failing", Bind: func() (net.Listener, error) { return failing, nil }},
		{Name: "sibling", Bind: func() (net.Listener, error) { return sibling, nil }},
	}, ListenerGroupOptions{})
	if err != nil {
		t.Fatalf("BindAll: %v", err)
	}
	t.Cleanup(func() { _ = group.Close() })

	serveDone := serveGroup(group, context.Background())
	awaitSignal(t, group.Started(), "all accept loops to start")

	errorDelivered := make(chan struct{})
	go func() {
		failing.yield(nil, errStub)
		close(errorDelivered)
	}()
	awaitSignal(t, errorDelivered, "terminal accept error delivery")
	if err := awaitServeResult(t, serveDone); !errors.Is(err, errStub) {
		t.Fatalf("Serve error = %v, want wrapped %v", err, errStub)
	}

	select {
	case <-sibling.closed:
	default:
		t.Fatal("sibling listener remained open after terminal accept error")
	}
}

func TestListenerGroupTreatsContextDrivenListenerCloseAsClean(t *testing.T) {
	listener := newScriptedListener()
	group, err := BindAll([]ListenerBinding{{
		Name: "db",
		Bind: func() (net.Listener, error) { return listener, nil },
	}}, ListenerGroupOptions{})
	if err != nil {
		t.Fatalf("BindAll: %v", err)
	}
	t.Cleanup(func() { _ = group.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := serveGroup(group, ctx)
	awaitSignal(t, group.Started(), "accept loop to start")
	cancel()

	if err := awaitServeResult(t, serveDone); err != nil {
		t.Fatalf("Serve after context cancellation = %v, want nil", err)
	}
	select {
	case <-listener.closed:
	default:
		t.Fatal("listener remained open after context cancellation")
	}
}

func TestListenerGroupRejectsConnectionsAtCapAndReturnsCapacityAfterSessionEnds(t *testing.T) {
	listener := newScriptedListener()
	handled := make(chan net.Conn, 3)
	var releaseByConn sync.Map
	group, err := BindAll([]ListenerBinding{{
		Name: "db",
		Bind: func() (net.Listener, error) { return listener, nil },
		Handle: func(_ context.Context, conn net.Conn) {
			handled <- conn
			release, ok := releaseByConn.Load(conn)
			if !ok {
				return
			}
			<-release.(chan struct{})
		},
	}}, ListenerGroupOptions{MaxConnections: 2})
	if err != nil {
		t.Fatalf("BindAll: %v", err)
	}
	t.Cleanup(func() {
		group.ForceClose()
		_ = group.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := serveGroup(group, ctx)
	awaitSignal(t, group.Started(), "accept loop to start")
	if err := group.OpenAdmission(); err != nil {
		t.Fatalf("OpenAdmission: %v", err)
	}

	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	first, firstPeer := newTrackedPipe(t)
	second, secondPeer := newTrackedPipe(t)
	releaseByConn.Store(first, releaseFirst)
	releaseByConn.Store(second, releaseSecond)
	listener.yield(first, nil)
	listener.yield(second, nil)
	started := map[net.Conn]bool{
		awaitHandledConn(t, handled): true,
		awaitHandledConn(t, handled): true,
	}
	if !started[first] || !started[second] {
		t.Fatalf("handled connections = %v, want first and second sessions", started)
	}

	rejected, rejectedPeer := newTrackedPipe(t)
	listener.yield(rejected, nil)
	awaitSignal(t, rejected.closed, "over-cap connection rejection")
	select {
	case conn := <-handled:
		t.Fatalf("over-cap connection reached handler: %p", conn)
	default:
	}

	close(releaseFirst)
	awaitSignal(t, first.closed, "first session completion")
	releaseReplacement := make(chan struct{})
	replacement, replacementPeer := newTrackedPipe(t)
	releaseByConn.Store(replacement, releaseReplacement)
	listener.yield(replacement, nil)
	if got := awaitHandledConn(t, handled); got != replacement {
		t.Fatalf("replacement handled connection = %p, want %p", got, replacement)
	}

	_ = firstPeer.Close()
	_ = secondPeer.Close()
	_ = rejectedPeer.Close()
	_ = replacementPeer.Close()
	close(releaseSecond)
	close(releaseReplacement)
	cancel()
	if err := awaitServeResult(t, serveDone); err != nil {
		t.Fatalf("Serve after context cancellation = %v, want nil", err)
	}
}

func awaitHandledConn(t *testing.T, handled <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-handled:
		return conn
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session handler")
		return nil
	}
}

func serveGroup(group *ListenerGroup, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- group.Serve(ctx) }()
	return done
}

func awaitServeResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for listener group to stop")
		return nil
	}
}

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
