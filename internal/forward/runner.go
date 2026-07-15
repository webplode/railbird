package forward

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jratienza65/railbird/internal/config"
)

var (
	ErrLoopsNotStarted = errors.New("forward accept loops have not all started")
	ErrAlreadyServing  = errors.New("listener group already serving")
	ErrGroupClosed     = errors.New("listener group is closed")
)

const defaultMaxConnections = 256

// MeshClient is the subset of the NetBird embedded client used by forwarding.
type MeshClient interface {
	ListenTCP(address string) (net.Listener, error)
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// ListenerBinding describes one listener before it is bound. BindAll invokes
// Bind sequentially so a failure can roll back the whole set transactionally.
type ListenerBinding struct {
	Name   string
	Bind   func() (net.Listener, error)
	Handle func(context.Context, net.Conn)
}

// ListenerGroupOptions controls process-wide session admission. The start hook
// is a deterministic test seam and should remain nil in production.
type ListenerGroupOptions struct {
	MaxConnections    int
	BeforeLoopStarted func(name string)
}

type boundListener struct {
	name   string
	ln     net.Listener
	handle func(context.Context, net.Conn)
}

// ListenerGroup owns a transactionally bound listener set, its atomic
// admission state, accept loops, and accepted-session lifecycle.
type ListenerGroup struct {
	listeners []boundListener
	opts      ListenerGroupOptions

	started     chan struct{}
	startedOnce sync.Once
	serveActive atomic.Bool
	admitting   atomic.Bool
	closing     atomic.Bool
	closeOnce   sync.Once

	sessionCtx    context.Context
	cancelSession context.CancelFunc
	sessionWG     sync.WaitGroup
	sessionMu     sync.Mutex
	sessions      map[net.Conn]struct{}
	capacity      chan struct{}
}

// BindAll binds every configured listener or closes all earlier listeners on
// the first failure. No accept loop is started until the entire set exists.
func BindAll(bindings []ListenerBinding, opts ListenerGroupOptions) (*ListenerGroup, error) {
	if len(bindings) == 0 {
		return nil, fmt.Errorf("bind forwards: no listener bindings")
	}
	if opts.MaxConnections <= 0 {
		opts.MaxConnections = defaultMaxConnections
	}
	group := &ListenerGroup{
		opts:      opts,
		started:   make(chan struct{}),
		sessions:  make(map[net.Conn]struct{}),
		capacity:  make(chan struct{}, opts.MaxConnections),
		listeners: make([]boundListener, 0, len(bindings)),
	}
	group.sessionCtx, group.cancelSession = context.WithCancel(context.Background())

	for i, binding := range bindings {
		name := binding.Name
		if name == "" {
			name = fmt.Sprintf("forward-%d", i+1)
		}
		if binding.Bind == nil {
			_ = group.Close()
			return nil, fmt.Errorf("bind %s: nil bind function", name)
		}
		ln, err := binding.Bind()
		if err != nil {
			_ = group.Close()
			return nil, fmt.Errorf("bind %s: %w", name, err)
		}
		if ln == nil {
			_ = group.Close()
			return nil, fmt.Errorf("bind %s: nil listener", name)
		}
		group.listeners = append(group.listeners, boundListener{name: name, ln: ln, handle: binding.Handle})
	}
	return group, nil
}

// Started closes only after every accept loop has reached its pre-Accept
// barrier. Admission remains closed until OpenAdmission is called separately.
func (g *ListenerGroup) Started() <-chan struct{} {
	return g.started
}

func (g *ListenerGroup) Admitting() bool {
	return g.admitting.Load()
}

// OpenAdmission atomically enables the entire listener set after its start
// barrier. It never opens a partial subset.
func (g *ListenerGroup) OpenAdmission() error {
	if g.closing.Load() {
		return ErrGroupClosed
	}
	select {
	case <-g.started:
		g.admitting.Store(true)
		if g.closing.Load() {
			g.admitting.Store(false)
			return ErrGroupClosed
		}
		return nil
	default:
		return ErrLoopsNotStarted
	}
}

// Serve starts every accept loop admission-closed and blocks until the parent
// context closes or one listener exits unexpectedly. An unexpected error is
// fatal to the whole set and closes sibling listeners.
func (g *ListenerGroup) Serve(ctx context.Context) error {
	if !g.serveActive.CompareAndSwap(false, true) {
		return ErrAlreadyServing
	}
	if g.closing.Load() {
		return ErrGroupClosed
	}

	terminal := make(chan error, 1)
	loopsDone := make(chan struct{})
	var loops sync.WaitGroup
	var started sync.WaitGroup
	started.Add(len(g.listeners))

	for i := range g.listeners {
		binding := &g.listeners[i]
		loops.Add(1)
		go func() {
			defer loops.Done()
			if g.opts.BeforeLoopStarted != nil {
				g.opts.BeforeLoopStarted(binding.name)
			}
			started.Done()
			if err := g.acceptLoop(binding); err != nil {
				select {
				case terminal <- err:
				default:
				}
				_ = g.Close()
			}
		}()
	}
	go func() {
		started.Wait()
		g.startedOnce.Do(func() { close(g.started) })
	}()
	go func() {
		loops.Wait()
		close(loopsDone)
	}()

	select {
	case <-ctx.Done():
		_ = g.Close()
		<-loopsDone
		return nil
	case err := <-terminal:
		_ = g.Close()
		<-loopsDone
		return err
	case <-loopsDone:
		select {
		case err := <-terminal:
			return err
		default:
			if ctx.Err() != nil || g.closing.Load() {
				return nil
			}
			return fmt.Errorf("forward accept loops exited unexpectedly")
		}
	}
}

func (g *ListenerGroup) acceptLoop(binding *boundListener) error {
	for {
		conn, err := binding.ln.Accept()
		if err != nil {
			if g.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept %s: %w", binding.name, err)
		}
		if conn == nil {
			if !g.closing.Load() {
				return fmt.Errorf("accept %s: nil connection", binding.name)
			}
			return nil
		}
		if !g.admitting.Load() {
			_ = conn.Close()
			continue
		}
		select {
		case g.capacity <- struct{}{}:
			g.startSession(binding, conn)
		default:
			log.Printf("forward %s: connection capacity reached; rejecting", binding.name)
			_ = conn.Close()
		}
	}
}

func (g *ListenerGroup) startSession(binding *boundListener, conn net.Conn) {
	g.sessionMu.Lock()
	if g.closing.Load() || !g.admitting.Load() {
		g.sessionMu.Unlock()
		<-g.capacity
		_ = conn.Close()
		return
	}
	g.sessions[conn] = struct{}{}
	g.sessionWG.Add(1)
	g.sessionMu.Unlock()

	go func() {
		defer func() {
			_ = conn.Close()
			g.sessionMu.Lock()
			delete(g.sessions, conn)
			g.sessionMu.Unlock()
			<-g.capacity
			g.sessionWG.Done()
		}()
		if binding.handle == nil {
			return
		}
		binding.handle(g.sessionCtx, conn)
	}()
}

// Close stops admission and closes every listener. Existing sessions remain
// alive so a supervisor can drain them before ForceClose.
func (g *ListenerGroup) Close() error {
	var joined error
	g.closeOnce.Do(func() {
		g.closing.Store(true)
		g.admitting.Store(false)
		for i := range g.listeners {
			if err := g.listeners[i].ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				joined = errors.Join(joined, fmt.Errorf("close %s: %w", g.listeners[i].name, err))
			}
		}
	})
	return joined
}

// Wait waits for established sessions to finish without admitting new work.
func (g *ListenerGroup) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		g.sessionWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ForceClose cancels session contexts and closes all currently tracked input
// connections, which unblocks the proxy's outbound side as well.
func (g *ListenerGroup) ForceClose() {
	g.cancelSession()
	g.sessionMu.Lock()
	connections := make([]net.Conn, 0, len(g.sessions))
	for conn := range g.sessions {
		connections = append(connections, conn)
	}
	g.sessionMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// NewListenerBinding creates the production binding/handler pair for one
// parsed forward. Building every binding before BindAll preserves whole-set
// startup rollback while keeping topology-specific details in this package.
func NewListenerBinding(c MeshClient, f Forward, mode config.Mode, res HostResolver, opts ProxyOptions) ListenerBinding {
	return ListenerBinding{
		Name: f.ListenPort,
		Bind: func() (net.Listener, error) {
			return listen(c, f.ListenPort, mode)
		},
		Handle: func(sessionCtx context.Context, conn net.Conn) {
			if err := Proxy(sessionCtx, c, conn, f.Target, mode, res, opts); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("proxy listener=:%s target=%s result=failed error=%v", f.ListenPort, redactedTarget(f.Target), err)
			}
		},
	}
}

// Run preserves the original single-forward API on top of ListenerGroup. New
// startup code should build all bindings first and call BindAll once.
func Run(ctx context.Context, c MeshClient, f Forward, mode config.Mode, res HostResolver) error {
	binding := NewListenerBinding(c, f, mode, res, defaultProxyOptions())
	group, err := BindAll([]ListenerBinding{binding}, ListenerGroupOptions{})
	if err != nil {
		return err
	}
	defer func() {
		_ = group.Close()
		group.ForceClose()
	}()

	serveDone := make(chan error, 1)
	go func() { serveDone <- group.Serve(ctx) }()
	select {
	case <-group.Started():
		if err := group.OpenAdmission(); err != nil {
			return err
		}
		log.Printf("forward mode=%s listener=:%s target=%s state=admitting", mode, f.ListenPort, redactedTarget(f.Target))
	case err := <-serveDone:
		return err
	case <-ctx.Done():
		_ = group.Close()
		return <-serveDone
	}
	return <-serveDone
}

// listen binds the appropriate listener for the given topology.
func listen(c MeshClient, port string, mode config.Mode) (net.Listener, error) {
	switch mode {
	case config.ModeIngress:
		if c == nil {
			return nil, fmt.Errorf("mesh client is nil")
		}
		return c.ListenTCP(":" + port)
	case config.ModeEgress:
		return net.Listen("tcp", "[::]:"+port)
	default:
		return nil, &net.OpError{Op: "listen", Err: errInvalidMode(mode)}
	}
}

type errInvalidMode config.Mode

func (e errInvalidMode) Error() string { return "invalid mode: " + string(e) }
