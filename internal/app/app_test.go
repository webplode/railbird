package app

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/forward"
)

type fakeHealth struct {
	errs       chan error
	ready      atomic.Bool
	readyEvent chan bool
	shutdowns  atomic.Int64
	draining   atomic.Bool
}

func newFakeHealth() *fakeHealth {
	return &fakeHealth{errs: make(chan error, 1), readyEvent: make(chan bool, 8)}
}

func (h *fakeHealth) SetReady(value bool) bool {
	if value && h.draining.Load() {
		return false
	}
	h.ready.Store(value)
	h.readyEvent <- value
	return true
}

func (h *fakeHealth) BeginDrain() {
	h.draining.Store(true)
	h.ready.Store(false)
	h.readyEvent <- false
}
func (h *fakeHealth) Terminal() <-chan error { return h.errs }
func (h *fakeHealth) Shutdown(context.Context) error {
	h.shutdowns.Add(1)
	return nil
}

type fakeMesh struct {
	stops atomic.Int64
}

func (*fakeMesh) ListenTCP(string) (net.Listener, error) { return nil, errors.New("unused") }
func (*fakeMesh) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (m *fakeMesh) Stop(context.Context) error { m.stops.Add(1); return nil }

type fakeGroup struct {
	started    chan struct{}
	serveError chan error
	admitting  atomic.Bool
	closed     atomic.Bool
	forced     atomic.Bool
}

func newFakeGroup() *fakeGroup {
	started := make(chan struct{})
	close(started)
	return &fakeGroup{started: started, serveError: make(chan error, 1)}
}

func (g *fakeGroup) Serve(ctx context.Context) error {
	select {
	case err := <-g.serveError:
		return err
	case <-ctx.Done():
		return nil
	}
}
func (g *fakeGroup) Started() <-chan struct{} { return g.started }
func (g *fakeGroup) OpenAdmission() error {
	g.admitting.Store(true)
	return nil
}
func (g *fakeGroup) Close() error               { g.closed.Store(true); g.admitting.Store(false); return nil }
func (g *fakeGroup) Wait(context.Context) error { return nil }
func (g *fakeGroup) ForceClose()                { g.forced.Store(true) }

func servingConfig() config.Config {
	return config.Config{
		Mode:               config.ModeEgress,
		IdentityMode:       config.IdentityEphemeral,
		HealthPort:         8080,
		ProbePolicy:        config.ProbeRequired,
		StartupTimeout:     time.Second,
		DrainTimeout:       time.Second,
		NetBirdStopTimeout: time.Second,
	}
}

func TestHealthBindFailurePreventsNetBirdStart(t *testing.T) {
	var meshStarts atomic.Int64
	err := RunServing(context.Background(), servingConfig(), Dependencies{
		NewHealth: func(int) (Health, error) { return nil, errors.New("port occupied") },
		StartMesh: func(context.Context, config.Config) (Mesh, error) {
			meshStarts.Add(1)
			return &fakeMesh{}, nil
		},
		NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) { return newFakeGroup(), nil },
		Probe:       func(context.Context, config.Config, Mesh, forward.HostResolver) error { return nil },
	})
	if err == nil || meshStarts.Load() != 0 {
		t.Fatalf("RunServing error=%v meshStarts=%d", err, meshStarts.Load())
	}
}

func TestStartupBarrierProbesBeforeAdmissionAndReadiness(t *testing.T) {
	health := newFakeHealth()
	mesh := &fakeMesh{}
	group := newFakeGroup()
	probeCalled := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunServing(ctx, servingConfig(), Dependencies{
			NewHealth: func(int) (Health, error) { return health, nil },
			StartMesh: func(context.Context, config.Config) (Mesh, error) { return mesh, nil },
			NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) {
				return group, nil
			},
			Probe: func(context.Context, config.Config, Mesh, forward.HostResolver) error {
				if group.admitting.Load() || health.ready.Load() {
					t.Error("admission/readiness opened before startup probe")
				}
				close(probeCalled)
				return nil
			},
		})
	}()
	await(t, probeCalled, "startup probe")
	awaitReady(t, health, true)
	if !group.admitting.Load() {
		t.Fatal("admission did not open after successful probe")
	}
	cancel()
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("RunServing shutdown: %v", err)
	}
	if health.ready.Load() || !group.closed.Load() || mesh.stops.Load() != 1 {
		t.Fatalf("shutdown state ready=%v closed=%v stops=%d", health.ready.Load(), group.closed.Load(), mesh.stops.Load())
	}
}

func TestProbeFailureNeverMarksReady(t *testing.T) {
	health := newFakeHealth()
	mesh := &fakeMesh{}
	group := newFakeGroup()
	err := RunServing(context.Background(), servingConfig(), Dependencies{
		NewHealth:   func(int) (Health, error) { return health, nil },
		StartMesh:   func(context.Context, config.Config) (Mesh, error) { return mesh, nil },
		NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) { return group, nil },
		Probe: func(context.Context, config.Config, Mesh, forward.HostResolver) error {
			return errors.New("target unavailable")
		},
	})
	if err == nil {
		t.Fatal("probe failure unexpectedly succeeded")
	}
	if health.ready.Load() || group.admitting.Load() || !group.closed.Load() || mesh.stops.Load() != 1 {
		t.Fatalf("failed startup state ready=%v admitting=%v closed=%v stops=%d", health.ready.Load(), group.admitting.Load(), group.closed.Load(), mesh.stops.Load())
	}
}

func TestUnexpectedForwardErrorIsFatalAfterReadiness(t *testing.T) {
	health := newFakeHealth()
	mesh := &fakeMesh{}
	group := newFakeGroup()
	done := make(chan error, 1)
	go func() {
		done <- RunServing(context.Background(), servingConfig(), Dependencies{
			NewHealth:   func(int) (Health, error) { return health, nil },
			StartMesh:   func(context.Context, config.Config) (Mesh, error) { return mesh, nil },
			NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) { return group, nil },
			Probe:       func(context.Context, config.Config, Mesh, forward.HostResolver) error { return nil },
		})
	}()
	awaitReady(t, health, true)
	group.serveError <- errors.New("accept failed")
	err := awaitErr(t, done)
	if err == nil || health.ready.Load() || mesh.stops.Load() != 1 {
		t.Fatalf("fatal result err=%v ready=%v stops=%d", err, health.ready.Load(), mesh.stops.Load())
	}
}

func TestUnexpectedCleanForwardExitIsFatalBeforeReadiness(t *testing.T) {
	health := newFakeHealth()
	mesh := &fakeMesh{}
	group := newFakeGroup()
	group.started = make(chan struct{})
	group.serveError <- nil
	err := RunServing(context.Background(), servingConfig(), Dependencies{
		NewHealth:   func(int) (Health, error) { return health, nil },
		StartMesh:   func(context.Context, config.Config) (Mesh, error) { return mesh, nil },
		NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) { return group, nil },
		Probe:       func(context.Context, config.Config, Mesh, forward.HostResolver) error { return nil },
	})
	if err == nil || health.ready.Load() || group.admitting.Load() {
		t.Fatalf("clean serve exit result err=%v ready=%v admitting=%v", err, health.ready.Load(), group.admitting.Load())
	}
}

type forcingGroup struct {
	*fakeGroup
	waits atomic.Int64
}

func (g *forcingGroup) Wait(ctx context.Context) error {
	if g.waits.Add(1) == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

type orderingMesh struct {
	group *forcingGroup
	stops atomic.Int64
}

func (*orderingMesh) ListenTCP(string) (net.Listener, error) { return nil, errors.New("unused") }
func (*orderingMesh) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (m *orderingMesh) Stop(context.Context) error {
	if !m.group.forced.Load() {
		return errors.New("mesh stopped before sessions were force-closed")
	}
	m.stops.Add(1)
	return nil
}

func TestDrainTimeoutForceClosesBeforeBoundedMeshStop(t *testing.T) {
	health := newFakeHealth()
	group := &forcingGroup{fakeGroup: newFakeGroup()}
	mesh := &orderingMesh{group: group}
	cfg := servingConfig()
	cfg.DrainTimeout = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunServing(ctx, cfg, Dependencies{
			NewHealth:   func(int) (Health, error) { return health, nil },
			StartMesh:   func(context.Context, config.Config) (Mesh, error) { return mesh, nil },
			NewForwards: func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error) { return group, nil },
			Probe:       func(context.Context, config.Config, Mesh, forward.HostResolver) error { return nil },
		})
	}()
	awaitReady(t, health, true)
	cancel()
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("RunServing shutdown: %v", err)
	}
	if !group.forced.Load() || group.waits.Load() != 2 || mesh.stops.Load() != 1 {
		t.Fatalf("forced=%v waits=%d stops=%d", group.forced.Load(), group.waits.Load(), mesh.stops.Load())
	}
}

func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func awaitReady(t *testing.T, health *fakeHealth, want bool) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case value := <-health.readyEvent:
			if value == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for ready=%v", want)
		}
	}
}

func awaitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RunServing")
		return nil
	}
}
