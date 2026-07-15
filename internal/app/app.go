// Package app owns railbird's serving lifecycle and shutdown ordering.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/dns"
	"github.com/jratienza65/railbird/internal/forward"
)

// Health is the lifecycle-only readiness surface. It does not continuously
// probe a database or target after activation.
type Health interface {
	SetReady(bool) bool
	BeginDrain()
	Terminal() <-chan error
	Shutdown(context.Context) error
}

// Mesh is the embedded userspace network surface needed by the serving app.
type Mesh interface {
	forward.MeshClient
	Stop(context.Context) error
}

// ForwardGroup is the listener/session lifecycle owned by the supervisor.
type ForwardGroup interface {
	Serve(context.Context) error
	Started() <-chan struct{}
	OpenAdmission() error
	Close() error
	Wait(context.Context) error
	ForceClose()
}

type HealthFactory func(port int) (Health, error)
type MeshFactory func(context.Context, config.Config) (Mesh, error)
type ForwardFactory func(config.Config, Mesh, forward.HostResolver) (ForwardGroup, error)
type ProbeFunc func(context.Context, config.Config, Mesh, forward.HostResolver) error

// Dependencies are explicit so lifecycle ordering can be tested without
// Railway, NetBird management credentials, or real listening ports.
type Dependencies struct {
	NewHealth   HealthFactory
	StartMesh   MeshFactory
	NewForwards ForwardFactory
	Probe       ProbeFunc
}

// RunServing supervises one serving profile (egress or persistent ingress).
// Bootstrap is intentionally a separate non-serving workflow.
func RunServing(ctx context.Context, cfg config.Config, deps Dependencies) error {
	if cfg.Mode == config.ModeIngress && cfg.IdentityMode == config.IdentityBootstrap {
		return fmt.Errorf("bootstrap identity mode is non-serving")
	}
	if err := validateDependencies(deps); err != nil {
		return err
	}

	health, err := deps.NewHealth(cfg.HealthPort)
	if err != nil {
		return fmt.Errorf("bind health: %w", err)
	}
	if !health.SetReady(false) {
		shutdownErr := shutdown(context.Background(), cfg, health, nil, nil)
		return errors.Join(fmt.Errorf("initialize health readiness"), shutdownErr)
	}

	supervisedCtx, cancelSupervision := context.WithCancel(ctx)
	defer cancelSupervision()
	terminal := make(chan error, 2)
	var terminalOnce sync.Once
	reportTerminal := func(err error) {
		if err == nil {
			return
		}
		terminalOnce.Do(func() {
			terminal <- err
			cancelSupervision()
		})
	}
	go func() {
		select {
		case err, ok := <-health.Terminal():
			if ok && err != nil {
				reportTerminal(fmt.Errorf("health serve: %w", err))
			}
		case <-supervisedCtx.Done():
		}
	}()

	startupCtx, cancelStartup := context.WithTimeout(supervisedCtx, cfg.StartupTimeout)
	defer cancelStartup()
	mesh, err := deps.StartMesh(startupCtx, cfg)
	if err != nil {
		shutdownErr := shutdown(context.Background(), cfg, health, nil, nil)
		return errors.Join(startupError(ctx, startupCtx, terminal, fmt.Errorf("start netbird: %w", err)), shutdownErr)
	}

	resolver, err := buildResolver(cfg, mesh)
	if err != nil {
		shutdownErr := shutdown(context.Background(), cfg, health, nil, mesh)
		return errors.Join(err, shutdownErr)
	}
	group, err := deps.NewForwards(cfg, mesh, resolver)
	if err != nil {
		shutdownErr := shutdown(context.Background(), cfg, health, nil, mesh)
		return errors.Join(fmt.Errorf("bind forwards: %w", err), shutdownErr)
	}

	serveDone := make(chan error, 1)
	go func() {
		err := group.Serve(supervisedCtx)
		serveDone <- err
		if err != nil {
			reportTerminal(fmt.Errorf("forward serve: %w", err))
		} else if supervisedCtx.Err() == nil {
			reportTerminal(fmt.Errorf("forward serve exited unexpectedly"))
		}
	}()

	select {
	case <-group.Started():
	case err := <-terminal:
		shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
		return errors.Join(err, shutdownErr)
	case <-startupCtx.Done():
		shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
		return errors.Join(startupError(ctx, startupCtx, terminal, fmt.Errorf("startup barrier: %w", startupCtx.Err())), shutdownErr)
	}

	if cfg.ProbePolicy == config.ProbeRequired {
		if err := deps.Probe(startupCtx, cfg, mesh, resolver); err != nil {
			shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
			return errors.Join(startupError(ctx, startupCtx, terminal, fmt.Errorf("startup probe: %w", err)), shutdownErr)
		}
	}
	select {
	case err := <-terminal:
		shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
		return errors.Join(err, shutdownErr)
	default:
	}
	if err := group.OpenAdmission(); err != nil {
		shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
		return errors.Join(fmt.Errorf("open admission: %w", err), shutdownErr)
	}
	if !health.SetReady(true) {
		shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
		return errors.Join(fmt.Errorf("health became terminal before readiness"), shutdownErr)
	}
	cancelStartup()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-terminal:
	case err := <-serveDone:
		if err != nil {
			runErr = fmt.Errorf("forward serve: %w", err)
		} else if ctx.Err() == nil {
			runErr = fmt.Errorf("forward serve exited unexpectedly")
		}
	}
	shutdownErr := shutdown(context.Background(), cfg, health, group, mesh)
	return errors.Join(runErr, shutdownErr)
}

func validateDependencies(deps Dependencies) error {
	if deps.NewHealth == nil || deps.StartMesh == nil || deps.NewForwards == nil || deps.Probe == nil {
		return fmt.Errorf("app dependencies are incomplete")
	}
	return nil
}

func buildResolver(cfg config.Config, mesh Mesh) (forward.HostResolver, error) {
	static := make(map[string]net.IP, len(cfg.StaticHosts))
	for host, value := range cfg.StaticHosts {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("validated static host %q has invalid IP", host)
		}
		static[host] = ip
	}
	var next forward.HostResolver
	if cfg.DNSOverTCP {
		next = &dns.Resolver{
			Server:       cfg.DNSResolver,
			Dial:         mesh,
			QueryTimeout: cfg.DNSQueryTimeout,
		}
	}
	return forward.ChainResolver(static, next), nil
}

// NewForwardGroup is the production ForwardFactory.
func NewForwardGroup(cfg config.Config, mesh Mesh, resolver forward.HostResolver) (ForwardGroup, error) {
	forwards, err := forward.Parse(cfg.Forwards)
	if err != nil {
		return nil, err
	}
	opts := forward.ProxyOptions{
		Dial: forward.DialOptions{
			AttemptTimeout: cfg.DialAttemptTimeout,
			TotalTimeout:   cfg.DialTotalTimeout,
			TCPKeepAlive:   cfg.TCPKeepalive,
		},
		IdleTimeout: cfg.IdleTimeout,
	}
	bindings := make([]forward.ListenerBinding, 0, len(forwards))
	for _, item := range forwards {
		bindings = append(bindings, forward.NewListenerBinding(mesh, item, cfg.Mode, resolver, opts))
	}
	return forward.BindAll(bindings, forward.ListenerGroupOptions{MaxConnections: cfg.MaxConnections})
}

// ProbeForwards is the production ProbeFunc. It uses the same resolver and
// dial path as a real connection and sends no application bytes.
func ProbeForwards(ctx context.Context, cfg config.Config, mesh Mesh, resolver forward.HostResolver) error {
	forwards, err := forward.Parse(cfg.Forwards)
	if err != nil {
		return err
	}
	opts := forward.DialOptions{
		AttemptTimeout: cfg.DialAttemptTimeout,
		TotalTimeout:   cfg.DialTotalTimeout,
		TCPKeepAlive:   cfg.TCPKeepalive,
	}
	for _, item := range forwards {
		conn, err := forward.DialTarget(ctx, mesh, item.Target, cfg.Mode, resolver, opts)
		if err != nil {
			return fmt.Errorf("probe listener %s target: %w", item.ListenPort, err)
		}
		_ = conn.Close()
	}
	return nil
}

func startupError(parent, startup context.Context, terminal <-chan error, fallback error) error {
	select {
	case err := <-terminal:
		return err
	default:
	}
	if parent.Err() != nil && errors.Is(startup.Err(), context.Canceled) {
		return nil
	}
	return fallback
}

func shutdown(ctx context.Context, cfg config.Config, health Health, group ForwardGroup, mesh Mesh) error {
	if health != nil {
		health.BeginDrain()
	}
	var result error
	if group != nil {
		result = errors.Join(result, group.Close())
		drainCtx, cancelDrain := context.WithTimeout(ctx, cfg.DrainTimeout)
		err := group.Wait(drainCtx)
		cancelDrain()
		if err != nil {
			group.ForceClose()
		}
	}
	postDrainCtx, cancelPostDrain := context.WithTimeout(ctx, cfg.NetBirdStopTimeout)
	if mesh != nil {
		result = errors.Join(result, mesh.Stop(postDrainCtx))
	}
	if group != nil {
		result = errors.Join(result, group.Wait(postDrainCtx))
	}
	cancelPostDrain()
	if health != nil {
		healthCtx, cancelHealth := context.WithTimeout(ctx, cfg.NetBirdStopTimeout)
		result = errors.Join(result, health.Shutdown(healthCtx))
		cancelHealth()
	}
	return result
}

// DefaultTimeouts is useful to deterministic callers constructing configs
// outside config.Load (primarily tests).
func DefaultTimeouts(cfg *config.Config) {
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = 90 * time.Second
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = 45 * time.Second
	}
	if cfg.NetBirdStopTimeout == 0 {
		cfg.NetBirdStopTimeout = 5 * time.Second
	}
}
