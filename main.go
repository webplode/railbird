package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jratienza65/railbird/internal/app"
	"github.com/jratienza65/railbird/internal/config"
	"github.com/jratienza65/railbird/internal/health"
	"github.com/jratienza65/railbird/internal/netbird"
	"github.com/jratienza65/railbird/internal/privilege"
)

const (
	runtimeUID = 65532
	runtimeGID = 65532
)

type runtimeDependencies struct {
	requireRuntimeIdentity func(uid, gid int) error
	prepareBootstrap       func(root string, uid, gid int, classify func() error) error
	classifyBootstrap      func(root string, uid, gid int) error
	prepareEphemeralState  func(path string, uid, gid int) error
	loadPersistentIdentity func(root, expectedPublicKey string, uid, gid int) (netbird.PersistentIdentity, error)
	runBootstrap           func(context.Context, config.Config) (string, error)
	runServing             func(context.Context, config.Config, netbird.Options) error
	bootstrapOutput        io.Writer
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, productionDependencies()); err != nil {
		log.Printf("railbird stopped: %v", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, getenv func(string) string, deps runtimeDependencies) error {
	cfg, err := config.Load(args, getenv)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateRuntimeDependencies(deps); err != nil {
		return err
	}
	for _, warning := range cfg.Warnings {
		log.Printf("configuration warning: %s", warning)
	}

	if cfg.Mode == config.ModeIngress && cfg.IdentityMode == config.IdentityBootstrap {
		return runBootstrapProfile(ctx, cfg, deps)
	}
	return runServingProfile(ctx, cfg, deps)
}

func runBootstrapProfile(ctx context.Context, cfg config.Config, deps runtimeDependencies) error {
	startupCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()

	classify := func() error {
		return deps.classifyBootstrap(cfg.RailwayVolumeMountPath, runtimeUID, runtimeGID)
	}
	if err := deps.prepareBootstrap(cfg.RailwayVolumeMountPath, runtimeUID, runtimeGID, classify); err != nil {
		return fmt.Errorf("bootstrap privilege boundary: %w", err)
	}

	publicKey, err := deps.runBootstrap(startupCtx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap identity: %w", err)
	}
	if _, err := fmt.Fprintf(deps.bootstrapOutput, "RAILBIRD_PEER_PUBLIC_KEY=%s\n", publicKey); err != nil {
		return fmt.Errorf("emit bootstrap public key: %w", err)
	}
	log.Printf("ingress bootstrap completed; remove NB_SETUP_KEY and RAILWAY_RUN_UID before persistent serving")
	return nil
}

func runServingProfile(ctx context.Context, cfg config.Config, deps runtimeDependencies) error {
	if err := deps.requireRuntimeIdentity(runtimeUID, runtimeGID); err != nil {
		return fmt.Errorf("serving privilege boundary: %w", err)
	}

	opts := netbirdOptions(cfg)
	switch cfg.IdentityMode {
	case config.IdentityEphemeral:
		if err := deps.prepareEphemeralState(cfg.StateDir, runtimeUID, runtimeGID); err != nil {
			return fmt.Errorf("prepare ephemeral state: %w", err)
		}
		opts.SetupKey = cfg.SetupKey
	case config.IdentityPersistent:
		identity, err := deps.loadPersistentIdentity(
			cfg.RailwayVolumeMountPath,
			cfg.ExpectedPeerPublicKey,
			runtimeUID,
			runtimeGID,
		)
		if err != nil {
			return fmt.Errorf("validate persistent identity: %w", err)
		}
		opts.PrivateKey = identity.PrivateKey
		opts.ExpectedPublicKey = cfg.ExpectedPeerPublicKey
	default:
		return fmt.Errorf("identity mode %q is not a serving profile", cfg.IdentityMode)
	}

	log.Printf("starting mode=%s identity=%s device=%s health_port=%d probe=%s", cfg.Mode, cfg.IdentityMode, cfg.DeviceName, cfg.HealthPort, cfg.ProbePolicy)
	return deps.runServing(ctx, cfg, opts)
}

func netbirdOptions(cfg config.Config) netbird.Options {
	return netbird.Options{
		DeviceName:    cfg.DeviceName,
		ManagementURL: cfg.ManagementURL,
		Mode:          cfg.Mode,
		StateDir:      cfg.StateDir,
		LogLevel:      cfg.LogLevel,
		DNSLabels:     cfg.DNSLabels,
		MTU:           cfg.MTU,
		StopTimeout:   cfg.NetBirdStopTimeout,
	}
}

func productionDependencies() runtimeDependencies {
	return runtimeDependencies{
		requireRuntimeIdentity: privilege.RequireRuntimeIdentity,
		prepareBootstrap:       privilege.PrepareBootstrap,
		classifyBootstrap: func(root string, uid, gid int) error {
			_, err := netbird.ClassifyBootstrapFilesystem(root, uid, gid)
			return err
		},
		prepareEphemeralState:  prepareEphemeralState,
		loadPersistentIdentity: netbird.LoadPersistentVolumeIdentity,
		runBootstrap:           runProductionBootstrap,
		runServing:             runProductionServing,
		bootstrapOutput:        os.Stdout,
	}
}

func runProductionBootstrap(ctx context.Context, cfg config.Config) (string, error) {
	opts := netbirdOptions(cfg)
	opts.SetupKey = cfg.SetupKey
	factory := netbird.NewBootstrapClientFactory(opts)
	return netbird.RunBootstrap(
		ctx,
		cfg.RailwayVolumeMountPath,
		opts,
		runtimeUID,
		runtimeGID,
		factory,
	)
}

func runProductionServing(ctx context.Context, cfg config.Config, opts netbird.Options) error {
	return app.RunServing(ctx, cfg, app.Dependencies{
		NewHealth: func(port int) (app.Health, error) {
			return health.Start(port)
		},
		StartMesh: func(startCtx context.Context, _ config.Config) (app.Mesh, error) {
			return netbird.New(startCtx, opts)
		},
		NewForwards: app.NewForwardGroup,
		Probe:       app.ProbeForwards,
	})
}

func validateRuntimeDependencies(deps runtimeDependencies) error {
	if deps.requireRuntimeIdentity == nil || deps.prepareBootstrap == nil || deps.classifyBootstrap == nil ||
		deps.prepareEphemeralState == nil || deps.loadPersistentIdentity == nil || deps.runBootstrap == nil ||
		deps.runServing == nil || deps.bootstrapOutput == nil {
		return fmt.Errorf("runtime dependencies are incomplete")
	}
	return nil
}

func prepareEphemeralState(path string, uid, gid int) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state path must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory permissions must be 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("state directory ownership is unavailable")
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		return fmt.Errorf("state directory owner %d:%d, want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
	return nil
}
